//! UART0 line I/O adapters for the `umsh-cli` `CliInput` / `CliOutput`
//! traits.
//!
//! Structurally identical to the CDC-ACM adapters in
//! `companion-cli-wio-tracker-l1`, and for the same reason: a dedicated
//! output task owns the TX half and drains a static channel, so echo
//! (driven from the RX path) and CLI responses (driven from the session)
//! never contend for one writer. The nRF version arrived at that split
//! after a shared-`RefCell` sender panicked when an inbound beacon landed
//! mid-echo; the hazard is transport-independent, so the shape carries
//! over rather than being rediscovered.
//!
//! What does NOT carry over is connection state. UART has no notion of a
//! host opening the port, so there is no `wait_connection` and no
//! disconnect handling — bytes written with no terminal attached simply
//! go to the CP2102 and are lost, which is the correct behaviour for a
//! serial console.
//!
//! `esp-println` writes to this same UART0 by direct register access.
//! Boot diagnostics therefore interleave cleanly ahead of the CLI banner,
//! but steady-state `println!` from other tasks would corrupt the
//! interactive line editing — the firmware keeps quiet once the CLI is up.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use esp_hal::Async;
use esp_hal::uart::{UartRx, UartTx};
use umsh_cli::io::{CliInput, CliOutput};

/// One chunk in the output queue. 64 bytes matches the nRF adapter's
/// USB-packet granularity; here it is just a convenient batch size.
pub type OutChunk = heapless::Vec<u8, 64>;

/// Output queue feeding [`drain_to_uart`]. Capacity 16 chunks ≈ 1 KiB:
/// enough that a `/help` block or peer listing does not stall, small
/// enough that a wedged writer back-pressures instead of buffering
/// without bound.
pub static OUTPUT_CH: Channel<CriticalSectionRawMutex, OutChunk, 16> = Channel::new();

/// Drain [`OUTPUT_CH`] to the UART forever. Owns the TX half — nothing
/// else writes to it.
pub async fn drain_to_uart(tx: &mut UartTx<'static, Async>) -> ! {
    loop {
        let chunk = OUTPUT_CH.receive().await;
        let mut sent = 0;
        while sent < chunk.len() {
            match tx.write_async(&chunk[sent..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => sent += n,
            }
        }
    }
}

async fn push_chunk(bytes: &[u8]) {
    let mut v: OutChunk = heapless::Vec::new();
    let to_copy = bytes.len().min(v.capacity());
    let _ = v.extend_from_slice(&bytes[..to_copy]);
    OUTPUT_CH.send(v).await;
}

/// Push `bytes` in 63-byte chunks. Multi-chunk pushes are not atomic
/// with other writers, so echo bytes can land between chunks of a long
/// line; CLI lines are short enough that this stays invisible.
async fn push_chunks(bytes: &[u8]) {
    for chunk in bytes.chunks(63) {
        push_chunk(chunk).await;
    }
}

// ─── CliOutput ───────────────────────────────────────────────────────────

pub struct UartOutput;

impl UartOutput {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UartOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl CliOutput for UartOutput {
    type Error = core::convert::Infallible;

    async fn write_line(&mut self, line: &str) -> Result<(), Self::Error> {
        push_chunks(line.as_bytes()).await;
        push_chunk(b"\r\n").await;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ─── CliInput ────────────────────────────────────────────────────────────

/// Line-accumulating UART reader with character echo and backspace
/// handling. Echo bytes are queued through [`OUTPUT_CH`]; this type never
/// touches the TX half.
///
/// `read_line` never returns `Ok(None)` — a serial console has no EOF.
pub struct UartInput {
    rx: UartRx<'static, Async>,
    buf: [u8; 256],
    len: usize,
}

impl UartInput {
    pub fn new(rx: UartRx<'static, Async>) -> Self {
        Self {
            rx,
            buf: [0; 256],
            len: 0,
        }
    }
}

impl CliInput for UartInput {
    type Error = core::convert::Infallible;

    async fn read_line<'io, 'buf>(
        &'io mut self,
        buf: &'buf mut [u8],
    ) -> Result<Option<&'buf str>, Self::Error>
    where
        'buf: 'io,
    {
        loop {
            // Emit a line as soon as a terminator is buffered. CR, LF, and
            // CR+LF are all accepted as one terminator so the CLI behaves
            // the same under screen, kermit, and a raw pipe.
            if let Some(term) = self.buf[..self.len]
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')
            {
                let copy_len = term.min(buf.len());
                buf[..copy_len].copy_from_slice(&self.buf[..copy_len]);
                let mut consumed = term + 1;
                if self.buf[term] == b'\r' && consumed < self.len && self.buf[consumed] == b'\n' {
                    consumed += 1;
                }
                self.buf.copy_within(consumed..self.len, 0);
                self.len -= consumed;
                let s = core::str::from_utf8(&buf[..copy_len]).unwrap_or("");
                return Ok(Some(s));
            }

            let mut pkt = [0u8; 64];
            let n = match self.rx.read_async(&mut pkt).await {
                Ok(0) => continue,
                // A FIFO overflow or framing error costs the in-flight
                // line, not the session: drop the partial buffer and
                // resynchronize on the next terminator.
                Err(_) => {
                    self.len = 0;
                    continue;
                }
                Ok(n) => n,
            };

            // Batch printable echo into one chunk per RX burst (flushed on
            // terminator, backspace, or end of burst) so a 60-character
            // paste produces one UART write instead of 60.
            let mut echo: OutChunk = heapless::Vec::new();

            for &b in &pkt[..n] {
                match b {
                    b'\r' | b'\n' => {
                        flush_echo(&mut echo).await;
                        if self.len < self.buf.len() {
                            self.buf[self.len] = b;
                            self.len += 1;
                        }
                        push_chunk(b"\r\n").await;
                    }
                    0x08 | 0x7F => {
                        flush_echo(&mut echo).await;
                        if self.len > 0 {
                            self.len -= 1;
                            push_chunk(b"\x08 \x08").await;
                        }
                    }
                    0x20..=0x7E => {
                        if self.len < self.buf.len() {
                            self.buf[self.len] = b;
                            self.len += 1;
                            if echo.push(b).is_err() {
                                flush_echo(&mut echo).await;
                                let _ = echo.push(b);
                            }
                        }
                    }
                    _ => {} // silently drop other control characters
                }
            }

            flush_echo(&mut echo).await;
        }
    }
}

/// Send the pending echo chunk if non-empty, leaving `echo` empty.
async fn flush_echo(echo: &mut OutChunk) {
    if echo.is_empty() {
        return;
    }
    let mut tmp = OutChunk::new();
    core::mem::swap(&mut tmp, echo);
    OUTPUT_CH.send(tmp).await;
}
