//! CDC ACM line I/O adapters for the `umsh-cli` `CliInput` / `CliOutput`
//! traits, with a dedicated output task that lets USB-level flow control
//! work correctly.
//!
//! ## Architecture
//!
//! Earlier revisions shared the USB `Sender` between `CdcOutput` and
//! `CdcInput` via `Rc<RefCell<…>>` so `read_line` could echo bytes back.
//! That had two compounding problems:
//!
//! 1. The `RefCell` borrow was held across `write_packet().await`. If a
//!    `wake` event fired during an echo (e.g. an inbound beacon while the
//!    user was pasting), `CliSession::service_events` would try to take
//!    a second `borrow_mut()` and panic.
//! 2. RX and TX were serialised inside one task. While echo was awaiting
//!    a host IN poll (~1 ms each), `read_packet` wasn't being called.
//!    On a long paste the nRF52840's tiny OUT buffer would fill and the
//!    host driver, instead of retrying NAKs indefinitely, would drop bytes.
//!
//! This rev splits the sender off into a dedicated `output_task` that
//! owns the `Sender` and drains a static `Channel`. Both `CdcOutput`
//! (CLI responses) and `CdcInput` (echo) push chunks onto the channel.
//! When the channel fills, writers `.send().await` naturally back-pressure;
//! `read_line` stops calling `read_packet`, USB NAKs the host's OUT
//! packets, and the host retries — proper end-to-end flow control with
//! no shared mutable state.

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::channel::Channel;
use embassy_usb::class::cdc_acm::Sender;
use embassy_usb::driver::Driver as UsbDriver;
use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
use umsh_cli::io::{CliInput, CliOutput};

/// One chunk in the output queue. Sized to one USB CDC bulk packet so the
/// output task can pass it straight to `write_packet` without further
/// splitting.
pub type OutChunk = heapless::Vec<u8, 64>;

/// Output queue feeding `output_task`. Capacity 16 packets ≈ 1 KiB; large
/// enough that bursts of CLI output (the `/help` block, peer listings) don't
/// stall, but small enough that a stuck host quickly back-pressures the
/// writers rather than silently buffering forever.
pub static OUTPUT_CH: Channel<ThreadModeRawMutex, OutChunk, 16> = Channel::new();

/// Drain `OUTPUT_CH` to the given `Sender` forever. Owns the sender —
/// nothing else writes to it.
pub async fn drain_to_sender<'d, D: UsbDriver<'d>>(sender: &mut Sender<'d, D>) -> ! {
    loop {
        let chunk = OUTPUT_CH.receive().await;
        let _ = sender.write_packet(&chunk).await;
    }
}

/// Push `bytes` (up to one USB packet) onto the output queue, awaiting on
/// back-pressure when the queue is full.
async fn push_chunk(bytes: &[u8]) {
    let mut v: OutChunk = heapless::Vec::new();
    let to_copy = bytes.len().min(v.capacity());
    let _ = v.extend_from_slice(&bytes[..to_copy]);
    OUTPUT_CH.send(v).await;
}

/// Push `bytes` in 63-byte chunks. Multi-chunk pushes are not atomic with
/// other writers — echo bytes can land between chunks of a long line. In
/// practice CLI lines are short, so this matches the existing visible
/// behaviour from prior revisions.
async fn push_chunks(bytes: &[u8]) {
    for chunk in bytes.chunks(63) {
        push_chunk(chunk).await;
    }
}

// ─── CliOutput ────────────────────────────────────────────────────────────────

pub struct CdcOutput;

impl CdcOutput {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CdcOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl CliOutput for CdcOutput {
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

// ─── CliInput ─────────────────────────────────────────────────────────────────

/// Line-accumulating CDC ACM reader with character echo and backspace
/// handling. Echo bytes are queued through `OUTPUT_CH`; this function
/// never touches the USB `Sender` directly.
///
/// `read_line` never returns `Ok(None)` (no EOF): on USB disconnect it
/// waits transparently for the next connection so the CLI session
/// continues across the user re-attaching their serial terminal.
pub struct CdcInput<'d, D: UsbDriver<'d>> {
    rx: CdcAcmRescue<'d, D>,
    buf: [u8; 256],
    len: usize,
}

impl<'d, D: UsbDriver<'d>> CdcInput<'d, D> {
    pub fn new(rx: CdcAcmRescue<'d, D>) -> Self {
        Self {
            rx,
            buf: [0; 256],
            len: 0,
        }
    }

    /// Wait until the host opens the CDC port. Exposed so callers can hold
    /// off on writing a banner until the writes will actually be delivered.
    pub async fn wait_connection(&mut self) {
        self.rx.wait_connection().await;
    }
}

impl<'d, D: UsbDriver<'d>> CliInput for CdcInput<'d, D> {
    type Error = core::convert::Infallible;

    async fn read_line<'io, 'buf>(
        &'io mut self,
        buf: &'buf mut [u8],
    ) -> Result<Option<&'buf str>, Self::Error>
    where
        'buf: 'io,
    {
        loop {
            // Emit a line if a terminator is in the buffer. Accept CR, LF,
            // or CR+LF as a single terminator.
            if let Some(term) = self.buf[..self.len]
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')
            {
                let copy_len = term.min(buf.len());
                buf[..copy_len].copy_from_slice(&self.buf[..copy_len]);
                let mut consumed = term + 1;
                if self.buf[term] == b'\r'
                    && consumed < self.len
                    && self.buf[consumed] == b'\n'
                {
                    consumed += 1;
                }
                self.buf.copy_within(consumed..self.len, 0);
                self.len -= consumed;
                let s = core::str::from_utf8(&buf[..copy_len]).unwrap_or("");
                return Ok(Some(s));
            }

            self.rx.wait_connection().await;

            let mut pkt = [0u8; 64];
            let n = match self.rx.read_packet(&mut pkt).await {
                Ok(0) | Err(_) => {
                    self.len = 0; // disconnect mid-line — drop partial buffer
                    continue;
                }
                Ok(n) => n,
            };

            // Per-byte processing: batch the printable echo into one chunk
            // per RX packet (flushed on terminator, backspace, or EOP) so a
            // 60-char paste produces one TX write instead of 60.
            //
            // When the output queue is full, each `push_chunk` awaits and
            // back-pressures the loop. Because we're inside `read_line` and
            // not calling `read_packet` while awaiting, USB OUT NAKs the
            // host and the host retries — no RX data loss.
            let mut echo: OutChunk = heapless::Vec::new();

            for &b in &pkt[..n] {
                match b {
                    b'\r' | b'\n' => {
                        if !echo.is_empty() {
                            let mut tmp = OutChunk::new();
                            core::mem::swap(&mut tmp, &mut echo);
                            OUTPUT_CH.send(tmp).await;
                        }
                        if self.len < self.buf.len() {
                            self.buf[self.len] = b;
                            self.len += 1;
                        }
                        push_chunk(b"\r\n").await;
                    }
                    0x08 | 0x7F => {
                        if !echo.is_empty() {
                            let mut tmp = OutChunk::new();
                            core::mem::swap(&mut tmp, &mut echo);
                            OUTPUT_CH.send(tmp).await;
                        }
                        if self.len > 0 {
                            self.len -= 1;
                            push_chunk(b"\x08 \x08").await;
                        }
                    }
                    0x20..=0x7E => {
                        if self.len < self.buf.len() {
                            self.buf[self.len] = b;
                            self.len += 1;
                            // echo is also at most 64 bytes; if it fills,
                            // flush and continue building the next chunk.
                            if echo.push(b).is_err() {
                                let mut tmp = OutChunk::new();
                                core::mem::swap(&mut tmp, &mut echo);
                                OUTPUT_CH.send(tmp).await;
                                let _ = echo.push(b);
                            }
                        }
                    }
                    _ => {} // silently drop other control characters
                }
            }

            if !echo.is_empty() {
                OUTPUT_CH.send(echo).await;
            }
        }
    }
}
