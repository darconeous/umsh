//! Panic capture into RTC fast RAM — the ESP32 analog of the nRF BSP's
//! `panic_persist`: the panic message survives the ensuing software reset
//! and is reported on the next boot over UART0.
//!
//! With the `panic-handler` feature enabled this module also installs the
//! `#[panic_handler]`: print the panic over UART0, record it, then software
//! reset so the RWDT never has to fire for a Rust-level panic. Exactly one
//! crate in a firmware image may provide the handler, so firmware that wants
//! a different handler leaves the feature off.

use core::fmt::Write;

/// Capacity of the persisted message; longer panics are truncated.
pub const MSG_CAPACITY: usize = 256;

const MAGIC: u32 = 0x554d_5350; // "UMSP"

#[repr(C)]
struct PanicRecord {
    magic: u32,
    len: u32,
    msg: [u8; MSG_CAPACITY],
}

// Safety: plain-old-data with no padding-dependent invariants; any bit
// pattern is handled (magic mismatch just reads as "no record").
unsafe impl esp_hal::Persistable for PanicRecord {}

#[esp_hal::ram(unstable(rtc_fast, persistent))]
static mut PANIC_RECORD: PanicRecord = PanicRecord {
    magic: 0,
    len: 0,
    msg: [0; MSG_CAPACITY],
};

struct RecordWriter(&'static mut PanicRecord);

impl Write for RecordWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let len = self.0.len as usize;
        let take = usize::min(MSG_CAPACITY - len, s.len());
        self.0.msg[len..len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.0.len = (len + take) as u32;
        Ok(())
    }
}

/// Record a panic message for retrieval after reset. Truncates at
/// [`MSG_CAPACITY`] bytes.
pub fn record(info: &core::panic::PanicInfo<'_>) {
    let record = unsafe { &mut *&raw mut PANIC_RECORD };
    record.magic = 0;
    record.len = 0;
    let mut writer = RecordWriter(record);
    let _ = write!(writer, "{info}");
    unsafe { &mut *&raw mut PANIC_RECORD }.magic = MAGIC;
}

/// If the previous boot ended in a captured panic, copy the message into
/// `buf` and return it as a `&str`. The record is consumed either way.
pub fn take_panic_message(buf: &mut [u8; MSG_CAPACITY]) -> Option<&str> {
    let record = unsafe { &mut *&raw mut PANIC_RECORD };
    if record.magic != MAGIC {
        return None;
    }
    record.magic = 0;
    let len = usize::min(record.len as usize, MSG_CAPACITY);
    buf[..len].copy_from_slice(&record.msg[..len]);
    // Truncation can split a UTF-8 sequence; degrade gracefully.
    match core::str::from_utf8(&buf[..len]) {
        Ok(msg) => Some(msg),
        Err(e) => core::str::from_utf8(&buf[..e.valid_up_to()]).ok(),
    }
}

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    esp_println::println!("\n*** panic: {info}");
    record(info);
    // Let the UART FIFO drain before resetting, or the tail of the message
    // is lost (~1 ms at 115200 baud per 12 bytes; be generous).
    let deadline = esp_hal::time::Instant::now() + esp_hal::time::Duration::from_millis(50);
    while esp_hal::time::Instant::now() < deadline {}
    esp_hal::system::software_reset()
}
