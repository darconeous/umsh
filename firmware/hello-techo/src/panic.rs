//! Panic handler for the hello-techo bringup firmware.
//!
//! Wires together three BSP pieces that are each unit-testable in
//! isolation but must be glued together in the binary:
//!
//! - `umsh_bsp_nrf52840::panic_persist::SyncNoinit` — the `.uninit`
//!   retained-RAM static that survives warm resets.
//! - `umsh_bsp_nrf52840::panic_persist::{PanicSlot, SliceWriter}` —
//!   framing and formatting over that region.
//! - `umsh_bsp_nrf52840::gpregret::reset_to_app` (GPREGRET=0, then
//!   `SCB::sys_reset`) — ensures the bootloader boots the app on the
//!   next start so the panic message is visible over USB-CDC.
//!
//! The `#[panic_handler]` attribute is permitted only in binary crates;
//! library crates cannot define one without causing a duplicate-symbol
//! link error. Everything else in this file could in principle live in the
//! BSP, but the handler itself cannot.

use umsh_bsp_nrf52840::panic_persist::{PanicSlot, SliceWriter, SyncNoinit};

/// Retained-RAM region for panic messages.
///
/// Placed in the `.uninit` section so cortex-m-rt does not zero it at
/// startup, allowing the previous boot's panic message to survive a warm
/// reset and be read on the next boot.
#[unsafe(link_section = ".uninit")]
pub static PANIC_REGION: SyncNoinit<[u8; 512]> = SyncNoinit::uninit();

/// Return a mutable byte slice over [`PANIC_REGION`].
///
/// # Safety
/// Must not be called while any other reference to `PANIC_REGION` is live.
/// In practice: called once at boot (before tasks start) to read + clear
/// a previous panic, and once more from the panic handler (after the
/// executor has stopped and no other code is running).
pub fn panic_region() -> &'static mut [u8] {
    unsafe { PANIC_REGION.as_bytes_mut() }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut slot = PanicSlot::new(panic_region());

    let mut msg = [0u8; 504];
    let msg_len = {
        let mut w = SliceWriter { buf: &mut msg, pos: 0 };
        let _ = core::fmt::write(&mut w, format_args!("{}", info));
        w.pos
    };
    slot.capture(&msg[..msg_len]);

    // Clear GPREGRET so the bootloader boots the app on next start,
    // letting the captured message be printed over USB-CDC.
    umsh_bsp_nrf52840::gpregret::reset_to_app();
}
