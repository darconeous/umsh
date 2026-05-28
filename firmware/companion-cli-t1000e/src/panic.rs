use core::fmt::Write as _;

use cortex_m_rt::{exception, ExceptionFrame};
use umsh_bsp_nrf52840::panic_persist::{PanicSlot, SliceWriter, SyncNoinit};

#[unsafe(link_section = ".uninit")]
pub static PANIC_REGION: SyncNoinit<[u8; 512]> = SyncNoinit::uninit();

pub fn panic_region() -> &'static mut [u8] {
    unsafe { PANIC_REGION.as_bytes_mut() }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut slot = PanicSlot::new(panic_region());
    let mut msg = [0u8; 504];
    let msg_len = {
        let mut w = SliceWriter { buf: &mut msg, pos: 0 };
        // Marker prefix proves the panic handler ran even if Display(info)
        // formats as empty (e.g. PanicInfo with stripped message).
        let _ = w.write_str("PANIC: ");
        let _ = core::fmt::write(&mut w, format_args!("{}", info));
        if w.pos == 7 {
            // Only the marker — nothing printable from PanicInfo.
            let _ = w.write_str("(no message)");
        }
        w.pos
    };
    slot.capture(&msg[..msg_len]);
    umsh_bsp_nrf52840::gpregret::reset_to_app();
}

/// Custom HardFault handler. cortex-m-rt's default is `loop {}`, which leaves
/// the CPU spinning until the WDT trips ~8 s later — and bypasses our
/// `#[panic_handler]` entirely, so the panic slot stays whatever it was. By
/// capturing the exception frame's faulting PC + LR into the panic slot and
/// triggering a soft reset, every HardFault is now recoverable and visible on
/// the next boot as a `HARDFAULT pc=... lr=...` line.
#[exception]
unsafe fn HardFault(ef: &ExceptionFrame) -> ! {
    let mut slot = PanicSlot::new(panic_region());
    let mut msg = [0u8; 504];
    let msg_len = {
        let mut w = SliceWriter { buf: &mut msg, pos: 0 };
        let _ = write!(
            w,
            "HARDFAULT pc=0x{:08x} lr=0x{:08x} r0=0x{:08x} r1=0x{:08x} r2=0x{:08x} r3=0x{:08x}",
            ef.pc(), ef.lr(), ef.r0(), ef.r1(), ef.r2(), ef.r3(),
        );
        w.pos
    };
    slot.capture(&msg[..msg_len]);
    umsh_bsp_nrf52840::gpregret::reset_to_app();
}
