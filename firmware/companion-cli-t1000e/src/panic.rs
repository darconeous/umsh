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
        let _ = core::fmt::write(&mut w, format_args!("{}", info));
        w.pos
    };
    slot.capture(&msg[..msg_len]);
    umsh_bsp_nrf52840::gpregret::reset_to_app();
}
