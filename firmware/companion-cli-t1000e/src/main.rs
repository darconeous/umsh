// T1000-E companion-radio CLI firmware binary.
//
// Compiles as `#![no_std] #![no_main]` for bare-metal targets and as a
// trivial host placeholder otherwise. The `target_os = "none"` gate covers
// both modes so `cargo check --workspace` succeeds on a developer's host
// even without `rustup target add thumbv7em-none-eabihf`.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use panic_halt as _;

#[cfg(target_os = "none")]
#[cortex_m_rt::entry]
fn main() -> ! {
    // TODO: bring up board + app:
    //
    // let board = umsh_bsp_t1000e::Board::init();
    // umsh_app_companion_cli::run(board)
    //
    // (Or via `#[embassy_executor::main]` once embassy machinery is wired
    // up in the chip-BSP.)
    loop {
        cortex_m::asm::wfi();
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    // Host placeholder. This binary only runs on the embedded target.
    // See docs/firmware-plan-t1000e.md for the real flashing procedure.
}
