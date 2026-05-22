// LilyGO T-Echo bringup firmware.
//
// Compiles as `#![no_std] #![no_main]` for bare-metal targets and as a
// trivial host placeholder otherwise. The `target_os = "none"` gate
// covers both modes so `cargo check --workspace` succeeds on a
// developer's host even without `rustup target add thumbv7em-none-eabihf`.
//
// See docs/firmware-plan-techo.md.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use panic_halt as _;

#[cfg(target_os = "none")]
#[cortex_m_rt::entry]
fn main() -> ! {
    // TODO: bring up the bringup firmware, in phases:
    //
    //   Phase 1 — embassy + USB-CDC echo.
    //   Phase 2 — WDT + PanicSlot capture + TouchlessResetWatcher +
    //             EscapeWatcher wired below the USB-CDC reader.
    //   Phase 3 — heartbeat LED via umsh_ux_tracker::led::LedEngine.
    //   Phase 4 — e-paper "hello world" via epd-waveshare.
    //
    // For now: trivial WFI loop so the firmware at least links and
    // boots on hardware.
    loop {
        cortex_m::asm::wfi();
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    // Host placeholder. This binary only runs on the embedded target.
    // See docs/firmware-plan-techo.md for the real flashing procedure.
}
