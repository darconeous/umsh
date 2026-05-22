//! GPREGRET-driven DFU entry for the Adafruit nRF52 UF2 bootloader.
//!
//! The Adafruit nRF52 UF2 bootloader reads POWER.GPREGRET on startup:
//!
//! | Value | Bootloader action                              |
//! |-------|------------------------------------------------|
//! | 0x57  | UF2 mass-storage + CDC DFU (TECHOBOOT drive)  |
//! | 0x4e  | Serial-only DFU (CDC; for nrfutil)             |
//! | 0xA8  | BLE OTA DFU (cold reset; SD not yet enabled)   |
//! | 0xB1  | BLE OTA DFU (warm; SD already initialized)     |
//! | 0x6d  | Skip DFU entirely, boot app immediately        |
//! | other | Boot application normally                      |
//!
//! Source-verified against Adafruit_nRF52_Bootloader commit 1224915
//! (the exact build on the LilyGO T-Echo, Board-ID "nRF52840-TEcho-v1").
//!
//! Safety contract: POWER.GPREGRET is only written from these functions,
//! never from CLI parsers or application-layer code.

use embassy_nrf::pac;

/// Enter UF2 mass-storage + CDC DFU mode (GPREGRET = 0x57).
///
/// The bootloader will expose TECHOBOOT as a removable UF2 drive **and**
/// a CDC serial port on next startup. This is what the MeshCore web
/// flasher and the Adafruit Arduino 1200-baud touchless-reset convention
/// both expect.
///
/// DIVERGES via [`cortex_m::peripheral::SCB::sys_reset`].
pub fn enter_dfu_uf2() -> ! {
    reset_with_gpregret(0x57)
}

/// Enter serial-only DFU mode (GPREGRET = 0x4e).
///
/// The bootloader will expose only a CDC DFU port on next startup
/// (no UF2 mass-storage drive). Suitable for `adafruit-nrfutil` /
/// `nrfutil` users who explicitly want the slimmer DFU interface.
///
/// DIVERGES via [`cortex_m::peripheral::SCB::sys_reset`].
pub fn enter_dfu_serial() -> ! {
    reset_with_gpregret(0x4e)
}

/// Trigger a plain system reset (GPREGRET = 0).
///
/// The bootloader will boot the application normally on the next startup.
/// Used by the panic handler so the bootloader does not accidentally enter
/// DFU mode after a panic-driven reset.
///
/// DIVERGES via [`cortex_m::peripheral::SCB::sys_reset`].
pub fn reset_to_app() -> ! {
    reset_with_gpregret(0x00)
}

/// Read the current value of POWER.GPREGRET. Diagnostic use only.
pub fn read_gpregret() -> (u8, u8) {
    let gp = pac::POWER.gpregret().read().gpregret();
    let gp2 = pac::POWER.gpregret2().read().gpregret();
    (gp, gp2)
}

/// Write POWER.GPREGRET without triggering a reset. Diagnostic use only —
/// e.g. write then immediately [`read_gpregret`] to verify the write landed.
pub fn write_gpregret(value: u8) {
    pac::POWER.gpregret().write(|w| w.set_gpregret(value));
}

/// Set GPREGRET to an arbitrary value and reset. Intended for diagnostic
/// use only (e.g. sweeping values to probe bootloader behavior). Prefer
/// [`enter_dfu_uf2`] or [`enter_dfu_serial`] for production paths.
///
/// DIVERGES via [`cortex_m::peripheral::SCB::sys_reset`].
pub fn enter_dfu_raw(value: u8) -> ! {
    reset_with_gpregret(value)
}

/// Simulate a physical double-tap reset by writing the Adafruit nRF52
/// UF2 bootloader's retained-RAM magic (`DFU_DBL_RESET_MAGIC = 0x5A1AD5`)
/// to the fixed address `0x20007F7C`, then triggering a system reset.
///
/// **Will not enter DFU.** The Adafruit bootloader only honors this magic
/// when `RESETREAS` indicates a RESET-pin reset. A `SYSRESETREQ` from
/// software sets `RESETREAS.SREQ`, not `RESETREAS.RESETPIN`, so the
/// bootloader ignores the magic and boots the app. This function exists
/// to confirm that path does not work from software — not as a real DFU
/// entry mechanism.
///
/// Verified against Adafruit_nRF52_Bootloader commit 1224915
/// (the T-Echo build): `src/main.c` line 177.
///
/// DIVERGES via [`cortex_m::peripheral::SCB::sys_reset`].
pub fn enter_dfu_dbl_tap_sim() -> ! {
    const DFU_DBL_RESET_MAGIC: u32 = 0x005A_1AD5;
    const DBL_RESET_MEM: *mut u32 = 0x2000_7F7C as *mut u32;
    cortex_m::interrupt::disable();
    unsafe { DBL_RESET_MEM.write_volatile(DFU_DBL_RESET_MAGIC) };
    cortex_m::peripheral::SCB::sys_reset()
}

fn reset_with_gpregret(value: u8) -> ! {
    // Disable all maskable interrupts (CPSID I / PRIMASK) so nothing
    // preempts between the GPREGRET write and the system reset.
    // Without this an in-flight USB / RTC / WDT interrupt can steal
    // AHB bus cycles, causing the bootloader to see a stale GPREGRET.
    // Verified empirically on T-Echo: dsb alone was not sufficient.
    cortex_m::interrupt::disable();
    pac::POWER.gpregret().write(|w| w.set_gpregret(value));
    cortex_m::peripheral::SCB::sys_reset()
}
