//! Enter the nRF52840 System OFF low-power mode with GPIO DETECT wake.
//!
//! System OFF is the deepest sleep state on nRF52840: only retention RAM
//! survives, and the CPU is power-gated. The chip wakes via a reset
//! triggered by one of:
//!
//! - GPIO DETECT signal (PIN_CNF SENSE = HIGH or LOW), this module's path
//! - NFC field, LPCOMP, watchdog, debugger attach
//!
//! Wake-from-OFF is observed by software as a fresh boot — `RESETREAS`
//! reports `OFF` (bit 16). The firmware must therefore restore any state
//! it cares about from non-volatile storage on the cold path.
//!
//! ## Usage
//!
//! ```ignore
//! use umsh_bsp_nrf52840::system_off::{power_off, WakePin, Port};
//! // Wake when the user button on P1.10 goes low (button press, pull-up).
//! power_off(&[WakePin { port: Port::P1, pin: 10 }]);
//! ```
//!
//! The caller is responsible for any pre-shutdown housekeeping (display
//! sleep, peripheral-rail drop, counter flush). This function only
//! configures SENSE on the wake pins and writes `POWER.SYSTEMOFF`.
//!
//! No SoftDevice is in use in the current firmware, so direct register
//! access is correct. If a SoftDevice is ever enabled in this codebase,
//! switch the SYSTEMOFF entry to `sd_power_system_off()` instead.

/// GPIO port for [`WakePin`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Port {
    P0,
    P1,
}

/// Which signal level wakes the chip from System OFF.
///
/// Choose based on the button's active level and pull configuration:
/// - Active-low button with pull-up → [`WakeSense::Low`] (T-Echo P1.10)
/// - Active-high button with pull-down → [`WakeSense::High`] (T1000-E P0.06)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeSense {
    /// Wake when the pin is driven high. PIN_CNF SENSE = 0b10.
    High,
    /// Wake when the pin is driven low. PIN_CNF SENSE = 0b11.
    Low,
}

/// A pin to configure for DETECT-driven wake from System OFF.
///
/// Only the SENSE bits of `PIN_CNF[n]` are modified; the existing DIR /
/// INPUT / PULL / DRIVE bits set by `embassy_nrf::gpio::Input::new(...)`
/// are preserved. The pin must already be configured as an input with the
/// appropriate pull before [`power_off`] is called.
#[derive(Clone, Copy, Debug)]
pub struct WakePin {
    pub port: Port,
    pub pin: u8,
    pub sense: WakeSense,
}

const P0_BASE: usize = 0x5000_0000;
const P1_BASE: usize = 0x5000_0300;
const PIN_CNF_OFFSET: usize = 0x700;
const IN_OFFSET: usize = 0x510;
const OUTSET_OFFSET: usize = 0x508;
const OUTCLR_OFFSET: usize = 0x50C;
const POWER_SYSTEMOFF: *mut u32 = 0x4000_0500 as *mut u32;

const PIN_CNF_SENSE_SHIFT: u32 = 16;
const PIN_CNF_SENSE_MASK: u32 = 0b11 << PIN_CNF_SENSE_SHIFT;
const PIN_CNF_SENSE_HIGH: u32 = 0b10 << PIN_CNF_SENSE_SHIFT;
const PIN_CNF_SENSE_LOW: u32 = 0b11 << PIN_CNF_SENSE_SHIFT;

fn pin_cnf_addr(port: Port, pin: u8) -> *mut u32 {
    let base = match port {
        Port::P0 => P0_BASE,
        Port::P1 => P1_BASE,
    };
    (base + PIN_CNF_OFFSET + (pin as usize) * 4) as *mut u32
}

fn port_base(port: Port) -> usize {
    match port {
        Port::P0 => P0_BASE,
        Port::P1 => P1_BASE,
    }
}

/// Read the current logical level of a pin from the GPIO IN register.
///
/// Works regardless of the pin's DIR/PULL/DRIVE configuration. Useful for
/// polling an input pin during shutdown without holding an `embassy_nrf::gpio`
/// handle (which may have already been tristated or dropped).
pub fn read_pin(port: Port, pin: u8) -> bool {
    let base = port_base(port);
    let in_addr: *const u32 = (base + IN_OFFSET) as *const u32;
    let bits = unsafe { core::ptr::read_volatile(in_addr) };
    (bits >> pin as u32) & 1 != 0
}

/// Drive a pin LOW as a push-pull output. Useful for asserting an
/// active-low peripheral RESET line before entering System OFF, holding
/// the peripheral in reset (lowest-power state) without relying on the
/// peripheral's power rail being switchable.
///
/// Order: clear the OUT bit first (so when DIR becomes output we already
/// drive LOW, not the previous OUT level), then write PIN_CNF =
/// `DIR=output, INPUT=connect, PULL=none, DRIVE=standard, SENSE=disabled`.
pub fn drive_pin_low(port: Port, pin: u8) {
    let base = port_base(port);
    let outclr: *mut u32 = (base + OUTCLR_OFFSET) as *mut u32;
    let cnf_addr = pin_cnf_addr(port, pin);
    unsafe {
        core::ptr::write_volatile(outclr, 1u32 << (pin as u32));
        // DIR=1 (output) at bit 0. All other fields zero.
        core::ptr::write_volatile(cnf_addr, 0x0000_0001);
    }
}

/// Drive a pin HIGH as a push-pull output. Symmetric counterpart to
/// [`drive_pin_low`] for chips whose RESET line is active-high.
pub fn drive_pin_high(port: Port, pin: u8) {
    let base = port_base(port);
    let outset: *mut u32 = (base + OUTSET_OFFSET) as *mut u32;
    let cnf_addr = pin_cnf_addr(port, pin);
    unsafe {
        core::ptr::write_volatile(outset, 1u32 << (pin as u32));
        core::ptr::write_volatile(cnf_addr, 0x0000_0001);
    }
}

/// Tri-state a pin: disconnected input, no pull, no drive.
///
/// Call this on every signal pin that leads to an unpowered peripheral
/// before entering System OFF to prevent reverse-current leakage through
/// ESD protection diodes on the peripheral's unpowered VCC rail.
///
/// Overwrites the full PIN_CNF register. Any prior DIR/PULL/DRIVE/SENSE
/// configuration is discarded — that's intentional since the chip is
/// about to power off.
pub fn tristate_pin(port: Port, pin: u8) {
    let addr = pin_cnf_addr(port, pin);
    // INPUT=disconnect (bit 1 = 1); all other fields zero (DIR=input,
    // PULL=disabled, DRIVE=S0S1, SENSE=disabled).
    unsafe { core::ptr::write_volatile(addr, 0x0000_0002) };
}

/// Configure one pin's SENSE bits for DETECT-driven wake.
///
/// - `WakeSense::Low`  — active-low button with pull-up (e.g. T-Echo P1.10).
/// - `WakeSense::High` — active-high button with pull-down (e.g. T1000-E P0.06).
///
/// Only the SENSE bits are written; DIR/INPUT/PULL/DRIVE are preserved.
pub fn configure_wake(pin: WakePin) {
    let addr = pin_cnf_addr(pin.port, pin.pin);
    let sense_bits = match pin.sense {
        WakeSense::High => PIN_CNF_SENSE_HIGH,
        WakeSense::Low => PIN_CNF_SENSE_LOW,
    };
    // SAFETY: PIN_CNF[n] is a memory-mapped register guaranteed by the
    // datasheet (§22 GPIO). Read-modify-write preserves DIR/INPUT/PULL/DRIVE.
    unsafe {
        let cur = core::ptr::read_volatile(addr);
        let new = (cur & !PIN_CNF_SENSE_MASK) | sense_bits;
        core::ptr::write_volatile(addr, new);
    }
}

/// Convenience wrapper for [`configure_wake`] with [`WakeSense::Low`].
pub fn configure_wake_low(pin: WakePin) {
    configure_wake(WakePin {
        sense: WakeSense::Low,
        ..pin
    });
}

/// Enter System OFF. Diverges — the chip either powers down (and later
/// resets on DETECT) or, when a debugger is attached, behaves like an
/// infinite WFI per the product spec (we still spin to keep the diverging
/// return type honest).
pub fn enter_system_off() -> ! {
    // Mask all maskable interrupts so nothing preempts between the final
    // peripheral state and the SYSTEMOFF write. (Matches the pattern in
    // [`crate::gpregret::reset_with_gpregret`].)
    cortex_m::interrupt::disable();
    // SAFETY: POWER.SYSTEMOFF is a write-only trigger register (§13.1.5
    // POWER Registers, nRF52840 product spec). Writing 1 starts the
    // System OFF sequence.
    unsafe { core::ptr::write_volatile(POWER_SYSTEMOFF, 1) };
    loop {
        cortex_m::asm::nop();
    }
}

/// Configure each pin's SENSE for DETECT wake, then enter System OFF. Diverges.
pub fn power_off(wake_pins: &[WakePin]) -> ! {
    for pin in wake_pins {
        configure_wake(*pin);
    }
    enter_system_off()
}
