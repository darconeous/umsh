//! Enter the nRF52840 System OFF low-power mode with GPIO DETECT wake.
//!
//! System OFF is the deepest sleep state on nRF52840: only retention RAM
//! survives, and the CPU is power-gated. The chip wakes via a reset
//! triggered by one of:
//!
//! - GPIO DETECT signal (PIN_CNF SENSE = HIGH or LOW), this module's
//!   [`power_off`] path
//! - the LPCOMP analog comparator, this module's [`arm_lpcomp_wake_up`]
//!   path — the wake a board with no button still gets, and the one that
//!   brings a solar node back when its cell recharges
//! - NFC field, watchdog, debugger attach
//!
//! Wake-from-OFF is observed by software as a fresh boot — `RESETREAS`
//! reports `OFF` (bit 16), plus `LPCOMP` (bit 17) when the comparator was
//! the trigger. The firmware must therefore restore any state it cares
//! about from non-volatile storage on the cold path.
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

/// Why a board is powering down.
///
/// Boards whose teardown differs between the two cases take this from
/// their `SHUTDOWN_SIGNAL`. The distinction that matters is battery
/// recovery: a node that shut down because its cell went flat should come
/// back when the cell recharges ([`arm_lpcomp_wake_up`]), while a node the
/// user turned off should stay off until the user turns it back on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownReason {
    /// A deliberate power-off: a button gesture, the host API, or a remote
    /// command. Arms only the board's usual user-facing wake sources.
    Requested,
    /// The protective low-battery cutoff. Arms battery-recovery wake on
    /// boards that support it.
    BatteryCritical,
}

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

/// Pull resistor to apply when fully configuring a GPIO wake input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakePull {
    None,
    Down,
    Up,
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
const LATCH_OFFSET: usize = 0x520;
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

fn pull_cnf_bits(pull: WakePull) -> u32 {
    (match pull {
        WakePull::None => 0b00,
        WakePull::Down => 0b01,
        WakePull::Up => 0b11,
    }) << 2
}

/// Fully configure a wake pin as a connected GPIO input. Unlike
/// [`configure_wake`], this does not preserve state left by an asynchronous
/// GPIO waiter; use it when another task may have reconfigured SENSE or INPUT
/// immediately before shutdown.
pub fn configure_wake_input(pin: WakePin, pull: WakePull) {
    let addr = pin_cnf_addr(pin.port, pin.pin);
    let sense_bits = match pin.sense {
        WakeSense::High => PIN_CNF_SENSE_HIGH,
        WakeSense::Low => PIN_CNF_SENSE_LOW,
    };
    // DIR=input, INPUT=connect, standard drive, requested pull and SENSE.
    unsafe { core::ptr::write_volatile(addr, pull_cnf_bits(pull) | sense_bits) };
}

/// Connect a pin's input buffer with the requested pull and SENSE disabled,
/// so [`read_pin`] returns the physical level. Needed before polling a pin
/// whose configuration may still be at the reset value (input buffer
/// disconnected — the IN register then reads 0 regardless of the pad).
pub fn connect_input(port: Port, pin: u8, pull: WakePull) {
    let addr = pin_cnf_addr(port, pin);
    // DIR=input, INPUT=connect, standard drive, requested pull, SENSE off.
    unsafe { core::ptr::write_volatile(addr, pull_cnf_bits(pull)) };
}

/// Convenience wrapper for [`configure_wake`] with [`WakeSense::Low`].
pub fn configure_wake_low(pin: WakePin) {
    configure_wake(WakePin {
        sense: WakeSense::Low,
        ..pin
    });
}

pub use embassy_nrf::pac::lpcomp::vals::{PselPsel as LpcompInput, Refsel as LpcompReference};

/// Arm LPCOMP as a System OFF wake source: the chip wakes — resets, with
/// `RESETREAS.LPCOMP` (bit 17) set alongside `OFF` — when `input` crosses
/// *upward* through `reference`, with 50 mV of hysteresis.
///
/// This is the battery-recovery wake. Point `input` at the board's battery
/// divider tap and pick the `reference` fraction that puts the crossing at
/// a cell voltage the node can actually run on; a node that shut itself
/// down on a flat cell then comes back by itself once solar or a charger
/// has refilled it, with no button and no cable.
///
/// Call immediately before [`enter_system_off`] or [`power_off`]. The two
/// wake mechanisms are independent — a board can arm button DETECT and
/// LPCOMP at once and be woken by whichever happens first.
///
/// Caveats:
///
/// - `reference` must be one of the VDD fractions; this helper does not
///   configure `EXTREFSEL`, so [`LpcompReference::ARef`] would compare
///   against whatever that register happens to hold.
/// - The reference is *relative to VDD*, so the absolute threshold moves
///   with the rail. On a board whose regulator holds VDD at 3.3 V this is
///   benign: while the regulator is in dropout VDD tracks the cell and the
///   tap sits below the fraction, so the comparator cannot trip until the
///   rail is back in regulation — one effective wake point. Boards running
///   the core straight off the cell must reason about this themselves.
/// - `input`'s pin must be left tri-stated, not driven. The comparator
///   reaches the pad through the analog mux, so `PIN_CNF`'s input buffer is
///   irrelevant, but a driven output would fight the divider.
/// - The divider feeding the pin must stay powered through System OFF —
///   which usually means leaving its gate driven, since a board that raises
///   the gate to save the divider's quiescent draw has nothing left to
///   compare.
pub fn arm_lpcomp_wake_up(input: LpcompInput, reference: LpcompReference) {
    use embassy_nrf::pac;
    use embassy_nrf::pac::lpcomp::vals::{Anadetect, Enable};

    let lpcomp = pac::LPCOMP;

    // Configuration registers only take effect on a disabled comparator,
    // and nothing else in the firmware touches LPCOMP, so this is belt and
    // braces against arriving here twice.
    lpcomp.enable().write(|w| w.set_enable(Enable::Disabled));

    lpcomp.psel().write(|w| w.set_psel(input));
    lpcomp.refsel().write(|w| w.set_refsel(reference));
    // Upward crossings only. A tap that is somehow already above the
    // threshold at entry does not wake, and a cell continuing to decay
    // produces a DOWN crossing, which this ignores.
    lpcomp.anadetect().write(|w| w.set_anadetect(Anadetect::Up));
    // 50 mV at the comparator input — enough that ripple on a recovering
    // cell doesn't chatter across the threshold.
    lpcomp.hyst().write(|w| w.set_hyst(true));

    lpcomp.enable().write(|w| w.set_enable(Enable::Enabled));
    lpcomp.tasks_start().write_value(1);

    // Startup is tens of microseconds. Bound the spin anyway: if READY
    // never arrives we fall through and enter System OFF unarmed, which is
    // just the old behavior — far better than hanging with the radio down
    // and the battery flat.
    for _ in 0..100_000u32 {
        if lpcomp.events_ready().read() != 0 {
            break;
        }
    }

    // Clear every event so nothing stale is latched into the armed state.
    lpcomp.events_ready().write_value(0);
    lpcomp.events_up().write_value(0);
    lpcomp.events_down().write_value(0);
    lpcomp.events_cross().write_value(0);

    // No INTENSET and no ISR: the System OFF wake rides the ANADETECT
    // signal into the power controller, not the interrupt path.
}

/// Enter System OFF. Diverges — the chip either powers down (and later
/// resets on DETECT) or, when a debugger is attached, behaves like an
/// infinite WFI per the product spec (we still spin to keep the diverging
/// return type honest).
///
/// Clears both ports' `LATCH` immediately before the trigger. `embassy-nrf`
/// puts the GPIOs in LDETECT mode, where the wake signal is derived from
/// `LATCH` rather than from live pin state, so a bit left set by an earlier
/// asynchronous pin wait holds that signal asserted — and writing
/// `SYSTEMOFF` with it asserted resets the chip instead of powering it down.
pub fn enter_system_off() -> ! {
    // Mask all maskable interrupts so nothing preempts between the final
    // peripheral state and the SYSTEMOFF write. (Matches the pattern in
    // [`crate::gpregret::reset_with_gpregret`].)
    cortex_m::interrupt::disable();
    // With interrupts masked the GPIOTE port handler can no longer drain
    // LATCH, so this is the last chance to clear it. Bits are cleared by
    // writing ones. A wake condition that is genuinely asserted right now
    // re-sets its bit within the cycle, which is the intended wake rather
    // than a race.
    for base in [P0_BASE, P1_BASE] {
        // SAFETY: LATCH is a memory-mapped W1C register at GPIO base +
        // 0x520 (§22 GPIO, nRF52840 product spec).
        unsafe { core::ptr::write_volatile((base + LATCH_OFFSET) as *mut u32, 0xFFFF_FFFF) };
    }
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
