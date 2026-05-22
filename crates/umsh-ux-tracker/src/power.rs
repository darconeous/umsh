//! Power intents and supporting state.
//!
//! Defines the [`PowerIntent`] enum that multiple sources (button task,
//! CLI command dispatcher, low-battery monitor, USB-CDC 1200-baud touch
//! handler) submit via an embassy channel to the single `power_task` —
//! see `docs/firmware-plan-t1000e.md` for the safety contract.
//!
//! This module deliberately stays free of embassy / hardware details so
//! the intent vocabulary and the low-battery shutdown logic can be
//! exercised without a runtime. The dispatch loop that maps intents to
//! `bsp::enter_*` calls lives next to the runtime wiring.

/// Things the firmware can decide to do that take the device out of its
/// normal operating state. All variants are terminal — the calling task
/// must assume the device will be reset or powered off shortly after
/// the intent is delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerIntent {
    /// Enter nRF52840 System OFF; wake on button press.
    PowerOff,
    /// Reset into the Adafruit bootloader's UF2 mass-storage DFU mode
    /// (`GPREGRET = 0x57`).
    EnterDfuUf2,
    /// Reset into the bootloader's serial / CDC DFU mode
    /// (`GPREGRET = 0x4e`). Required by the WebSerial-based MeshCore
    /// flasher and by `adafruit-nrfutil --touch 1200`.
    EnterDfuSerial,
    /// Plain warm reset back into the running firmware.
    Reboot,
}

/// Why a [`PowerIntent`] was submitted. Useful for logging and
/// post-mortem reporting via the persisted panic / event log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerIntentSource {
    /// User long-pressed the button.
    ButtonLongPress,
    /// User typed a CLI command.
    CliCommand,
    /// Low-battery monitor decided the cell needs to be protected.
    LowBattery,
    /// USB host did the 1200-baud DTR-drop dance.
    UsbCdc1200BaudTouch,
    /// USB-CDC rescue escape sequence.
    UsbCdcRescueEscape,
}

/// Tracks consecutive low-battery samples and emits a [`PowerIntent::PowerOff`]
/// once the streak crosses the configured threshold while the device is
/// not USB-powered.
///
/// Matches the Meshtastic behavior documented in
/// `docs/t1000e-hardware.md`: the T1000-E has no confirmed hardware
/// undervoltage cutoff, so firmware must protect the Li-ion cell by
/// shutting down before the voltage falls too far below the OCV table's
/// 3.1 V floor.
#[derive(Debug)]
pub struct LowBatteryDetector {
    threshold_mv: u16,
    streak_required: u8,
    streak: u8,
    fired: bool,
}

impl LowBatteryDetector {
    /// Create a detector. `threshold_mv` is the floor (samples strictly
    /// below this count toward the streak); `streak_required` is the
    /// number of consecutive low samples while not USB-powered needed
    /// to fire.
    pub fn new(threshold_mv: u16, streak_required: u8) -> Self {
        debug_assert!(streak_required > 0);
        Self {
            threshold_mv,
            streak_required,
            streak: 0,
            fired: false,
        }
    }

    /// Default per the T1000-E plan: 3.1 V floor, 10-sample streak.
    pub fn t1000e_default() -> Self {
        Self::new(3_100, 10)
    }

    /// Feed one sample. Returns [`PowerIntent::PowerOff`] the first
    /// time the streak crosses the threshold; subsequent calls return
    /// `None` until [`reset`](Self::reset) is called. This lets the
    /// power task act on a single fire and ignore further samples
    /// while it tears down.
    pub fn observe(&mut self, sample_mv: u16, usb_powered: bool) -> Option<PowerIntent> {
        if self.fired {
            return None;
        }

        // USB powering the board: streak is invalid (battery reading
        // may be conditioned by charge current); reset and report
        // nothing.
        if usb_powered {
            self.streak = 0;
            return None;
        }

        if sample_mv < self.threshold_mv {
            self.streak = self.streak.saturating_add(1);
            if self.streak >= self.streak_required {
                self.fired = true;
                return Some(PowerIntent::PowerOff);
            }
        } else {
            self.streak = 0;
        }

        None
    }

    /// Number of consecutive low-while-on-battery samples seen so far.
    pub fn streak(&self) -> u8 {
        self.streak
    }

    /// True once the detector has fired and is suppressing further events.
    pub fn fired(&self) -> bool {
        self.fired
    }

    /// Re-arm the detector (clears the fired flag and the streak).
    pub fn reset(&mut self) {
        self.streak = 0;
        self.fired = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streak_fires_at_threshold() {
        let mut d = LowBatteryDetector::new(3_100, 3);
        assert!(d.observe(3_000, false).is_none());
        assert!(d.observe(3_000, false).is_none());
        assert_eq!(d.observe(3_000, false), Some(PowerIntent::PowerOff));
    }

    #[test]
    fn good_sample_resets_streak() {
        let mut d = LowBatteryDetector::new(3_100, 3);
        d.observe(3_000, false);
        d.observe(3_000, false);
        // Single good sample resets.
        assert!(d.observe(3_500, false).is_none());
        assert_eq!(d.streak(), 0);
        // Need a fresh streak of 3.
        d.observe(3_000, false);
        d.observe(3_000, false);
        assert_eq!(d.observe(3_000, false), Some(PowerIntent::PowerOff));
    }

    #[test]
    fn usb_powered_resets_streak() {
        let mut d = LowBatteryDetector::new(3_100, 3);
        d.observe(3_000, false);
        d.observe(3_000, false);
        // Plugging in resets even if voltage is still low.
        assert!(d.observe(3_000, true).is_none());
        assert_eq!(d.streak(), 0);
        // Unplug + low: streak begins again, doesn't carry over.
        d.observe(3_000, false);
        d.observe(3_000, false);
        assert_eq!(d.observe(3_000, false), Some(PowerIntent::PowerOff));
    }

    #[test]
    fn boundary_at_threshold_is_not_low() {
        let mut d = LowBatteryDetector::new(3_100, 1);
        // 3100 mV exactly is the floor, not strictly below it.
        assert!(d.observe(3_100, false).is_none());
        // 3099 fires.
        assert_eq!(d.observe(3_099, false), Some(PowerIntent::PowerOff));
    }

    #[test]
    fn fires_only_once_until_reset() {
        let mut d = LowBatteryDetector::new(3_100, 1);
        assert_eq!(d.observe(3_000, false), Some(PowerIntent::PowerOff));
        // Further samples ignored.
        assert!(d.observe(3_000, false).is_none());
        assert!(d.observe(3_500, false).is_none());
        assert!(d.fired());

        d.reset();
        assert!(!d.fired());
        assert_eq!(d.observe(3_000, false), Some(PowerIntent::PowerOff));
    }

    #[test]
    fn t1000e_default_matches_plan() {
        let d = LowBatteryDetector::t1000e_default();
        // 3.1 V floor, 10 consecutive samples.
        let mut d = d;
        for _ in 0..9 {
            assert!(d.observe(3_099, false).is_none());
        }
        assert_eq!(d.observe(3_099, false), Some(PowerIntent::PowerOff));
    }
}
