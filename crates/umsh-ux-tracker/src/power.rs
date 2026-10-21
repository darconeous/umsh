//! Power intents and supporting state.
//!
//! Defines the [`PowerIntent`] enum that multiple sources (button task,
//! CLI command dispatcher, low-battery monitor, USB-CDC 1200-baud touch
//! handler) submit via an embassy channel to the single `power_task`.
//!
//! This module deliberately stays free of embassy / hardware details so
//! the intent vocabulary and the low-battery shutdown logic can be
//! exercised without a runtime. The dispatch loop that maps intents to
//! `bsp::enter_*` calls lives next to the runtime wiring.

use crate::battery::BatteryThresholds;

/// Things the firmware can decide to do that take the device out of its
/// normal operating state. All variants are terminal—the calling task
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

/// How long the cell must read critical before [`LowBatteryDetector`]
/// fires.
pub const CUTOFF_HOLD_MS: u64 = 5 * 60 * 1_000;

/// Longest gap between two critical readings that still counts as one
/// continuous run. Monitors sample a cell at or below `low_mv` every 30 s,
/// so a longer gap means readings went missing rather than that the cell
/// stayed low.
pub const CUTOFF_MAX_GAP_MS: u64 = 90 * 1_000;

/// The protective low-battery cutoff: emits [`PowerIntent::PowerOff`] once
/// the cell has read at or below `critical_mv` continuously for
/// [`CUTOFF_HOLD_MS`].
///
/// None of the nRF52840 boards has a confirmed hardware undervoltage
/// cutoff that acts before the cell is damaged, so firmware has to.
///
/// External power does not suspend it. VBUS being present says nothing
/// about whether the source carries the load—a solar panel at dawn or
/// under cloud holds VBUS up while the node runs off the cell—and a
/// reading taken under charge current sits above the resting voltage, so
/// a critical reading with VBUS present is, if anything, worse than it
/// looks.
///
/// The run is measured in elapsed time rather than in samples, so
/// on-demand reads and fast powered cadences cannot hurry it, and a gap
/// longer than [`CUTOFF_MAX_GAP_MS`] starts it over.
#[derive(Debug)]
pub struct LowBatteryDetector {
    critical_mv: u16,
    since_ms: Option<u64>,
    last_ms: u64,
    fired: bool,
}

impl LowBatteryDetector {
    pub fn new(thresholds: BatteryThresholds) -> Self {
        Self {
            critical_mv: thresholds.critical_mv,
            since_ms: None,
            last_ms: 0,
            fired: false,
        }
    }

    /// Feed one reading taken at `now_ms` (monotonic). Returns
    /// [`PowerIntent::PowerOff`] the first time the critical run reaches
    /// [`CUTOFF_HOLD_MS`]; subsequent calls return `None` until
    /// [`reset`](Self::reset), so the caller acts on a single fire.
    pub fn observe(&mut self, now_ms: u64, battery_mv: u16) -> Option<PowerIntent> {
        if self.fired {
            return None;
        }

        if battery_mv > self.critical_mv {
            self.since_ms = None;
            return None;
        }

        let since = match self.since_ms {
            Some(since) if now_ms.saturating_sub(self.last_ms) <= CUTOFF_MAX_GAP_MS => since,
            _ => now_ms,
        };
        self.since_ms = Some(since);
        self.last_ms = now_ms;

        if now_ms.saturating_sub(since) >= CUTOFF_HOLD_MS {
            self.fired = true;
            return Some(PowerIntent::PowerOff);
        }
        None
    }

    /// True once the detector has fired and is suppressing further events.
    pub fn fired(&self) -> bool {
        self.fired
    }

    /// Re-arm the detector (clears the fired flag and the current run).
    pub fn reset(&mut self) {
        self.since_ms = None;
        self.fired = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MS: u64 = 30_000;

    fn detector() -> LowBatteryDetector {
        LowBatteryDetector::new(BatteryThresholds::default())
    }

    /// Feed `count` readings `step_ms` apart starting at `start_ms`;
    /// returns the time of the reading that fired, if any.
    fn feed(
        d: &mut LowBatteryDetector,
        start_ms: u64,
        step_ms: u64,
        count: u64,
        mv: u16,
    ) -> Option<u64> {
        (0..count)
            .map(|i| start_ms + i * step_ms)
            .find(|&now| d.observe(now, mv).is_some())
    }

    #[test]
    fn fires_after_the_hold_time() {
        let mut d = detector();
        assert_eq!(
            feed(&mut d, 1_000, SAMPLE_MS, 20, 3_000),
            Some(1_000 + CUTOFF_HOLD_MS)
        );
    }

    #[test]
    fn critical_boundary_matches_classify() {
        // `classify` calls 3100 mV exactly Critical; so does the cutoff.
        let mut d = detector();
        assert!(feed(&mut d, 0, SAMPLE_MS, 20, 3_100).is_some());
        let mut d = detector();
        assert!(feed(&mut d, 0, SAMPLE_MS, 20, 3_101).is_none());
    }

    #[test]
    fn a_good_reading_restarts_the_run() {
        let mut d = detector();
        assert!(feed(&mut d, 0, SAMPLE_MS, 9, 3_000).is_none());
        assert!(d.observe(9 * SAMPLE_MS, 3_200).is_none());
        // The run starts over at the next critical reading.
        let restart = 10 * SAMPLE_MS;
        assert_eq!(
            feed(&mut d, restart, SAMPLE_MS, 20, 3_000),
            Some(restart + CUTOFF_HOLD_MS)
        );
    }

    #[test]
    fn a_long_gap_restarts_the_run() {
        let mut d = detector();
        assert!(feed(&mut d, 0, SAMPLE_MS, 9, 3_000).is_none());
        // Readings went missing for longer than the allowed gap.
        let resume = 8 * SAMPLE_MS + CUTOFF_MAX_GAP_MS + 1;
        assert_eq!(
            feed(&mut d, resume, SAMPLE_MS, 20, 3_000),
            Some(resume + CUTOFF_HOLD_MS)
        );
    }

    #[test]
    fn rapid_readings_do_not_hurry_it() {
        // One reading a second, as a powered cadence or a stream of
        // on-demand reads would give: still five minutes.
        let mut d = detector();
        assert_eq!(feed(&mut d, 0, 1_000, 400, 3_000), Some(CUTOFF_HOLD_MS));
    }

    #[test]
    fn fires_only_once_until_reset() {
        let mut d = detector();
        let fired_at = feed(&mut d, 0, SAMPLE_MS, 20, 3_000).unwrap();
        assert!(d.fired());
        assert!(d.observe(fired_at + SAMPLE_MS, 3_000).is_none());

        d.reset();
        assert!(!d.fired());
        let restart = fired_at + 2 * SAMPLE_MS;
        assert_eq!(
            feed(&mut d, restart, SAMPLE_MS, 20, 3_000),
            Some(restart + CUTOFF_HOLD_MS)
        );
    }
}
