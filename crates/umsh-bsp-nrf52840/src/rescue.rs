//! USB-CDC DFU rescue paths.
//!
//! Two low-level mechanisms for getting the device into DFU mode
//! independent of the CLI session, per the safety contract in
//! `docs/firmware-plan-t1000e.md`:
//!
//! - [`TouchlessResetWatcher`] — watches CDC control requests for the
//!   1200-baud touchless reset (host opens port at 1200 baud and then
//!   drops DTR). This is how `flasher.meshcore.co.uk` and
//!   `adafruit-nrfutil --touch 1200` trigger DFU. The Adafruit nRF52
//!   bootloader does **not** implement this; firmware is responsible.
//!
//! - [`EscapeWatcher`] — observes the inbound byte stream and fires
//!   when the magic sequence `Ctrl-C Ctrl-C Ctrl-C dfu\r` appears.
//!   Used when the CLI parser is wedged (panicked task, deadlocked
//!   channel, mis-parsed mode) so a human at a terminal can still
//!   force DFU.
//!
//! Both mechanisms run *below* the CLI parser so a hung or
//! mis-configured CLI can't block them. The escape watcher
//! deliberately observes without consuming, so the CLI parser still
//! sees all bytes — Ctrl-C continues to mean "abort" to the CLI even
//! while the rescue prefix accumulates.

/// What a watcher decided to do as a result of an input event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RescueAction {
    /// No action this event.
    None,
    /// Caller should immediately invoke `bsp::enter_dfu_serial()`
    /// (GPREGRET = `0x4e`). The web flasher requires serial DFU mode
    /// because WebSerial cannot speak to a mass-storage device.
    TriggerDfuSerial,
}

/// Watcher for the 1200-baud touchless reset.
///
/// Track CDC `SET_LINE_CODING` (baud rate) and
/// `SET_CONTROL_LINE_STATE` (DTR / RTS) events. When the host opens
/// the port at 1200 baud and then drops DTR, return
/// [`RescueAction::TriggerDfuSerial`] so the caller can put the
/// device into serial DFU mode.
///
/// The watcher self-suppresses after firing — once
/// [`TouchlessResetWatcher::fired`] is true, subsequent events return
/// `None` until [`TouchlessResetWatcher::reset`] is called. In normal
/// operation the BSP's `enter_dfu_serial()` diverges so the
/// suppression is moot; it exists for defensive symmetry and
/// testability.
#[derive(Debug)]
pub struct TouchlessResetWatcher {
    baud: u32,
    dtr: bool,
    fired: bool,
}

impl Default for TouchlessResetWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl TouchlessResetWatcher {
    /// Construct with the conventional power-on assumption: baud
    /// 115200, DTR low (host has not yet opened the port).
    pub const fn new() -> Self {
        Self {
            baud: 115_200,
            dtr: false,
            fired: false,
        }
    }

    /// Notify of a CDC `SET_LINE_CODING` request.
    pub fn on_line_coding(&mut self, baud: u32) -> RescueAction {
        self.baud = baud;
        RescueAction::None
    }

    /// Notify of a CDC `SET_CONTROL_LINE_STATE` request. Only `dtr`
    /// is consulted; `rts` is accepted for API completeness but
    /// ignored, since the Arduino-ecosystem 1200-baud convention is
    /// DTR-driven.
    pub fn on_control_line_state(&mut self, dtr: bool, _rts: bool) -> RescueAction {
        let was_high = self.dtr;
        self.dtr = dtr;
        if was_high && !dtr && self.baud == 1_200 && !self.fired {
            self.fired = true;
            return RescueAction::TriggerDfuSerial;
        }
        RescueAction::None
    }

    pub fn fired(&self) -> bool {
        self.fired
    }

    pub fn reset(&mut self) {
        self.fired = false;
    }
}

/// Observes inbound CDC bytes for the rescue prefix
/// `Ctrl-C Ctrl-C Ctrl-C dfu` followed by `\r` or `\n`. On match,
/// returns [`RescueAction::TriggerDfuSerial`] so the caller can put the
/// device into serial DFU mode independent of the CLI session.
///
/// The watcher is *non-consuming*: callers should hand each received
/// byte to [`EscapeWatcher::observe`] before passing it to the CLI
/// parser, not instead of. This preserves Ctrl-C's "abort" semantics
/// inside the CLI.
#[derive(Debug)]
pub struct EscapeWatcher {
    state: EscapeState,
    fired: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeState {
    Idle,
    Ctrl1,
    Ctrl2,
    Armed,
    GotD,
    GotDf,
    GotDfu,
}

const CTRL_C: u8 = 0x03;

impl Default for EscapeWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl EscapeWatcher {
    pub const fn new() -> Self {
        Self {
            state: EscapeState::Idle,
            fired: false,
        }
    }

    /// Feed one received byte. Returns `TriggerDfuSerial` exactly once
    /// on completion of the magic sequence; further bytes return `None`
    /// until [`reset`](Self::reset) is called.
    pub fn observe(&mut self, byte: u8) -> RescueAction {
        if self.fired {
            return RescueAction::None;
        }

        self.state = match (self.state, byte) {
            // Building up the Ctrl-C prefix.
            (EscapeState::Idle, CTRL_C) => EscapeState::Ctrl1,
            (EscapeState::Ctrl1, CTRL_C) => EscapeState::Ctrl2,
            (EscapeState::Ctrl2, CTRL_C) => EscapeState::Armed,

            // Armed: matching "dfu".
            (EscapeState::Armed, b'd') => EscapeState::GotD,
            (EscapeState::GotD, b'f') => EscapeState::GotDf,
            (EscapeState::GotDf, b'u') => EscapeState::GotDfu,

            // Terminator after "dfu" — fire.
            (EscapeState::GotDfu, b'\r') | (EscapeState::GotDfu, b'\n') => {
                self.fired = true;
                self.state = EscapeState::Idle;
                return RescueAction::TriggerDfuSerial;
            }

            // Anything else in a Ctrl-prefix or armed sub-state resets,
            // but a Ctrl-C in those positions restarts the prefix
            // (so e.g. four Ctrl-Cs still arms after the third).
            (_, CTRL_C) => EscapeState::Ctrl1,
            _ => EscapeState::Idle,
        };
        RescueAction::None
    }

    /// Convenience: observe every byte in a slice.
    pub fn observe_slice(&mut self, bytes: &[u8]) -> RescueAction {
        for &b in bytes {
            if let RescueAction::TriggerDfuSerial = self.observe(b) {
                return RescueAction::TriggerDfuSerial;
            }
        }
        RescueAction::None
    }

    pub fn fired(&self) -> bool {
        self.fired
    }

    pub fn reset(&mut self) {
        self.state = EscapeState::Idle;
        self.fired = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(w: &mut TouchlessResetWatcher, baud: u32) {
        w.on_line_coding(baud);
        w.on_control_line_state(true, true);
    }

    fn close(w: &mut TouchlessResetWatcher) -> RescueAction {
        w.on_control_line_state(false, false)
    }

    #[test]
    fn default_does_not_fire() {
        let w = TouchlessResetWatcher::new();
        assert!(!w.fired());
    }

    #[test]
    fn normal_open_close_does_not_fire() {
        let mut w = TouchlessResetWatcher::new();
        open(&mut w, 115_200);
        assert_eq!(close(&mut w), RescueAction::None);
        assert!(!w.fired());
    }

    #[test]
    fn open_at_1200_then_close_fires() {
        let mut w = TouchlessResetWatcher::new();
        open(&mut w, 1_200);
        assert_eq!(close(&mut w), RescueAction::TriggerDfuSerial);
        assert!(w.fired());
    }

    #[test]
    fn change_to_1200_then_close_fires() {
        // Open at 115200, then change baud to 1200, then close.
        let mut w = TouchlessResetWatcher::new();
        open(&mut w, 115_200);
        w.on_line_coding(1_200);
        assert_eq!(close(&mut w), RescueAction::TriggerDfuSerial);
    }

    #[test]
    fn change_away_from_1200_before_close_does_not_fire() {
        // Open at 1200, change to 115200, close.
        let mut w = TouchlessResetWatcher::new();
        open(&mut w, 1_200);
        w.on_line_coding(115_200);
        assert_eq!(close(&mut w), RescueAction::None);
    }

    #[test]
    fn dtr_drop_without_prior_assertion_does_not_fire() {
        // Adversarial sequence: SET_LINE_CODING(1200) then immediate
        // DTR=false without a prior DTR=true. There was no falling
        // edge from "open" to "close" — host never opened the port.
        let mut w = TouchlessResetWatcher::new();
        w.on_line_coding(1_200);
        assert_eq!(close(&mut w), RescueAction::None);
        assert!(!w.fired());
    }

    #[test]
    fn fires_only_once_until_reset() {
        let mut w = TouchlessResetWatcher::new();
        open(&mut w, 1_200);
        assert_eq!(close(&mut w), RescueAction::TriggerDfuSerial);
        // Reopen at 1200 and reclose; should NOT fire again until reset.
        open(&mut w, 1_200);
        assert_eq!(close(&mut w), RescueAction::None);

        w.reset();
        open(&mut w, 1_200);
        assert_eq!(close(&mut w), RescueAction::TriggerDfuSerial);
    }

    #[test]
    fn dtr_high_to_high_is_not_a_close() {
        // Host setting DTR=true multiple times without a drop in between
        // must not be misinterpreted.
        let mut w = TouchlessResetWatcher::new();
        w.on_line_coding(1_200);
        w.on_control_line_state(true, false);
        assert_eq!(w.on_control_line_state(true, true), RescueAction::None);
        assert!(!w.fired());
    }

    #[test]
    fn rts_changes_are_ignored() {
        // Toggling RTS while DTR stays high should not affect anything.
        let mut w = TouchlessResetWatcher::new();
        w.on_line_coding(1_200);
        w.on_control_line_state(true, false);
        assert_eq!(w.on_control_line_state(true, true), RescueAction::None);
        assert_eq!(w.on_control_line_state(true, false), RescueAction::None);
    }

    // ---------- EscapeWatcher tests ----------

    const MAGIC: &[u8] = b"\x03\x03\x03dfu\r";

    #[test]
    fn escape_default_does_not_fire() {
        let w = EscapeWatcher::new();
        assert!(!w.fired());
    }

    #[test]
    fn escape_magic_sequence_fires() {
        let mut w = EscapeWatcher::new();
        assert_eq!(w.observe_slice(MAGIC), RescueAction::TriggerDfuSerial);
        assert!(w.fired());
    }

    #[test]
    fn escape_magic_sequence_with_lf_fires() {
        let mut w = EscapeWatcher::new();
        assert_eq!(
            w.observe_slice(b"\x03\x03\x03dfu\n"),
            RescueAction::TriggerDfuSerial
        );
    }

    #[test]
    fn escape_random_bytes_do_not_fire() {
        let mut w = EscapeWatcher::new();
        assert_eq!(w.observe_slice(b"hello world\r\n"), RescueAction::None);
        assert!(!w.fired());
    }

    #[test]
    fn escape_two_ctrl_c_then_other_resets() {
        let mut w = EscapeWatcher::new();
        w.observe_slice(b"\x03\x03x");
        // Now the full magic sequence should still work afterwards.
        assert_eq!(w.observe_slice(MAGIC), RescueAction::TriggerDfuSerial);
    }

    #[test]
    fn escape_three_ctrl_c_then_wrong_command_resets() {
        let mut w = EscapeWatcher::new();
        assert_eq!(w.observe_slice(b"\x03\x03\x03nope\r"), RescueAction::None);
        // Re-attempt with the right sequence should still work.
        assert_eq!(w.observe_slice(MAGIC), RescueAction::TriggerDfuSerial);
    }

    #[test]
    fn escape_is_case_sensitive() {
        // Uppercase DFU should NOT trigger.
        let mut w = EscapeWatcher::new();
        assert_eq!(w.observe_slice(b"\x03\x03\x03DFU\r"), RescueAction::None);
    }

    #[test]
    fn escape_extra_ctrl_c_after_arm_restarts_prefix() {
        // Four Ctrl-Cs in a row: the fourth lands us back in Ctrl1
        // (so the prefix is partially re-built rather than completely
        // lost), then we still need two more Ctrl-Cs to re-arm.
        let mut w = EscapeWatcher::new();
        w.observe_slice(b"\x03\x03\x03\x03"); // 4 Ctrl-Cs
        // Currently in Ctrl1 (4th Ctrl-C reset from Armed back to Ctrl1).
        // Need two more Ctrl-Cs to re-arm.
        assert_eq!(
            w.observe_slice(b"\x03\x03dfu\r"),
            RescueAction::TriggerDfuSerial
        );
    }

    #[test]
    fn escape_magic_in_middle_of_stream_fires() {
        let mut w = EscapeWatcher::new();
        let stream = b"some other text\x03\x03\x03dfu\r more stuff";
        assert_eq!(w.observe_slice(stream), RescueAction::TriggerDfuSerial);
    }

    #[test]
    fn escape_fires_only_once_until_reset() {
        let mut w = EscapeWatcher::new();
        assert_eq!(w.observe_slice(MAGIC), RescueAction::TriggerDfuSerial);
        assert_eq!(w.observe_slice(MAGIC), RescueAction::None);

        w.reset();
        assert_eq!(w.observe_slice(MAGIC), RescueAction::TriggerDfuSerial);
    }

    #[test]
    fn escape_observes_individual_bytes() {
        let mut w = EscapeWatcher::new();
        let mut fired = false;
        for &b in MAGIC {
            if let RescueAction::TriggerDfuSerial = w.observe(b) {
                fired = true;
            }
        }
        assert!(fired);
    }
}
