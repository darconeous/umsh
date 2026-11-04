//! Completion of the STOP requested by embassy-nrf 0.11's error path, and
//! the stop and bus clear that recover a controller whose transaction was
//! abandoned mid-transfer.

const POLL_LIMIT: usize = 100_000;

/// Eight data bits and an acknowledge: enough clocks to walk any target
/// out of whatever octet it was in the middle of.
const CLEAR_CLOCKS: usize = 9;

pub(crate) trait StopEvents {
    fn error_pending(&self) -> bool;
    fn suspended(&self) -> bool;
    fn stopped(&mut self) -> bool;
    fn resume_and_stop(&mut self);
    fn acknowledge_stop(&mut self);
}

/// The open-drain lines of a bus whose controller has handed them back to
/// GPIO.
pub(crate) trait BusLines {
    fn release_scl(&mut self);
    fn pull_scl(&mut self);
    fn release_sda(&mut self);
    fn pull_sda(&mut self);
    fn sda_high(&self) -> bool;
    /// Half of one bus clock period.
    fn half_clock(&mut self);
}

/// False means shutdown was not confirmed: the caller must disable the
/// controller before returning the borrowed buffers or releasing the
/// controller's mutex.
pub(crate) fn finish_error_stop(registers: &mut impl StopEvents) -> bool {
    // async_wait clears ERROR when it requests STOP and returns the error.
    // If STOPPED wins first, async_wait consumes STOPPED, leaves ERROR set,
    // and check_operations reports the error. That branch is already done.
    // SUSPENDED is a third completion path; unlike STOPPED, it is not cleared
    // by async_wait and needs an explicit resume/stop sequence here.
    if registers.error_pending() && !registers.suspended() {
        return true;
    }
    if registers.suspended() {
        registers.resume_and_stop();
    }
    wait_stopped(registers)
}

/// Stop a transfer nobody is waiting for any more. Whether it was
/// running, suspended, or already finished, resume-then-stop ends it.
/// False means STOPPED never arrived—typically because SCL is held low
/// and the controller cannot clock the STOP out.
pub(crate) fn stop_abandoned(registers: &mut impl StopEvents) -> bool {
    registers.resume_and_stop();
    wait_stopped(registers)
}

/// Free a bus a target is holding mid-octet: clock SCL until the target
/// lets go of SDA, then issue a STOP so every target sees the bus idle.
/// False means SDA is still low afterward.
pub(crate) fn clear_bus(lines: &mut impl BusLines) -> bool {
    lines.release_sda();
    lines.release_scl();
    lines.half_clock();
    for _ in 0..CLEAR_CLOCKS {
        if lines.sda_high() {
            break;
        }
        lines.pull_scl();
        lines.half_clock();
        lines.release_scl();
        lines.half_clock();
    }
    // SDA falling then rising while SCL is high: a START, then the STOP.
    lines.pull_sda();
    lines.half_clock();
    lines.release_sda();
    lines.half_clock();
    lines.sda_high()
}

fn wait_stopped(registers: &mut impl StopEvents) -> bool {
    for _ in 0..POLL_LIMIT {
        if registers.stopped() {
            registers.acknowledge_stop();
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Events {
        error: bool,
        suspended: bool,
        stop_after: Option<usize>,
        polls: usize,
        resumed: bool,
        acknowledged: bool,
    }

    impl StopEvents for Events {
        fn error_pending(&self) -> bool {
            self.error
        }
        fn suspended(&self) -> bool {
            self.suspended
        }
        fn stopped(&mut self) -> bool {
            self.polls += 1;
            self.stop_after.is_some_and(|n| self.polls > n)
        }
        fn resume_and_stop(&mut self) {
            self.resumed = true;
        }
        fn acknowledge_stop(&mut self) {
            self.acknowledged = true;
        }
    }

    fn events(error: bool, suspended: bool, stop_after: Option<usize>) -> Events {
        Events {
            error,
            suspended,
            stop_after,
            polls: 0,
            resumed: false,
            acknowledged: false,
        }
    }

    #[test]
    fn nack_waits_for_delayed_stop_before_controller_reuse() {
        for delay in [0, 1, 20] {
            let mut r = events(false, false, Some(delay));
            assert!(finish_error_stop(&mut r));
            assert_eq!(r.polls, delay + 1);
            assert!(r.acknowledged);
            assert!(!r.resumed);
        }
    }

    #[test]
    fn stop_already_consumed_by_hal_does_not_wait_for_another_event() {
        let mut r = events(true, false, None);
        assert!(finish_error_stop(&mut r));
        assert_eq!(r.polls, 0);
        assert!(!r.resumed);
    }

    #[test]
    fn suspended_error_is_resumed_and_stopped_before_returning() {
        for error in [false, true] {
            let mut r = events(error, true, Some(3));
            assert!(finish_error_stop(&mut r));
            assert!(r.resumed && r.acknowledged);
            assert_eq!(r.polls, 4);
        }
    }

    #[test]
    fn missing_stop_is_reported_after_a_bounded_wait() {
        let mut r = events(false, false, None);
        assert!(!finish_error_stop(&mut r));
        assert_eq!(r.polls, POLL_LIMIT);
        assert!(!r.acknowledged);
    }

    #[test]
    fn an_abandoned_transfer_is_resumed_and_stopped_whatever_its_state() {
        for suspended in [false, true] {
            let mut r = events(false, suspended, Some(2));
            assert!(stop_abandoned(&mut r));
            assert!(r.resumed && r.acknowledged);
        }
        let mut r = events(false, false, None);
        assert!(!stop_abandoned(&mut r));
        assert_eq!(r.polls, POLL_LIMIT);
        assert!(!r.acknowledged);
    }

    /// A target that holds SDA low until it has seen `holds_for` clocks,
    /// or forever.
    struct Lines {
        holds_for: Option<usize>,
        scl_low: bool,
        sda_pulled: bool,
        clocks: usize,
        /// SDA falling and rising while SCL was high.
        starts: usize,
        stops: usize,
    }

    impl Lines {
        fn new(holds_for: Option<usize>) -> Self {
            Self {
                holds_for,
                scl_low: false,
                sda_pulled: false,
                clocks: 0,
                starts: 0,
                stops: 0,
            }
        }
        fn target_holds_sda(&self) -> bool {
            self.holds_for.is_none_or(|n| self.clocks < n)
        }
    }

    impl BusLines for Lines {
        fn release_scl(&mut self) {
            if self.scl_low {
                self.clocks += 1;
            }
            self.scl_low = false;
        }
        fn pull_scl(&mut self) {
            self.scl_low = true;
        }
        fn release_sda(&mut self) {
            if self.sda_pulled && !self.scl_low {
                self.stops += 1;
            }
            self.sda_pulled = false;
        }
        fn pull_sda(&mut self) {
            if !self.sda_pulled && !self.scl_low {
                self.starts += 1;
            }
            self.sda_pulled = true;
        }
        fn sda_high(&self) -> bool {
            !self.sda_pulled && !self.target_holds_sda()
        }
        fn half_clock(&mut self) {}
    }

    #[test]
    fn an_idle_bus_gets_only_a_stop() {
        let mut lines = Lines::new(Some(0));
        assert!(clear_bus(&mut lines));
        assert_eq!(lines.clocks, 0);
        assert_eq!((lines.starts, lines.stops), (1, 1));
    }

    #[test]
    fn a_target_holding_sda_is_clocked_until_it_lets_go() {
        for holds_for in 1..=CLEAR_CLOCKS {
            let mut lines = Lines::new(Some(holds_for));
            assert!(clear_bus(&mut lines));
            assert_eq!(lines.clocks, holds_for);
            assert_eq!((lines.starts, lines.stops), (1, 1));
            assert!(!lines.scl_low);
        }
    }

    #[test]
    fn a_line_held_low_for_good_stops_after_nine_clocks() {
        let mut lines = Lines::new(None);
        assert!(!clear_bus(&mut lines));
        assert_eq!(lines.clocks, CLEAR_CLOCKS);
        assert!(!lines.scl_low && !lines.sda_pulled);
    }
}
