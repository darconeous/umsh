//! Completion of the STOP requested by embassy-nrf 0.11's error path.

const POLL_LIMIT: usize = 100_000;

pub(crate) trait StopEvents {
    fn error_pending(&self) -> bool;
    fn suspended(&self) -> bool;
    fn stopped(&mut self) -> bool;
    fn resume_and_stop(&mut self);
    fn acknowledge_stop(&mut self);
}

/// False means shutdown was not confirmed: the caller must reset without
/// returning the borrowed buffers or releasing the controller's mutex.
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
    fn missing_stop_requires_reset_after_a_bounded_wait() {
        let mut r = events(false, false, None);
        assert!(!finish_error_stop(&mut r));
        assert_eq!(r.polls, POLL_LIMIT);
        assert!(!r.acknowledged);
    }
}
