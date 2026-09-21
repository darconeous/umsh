//! Public BLE discovery policy. No hardware or host-stack dependencies.

pub const ADVERTISING_INTERVAL_US: u64 = 1_022_500;
pub const RPA_TIMEOUT_SECS: u64 = 900;

/// Avoid a tight controller rebuild loop while keeping retries short enough
/// for background reconnection. A stable run resets consecutive-failure delay.
#[derive(Default)]
pub struct RestartBackoff(u64);
impl RestartBackoff {
    pub fn after_exit(&mut self, uptime_ms: u64) -> u64 {
        if uptime_ms >= 30_000 {
            self.0 = 0;
        }
        self.0 = (self.0 * 2).clamp(1_000, 5_000);
        self.0
    }
    pub fn reset(&mut self) {
        self.0 = 0;
    }
}

pub struct AdvertisementData {
    pub advertising: [u8; 31],
    pub advertising_len: usize,
    pub scan_response: [u8; 31],
    pub scan_response_len: usize,
}

pub fn utf8_prefix_len(bytes: &[u8], limit: usize) -> usize {
    let Ok(text) = core::str::from_utf8(bytes) else {
        return 0;
    };
    let mut len = bytes.len().min(limit);
    while !text.is_char_boundary(len) {
        len -= 1;
    }
    len
}

/// Names and service identity are disclosed only during deliberate pairing.
pub fn advertisement(service_uuid_le: [u8; 16], name: &[u8], pairing: bool) -> AdvertisementData {
    let mut data = AdvertisementData {
        advertising: [0; 31],
        advertising_len: 3,
        scan_response: [0; 31],
        scan_response_len: 0,
    };
    data.advertising[..3].copy_from_slice(&[2, 1, if pairing { 6 } else { 4 }]);
    if pairing {
        data.advertising[3..5].copy_from_slice(&[17, 7]);
        data.advertising[5..21].copy_from_slice(&service_uuid_le);
        data.advertising_len = 21;
        let len = utf8_prefix_len(name, 8);
        if len != 0 {
            data.advertising[21..23].copy_from_slice(&[(len + 1) as u8, 8]);
            data.advertising[23..23 + len].copy_from_slice(&name[..len]);
            data.advertising_len = 23 + len;
        }
        let len = utf8_prefix_len(name, 29);
        if len != 0 {
            data.scan_response[..2]
                .copy_from_slice(&[(len + 1) as u8, if len == name.len() { 9 } else { 8 }]);
            data.scan_response[2..2 + len].copy_from_slice(&name[..len]);
            data.scan_response_len = 2 + len;
        }
    }
    data
}

pub const fn name_visible(pairing: bool, encrypted: bool, durable_bond: bool) -> bool {
    pairing || (encrypted && durable_bond)
}

/// A deadline survives stack recreation; only an explicit open extends it.
#[derive(Default, Debug)]
pub struct PairingDeadline(Option<u64>);
impl PairingDeadline {
    pub const fn new() -> Self {
        Self(None)
    }
    pub fn open(&mut self, now_ms: u64, window_ms: u64) {
        self.0 = Some(now_ms.saturating_add(window_ms));
    }
    pub fn close(&mut self) {
        self.0 = None;
    }
    pub fn expired(&self, now_ms: u64) -> bool {
        self.0.is_some_and(|deadline| now_ms >= deadline)
    }
    pub fn at(&self) -> Option<u64> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_backoff_is_bounded_and_resets_after_stable_operation() {
        let mut backoff = RestartBackoff::default();
        for expected in [1_000, 2_000, 4_000, 5_000, 5_000] {
            assert_eq!(backoff.after_exit(10), expected);
        }
        assert_eq!(backoff.after_exit(30_000), 1_000);
        assert_eq!(backoff.after_exit(10), 2_000);
        backoff.reset();
        assert_eq!(backoff.after_exit(10), 1_000);
    }
    #[test]
    fn reconnect_contains_only_generic_flags_regardless_of_service_or_name() {
        for (uuid, name) in [
            ([0xa5; 16], b"Alice's radio 1234".as_slice()),
            ([0x5a; 16], b"Another radio".as_slice()),
            ([0; 16], b"".as_slice()),
        ] {
            let d = advertisement(uuid, name, false);
            assert_eq!(&d.advertising[..d.advertising_len], &[2, 1, 4]);
            assert_eq!(&d.advertising[d.advertising_len..], &[0; 28]);
            assert_eq!(d.scan_response_len, 0);
            assert_eq!(d.scan_response, [0; 31]);
        }
    }
    #[test]
    fn pairing_advertises_service_even_without_a_usable_name() {
        for name in [b"".as_slice(), &[0xff]] {
            let d = advertisement([0xa5; 16], name, true);
            assert_eq!(d.advertising_len, 21);
            assert_eq!(&d.advertising[..5], &[2, 1, 6, 17, 7]);
            assert_eq!(&d.advertising[5..21], &[0xa5; 16]);
            assert_eq!(d.scan_response_len, 0);
        }
    }
    #[test]
    fn pairing_names_obey_payload_and_utf8_limits() {
        let d = advertisement([0; 16], "1234567é radio".as_bytes(), true);
        assert_eq!(&d.advertising[21..d.advertising_len], b"\x08\x081234567");
        assert_eq!(d.advertising[2], 6);
        assert_eq!(&d.advertising[3..5], &[17, 7]);
        assert_eq!(&d.advertising[5..21], &[0; 16]);
        assert_eq!(d.scan_response[1], 9);
        let long = "é".repeat(20);
        let d = advertisement([0; 16], long.as_bytes(), true);
        assert_eq!(d.scan_response_len, 30);
        assert_eq!(d.scan_response[1], 8);
        assert!(core::str::from_utf8(&d.scan_response[2..30]).is_ok());
        let closed = advertisement([0; 16], long.as_bytes(), false);
        assert_eq!(closed.scan_response_len, 0);
    }
    #[test]
    fn encrypted_and_retained_are_both_required_outside_pairing() {
        for pairing in [false, true] {
            for encrypted in [false, true] {
                for retained in [false, true] {
                    assert_eq!(
                        name_visible(pairing, encrypted, retained),
                        pairing || (encrypted && retained)
                    );
                }
            }
        }
    }
    #[test]
    fn deadline_does_not_extend_when_stack_restarts() {
        let mut deadline = PairingDeadline::new();
        deadline.open(1000, 30000);
        assert!(!deadline.expired(30999));
        assert!(deadline.expired(31000));
        deadline.close();
        assert!(!deadline.expired(60000));
        deadline.open(60000, 20000);
        assert_eq!(deadline.at(), Some(80000));
    }
    #[test]
    fn every_pairing_exit_removes_name_and_service_without_resetting_security() {
        use crate::ble_security::PairingRuntime;
        let initial = PairingRuntime {
            pairing_mode: false,
            failures: 2,
            locked_out: false,
        };
        for exit in 0..4 {
            let mut state = initial;
            let mut deadline = PairingDeadline::new();
            state.pairing_mode = true;
            deadline.open(1000, 30000);
            assert_ne!(
                advertisement([1; 16], b"radio", state.pairing_mode).scan_response_len,
                0
            );
            match exit {
                0 => {
                    assert!(deadline.expired(31000));
                    state.pairing_mode = false;
                }
                1 => state.pairing_mode = false, // explicit close
                2 => state = state.pairing_succeeded(),
                _ => state = state.bonded_reconnect(),
            }
            deadline.close();
            let data = advertisement([1; 16], b"radio", state.pairing_mode);
            assert_eq!(&data.advertising[..data.advertising_len], &[2, 1, 4]);
            assert_eq!(&data.advertising[3..], &[0; 28]);
            assert_eq!(data.scan_response_len, 0);
            assert_eq!(data.scan_response, [0; 31]);
            assert_eq!(deadline.at(), None);
            assert_eq!(state.failures, if exit == 2 { 0 } else { 2 });
            // Reopening advertises the current name and the service again.
            let reopened = advertisement([1; 16], b"renamed", true);
            assert_eq!(&reopened.advertising[3..5], &[17, 7]);
            assert_eq!(&reopened.advertising[5..21], &[1; 16]);
            assert_eq!(
                &reopened.scan_response[..reopened.scan_response_len],
                b"\x08\x09renamed"
            );
        }
    }
}
