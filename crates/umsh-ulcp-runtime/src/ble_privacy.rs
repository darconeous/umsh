//! Public BLE discovery policy. No hardware or host-stack dependencies.

pub const ADVERTISING_INTERVAL_US: u64 = 546_250;
pub const FAST_ADVERTISING_INTERVAL_US: u64 = 20_000;
pub const STARTUP_FAST_ADVERTISING_MS: u64 = 30_000;
pub const RPA_TIMEOUT_SECS: u64 = 900;

/// Bluetooth company identifier for devices without an assigned one.
pub const COMPANY_ID: u16 = 0xFFFF;

/// Hardware models named in pairing advertisements, as assigned in
/// `docs/hardware/boards.json`. Zero is unspecified; `0xFF00` and above are
/// private use.
pub mod model {
    pub const LILYGO_T_ECHO: u16 = 1;
    pub const SEEED_SENSECAP_T1000_E: u16 = 2;
    pub const SEEED_SENSECAP_SOLAR_P1: u16 = 3;
    pub const SEEED_WIO_TRACKER_L1: u16 = 4;
    pub const SEEED_XIAO_NRF52840_KIT: u16 = 5;
    pub const HELTEC_LORA32_V2: u16 = 6;
    pub const HELTEC_LORA32_V3: u16 = 7;
    pub const LILYGO_T_BEAM_SUPREME: u16 = 8;
    pub const LILYGO_T_LORA_PAGER: u16 = 9;
}

/// Choose the window duration from the retained bond count when it opens.
pub const fn pairing_window_ms(bond_count: u8) -> u64 {
    if bond_count == 0 {
        5 * 60 * 1000
    } else {
        2 * 60 * 1000
    }
}

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
    /// Both controller interval bounds use the same pairing-policy snapshot
    /// as the payload, including when a pairing window opens or closes.
    pub interval_us: u64,
    /// Absolute boot uptime when this advertisement needs reconfiguration.
    /// Stack recreation must not extend the startup fast-advertising period.
    pub refresh_at_ms: Option<u64>,
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

/// Service discovery remains public; the model and name are disclosed only
/// during pairing.
pub fn advertisement(
    service_uuid_le: [u8; 16],
    name: &[u8],
    model_id: u16,
    pairing: bool,
    uptime_ms: u64,
) -> AdvertisementData {
    let startup = uptime_ms < STARTUP_FAST_ADVERTISING_MS;
    let mut data = AdvertisementData {
        interval_us: if pairing || startup {
            FAST_ADVERTISING_INTERVAL_US
        } else {
            ADVERTISING_INTERVAL_US
        },
        refresh_at_ms: if startup && !pairing {
            Some(STARTUP_FAST_ADVERTISING_MS)
        } else {
            None
        },
        advertising: [0; 31],
        advertising_len: 21,
        scan_response: [0; 31],
        scan_response_len: 0,
    };
    data.advertising[..3].copy_from_slice(&[2, 1, if pairing { 6 } else { 4 }]);
    data.advertising[3..5].copy_from_slice(&[17, 7]);
    data.advertising[5..21].copy_from_slice(&service_uuid_le);
    if pairing {
        // Hosts that report only the primary packet title the device by its
        // model: manufacturer data, company identifier first.
        data.advertising[21..23].copy_from_slice(&[5, 0xff]);
        data.advertising[23..25].copy_from_slice(&COMPANY_ID.to_le_bytes());
        data.advertising[25..27].copy_from_slice(&model_id.to_be_bytes());
        data.advertising_len = 27;
        // The name travels only in the scan response. A prefix in the primary
        // packet would be reported, and cached, in place of the full name.
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

    const MODEL: u16 = 0x0102;

    #[test]
    fn model_constants_match_the_board_list() {
        // The board list keeps one board per line, `id` then `model_id`.
        let boards = include_str!("../../../docs/hardware/boards.json");
        let models = [
            ("techo", model::LILYGO_T_ECHO),
            ("t1000e", model::SEEED_SENSECAP_T1000_E),
            ("sensecap-solar", model::SEEED_SENSECAP_SOLAR_P1),
            ("wio-tracker-l1", model::SEEED_WIO_TRACKER_L1),
            ("xiao-nrf52", model::SEEED_XIAO_NRF52840_KIT),
            ("heltec-v2", model::HELTEC_LORA32_V2),
            ("heltec-v3", model::HELTEC_LORA32_V3),
            ("tbeam-supreme", model::LILYGO_T_BEAM_SUPREME),
            ("tlora-pager", model::LILYGO_T_LORA_PAGER),
        ];
        for (board, id) in models {
            let entry = std::format!("\"id\": \"{board}\", \"model_id\": {id},");
            assert!(
                boards.contains(&entry),
                "{board} disagrees with boards.json"
            );
        }
        assert_eq!(boards.matches("\"model_id\":").count(), models.len());
    }

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
    fn pairing_and_reconnect_intervals_use_exact_controller_units() {
        for (pairing, interval_us, controller_units) in [(true, 20_000, 32), (false, 546_250, 874)]
        {
            let data = advertisement([0; 16], b"TrackerB2", MODEL, pairing, 30_000);
            assert_eq!(data.interval_us, interval_us);
            assert_eq!(data.interval_us % 625, 0);
            assert_eq!(data.interval_us / 625, controller_units);
        }
    }
    #[test]
    fn startup_boost_expires_without_changing_privacy_or_restarting_with_the_stack() {
        for uptime_ms in [0, 10_000, 29_999, 30_000, 30_001, 300_000] {
            // Repeated construction models internal stack restart/re-enable:
            // the boot deadline and payload privacy remain unchanged.
            let data = advertisement([0xa5; 16], b"TrackerB2", MODEL, false, uptime_ms);
            assert_eq!(data.advertising_len, 21);
            assert_eq!(data.advertising[2], 4);
            assert_eq!(data.scan_response_len, 0);
            if uptime_ms < 30_000 {
                assert_eq!(data.interval_us, 20_000);
                assert_eq!(data.refresh_at_ms, Some(30_000));
            } else {
                assert_eq!(data.interval_us, 546_250);
                assert_eq!(data.refresh_at_ms, None);
            }
            let pairing = advertisement([0xa5; 16], b"TrackerB2", MODEL, true, uptime_ms);
            assert_eq!(pairing.interval_us, 20_000);
            assert_eq!(pairing.refresh_at_ms, None);
            assert_ne!(pairing.scan_response_len, 0);
        }
    }
    #[test]
    fn reconnect_contains_only_flags_and_service_regardless_of_name() {
        for (uuid, name) in [
            ([0xa5; 16], b"Alice's radio 1234".as_slice()),
            ([0x5a; 16], b"Another radio".as_slice()),
            ([0; 16], b"".as_slice()),
        ] {
            let d = advertisement(uuid, name, MODEL, false, 30_000);
            assert_eq!(d.advertising_len, 21);
            assert_eq!(&d.advertising[..5], &[2, 1, 4, 17, 7]);
            assert_eq!(&d.advertising[5..21], &uuid);
            assert_eq!(&d.advertising[d.advertising_len..], &[0; 10]);
            assert_eq!(d.scan_response_len, 0);
            assert_eq!(d.scan_response, [0; 31]);
        }
    }
    #[test]
    fn pairing_advertises_service_and_model_even_without_a_usable_name() {
        for name in [b"".as_slice(), &[0xff]] {
            let d = advertisement([0xa5; 16], name, MODEL, true, 30_000);
            assert_eq!(d.advertising_len, 27);
            assert_eq!(&d.advertising[..5], &[2, 1, 6, 17, 7]);
            assert_eq!(&d.advertising[5..21], &[0xa5; 16]);
            assert_eq!(&d.advertising[21..27], &[5, 0xff, 0xff, 0xff, 1, 2]);
            assert_eq!(d.scan_response_len, 0);
        }
    }
    #[test]
    fn pairing_name_travels_only_in_the_scan_response() {
        for name in [b"TrackerB2".as_slice(), b"12345678901234567890123456789"] {
            let d = advertisement([0xa5; 16], name, MODEL, true, 30_000);
            assert_eq!(d.advertising_len, 27);
            assert_eq!(&d.advertising[..5], &[2, 1, 6, 17, 7]);
            assert_eq!(&d.advertising[5..21], &[0xa5; 16]);
            // Manufacturer data: company identifier, then the model.
            assert_eq!(&d.advertising[21..27], &[5, 0xff, 0xff, 0xff, 1, 2]);
            assert_eq!(&d.advertising[27..], &[0; 4]);
            assert_eq!(d.scan_response_len, name.len() + 2);
            assert_eq!(d.scan_response[0], (name.len() + 1) as u8);
            assert_eq!(d.scan_response[1], 9); // Complete Local Name
            assert_eq!(&d.scan_response[2..d.scan_response_len], name);
        }
    }
    #[test]
    fn pairing_names_obey_payload_and_utf8_limits() {
        let d = advertisement([0; 16], "1234567é radio".as_bytes(), MODEL, true, 30_000);
        assert_eq!(d.advertising_len, 27);
        assert_eq!(d.advertising[2], 6);
        assert_eq!(&d.advertising[3..5], &[17, 7]);
        assert_eq!(&d.advertising[5..21], &[0; 16]);
        assert_eq!(d.scan_response[1], 9);
        assert_eq!(
            &d.scan_response[2..d.scan_response_len],
            "1234567é radio".as_bytes()
        );
        let long = "é".repeat(20);
        let d = advertisement([0; 16], long.as_bytes(), MODEL, true, 30_000);
        assert_eq!(d.scan_response_len, 30);
        assert_eq!(d.scan_response[1], 8);
        assert!(core::str::from_utf8(&d.scan_response[2..30]).is_ok());
        let closed = advertisement([0; 16], long.as_bytes(), MODEL, false, 30_000);
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
        deadline.open(1000, pairing_window_ms(0));
        assert_eq!(deadline.at(), Some(301_000));
        assert!(!deadline.expired(300_999));
        assert!(deadline.expired(301_000));
        deadline.close();
        assert!(!deadline.expired(600_000));
        for bonds in 1..=4 {
            deadline.open(600_000, pairing_window_ms(bonds));
            assert_eq!(deadline.at(), Some(720_000));
            assert!(!deadline.expired(719_999));
            assert!(deadline.expired(720_000));
        }
        // Clearing all hosts gives the next window the initial setup duration.
        deadline.open(800_000, pairing_window_ms(0));
        assert_eq!(deadline.at(), Some(1_100_000));
    }
    #[test]
    fn every_pairing_exit_removes_name_and_retains_service_without_resetting_security() {
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
            assert_eq!(
                advertisement([1; 16], b"radio", MODEL, state.pairing_mode, 30_000).interval_us,
                20_000
            );
            assert_ne!(
                advertisement([1; 16], b"radio", MODEL, state.pairing_mode, 30_000)
                    .scan_response_len,
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
            let data = advertisement([1; 16], b"radio", MODEL, state.pairing_mode, 30_000);
            assert_eq!(data.interval_us, 546_250);
            assert_eq!(data.advertising_len, 21);
            assert_eq!(&data.advertising[..5], &[2, 1, 4, 17, 7]);
            assert_eq!(&data.advertising[5..21], &[1; 16]);
            assert_eq!(&data.advertising[21..], &[0; 10]);
            assert_eq!(data.scan_response_len, 0);
            assert_eq!(data.scan_response, [0; 31]);
            assert_eq!(deadline.at(), None);
            assert_eq!(state.failures, if exit == 2 { 0 } else { 2 });
            // Reopening advertises the current name and the service again.
            let reopened = advertisement([1; 16], b"renamed", MODEL, true, 30_000);
            assert_eq!(reopened.interval_us, 20_000);
            assert_eq!(&reopened.advertising[3..5], &[17, 7]);
            assert_eq!(&reopened.advertising[5..21], &[1; 16]);
            assert_eq!(
                &reopened.scan_response[..reopened.scan_response_len],
                b"\x08\x09renamed"
            );
        }
    }
}
