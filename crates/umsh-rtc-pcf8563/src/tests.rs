//! Host tests over a register-file mock.
//!
//! BCD arithmetic and the time-block layout are proven here. That the
//! layout matches the silicon is a hardware-validation item.

extern crate alloc;

use alloc::vec::Vec;

use embassy_futures::block_on;
use embedded_hal_async::i2c::{ErrorType, I2c, Operation};

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MockError;

impl embedded_hal_async::i2c::Error for MockError {
    fn kind(&self) -> embedded_hal_async::i2c::ErrorKind {
        embedded_hal_async::i2c::ErrorKind::Other
    }
}

struct MockRtc {
    regs: [u8; 16],
    writes: Vec<Vec<u8>>,
    fail: bool,
}

impl MockRtc {
    fn new() -> Self {
        Self {
            regs: [0u8; 16],
            writes: Vec::new(),
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            fail: true,
            ..Self::new()
        }
    }

    /// Load the seven time-block registers.
    fn with_time(mut self, block: [u8; TIME_BLOCK_LEN]) -> Self {
        self.regs[TIME_BLOCK as usize..TIME_BLOCK as usize + TIME_BLOCK_LEN]
            .copy_from_slice(&block);
        self
    }
}

impl ErrorType for MockRtc {
    type Error = MockError;
}

impl I2c for MockRtc {
    async fn transaction(
        &mut self,
        _address: u8,
        operations: &mut [Operation<'_>],
    ) -> core::result::Result<(), Self::Error> {
        if self.fail {
            return Err(MockError);
        }
        let mut pending: Option<u8> = None;
        for op in operations {
            match op {
                Operation::Write(bytes) => {
                    if bytes.len() == 1 {
                        pending = Some(bytes[0]);
                    } else {
                        let start = bytes[0] as usize;
                        // The part auto-increments through the block.
                        self.regs[start..start + bytes.len() - 1].copy_from_slice(&bytes[1..]);
                        self.writes.push(bytes.to_vec());
                    }
                }
                Operation::Read(buf) => {
                    let start = pending.expect("read without a register write") as usize;
                    buf.copy_from_slice(&self.regs[start..start + buf.len()]);
                }
            }
        }
        Ok(())
    }
}

/// 2026-08-25T17:04:09Z — a Tuesday.
const SAMPLE_EPOCH: u32 = 1_787_677_449;
const SAMPLE_BLOCK: [u8; TIME_BLOCK_LEN] = [
    0x09, // seconds, VL clear
    0x04, // minutes
    0x17, // hours
    0x25, // day
    0x02, // weekday: Tuesday
    0x08, // month, century bit clear
    0x26, // year within 2000s
];

// ─── BCD ──────────────────────────────────────────────────────────────────

#[test]
fn bcd_round_trips_every_two_digit_value() {
    for v in 0u8..=99 {
        assert_eq!(from_bcd(to_bcd(v)), Some(v), "{v}");
    }
}

#[test]
fn a_non_digit_nibble_is_not_bcd() {
    assert_eq!(from_bcd(0x1A), None);
    assert_eq!(from_bcd(0xA1), None);
    assert_eq!(from_bcd(0xFF), None);
    assert_eq!(from_bcd(0x99), Some(99));
}

#[test]
fn weekdays_advance_and_wrap() {
    // 1970-01-01 was a Thursday, which the part numbers 4.
    assert_eq!(weekday_from_unix(0), 4);
    assert_eq!(weekday_from_unix(86_400), 5);
    assert_eq!(weekday_from_unix(3 * 86_400), 0, "Sunday");
    assert_eq!(weekday_from_unix(7 * 86_400), 4);
    assert_eq!(weekday_from_unix(SAMPLE_EPOCH), 2, "Tuesday");
}

// ─── Decode ───────────────────────────────────────────────────────────────

#[test]
fn a_time_block_decodes_to_its_instant() {
    assert_eq!(decode_time_block(&SAMPLE_BLOCK), Some(SAMPLE_EPOCH));
}

#[test]
fn reserved_bits_do_not_reach_the_fields() {
    let mut block = SAMPLE_BLOCK;
    // Set every bit the part reserves in each field's register.
    block[1] |= 0x80;
    block[2] |= 0xC0;
    block[3] |= 0xC0;
    block[5] |= 0x80; // century bit, deliberately ignored
    assert_eq!(decode_time_block(&block), Some(SAMPLE_EPOCH));
}

#[test]
fn a_stopped_oscillator_reports_no_time() {
    let mut block = SAMPLE_BLOCK;
    block[0] |= VOLTAGE_LOW;
    assert_eq!(
        decode_time_block(&block),
        None,
        "the voltage-low flag must win over a well-formed reading"
    );
}

#[test]
fn a_corrupt_field_reports_no_time() {
    for i in 0..TIME_BLOCK_LEN {
        if i == 4 {
            continue; // weekday is not decoded
        }
        let mut block = SAMPLE_BLOCK;
        block[i] |= 0x0F; // force the low nibble past 9
        assert_eq!(decode_time_block(&block), None, "register {i}");
    }
}

#[test]
fn an_impossible_date_reports_no_time() {
    let mut block = SAMPLE_BLOCK;
    block[3] = 0x31; // 31 August is real...
    assert!(decode_time_block(&block).is_some());
    block[5] = 0x09; // ...31 September is not
    assert_eq!(decode_time_block(&block), None);
}

#[test]
fn a_reading_from_before_this_software_is_refused() {
    // A clock whose backup domain died without latching the flag.
    let block = [0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x00]; // 2000-01-01
    assert_eq!(decode_time_block(&block), None);

    // The floor itself is accepted.
    let floor = encode_time_block(MIN_PLAUSIBLE_EPOCH).unwrap();
    assert_eq!(decode_time_block(&floor), Some(MIN_PLAUSIBLE_EPOCH));
}

// ─── Encode ───────────────────────────────────────────────────────────────

#[test]
fn an_instant_encodes_to_its_time_block() {
    assert_eq!(encode_time_block(SAMPLE_EPOCH), Some(SAMPLE_BLOCK));
}

#[test]
fn encoding_clears_the_voltage_low_flag() {
    let block = encode_time_block(SAMPLE_EPOCH).unwrap();
    assert_eq!(block[0] & VOLTAGE_LOW, 0);
}

#[test]
fn encoding_leaves_the_century_bit_clear() {
    let block = encode_time_block(SAMPLE_EPOCH).unwrap();
    assert_eq!(block[5] & 0x80, 0);
}

#[test]
fn instants_round_trip_through_the_registers() {
    // A leap day, a year boundary, noon, and midnight.
    for epoch in [
        MIN_PLAUSIBLE_EPOCH,
        1_582_934_400, // 2020-02-29T00:00:00Z
        1_609_459_199, // 2020-12-31T23:59:59Z
        SAMPLE_EPOCH,
        4_102_444_799, // 2099-12-31T23:59:59Z
    ] {
        let block = encode_time_block(epoch).unwrap_or_else(|| panic!("{epoch} should encode"));
        assert_eq!(decode_time_block(&block), Some(epoch), "{epoch}");
    }
}

#[test]
fn instants_outside_the_represented_century_are_refused() {
    assert_eq!(encode_time_block(0), None, "1970 predates the century");
    assert_eq!(
        encode_time_block(4_102_444_800), // 2100-01-01T00:00:00Z
        None,
        "2100 is past the century this driver represents"
    );
}

// ─── Driver ───────────────────────────────────────────────────────────────

#[test]
fn read_returns_the_clock() {
    let mut rtc = Pcf8563::new(MockRtc::new().with_time(SAMPLE_BLOCK));
    assert_eq!(block_on(rtc.read()).unwrap(), Some(SAMPLE_EPOCH));
}

#[test]
fn write_sends_the_whole_block_in_one_transaction() {
    let mut rtc = Pcf8563::new(MockRtc::new());
    block_on(rtc.write(SAMPLE_EPOCH)).unwrap();
    let writes = rtc.release().writes;
    assert_eq!(writes.len(), 1, "a split write can be caught mid-rollover");
    assert_eq!(writes[0][0], TIME_BLOCK);
    assert_eq!(&writes[0][1..], &SAMPLE_BLOCK);
}

#[test]
fn a_written_clock_reads_back_and_is_no_longer_voltage_low() {
    let mut rtc = Pcf8563::new(MockRtc::new().with_time([VOLTAGE_LOW, 0, 0, 0, 0, 0, 0]));
    assert_eq!(block_on(rtc.read()).unwrap(), None);
    assert!(block_on(rtc.voltage_low()).unwrap());

    block_on(rtc.write(SAMPLE_EPOCH)).unwrap();
    assert_eq!(block_on(rtc.read()).unwrap(), Some(SAMPLE_EPOCH));
    assert!(!block_on(rtc.voltage_low()).unwrap());
}

#[test]
fn an_unrepresentable_instant_touches_no_register() {
    let mut rtc = Pcf8563::new(MockRtc::new());
    assert_eq!(block_on(rtc.write(0)), Err(Error::Unrepresentable));
    assert!(rtc.release().writes.is_empty());
}

#[test]
fn a_missing_rtc_is_not_present_and_errors_on_read() {
    let mut rtc = Pcf8563::new(MockRtc::failing());
    assert!(!block_on(rtc.present()));
    assert!(matches!(block_on(rtc.read()), Err(Error::Bus(_))));
}

#[test]
fn a_responding_rtc_is_present() {
    let mut rtc = Pcf8563::new(MockRtc::new().with_time(SAMPLE_BLOCK));
    assert!(block_on(rtc.present()));
}
