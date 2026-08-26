//! Host tests over a register-file mock.
//!
//! These prove the driver's own arithmetic and access patterns: which
//! registers it touches, which bits it preserves, how it encodes and
//! decodes. They cannot prove a register address or bit position is the
//! one the silicon uses — that stays a hardware-validation item, and no
//! test here should be read as evidence for it.

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

/// A 256-byte register file that records every write.
struct MockPmic {
    regs: [u8; 256],
    writes: Vec<(u8, u8)>,
    fail: bool,
}

impl MockPmic {
    fn new() -> Self {
        let mut regs = [0u8; 256];
        regs[reg::IC_TYPE as usize] = CHIP_ID;
        Self {
            regs,
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

    fn with(mut self, register: u8, value: u8) -> Self {
        self.regs[register as usize] = value;
        self
    }

    fn touched(&self, register: u8) -> bool {
        self.writes.iter().any(|(r, _)| *r == register)
    }

    fn written_to(&self, register: u8) -> Vec<u8> {
        self.writes
            .iter()
            .filter(|(r, _)| *r == register)
            .map(|(_, v)| *v)
            .collect()
    }
}

impl ErrorType for MockPmic {
    type Error = MockError;
}

impl I2c for MockPmic {
    async fn transaction(
        &mut self,
        _address: u8,
        operations: &mut [Operation<'_>],
    ) -> core::result::Result<(), Self::Error> {
        if self.fail {
            return Err(MockError);
        }
        // The driver only ever issues `write` (register + value) and
        // `write_read` (register, then one byte back).
        let mut pending: Option<u8> = None;
        for op in operations {
            match op {
                Operation::Write(bytes) => match bytes {
                    [register] => pending = Some(*register),
                    [register, value] => {
                        self.regs[*register as usize] = *value;
                        self.writes.push((*register, *value));
                    }
                    _ => panic!("unexpected write of {} bytes", bytes.len()),
                },
                Operation::Read(buf) => {
                    let register = pending.expect("read without a preceding register write");
                    assert_eq!(buf.len(), 1, "the driver reads one byte at a time");
                    buf[0] = self.regs[register as usize];
                }
            }
        }
        Ok(())
    }
}

fn pmic(mock: MockPmic) -> Axp2101<MockPmic> {
    Axp2101::new(mock)
}

// ─── Identity ─────────────────────────────────────────────────────────────

#[test]
fn probe_accepts_the_axp2101() {
    let mut p = pmic(MockPmic::new());
    assert!(block_on(p.probe()).is_ok());
}

#[test]
fn probe_rejects_another_chip_by_id() {
    let mut p = pmic(MockPmic::new().with(reg::IC_TYPE, 0x03));
    assert_eq!(block_on(p.probe()), Err(Error::WrongChip(0x03)));
}

#[test]
fn probe_writes_nothing() {
    let mut p = pmic(MockPmic::new().with(reg::IC_TYPE, 0x00));
    let _ = block_on(p.probe());
    assert!(p.release().writes.is_empty());
}

#[test]
fn a_dead_bus_surfaces_as_a_bus_error() {
    let mut p = pmic(MockPmic::failing());
    assert!(matches!(block_on(p.probe()), Err(Error::Bus(_))));
}

// ─── Rail voltage encoding ────────────────────────────────────────────────

#[test]
fn rail_voltages_round_trip_across_the_range() {
    let mut mv = reg::LDO_VOL_MIN_MV;
    while mv <= reg::LDO_VOL_MAX_MV {
        let field = encode_rail_mv(mv).unwrap_or_else(|| panic!("{mv} mV should encode"));
        assert_eq!(decode_rail_mv(field), mv);
        mv += reg::LDO_VOL_STEP_MV;
    }
}

#[test]
fn the_board_rail_voltage_encodes_as_expected() {
    // 3300 mV is what every peripheral rail on the T-Beam Supreme runs at.
    assert_eq!(encode_rail_mv(3300), Some(28));
    assert_eq!(decode_rail_mv(28), 3300);
}

#[test]
fn off_grid_and_out_of_range_voltages_are_refused() {
    assert_eq!(encode_rail_mv(3350), None, "off the 100 mV grid");
    assert_eq!(encode_rail_mv(499), None, "below the part's minimum");
    assert_eq!(encode_rail_mv(3600), None, "above the part's maximum");
    assert_eq!(encode_rail_mv(0), None);
}

#[test]
fn setting_an_unsupported_voltage_touches_no_register() {
    let mut p = pmic(MockPmic::new());
    assert_eq!(
        block_on(p.set_rail_voltage(Rail::Aldo3, 3350)),
        Err(Error::UnsupportedVoltage(3350))
    );
    assert!(p.release().writes.is_empty());
}

// ─── Rail control ─────────────────────────────────────────────────────────

#[test]
fn each_rail_owns_a_distinct_enable_bit_and_voltage_register() {
    let rails = [
        Rail::Aldo1,
        Rail::Aldo2,
        Rail::Aldo3,
        Rail::Aldo4,
        Rail::Bldo1,
        Rail::Bldo2,
    ];
    for (i, a) in rails.iter().enumerate() {
        for b in &rails[i + 1..] {
            assert_ne!(
                a.enable_bit(),
                b.enable_bit(),
                "{a:?} and {b:?} share a bit"
            );
            assert_ne!(
                a.voltage_reg(),
                b.voltage_reg(),
                "{a:?} and {b:?} share a voltage register"
            );
        }
    }
}

#[test]
fn enabling_a_rail_preserves_its_neighbors() {
    // Every other rail already on.
    let mut p = pmic(MockPmic::new().with(reg::LDO_ONOFF_CTRL0, 0b0011_1011));
    block_on(p.set_rail_enabled(Rail::Aldo3, true)).unwrap();
    assert_eq!(p.release().written_to(reg::LDO_ONOFF_CTRL0), [0b0011_1111]);
}

#[test]
fn disabling_a_rail_clears_only_its_own_bit() {
    let mut p = pmic(MockPmic::new().with(reg::LDO_ONOFF_CTRL0, 0b0011_1111));
    block_on(p.set_rail_enabled(Rail::Aldo4, false)).unwrap();
    assert_eq!(p.release().written_to(reg::LDO_ONOFF_CTRL0), [0b0011_0111]);
}

#[test]
fn setting_a_rail_voltage_preserves_the_reserved_high_bits() {
    let mut p = pmic(MockPmic::new().with(reg::ALDO3_VOL, 0xE0));
    block_on(p.set_rail_voltage(Rail::Aldo3, 3300)).unwrap();
    assert_eq!(p.release().written_to(reg::ALDO3_VOL), [0xE0 | 28]);
}

#[test]
fn enable_rail_at_sets_the_voltage_before_switching_on() {
    let mut p = pmic(MockPmic::new());
    block_on(p.enable_rail_at(Rail::Aldo3, 3300)).unwrap();
    let writes = p.release().writes;
    let volt = writes
        .iter()
        .position(|(r, _)| *r == reg::ALDO3_VOL)
        .expect("voltage written");
    let enable = writes
        .iter()
        .position(|(r, _)| *r == reg::LDO_ONOFF_CTRL0)
        .expect("rail enabled");
    assert!(
        volt < enable,
        "a rail must be set to its voltage before it is switched on"
    );
}

#[test]
fn the_dcdc_enable_register_is_never_written() {
    // DCDC1 is the MCU core supply. Exercise everything that touches
    // rails and confirm none of it reaches 0x80.
    let mut p = pmic(MockPmic::new());
    block_on(p.enable_rail_at(Rail::Aldo1, 3300)).unwrap();
    block_on(p.enable_rail_at(Rail::Aldo3, 3300)).unwrap();
    block_on(p.enable_rail_at(Rail::Bldo1, 3300)).unwrap();
    block_on(p.set_rail_enabled(Rail::Aldo4, false)).unwrap();
    block_on(p.cold_boot_cycle(&[Rail::Aldo1, Rail::Aldo2, Rail::Bldo1], &mut NoDelay)).unwrap();
    assert!(!p.release().touched(reg::DC_ONOFF_DVM_CTRL));
}

// ─── Cold-boot cycle ──────────────────────────────────────────────────────

/// A delay that records what it was asked to wait.
struct RecordingDelay(Vec<u32>);

impl DelayNs for RecordingDelay {
    async fn delay_ns(&mut self, ns: u32) {
        self.0.push(ns / 1_000_000);
    }
}

struct NoDelay;

impl DelayNs for NoDelay {
    async fn delay_ns(&mut self, _ns: u32) {}
}

#[test]
fn the_cold_boot_cycle_drops_exactly_the_named_rails_then_waits() {
    let mut p = pmic(MockPmic::new().with(reg::LDO_ONOFF_CTRL0, 0b0011_1111));
    let mut delay = RecordingDelay(Vec::new());
    block_on(p.cold_boot_cycle(&[Rail::Aldo1, Rail::Aldo2, Rail::Bldo1], &mut delay)).unwrap();

    // ALDO3 (radio) and ALDO4 (GNSS) must survive; the three named rails go.
    let final_state = p.release().regs[reg::LDO_ONOFF_CTRL0 as usize];
    assert_eq!(final_state, 0b0010_1100);
    assert_eq!(delay.0, [COLD_BOOT_SETTLE_MS]);
}

#[test]
fn the_cold_boot_cycle_leaves_the_rails_off_for_the_caller_to_restore() {
    let mut p = pmic(MockPmic::new().with(reg::LDO_ONOFF_CTRL0, 0xFF));
    block_on(p.cold_boot_cycle(&[Rail::Aldo1], &mut NoDelay)).unwrap();
    assert!(!block_on(p.rail_enabled(Rail::Aldo1)).unwrap());
}

// ─── Charger ──────────────────────────────────────────────────────────────

#[test]
fn charge_current_and_voltage_write_their_own_fields() {
    let mut p = pmic(
        MockPmic::new()
            .with(reg::ICC_CHG_SET, 0xE0)
            .with(reg::CV_CHG_VOL_SET, 0xF8),
    );
    block_on(p.set_charge_current(ChargeCurrent::Ma500)).unwrap();
    block_on(p.set_charge_voltage(ChargeVoltage::V4_2)).unwrap();
    let mock = p.release();
    assert_eq!(mock.written_to(reg::ICC_CHG_SET), [0xE0 | 11]);
    assert_eq!(mock.written_to(reg::CV_CHG_VOL_SET), [0xF8 | 3]);
}

#[test]
fn the_charge_current_codes_skip_the_unassigned_gap() {
    // Codes 1-3 are not current steps on this part.
    assert_eq!(ChargeCurrent::Off as u8, 0);
    assert_eq!(ChargeCurrent::Ma100 as u8, 4);
    assert_eq!(ChargeCurrent::Ma500 as u8, 11);
    assert_eq!(ChargeCurrent::Ma1000 as u8, 16);
}

#[test]
fn every_charge_current_code_fits_its_register_field() {
    for c in [
        ChargeCurrent::Off,
        ChargeCurrent::Ma100,
        ChargeCurrent::Ma500,
        ChargeCurrent::Ma1000,
    ] {
        assert_eq!(c as u8 & !reg::ICC_CHG_MASK, 0, "{c:?} overflows the field");
    }
    for v in [
        ChargeVoltage::V4_0,
        ChargeVoltage::V4_2,
        ChargeVoltage::V4_4,
    ] {
        assert_eq!(v as u8 & !reg::CV_CHG_MASK, 0, "{v:?} overflows the field");
    }
}

#[test]
fn handing_the_led_to_the_charger_selects_the_charger_source() {
    let mut p = pmic(MockPmic::new().with(reg::CHGLED_SET_CTRL, 0x35));
    block_on(p.set_charge_led(ChargeLed::Charger)).unwrap();
    assert_eq!(
        p.release().written_to(reg::CHGLED_SET_CTRL),
        [(0x35 & reg::CHGLED_CHARGER_KEEP) | reg::CHGLED_CHARGER_CTRL]
    );
}

#[test]
fn manual_led_modes_carry_distinct_patterns() {
    let mut seen = Vec::new();
    for mode in [
        ChargeLed::Off,
        ChargeLed::Blink1Hz,
        ChargeLed::Blink4Hz,
        ChargeLed::On,
    ] {
        let mut p = pmic(MockPmic::new());
        block_on(p.set_charge_led(mode)).unwrap();
        let v = p.release().written_to(reg::CHGLED_SET_CTRL)[0];
        assert_eq!(v & 0x07, reg::CHGLED_MANUAL_CTRL, "{mode:?} manual source");
        seen.push(v);
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 4, "two LED modes encoded identically");
}

#[test]
fn charge_state_decodes_every_assigned_code() {
    let cases = [
        (0, ChargeState::Trickle),
        (1, ChargeState::Precharge),
        (2, ChargeState::ConstantCurrent),
        (3, ChargeState::ConstantVoltage),
        (4, ChargeState::Done),
        (5, ChargeState::NotCharging),
        (6, ChargeState::Unknown(6)),
        (7, ChargeState::Unknown(7)),
    ];
    for (code, want) in cases {
        // Direction bits set, to prove the field is masked out.
        let mut p = pmic(MockPmic::new().with(reg::STATUS2, 0b1110_0000 | code));
        assert_eq!(block_on(p.charge_state()).unwrap(), want);
    }
}

#[test]
fn done_is_not_reported_as_charging() {
    assert!(!ChargeState::Done.is_charging());
    assert!(!ChargeState::NotCharging.is_charging());
    assert!(ChargeState::ConstantCurrent.is_charging());
    assert!(ChargeState::Trickle.is_charging());
}

#[test]
fn charge_direction_reads_the_high_field() {
    for (code, want) in [
        (0b000, ChargeDirection::Standby),
        (0b001, ChargeDirection::Charging),
        (0b010, ChargeDirection::Discharging),
        (0b011, ChargeDirection::Unknown(3)),
    ] {
        let mut p = pmic(MockPmic::new().with(reg::STATUS2, (code << 5) | 0x07));
        assert_eq!(block_on(p.charge_direction()).unwrap(), want);
    }
}

// ─── Telemetry ────────────────────────────────────────────────────────────

#[test]
fn enabling_telemetry_leaves_the_thermistor_channel_alone() {
    let mut p = pmic(MockPmic::new());
    block_on(p.enable_telemetry()).unwrap();
    let state = p.release().regs[reg::ADC_CHANNEL_CTRL as usize];
    assert_eq!(state & (1 << reg::ADC_CH_VBAT), 1 << reg::ADC_CH_VBAT);
    assert_eq!(state & (1 << reg::ADC_CH_VBUS), 1 << reg::ADC_CH_VBUS);
    assert_eq!(state & (1 << reg::ADC_CH_VSYS), 1 << reg::ADC_CH_VSYS);
    assert_eq!(state & 0b10, 0, "the TS channel must stay off");
}

#[test]
fn battery_voltage_assembles_five_high_bits_over_a_low_byte() {
    let mut p = pmic(
        MockPmic::new()
            .with(reg::STATUS1, 1 << reg::STATUS1_BATTERY_PRESENT)
            // High byte carries reserved bits above the 5 significant ones.
            .with(reg::ADC_VBAT_H, 0b1110_1110)
            .with(reg::ADC_VBAT_L, 0x1C),
    );
    assert_eq!(
        block_on(p.battery_millivolts()).unwrap(),
        Some(0x0E_1C) // 3612 mV
    );
}

#[test]
fn battery_voltage_is_absent_without_a_cell() {
    let mut p = pmic(MockPmic::new().with(reg::ADC_VBAT_H, 0x0E));
    assert_eq!(block_on(p.battery_millivolts()).unwrap(), None);
}

#[test]
fn vbus_voltage_assembles_six_high_bits_and_is_absent_when_unplugged() {
    let mut p = pmic(
        MockPmic::new()
            .with(reg::STATUS1, 1 << reg::STATUS1_VBUS_GOOD)
            .with(reg::ADC_VBUS_H, 0b1101_0011)
            .with(reg::ADC_VBUS_L, 0x88),
    );
    assert_eq!(block_on(p.vbus_millivolts()).unwrap(), Some(0x13_88)); // 5000 mV

    let mut p = pmic(MockPmic::new().with(reg::ADC_VBUS_H, 0x13));
    assert_eq!(block_on(p.vbus_millivolts()).unwrap(), None);
}

#[test]
fn an_unlearned_gauge_reading_is_reported_as_unknown_not_as_a_percentage() {
    let present = 1 << reg::STATUS1_BATTERY_PRESENT;
    for raw in [101u8, 0xFF] {
        let mut p = pmic(
            MockPmic::new()
                .with(reg::STATUS1, present)
                .with(reg::BAT_PERCENT_DATA, raw),
        );
        assert_eq!(block_on(p.battery_percent()).unwrap(), None, "raw {raw}");
    }
    for raw in [0u8, 55, 100] {
        let mut p = pmic(
            MockPmic::new()
                .with(reg::STATUS1, present)
                .with(reg::BAT_PERCENT_DATA, raw),
        );
        assert_eq!(block_on(p.battery_percent()).unwrap(), Some(raw));
    }
}

// ─── Interrupts ───────────────────────────────────────────────────────────

#[test]
fn irq_masks_are_distinct_and_land_in_the_right_register() {
    // Byte index within INTEN/INTSTS each event belongs to.
    let cases = [
        (IrqMask::POWER_KEY_LONG, 1),
        (IrqMask::POWER_KEY_SHORT, 1),
        (IrqMask::BATTERY_REMOVED, 1),
        (IrqMask::BATTERY_INSERTED, 1),
        (IrqMask::VBUS_REMOVED, 1),
        (IrqMask::VBUS_INSERTED, 1),
        (IrqMask::CHARGE_STARTED, 2),
        (IrqMask::CHARGE_DONE, 2),
    ];
    for (i, (mask, byte)) in cases.iter().enumerate() {
        assert_eq!(mask.0.count_ones(), 1, "each event is a single bit");
        let bytes = mask.bytes();
        assert_ne!(bytes[*byte], 0, "event {i} missed its register");
        for (b, v) in bytes.iter().enumerate() {
            if b != *byte {
                assert_eq!(*v, 0, "event {i} leaked into register byte {b}");
            }
        }
        for (other, _) in &cases[i + 1..] {
            assert_ne!(mask.0, other.0, "two events share a bit");
        }
    }
}

#[test]
fn clearing_stale_irqs_writes_ones_to_every_status_register() {
    let mut p = pmic(MockPmic::new());
    block_on(p.clear_all_irqs()).unwrap();
    let mock = p.release();
    for register in reg::INTSTS {
        assert_eq!(mock.written_to(register), [0xFF]);
    }
    for register in reg::INTEN {
        assert!(!mock.touched(register), "clearing must not enable anything");
    }
}

#[test]
fn enabling_irqs_spreads_the_mask_across_the_three_registers() {
    let mut p = pmic(MockPmic::new());
    let wanted = IrqMask::POWER_KEY_SHORT
        .union(IrqMask::VBUS_INSERTED)
        .union(IrqMask::CHARGE_DONE);
    block_on(p.set_irq_enabled(wanted)).unwrap();
    let mock = p.release();
    assert_eq!(mock.written_to(reg::INTEN[0]), [0x00]);
    assert_eq!(mock.written_to(reg::INTEN[1]), [0b1000_1000]);
    assert_eq!(mock.written_to(reg::INTEN[2]), [0b0001_0000]);
}

#[test]
fn taking_irqs_reports_and_clears_exactly_what_was_read() {
    let mut p = pmic(
        MockPmic::new()
            .with(reg::INTSTS[1], 0b1000_0000) // VBUS inserted
            .with(reg::INTSTS[2], 0b0001_0000), // charge done
    );
    let taken = block_on(p.take_irqs()).unwrap();
    assert!(taken.contains(IrqMask::VBUS_INSERTED));
    assert!(taken.contains(IrqMask::CHARGE_DONE));
    assert!(!taken.contains(IrqMask::POWER_KEY_SHORT));

    let mock = p.release();
    assert_eq!(mock.written_to(reg::INTSTS[1]), [0b1000_0000]);
    assert_eq!(mock.written_to(reg::INTSTS[2]), [0b0001_0000]);
    assert!(
        !mock.touched(reg::INTSTS[0]),
        "a register with nothing latched must not be written"
    );
}

#[test]
fn reading_irq_status_does_not_clear_it() {
    let mut p = pmic(MockPmic::new().with(reg::INTSTS[1], 0b1000_0000));
    let status = block_on(p.irq_status()).unwrap();
    assert!(status.contains(IrqMask::VBUS_INSERTED));
    assert!(p.release().writes.is_empty());
}

#[test]
fn an_empty_mask_contains_nothing_and_is_empty() {
    assert!(IrqMask::NONE.is_empty());
    assert!(!IrqMask::NONE.contains(IrqMask::POWER_KEY_SHORT));
    assert!(!IrqMask::ALL.contains(IrqMask::NONE));
    assert!(IrqMask::ALL.contains(IrqMask::POWER_KEY_SHORT));
}

// ─── Power key ────────────────────────────────────────────────────────────

#[test]
fn the_two_press_times_occupy_separate_fields() {
    let mut p = pmic(MockPmic::new().with(reg::IRQ_OFF_ON_LEVEL_CTRL, 0xF0));
    block_on(p.set_power_on_press(PowerOnPress::S1)).unwrap();
    block_on(p.set_power_off_press(PowerOffPress::S4)).unwrap();
    let mock = p.release();
    let writes = mock.written_to(reg::IRQ_OFF_ON_LEVEL_CTRL);
    // On-time in bits [1:0], off-time in [3:2], high nibble preserved.
    assert_eq!(writes[0], 0xF0 | 0b10);
    assert_eq!(writes[1], 0xF0 | 0b10);
}

#[test]
fn a_longer_power_off_hold_sets_the_upper_field() {
    let mut p = pmic(MockPmic::new());
    block_on(p.set_power_off_press(PowerOffPress::S10)).unwrap();
    assert_eq!(
        p.release().written_to(reg::IRQ_OFF_ON_LEVEL_CTRL),
        [0b0000_1100]
    );
}

#[test]
fn power_off_requests_the_soft_shutdown_bit_without_disturbing_the_register() {
    let mut p = pmic(MockPmic::new().with(reg::COMMON_CONFIG, 0b0011_0100));
    block_on(p.power_off()).unwrap();
    assert_eq!(p.release().written_to(reg::COMMON_CONFIG), [0b0011_0101]);
}
