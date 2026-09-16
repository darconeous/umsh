use crate::{input::*, power::*, rtc};
use embedded_hal::i2c::{ErrorKind, ErrorType};
use embedded_hal_async::i2c::{I2c, Operation};
use std::{boxed::Box, collections::VecDeque, vec, vec::Vec};

#[derive(Debug)]
enum Op {
    Write(u8, Vec<u8>),
    Read(u8, Vec<u8>, Vec<u8>),
    FailedWrite(u8, Vec<u8>),
    FailedRead(u8, Vec<u8>),
}
struct Bus(VecDeque<Op>);
impl ErrorType for Bus {
    type Error = ErrorKind;
}
impl I2c for Bus {
    async fn transaction(
        &mut self,
        address: u8,
        ops: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        match (self.0.pop_front().expect("unexpected bus transaction"), ops) {
            (Op::Write(a, expected), [Operation::Write(actual)]) => {
                assert_eq!(a, address);
                assert_eq!(&expected, actual);
            }
            (Op::Read(a, reg, value), [Operation::Write(actual), Operation::Read(out)]) => {
                assert_eq!(a, address);
                assert_eq!(&reg, actual);
                out.copy_from_slice(&value);
            }
            (Op::FailedWrite(a, expected), [Operation::Write(actual)]) => {
                assert_eq!(a, address);
                assert_eq!(&expected, actual);
                return Err(ErrorKind::Bus);
            }
            (Op::FailedRead(a, expected), [Operation::Write(actual), Operation::Read(_)]) => {
                assert_eq!(a, address);
                assert_eq!(&expected, actual);
                return Err(ErrorKind::Bus);
            }
            other => panic!("unexpected operation: {other:?}"),
        }
        Ok(())
    }
}
impl Drop for Bus {
    fn drop(&mut self) {
        assert!(self.0.is_empty(), "unconsumed expectations");
    }
}

#[test]
fn quadrature_complete_cycles_bounce_and_reversal() {
    let mut q = Quadrature::new(3);
    for state in [1, 3, 1, 0, 1, 0, 2] {
        assert_eq!(q.transition(state), 0);
    }
    assert_eq!(q.transition(3), 1);
    for state in [2, 0, 1] {
        assert_eq!(q.transition(state), 0);
    }
    assert_eq!(q.transition(3), -1);
    // Return before a full detent must not move focus.
    for state in [1, 0, 1, 3] {
        assert_eq!(q.transition(state), 0);
    }
}
#[test]
fn quadrature_invalid_transition_and_partial_start_resynchronize() {
    let mut q = Quadrature::new(0);
    for state in [2, 3, 0, 2, 3] {
        assert_eq!(q.transition(state), 0);
    }
    for _ in 0..1000 {
        for state in [1, 0, 2] {
            assert_eq!(q.transition(state), 0);
        }
        assert_eq!(q.transition(3), 1);
    }
}
#[test]
fn debounce_does_not_repeat_or_accept_bounce() {
    let mut b = Debounce::new(false);
    for (pressed, now) in [(true, 1), (false, 3), (true, 5), (true, 19)] {
        assert_eq!(b.sample(pressed, now), None);
    }
    assert_eq!(b.sample(true, 20), Some(true));
    assert_eq!(b.sample(true, 5000), None);
    assert_eq!(b.sample(false, 5010), None);
    assert_eq!(b.sample(false, 5025), Some(false));
}

#[test]
fn wake_press_keeps_its_gate_through_bounce_and_hold() {
    let mut latch = PressLatch::default();
    assert!(latch.observe(true, 1));
    assert!(!latch.observe(false, 3));
    assert_eq!(latch.deadline(), Some(18));
    assert!(!latch.observe(true, 5));
    assert_eq!(latch.deadline(), None);
    assert!(!latch.observe(true, 5000));
    assert!(!latch.observe(false, 5001));
    assert!(!latch.observe(false, 5016));
    assert!(latch.observe(true, 5017));
}

#[test]
fn every_wake_phase_discards_the_incomplete_cycle_then_counts_normally() {
    for cycle in [[3, 1, 0, 2, 3], [3, 2, 0, 1, 3]] {
        for phase in 0..4 {
            let mut q = Quadrature::new(cycle[phase]);
            if phase != 0 {
                for &ab in &cycle[phase + 1..] {
                    assert_eq!(q.transition(ab), 0);
                }
            }
            for &ab in &cycle[1..4] {
                assert_eq!(q.transition(ab), 0);
            }
            assert_eq!(q.transition(3), if cycle[1] == 1 { 1 } else { -1 });
        }
    }
}
#[test]
fn keyboard_backspace_uses_one_based_fifo_and_suppresses_repeat() {
    let mut kb = Keyboard::new(Bus(VecDeque::new()));
    assert_eq!(kb.decode(0x9d), KeyEvent::Other);
    assert_eq!(kb.decode(0x9e), KeyEvent::BackPress);
    assert_eq!(kb.decode(0x9e), KeyEvent::Other);
    assert_eq!(kb.decode(0x1e), KeyEvent::BackRelease);
    assert_eq!(kb.decode(0x9e), KeyEvent::BackPress);
}
#[test]
fn keyboard_fifo_overflow_discards_incomplete_gesture() {
    let mut ops = vec![Op::Read(0x34, vec![2], vec![8])];
    for _ in 0..10 {
        ops.push(Op::Read(0x34, vec![4], vec![0x9e]));
    }
    ops.push(Op::Write(0x34, vec![2, 0x1f]));
    let mut kb = Keyboard::new(Bus(ops.into()));
    assert_eq!(
        embassy_futures::block_on(kb.next()).unwrap(),
        Some(KeyEvent::Overflow)
    );
}
#[test]
fn gauge_diagnostics_preserve_signed_current_capacities_and_voltage_sentinel() {
    let words: [(u8, u16); 7] = [
        (0x0c, (-237i16) as u16),
        (0x10, 900),
        (0x12, 1500),
        (0x3c, 1500),
        (0x30, 65535),
        (0x0a, 0x0208),
        (0x3a, 0x0060),
    ];
    let ops = words
        .into_iter()
        .map(|(reg, value)| Op::Read(0x55, vec![reg], value.to_le_bytes().to_vec()))
        .collect();
    let reading = embassy_futures::block_on(Battery::new(Bus(ops)).diagnostics()).unwrap();
    assert_eq!(
        reading,
        GaugeDiagnostics {
            current_ma: -237,
            remaining_mah: 900,
            full_mah: 1500,
            design_mah: 1500,
            charging_mv: u16::MAX,
            status: 0x0208,
            operation: 0x0060,
        }
    );
}

#[derive(Default)]
struct GaugeDelay(Vec<u32>);
impl embedded_hal_async::delay::DelayNs for GaugeDelay {
    async fn delay_ns(&mut self, ns: u32) {
        self.0.push(ns);
    }
}

fn gauge_word(ops: &mut Vec<Op>, reg: u8, value: u16) {
    ops.push(Op::Read(0x55, vec![reg], value.to_le_bytes().to_vec()));
}

#[test]
fn battery_group_selects_dependencies_and_preserves_independent_failures() {
    use umsh_ulcp::{
        Status,
        battery_diagnostics::{Fields, Value},
        ids::prop,
    };
    let keys = [
        prop::BATTERY_CURRENT,
        prop::BATTERY_EXT_POWER_PRESENT,
        prop::BATTERY_FULL_CAPACITY,
        prop::BATTERY_PRESENT,
        prop::BATTERY_GAUGE_FULL,
        prop::BATTERY_GAUGE_STATUS,
        prop::BATTERY_GAUGE_INITIALIZED,
        prop::BATTERY_GAUGE_OPERATION_STATUS,
    ];
    let fields = keys.into_iter().fold(Fields::NONE, |fields, key| {
        fields.union(Fields::for_key(key))
    });
    let mut ops = vec![Op::Read(0x6b, vec![0x11], vec![0x80])];
    gauge_word(&mut ops, 0x0a, 0x208);
    gauge_word(&mut ops, 0x3a, 0xa6);
    ops.push(Op::FailedRead(0x55, vec![0x0c]));
    gauge_word(&mut ops, 0x12, 1500);
    let mut delay = GaugeDelay::default();
    let sample =
        embassy_futures::block_on(Battery::new(Bus(ops.into())).sample(fields, &mut delay));
    assert_eq!(sample.get(prop::BATTERY_CURRENT), Err(Status::FAILURE));
    assert_eq!(
        sample.get(prop::BATTERY_FULL_CAPACITY),
        Ok(Some(Value::Unsigned(1500)))
    );
    assert_eq!(
        sample.get(prop::BATTERY_EXT_POWER_PRESENT),
        Ok(Some(Value::Bool(true)))
    );
    assert_eq!(
        sample.get(prop::BATTERY_GAUGE_FULL),
        Ok(Some(Value::Bool(true)))
    );
    assert_eq!(
        sample.get(prop::BATTERY_GAUGE_OPERATION_STATUS),
        Ok(Some(Value::Unsigned(0xa6)))
    );
    assert!(delay.0.iter().all(|&delay| delay >= 100_000));
}

#[test]
fn battery_group_external_power_does_not_touch_the_gauge() {
    use umsh_ulcp::{
        battery_diagnostics::{Fields, Value},
        ids::prop,
    };
    let ops = vec![Op::Read(0x6b, vec![0x11], vec![0])];
    let sample = embassy_futures::block_on(Battery::new(Bus(ops.into())).sample(
        Fields::for_key(prop::BATTERY_EXT_POWER_PRESENT),
        &mut GaugeDelay::default(),
    ));
    assert_eq!(
        sample.get(prop::BATTERY_EXT_POWER_PRESENT),
        Ok(Some(Value::Bool(false)))
    );
}

#[test]
fn live_gauge_telemetry_reads_only_standard_commands_and_fails_as_one_property() {
    use umsh_ulcp::{
        Status, battery_diagnostics::Fields, battery_gauge_telemetry::FIELDS, ids::prop,
    };
    // Success and each possible read failure. No unlock or other writes, and
    // earlier scalar successes remain available if a telemetry read fails.
    for failed in 0..=FIELDS.len() {
        let mut ops = vec![Op::Read(0x6b, vec![0x11], vec![0x80])];
        for (i, field) in FIELDS.iter().enumerate() {
            if i == failed {
                ops.push(Op::FailedRead(0x55, vec![field.register]));
                break;
            }
            gauge_word(&mut ops, field.register, 65535 - i as u16);
        }
        let mut delay = GaugeDelay::default();
        let sample = embassy_futures::block_on(Battery::new(Bus(ops.into())).sample(
            Fields::GAUGE_TELEMETRY.union(Fields::for_key(prop::BATTERY_EXT_POWER_PRESENT)),
            &mut delay,
        ));
        assert_eq!(
            sample.get(prop::BATTERY_EXT_POWER_PRESENT),
            Ok(Some(umsh_ulcp::battery_diagnostics::Value::Bool(true)))
        );
        if failed == FIELDS.len() {
            let sample = sample.gauge_telemetry.unwrap();
            assert_eq!(sample.raw[0], 65535);
            assert_eq!(sample.value(0), -1);
            assert_eq!(sample.value(3), -4);
            assert_eq!(sample.raw[11], 65524);
        } else {
            assert_eq!(sample.gauge_telemetry, Err(Status::FAILURE));
        }
        assert!(delay.0.iter().all(|&ns| ns == 100_000));
    }
}

#[test]
fn battery_group_initializing_gauge_has_no_capacity_estimate() {
    use umsh_ulcp::{
        battery_diagnostics::{Fields, Value},
        ids::prop,
    };
    let mut ops = Vec::new();
    gauge_word(&mut ops, 0x0a, 8);
    gauge_word(&mut ops, 0x3a, 6);
    let sample = embassy_futures::block_on(
        Battery::new(Bus(ops.into())).sample(
            Fields::for_key(prop::BATTERY_FULL_CAPACITY)
                .union(Fields::for_key(prop::BATTERY_GAUGE_INITIALIZED)),
            &mut GaugeDelay::default(),
        ),
    );
    assert_eq!(sample.get(prop::BATTERY_FULL_CAPACITY), Ok(None));
    assert_eq!(
        sample.get(prop::BATTERY_GAUGE_INITIALIZED),
        Ok(Some(Value::Bool(false)))
    );
}

fn gauge_command(ops: &mut Vec<Op>, command: u16) {
    let [lo, hi] = command.to_le_bytes();
    ops.push(Op::Write(0x55, vec![0, lo]));
    ops.push(Op::Write(0x55, vec![1, hi]));
}

fn inspection_block(ops: &mut Vec<Op>, address: u16, bad_checksum: bool) {
    let [lo, hi] = address.to_le_bytes();
    ops.push(Op::Write(0x55, vec![0x3e, lo]));
    ops.push(Op::Write(0x55, vec![0x3f, hi]));
    let mut block = vec![0; 36];
    block[..2].copy_from_slice(&[lo, hi]);
    // Known independent fixture at 0x929A: ID, CEDV, FCC and design.
    if address == 0x929a {
        block[2..9].copy_from_slice(&[0, 0x10, 0x2a, 5, 0x5c, 5, 0xdc]);
    }
    block[34] = !block[..34].iter().copied().fold(0u8, u8::wrapping_add);
    if bad_checksum {
        block[34] ^= 1;
    }
    block[35] = 36;
    ops.push(Op::Read(0x55, vec![0x3e], block));
}

fn inspection_unseal(ops: &mut Vec<Op>) {
    gauge_command(ops, 0x0414);
    gauge_command(ops, 0x3672);
    gauge_word(ops, 0x3a, 4);
}

#[test]
fn inspection_reads_ram_preserves_access_and_never_writes_parameters() {
    use umsh_ulcp::battery_gauge_config::FIELDS;
    for field in FIELDS {
        assert_eq!(
            crate::gauge::CONFIG_BLOCKS
                .iter()
                .filter(|&&(base, len)| field.address >= base
                    && usize::from(field.address - base) + field.width <= len)
                .count(),
            1
        );
    }
    for security in [2, 4, 6] {
        let mut ops = Vec::new();
        gauge_word(&mut ops, 0x3a, security | 0x20);
        if security == 6 {
            inspection_unseal(&mut ops);
        }
        if security != 2 {
            gauge_command(&mut ops, 0xffff);
            gauge_command(&mut ops, 0xffff);
            gauge_word(&mut ops, 0x3a, 2);
        }
        for (address, _) in crate::gauge::CONFIG_BLOCKS {
            inspection_block(&mut ops, address, false);
        }
        if security != 2 {
            gauge_command(&mut ops, 0x0030);
            gauge_word(&mut ops, 0x3a, 6);
            if security == 4 {
                inspection_unseal(&mut ops);
            }
        }
        let mut delay = GaugeDelay::default();
        let result = embassy_futures::block_on(crate::gauge::inspect_configuration(
            &mut Bus(ops.into()),
            &mut delay,
        ))
        .unwrap();
        assert_eq!(
            delay.0.iter().filter(|&&ns| ns == 4_000_000_000).count(),
            if security == 2 { 0 } else { 2 }
        );
        assert_eq!(
            [result.value(3), result.value(4), result.value(5)],
            [0x102a, 1372, 1500]
        );
    }
}

#[test]
fn inspection_reseals_after_any_block_failure_or_interrupted_unseal() {
    for failed in 0..crate::gauge::CONFIG_BLOCKS.len() {
        let mut ops = Vec::new();
        gauge_word(&mut ops, 0x3a, 6);
        inspection_unseal(&mut ops);
        gauge_command(&mut ops, 0xffff);
        gauge_command(&mut ops, 0xffff);
        gauge_word(&mut ops, 0x3a, 2);
        for (i, (address, _)) in crate::gauge::CONFIG_BLOCKS
            .into_iter()
            .enumerate()
            .take(failed + 1)
        {
            inspection_block(&mut ops, address, i == failed);
        }
        gauge_command(&mut ops, 0x0030);
        gauge_word(&mut ops, 0x3a, 6);
        assert!(matches!(
            embassy_futures::block_on(crate::gauge::inspect_configuration(
                &mut Bus(ops.into()),
                &mut GaugeDelay::default()
            )),
            Err(crate::gauge::ConfigError::InvalidBlock { .. })
        ));
    }
    let mut ops = Vec::new();
    gauge_word(&mut ops, 0x3a, 6);
    ops.push(Op::FailedWrite(0x55, vec![0, 0x14]));
    gauge_command(&mut ops, 0x0030);
    gauge_word(&mut ops, 0x3a, 6);
    assert_eq!(
        embassy_futures::block_on(crate::gauge::inspect_configuration(
            &mut Bus(ops.into()),
            &mut GaugeDelay::default()
        )),
        Err(crate::gauge::ConfigError::Bus(ErrorKind::Bus))
    );
}

#[test]
fn inspection_does_not_exit_existing_configuration_mode() {
    let mut ops = Vec::new();
    gauge_word(&mut ops, 0x3a, 0x402);
    assert_eq!(
        embassy_futures::block_on(crate::gauge::inspect_configuration(
            &mut Bus(ops.into()),
            &mut GaugeDelay::default()
        )),
        Err(crate::gauge::ConfigError::ConfigurationBusy)
    );
}

fn gauge_taper_read(ops: &mut Vec<Op>, taper: u16) {
    ops.push(Op::Write(0x55, vec![0x3e, 1]));
    ops.push(Op::Write(0x55, vec![0x3f, 0x92]));
    let mut block = vec![0; 36];
    block[..2].copy_from_slice(&[1, 0x92]);
    block[2..4].copy_from_slice(&taper.to_be_bytes());
    block[34] = !block[..34].iter().copied().fold(0u8, u8::wrapping_add);
    block[35] = 36;
    ops.push(Op::Read(0x55, vec![0x3e], block));
}

fn gauge_access(ops: &mut Vec<Op>, security: u16, taper: u16) {
    if security == 6 {
        inspection_unseal(ops);
    }
    if security != 2 {
        gauge_command(ops, 0xffff);
        gauge_command(ops, 0xffff);
        gauge_word(ops, 0x3a, 2);
    }
    gauge_taper_read(ops, taper);
}

fn gauge_begin_update(ops: &mut Vec<Op>, security: u16) {
    gauge_access(ops, security, 220);
    gauge_command(ops, 0x0090);
}

fn gauge_restore(ops: &mut Vec<Op>, security: u16) {
    if security != 2 {
        gauge_word(ops, 0x3a, 2);
        gauge_command(ops, 0x0030);
        gauge_word(ops, 0x3a, 6);
        if security == 4 {
            inspection_unseal(ops);
        }
    }
}

fn gauge_finish_update(ops: &mut Vec<Op>, security: u16) {
    gauge_command(ops, 0x0091);
    gauge_word(ops, 0x3a, 2);
    gauge_restore(ops, security);
}

fn gauge_capacity_transfer(ops: &mut Vec<Op>, readback: [u8; 6]) {
    // Independent wire fixture: RAM address 0x929D, two BE 1800 mAh
    // parameters (0x0708), checksum 0xB2, total command length eight.
    for (reg, value) in [
        (0x3e, 0x9d),
        (0x3f, 0x92),
        (0x40, 0x07),
        (0x41, 0x08),
        (0x42, 0x07),
        (0x43, 0x08),
        (0x60, 0xb2),
        (0x61, 8),
        (0x3e, 0x9d),
        (0x3f, 0x92),
    ] {
        ops.push(Op::Write(0x55, vec![reg, value]));
    }
    ops.push(Op::Read(0x55, vec![0x3e], readback.to_vec()));
}

#[test]
fn gauge_correct_profile_preserves_learned_full_capacity_without_parameter_writes() {
    let mut ops = Vec::new();
    gauge_word(&mut ops, 0x3a, 0x26);
    gauge_word(&mut ops, 0x3c, 1800);
    gauge_word(&mut ops, 0x12, 1372);
    gauge_access(&mut ops, 6, 220);
    gauge_restore(&mut ops, 6);
    let result = embassy_futures::block_on(
        Battery::new(Bus(ops.into())).ensure_stock_capacity(&mut GaugeDelay::default()),
    )
    .unwrap();
    assert_eq!(
        result,
        crate::gauge::CapacityConfig {
            changed: false,
            design_mah: 1800,
            full_mah: 1372,
            taper_ma: 220,
        }
    );
}

#[test]
fn gauge_repairs_default_capacity_and_restores_each_access_mode() {
    for security in [2, 4, 6] {
        let mut ops = Vec::new();
        gauge_word(&mut ops, 0x3a, 0x20 | security);
        gauge_word(&mut ops, 0x3c, 3000);
        gauge_word(&mut ops, 0x12, 2872);
        gauge_begin_update(&mut ops, security);
        gauge_word(&mut ops, 0x3a, 0x402);
        gauge_capacity_transfer(&mut ops, [0x9d, 0x92, 7, 8, 7, 8]);
        gauge_finish_update(&mut ops, security);
        gauge_word(&mut ops, 0x3c, 1800);
        gauge_word(&mut ops, 0x12, 1800);
        let mut delay = GaugeDelay::default();
        let result = embassy_futures::block_on(
            Battery::new(Bus(ops.into())).ensure_stock_capacity(&mut delay),
        )
        .unwrap();
        assert!(result.changed);
        assert_eq!((result.design_mah, result.full_mah), (1800, 1800));
        assert!(
            delay.0.windows(8).any(|window| window
                == [
                    100_000, 10_000_000, 100_000, 10_000_000, 100_000, 100_000, 100_000, 100_000
                ]),
            "RAM selection must settle before writing the four capacity bytes"
        );
        assert!(
            delay.0.contains(&1_100_000_000),
            "configuration settling delay"
        );
        assert!(
            delay.0.contains(&2_000_000_000),
            "standard-command readback settling delay"
        );
    }
}

#[test]
fn gauge_taper_migration_preserves_learned_capacity_unless_design_changes() {
    for design in [1500, 1800] {
        for readback in [100, 220] {
            let mut ops = Vec::new();
            gauge_word(&mut ops, 0x3a, 0xa6);
            gauge_word(&mut ops, 0x3c, design);
            gauge_word(&mut ops, 0x12, 1372);
            gauge_access(&mut ops, 6, 100);
            gauge_command(&mut ops, 0x0090);
            gauge_word(&mut ops, 0x3a, 0x402);
            // Address 0x9201, BE 220 mA (0x00DC), checksum 0x90.
            for (reg, value) in [
                (0x3e, 1),
                (0x3f, 0x92),
                (0x40, 0),
                (0x41, 0xdc),
                (0x60, 0x90),
                (0x61, 6),
            ] {
                ops.push(Op::Write(0x55, vec![reg, value]));
            }
            gauge_taper_read(&mut ops, readback);
            if readback == 220 && design != 1800 {
                gauge_capacity_transfer(&mut ops, [0x9d, 0x92, 7, 8, 7, 8]);
            }
            gauge_finish_update(&mut ops, 6);
            let expected_full = if design == 1800 { 1372 } else { 1800 };
            if readback == 220 {
                gauge_word(&mut ops, 0x3c, 1800);
                gauge_word(&mut ops, 0x12, expected_full);
            }
            let mut delay = GaugeDelay::default();
            let result = embassy_futures::block_on(
                Battery::new(Bus(ops.into())).ensure_stock_capacity(&mut delay),
            );
            if readback == 220 {
                let result = result.unwrap();
                assert!(result.changed);
                assert_eq!((result.full_mah, result.taper_ma), (expected_full, 220));
            } else {
                assert_eq!(result, Err(crate::gauge::ConfigError::TaperVerify(100)));
            }
            assert_eq!(delay.0.iter().filter(|&&ns| ns == 4_000_000_000).count(), 2);
        }
    }
}

#[test]
fn gauge_failed_transfer_exits_configuration_and_reseals_without_commit() {
    let mut ops = Vec::new();
    gauge_word(&mut ops, 0x3a, 6);
    gauge_word(&mut ops, 0x3c, 3000);
    gauge_word(&mut ops, 0x12, 2872);
    gauge_begin_update(&mut ops, 6);
    gauge_word(&mut ops, 0x3a, 0x402);
    ops.push(Op::Write(0x55, vec![0x3e, 0x9d]));
    ops.push(Op::Write(0x55, vec![0x3f, 0x92]));
    ops.push(Op::FailedWrite(0x55, vec![0x40, 7]));
    gauge_finish_update(&mut ops, 6);
    let result = embassy_futures::block_on(
        Battery::new(Bus(ops.into())).ensure_stock_capacity(&mut GaugeDelay::default()),
    );
    assert_eq!(result, Err(crate::gauge::ConfigError::Bus(ErrorKind::Bus)));
}

#[test]
fn gauge_rejected_checksum_is_detected_and_exits_configuration() {
    let mut ops = Vec::new();
    gauge_word(&mut ops, 0x3a, 2);
    gauge_word(&mut ops, 0x3c, 3000);
    gauge_word(&mut ops, 0x12, 2872);
    gauge_begin_update(&mut ops, 2);
    gauge_word(&mut ops, 0x3a, 0x402);
    gauge_capacity_transfer(&mut ops, [0x9d, 0x92, 0x0b, 0xb8, 0x0b, 0xb8]);
    gauge_finish_update(&mut ops, 2);
    let result = embassy_futures::block_on(
        Battery::new(Bus(ops.into())).ensure_stock_capacity(&mut GaugeDelay::default()),
    );
    assert_eq!(
        result,
        Err(crate::gauge::ConfigError::MemoryVerify([
            0x9d, 0x92, 0x0b, 0xb8, 0x0b, 0xb8
        ]))
    );
}

#[test]
fn gauge_configuration_timeout_is_bounded_and_cleans_up() {
    let mut ops = Vec::new();
    gauge_word(&mut ops, 0x3a, 4);
    gauge_word(&mut ops, 0x3c, 3000);
    gauge_word(&mut ops, 0x12, 2872);
    gauge_begin_update(&mut ops, 4);
    for _ in 0..6 {
        gauge_word(&mut ops, 0x3a, 2);
    }
    gauge_finish_update(&mut ops, 4);
    let result = embassy_futures::block_on(
        Battery::new(Bus(ops.into())).ensure_stock_capacity(&mut GaugeDelay::default()),
    );
    assert_eq!(result, Err(crate::gauge::ConfigError::Timeout));
}

#[test]
fn gauge_recovers_interrupted_configuration_before_reading_capacity() {
    let mut ops = Vec::new();
    gauge_word(&mut ops, 0x3a, 0x402);
    gauge_command(&mut ops, 0x0091);
    gauge_word(&mut ops, 0x3a, 2);
    gauge_word(&mut ops, 0x3c, 1800);
    gauge_word(&mut ops, 0x12, 1470);
    gauge_access(&mut ops, 2, 220);
    let result = embassy_futures::block_on(
        Battery::new(Bus(ops.into())).ensure_stock_capacity(&mut GaugeDelay::default()),
    )
    .unwrap();
    assert!(!result.changed);
    assert_eq!(result.full_mah, 1470);
}

#[test]
fn charger_updates_preserve_unrelated_bits_without_reset_or_gauge_writes() {
    for failed in 0..=4 {
        let before = [0x80, 0xa3, 3, 0x7f];
        let mut after = [0x8b, 0xa2, 0x5b, 0xcf];
        if failed < 4 {
            // Simulate an ACKed write which did not take effect, one per field.
            after[failed] = before[failed];
        }
        let ops = [
            (3, 0xff, 0xcf),
            (9, 0x7c, 0x5c),
            (7, 0x7f, 0xcf),
            (6, 3, 0x5b),
            (5, 0xa3, 0xa2),
            (4, 0x80, 0x8b),
            (2, 0x1d, 0xdd),
        ];
        let mut expected = Vec::new();
        for (i, value) in before.into_iter().enumerate() {
            expected.push(Op::Read(0x6b, vec![4 + i as u8], vec![value]));
        }
        for (reg, old, new) in ops {
            expected.push(Op::Read(0x6b, vec![reg], vec![old]));
            expected.push(Op::Write(0x6b, vec![reg, new]));
        }
        for (i, value) in after.into_iter().enumerate() {
            expected.push(Op::Read(0x6b, vec![4 + i as u8], vec![value]));
        }
        if failed == 4 {
            expected.push(Op::Read(0x6b, vec![3], vec![0xcf]));
            expected.push(Op::Write(0x6b, vec![3, 0xdf]));
        }
        let result = embassy_futures::block_on(Battery::new(Bus(expected.into())).init());
        if failed == 4 {
            assert_eq!(result, Ok(ChargerSetup { before, after }));
            assert_eq!(64 * (1 + u16::from(after[1] & 15)), 192);
            assert_eq!(3840 + 16 * u16::from(after[2] >> 2), 4192);
        } else {
            assert!(
                matches!(result, Err(ChargerError::Verify { register, .. }) if register == 4 + failed as u8)
            );
        }
    }
}

#[test]
fn power_off_disconnects_immediately_and_preserves_charger_policy() {
    for (old, new) in [(0x5c, 0x74), (0x40, 0x60)] {
        let expected = vec![
            Op::Read(0x6b, vec![9], vec![old]),
            Op::Write(0x6b, vec![9, new]),
        ];
        embassy_futures::block_on(Battery::new(Bus(expected.into())).power_off()).unwrap();
    }
}

#[test]
fn power_off_reports_failed_disconnect_for_retry() {
    let expected = vec![
        Op::Read(0x6b, vec![9], vec![0x44]),
        Op::FailedWrite(0x6b, vec![9, 0x64]),
    ];
    assert!(embassy_futures::block_on(Battery::new(Bus(expected.into())).power_off()).is_err());
}
#[test]
fn battery_unknown_is_not_zero_or_charged() {
    let r = decode_reading(0, true, None);
    assert_eq!((r.voltage_mv, r.percent, r.charge), (None, None, None));
    let r = decode_reading(0x18, true, Some((4000, 8, 75, 0x20)));
    assert_eq!(r.percent, Some(75));
    assert_eq!(r.charge, Some(Charge::Charged));
    let r = decode_reading(0, true, Some((4000, 8, 255, 0)));
    assert_eq!((r.percent, r.charge), (None, None));
    assert_eq!(
        decode_reading(0, false, Some((0, 8, 0, 0x20))).voltage_mv,
        None
    );
}
#[test]
fn low_battery_needs_ten_consecutive_valid_unpowered_samples() {
    let mut policy = LowBattery::default();
    let mut r = decode_reading(0, false, Some((3100, 8, 0, 0x20)));
    for _ in 0..9 {
        assert!(!policy.sample(Some(&r)));
    }
    assert!(!policy.sample(None));
    for _ in 0..9 {
        assert!(!policy.sample(Some(&r)));
    }
    r.vbus = true;
    assert!(!policy.sample(Some(&r)));
    r.vbus = false;
    for _ in 0..9 {
        assert!(!policy.sample(Some(&r)));
    }
    assert!(policy.sample(Some(&r)));
}
#[test]
fn rtc_calendar_and_invalid_oscillator() {
    let leap = [0x59, 0x59, 0x23, 0x29, 4, 2, 0x24];
    let epoch = rtc::decode(&leap).unwrap();
    assert_eq!(rtc::encode(epoch), Some(leap));
    let mut bad = leap;
    bad[0] |= 0x80;
    assert_eq!(rtc::decode(&bad), None);
    bad = leap;
    bad[5] = 0x1a;
    assert_eq!(rtc::decode(&bad), None);
    bad = leap;
    bad[6] = 0x23;
    assert_eq!(rtc::decode(&bad), None);
}

#[test]
fn rtc_retains_time_at_init_and_uses_the_pcf85063_register_layout() {
    let date = [0x59, 0x59, 0x23, 0x29, 4, 2, 0x24];
    let epoch = rtc::decode(&date).unwrap();
    let expected = vec![
        Op::Read(0x51, vec![1], vec![0xa0]),
        Op::Write(0x51, vec![1, 0xa7]),
        Op::Read(0x51, vec![0], vec![0]),
        Op::Read(0x51, vec![4], date.to_vec()),
        Op::Read(0x51, vec![0], vec![1]),
        Op::Write(0x51, vec![0, 0x21]),
        Op::Write(0x51, vec![4, 0x59, 0x59, 0x23, 0x29, 4, 2, 0x24]),
        Op::Read(0x51, vec![0], vec![0x21]),
        Op::Write(0x51, vec![0, 1]),
    ];
    embassy_futures::block_on(async {
        let mut clock = rtc::Pcf85063::new(Bus(expected.into()));
        clock.init().await.unwrap();
        assert_eq!(clock.read().await.unwrap(), Some(epoch));
        clock.write(epoch).await.unwrap();
    });
}

#[test]
fn expander_initialization_and_shutdown_keep_unused_domains_off() {
    struct Delay;
    impl embedded_hal_async::delay::DelayNs for Delay {
        async fn delay_ns(&mut self, _: u32) {}
    }
    let expected = vec![
        Op::Write(0x20, vec![2, 0, 0]),
        Op::Write(0x20, vec![4, 0, 0]),
        Op::Write(0x20, vec![6, 0x40, 0xec]),
        Op::Write(0x20, vec![2, 8, 1]),
        Op::Write(0x20, vec![2, 12, 1]),
        Op::Write(0x20, vec![2, 28, 1]),
        Op::Write(0x20, vec![2, 0, 0]),
    ];
    embassy_futures::block_on(async {
        let mut power = Expander::new(Bus(expected.into()));
        power.init(&mut Delay).await.unwrap();
        power.set(GPS_ENABLE, true).await.unwrap();
        power.shutdown().await.unwrap();
        // A GNSS task resuming during shutdown must never re-enable its rail.
        power.set(GPS_ENABLE | GPS_RESET, true).await.unwrap();
    });
}
#[test]
fn framebuffer_clipping_packing_and_last_stripe() {
    use crate::display::*;
    use embedded_graphics::{pixelcolor::BinaryColor, prelude::*};
    let mut fb = Framebuffer::new(Box::leak(Box::new([0; FRAME_BYTES])));
    fb.draw_iter([
        Pixel(Point::new(-1, 0), BinaryColor::On),
        Pixel(Point::new(0, 0), BinaryColor::On),
        Pixel(Point::new(479, 221), BinaryColor::On),
        Pixel(Point::new(480, 221), BinaryColor::On),
    ])
    .unwrap();
    let mut bytes = [0; STRIPE_BYTES];
    assert_eq!(fb.stripe(0, &mut bytes), STRIPE_BYTES);
    assert_eq!(&bytes[..4], &[255, 255, 0, 0]);
    let len = fb.stripe(220, &mut bytes);
    assert_eq!(len, 1920);
    assert_eq!(&bytes[len - 2..len], &[255, 255]);
}

#[test]
fn repainting_an_unchanged_frame_needs_no_transfers() {
    use crate::display::*;
    use embedded_graphics::{pixelcolor::BinaryColor, prelude::*};
    let mut frame = Framebuffer::new(Box::leak(Box::new([0; FRAME_BYTES])));
    let mut sent = Framebuffer::new(Box::leak(Box::new([0; FRAME_BYTES])));
    let pixel = Pixel(Point::new(20, 26), BinaryColor::On);
    frame.draw_iter([pixel]).unwrap();
    assert!(!frame.stripe_matches(24, &sent));
    assert!(frame.stripe_matches(28, &sent));
    // Only successful transfers update history; an uncommitted stripe retries.
    assert!(!frame.stripe_matches(24, &sent));
    sent.copy_stripe_from(24, &frame);
    frame.clear(BinaryColor::Off).unwrap();
    frame.draw_iter([pixel]).unwrap();
    assert!(
        (0..HEIGHT)
            .step_by(STRIPE_ROWS)
            .all(|y| frame.stripe_matches(y, &sent))
    );
    frame.clear(BinaryColor::Off).unwrap();
    assert!(!frame.stripe_matches(24, &sent));
    assert_eq!(
        (0..HEIGHT)
            .step_by(STRIPE_ROWS)
            .filter(|&y| !frame.stripe_matches(y, &sent))
            .count(),
        1
    );
    // The short final stripe follows the same history rules.
    frame
        .draw_iter([Pixel(Point::new(479, 221), BinaryColor::On)])
        .unwrap();
    assert!(!frame.stripe_matches(220, &sent));
    sent.copy_stripe_from(220, &frame);
    assert!(frame.stripe_matches(220, &sent));
}
