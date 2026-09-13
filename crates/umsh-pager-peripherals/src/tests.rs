use crate::{input::*, power::*, rtc};
use embedded_hal::i2c::{ErrorKind, ErrorType};
use embedded_hal_async::i2c::{I2c, Operation};
use std::{boxed::Box, collections::VecDeque, vec, vec::Vec};

#[derive(Debug)]
enum Op {
    Write(u8, Vec<u8>),
    Read(u8, Vec<u8>, Vec<u8>),
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
fn charger_updates_preserve_unrelated_bits_without_reset_or_gauge_writes() {
    let ops = [
        (3, 0xff, 0xcf),
        (7, 0xff, 0xcf),
        (6, 3, 0x5b),
        (4, 0x80, 0x8b),
        (2, 0x1d, 0xdd),
        (3, 0xcf, 0xdf),
    ];
    let mut expected = Vec::new();
    for (reg, old, new) in ops {
        expected.push(Op::Read(0x6b, vec![reg], vec![old]));
        expected.push(Op::Write(0x6b, vec![reg, new]));
    }
    embassy_futures::block_on(Battery::new(Bus(expected.into())).init()).unwrap();
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
