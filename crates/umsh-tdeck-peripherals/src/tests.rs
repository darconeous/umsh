use crate::battery::Rail;
use crate::es7210;
use crate::gt911::{Gt911, Point, Polarity, Report, landscape};
use crate::keyboard::{Identity, Key, Latch, Status, identity, key, status};
use crate::trackball::{AXIS_LOCK_MS, Direction::*, IDLE_MS, Trackball};
use embedded_hal::i2c::{ErrorKind, ErrorType};
use embedded_hal_async::i2c::{I2c, Operation};
use std::{collections::VecDeque, vec, vec::Vec};

#[test]
fn a_step_takes_the_threshold_of_edges_one_way() {
    let mut ball = Trackball::new(3);
    assert_eq!(ball.edge(Down, 0), None);
    assert_eq!(ball.edge(Down, 5), None);
    assert_eq!(ball.edge(Down, 10), Some(Down));
    // The count starts over after a step.
    assert_eq!(ball.edge(Down, 15), None);
}

#[test]
fn a_roll_back_takes_back_what_was_counted() {
    let mut ball = Trackball::new(2);
    assert_eq!(ball.edge(Right, 0), None);
    assert_eq!(ball.edge(Left, 5), None);
    assert_eq!(ball.edge(Right, 10), None);
    assert_eq!(ball.edge(Right, 15), Some(Right));
}

#[test]
fn a_pause_starts_the_count_over() {
    let mut ball = Trackball::new(2);
    assert_eq!(ball.edge(Up, 0), None);
    assert_eq!(ball.edge(Up, IDLE_MS), None);
    assert_eq!(ball.edge(Up, IDLE_MS + 5), Some(Up));
}

#[test]
fn the_other_axis_waits_out_the_lock_after_a_step() {
    let mut ball = Trackball::new(1);
    assert_eq!(ball.edge(Down, 0), Some(Down));
    // Wobble across the roll is not a step.
    assert_eq!(ball.edge(Left, 10), None);
    // Along the roll is.
    assert_eq!(ball.edge(Down, 20), Some(Down));
    assert_eq!(ball.edge(Left, 20 + AXIS_LOCK_MS), Some(Left));
}

#[test]
fn key_mode_bytes_map_to_keys() {
    assert_eq!(key(0), None);
    assert_eq!(key(b'a'), Some(Key::Character('a')));
    assert_eq!(key(b'A'), Some(Key::Character('A')));
    assert_eq!(key(b'@'), Some(Key::Character('@')));
    assert_eq!(key(b' '), Some(Key::Space));
    assert_eq!(key(0x0d), Some(Key::Enter));
    assert_eq!(key(0x08), Some(Key::Backspace));
    assert_eq!(key(0x0c), Some(Key::AltC));
    assert_eq!(key(0x04), Some(Key::Mute));
    // Shift on a symbol, from stock firmware.
    assert_eq!(key(0x11), Some(Key::Character('1')));
    assert_eq!(key(0x7f), None);
    assert_eq!(key(0xe0), None);
}

#[test]
fn umsh_firmware_identifies_itself_and_stock_gives_a_key() {
    // What the keyboard firmware sends for protocol 1.1 with sleep.
    let ours = [0xa5, 0x5a, 1, 1, 0x00, 0x01, 0x07];
    let found = identity(&ours).unwrap();
    assert_eq!(
        found,
        Identity {
            major: 1,
            minor: 1,
            capabilities: 1
        }
    );
    assert!(found.sleeps());
    // A damaged reply is not trusted.
    let mut damaged = ours;
    damaged[5] = 0;
    assert_eq!(identity(&damaged), None);
    // Stock firmware: a key, then whatever the bus gives.
    assert_eq!(identity(&[b'q', 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), None);
}

#[test]
fn protocol_1_2_reports_its_status() {
    // Sleep and status.
    let found = identity(&[0xa5, 0x5a, 1, 2, 0x00, 0x03, 0xb4]).unwrap();
    assert!(found.sleeps() && found.reports_status());
    // Protocol 1.1 does not.
    assert!(
        !Identity {
            major: 1,
            minor: 1,
            capabilities: 1
        }
        .reports_status()
    );
}

#[test]
fn the_status_byte_decodes() {
    assert_eq!(status(0), Status::default());
    let latches = [
        (1, Latch::ShiftNext),
        (2, Latch::SymNext),
        // Alt next, which nothing sends yet.
        (3, Latch::None),
        (4, Latch::CapsLock),
        (5, Latch::SymLock),
        (6, Latch::None),
        (7, Latch::None),
    ];
    for (code, latch) in latches {
        assert_eq!(status(code).latch, latch);
    }
    assert_eq!(
        status(0b1111_1100),
        Status {
            latch: Latch::CapsLock,
            light: true,
            left_shift: true,
            right_shift: true,
            alt: true,
            repeat: true,
        }
    );
    assert_eq!(
        status(0b0001_0000),
        Status {
            left_shift: true,
            ..Status::default()
        }
    );
}

#[test]
fn the_rail_tells_battery_from_external_power() {
    assert_eq!(Rail::classify(0), Rail::Off);
    assert_eq!(Rail::classify(3700), Rail::Battery(3700));
    assert_eq!(Rail::classify(4200), Rail::Battery(4200));
    assert_eq!(Rail::classify(4550), Rail::External);
}

#[test]
fn touch_polarity_is_the_opposite_of_idle() {
    let low = Polarity::from_idle(true);
    assert_eq!(low, Polarity::ActiveLow);
    assert!(low.asserted(false) && !low.asserted(true));
    let high = Polarity::from_idle(false);
    assert!(high.asserted(true) && !high.asserted(false));
}

#[test]
fn portrait_points_turn_to_landscape() {
    assert_eq!(landscape(0, 0), Point { x: 0, y: 239 });
    assert_eq!(landscape(239, 319), Point { x: 319, y: 0 });
    // Out of range is held to the edge.
    assert_eq!(landscape(400, 400), Point { x: 319, y: 0 });
}

#[derive(Debug)]
enum Op {
    Write(u8, Vec<u8>),
    Read(u8, Vec<u8>, Vec<u8>),
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
fn the_gt911_is_found_at_either_address_and_reports_points() {
    embassy_futures::block_on(async {
        let bus = Bus(VecDeque::from([
            Op::FailedRead(0x5d, vec![0x81, 0x40]),
            Op::Read(0x14, vec![0x81, 0x40], b"911\0".to_vec()),
            // Nothing new.
            Op::Read(0x14, vec![0x81, 0x4e], vec![0x00; 6]),
            // One point: raw (10, 300).
            Op::Read(0x14, vec![0x81, 0x4e], vec![0x81, 0, 10, 0, 0x2c, 1]),
            Op::Write(0x14, vec![0x81, 0x4e, 0]),
            // Lifted.
            Op::Read(0x14, vec![0x81, 0x4e], vec![0x80, 0, 0, 0, 0, 0]),
            Op::Write(0x14, vec![0x81, 0x4e, 0]),
            Op::Write(0x14, vec![0x80, 0x40, 5]),
        ]));
        let Ok(mut touch) = Gt911::probe(bus).await else {
            panic!("not found");
        };
        assert_eq!(touch.address(), 0x14);
        assert_eq!(touch.read().await, Ok(Report::Pending));
        assert_eq!(
            touch.read().await,
            Ok(Report::Touched(Point { x: 300, y: 229 }))
        );
        assert_eq!(touch.read().await, Ok(Report::Released));
        touch.sleep().await.unwrap();
    });
}

/// A controller at 0x5d whose status reads come from `statuses` in turn.
fn polarity_bus(statuses: &[u8]) -> Bus {
    let mut ops = vec![Op::Read(0x5d, vec![0x81, 0x40], b"911\0".to_vec())];
    for &status in statuses {
        let mut report = vec![0; 6];
        report[0] = status;
        ops.push(Op::Read(0x5d, vec![0x81, 0x4e], report));
        if status & 0x80 != 0 {
            ops.push(Op::Write(0x5d, vec![0x81, 0x4e, 0]));
        }
    }
    Bus(VecDeque::from(ops))
}

#[test]
fn touch_polarity_comes_from_the_line_between_two_empty_reads() {
    embassy_futures::block_on(async {
        let Ok(mut touch) = Gt911::probe(polarity_bus(&[0, 0])).await else {
            panic!("not found");
        };
        assert_eq!(
            touch.idle_polarity(|| true).await,
            Ok(Some(Polarity::ActiveLow))
        );
        let Ok(mut touch) = Gt911::probe(polarity_bus(&[0, 0])).await else {
            panic!("not found");
        };
        assert_eq!(
            touch.idle_polarity(|| false).await,
            Ok(Some(Polarity::ActiveHigh))
        );
    });
}

#[test]
fn a_report_around_the_sample_leaves_the_polarity_unknown() {
    embassy_futures::block_on(async {
        // A finger down before the sample: the line is never looked at.
        let Ok(mut touch) = Gt911::probe(polarity_bus(&[0x81])).await else {
            panic!("not found");
        };
        assert_eq!(
            touch
                .idle_polarity(|| panic!("sampled under a report"))
                .await,
            Ok(None)
        );
        // A release reported just after it.
        let Ok(mut touch) = Gt911::probe(polarity_bus(&[0, 0x80])).await else {
            panic!("not found");
        };
        assert_eq!(touch.idle_polarity(|| true).await, Ok(None));
    });
}

#[test]
fn the_microphone_adc_powers_down_microphones_then_analog_then_clocks() {
    embassy_futures::block_on(async {
        let mut bus = Bus(VecDeque::from([
            Op::Write(0x40, vec![0x47, 0xff]),
            Op::Write(0x40, vec![0x48, 0xff]),
            Op::Write(0x40, vec![0x49, 0xff]),
            Op::Write(0x40, vec![0x4a, 0xff]),
            Op::Write(0x40, vec![0x4b, 0xff]),
            Op::Write(0x40, vec![0x4c, 0xff]),
            Op::Write(0x40, vec![0x40, 0xc0]),
            Op::Write(0x40, vec![0x01, 0x7f]),
            Op::Write(0x40, vec![0x06, 0x07]),
        ]));
        es7210::power_down(&mut bus).await.unwrap();
    });
}

#[test]
fn no_answer_is_no_touch_panel() {
    embassy_futures::block_on(async {
        let bus = Bus(VecDeque::from([
            Op::FailedRead(0x5d, vec![0x81, 0x40]),
            Op::FailedRead(0x14, vec![0x81, 0x40]),
        ]));
        assert!(Gt911::probe(bus).await.is_err());
    });
}
