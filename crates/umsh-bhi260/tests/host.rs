use embassy_futures::block_on;
use embedded_hal_async::{
    delay::DelayNs,
    i2c::{ErrorKind, ErrorType, I2c, Operation},
};
use std::collections::VecDeque;
use umsh_bhi260::{ADDRESS, Bhi260, Error, SensorSet, TRANSFER_BYTES};

enum Step {
    Write(Vec<u8>),
    Read(u8, Vec<u8>),
    Fail(u8),
}

struct Bus(VecDeque<Step>);
impl ErrorType for Bus {
    type Error = ErrorKind;
}
impl I2c for Bus {
    async fn transaction(
        &mut self,
        address: u8,
        ops: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        assert_eq!(address, ADDRESS);
        match (self.0.pop_front().expect("unexpected transaction"), ops) {
            (Step::Write(expected), [Operation::Write(actual)]) => assert_eq!(*actual, expected),
            (Step::Read(reg, data), [Operation::Write(actual), Operation::Read(out)]) => {
                assert_eq!(*actual, [reg]);
                assert_eq!(out.len(), data.len());
                out.copy_from_slice(&data);
            }
            (Step::Fail(reg), [Operation::Write(actual), Operation::Read(_)]) => {
                assert_eq!(*actual, [reg]);
                return Err(ErrorKind::Other);
            }
            _ => panic!("wrong transaction shape"),
        }
        Ok(())
    }
}
#[derive(Default)]
struct Delay(u64);
impl DelayNs for Delay {
    async fn delay_ns(&mut self, ns: u32) {
        self.0 += u64::from(ns);
    }
}
fn driver(steps: Vec<Step>) -> Bhi260<Bus> {
    Bhi260::new(Bus(steps.into()), ADDRESS)
}
fn read(reg: u8, bytes: &[u8]) -> Step {
    Step::Read(reg, bytes.to_vec())
}
fn write(bytes: &[u8]) -> Step {
    Step::Write(bytes.to_vec())
}

#[test]
fn hardware_timestamp_is_fresh_or_fails_with_a_bound() {
    let mut sensor = driver(vec![
        read(0x26, &[0; 5]),
        write(&[0x15, 1]),
        read(0x26, &[64, 1, 0, 0, 0]),
    ]);
    assert_eq!(block_on(sensor.timestamp(&mut Delay::default())), Ok(320));
    let mut steps = vec![read(0x26, &[0; 5]), write(&[0x15, 1])];
    for _ in 0..5 {
        steps.push(read(0x26, &[0; 5]));
    }
    let mut sensor = driver(steps);
    assert_eq!(
        block_on(sensor.timestamp(&mut Delay::default())),
        Err(Error::Timeout)
    );
}

#[test]
fn an_already_asserted_interrupt_is_data_not_a_reset() {
    use umsh_bhi260::{InterruptStatus, fifo::Kind};
    let irq = InterruptStatus(0x0b);
    assert!(irq.asserted());
    assert!(irq.fifo(Kind::Wake));
    assert!(irq.fifo(Kind::NonWake));
    assert!(!irq.fault());
    assert!(InterruptStatus(0x81).fault());
    assert!(!InterruptStatus(0).asserted());
}

#[test]
fn upload_streams_one_word_count_header_and_preserves_all_image_bytes() {
    let mut firmware = vec![0xab; 520];
    firmware[..2].copy_from_slice(&[0x2b, 0x66]);
    let mut first = vec![0, 2, 0, 130, 0];
    first.extend_from_slice(&firmware[..TRANSFER_BYTES - 4]);
    let mut steps = vec![
        read(0x1c, &[0x89]),
        write(&[0x14, 1]),
        read(0x25, &[0x10]),
        write(&[5, 0]),
        write(&[6, 0x40]),
        write(&[7, 0x0c]),
        Step::Write(first),
    ];
    for chunk in firmware[TRANSFER_BYTES - 4..].chunks(TRANSFER_BYTES) {
        let mut packet = vec![0];
        packet.extend_from_slice(chunk);
        steps.push(Step::Write(packet));
    }
    steps.extend([
        read(0x25, &[0x10]),
        read(0x25, &[0x30]),
        write(&[0, 3, 0, 0, 0]),
        read(0x25, &[0x30]),
        read(0x1c, &[0x89, 2, 3, 0, 0, 0, 0, 0]),
        read(0x1c, &[0x89, 2, 3, 0, 0x34, 0x12, 5, 0]),
    ]);
    let mut dev = driver(steps);
    let version = block_on(dev.boot(&firmware, &mut Delay::default())).unwrap();
    assert_eq!(version.kernel, 0x1234);
    assert_eq!(version.user, 5);
    assert!(dev.into_inner().0.is_empty());
}

#[test]
fn invalid_images_do_not_touch_hardware() {
    for firmware in [&[][..], &[0x2b, 0x66, 0], &[0, 0, 0, 0]] {
        let mut dev = driver(vec![]);
        assert_eq!(
            block_on(dev.boot(firmware, &mut Delay::default())),
            Err(Error::InvalidFirmware)
        );
    }
}

#[test]
fn boot_verification_errors_stop_immediately() {
    let mut dev = driver(vec![write(&[0x14, 1]), read(0x25, &[0x50])]);
    assert_eq!(
        block_on(dev.reset(&mut Delay::default())),
        Err(Error::FirmwareVerification(0x50))
    );
    assert!(dev.into_inner().0.is_empty());
}

#[test]
fn parameter_waits_for_status_and_validates_the_reply() {
    let mut bitmap = [0; 32];
    bitmap[9] = 1 << 5; // Sensor 77.
    let mut dev = driver(vec![
        write(&[0, 0x1f, 0x11, 0, 0]),
        read(0x2d, &[0]),
        read(0x2d, &[0x20]),
        read(3, &[0x1f, 1, 32, 0]),
        read(3, &bitmap),
    ]);
    let set = block_on(dev.virtual_sensors(&mut Delay::default())).unwrap();
    assert!(set.contains(77));
    assert!(!set.contains(75));
    assert!(!set.contains(143));
    assert!(dev.into_inner().0.is_empty());
}

#[test]
fn parameter_errors_drain_the_reply_and_leave_output_untouched() {
    for (code, length) in [(0x120u16, 32usize), (0x11f, 260)] {
        let mut header = code.to_le_bytes().to_vec();
        header.extend_from_slice(&(length as u16).to_le_bytes());
        let mut steps = vec![
            write(&[0, 0x1f, 0x11, 0, 0]),
            read(0x2d, &[0x20]),
            read(3, &header),
        ];
        for chunk in vec![0x55; length].chunks(TRANSFER_BYTES) {
            steps.push(read(3, chunk));
        }
        let mut dev = driver(steps);
        let mut out = [0xa5; 32];
        assert!(block_on(dev.parameter(0x11f, &mut out, &mut Delay::default())).is_err());
        assert_eq!(out, [0xa5; 32]);
        assert!(dev.into_inner().0.is_empty());
    }
}

#[test]
fn a_missing_response_has_a_finite_deadline() {
    let mut steps = vec![write(&[0, 0x1f, 0x11, 0, 0])];
    steps.extend((0..100).map(|_| read(0x2d, &[0])));
    let mut dev = driver(steps);
    let mut delay = Delay::default();
    assert_eq!(
        block_on(dev.virtual_sensors(&mut delay)),
        Err(Error::Timeout)
    );
    assert_eq!(delay.0, 1_000_000_000);
    assert!(dev.into_inner().0.is_empty());
}

#[test]
fn bus_errors_are_not_retried_in_a_spin() {
    let mut dev = driver(vec![write(&[0, 0x1f, 0x11, 0, 0]), Step::Fail(0x2d)]);
    assert_eq!(
        block_on(dev.virtual_sensors(&mut Delay::default())),
        Err(Error::Bus(ErrorKind::Other))
    );
    assert!(dev.into_inner().0.is_empty());
}

#[test]
fn bitmap_covers_the_full_sensor_id_range() {
    let mut set = SensorSet([0; 32]);
    set.0[31] = 0x80;
    assert!(set.contains(255));
    assert!(!set.contains(0));
}

#[test]
fn sensor_configuration_encodes_float_rate_and_24_bit_latency() {
    let mut dev = driver(vec![
        write(&[0, 0x0d, 0, 8, 0, 77, 0, 0, 0x80, 0x3f, 0x56, 0x34, 0x12]),
        write(&[0, 0x0d, 0, 8, 0, 77, 0, 0, 0, 0, 0, 0, 0]),
    ]);
    block_on(dev.configure_sensor(77, 1.0, 0x12_3456)).unwrap();
    block_on(dev.configure_sensor(77, 0.0, 0)).unwrap();
    assert!(dev.into_inner().0.is_empty());
}

#[test]
fn invalid_sensor_configuration_does_not_write_a_command() {
    let mut dev = driver(vec![]);
    for (id, rate, latency) in [
        (0, 1.0, 0),
        (224, 1.0, 0),
        (77, f32::NAN, 0),
        (77, -1.0, 0),
        (77, 1.0, 0x100_0000),
    ] {
        assert_eq!(
            block_on(dev.configure_sensor(id, rate, latency)),
            Err(Error::InvalidArgument)
        );
    }
}

#[test]
fn a_fifo_header_is_read_once_per_transfer_not_once_per_chunk() {
    use umsh_bhi260::fifo::Kind;
    let mut dev = driver(vec![
        read(1, &[5, 0]),
        read(1, &[77, 1, 2]),
        read(1, &[3, 4]),
        read(1, &[0, 0]),
    ]);
    let mut remaining = 0;
    let mut out = [0; 3];
    assert_eq!(
        block_on(dev.read_fifo(Kind::Wake, &mut remaining, &mut out)),
        Ok(3)
    );
    assert_eq!(remaining, 2);
    assert_eq!(
        block_on(dev.read_fifo(Kind::Wake, &mut remaining, &mut out)),
        Ok(2)
    );
    assert_eq!(remaining, 0);
    assert_eq!(
        block_on(dev.read_fifo(Kind::Wake, &mut remaining, &mut out)),
        Ok(0)
    );
    assert!(dev.into_inner().0.is_empty());
}
