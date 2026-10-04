extern crate std;
use super::*;
use embassy_futures::{
    block_on,
    join::join,
    select::{Either, select},
};
use embedded_hal::i2c::{ErrorKind, ErrorType};
use embedded_hal_async::i2c::Operation;
use std::{collections::VecDeque, vec, vec::Vec};

// Bosch worked temperature vector: dig_T1=27504, T2=26435, T3=-1000,
// adc_T=519888 gives 25.08 C, or 298.2 K after wire quantization.
const TRIM: [u8; 6] = [0x70, 0x6b, 0x43, 0x67, 0x18, 0xfc];
enum Step {
    Write(Vec<u8>),
    Read(u8, Vec<u8>),
    Fail,
}
struct Bus {
    steps: VecDeque<Step>,
    address: u8,
}
impl ErrorType for Bus {
    type Error = ErrorKind;
}
impl I2c for Bus {
    async fn transaction(
        &mut self,
        address: u8,
        ops: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        assert_eq!(address, self.address);
        match self.steps.pop_front().expect("unexpected transaction") {
            Step::Write(bytes) => match ops {
                [Operation::Write(actual)] => assert_eq!(*actual, bytes),
                _ => panic!("expected write"),
            },
            Step::Read(reg, bytes) => match ops {
                [Operation::Write(actual), Operation::Read(out)] => {
                    assert_eq!(*actual, [reg]);
                    out.copy_from_slice(&bytes);
                }
                _ => panic!("expected register read"),
            },
            Step::Fail => return Err(ErrorKind::Other),
        }
        Ok(())
    }
}
#[derive(Default)]
struct Delay {
    ms: u32,
}
impl DelayNs for Delay {
    async fn delay_ns(&mut self, ns: u32) {
        self.ms += ns / 1_000_000;
    }
}
fn reading(raw: u32) -> Vec<Step> {
    vec![
        Step::Read(0xd0, vec![0x60]),
        Step::Write(vec![0xf4, 0]),
        Step::Read(0xf3, vec![0]),
        Step::Read(0x88, TRIM.to_vec()),
        Step::Write(vec![0xf5, 0]),
        Step::Write(vec![0xf2, 0]),
        Step::Write(vec![0xf4, 0x21]),
        Step::Read(0xf3, vec![0]),
        Step::Read(
            0xfa,
            vec![(raw >> 12) as u8, (raw >> 4) as u8, (raw << 4) as u8],
        ),
    ]
}

#[test]
fn compensation_handles_signed_trims_and_invalid_data() {
    assert_eq!(compensate(TRIM, 519888), Some(2982));
    // Lower ADC input produces a negative Celsius reading.
    assert_eq!(compensate(TRIM, 400000), Some(2605));
    for raw in [0, 0x80000, 0xfffff, u32::MAX] {
        assert_eq!(compensate(TRIM, raw), None);
    }
    assert_eq!(compensate([0; 6], 519888), None);
    assert_eq!(compensate([255; 6], 519888), None);
    // Corrupt trims stay bounded even in debug builds.
    for raw in [1, 0xffffe] {
        let _ = compensate([255, 255, 0, 128, 255, 127], raw);
    }
}

#[test]
fn every_get_forces_temperature_only_and_reloads_calibration() {
    for address in [0x76, 0x77] {
        let mut bus = Bus {
            steps: reading(519888).into_iter().chain(reading(400000)).collect(),
            address,
        };
        let mut delay = Delay::default();
        assert_eq!(block_on(sample(&mut bus, address, &mut delay)), Ok(2982));
        assert_eq!(block_on(sample(&mut bus, address, &mut delay)), Ok(2605));
        assert_eq!(delay.ms, 10);
        assert!(bus.steps.is_empty());
    }
}

#[test]
fn probe_never_samples_and_rejects_other_chips() {
    for (id, expected) in [
        (0x60, Ok(())),
        (0x58, Err(Error::WrongChip)),
        (0xff, Err(Error::WrongChip)),
    ] {
        let mut bus = Bus {
            steps: [Step::Read(0xd0, vec![id])].into(),
            address: 0x77,
        };
        assert_eq!(block_on(probe(&mut bus, 0x77)), expected);
        assert!(bus.steps.is_empty());
    }
}

#[test]
fn errors_do_not_return_old_readings_and_next_get_can_recover() {
    let mut steps: VecDeque<_> = reading(0x80000).into();
    steps.push_back(Step::Fail);
    steps.extend(reading(519888));
    let mut bus = Bus {
        steps,
        address: 0x77,
    };
    let mut delay = Delay::default();
    assert_eq!(
        block_on(sample(&mut bus, 0x77, &mut delay)),
        Err(Error::InvalidReading)
    );
    assert_eq!(
        block_on(sample(&mut bus, 0x77, &mut delay)),
        Err(Error::Bus(ErrorKind::Other))
    );
    assert_eq!(block_on(sample(&mut bus, 0x77, &mut delay)), Ok(2982));
}

#[test]
fn busy_or_nvm_copy_is_bounded_and_never_reads_stale_data() {
    for status in [1, 8, 9] {
        let mut steps: VecDeque<_> = reading(519888).into_iter().take(7).collect();
        for _ in 0..40 {
            steps.push_back(Step::Read(0xf3, vec![status]));
        }
        let mut bus = Bus {
            steps,
            address: 0x77,
        };
        let mut delay = Delay::default();
        assert_eq!(
            block_on(sample(&mut bus, 0x77, &mut delay)),
            Err(Error::Timeout)
        );
        assert_eq!(delay.ms, 205);
        assert!(bus.steps.is_empty());
    }
}

#[test]
fn canceled_request_cannot_supply_next_requests_reading() {
    let service = service::Service::new();
    assert_eq!(block_on(service.sample()), None);
    service.detected(0x77);
    let old = match block_on(select(service.sample(), service.request())) {
        Either::Second(id) => id,
        _ => panic!("sampling must await the worker"),
    };
    service.complete(old, Some(2800));
    let (value, ()) = block_on(join(service.sample(), async {
        let new = service.request().await;
        assert_ne!(old, new);
        service.complete(new, Some(2982));
    }));
    assert_eq!(value, Some(2982));
    let (value, ()) = block_on(join(service.sample(), async {
        let request = service.request().await;
        service.complete(request, None);
    }));
    assert_eq!(value, None);
    assert_eq!(service.address(), Some(0x77));
}

#[test]
fn canceled_inflight_acquisition_can_complete_after_next_request_starts() {
    let service = service::Service::new();
    service.detected(0x77);
    let old = match block_on(select(service.sample(), service.request())) {
        Either::Second(id) => id,
        _ => panic!("expected pending acquisition"),
    };
    let (value, ()) = block_on(join(service.sample(), async {
        let new = service.request().await;
        service.complete(old, Some(2800));
        // Give the new waiter a chance to consume and reject the old reply.
        embassy_futures::yield_now().await;
        service.complete(new, Some(3000));
    }));
    assert_eq!(value, Some(3000));
}
