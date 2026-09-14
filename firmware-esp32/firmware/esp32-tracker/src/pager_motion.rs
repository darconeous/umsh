//! Pager adapter: stock BHI260AP activity/tilt interrupts, with bounded
//! acceleration windows. No timer samples the accelerometer while idle.
use super::*;
use umsh_bhi260::{
    ADDRESS, Bhi260,
    fifo::{Decoder, Kind},
};
use umsh_motion::{
    Acceleration, Activity, Availability, DisplayPolicy, State,
    service::{Service, Wake},
};

pub static SERVICE: Service = Service::new();
static FIRMWARE: &[u8] = include_bytes!("../../../assets/bhi260/BHI260AP.fw");

#[derive(Debug)]
enum Fault {
    Initialization,
    Timeout,
    Bus,
    Timestamp,
    Decoder,
    Discontinuity,
    HubReset,
    Range,
    TransferLimit,
    InterruptStuck,
    Gpio,
    DrainLimit,
}

fn publish(state: State) {
    SERVICE.observations.sender().send(state);
}

#[embassy_executor::task]
pub async fn task(bus: &'static board::I2cBus, pin: peripherals::GPIO8<'static>) {
    let mut irq = Input::new(pin, InputConfig::default());
    let mut sensor = Bhi260::new(I2cDevice::new(bus), ADDRESS);
    let mut state = State::new();
    let mut failures = 0u8;
    // Also stop a diagnostic image left running across an ESP32-only reset.
    let _ = with_timeout(Duration::from_secs(6), sensor.reset(&mut Delay)).await;
    loop {
        SERVICE.changed.reset();
        let control = SERVICE.control();
        if !control.sensing() || failures >= 3 {
            state.invalidate(if failures >= 3 {
                Availability::Failed
            } else {
                Availability::Disabled
            });
            publish(state);
            if control.shutdown {
                SERVICE.stopped.signal(());
                return;
            }
            SERVICE.changed.wait().await;
            failures = 0;
            continue;
        }
        state.invalidate(Availability::Starting);
        publish(state);
        // Startup can be canceled, followed by reset to restore command framing.
        // Once running, policy changes leave other consumers' sensing active.
        let failed = match select(
            with_timeout(Duration::from_secs(20), initialize(&mut sensor)),
            SERVICE.changed.wait(),
        )
        .await
        {
            Either::First(Ok(Ok(()))) => {
                state.availability = Availability::Ready;
                publish(state);
                debug_log(format_args!(
                    "motion: ready; activity + tilt, gyro suspended"
                ));
                run(&mut sensor, &mut irq, &mut state).await.err()
            }
            Either::First(Ok(Err(()))) => Some(Fault::Initialization),
            Either::First(Err(_)) => Some(Fault::Timeout),
            Either::Second(()) => None,
        };
        SERVICE.cancel();
        state.invalidate(if failed.is_some() {
            Availability::Failed
        } else {
            Availability::Disabled
        });
        publish(state);
        let _ = with_timeout(Duration::from_secs(6), sensor.reset(&mut Delay)).await;
        if let Some(fault) = failed {
            failures += 1;
            debug_log(format_args!(
                "motion: failure={fault:?}; recovery {failures}/3"
            ));
            if failures < 3 {
                // At most two timed retries per configuration. Once exhausted,
                // only an explicit consumer change or reboot tries again.
                let _ = select(
                    Timer::after_secs(5 * u64::from(failures)),
                    SERVICE.changed.wait(),
                )
                .await;
            }
        }
    }
}

async fn initialize<I: embedded_hal_async::i2c::I2c>(sensor: &mut Bhi260<I>) -> Result<(), ()> {
    sensor.boot(FIRMWARE, &mut Delay).await.map_err(|_| ())?;
    debug_log(format_args!("motion: firmware loaded"));
    let ticks = sensor.timestamp(&mut Delay).await.map_err(|_| ())?;
    debug_log(format_args!("motion: timestamp latch={ticks}"));
    let set = sensor.virtual_sensors(&mut Delay).await.map_err(|_| ())?;
    if ![1, 48, 63].iter().all(|id| set.contains(*id)) {
        return Err(());
    }
    let physical = sensor.physical_sensors(&mut Delay).await.map_err(|_| ())?;
    if physical[0] != 0x0a || physical[1..].iter().any(|b| *b != 0) {
        return Err(());
    }
    Timer::after_millis(100).await;
    let mut buffer = [0; umsh_bhi260::TRANSFER_BYTES];
    for kind in [Kind::Wake, Kind::NonWake] {
        let mut remaining = 0;
        let mut empty = false;
        for _ in 0..128 {
            if sensor
                .read_fifo(kind, &mut remaining, &mut buffer)
                .await
                .map_err(|_| ())?
                == 0
            {
                empty = true;
                break;
            }
        }
        if !empty {
            return Err(());
        }
    }
    for id in [48, 63] {
        sensor.configure_sensor(id, 1.0, 0).await.map_err(|_| ())?;
    }
    Timer::after_millis(500).await;
    for id in [1, 3] {
        let mut info = [0; 20];
        sensor
            .parameter(0x120 + id, &mut info, &mut Delay)
            .await
            .map_err(|_| ())?;
        let mode = info[6] >> 5;
        let rate = f32::from_le_bytes(info[9..13].try_into().unwrap());
        debug_log(format_args!(
            "motion: physical {id} mode={mode} rate={rate}"
        ));
        if (id == 1 && (mode != 6 || rate != 50.0)) || (id == 3 && (mode != 1 || rate != 0.0)) {
            return Err(());
        }
    }
    Ok(())
}

async fn run<I: embedded_hal_async::i2c::I2c>(
    sensor: &mut Bhi260<I>,
    irq: &mut Input<'static>,
    state: &mut State,
) -> Result<(), Fault> {
    let mut wake = Decoder::new();
    let mut nonwake = Decoder::new();
    for decoder in [&mut wake, &mut nonwake] {
        for (id, size) in [(1, 7), (48, 1), (63, 3)] {
            decoder.register(id, size).map_err(|_| Fault::Bus)?;
        }
    }
    let mut policy = DisplayPolicy::new();
    let mut window: Option<Instant> = None;
    let mut range = 0i32;
    let mut samples = 0u8;
    let mut empty_irqs = 0;
    let mut active_batches = 0;
    let mut generation = SERVICE.control().generation;
    loop {
        let control = SERVICE.control();
        if !control.sensing() {
            return Ok(());
        }
        // All bus activity, including an asserted interrupt, is bounded. A
        // stuck bus cannot prevent settings/shutdown cancellation above.
        let batch = async {
            if generation != control.generation {
                generation = control.generation;
                policy.reset();
                state.acceleration = None;
                publish(*state);
                if window.take().is_some() {
                    sensor
                        .configure_sensor(1, 0.0, 0)
                        .await
                        .map_err(|_| Fault::Bus)?;
                }
            }
            if window.is_some_and(|at| Instant::now() >= at) {
                debug_log(format_args!(
                    "motion: end n={samples} used={} move={}",
                    policy.episode_consumed(),
                    policy.movement_confirmed(),
                ));
                sensor
                    .configure_sensor(1, 0.0, 0)
                    .await
                    .map_err(|_| Fault::Bus)?;
                window = None;
                policy.end_window();
            }
            let status =
                umsh_bhi260::InterruptStatus(sensor.register(0x2d).await.map_err(|_| Fault::Bus)?);
            if status.fault() {
                return Err(Fault::HubReset);
            }
            if !status.fifo(Kind::Wake) && !status.fifo(Kind::NonWake) {
                return Ok(false);
            }
            let clock = sensor
                .timestamp(&mut Delay)
                .await
                .map_err(|_| Fault::Timestamp)?;
            let host = Instant::now().as_millis();
            let mut progress = false;
            let mut buffer = [0; umsh_bhi260::TRANSFER_BYTES];
            for (kind, decoder) in [(Kind::Wake, &mut wake), (Kind::NonWake, &mut nonwake)] {
                if !status.fifo(kind) {
                    continue;
                }
                let mut remaining = 0;
                for _ in 0..128 {
                    let count = sensor
                        .read_fifo(kind, &mut remaining, &mut buffer)
                        .await
                        .map_err(|_| Fault::Bus)?;
                    progress |= count != 0;
                    for byte in &buffer[..count] {
                        let Some(event) = decoder.push(*byte).map_err(|_| Fault::Decoder)? else {
                            continue;
                        };
                        if event.discontinuity() {
                            return Err(Fault::Discontinuity);
                        }
                        if !matches!(event.id, 1 | 48 | 63) {
                            continue;
                        }
                        let Some(ticks) = event.ticks else {
                            policy.end_window();
                            continue;
                        };
                        // Compare modulo the sensor's 40-bit clock. Stale or
                        // future records cannot establish movement/orientation.
                        let age = clock.wrapping_sub(ticks) & ((1u64 << 40) - 1);
                        if age > 100 * 64 {
                            policy.end_window();
                            continue;
                        }
                        let at = host.saturating_sub(age / 64);
                        let payload = event.payload();
                        let moving = event.id == 48 || (event.id == 63 && payload[0] & 1 != 0);
                        if event.id == 63 && payload[1] & 1 != 0 {
                            state.activity(at, Activity::Stationary);
                            policy.activity(at, Activity::Stationary);
                            if window.take().is_some() {
                                sensor
                                    .configure_sensor(1, 0.0, 0)
                                    .await
                                    .map_err(|_| Fault::Bus)?;
                            }
                            publish(*state);
                        }
                        if moving {
                            state.activity(at, Activity::Moving);
                            publish(*state);
                            policy.activity(at, Activity::Moving);
                            if SERVICE.control().display() && window.is_none() {
                                sensor
                                    .configure_sensor(1, 25.0, 0)
                                    .await
                                    .map_err(|_| Fault::Bus)?;
                                window = Some(Instant::now() + Duration::from_secs(1));
                                samples = 0;
                                let mut config = [0; 12];
                                sensor
                                    .parameter(0x501, &mut config, &mut Delay)
                                    .await
                                    .map_err(|_| Fault::Bus)?;
                                range = i32::from(u16::from_le_bytes([config[10], config[11]]));
                                if !(1..=16).contains(&range) {
                                    debug_log(format_args!("motion: invalid range {range}"));
                                    return Err(Fault::Range);
                                }
                                debug_log(format_args!(
                                    "motion: verify id={} at={at} range={range}g",
                                    event.id
                                ));
                            }
                        }
                        if event.id == 1 && window.is_some() {
                            let raw: [i16; 3] = core::array::from_fn(|i| {
                                i16::from_le_bytes([payload[2 * i], payload[2 * i + 1]])
                            });
                            // Face-up native Z is negative; native Y is positive
                            // with the keyboard below the screen. Rotate 180
                            // degrees about Y into the shared display axes.
                            let sample = Acceleration {
                                at_ms: at,
                                mg: [
                                    -i32::from(raw[0]) * range * 1000 / 32768,
                                    i32::from(raw[1]) * range * 1000 / 32768,
                                    -i32::from(raw[2]) * range * 1000 / 32768,
                                ],
                                clipped: raw.iter().any(|v| v.unsigned_abs() >= 32760),
                            };
                            state.acceleration = Some(sample);
                            samples = samples.saturating_add(1);
                            if samples == 1 {
                                debug_log(format_args!("motion: mg={:?}", sample.mg));
                            }
                            publish(*state);
                            if policy.sample(Instant::now().as_millis(), sample) {
                                let c = SERVICE.control();
                                if c.display() {
                                    SERVICE.display_wake.signal(Wake {
                                        generation: c.generation,
                                        at_ms: Instant::now().as_millis(),
                                    });
                                }
                                sensor
                                    .configure_sensor(1, 0.0, 0)
                                    .await
                                    .map_err(|_| Fault::Bus)?;
                                window = None;
                                policy.end_window();
                            }
                        }
                    }
                    if remaining == 0 {
                        break;
                    }
                }
                if remaining != 0 {
                    return Err(Fault::TransferLimit);
                }
            }
            Ok(progress)
        };
        let progress = with_timeout(Duration::from_secs(2), batch)
            .await
            .map_err(|_| Fault::Timeout)??;
        if progress {
            active_batches += 1;
            empty_irqs = 0;
            if active_batches > 128 {
                return Err(Fault::DrainLimit);
            }
            continue;
        }
        if irq.is_high() {
            // A new assertion can race the empty status read. Reread briefly,
            // then fail quiet rather than repeatedly completing a level wait.
            empty_irqs += 1;
            if empty_irqs >= 3 {
                return Err(Fault::InterruptStuck);
            }
            Timer::after_millis(2).await;
            continue;
        }
        empty_irqs = 0;
        active_batches = 0;
        let deadline = async {
            match window {
                Some(at) => Timer::at(at).await,
                None => core::future::pending::<()>().await,
            }
        };
        match select3(
            irq.wait_for_with_options(
                Event::HighLevel,
                esp_hal::gpio::WaitForOptions::default().with_wake_enable(true),
            ),
            deadline,
            SERVICE.changed.wait(),
        )
        .await
        {
            Either3::First(Err(_)) => return Err(Fault::Gpio),
            _ => {}
        }
    }
}
