//! Opt-in, bounded BHI260AP feasibility probe. Does not wake the display or
//! advertise motion support. Normal builds do not include the Bosch image.
use super::*;
use umsh_bhi260::fifo::{Decoder, Kind};
use umsh_bhi260::{ADDRESS, Bhi260};

static FIRMWARE: &[u8] = include_bytes!("../../../assets/bhi260/BHI260AP.fw");

#[embassy_executor::task]
pub async fn task(bus: &'static board::I2cBus, pin: peripherals::GPIO8<'static>) {
    let mut irq = Input::new(pin, InputConfig::default());
    // Give USB/debug output and the normal tracker services time to start.
    Timer::after_secs(10).await;
    let mut sensor = Bhi260::new(I2cDevice::new(bus), ADDRESS);
    // Keep totals independently of the best-effort diagnostic queue so a
    // dropped log line cannot be mistaken for an absent sensor event.
    // Motion, stationary, orientation, acceleration, tilt, pickup, activity.
    let mut totals = [0u32; 7];
    // Operator testing may be asynchronous. This deadline bounds the whole
    // diagnostic session; it does not schedule periodic sensor reads.
    let result = with_timeout(Duration::from_secs(8 * 60 * 60), async {
        debug_log(format_args!(
            "bhi260: qualification starting, irq={}",
            irq.is_high()
        ));
        let version = sensor.boot(FIRMWARE, &mut Delay).await?;
        debug_log(format_args!("bhi260: version {version:?}"));
        Timer::after_millis(20).await;
        let set = sensor.virtual_sensors(&mut Delay).await?;
        for (index, bytes) in set.0.chunks(8).enumerate() {
            debug_log(format_args!(
                "bhi260: virtual bitmap {}={:02x?}",
                index * 8,
                bytes
            ));
            Timer::after_millis(20).await;
        }
        for id in 1..=223 {
            if set.contains(id) {
                debug_log(format_args!("bhi260: virtual sensor {id}"));
                // Do not overflow the bounded debug queue during enumeration.
                Timer::after_millis(20).await;
            }
        }
        let physical = sensor.physical_sensors(&mut Delay).await?;
        debug_log(format_args!("bhi260: physical bitmap={physical:02x?}"));
        Timer::after_millis(20).await;
        debug_log(format_args!(
            "bhi260: candidates stationary={} motion={} any-lp={} any-lp-wake={}",
            set.contains(75),
            set.contains(77),
            set.contains(142),
            set.contains(143)
        ));
        Timer::after_millis(20).await;
        // Test dependencies independently. Presence is not sufficient: a
        // motion/gesture algorithm may secretly request the physical gyro.
        for candidate in [75u8, 77, 48, 55, 57, 59, 61, 63, 67, 69, 70] {
            if !set.contains(candidate) {
                continue;
            }
            let mut virtual_info = [0; 28];
            sensor
                .parameter(0x300 + u16::from(candidate), &mut virtual_info, &mut Delay)
                .await?;
            debug_log(format_args!(
                "bhi260: candidate {candidate} info={virtual_info:02x?}"
            ));
            sensor.configure_sensor(candidate, 1.0, 0).await?;
            Timer::after_millis(500).await;
            for id in [1u16, 3] {
                let mut info = [0; 20];
                sensor.parameter(0x120 + id, &mut info, &mut Delay).await?;
                let rate = f32::from_le_bytes(info[9..13].try_into().unwrap());
                debug_log(format_args!(
                    "bhi260: candidate {candidate} physical {id} mode={} rate={rate}",
                    info[6] >> 5
                ));
                Timer::after_millis(20).await;
            }
            sensor.configure_sensor(candidate, 0.0, 0).await?;
            Timer::after_millis(250).await;
        }
        // Start the actual experiment from a fresh firmware instance. Candidate
        // algorithms can have delayed output after being disabled; do not mix
        // their FIFO frames with the selected experiment's sensor registry.
        sensor.boot(FIRMWARE, &mut Delay).await?;
        Timer::after_millis(500).await;
        // Drain all startup transfers, not just the first FIFO packet. Every
        // read is bounded, and reaching the budget without an empty FIFO fails
        // the experiment instead of silently losing transfer framing.
        let mut buffer = [0; umsh_bhi260::TRANSFER_BYTES];
        for kind in [Kind::Wake, Kind::NonWake] {
            let mut remaining = 0;
            let mut empty = false;
            for _ in 0..128 {
                let count = sensor.read_fifo(kind, &mut remaining, &mut buffer).await?;
                if count == 0 {
                    empty = true;
                    break;
                }
            }
            if !empty {
                return Ok("discovery FIFO transfer limit");
            }
        }
        let mut wake = Decoder::new();
        let mut nonwake = Decoder::new();
        for (id, size) in [(1, 7), (48, 1), (61, 1), (63, 3), (70, 2), (75, 1), (77, 1)] {
            wake.register(id, size).unwrap();
            nonwake.register(id, size).unwrap();
        }
        for id in [75, 77, 70, 48, 61, 63] {
            sensor.configure_sensor(id, 1.0, 0).await?;
        }
        Timer::after_millis(100).await;
        for id in [75u16, 77, 70, 48, 61, 63] {
            let mut config = [0; 12];
            sensor
                .parameter(0x500 + id, &mut config, &mut Delay)
                .await?;
            debug_log(format_args!("bhi260: armed {id} config={config:02x?}"));
            Timer::after_millis(20).await;
        }
        for id in [1u16, 3] {
            let mut info = [0; 20];
            sensor.parameter(0x120 + id, &mut info, &mut Delay).await?;
            let rate = f32::from_le_bytes(info[9..13].try_into().unwrap());
            debug_log(format_args!("bhi260: combined physical {id} mode={} rate={rate}", info[6] >> 5));
            Timer::after_millis(20).await;
        }
        // One bounded diagnostic baseline while the operator has confirmed
        // the board is face-up. This is not a production sampling fallback.
        sensor.configure_sensor(1, 25.0, 0).await?;
        let mut window: Option<Instant> = Some(Instant::now() + Duration::from_secs(1));
        let mut samples = 0u32;
        let mut irq_count = 0u32;
        debug_log(format_args!(
            "bhi260: IRQ TEST READY; leave still, then pick up and rotate"
        ));
        loop {
            if let Some(deadline) = window {
                if Instant::now() >= deadline {
                    sensor.configure_sensor(1, 0.0, 0).await?;
                    debug_log(format_args!(
                        "bhi260: sample window ended samples={samples} irqs={irq_count} totals={totals:?}"
                    ));
                    window = None;
                }
            }
            let status = sensor.register(0x2d).await?;
            let mut progress = false;
            for (kind, mask, decoder) in [
                (Kind::Wake, 0x06, &mut wake),
                (Kind::NonWake, 0x18, &mut nonwake),
            ] {
                if status & mask == 0 {
                    continue;
                }
                let mut remaining = 0;
                for _ in 0..128 {
                    let count = sensor.read_fifo(kind, &mut remaining, &mut buffer).await?;
                    progress |= count != 0;
                    for byte in &buffer[..count] {
                        let event = match decoder.push(*byte) {
                            Ok(Some(event)) => event,
                            Ok(None) => continue,
                            Err(error) => {
                                debug_log(format_args!("bhi260: FIFO error {error:?}"));
                                return Ok("FIFO decode failure");
                            }
                        };
                        if event.discontinuity() {
                            debug_log(format_args!(
                                "bhi260: FIFO discontinuity {:?}",
                                event.payload()
                            ));
                            return Ok("FIFO discontinuity");
                        }
                        match event.id {
                            77 => {
                                totals[0] += 1;
                                debug_log(format_args!("bhi260: MOTION ticks={:?}", event.ticks));
                                sensor.configure_sensor(75, 1.0, 0).await?;
                            }
                            48 => {
                                totals[4] += 1;
                                debug_log(format_args!("bhi260: TILT ticks={:?}", event.ticks));
                            }
                            61 => {
                                totals[5] += 1;
                                debug_log(format_args!("bhi260: PICKUP ticks={:?}", event.ticks));
                                sensor.configure_sensor(61, 1.0, 0).await?;
                            }
                            63 => {
                                totals[6] += 1;
                                debug_log(format_args!("bhi260: ACTIVITY {:?} ticks={:?}", event.payload(), event.ticks));
                            }
                            75 => {
                                totals[1] += 1;
                                debug_log(format_args!(
                                    "bhi260: STATIONARY ticks={:?}; rearm motion",
                                    event.ticks
                                ));
                                sensor.configure_sensor(77, 1.0, 0).await?;
                            }
                            70 => {
                                totals[2] += 1;
                                debug_log(format_args!(
                                    "bhi260: ORIENTATION {:?} ticks={:?}",
                                    event.payload(),
                                    event.ticks
                                ));
                            }
                            1 => {
                                totals[3] += 1;
                                samples += 1;
                                if samples == 1 || samples % 5 == 0 {
                                    let p = event.payload();
                                    let xyz = [
                                        i16::from_le_bytes([p[0], p[1]]),
                                        i16::from_le_bytes([p[2], p[3]]),
                                        i16::from_le_bytes([p[4], p[5]]),
                                    ];
                                    debug_log(format_args!(
                                        "bhi260: ACC raw={xyz:?} ticks={:?}",
                                        event.ticks
                                    ));
                                }
                            }
                            // Spacer and configuration meta events are frequent
                            // enough to bury the measurements in a small log
                            // queue. Fault meta events are handled above.
                            _ => {}
                        }
                        // Evaluate native gesture alternatives without polling.
                        // Activity bit 0 means "still ended"; an initial "still
                        // started" report must not be treated as movement.
                        let starts_window = matches!(event.id, 48 | 61 | 77)
                            || (event.id == 63 && event.payload()[0] & 1 != 0);
                        if starts_window && window.is_none() {
                            sensor.configure_sensor(1, 25.0, 0).await?;
                            window = Some(Instant::now() + Duration::from_secs(1));
                            samples = 0;
                        }
                    }
                    if remaining == 0 {
                        break;
                    }
                }
                if remaining != 0 {
                    return Ok("FIFO transfer limit");
                }
            }
            if progress {
                continue;
            }
            if irq.is_high() {
                debug_log(format_args!(
                    "bhi260: asserted IRQ without FIFO progress status={status:#04x}"
                ));
                return Ok("asserted IRQ without FIFO progress");
            }
            let deadline = async {
                match window {
                    Some(at) => Timer::at(at).await,
                    None => core::future::pending::<()>().await,
                }
            };
            match select(irq.wait_for(Event::HighLevel), deadline).await {
                Either::First(()) => irq_count += 1,
                Either::Second(()) => {}
            }
        }
        #[allow(unreachable_code)]
        Ok::<&str, umsh_bhi260::Error<_>>("complete")
    })
    .await;
    debug_log(format_args!("bhi260: qualification result={result:?}"));
    Timer::after_millis(20).await;
    debug_log(format_args!(
        "bhi260: totals [motion, stationary, orientation, acc, tilt, pickup, activity]={totals:?}"
    ));
    Timer::after_millis(20).await;
    // Reset to ROM so all candidate sensors are disabled, including after an
    // error, canceled operation, or overall probe timeout.
    let cleanup = with_timeout(Duration::from_secs(6), sensor.reset(&mut Delay)).await;
    debug_log(format_args!("bhi260: cleanup={cleanup:?}"));
}
