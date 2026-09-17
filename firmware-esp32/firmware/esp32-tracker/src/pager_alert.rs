//! Board presentation of the session-owned locate alert.
use super::*;
use esp_hal::{dma::DmaTxStreamBuf, rtc_cntl::WakeLock};
use umsh_pager_peripherals::{
    alert::{Codec, Haptic, PERIOD_MS, PULSE_MS, ToneSamples},
    power::{AMPLIFIER_ENABLE, HAPTIC_ENABLE},
};
use umsh_ux_tracker::buzzer::{BuzzerDecision, BuzzerEngine, melodies};

// The display's first redraw can starve a 40 ms stream. Keep enough queued
// audio for that CPU work, while leaving room for a ramp/tail inside 250 ms.
const BUFFER_MS: u64 = 128;

static ACTIVE: AtomicBool = AtomicBool::new(false);
static BRIGHT: AtomicBool = AtomicBool::new(false);
static STOPPING: AtomicBool = AtomicBool::new(false);
static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
pub static DISPLAY_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static CANCEL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOPPED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}
pub fn bright() -> bool {
    active() && BRIGHT.load(Ordering::Acquire)
}
pub fn set(active: bool) {
    let active = active && !STOPPING.load(Ordering::Acquire);
    if ACTIVE.swap(active, Ordering::AcqRel) == active {
        return;
    }
    if active {
        super::input::alert_started();
    } else {
        phase(false);
    }
    super::input::discard_navigation();
    CHANGED.signal(());
    DISPLAY_CHANGED.signal(());
}
pub fn cancel() {
    CANCEL.signal(());
}
#[embassy_executor::task]
pub async fn cancel_task() {
    loop {
        CANCEL.wait().await;
        if active() {
            INPUT_CH.send(InEvent::CancelAlert).await;
        }
    }
}
pub async fn shutdown() {
    STOPPING.store(true, Ordering::Release);
    STOPPED.reset();
    set(false);
    CHANGED.signal(());
    if with_timeout(Duration::from_millis(500), STOPPED.wait())
        .await
        .is_err()
    {
        debug_log(format_args!("pager: alert cleanup timed out"));
    }
}
fn phase(on: bool) {
    if BRIGHT.swap(on, Ordering::AcqRel) != on {
        DISPLAY_CHANGED.signal(());
    }
}

async fn enable(expander: &'static board::SharedExpander, mask: u16, on: bool) -> bool {
    matches!(
        with_timeout(Duration::from_millis(100), async {
            let mut expander = expander.lock().await;
            // A control change may have arrived while acquiring the bus owner.
            expander.set(mask, on && active()).await
        })
        .await,
        Ok(Ok(()))
    )
}

async fn codec_init(codec: &mut Codec<board::I2cHandle>) -> bool {
    #[cfg(feature = "ulcp-i2c")]
    let _held = board::i2c::CODEC_PROCEDURE.hold(0x18);
    matches!(
        with_timeout(Duration::from_millis(150), codec.init(&mut Delay)).await,
        Ok(Ok(()))
    )
}
async fn haptic_init(haptic: &mut Haptic<board::I2cHandle>) -> bool {
    #[cfg(feature = "ulcp-i2c")]
    let _held = board::i2c::HAPTIC_PROCEDURE.hold(0x5a);
    matches!(
        with_timeout(Duration::from_millis(100), haptic.init()).await,
        Ok(Ok(()))
    )
}
async fn haptic_play(haptic: &mut Haptic<board::I2cHandle>, on: bool) -> bool {
    matches!(
        with_timeout(Duration::from_millis(50), haptic.play(on)).await,
        Ok(Ok(()))
    )
}
async fn codec_mute(codec: &mut Codec<board::I2cHandle>, muted: bool) -> bool {
    #[cfg(feature = "ulcp-i2c")]
    let _held = board::i2c::CODEC_PROCEDURE.hold(0x18);
    matches!(
        with_timeout(Duration::from_millis(50), codec.mute(muted)).await,
        Ok(Ok(()))
    )
}
async fn codec_sleep(codec: &mut Codec<board::I2cHandle>) {
    #[cfg(feature = "ulcp-i2c")]
    let _held = board::i2c::CODEC_PROCEDURE.hold(0x18);
    if !matches!(
        with_timeout(Duration::from_millis(100), codec.sleep()).await,
        Ok(Ok(()))
    ) {
        debug_log(format_args!("pager: codec sleep failed"));
    }
}
async fn cleanup(
    codec: &mut Codec<board::I2cHandle>,
    haptic: &mut Haptic<board::I2cHandle>,
    expander: &'static board::SharedExpander,
) {
    // Physical enables first: even a failed codec transaction cannot leave sound on.
    if !enable(expander, AMPLIFIER_ENABLE | HAPTIC_ENABLE, false).await {
        debug_log(format_args!("pager: alert enable cleanup failed"));
    }
    codec_sleep(codec).await;
    {
        #[cfg(feature = "ulcp-i2c")]
        let _held = board::i2c::HAPTIC_PROCEDURE.hold(0x5a);
        // EN low can make the chip inaccessible; its output is already disabled.
        let _ = with_timeout(Duration::from_millis(50), haptic.sleep()).await;
    }
}

// Keep task construction out of the already large board bring-up frame.
#[inline(never)]
pub fn spawn(
    spawner: embassy_executor::Spawner,
    bus: &'static board::I2cBus,
    expander: &'static board::SharedExpander,
    i2s: peripherals::I2S0<'static>,
    dma: peripherals::DMA_CH1<'static>,
    mclk: peripherals::GPIO10<'static>,
    bclk: peripherals::GPIO11<'static>,
    ws: peripherals::GPIO18<'static>,
    dout: peripherals::GPIO45<'static>,
) {
    spawner.spawn(cancel_task().unwrap());
    spawner.spawn(task(bus, expander, i2s, dma, mclk, bclk, ws, dout).unwrap());
}

#[embassy_executor::task]
pub async fn task(
    bus: &'static board::I2cBus,
    expander: &'static board::SharedExpander,
    mut i2s: peripherals::I2S0<'static>,
    mut dma: peripherals::DMA_CH1<'static>,
    mut mclk: peripherals::GPIO10<'static>,
    mut bclk: peripherals::GPIO11<'static>,
    mut ws: peripherals::GPIO18<'static>,
    mut dout: peripherals::GPIO45<'static>,
) {
    // Four 32 ms descriptors in static internal RAM.
    let mut buffer = Some(esp_hal::dma_tx_stream_buffer!(8192, 2048));
    let mut codec = Codec(I2cDevice::new(bus));
    let mut haptic = Haptic(I2cDevice::new(bus));
    loop {
        while !active() {
            if STOPPING.load(Ordering::Acquire) {
                STOPPED.signal(());
                return;
            }
            CHANGED.wait().await;
        }
        let guard = WakeLock::new();
        let mut haptic_ok =
            enable(expander, HAPTIC_ENABLE, true).await && haptic_init(&mut haptic).await;
        let mut audio_ok = codec_init(&mut codec).await;
        if !haptic_ok {
            debug_log(format_args!("pager: alert haptic initialization failed"));
            let _ = enable(expander, HAPTIC_ENABLE, false).await;
        }
        if !audio_ok {
            debug_log(format_args!("pager: alert codec initialization failed"));
        }
        // Reborrow each activation. TX and unused RX guards both die before idle.
        let mut transfer = if audio_ok && active() {
            let tx = board::audio::transmitter(
                i2s.reborrow(),
                dma.reborrow(),
                mclk.reborrow(),
                bclk.reborrow(),
                ws.reborrow(),
                dout.reborrow(),
            );
            let mut tx_buffer = buffer.take().unwrap();
            tx_buffer.push_with(|bytes| {
                bytes.fill(0);
                bytes.len()
            });
            match tx.write(tx_buffer) {
                Ok(t) => Some(t),
                Err((_, tx, returned)) => {
                    debug_log(format_args!("pager: alert DMA start failed"));
                    drop(tx);
                    buffer = Some(returned);
                    audio_ok = false;
                    None
                }
            }
        } else {
            None
        };
        let origin = Instant::now().as_millis() + BUFFER_MS;
        if audio_ok && active() {
            audio_ok = codec_mute(&mut codec, false).await
                && enable(expander, AMPLIFIER_ENABLE, true).await;
            if !audio_ok {
                debug_log(format_args!("pager: alert amplifier/unmute failed"));
                let _ = enable(expander, AMPLIFIER_ENABLE, false).await;
            }
        }
        if !active() {
            audio_ok = false;
        }
        if !audio_ok {
            if let Some(t) = transfer.take() {
                let (tx, returned) = t.stop();
                drop(tx);
                buffer = Some(returned);
            }
            codec_sleep(&mut codec).await;
        }
        let mut engine = BuzzerEngine::new();
        engine.play_alert(&melodies::LOCATE, origin, PERIOD_MS);
        let mut samples = ToneSamples::default();
        let mut frames = 0u64;
        let mut haptic_on = false;
        let mut stopping_at = None;
        let mut tail_frames = 0u32;
        let mut last_sample = 0i16;
        let mut tail_sample = 0i16;
        loop {
            let now = Instant::now().as_millis();
            if !active() && stopping_at.is_none() {
                stopping_at = Some(now + BUFFER_MS + 20);
                tail_sample = last_sample;
                phase(false);
                if haptic_ok {
                    let _ = haptic_play(&mut haptic, false).await;
                }
            }
            if STOPPING.load(Ordering::Acquire) || stopping_at.is_some_and(|at| now >= at) {
                break;
            }
            let elapsed = now.saturating_sub(origin);
            let pulse = stopping_at.is_none()
                && active()
                && now >= origin
                && umsh_pager_peripherals::alert::bright(elapsed);
            phase(pulse);
            if haptic_ok && pulse != haptic_on {
                haptic_ok = haptic_play(&mut haptic, pulse).await;
                haptic_on = pulse;
                if !haptic_ok {
                    debug_log(format_args!("pager: alert haptic failed"));
                    let _ = enable(expander, HAPTIC_ENABLE, false).await;
                }
            }
            if let Some(t) = transfer.as_mut() {
                while t.available_bytes() > 0 {
                    let n = t.push_with(|bytes| {
                        for frame in bytes.chunks_exact_mut(4) {
                            let data = if stopping_at.is_some() {
                                let gain = 80u32.saturating_sub(tail_frames);
                                tail_frames = tail_frames.saturating_add(1);
                                let v = (i32::from(tail_sample) * gain as i32 / 80) as i16;
                                let b = v.to_le_bytes();
                                [b[0], b[1], b[0], b[1]]
                            } else {
                                let hz = match engine.tick(origin + frames / 16) {
                                    BuzzerDecision::Tone { frequency_hz, .. } if audio_ok => {
                                        frequency_hz
                                    }
                                    _ => 0,
                                };
                                samples.frame(hz, (frames % 2400) as u32)
                            };
                            last_sample = i16::from_le_bytes([data[0], data[1]]);
                            frame.copy_from_slice(&data);
                            frames += 1;
                        }
                        bytes.len() / 4 * 4
                    });
                    if n == 0 {
                        break;
                    }
                }
            }
            let deadline = stopping_at.unwrap_or_else(|| {
                if now < origin {
                    origin
                } else {
                    let cycle = origin + elapsed / PERIOD_MS * PERIOD_MS;
                    if pulse {
                        cycle + PULSE_MS
                    } else {
                        cycle + PERIOD_MS
                    }
                }
            });
            let dma_ready = async {
                match transfer.as_mut() {
                    Some(t) => t.wait_for_available_async().await,
                    None => core::future::pending().await,
                }
            };
            match select3(
                CHANGED.wait(),
                Timer::at(Instant::from_millis(deadline)),
                dma_ready,
            )
            .await
            {
                Either3::Third(Err(error)) => {
                    println!(
                        "pager: alert DMA failed: {error:?} at {elapsed} ms, generated {} frames",
                        frames
                    );
                    audio_ok = false;
                    let _ = enable(expander, AMPLIFIER_ENABLE, false).await;
                    if let Some(t) = transfer.take() {
                        let (tx, returned) = t.stop();
                        drop(tx);
                        buffer = Some(returned);
                    }
                    codec_sleep(&mut codec).await;
                }
                _ => {}
            }
            // A stop followed by a start during the silent tail starts cleanly
            // after cleanup; never allow old DMA data to become a new alert.
        }
        let _ = codec_mute(&mut codec, true).await;
        let _ = enable(expander, AMPLIFIER_ENABLE, false).await;
        if let Some(t) = transfer.take() {
            let (tx, returned) = t.stop();
            drop(tx);
            buffer = Some(returned);
        }
        drop(transfer);
        engine.stop_alert();
        cleanup(&mut codec, &mut haptic, expander).await;
        // A stopped streaming buffer retains its prefill cursor. Reconstruct it.
        let (descriptors, bytes) = buffer.take().unwrap().split();
        buffer = Some(DmaTxStreamBuf::new(descriptors, bytes).expect("same Pager audio buffer"));
        phase(false);
        drop(guard);
    }
}
