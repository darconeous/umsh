//! Board presentation of the session-owned locate alert, and the sounds
//! the communicator plays, on the codec, the amplifier, and the haptic
//! driver.
use super::*;
use crate::audio_stream::{self, Request, Stream};
use esp_hal::rtc_cntl::WakeLock;
use umsh_pager_peripherals::{
    alert::{Codec, Haptic, PERIOD_MS, PULSE_MS},
    power::{AMPLIFIER_ENABLE, HAPTIC_ENABLE},
};
use umsh_sound::{Level, Player, Sound, Wave, melodies};

/// How long the stream buffer holds, in milliseconds: how long after the
/// alert stops it is still being heard.
const BUFFER_MS: u64 = 128;
/// Silence after the codec is unmuted and the amplifier enabled, before
/// the first note. Powered up from cold, the ES8311's analog path and the
/// NS4150B are not yet heard when the buffer's own silence has played out:
/// the start of a sound was lost without this. Tuned by ear on the bench.
const WARM_UP_MS: u32 = 250;

static ACTIVE: AtomicBool = AtomicBool::new(false);
/// A sound other than the alert is under way.
static CHIMING: AtomicBool = AtomicBool::new(false);
static PLAY: Signal<CriticalSectionRawMutex, Request> = Signal::new();
static BRIGHT: AtomicBool = AtomicBool::new(false);
static STOPPING: AtomicBool = AtomicBool::new(false);
static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
pub static DISPLAY_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static CANCEL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOPPED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static TICK: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// How long the motor stays powered for a tick: the buzz and its run-down.
const TICK_MS: u64 = 300;

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
        crate::input_gate::alert_started();
    } else {
        phase(false);
    }
    crate::input_gate::discard_navigation();
    CHANGED.signal(());
    DISPLAY_CHANGED.signal(());
}
pub fn cancel() {
    CANCEL.signal(());
}
/// Plays `request` once on the speaker. An alert under way has the
/// speaker; the sound is dropped.
pub fn play(request: Request) {
    if !active() && !STOPPING.load(Ordering::Acquire) {
        PLAY.signal(request);
    }
}
/// Whether the speaker is wanted: for the alert, or for a sound.
fn sounding() -> bool {
    active() || CHIMING.load(Ordering::Acquire)
}
/// One short haptic buzz, for something that calls for attention without an
/// alert. An alert under way already has the motor; the tick is dropped.
pub fn tick() {
    TICK.signal(());
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
            expander.set(mask, on && sounding()).await
        })
        .await,
        Ok(Ok(()))
    )
}

/// Powers the haptic driver for one short buzz and off again. Called only while
/// no alert is under way, so the alert's enable gate does not apply.
async fn tick_buzz(
    expander: &'static board::SharedExpander,
    haptic: &mut Haptic<board::I2cHandle>,
) {
    let _guard = WakeLock::new();
    let power = |on: bool| {
        with_timeout(Duration::from_millis(100), async move {
            expander.lock().await.set(HAPTIC_ENABLE, on).await
        })
    };
    if matches!(power(true).await, Ok(Ok(()))) && haptic_init(haptic).await {
        let buzzed = {
            #[cfg(feature = "ulcp-i2c")]
            let _held = board::i2c::HAPTIC_PROCEDURE.hold(0x5a);
            matches!(
                with_timeout(Duration::from_millis(50), haptic.buzz()).await,
                Ok(Ok(()))
            )
        };
        if buzzed {
            Timer::after(Duration::from_millis(TICK_MS)).await;
        } else {
            debug_log(format_args!("pager: haptic tick failed"));
        }
    }
    {
        #[cfg(feature = "ulcp-i2c")]
        let _held = board::i2c::HAPTIC_PROCEDURE.hold(0x5a);
        let _ = with_timeout(Duration::from_millis(50), haptic.sleep()).await;
    }
    if !matches!(power(false).await, Ok(Ok(()))) {
        debug_log(format_args!("pager: haptic tick power-off failed"));
    }
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

/// Plays `request` once: the codec and the amplifier up, the sound out, and
/// both down again. An alert that starts takes the speaker: the sound is
/// cut short and the session ends, for the alert's own to begin.
#[allow(clippy::too_many_arguments)]
async fn chime(
    request: Request,
    codec: &mut Codec<board::I2cHandle>,
    expander: &'static board::SharedExpander,
    buffer: &mut Option<esp_hal::dma::DmaTxStreamBuf>,
    i2s: &mut peripherals::I2S0<'static>,
    dma: &mut peripherals::DMA_CH1<'static>,
    mclk: &mut peripherals::GPIO10<'static>,
    bclk: &mut peripherals::GPIO11<'static>,
    ws: &mut peripherals::GPIO18<'static>,
    dout: &mut peripherals::GPIO45<'static>,
) {
    let mut player = Player::new();
    player.set_volume(request.volume);
    if !player.play_choice(request.choice) {
        return;
    }
    let _guard = WakeLock::new();
    CHIMING.store(true, Ordering::Release);
    let mut transfer = None;
    if codec_init(codec).await {
        let tx = board::audio::transmitter(
            i2s.reborrow(),
            dma.reborrow(),
            mclk.reborrow(),
            bclk.reborrow(),
            ws.reborrow(),
            dout.reborrow(),
        );
        match audio_stream::start(tx, buffer.take().unwrap()) {
            Ok(t) => transfer = Some(t),
            Err(returned) => {
                debug_log(format_args!("pager: sound DMA start failed"));
                *buffer = Some(returned);
            }
        }
    } else {
        debug_log(format_args!("pager: sound codec initialization failed"));
    }
    if let Some(t) = transfer.as_mut() {
        if codec_mute(codec, false).await && enable(expander, AMPLIFIER_ENABLE, true).await {
            let mut stream = Stream::after(WARM_UP_MS);
            loop {
                if active() {
                    stream.cut();
                }
                stream.fill(t, &mut player);
                if stream.drained() || STOPPING.load(Ordering::Acquire) {
                    break;
                }
                if let Either::Second(Err(error)) =
                    select(CHANGED.wait(), t.wait_for_available_async()).await
                {
                    debug_log(format_args!("pager: sound DMA failed: {error:?}"));
                    break;
                }
            }
        } else {
            debug_log(format_args!("pager: sound amplifier/unmute failed"));
        }
    }
    let _ = codec_mute(codec, true).await;
    CHIMING.store(false, Ordering::Release);
    if !enable(expander, AMPLIFIER_ENABLE, false).await {
        debug_log(format_args!("pager: sound amplifier cleanup failed"));
    }
    if let Some(t) = transfer.take() {
        *buffer = Some(audio_stream::finish(t));
    }
    codec_sleep(codec).await;
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
    let mut buffer = Some(audio_stream::stream_buffer!());
    let mut codec = Codec(I2cDevice::new(bus));
    let mut haptic = Haptic(I2cDevice::new(bus));
    loop {
        while !active() {
            if STOPPING.load(Ordering::Acquire) {
                STOPPED.signal(());
                return;
            }
            match select3(CHANGED.wait(), TICK.wait(), PLAY.wait()).await {
                Either3::First(()) => {}
                Either3::Second(()) => tick_buzz(expander, &mut haptic).await,
                Either3::Third(request) => {
                    chime(
                        request,
                        &mut codec,
                        expander,
                        &mut buffer,
                        &mut i2s,
                        &mut dma,
                        &mut mclk,
                        &mut bclk,
                        &mut ws,
                        &mut dout,
                    )
                    .await
                }
            }
        }
        TICK.reset();
        PLAY.reset();
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
            match audio_stream::start(tx, buffer.take().unwrap()) {
                Ok(t) => Some(t),
                Err(returned) => {
                    debug_log(format_args!("pager: alert DMA start failed"));
                    buffer = Some(returned);
                    audio_ok = false;
                    None
                }
            }
        } else {
            None
        };
        // The flash and the motor keep step with the first warble, which
        // follows the buffer's silence and the warm-up.
        let origin = Instant::now().as_millis() + BUFFER_MS + u64::from(WARM_UP_MS);
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
                buffer = Some(audio_stream::finish(t));
            }
            codec_sleep(&mut codec).await;
        }
        // The first frame after the prefill is the alert's first.
        let mut player = Player::new();
        player.play_every(
            &Sound::Tones(melodies::LOCATE.notes, Wave::Sine),
            Level::Full,
            PERIOD_MS as u32,
        );
        let mut stream = Stream::after(WARM_UP_MS);
        let mut haptic_on = false;
        let mut stopping_at = None;
        loop {
            let now = Instant::now().as_millis();
            if !active() && stopping_at.is_none() {
                stopping_at = Some(now + BUFFER_MS + 20);
                stream.cut();
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
                stream.fill(t, &mut player);
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
                    println!("pager: alert DMA failed: {error:?} at {elapsed} ms");
                    let _ = enable(expander, AMPLIFIER_ENABLE, false).await;
                    if let Some(t) = transfer.take() {
                        buffer = Some(audio_stream::finish(t));
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
            buffer = Some(audio_stream::finish(t));
        }
        cleanup(&mut codec, &mut haptic, expander).await;
        phase(false);
        drop(guard);
    }
}
