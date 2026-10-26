//! The communicator's sounds on the T-Deck's speaker. The MAX98357A has no
//! control lines and is powered whenever V3V is, so between sounds the
//! transmitter is dropped and its clocks stop, which silences it.
use super::*;
use crate::audio_stream::{self, Request, Stream};
use esp_hal::rtc_cntl::WakeLock;
use umsh_sound::Player;

static PLAY: Signal<CriticalSectionRawMutex, Request> = Signal::new();
static STOPPING: AtomicBool = AtomicBool::new(false);
static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOPPED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Plays `request` once, after any sound under way.
pub fn play(request: Request) {
    if !STOPPING.load(Ordering::Acquire) {
        PLAY.signal(request);
    }
}

/// Ends any sound and stops the task, before the rail goes down.
pub async fn shutdown() {
    STOPPING.store(true, Ordering::Release);
    STOPPED.reset();
    CHANGED.signal(());
    if with_timeout(Duration::from_millis(500), STOPPED.wait())
        .await
        .is_err()
    {
        debug_log(format_args!("tdeck: sound cleanup timed out"));
    }
}

#[embassy_executor::task]
pub async fn task(
    mut i2s: peripherals::I2S0<'static>,
    mut dma: peripherals::DMA_CH1<'static>,
    mut bclk: peripherals::GPIO7<'static>,
    mut ws: peripherals::GPIO5<'static>,
    mut dout: peripherals::GPIO6<'static>,
) {
    let mut buffer = Some(audio_stream::stream_buffer!());
    let mut player = Player::new();
    loop {
        let request = match select(PLAY.wait(), CHANGED.wait()).await {
            Either::First(request) => request,
            Either::Second(()) => {
                if STOPPING.load(Ordering::Acquire) {
                    STOPPED.signal(());
                    return;
                }
                continue;
            }
        };
        player.set_volume(request.volume);
        if !player.play_choice(request.choice) {
            continue;
        }
        let _guard = WakeLock::new();
        // Reborrow each sound, so the transmitter and its clocks are gone
        // between them.
        let tx = board::audio::transmitter(
            i2s.reborrow(),
            dma.reborrow(),
            bclk.reborrow(),
            ws.reborrow(),
            dout.reborrow(),
        );
        let mut transfer = match audio_stream::start(tx, buffer.take().unwrap()) {
            Ok(t) => t,
            Err(returned) => {
                debug_log(format_args!("tdeck: sound DMA start failed"));
                buffer = Some(returned);
                continue;
            }
        };
        let mut stream = Stream::after(0);
        loop {
            if STOPPING.load(Ordering::Acquire) {
                stream.cut();
            }
            stream.fill(&mut transfer, &mut player);
            if stream.drained() {
                break;
            }
            // A sound asked for meanwhile waits for this one to end.
            if let Either::Second(Err(error)) =
                select(CHANGED.wait(), transfer.wait_for_available_async()).await
            {
                debug_log(format_args!("tdeck: sound DMA failed: {error:?}"));
                break;
            }
        }
        buffer = Some(audio_stream::finish(transfer));
        player.stop();
        if STOPPING.load(Ordering::Acquire) {
            STOPPED.signal(());
            return;
        }
    }
}
