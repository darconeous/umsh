//! The key light: PWM on GPIO9, the gate of the FET that switches the key
//! LEDs. 1 kHz and 8 bits, as on stock firmware.
//!
//! The PWM runs from the APB clock, which stops in light sleep, so the
//! light holds a wake lock while it is on. Off, its output is a steady low,
//! which sleep keeps; the gate's pull-up would light the LEDs otherwise.
//!
//! The light fades to each duty the controller asks for, from wherever it
//! is, so a sleep in the middle of a fade fades out from there.

use embassy_futures::select::{Either3, select3};
use embassy_time::{Duration, Instant, Timer};
use esp_hal::{
    gpio::DriveMode,
    ledc::{
        LSGlobalClkSource, Ledc, LowSpeed,
        channel::{self, Channel, ChannelHW, ChannelIFace},
        timer::{self, LSClockSource, Timer as LedcTimer, TimerIFace, config::Duty},
    },
    peripherals::{GPIO9, LEDC},
    rtc_cntl::WakeLock,
    time::Rate,
};
use firmware_tdeck_tkeyboard::backlight::{Fade, RESTORE_MS};
use static_cell::StaticCell;

use crate::power::{self, Part};
use crate::{LIGHT, with_keyboard};

/// One PWM period, and then some: a new duty takes effect at the end of
/// the period it is written in.
const LATCH: Duration = Duration::from_millis(2);
/// How often a fade moves the duty.
const STEP: Duration = Duration::from_millis(10);

pub struct Light {
    channel: Channel<'static, LowSpeed>,
    /// Held while the light is on.
    awake: Option<WakeLock>,
}

impl Light {
    /// Sets the light up, off.
    pub fn new(ledc: LEDC<'static>, pin: GPIO9<'static>) -> Self {
        static TIMER: StaticCell<LedcTimer<'static, LowSpeed>> = StaticCell::new();
        let mut ledc = Ledc::new(ledc);
        ledc.set_global_slow_clock(LSGlobalClkSource::APBClk);
        let timer = TIMER.init(ledc.timer(timer::Number::Timer0));
        timer
            .configure(timer::config::Config {
                duty: Duty::Duty8Bit,
                clock_source: LSClockSource::APBClk,
                frequency: Rate::from_khz(1),
            })
            .unwrap();
        let mut channel = ledc.channel(channel::Number::Channel0, pin);
        channel
            .configure(channel::config::Config {
                timer,
                duty_pct: 0,
                drive_mode: DriveMode::PushPull,
            })
            .unwrap();
        Self {
            channel,
            awake: None,
        }
    }

    /// Drives `duty`, and returns once the PWM has stopped driving a light
    /// turned off, so sleep cannot stop it mid-pulse.
    async fn set(&mut self, duty: u8) {
        // A full count is fully on; 255 of 256 would leave a sliver off.
        // Arduino's `ledcWrite` makes the same substitution.
        let count = if duty == u8::MAX {
            1 << 8
        } else {
            u32::from(duty)
        };
        self.channel.set_duty_hw(count);
        if duty == 0 {
            if self.awake.is_some() {
                Timer::after(LATCH).await;
            }
            self.awake = None;
        } else {
            self.awake.get_or_insert_with(WakeLock::new);
        }
    }
}

#[embassy_executor::task]
pub async fn task(mut light: Light) {
    let mut power = power::Receiver::new();
    let mut level = 0;
    let mut fade: Option<Fade> = None;
    let mut asleep = false;
    // When the light comes back as it was before a sleep, unless the host
    // sets it first.
    let mut restore_at: Option<Instant> = None;
    loop {
        let next = match (fade, restore_at) {
            (Some(_), Some(at)) => Some(at.min(Instant::now() + STEP)),
            (Some(_), None) => Some(Instant::now() + STEP),
            (None, at) => at,
        };
        let tick = async {
            match next {
                Some(at) => Timer::at(at).await,
                None => core::future::pending().await,
            }
        };
        match select3(LIGHT.wait(), power.changed(), tick).await {
            Either3::First(duty) => {
                let now = Instant::now().as_millis();
                fade = (duty != level).then(|| Fade::new(level, duty, now));
            }
            Either3::Second(sleeping) => {
                asleep = sleeping;
                if sleeping {
                    restore_at = None;
                    let now = Instant::now().as_millis();
                    fade = (level != 0).then(|| Fade::new(level, 0, now));
                } else {
                    restore_at = Some(Instant::now() + Duration::from_millis(RESTORE_MS));
                }
            }
            Either3::Third(()) => {
                if restore_at.is_some_and(|at| at <= Instant::now()) {
                    restore_at = None;
                    // The light's new duty, if any, comes as a signal.
                    with_keyboard(|keyboard| keyboard.restore_light());
                }
                if let Some(going) = fade {
                    let now = Instant::now().as_millis();
                    level = going.level(now);
                    light.set(level).await;
                    if going.done(now) {
                        fade = None;
                    }
                }
            }
        }
        if asleep && fade.is_none() && level == 0 {
            power::parked(Part::Light);
        }
    }
}
