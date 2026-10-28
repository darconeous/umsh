//! The key light: PWM on GPIO9, the gate of the FET that switches the key
//! LEDs. 1 kHz and 8 bits, as on stock firmware.
//!
//! The PWM runs from the APB clock, which stops in light sleep, so the
//! light holds a wake lock while it is on. Off, its output is a steady low,
//! which sleep keeps; the gate's pull-up would light the LEDs otherwise.

use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Timer};
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
use static_cell::StaticCell;

use crate::power::{self, Part};
use crate::{LIGHT, with_keyboard};

/// One PWM period, and then some: a new duty takes effect at the end of
/// the period it is written in.
const LATCH: Duration = Duration::from_millis(2);

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

    fn set(&mut self, duty: u8) {
        // A full count is fully on; 255 of 256 would leave a sliver off.
        // Arduino's `ledcWrite` makes the same substitution.
        let count = if duty == u8::MAX {
            1 << 8
        } else {
            u32::from(duty)
        };
        self.channel.set_duty_hw(count);
        if duty == 0 {
            self.awake = None;
        } else {
            self.awake.get_or_insert_with(WakeLock::new);
        }
    }

    /// Turns the light off for sleep, and returns once the PWM has stopped
    /// driving it.
    async fn park(&mut self) {
        self.channel.set_duty_hw(0);
        Timer::after(LATCH).await;
        self.awake = None;
    }
}

#[embassy_executor::task]
pub async fn task(mut light: Light) {
    let mut asleep = power::Receiver::new();
    loop {
        match select(LIGHT.wait(), asleep.until_asleep()).await {
            Either::First(duty) => light.set(duty),
            Either::Second(()) => {
                light.park().await;
                asleep.park_until_awake(Part::Light).await;
                light.set(with_keyboard(|keyboard| keyboard.backlight()));
            }
        }
    }
}
