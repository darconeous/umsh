//! The S3's side: an I²C target at the stock address, and the sleep the
//! host can send the keyboard into.
//!
//! On a sleep command the target comes off the bus, which drops its wake
//! lock, the other tasks park, and the task waits for SCL to fall, which
//! any traffic on the bus does. With nothing else awake the chip sleeps
//! until then. The transaction that woke it goes unanswered, and the host
//! retries it. Traffic while the others are still parking, as the light
//! fades out, wakes the keyboard just the same.

use embassy_futures::select::{Either, select};
use esp_hal::{
    gpio::{AnyPin, Flex, InputConfig},
    i2c::slave::{self, Command, I2cSlave},
    peripherals::I2C0,
};
use esp_println::println;
use firmware_tdeck_tkeyboard::{
    controller::{MAX_REPLY, Power},
    protocol,
};

use crate::{power, with_keyboard};

/// The longest write kept; the rest of a longer one is dropped. Every
/// command is two bytes or less.
const WRITE_CAPACITY: usize = 32;

pub struct Bus {
    pub i2c: I2C0<'static>,
    pub sda: AnyPin<'static>,
    pub scl: AnyPin<'static>,
}

#[embassy_executor::task]
pub async fn task(mut bus: Bus) {
    loop {
        serve(&mut bus).await;
        // SCL has its pull-up on the board. A pin being waited on is a
        // wake source.
        let mut scl = Flex::new(bus.scl.reborrow());
        scl.apply_input_config(&InputConfig::default());
        scl.set_input_enable(true);
        // The host may come back before the light is out: a host retries
        // a sleeping keyboard for only a few milliseconds.
        if let Either::First(()) = select(power::park(), scl.wait_for_low()).await {
            scl.wait_for_low().await;
        }
        power::wake();
        with_keyboard(|keyboard| keyboard.on_wake());
    }
}

/// Answers the host until it sends the keyboard to sleep.
async fn serve(bus: &mut Bus) {
    let mut target = I2cSlave::new(bus.i2c.reborrow(), slave::Config::new(protocol::ADDRESS))
        .unwrap()
        .with_sda(bus.sda.reborrow())
        .with_scl(bus.scl.reborrow())
        .into_async();
    let mut write = [0; WRITE_CAPACITY];
    loop {
        match target.listen_async(&mut write).await {
            Ok(Command::Write(len)) => {
                if with_keyboard(|keyboard| keyboard.on_write(&write[..len])) == Power::Sleep {
                    return;
                }
            }
            // The host's clock is held until the reply is queued. A host
            // that reads past the reply gets 0xFF, an idle bus.
            Ok(Command::Read) => {
                let mut reply = [0; MAX_REPLY];
                let len = with_keyboard(|keyboard| keyboard.on_read(&mut reply));
                if let Err(error) = target.respond_to_read_async(&reply[..len]).await {
                    println!("i2c: read: {error:?}");
                }
            }
            // A transaction gone wrong is dropped; the next listen starts
            // the target afresh.
            Err(error) => println!("i2c: {error:?}"),
        }
    }
}
