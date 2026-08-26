//! PCF8563 battery-backed real-time clock, async, over
//! `embedded-hal-async` I²C.
//!
//! Time only: read the clock, set the clock. Alarms, the timer, and
//! CLKOUT are not transcribed — no UMSH board wires them to anything
//! yet, and the alarm interrupt's polarity and open-drain behavior want
//! hardware validation before anything depends on them.
//!
//! # Why this is worth having
//!
//! A board with one of these knows what time it is at boot without a
//! GNSS fix, which no other UMSH board does. It is the first
//! `TimeSource::ExternalRtc` in the tree: the wall clock takes the RTC's
//! reading at boot, and a later GNSS fix steps the clock and is written
//! back here so the next boot starts closer.
//!
//! # Not knowing is a state
//!
//! The part latches a voltage-low flag when its oscillator has stopped —
//! a dead backup cell, a first power-up. In that condition it does not
//! report *no* time, it reports whatever its registers hold. So
//! [`Pcf8563::read`] answers `None` on that flag rather than handing up
//! a well-formed instant that is wrong by decades, and applies the same
//! plausibility floor the GNSS parser uses as a backstop.
//!
//! # The century bit
//!
//! Upstream drivers disagree about which polarity of the century bit
//! means 19xx, and the disagreement is old enough that both conventions
//! exist in shipping hardware. UMSH sidesteps it: this driver reads and
//! writes 2000–2099 only, writes the century bit as zero, and ignores it
//! on read. Nothing is lost — the clock's `u32` epoch runs out in 2106
//! and the plausibility floor already refuses anything before 2020.

#![no_std]

use embedded_hal_async::i2c::I2c;
use umsh_gnss::epoch::{DateTime, MIN_PLAUSIBLE_EPOCH};

#[cfg(test)]
mod tests;

/// The PCF8563's fixed 7-bit I²C address.
pub const DEFAULT_ADDRESS: u8 = 0x51;

/// Seconds register. Bit 7 is the voltage-low flag; bits 6:0 are BCD
/// seconds.
const REG_SECONDS: u8 = 0x02;
/// Bit 7 of [`REG_SECONDS`]: the oscillator has stopped since this was
/// last cleared, so the time is not trustworthy.
const VOLTAGE_LOW: u8 = 0x80;

/// The first register of the contiguous time block: seconds, minutes,
/// hours, day, weekday, month/century, year.
const TIME_BLOCK: u8 = REG_SECONDS;
const TIME_BLOCK_LEN: usize = 7;

/// Field masks. The unmasked bits are reserved and read as anything.
const MASK_SECONDS: u8 = 0x7F;
const MASK_MINUTES: u8 = 0x7F;
const MASK_HOURS: u8 = 0x3F;
const MASK_DAY: u8 = 0x3F;
const MASK_WEEKDAY: u8 = 0x07;
const MASK_MONTH: u8 = 0x1F;

/// The only century this driver represents.
const CENTURY: i32 = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    /// The bus refused the transfer.
    Bus(E),
    /// The instant is outside 2000–2099, which this driver does not
    /// represent, or is not a real date.
    Unrepresentable,
}

impl<E> From<E> for Error<E> {
    fn from(e: E) -> Self {
        Error::Bus(e)
    }
}

type Result<T, E> = core::result::Result<T, Error<E>>;

/// Decode a packed-BCD byte, or `None` if either nibble is not a digit.
const fn from_bcd(value: u8) -> Option<u8> {
    let tens = value >> 4;
    let ones = value & 0x0F;
    if tens > 9 || ones > 9 {
        return None;
    }
    Some(tens * 10 + ones)
}

/// Encode 0–99 as packed BCD.
const fn to_bcd(value: u8) -> u8 {
    ((value / 10) << 4) | (value % 10)
}

/// Day of week, 0 = Sunday, as the part numbers them.
///
/// The PCF8563 keeps this field but never derives it — it only counts
/// the register up — so a writer has to compute it or the field drifts
/// into nonsense.
const fn weekday_from_unix(seconds: u32) -> u8 {
    // 1970-01-01 was a Thursday.
    ((seconds / 86_400 + 4) % 7) as u8
}

pub struct Pcf8563<I> {
    i2c: I,
    addr: u8,
}

impl<I: I2c> Pcf8563<I> {
    pub fn new(i2c: I) -> Self {
        Self::with_address(i2c, DEFAULT_ADDRESS)
    }

    pub fn with_address(i2c: I, addr: u8) -> Self {
        Self { i2c, addr }
    }

    pub fn release(self) -> I {
        self.i2c
    }

    /// Whether anything answers at the RTC's address.
    ///
    /// A bare presence check: the PCF8563 has no identity register, so
    /// this cannot distinguish it from another part strapped to 0x51.
    pub async fn present(&mut self) -> bool {
        let mut scratch = [0u8; 1];
        self.i2c
            .write_read(self.addr, &[REG_SECONDS], &mut scratch)
            .await
            .is_ok()
    }

    /// Whether the oscillator has stopped since the clock was last set.
    pub async fn voltage_low(&mut self) -> Result<bool, I::Error> {
        let mut buf = [0u8; 1];
        self.i2c
            .write_read(self.addr, &[REG_SECONDS], &mut buf)
            .await?;
        Ok(buf[0] & VOLTAGE_LOW != 0)
    }

    /// The current time as seconds since the Unix epoch.
    ///
    /// `None` means the RTC has no time to give: the oscillator stopped,
    /// a BCD field is not a digit, or the assembled date is implausible.
    /// A caller must treat that as "unknown", never as a fallback value.
    pub async fn read(&mut self) -> Result<Option<u32>, I::Error> {
        let mut buf = [0u8; TIME_BLOCK_LEN];
        self.i2c
            .write_read(self.addr, &[TIME_BLOCK], &mut buf)
            .await?;
        Ok(decode_time_block(&buf))
    }

    /// Set the clock from a Unix second count, clearing the voltage-low
    /// flag.
    ///
    /// Writes the whole time block in one transaction so the registers
    /// cannot be caught half-updated across a rollover.
    pub async fn write(&mut self, seconds: u32) -> Result<(), I::Error> {
        let block = encode_time_block(seconds).ok_or(Error::Unrepresentable)?;
        let mut payload = [0u8; 1 + TIME_BLOCK_LEN];
        payload[0] = TIME_BLOCK;
        payload[1..].copy_from_slice(&block);
        self.i2c.write(self.addr, &payload).await?;
        Ok(())
    }
}

/// Assemble a time-block read into a Unix second count.
fn decode_time_block(buf: &[u8; TIME_BLOCK_LEN]) -> Option<u32> {
    if buf[0] & VOLTAGE_LOW != 0 {
        return None;
    }
    let second = from_bcd(buf[0] & MASK_SECONDS)?;
    let minute = from_bcd(buf[1] & MASK_MINUTES)?;
    let hour = from_bcd(buf[2] & MASK_HOURS)?;
    let day = from_bcd(buf[3] & MASK_DAY)?;
    // buf[4] is the weekday, which carries no information the date does
    // not already fix.
    let month = from_bcd(buf[5] & MASK_MONTH)?;
    let year = from_bcd(buf[6])?;

    let at = DateTime {
        year: CENTURY + year as i32,
        month,
        day,
        hour,
        minute,
        second,
    };
    let seconds = at.to_unix()?;
    // Backstop: a clock that lost its backup domain without latching the
    // flag still cannot be reporting a date from before this software.
    (seconds >= MIN_PLAUSIBLE_EPOCH).then_some(seconds)
}

/// Encode a Unix second count as the seven time-block registers.
fn encode_time_block(seconds: u32) -> Option<[u8; TIME_BLOCK_LEN]> {
    let at = DateTime::from_unix(seconds);
    if at.year < CENTURY || at.year >= CENTURY + 100 {
        return None;
    }
    Some([
        // Writing the seconds register with bit 7 clear also clears the
        // voltage-low flag, which is how the part is told its time is
        // good again.
        to_bcd(at.second),
        to_bcd(at.minute),
        to_bcd(at.hour),
        to_bcd(at.day),
        weekday_from_unix(seconds) & MASK_WEEKDAY,
        // Century bit left at zero; see the module docs.
        to_bcd(at.month),
        to_bcd((at.year - CENTURY) as u8),
    ])
}
