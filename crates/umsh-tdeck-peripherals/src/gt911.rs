//! The GT911 touch controller (§7). Its address and the sense of its
//! interrupt line both vary between panels, so both are found at boot;
//! the panel's stored configuration is never written.

use embedded_hal_async::i2c::I2c;

/// The two addresses the GT911 latches from INT at reset.
pub const ADDRESSES: [u8; 2] = [0x5d, 0x14];
const COMMAND: u16 = 0x8040;
const PRODUCT_ID: u16 = 0x8140;
/// Status, then the first point: its track ID, then X and Y little-endian.
const STATUS: u16 = 0x814e;
/// Status: a report is ready, and how many points it holds.
const READY: u8 = 0x80;
const COUNT: u8 = 0x0f;

/// The panel in landscape, as the frame is drawn.
pub const WIDTH: u16 = 320;
pub const HEIGHT: u16 = 240;

/// Which level of INT means a report is waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polarity {
    ActiveLow,
    ActiveHigh,
}

impl Polarity {
    /// The sense of a line read `high` with no point reported.
    #[must_use]
    pub const fn from_idle(high: bool) -> Self {
        if high {
            Self::ActiveLow
        } else {
            Self::ActiveHigh
        }
    }
    /// Whether a line read `high` is asserted.
    #[must_use]
    pub const fn asserted(self, high: bool) -> bool {
        matches!(
            (self, high),
            (Self::ActiveHigh, true) | (Self::ActiveLow, false)
        )
    }
}

/// A point on the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: u16,
    pub y: u16,
}

/// A raw portrait point turned to the landscape frame: X and Y swapped,
/// then Y mirrored (LilyGO's mapping; a corner test confirms it).
#[must_use]
pub const fn landscape(raw_x: u16, raw_y: u16) -> Point {
    let x = if raw_y < WIDTH { raw_y } else { WIDTH - 1 };
    let y = if raw_x < HEIGHT { raw_x } else { HEIGHT - 1 };
    Point {
        x,
        y: HEIGHT - 1 - y,
    }
}

/// What the controller reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    /// No new report since the last read.
    Pending,
    /// A finger, at its first point.
    Touched(Point),
    /// Every finger lifted.
    Released,
}

pub struct Gt911<I> {
    i2c: I,
    address: u8,
}

impl<I: I2c> Gt911<I> {
    /// The controller at whichever address answers with a product ID.
    pub async fn probe(mut i2c: I) -> Result<Self, I> {
        for address in ADDRESSES {
            let mut id = [0; 4];
            if read(&mut i2c, address, PRODUCT_ID, &mut id).await.is_ok() && id[0].is_ascii_digit()
            {
                return Ok(Self { i2c, address });
            }
        }
        Err(i2c)
    }

    pub const fn address(&self) -> u8 {
        self.address
    }

    /// The latest report, acknowledged so the controller makes the next.
    /// The status and the first point come in one transfer.
    pub async fn read(&mut self) -> Result<Report, I::Error> {
        let mut report = [0; 6];
        read(&mut self.i2c, self.address, STATUS, &mut report).await?;
        let [status, _track, x_low, x_high, y_low, y_high] = report;
        if status & READY == 0 {
            return Ok(Report::Pending);
        }
        let report = if status & COUNT == 0 {
            Report::Released
        } else {
            Report::Touched(landscape(
                u16::from_le_bytes([x_low, x_high]),
                u16::from_le_bytes([y_low, y_high]),
            ))
        };
        write(&mut self.i2c, self.address, STATUS, 0).await?;
        Ok(report)
    }

    /// The sense of INT, from `line_high` sampled between two reads that
    /// both found nothing reported (§7.3). A report on either side means
    /// the line may not have been idle: `None`, and the caller tries
    /// again. The first read only proves no finger is down if it comes at
    /// least a report period after the last one acknowledged.
    pub async fn idle_polarity(
        &mut self,
        line_high: impl FnOnce() -> bool,
    ) -> Result<Option<Polarity>, I::Error> {
        if self.read().await? != Report::Pending {
            return Ok(None);
        }
        let high = line_high();
        if self.read().await? != Report::Pending {
            return Ok(None);
        }
        Ok(Some(Polarity::from_idle(high)))
    }

    /// Sleeps until INT is driven high for a few milliseconds.
    pub async fn sleep(&mut self) -> Result<(), I::Error> {
        write(&mut self.i2c, self.address, COMMAND, 5).await
    }
}

async fn read<I: I2c>(
    i2c: &mut I,
    address: u8,
    register: u16,
    out: &mut [u8],
) -> Result<(), I::Error> {
    i2c.write_read(address, &register.to_be_bytes(), out).await
}

async fn write<I: I2c>(i2c: &mut I, address: u8, register: u16, value: u8) -> Result<(), I::Error> {
    let [high, low] = register.to_be_bytes();
    i2c.write(address, &[high, low, value]).await
}
