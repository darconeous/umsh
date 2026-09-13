//! PCF85063A, 24-hour mode, 2000–2099. Oscillator-stop means unknown time.
use embedded_hal_async::i2c::I2c;
use umsh_gnss::epoch::{DateTime, MIN_PLAUSIBLE_EPOCH};
pub struct Pcf85063<I> {
    i2c: I,
}
impl<I: I2c> Pcf85063<I> {
    pub fn new(i2c: I) -> Self {
        Self { i2c }
    }
    /// Disable the unused clock output without touching retained time.
    pub async fn init(&mut self) -> Result<(), I::Error> {
        crate::update(&mut self.i2c, 0x51, 1, 7, 7).await
    }
    pub async fn read(&mut self) -> Result<Option<u32>, I::Error> {
        let control = crate::read(&mut self.i2c, 0x51, 0).await?;
        let mut bytes = [0; 7];
        self.i2c.write_read(0x51, &[4], &mut bytes).await?;
        // Don't reinterpret a stopped, test-mode, or 12-hour clock as 24-hour time.
        if control & 0xa2 != 0 {
            return Ok(None);
        }
        Ok(decode(&bytes))
    }
    pub async fn write(&mut self, epoch: u32) -> Result<(), I::Error> {
        let Some(bytes) = encode(epoch) else {
            return Ok(());
        };
        // Stop before changing all time fields; a failed write leaves it stopped
        // and therefore invalid on the next read.
        crate::update(&mut self.i2c, 0x51, 0, 0xa2, 0x20).await?;
        let mut command = [4; 8];
        command[1..].copy_from_slice(&bytes);
        self.i2c.write(0x51, &command).await?;
        crate::update(&mut self.i2c, 0x51, 0, 0xa2, 0).await
    }
}
fn bcd(v: u8) -> Option<u8> {
    ((v >> 4) < 10 && (v & 15) < 10).then_some((v >> 4) * 10 + (v & 15))
}
fn packed(v: u8) -> u8 {
    (v / 10) << 4 | (v % 10)
}
pub fn decode(b: &[u8; 7]) -> Option<u32> {
    if b[0] & 0x80 != 0 {
        return None;
    }
    let date = DateTime {
        year: 2000 + i32::from(bcd(b[6])?),
        month: bcd(b[5] & 0x1f)?,
        day: bcd(b[3] & 0x3f)?,
        hour: bcd(b[2] & 0x3f)?,
        minute: bcd(b[1] & 0x7f)?,
        second: bcd(b[0] & 0x7f)?,
    };
    date.to_unix().filter(|t| *t >= MIN_PLAUSIBLE_EPOCH)
}
pub fn encode(epoch: u32) -> Option<[u8; 7]> {
    let d = DateTime::from_unix(epoch);
    if !(2000..=2099).contains(&d.year) {
        return None;
    }
    Some([
        packed(d.second),
        packed(d.minute),
        packed(d.hour),
        packed(d.day),
        ((epoch / 86400 + 4) % 7) as u8,
        packed(d.month),
        packed((d.year - 2000) as u8),
    ])
}
