//! XL9555 power domains and BQ25896/BQ27220 telemetry. No gauge provisioning.
use embedded_hal_async::{delay::DelayNs, i2c::I2c};

const EXPANDER: u8 = 0x20;
const CHARGER: u8 = 0x6b;
const GAUGE: u8 = 0x55;
pub const KEYBOARD_RESET: u16 = 1 << 2;
pub const RADIO_ENABLE: u16 = 1 << 3;
pub const GPS_ENABLE: u16 = 1 << 4;
pub const GPS_RESET: u16 = 1 << 7;
pub const KEYBOARD_ENABLE: u16 = 1 << 8;
// Bit 10 is SD detect; bit 11 remains an input, following LilyGo's board setup.
const OUTPUTS: u16 = 0x13bf;

pub struct Expander<I> {
    i2c: I,
    outputs: u16,
    shutting_down: bool,
}
impl<I: I2c> Expander<I> {
    pub fn new(i2c: I) -> Self {
        Self {
            i2c,
            outputs: 0,
            shutting_down: false,
        }
    }
    pub async fn init(&mut self, delay: &mut impl DelayNs) -> Result<(), I::Error> {
        // Latch low before changing direction: no transient enables at boot.
        self.i2c.write(EXPANDER, &[2, 0, 0]).await?;
        self.i2c.write(EXPANDER, &[4, 0, 0]).await?;
        let config = (!OUTPUTS).to_le_bytes();
        self.i2c.write(EXPANDER, &[6, config[0], config[1]]).await?;
        self.outputs = 0;
        self.set(KEYBOARD_ENABLE | RADIO_ENABLE, true).await?;
        delay.delay_ms(10).await;
        self.set(KEYBOARD_RESET, true).await?;
        delay.delay_ms(10).await;
        Ok(())
    }
    pub async fn set(&mut self, mask: u16, enabled: bool) -> Result<(), I::Error> {
        if self.shutting_down && enabled {
            return Ok(());
        }
        let next = if enabled {
            self.outputs | (mask & OUTPUTS)
        } else {
            self.outputs & !mask
        };
        let bytes = next.to_le_bytes();
        self.i2c.write(EXPANDER, &[2, bytes[0], bytes[1]]).await?;
        self.outputs = next;
        Ok(())
    }
    pub async fn shutdown(&mut self) -> Result<(), I::Error> {
        self.shutting_down = true;
        self.set(OUTPUTS, false).await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charge {
    Discharging,
    Charging,
    Charged,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub voltage_mv: Option<u16>,
    pub percent: Option<u8>,
    pub charge: Option<Charge>,
    pub vbus: bool,
}
pub struct Battery<I> {
    i2c: I,
}
impl<I: I2c> Battery<I> {
    pub fn new(i2c: I) -> Self {
        Self { i2c }
    }
    pub async fn init(&mut self) -> Result<(), I::Error> {
        // Disable charge during profile changes and disable OTG. No global reset.
        crate::update(&mut self.i2c, CHARGER, 3, 0x30, 0).await?;
        // Disable register watchdog; retain termination, safety timer, and JEITA.
        crate::update(&mut self.i2c, CHARGER, 7, 0x30, 0).await?;
        // 3840 + 22*16 = 4192 mV; 11*64 = 704 mA for the stock 1500 mAh cell.
        crate::update(&mut self.i2c, CHARGER, 6, 0xfc, 22 << 2).await?;
        crate::update(&mut self.i2c, CHARGER, 4, 0x7f, 11).await?;
        crate::update(&mut self.i2c, CHARGER, 2, 0xc0, 0xc0).await?;
        crate::update(&mut self.i2c, CHARGER, 3, 0x10, 0x10).await
    }
    async fn word(&mut self, reg: u8) -> Result<u16, I::Error> {
        let mut bytes = [0; 2];
        self.i2c.write_read(GAUGE, &[reg], &mut bytes).await?;
        Ok(u16::from_le_bytes(bytes))
    }
    pub async fn read(&mut self) -> Result<Reading, I::Error> {
        let status = crate::read(&mut self.i2c, CHARGER, 0x0b).await?;
        let vbus = crate::read(&mut self.i2c, CHARGER, 0x11).await? & 0x80 != 0;
        // A missing gauge must not suppress USB attach/detach detection.
        let gauge = match (
            self.word(8).await,
            self.word(0x0a).await,
            self.word(0x2c).await,
            self.word(0x3a).await,
        ) {
            (Ok(mv), Ok(flags), Ok(soc), Ok(operation)) => Some((mv, flags, soc, operation)),
            _ => None,
        };
        Ok(decode_reading(status, vbus, gauge))
    }
    pub async fn sleep(&mut self) -> Result<(), I::Error> {
        crate::update(&mut self.i2c, CHARGER, 2, 0xc0, 0).await
    }
}

pub fn decode_reading(status: u8, vbus: bool, gauge: Option<(u16, u16, u16, u16)>) -> Reading {
    let mut reading = Reading {
        voltage_mv: None,
        percent: None,
        charge: None,
        vbus,
    };
    if let Some((mv, flags, soc, operation)) = gauge {
        // BAT_DET bit 3 and a plausible single-cell voltage; INITCOMP gates SOC.
        if flags & 8 != 0 && (2000..=4600).contains(&mv) {
            reading.voltage_mv = Some(mv);
            reading.percent = (operation & 0x20 != 0 && soc <= 100).then_some(soc as u8);
            reading.charge = if !vbus {
                Some(Charge::Discharging)
            } else {
                match (status >> 3) & 3 {
                    1 | 2 => Some(Charge::Charging),
                    3 => Some(Charge::Charged),
                    _ => None,
                }
            };
        }
    }
    reading
}

#[derive(Default)]
pub struct LowBattery {
    consecutive: u8,
}
impl LowBattery {
    /// Called only on the one-second cadence, not on host-requested samples.
    pub fn sample(&mut self, sample: Option<&Reading>) -> bool {
        if sample.is_some_and(|r| !r.vbus && r.voltage_mv.is_some_and(|mv| mv <= 3100)) {
            self.consecutive = self.consecutive.saturating_add(1);
        } else {
            self.consecutive = 0;
        }
        self.consecutive >= 10
    }
}
