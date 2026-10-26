//! Pager locate outputs. ES8311 register sequencing follows Espressif's
//! Apache-2.0 esp-bsp/components/es8311 driver; fixed 4.096 MHz MCLK / 16 kHz.
use embedded_hal_async::{delay::DelayNs, i2c::I2c};

pub const CODEC: u8 = 0x18;
pub const HAPTIC: u8 = 0x5a;
pub const PERIOD_MS: u64 = 3_000;
pub const PULSE_MS: u64 = 600;
// Unity codec gain; the tones `umsh-sound` makes keep about 12 dB of headroom.
// The ES8311 uses 0.5 dB steps relative to 0xbf (0 dB).
pub const DAC_VOLUME: u8 = 0xbf;

pub fn bright(elapsed_ms: u64) -> bool {
    elapsed_ms % PERIOD_MS < PULSE_MS
}

pub struct Codec<I>(pub I);
impl<I: I2c> Codec<I> {
    async fn write(&mut self, reg: u8, value: u8) -> Result<(), I::Error> {
        self.0.write(CODEC, &[reg, value]).await
    }
    pub async fn init(&mut self, delay: &mut impl DelayNs) -> Result<(), I::Error> {
        self.write(0x00, 0x1f).await?;
        delay.delay_ms(20).await;
        // Slave, MCLK pin, 256fs, 16-bit Philips input. ADC stays powered down.
        for (r, v) in [
            (0x00, 0x00),
            (0x00, 0x80),
            (0x01, 0x3f),
            (0x02, 0x00),
            (0x03, 0x10),
            (0x04, 0x10),
            (0x05, 0x00),
            (0x06, 0x03),
            (0x07, 0x00),
            (0x08, 0xff),
            (0x09, 0x0c),
            (0x0a, 0x4c),
            (0x31, 0x60),
            (0x32, DAC_VOLUME),
            (0x0d, 0x01),
            (0x0e, 0x6a),
            (0x12, 0x00),
            (0x13, 0x10),
            (0x37, 0x08),
        ] {
            self.write(r, v).await?;
        }
        Ok(())
    }
    pub async fn mute(&mut self, muted: bool) -> Result<(), I::Error> {
        crate::update(&mut self.0, CODEC, 0x31, 0x60, if muted { 0x60 } else { 0 }).await
    }
    pub async fn sleep(&mut self) -> Result<(), I::Error> {
        self.mute(true).await?;
        // DAC/output, analog, then internal clocks off. Amplifier is external.
        for (r, v) in [
            (0x12, 0x02),
            (0x13, 0x00),
            (0x0e, 0xff),
            (0x0d, 0xfa),
            (0x01, 0x00),
        ] {
            self.write(r, v).await?;
        }
        Ok(())
    }
}

pub struct Haptic<I>(pub I);
impl<I: I2c> Haptic<I> {
    pub async fn init(&mut self) -> Result<(), I::Error> {
        // Library-1 ERM, internal trigger, open-loop library playback. Same
        // board configuration as LilyGo SensorDRV2605; no boot effect.
        for (r, v) in [
            (0x01, 0),
            (0x02, 0),
            (0x03, 1),
            (0x04, 15),
            (0x05, 0),
            (0x0c, 0),
            (0x0d, 0),
            (0x0e, 0),
            (0x0f, 0),
            (0x10, 0),
        ] {
            self.0.write(HAPTIC, &[r, v]).await?;
        }
        crate::update(&mut self.0, HAPTIC, 0x1a, 0x80, 0).await?;
        crate::update(&mut self.0, HAPTIC, 0x1d, 0x20, 0x20).await
    }
    pub async fn play(&mut self, on: bool) -> Result<(), I::Error> {
        self.0.write(HAPTIC, &[0x0c, u8::from(on)]).await
    }
    /// Plays a short buzz in place of the alert's long one: library effect
    /// 47, Buzz 1, alone in the sequence. The clicks are too short for the
    /// motor to spin up and are barely felt. `init` restores the long buzz.
    pub async fn buzz(&mut self) -> Result<(), I::Error> {
        self.0.write(HAPTIC, &[0x04, 47]).await?;
        self.0.write(HAPTIC, &[0x05, 0]).await?;
        self.play(true).await
    }
    pub async fn sleep(&mut self) -> Result<(), I::Error> {
        self.play(false).await?;
        self.0.write(HAPTIC, &[0x01, 0x40]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_hal::i2c::{ErrorKind, ErrorType};
    use embedded_hal_async::i2c::Operation;
    use std::vec::Vec;

    struct Registers {
        values: [u8; 256],
        writes: Vec<(u8, u8)>,
        address: u8,
        fail: Option<u8>,
    }
    impl Registers {
        fn new(address: u8) -> Self {
            Self {
                values: [0; 256],
                writes: Vec::new(),
                address,
                fail: None,
            }
        }
    }
    impl ErrorType for Registers {
        type Error = ErrorKind;
    }
    impl I2c for Registers {
        async fn transaction(
            &mut self,
            addr: u8,
            ops: &mut [Operation<'_>],
        ) -> Result<(), ErrorKind> {
            assert_eq!(addr, self.address);
            match ops {
                [Operation::Write(bytes)] => {
                    if self.fail == Some(bytes[0]) {
                        return Err(ErrorKind::Bus);
                    }
                    assert_eq!(bytes.len(), 2);
                    self.values[bytes[0] as usize] = bytes[1];
                    self.writes.push((bytes[0], bytes[1]));
                }
                [Operation::Write(reg), Operation::Read(out)] => {
                    assert_eq!(out.len(), 1);
                    out[0] = self.values[reg[0] as usize];
                }
                _ => panic!("unexpected operation"),
            }
            Ok(())
        }
    }
    struct Delay;
    impl DelayNs for Delay {
        async fn delay_ns(&mut self, _: u32) {}
    }
    #[test]
    fn codec_starts_muted_at_unity_gain_and_sleeps_after_muting() {
        embassy_futures::block_on(async {
            let mut c = Codec(Registers::new(CODEC));
            c.init(&mut Delay).await.unwrap();
            assert_eq!(c.0.writes[0], (0, 0x1f));
            assert_eq!(c.0.values[0x31] & 0x60, 0x60);
            assert_eq!(c.0.values[0x32], 0xbf);
            assert_eq!(c.0.values[0x09], 0x0c);
            assert_eq!(c.0.values[0x0e] & 0x60, 0x60); // no capture
            c.mute(false).await.unwrap();
            assert_eq!(c.0.values[0x31] & 0x60, 0);
            c.0.writes.clear();
            c.sleep().await.unwrap();
            assert_eq!(c.0.writes[0], (0x31, 0x60));
            assert_eq!(c.0.values[0x12] & 2, 2);
            assert_eq!(c.0.values[0x01], 0);
        });
    }
    #[test]
    fn haptic_does_not_play_during_init_and_stops_before_standby() {
        embassy_futures::block_on(async {
            let mut h = Haptic(Registers::new(HAPTIC));
            h.init().await.unwrap();
            assert!(!h.0.writes.contains(&(0x0c, 1)));
            assert_eq!(h.0.values[3], 1);
            assert_eq!(h.0.values[4], 15);
            assert_eq!(h.0.values[0x1a] & 0x80, 0);
            h.play(true).await.unwrap();
            h.0.writes.clear();
            h.sleep().await.unwrap();
            assert_eq!(h.0.writes, [(0x0c, 0), (0x01, 0x40)]);
        });
    }
    #[test]
    fn initialization_failure_never_starts_an_output() {
        embassy_futures::block_on(async {
            let mut c = Codec(Registers::new(CODEC));
            c.0.fail = Some(0x04);
            assert!(c.init(&mut Delay).await.is_err());
            assert!(!c.0.writes.contains(&(0x31, 0)));
            let mut h = Haptic(Registers::new(HAPTIC));
            h.0.fail = Some(0x03);
            assert!(h.init().await.is_err());
            assert!(!h.0.writes.contains(&(0x0c, 1)));
        });
    }
    #[test]
    fn pulse_and_gap_repeat() {
        for base in [0, 3000, 6000] {
            assert!(bright(base));
            assert!(bright(base + 599));
            assert!(!bright(base + 600));
            assert!(!bright(base + 2999));
        }
    }
}
