//! Pager locate outputs. ES8311 register sequencing follows Espressif's
//! Apache-2.0 esp-bsp/components/es8311 driver; fixed 4.096 MHz MCLK / 16 kHz.
use embedded_hal_async::{delay::DelayNs, i2c::I2c};

pub const CODEC: u8 = 0x18;
pub const HAPTIC: u8 = 0x5a;
pub const PERIOD_MS: u64 = 3_000;
pub const PULSE_MS: u64 = 600;
// Unity codec gain; the PCM generator retains approximately 12 dB of headroom.
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
    pub async fn sleep(&mut self) -> Result<(), I::Error> {
        self.play(false).await?;
        self.0.write(HAPTIC, &[0x01, 0x40]).await
    }
}

/// Allocation-free 16 kHz sine oscillator, ~-12 dBFS, with a 5 ms
/// envelope at both ends of each 150 ms note. Identical stereo samples.
#[derive(Default)]
pub struct ToneSamples {
    phase: u32,
}
impl ToneSamples {
    pub fn frame(&mut self, hz: u16, note_sample: u32) -> [u8; 4] {
        const QUARTER: [i32; 17] = [
            0, 803, 1598, 2378, 3135, 3862, 4551, 5197, 5793, 6333, 6811, 7225, 7568, 7839, 8035,
            8153, 8192,
        ];
        if hz == 0 {
            self.phase = 0;
            return [0; 4];
        }
        let i = (self.phase >> 26) as usize;
        let v = match i / 16 {
            0 => QUARTER[i],
            1 => QUARTER[32 - i],
            2 => -QUARTER[i - 32],
            _ => -QUARTER[64 - i],
        };
        self.phase = self
            .phase
            .wrapping_add(((u64::from(hz) << 32) / 16_000) as u32);
        let envelope = note_sample.min(2399u32.saturating_sub(note_sample)).min(80) as i32;
        let bytes = ((v * envelope / 80) as i16).to_le_bytes();
        [bytes[0], bytes[1], bytes[0], bytes[1]]
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
    #[test]
    fn tones_have_the_requested_fundamental_at_16khz() {
        for hz in [1900, 2600] {
            let mut samples = ToneSamples::default();
            let mut previous = 0i16;
            let mut crossings = 0u16;
            for _ in 0..16_000 {
                let frame = samples.frame(hz, 1000);
                let sample = i16::from_le_bytes([frame[0], frame[1]]);
                if previous <= 0 && sample > 0 {
                    crossings += 1;
                }
                previous = sample;
            }
            assert!(crossings.abs_diff(hz) <= 1, "{hz}: {crossings}");
        }
    }
    #[test]
    fn samples_are_stereo_bounded_and_ramped() {
        let mut s = ToneSamples::default();
        let mut peak = 0;
        for i in 0..2400 {
            let f = s.frame(2600, i);
            assert_eq!(&f[..2], &f[2..]);
            let v = i16::from_le_bytes([f[0], f[1]]).unsigned_abs();
            peak = peak.max(v);
            assert!(v <= 8192);
            if i == 0 || i == 2399 {
                assert_eq!(v, 0);
            }
        }
        assert!(peak > 8000);
        assert_eq!(s.frame(0, 100), [0; 4]);
    }
}
