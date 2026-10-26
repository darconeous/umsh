//! How loud a volume setting plays.

/// The loudest volume, and the one that plays sounds as they are made.
pub const MAX_VOLUME: u8 = 255;

/// Gains in steps of 1 dB from −36 dB to +12 dB, out of 4096.
const GAIN: [u16; 49] = [
    65, 73, 82, 92, 103, 115, 130, 145, 163, 183, 205, 230, 258, 290, 325, 365, 410, 460, 516, 579,
    649, 728, 817, 917, 1029, 1154, 1295, 1453, 1631, 1830, 2053, 2303, 2584, 2900, 3254, 3651,
    4096, 4596, 5157, 5786, 6492, 7284, 8173, 9170, 10289, 11544, 12953, 14533, 16306,
];

/// The multiplier `volume` applies, out of 4096: 48 dB from the quietest
/// to the loudest, even in decibels. The loudest takes the tones, which
/// are made about 12 dB below full scale, to full scale; the device's
/// default leaves them as they are made.
#[must_use]
pub fn scale(volume: u8) -> i32 {
    let step = (u32::from(volume) * 48 + 127) / u32::from(MAX_VOLUME);
    i32::from(GAIN[step as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_runs_48_db_and_never_reaches_silence() {
        assert_eq!(scale(0), 65);
        assert_eq!(scale(MAX_VOLUME), 16306);
        assert!((1..=255).all(|v| scale(v) >= scale(v - 1)));
    }

    #[test]
    fn the_default_volume_plays_tones_as_they_are_made() {
        // `DEFAULT_SOUND_VOLUME`, as the device session keeps it after a
        // reset.
        assert_eq!(scale(191), 4096);
    }

    #[test]
    fn the_loudest_tone_stays_within_full_scale() {
        assert!(8192 * scale(MAX_VOLUME) / 4096 <= i32::from(i16::MAX));
    }
}
