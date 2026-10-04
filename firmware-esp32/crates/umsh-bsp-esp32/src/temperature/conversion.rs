//! ESP32-S3 transfer function and eFuse correction, independent of hardware.
//! Constants: ESP-IDF v5.4.2 `hal/esp32s3/include/hal/temperature_sensor_ll.h`
//! and `soc/esp32s3/temperature_sensor_periph.c`.

pub(super) struct Range {
    pub dac: u8,
    offset: i32,
    min_c: i32,
    max_c: i32,
}

// Try the most accurate range first, then progressively wider ranges.
pub(super) const RANGES: [Range; 5] = [
    Range {
        dac: 15,
        offset: 0,
        min_c: -10,
        max_c: 80,
    },
    Range {
        dac: 7,
        offset: -1,
        min_c: 20,
        max_c: 100,
    },
    Range {
        dac: 11,
        offset: 1,
        min_c: -30,
        max_c: 50,
    },
    Range {
        dac: 5,
        offset: -2,
        min_c: 50,
        max_c: 125,
    },
    Range {
        dac: 10,
        offset: 2,
        min_c: -40,
        max_c: 20,
    },
];

/// eFuse uses a nine-bit sign/magnitude correction in tenths of a degree C.
/// Unknown calibration versions use the nominal transfer function, as in IDF.
pub(super) fn correction(major_version: u8, bits: u16) -> i32 {
    if major_version != 1 {
        return 0;
    }
    let magnitude = i32::from(bits & 0xff);
    if bits & 0x100 != 0 {
        -magnitude
    } else {
        magnitude
    }
}

impl Range {
    /// Return tenths of a kelvin, rounding once after calibration. Out-of-range
    /// acquisitions are invalid; another hardware range must be sampled.
    pub fn decode(&self, raw: u8, correction: i32) -> Option<u16> {
        // Fixed point in 1/10000 C keeps the vendor's full transfer function.
        let c = i32::from(raw) * 4386 - self.offset * 278800 - 205200 - correction * 1000;
        if c < self.min_c * 10000 || c > self.max_c * 10000 {
            return None;
        }
        Some(((c + 2731500 + 500) / 1000) as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nominal_kelvin_and_negative_celsius() {
        assert_eq!(RANGES[0].decode(104, 0), Some(2982)); // 25.0944 C
        assert_eq!(RANGES[0].decode(30, 0), Some(2658)); // -7.362 C
        assert_eq!(RANGES[0].decode(0, 0), None);
        assert_eq!(RANGES[0].decode(255, 0), None);
    }

    #[test]
    fn factory_correction_is_signed_tenths_and_subtracted() {
        assert_eq!(correction(1, 23), 23);
        assert_eq!(correction(1, 0x100 | 23), -23);
        assert_eq!(correction(0, 23), 0);
        assert_eq!(correction(2, 23), 0);
        assert_eq!(RANGES[0].decode(104, correction(1, 23)), Some(2959));
        assert_eq!(RANGES[0].decode(104, correction(1, 0x117)), Some(3005));
    }

    #[test]
    fn alternate_ranges_cover_hot_and_cold_measurements() {
        assert_eq!(RANGES[3].decode(204, 0), Some(3979)); // 124.7144 C
        assert_eq!(RANGES[4].decode(83, 0), Some(2333)); // -39.8762 C
        assert_eq!(RANGES[3].decode(255, 0), None);
        assert_eq!(RANGES[4].decode(0, 0), None);
        // All accepted values are numeric ULCP words, never the sentinel.
        for range in RANGES.iter() {
            for raw in 0..=255 {
                if let Some(value) = range.decode(raw, 0) {
                    assert!((2332..=3982).contains(&value));
                }
            }
        }
    }
}
