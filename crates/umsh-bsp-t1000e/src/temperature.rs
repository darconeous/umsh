//! T1000-E NTC on P0.31/AIN7. The power task owns its ADC and shared enables.
//!
//! Divider: NTC above the sense node, 8.25 kΩ below it. Resistance data and
//! the min(VBAT, 3.3 V) supply model come from MeshCore's T1000-E driver:
//! https://github.com/meshcore-dev/MeshCore/blob/main/variants/t1000-e/t1000e_sensors.cpp
//! The supply model is an estimate, particularly near regulator dropout.

// Resistance in ohms at each whole degree Celsius from -30 through 105.
const OHMS: [u32; 136] = [
    113347, 107565, 102116, 96978, 92132, 87559, 83242, 79166, 75316, 71677, 68237, 64991, 61919,
    59011, 56258, 53650, 51178, 48835, 46613, 44506, 42506, 40600, 38791, 37073, 35442, 33892,
    32420, 31020, 29689, 28423, 27219, 26076, 24988, 23951, 22963, 22021, 21123, 20267, 19450,
    18670, 17926, 17214, 16534, 15886, 15266, 14674, 14108, 13566, 13049, 12554, 12081, 11628,
    11195, 10780, 10382, 10000, 9634, 9284, 8947, 8624, 8315, 8018, 7734, 7461, 7199, 6948, 6707,
    6475, 6253, 6039, 5834, 5636, 5445, 5262, 5086, 4917, 4754, 4597, 4446, 4301, 4161, 4026, 3896,
    3771, 3651, 3535, 3423, 3315, 3211, 3111, 3014, 2922, 2834, 2748, 2666, 2586, 2509, 2435, 2364,
    2294, 2228, 2163, 2100, 2040, 1981, 1925, 1870, 1817, 1766, 1716, 1669, 1622, 1578, 1535, 1493,
    1452, 1413, 1375, 1338, 1303, 1268, 1234, 1202, 1170, 1139, 1110, 1081, 1053, 1026, 999, 974,
    949, 925, 902, 880, 858,
];

/// Convert a fresh 14-bit SAADC sample (3.6 V full scale) and VBAT in mV
/// to tenths of a kelvin. Open/short circuits and values beyond the table
/// are unavailable, never clamped into plausible endpoint temperatures.
pub fn from_adc(raw: i16, battery_mv: u16) -> Option<u16> {
    if raw <= 0 || raw >= 16384 || !(2000..=5000).contains(&battery_mv) {
        return None;
    }
    let node = u64::from(raw as u16) * 3600;
    let supply = u64::from(battery_mv.min(3300)) * 16384;
    if node >= supply {
        return None;
    }
    from_resistance(8250 * (supply - node), node)
}

// Keep the resistance as a fraction to avoid rounding it before interpolation.
fn from_resistance(numerator: u64, denominator: u64) -> Option<u16> {
    if numerator > u64::from(OHMS[0]) * denominator
        || numerator < u64::from(OHMS[135]) * denominator
    {
        return None;
    }
    for (index, pair) in OHMS.windows(2).enumerate() {
        let cold = u64::from(pair[0]) * denominator;
        let hot = u64::from(pair[1]) * denominator;
        if numerator >= hot {
            // 243.15 K at index zero. Round only the final 0.1 K value.
            let span = cold - hot;
            let twice_tenths = (4863 + index as u64 * 20) * span + 20 * (cold - numerator);
            return Some(((twice_tenths + span) / (2 * span)) as u16);
        }
    }
    None
}

#[cfg(target_os = "none")]
mod sampling {
    use core::sync::atomic::{AtomicU32, Ordering};
    use embassy_sync::{blocking_mutex::raw::ThreadModeRawMutex, signal::Signal};

    pub(crate) static REQUEST: Signal<ThreadModeRawMutex, u32> = Signal::new();
    pub(crate) static REPLY: Signal<ThreadModeRawMutex, (u32, Option<u16>)> = Signal::new();
    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// One caller at a time. Canceling the wait does not cancel ADC work;
    /// sequence numbers prevent its late reply satisfying the next request.
    pub async fn sample() -> Option<u16> {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        REPLY.reset();
        REQUEST.signal(id);
        embassy_time::with_timeout(embassy_time::Duration::from_secs(2), async {
            loop {
                let (reply_id, value) = REPLY.wait().await;
                if reply_id == id {
                    return value;
                }
            }
        })
        .await
        .ok()
        .flatten()
    }
}
#[cfg(target_os = "none")]
pub use sampling::sample;
#[cfg(target_os = "none")]
pub(crate) use sampling::{REPLY, REQUEST};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temperature_table_endpoints_and_every_knot() {
        for (i, ohms) in OHMS.iter().enumerate() {
            assert_eq!(
                from_resistance(u64::from(*ohms), 1),
                Some(2432 + i as u16 * 10)
            );
        }
        assert_eq!(from_resistance(113348, 1), None);
        assert_eq!(from_resistance(857, 1), None);
        // Halfway between 25 and 26 C, including the Kelvin offset.
        assert_eq!(from_resistance(19634, 2), Some(2987));
    }

    #[test]
    fn temperature_adc_supply_and_faults() {
        assert_eq!(from_adc(6790, 4000), Some(2982));
        assert_eq!(from_adc(6173, 3000), Some(2982));
        for raw in [i16::MIN, -1, 0, 1, 15018, 16383, 16384, i16::MAX] {
            assert_eq!(from_adc(raw, 4000), None, "raw {raw}");
        }
        assert_eq!(from_adc(6789, 0), None);
        assert_eq!(from_adc(6789, 6000), None);
    }
}
