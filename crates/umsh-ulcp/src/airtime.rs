//! LoRa airtime estimation.
//!
//! Shared by the host client (worst-case `t_frame_ms` for the MAC
//! scheduler) and the ULCP session (duty-cycle accounting for
//! `PROP_PHY_DUTY_NOW`), so both sides account airtime identically.

/// LoRa on-air time of one frame with an explicit header and CRC, in
/// milliseconds, rounded up.
///
/// This is Semtech's time-on-air formula. Symbols last `2^SF / BW`, and
/// the payload takes
/// `8 + ceil(max(8·PL − 4·SF + 44, 0) / (4·(SF − 2·DE))) · CR` of them,
/// where `DE` is low-data-rate optimization. The preamble adds
/// `preamble_symbols + 4.25`. SF5 and SF6, which only the SX126x and
/// LR11xx families have, carry 8 fewer bits of header overhead and take
/// 6.25 symbols past the preamble instead.
///
/// The coding rate is given by its denominator (`5` for CR 4/5 through `8`
/// for CR 4/8). Low-data-rate optimization is assumed for symbols longer
/// than 16 ms, which is conservative for drivers that enable it for only
/// some of those configurations. Out-of-range inputs are clamped rather
/// than rejected: this is an estimate for scheduling and duty accounting,
/// not a validator.
pub fn lora_airtime_ms_with_preamble(
    sf: u8,
    bw_hz: u32,
    cr_denom: u8,
    payload_bytes: usize,
    preamble_symbols: u16,
) -> u32 {
    let sf = u64::from(sf.clamp(5, 12));
    let bw = u64::from(bw_hz.max(1));
    let ldro = u64::from((1u64 << sf) * 1_000 > 16 * bw);
    // Header and CRC bits, and the quarter symbols past the preamble.
    let (overhead_bits, sync_quarters) = if sf < 7 { (36, 25) } else { (44, 17) };
    let numerator = (8 * payload_bytes as u64 + overhead_bits).saturating_sub(4 * sf);
    let payload_symbols =
        8 + numerator.div_ceil(4 * (sf - 2 * ldro)) * u64::from(cr_denom.clamp(5, 8));
    let quarter_symbols = 4 * (u64::from(preamble_symbols) + payload_symbols) + sync_quarters;
    (quarter_symbols * (1u64 << sf) * 1_000).div_ceil(4 * bw) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_duration_includes_preamble_and_rounds_up() {
        // Standard explicit-header/CRC airtimes: 56.576 ms and 623.104 ms.
        assert_eq!(lora_airtime_ms_with_preamble(7, 125_000, 5, 20, 8), 57);
        assert_eq!(lora_airtime_ms_with_preamble(10, 500_000, 5, 255, 32), 624);
        // SF12/BW125 requires low-data-rate optimization: 9,019.392 ms.
        assert_eq!(lora_airtime_ms_with_preamble(12, 125_000, 5, 255, 8), 9020);
    }

    #[test]
    fn sf5_and_sf6_use_their_own_header_and_sync() {
        // SX126x datasheet: 8 + 6.25 + 8 + 9·5 = 67.25 symbols of 256 µs,
        // 17.216 ms.
        assert_eq!(lora_airtime_ms_with_preamble(5, 125_000, 5, 20, 8), 18);
        // 8 + 6.25 + 8 + 8·5 = 62.25 symbols of 512 µs, 31.872 ms.
        assert_eq!(lora_airtime_ms_with_preamble(6, 125_000, 5, 20, 8), 32);
    }

    #[test]
    fn plausible_magnitudes() {
        // ~255-byte frame at SF11/BW250 is on the order of seconds.
        let slow = lora_airtime_ms_with_preamble(11, 250_000, 5, 255, 32);
        assert!((500..5_000).contains(&slow), "airtime {slow}");
        // Faster settings give shorter airtime.
        assert!(lora_airtime_ms_with_preamble(7, 250_000, 5, 255, 32) < slow);
        // Higher coding overhead gives longer airtime.
        assert!(
            lora_airtime_ms_with_preamble(7, 125_000, 8, 100, 32)
                > lora_airtime_ms_with_preamble(7, 125_000, 5, 100, 32)
        );
    }

    #[test]
    fn short_frame_nonzero() {
        assert!(lora_airtime_ms_with_preamble(7, 500_000, 5, 1, 8) > 0);
    }
}
