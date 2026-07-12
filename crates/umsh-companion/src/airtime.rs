//! LoRa airtime estimation.
//!
//! Shared by the host client (worst-case `t_frame_ms` for the MAC
//! scheduler) and the NCP session (duty-cycle accounting for
//! `PROP_PHY_DUTY_NOW`), so both sides account airtime identically.

/// Conservative LoRa on-air time estimate in milliseconds.
///
/// Standard LoRa airtime formula with explicit header, CRC on, and
/// auto-LDRO; the preamble of 8 + 4.25 symbols is approximated as 12.
/// Numeric twin of `umsh_radio_loraphy::airtime_ms` (which takes
/// `lora-modulation` enums), generalized over the coding-rate
/// denominator (`5` for CR 4/5 through `8` for CR 4/8).
///
/// Out-of-range inputs are clamped rather than rejected: this is an
/// estimate for scheduling and duty accounting, not a validator.
pub fn lora_airtime_ms(sf: u8, bw_hz: u32, cr_denom: u8, payload_bytes: usize) -> u32 {
    let sf = u32::from(sf.clamp(5, 12));
    let t_sym_us = (1u64 << sf) * 1_000_000 / u64::from(bw_hz.max(1));

    // LDRO required when t_sym > 16 ms.
    let ldro: i64 = if t_sym_us > 16_000 { 1 } else { 0 };

    let sf = i64::from(sf);
    let payload = payload_bytes as i64;
    let num = (8 * payload - 4 * sf + 44 + 20 - 16 * ldro).max(0);
    let denom = 4 * (sf - 2 * ldro);
    let ceil = (num + denom - 1) / denom;
    let n_payload_sym = 8 + ceil * i64::from(cr_denom.clamp(5, 8));

    let total_sym = 12 + n_payload_sym as u64;
    ((total_sym * t_sym_us) / 1_000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plausible_magnitudes() {
        // ~255-byte frame at SF11/BW250 is on the order of seconds.
        let slow = lora_airtime_ms(11, 250_000, 5, 255);
        assert!((500..5_000).contains(&slow), "airtime {slow}");
        // Faster settings give shorter airtime.
        assert!(lora_airtime_ms(7, 250_000, 5, 255) < slow);
        // Higher coding overhead gives longer airtime.
        assert!(lora_airtime_ms(7, 125_000, 8, 100) > lora_airtime_ms(7, 125_000, 5, 100));
    }

    #[test]
    fn short_frame_nonzero() {
        assert!(lora_airtime_ms(7, 500_000, 5, 1) > 0);
    }
}
