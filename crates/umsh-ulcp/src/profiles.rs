//! Vetted LoRa PHY profiles.
//!
//! The one table every shipped preset comes from: firmware factory
//! defaults, host tools, the web debugger, and the iOS app through
//! `umsh-mobile-core`. Tests and examples spell out their own PHY
//! literals instead of reaching for this table, so editing an entry
//! here never silently rewrites a test.
//!
//! The MeshCore entries mirror that project's published suggested
//! settings, <https://api.meshcore.nz/api/v1/config>
//! (`config.suggested_radio_settings.entries`), read 2026-08-26. The
//! two entries MeshCore marks deprecated are left out, as is its
//! `path_hash_size`, which has no UMSH meaning.

use crate::ids::DUTY_LIMIT_DISABLED;

/// A vetted PHY profile: the four parameters two nodes must agree on to
/// hear each other, plus the local settings vetted alongside them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhyProfile {
    /// Stable identifier. `meshcore-` plus an ISO 3166-1 alpha-2
    /// country code, or `eu` where the profile spans the union.
    pub id: &'static str,
    /// Display name, as an operator picking a profile sees it.
    pub name: &'static str,
    /// Center frequency in kHz (`PROP_PHY_FREQ`).
    pub freq_khz: u32,
    /// LoRa bandwidth in Hz (`PROP_PHY_LORA_BW`).
    pub bw_hz: u32,
    /// LoRa spreading factor (`PROP_PHY_LORA_SF`).
    pub sf: u8,
    /// Coding-rate denominator, 5 for 4/5 through 8 for 4/8
    /// (`PROP_PHY_LORA_CR`).
    pub cr_denom: u8,
    /// Transmit power vetted for this profile's band and occupied
    /// bandwidth. `None` where no power has been vetted, in which case
    /// adopting the profile leaves a device's configured power alone.
    pub tx_power_dbm: Option<i8>,
    /// Duty-cycle limit in `PROP_PHY_DUTY_LIMIT` units.
    pub duty_limit: u16,
    /// SX126x-style 16-bit sync word (`PROP_PHY_LORA_SW`).
    pub sync_word: u16,
    /// Preamble symbols to emit on transmit.
    pub tx_preamble_symbols: u16,
}

impl PhyProfile {
    /// Whether a node on this profile and one on the given parameters
    /// can hear each other.
    ///
    /// Transmit power and the duty-cycle limit are excluded. Neither
    /// changes what a receiver can decode, and a radio reports power
    /// clamped to what it can actually reach — comparing power would
    /// call two radios on the same profile different merely because one
    /// of them cannot transmit as hard as the other.
    pub const fn interoperates_with(
        &self,
        freq_khz: u32,
        bw_hz: u32,
        sf: u8,
        cr_denom: u8,
    ) -> bool {
        self.freq_khz == freq_khz
            && self.bw_hz == bw_hz
            && self.sf == sf
            && self.cr_denom == cr_denom
    }
}

/// The private-network sync word every vetted profile uses. The spec
/// suggests it in `docs/protocol/src/ulcp-radio.md`, and it is what
/// `enable_public_network = false` selects on an SX126x.
pub const DEFAULT_SYNC_WORD: u16 = 0x1424;

/// The LoRa bandwidths a device accepts for `PROP_PHY_LORA_BW`, in Hz.
pub const SUPPORTED_BANDWIDTHS_HZ: [u32; 10] = [
    7_810, 10_420, 15_630, 20_830, 31_250, 41_670, 62_500, 125_000, 250_000, 500_000,
];

/// Preamble symbols MeshCore nodes transmit at SF7-SF8 since v1.16.
/// Receivers detect after a shorter minimum, so this figure constrains
/// transmit only.
const MESHCORE_TX_PREAMBLE: u16 = 32;

/// Roughly 10% of the hour, for the European 869.4-869.65 MHz sub-band
/// where that ceiling is a condition of use.
const DUTY_10_PERCENT: u16 = 6_553;

/// The profile firmware ships on and the app recommends.
const MESHCORE_US_CA: PhyProfile = PhyProfile {
    id: "meshcore-us-ca",
    name: "MeshCore USA/Canada (recommended)",
    freq_khz: 910_525,
    bw_hz: 62_500,
    sf: 7,
    cr_denom: 5,
    // Vetted for this profile's band at this occupied bandwidth. Other
    // profiles carry their own figure or none; there is no rule here to
    // extrapolate from.
    tx_power_dbm: Some(21),
    duty_limit: DUTY_LIMIT_DISABLED,
    sync_word: DEFAULT_SYNC_WORD,
    tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
};

/// Every vetted profile, in the order an operator is offered them: the
/// default first, then the rest as MeshCore publishes them.
pub const VETTED: &[PhyProfile] = &[
    MESHCORE_US_CA,
    PhyProfile {
        id: "meshcore-au",
        name: "MeshCore Australia",
        freq_khz: 915_800,
        bw_hz: 250_000,
        sf: 10,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-au-narrow",
        name: "MeshCore Australia (narrow)",
        freq_khz: 916_575,
        bw_hz: 62_500,
        sf: 7,
        cr_denom: 8,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-au-mid",
        name: "MeshCore Australia (mid)",
        freq_khz: 915_075,
        bw_hz: 125_000,
        sf: 9,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-au-sa-wa",
        name: "MeshCore Australia: SA, WA",
        freq_khz: 923_125,
        bw_hz: 62_500,
        sf: 8,
        cr_denom: 8,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-au-qld",
        name: "MeshCore Australia: QLD",
        freq_khz: 923_125,
        bw_hz: 62_500,
        sf: 8,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-br",
        name: "MeshCore Brazil",
        freq_khz: 923_125,
        bw_hz: 62_500,
        sf: 8,
        cr_denom: 8,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-cr",
        name: "MeshCore Costa Rica",
        freq_khz: 910_525,
        bw_hz: 125_000,
        sf: 11,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-eu-narrow",
        name: "MeshCore EU/UK (narrow)",
        freq_khz: 869_618,
        bw_hz: 62_500,
        sf: 8,
        cr_denom: 8,
        tx_power_dbm: None,
        duty_limit: DUTY_10_PERCENT,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-cz-narrow",
        name: "MeshCore Czech Republic (narrow)",
        freq_khz: 869_432,
        bw_hz: 62_500,
        sf: 7,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_10_PERCENT,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-eu-433-long-range",
        name: "MeshCore EU 433 MHz (long range)",
        freq_khz: 433_650,
        bw_hz: 250_000,
        sf: 11,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-eu-433-narrow",
        name: "MeshCore EU 433 MHz (narrow)",
        freq_khz: 433_650,
        bw_hz: 62_500,
        sf: 8,
        cr_denom: 8,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-hu",
        name: "MeshCore Hungary",
        freq_khz: 869_618,
        bw_hz: 62_500,
        sf: 7,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_10_PERCENT,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-nl",
        name: "MeshCore Netherlands",
        freq_khz: 869_618,
        bw_hz: 62_500,
        sf: 7,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_10_PERCENT,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-nz-narrow",
        name: "MeshCore New Zealand (narrow)",
        freq_khz: 917_375,
        bw_hz: 62_500,
        sf: 7,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-nz-gisborne",
        name: "MeshCore New Zealand (Gisborne)",
        freq_khz: 917_375,
        bw_hz: 250_000,
        sf: 11,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-pt-433",
        name: "MeshCore Portugal 433",
        freq_khz: 433_375,
        bw_hz: 62_500,
        sf: 9,
        cr_denom: 6,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-pt-868",
        name: "MeshCore Portugal 868",
        freq_khz: 869_618,
        bw_hz: 62_500,
        sf: 7,
        cr_denom: 6,
        tx_power_dbm: None,
        duty_limit: DUTY_10_PERCENT,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-sk",
        name: "MeshCore Slovakia",
        freq_khz: 869_618,
        bw_hz: 62_500,
        sf: 7,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_10_PERCENT,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-ch",
        name: "MeshCore Switzerland",
        freq_khz: 869_618,
        bw_hz: 62_500,
        sf: 8,
        cr_denom: 8,
        tx_power_dbm: None,
        duty_limit: DUTY_10_PERCENT,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
    PhyProfile {
        id: "meshcore-vn-narrow",
        name: "MeshCore Vietnam (narrow)",
        freq_khz: 920_250,
        bw_hz: 62_500,
        sf: 8,
        cr_denom: 5,
        tx_power_dbm: None,
        duty_limit: DUTY_LIMIT_DISABLED,
        sync_word: DEFAULT_SYNC_WORD,
        tx_preamble_symbols: MESHCORE_TX_PREAMBLE,
    },
];

/// The profile a device comes up on out of the box, and after a factory
/// reset.
pub const DEFAULT: &PhyProfile = &MESHCORE_US_CA;

/// `DEFAULT`'s vetted transmit power, for the firmware defaults that
/// need a plain value. A default profile without one fails the build.
pub const DEFAULT_TX_POWER_DBM: i8 = match DEFAULT.tx_power_dbm {
    Some(power) => power,
    None => panic!("the default profile must carry a vetted transmit power"),
};

/// The profile with the given identifier.
pub fn by_id(id: &str) -> Option<&'static PhyProfile> {
    VETTED.iter().find(|profile| profile.id == id)
}

/// The vetted profile the given parameters spell out, if any.
pub fn matching(freq_khz: u32, bw_hz: u32, sf: u8, cr_denom: u8) -> Option<&'static PhyProfile> {
    VETTED
        .iter()
        .find(|profile| profile.interoperates_with(freq_khz, bw_hz, sf, cr_denom))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_unique_and_well_formed() {
        for (index, profile) in VETTED.iter().enumerate() {
            assert!(
                profile
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
                "{} is not kebab-case",
                profile.id
            );
            assert!(!profile.name.is_empty(), "{} has no name", profile.id);
            for other in &VETTED[index + 1..] {
                assert_ne!(profile.id, other.id, "duplicate identifier");
            }
        }
    }

    #[test]
    fn parameters_are_settable_on_a_device() {
        for profile in VETTED {
            assert!(
                SUPPORTED_BANDWIDTHS_HZ.contains(&profile.bw_hz),
                "{} has an unsupported bandwidth",
                profile.id
            );
            assert!(
                (5..=12).contains(&profile.sf),
                "{} has a bad SF",
                profile.id
            );
            assert!(
                (5..=8).contains(&profile.cr_denom),
                "{} has a bad coding rate",
                profile.id
            );
            // The narrowest tunable range of any radio UMSH ships on.
            assert!(
                (150_000..=960_000).contains(&profile.freq_khz),
                "{} is outside every shipped radio's range",
                profile.id
            );
            assert_eq!(profile.sync_word, DEFAULT_SYNC_WORD, "{}", profile.id);
            assert_eq!(
                profile.tx_preamble_symbols, MESHCORE_TX_PREAMBLE,
                "{}",
                profile.id
            );
        }
    }

    #[test]
    fn european_sub_band_profiles_carry_its_duty_ceiling() {
        for profile in VETTED {
            let in_sub_band = (869_400..=869_650).contains(&profile.freq_khz);
            let expected = if in_sub_band {
                DUTY_10_PERCENT
            } else {
                DUTY_LIMIT_DISABLED
            };
            assert_eq!(profile.duty_limit, expected, "{}", profile.id);
        }
    }

    #[test]
    fn the_default_is_vetted_and_carries_a_power() {
        assert_eq!(DEFAULT.id, "meshcore-us-ca");
        assert!(VETTED.contains(DEFAULT));
        assert_eq!(DEFAULT_TX_POWER_DBM, 21);
        assert_eq!(by_id("meshcore-us-ca"), Some(DEFAULT));
        assert_eq!(by_id("nonesuch"), None);
    }

    #[test]
    fn interop_ignores_local_settings() {
        let profile = DEFAULT;
        assert!(profile.interoperates_with(910_525, 62_500, 7, 5));
        assert!(!profile.interoperates_with(915_000, 62_500, 7, 5));
        assert!(!profile.interoperates_with(910_525, 125_000, 7, 5));
        assert_eq!(matching(910_525, 62_500, 7, 5), Some(DEFAULT));
        assert_eq!(matching(902_000, 62_500, 7, 5), None);
    }
}
