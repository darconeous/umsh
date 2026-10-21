//! The hardware models devices name themselves by, as assigned in
//! `docs/hardware/boards.json`, and what the interface calls each.

pub const LILYGO_T_ECHO: u16 = 1;
pub const SEEED_SENSECAP_T1000_E: u16 = 2;
pub const SEEED_SENSECAP_SOLAR_P1: u16 = 3;
pub const SEEED_WIO_TRACKER_L1: u16 = 4;
pub const SEEED_XIAO_NRF52840_KIT: u16 = 5;
pub const HELTEC_LORA32_V2: u16 = 6;
pub const HELTEC_LORA32_V3: u16 = 7;
pub const LILYGO_T_BEAM_SUPREME: u16 = 8;
pub const LILYGO_T_LORA_PAGER: u16 = 9;
pub const SEEED_XIAO_ESP32S3_KIT: u16 = 10;
pub const LILYGO_T_DECK: u16 = 11;

/// What the interface calls `model`, or `None` for one it does not know.
#[must_use]
pub const fn name(model: u16) -> Option<&'static str> {
    Some(match model {
        LILYGO_T_ECHO => "T-Echo",
        SEEED_SENSECAP_T1000_E => "T1000-E",
        SEEED_SENSECAP_SOLAR_P1 => "Solar P1",
        SEEED_WIO_TRACKER_L1 => "Wio Tracker L1",
        SEEED_XIAO_NRF52840_KIT => "XIAO nRF52840",
        HELTEC_LORA32_V2 => "Heltec V2",
        HELTEC_LORA32_V3 => "Heltec V3",
        LILYGO_T_BEAM_SUPREME => "T-Beam Supreme",
        LILYGO_T_LORA_PAGER => "T-LoRa Pager",
        SEEED_XIAO_ESP32S3_KIT => "XIAO ESP32S3",
        LILYGO_T_DECK => "T-Deck",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// Every model `boards.json` assigns is named here, and nothing else.
    #[test]
    fn every_model_in_boards_json_has_a_name() {
        let json = include_str!("../../../docs/hardware/boards.json");
        let mut assigned = std::vec::Vec::new();
        for (at, _) in json.match_indices("\"model_id\"") {
            let rest = &json[at + "\"model_id\"".len()..];
            let digits: std::string::String = rest
                .trim_start_matches([':', ' '])
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            assigned.push(digits.parse::<u16>().unwrap());
        }
        assert!(!assigned.is_empty());
        for model in &assigned {
            assert!(name(*model).is_some(), "model {model} has no name");
        }
        for model in 0..=u16::from(u8::MAX) {
            if name(model).is_some() {
                assert!(
                    assigned.contains(&model),
                    "model {model} is not in boards.json"
                );
            }
        }
    }
}
