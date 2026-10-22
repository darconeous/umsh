//! The models devices name themselves by, as assigned in
//! `docs/hardware/boards.json` and, for hosts with no fixed radio hardware,
//! `docs/hardware/platforms.json`, and what the interface calls each.

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

pub const IPHONE: u16 = 0xFE00;
pub const IPAD: u16 = 0xFE01;
pub const ANDROID_PHONE: u16 = 0xFE02;
pub const ANDROID_TABLET: u16 = 0xFE03;
pub const MAC: u16 = 0xFE04;
pub const COMPUTER: u16 = 0xFE05;

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
        IPHONE => "iPhone",
        IPAD => "iPad",
        ANDROID_PHONE => "Android phone",
        ANDROID_TABLET => "Android tablet",
        MAC => "Mac",
        COMPUTER => "Computer",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// The `model_id`s a list assigns.
    fn assigned(json: &str) -> std::vec::Vec<u16> {
        json.match_indices("\"model_id\"")
            .map(|(at, _)| {
                let rest = &json[at + "\"model_id\"".len()..];
                let digits: std::string::String = rest
                    .trim_start_matches([':', ' '])
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                digits.parse::<u16>().unwrap()
            })
            .collect()
    }

    /// Every model `boards.json` and `platforms.json` assign is named here,
    /// and nothing else.
    #[test]
    fn every_assigned_model_has_a_name() {
        let boards = assigned(include_str!("../../../docs/hardware/boards.json"));
        let platforms = assigned(include_str!("../../../docs/hardware/platforms.json"));
        assert!(!boards.is_empty() && !platforms.is_empty());
        assert!(boards.iter().all(|model| (0x0001..=0xFDFF).contains(model)));
        assert!(
            platforms
                .iter()
                .all(|model| (0xFE00..=0xFEFF).contains(model))
        );
        for model in boards.iter().chain(&platforms) {
            assert!(name(*model).is_some(), "model {model} has no name");
        }
        for model in 0..=u16::MAX {
            if name(model).is_some() {
                assert!(
                    boards.contains(&model) || platforms.contains(&model),
                    "model {model} is assigned nowhere"
                );
            }
        }
    }
}
