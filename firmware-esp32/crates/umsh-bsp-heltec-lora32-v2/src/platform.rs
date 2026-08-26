//! [`HeltecV2Platform`] — the concrete `umsh_mac::Platform` bundle for the
//! Heltec WiFi LoRa 32 V2.
//!
//! Composes the chip-level Espressif plumbing from [`umsh_bsp_esp32`]
//! (the RF-gated hardware RNG and the partition-backed counter and
//! key-value stores) with software AES / SHA / Ed25519 from
//! [`umsh_crypto`] and the channel-based radio handle from
//! [`umsh_radio_loraphy`] (driving the on-board SX1276 LoRa modem).
//!
//! Identical in shape to `umsh_bsp_heltec_lora32_v3::platform` — the
//! radio handle is generic over the `lora_phy` `RadioKind`, so the
//! SX1276/SX1262 difference does not reach this bundle. What does differ
//! is the capacity alias below.
//!
//! ## Construction order
//!
//! [`umsh_bsp_esp32::rng::EspCryptoRng`] only exists while an RF entropy
//! source is live, so the BLE controller must be initialized **before**
//! the MAC is built, and must stay alive for as long as it runs. See that
//! module for why this is enforced rather than documented. On this board
//! that constraint sits next to a second one pulling the other way: ADC2
//! carries the battery divider and `Adc::new` panics once the radio
//! controller has claimed it, so the battery sampler is built first, then
//! the controller, then the MAC.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::Delay;

use umsh_bsp_esp32::flash_store::{EspCounterStore, EspKeyValueStore};
use umsh_bsp_esp32::rng::EspCryptoRng;
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_hal::EmbassyClock;
use umsh_mac::Platform;

/// Concrete [`Platform`] bundle for the Heltec V2.
pub struct HeltecV2Platform;

impl Platform for HeltecV2Platform {
    type Identity = SoftwareIdentity;
    type Aes = SoftwareAes;
    type Sha = SoftwareSha256;
    type Radio = umsh_radio_loraphy::LoraphyRadio<CriticalSectionRawMutex, 4, 2>;
    type Delay = Delay;
    type Clock = EmbassyClock;
    type Rng = EspCryptoRng;
    type CounterStore = EspCounterStore;
    type KeyValueStore = EspKeyValueStore;
}

/// MAC coordinator for the Heltec V2: 2 identities (1 long-term + 1 PFS
/// ephemeral session), 8 peers, 4 channels, 4 pending ACKs, 8 TX queue
/// slots, 255-byte frame buffer, 32-entry dup cache.
///
/// Matches the Heltec V3's capacities so behavior is comparable across
/// the two Espressif boards. The classic ESP32 has substantially less
/// DRAM than the S3, so this alias is the first thing to trim if the
/// image outgrows the budget.
pub type HeltecV2Mac = umsh_mac::Mac<HeltecV2Platform, 2, 8, 4, 4, 8, 255, 32>;
