//! [`TBeamSupremePlatform`] — the concrete `umsh_mac::Platform` bundle
//! for the LILYGO T-Beam Supreme.
//!
//! Composes the chip-level Espressif plumbing from [`umsh_bsp_esp32`]
//! (the RF-gated hardware RNG and the partition-backed counter and
//! key-value stores) with software AES / SHA / Ed25519 from
//! [`umsh_crypto`] and the channel-based radio handle from
//! [`umsh_radio_loraphy`] (driving the on-board SX1262 LoRa modem).
//!
//! Identical to the Heltec V3's bundle — the two boards share the chip,
//! the radio, and therefore the whole type surface; what differs between
//! them (power topology, display, GNSS) lives outside the MAC.
//!
//! ## Construction order
//!
//! [`umsh_bsp_esp32::rng::EspCryptoRng`] only exists while an RF entropy
//! source is live, so the BLE controller must be initialized **before**
//! the MAC is built, and must stay alive for as long as it runs. See that
//! module for why this is enforced rather than documented.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::Delay;

use umsh_bsp_esp32::flash_store::{EspCounterStore, EspKeyValueStore};
use umsh_bsp_esp32::rng::EspCryptoRng;
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_hal::EmbassyClock;
use umsh_mac::Platform;

/// Concrete [`Platform`] bundle for the T-Beam Supreme.
pub struct TBeamSupremePlatform;

impl Platform for TBeamSupremePlatform {
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

/// Default-capacity MAC coordinator: 2 identities (1 long-term + 1 PFS
/// ephemeral session), 8 peers, 4 channels, 4 pending ACKs, 8 TX queue
/// slots, 255-byte frame buffer, 32-entry dup cache.
///
/// Matches the T-Echo and Heltec V3 capacities so behavior is comparable
/// across the reference boards.
pub type TBeamSupremeMac = umsh_mac::Mac<TBeamSupremePlatform, 2, 8, 4, 4, 8, 255, 32>;
