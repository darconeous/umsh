//! [`T1000EPlatform`] — the concrete `umsh_mac::Platform` bundle for the
//! Seeed Studio SenseCAP T1000-E.
//!
//! Composes the chip-level nRF52840 plumbing from [`umsh_bsp_nrf52840`]
//! (clock, hardware RNG, NVMC-backed counter and key-value stores) with
//! software AES / SHA / Ed25519 from [`umsh_crypto`] and the
//! channel-based radio handle from [`umsh_radio_loraphy`]. The T1000-E
//! carries an LR1110 LoRa chip; the `LoraphyRadio` wrapper is
//! chip-agnostic — the actual chip driver is owned by the firmware's
//! radio runner task.

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_time::Delay;

use umsh_bsp_nrf52840::flash_store::{NvmcCounterStore, NvmcKeyValueStore};
use umsh_bsp_nrf52840::{EmbassyClock, Nrf52840Rng};
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_mac::Platform;

/// Concrete [`Platform`] bundle for the T1000-E.
///
/// Use it as `Mac<T1000EPlatform, ...>`. The BSP also re-exports the
/// default-capacity [`T1000EMac`] alias; firmwares that want
/// non-default `Host` / `LocalNode` capacities define their own.
pub struct T1000EPlatform;

impl Platform for T1000EPlatform {
    type Identity      = SoftwareIdentity;
    type Aes           = SoftwareAes;
    type Sha           = SoftwareSha256;
    type Radio         = umsh_radio_loraphy::LoraphyRadio<ThreadModeRawMutex, 4, 2>;
    type Delay         = Delay;
    type Clock         = EmbassyClock;
    type Rng           = Nrf52840Rng;
    type CounterStore  = NvmcCounterStore;
    type KeyValueStore = NvmcKeyValueStore;
}

/// Default-capacity MAC coordinator for the T1000-E firmware:
/// 2 identities (1 long-term + 1 PFS ephemeral session), 8 peers, 4 channels,
/// 4 pending ACKs, 8 TX queue slots, 255-byte frame buffer, 32-entry dup cache.
pub type T1000EMac = umsh_mac::Mac<T1000EPlatform, 2, 8, 4, 4, 8, 255, 32>;
