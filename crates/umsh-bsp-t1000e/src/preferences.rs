//! T1000-E retained Sleep and Silence preferences.
//!
//! `POWER.GPREGRET2` survives resets and nRF System OFF. The resident
//! bootloader uses `GPREGRET`, not `GPREGRET2`, for DFU selection, so the two
//! lifecycles remain independent. A cold loss of all power resets preferences
//! to Awake + Noisy, which is the safe default.

use embassy_nrf::pac;
use umsh_ux_tracker::state::UserPreferences;

pub fn load() -> UserPreferences {
    UserPreferences::decode(pac::POWER.gpregret2().read().gpregret())
}

pub fn store(preferences: UserPreferences) {
    pac::POWER
        .gpregret2()
        .write(|w| w.set_gpregret(preferences.encode()));
}

pub fn set_asleep(asleep: bool) -> UserPreferences {
    critical_section::with(|_| {
        let mut preferences = load();
        preferences.asleep = asleep;
        store(preferences);
        preferences
    })
}

pub fn set_silent(silent: bool) -> UserPreferences {
    critical_section::with(|_| {
        let mut preferences = load();
        preferences.silent = silent;
        store(preferences);
        preferences
    })
}

pub fn toggle_silent() -> UserPreferences {
    critical_section::with(|_| {
        let mut preferences = load();
        preferences.silent = !preferences.silent;
        store(preferences);
        preferences
    })
}

pub fn set_battery_critical(battery_critical: bool) -> UserPreferences {
    critical_section::with(|_| {
        let mut preferences = load();
        preferences.battery_critical = battery_critical;
        store(preferences);
        preferences
    })
}
