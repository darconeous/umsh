//! Bluetooth as an image built without it sees it: the functions the
//! rest of the firmware calls in `ble.rs`, on a transport that is not
//! there.
//!
//! Nothing here is reachable from a host. The session advertises no
//! Bluetooth capability in such an image and answers the transport's
//! properties as unknown before any of these hooks would run, and the
//! menu carries no Bluetooth entries. The functions exist so the shared
//! code that calls them needs no feature gates of its own.

use umsh_ulcp_runtime::driver;
use umsh_ux_display_tracker::screen;

/// What the panel shows of this transport: nothing.
pub(crate) struct Panel {
    pub enabled: Option<bool>,
    pub link: screen::LinkState,
    pub bonds: u8,
    pub pairing: screen::PairingState,
}

pub(crate) fn panel() -> Panel {
    Panel {
        enabled: None,
        link: screen::LinkState::Disabled,
        bonds: 0,
        pairing: screen::PairingState::Closed,
    }
}

#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
pub(crate) fn pairing_indicated() -> bool {
    false
}

pub(crate) fn pairing_window_open() -> bool {
    false
}

pub(crate) fn request_pairing() {}

pub(crate) fn request_clear_bonds() {}

pub(crate) fn device_name_changed() {}

pub(crate) fn boot_settings_ready() {}

pub(crate) fn set_enabled(_enabled: bool) {}

pub(crate) fn set_advertising_allowed(_allowed: bool) {}

/// No transport, so nothing about it ever changes.
pub(crate) async fn event() -> driver::PublishEvent {
    core::future::pending().await
}

pub(crate) async fn apply_pairing_pin(_pin: Option<u32>) -> bool {
    false
}

pub(crate) async fn clear_bonds(_reply_over_ble: bool) -> bool {
    false
}

pub(crate) async fn set_pairing(_open: bool) -> bool {
    false
}
