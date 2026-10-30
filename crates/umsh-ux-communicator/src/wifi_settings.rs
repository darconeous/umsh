//! Device › Wi-Fi: the switch, the network in use, the saved and nearby
//! networks, a network's sheet, a password being typed, and a network that
//! hides its name.
//!
//! Saved networks join by themselves; the screen only says what the device
//! is doing and changes what it keeps. A password is typed in the clear and
//! never shown again.

use buoyant::focus::FocusState;
use buoyant::view::EditBuffer;
use heapless::String;

use crate::model::{Ssid, State, WifiSecurity};
use crate::nav::{DevicePage, Screen, keys};

/// The longest passphrase, in octets.
pub const PASSWORD_MAX: usize = 63;
/// The shortest WPA passphrase, in octets.
pub const PASSWORD_MIN: usize = 8;

/// A password as it is typed. Never formatted.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordText(pub EditBuffer<String<PASSWORD_MAX>>);

impl PasswordText {
    #[must_use]
    pub const fn new() -> Self {
        Self(EditBuffer::new())
    }

    /// Whether it is a passphrase a network could take.
    #[must_use]
    pub fn valid(&self) -> bool {
        (PASSWORD_MIN..=PASSWORD_MAX).contains(&self.0.text().len())
    }
}

impl Default for PasswordText {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for PasswordText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PasswordText(..)")
    }
}

/// A network's name, as it is typed into Other network.
pub type NetworkText = EditBuffer<String<32>>;

/// A screen under Device › Wi-Fi.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WifiPage {
    Main,
    /// A network's sheet; while `confirm`, Forget asks to be confirmed.
    Sheet {
        ssid: Ssid,
        confirm: bool,
    },
    /// A password for `ssid`: to join it, or with `change`, a saved one's
    /// new one.
    Password {
        ssid: Ssid,
        security: WifiSecurity,
        change: bool,
        text: PasswordText,
    },
    /// A network that hides its name; while `choosing`, its security's
    /// choices are open.
    Other {
        name: NetworkText,
        security: WifiSecurity,
        password: PasswordText,
        choosing: bool,
    },
}

/// The security a network that hides its name can be joined with.
pub const OTHER_SECURITY: [WifiSecurity; 3] =
    [WifiSecurity::Open, WifiSecurity::Wpa2, WifiSecurity::Wpa3];

/// `ssid` as text: octets that are not UTF-8 read as `?`. Never longer
/// than the SSID, so it always fits.
#[must_use]
pub fn ssid_text(ssid: &[u8]) -> String<32> {
    let mut text = String::new();
    for chunk in ssid.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c.is_control() || text.push(c).is_err() {
                _ = text.push('?');
            }
        }
        if !chunk.invalid().is_empty() {
            _ = text.push('?');
        }
    }
    text
}

impl State {
    /// Shows Wi-Fi, its switch focused, and looks for networks.
    pub fn open_wifi(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Wifi {
                page: WifiPage::Main,
            },
            focus: FocusState::requesting(keys::WIFI_ENABLED),
        });
        if self.wifi.enabled == Some(true) {
            self.node.scan_wifi();
        }
        self.settle();
        self.refresh_settings();
    }

    /// The Wi-Fi page shown, if one is.
    fn wifi_page(&mut self) -> Option<(&mut WifiPage, &mut FocusState)> {
        match self.screens.last_mut() {
            Some(Screen::Device {
                page: DevicePage::Wifi { page },
                focus,
            }) => Some((page, focus)),
            _ => None,
        }
    }

    fn push_wifi(&mut self, page: WifiPage, focus: buoyant::focus::FocusKey) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Wifi { page },
            focus: FocusState::requesting(focus),
        });
        self.settle();
    }

    pub fn toggle_wifi(&mut self) {
        let Some(on) = self.wifi.enabled else {
            return;
        };
        self.node.set_wifi_enabled(!on);
        self.wifi.enabled = Some(!on);
        if !on {
            self.node.scan_wifi();
        }
    }

    pub fn scan_wifi(&mut self) {
        self.node.scan_wifi();
    }

    pub fn toggle_ip_multicast(&mut self) {
        let Some(on) = self.wifi.ip_multicast else {
            return;
        };
        self.node.set_ip_multicast(!on);
        self.wifi.ip_multicast = Some(!on);
    }

    /// Opens the sheet of the network in use.
    pub fn open_current_wifi(&mut self) {
        let ssid = self.wifi.current.clone();
        self.open_wifi_sheet(ssid);
    }

    /// Opens the sheet of the saved network `index` lists.
    pub fn open_saved_wifi(&mut self, index: usize) {
        if let Some(network) = self.wifi.saved.get(index) {
            let ssid = network.ssid.clone();
            self.open_wifi_sheet(ssid);
        }
    }

    fn open_wifi_sheet(&mut self, ssid: Ssid) {
        if ssid.is_empty() {
            return;
        }
        let failing = self.wifi.current == ssid && self.wifi.status.failing();
        let focus = match (self.wifi.current == ssid, failing) {
            (true, true) => keys::WIFI_CHANGE_PASSWORD,
            (true, false) => keys::WIFI_ACT,
            (false, _) => keys::WIFI_ACT,
        };
        self.push_wifi(
            WifiPage::Sheet {
                ssid,
                confirm: false,
            },
            focus,
        );
    }

    /// Joins the nearby network `index` lists: at once when it is open,
    /// otherwise once its password is typed.
    pub fn join_nearby_wifi(&mut self, index: usize) {
        let Some(network) = self.wifi.nearby.get(index) else {
            return;
        };
        let (ssid, security) = (network.ssid.clone(), network.security);
        if security.takes_password() {
            self.push_wifi(
                WifiPage::Password {
                    ssid,
                    security,
                    change: false,
                    text: PasswordText::new(),
                },
                keys::WIFI_PASSWORD_FIELD,
            );
        } else {
            self.node.save_wifi(&ssid, security, "", false);
        }
    }

    /// Joins or leaves the network whose sheet is shown.
    pub fn wifi_sheet_act(&mut self) {
        let Some((WifiPage::Sheet { ssid, .. }, _)) = self.wifi_page() else {
            return;
        };
        let ssid = ssid.clone();
        if self.wifi.current == ssid {
            self.node.disconnect_wifi();
        } else {
            self.node.join_wifi(&ssid);
        }
        self.back();
    }

    pub fn toggle_wifi_auto_join(&mut self) {
        let Some((WifiPage::Sheet { ssid, .. }, _)) = self.wifi_page() else {
            return;
        };
        let ssid = ssid.clone();
        if let Some(on) = self.wifi.saved(&ssid).map(|network| network.auto_join) {
            self.node.set_wifi_auto_join(&ssid, !on);
        }
    }

    pub fn open_wifi_change_password(&mut self) {
        let Some((WifiPage::Sheet { ssid, .. }, _)) = self.wifi_page() else {
            return;
        };
        let ssid = ssid.clone();
        let security = self
            .wifi
            .saved(&ssid)
            .map_or(WifiSecurity::Wpa2, |network| network.security);
        self.push_wifi(
            WifiPage::Password {
                ssid,
                security,
                change: true,
                text: PasswordText::new(),
            },
            keys::WIFI_PASSWORD_FIELD,
        );
    }

    /// Asks to confirm forgetting the network whose sheet is shown, Cancel
    /// focused.
    pub fn ask_forget_wifi(&mut self) {
        if let Some((WifiPage::Sheet { confirm, .. }, focus)) = self.wifi_page() {
            *confirm = true;
            *focus = FocusState::requesting(keys::WIFI_FORGET_CANCEL);
        }
    }

    pub fn cancel_forget_wifi(&mut self) {
        if let Some((WifiPage::Sheet { confirm, .. }, focus)) = self.wifi_page() {
            *confirm = false;
            *focus = FocusState::requesting(keys::WIFI_FORGET);
        }
    }

    pub fn forget_wifi(&mut self) {
        let Some((WifiPage::Sheet { ssid, .. }, _)) = self.wifi_page() else {
            return;
        };
        let ssid = ssid.clone();
        self.node.forget_wifi(&ssid);
        self.back();
    }

    /// The password being typed.
    pub fn wifi_password_mut(&mut self) -> Option<&mut EditBuffer<String<PASSWORD_MAX>>> {
        match self.wifi_page()? {
            (WifiPage::Password { text, .. }, _) => Some(&mut text.0),
            (WifiPage::Other { password, .. }, _) => Some(&mut password.0),
            _ => None,
        }
    }

    /// Joins with the password typed, or gives a saved network it.
    pub fn submit_wifi_password(&mut self) {
        let Some((
            WifiPage::Password {
                ssid,
                security,
                change,
                text,
            },
            _,
        )) = self.wifi_page()
        else {
            return;
        };
        if !text.valid() {
            return;
        }
        let (ssid, security, change) = (ssid.clone(), *security, *change);
        let password: String<PASSWORD_MAX> = text.0.text().try_into().unwrap_or_default();
        if change {
            self.node.change_wifi_password(&ssid, &password);
            // Back past the sheet, to the list.
            self.back();
        } else {
            self.node.save_wifi(&ssid, security, &password, false);
        }
        self.back();
    }

    pub fn open_other_wifi(&mut self) {
        self.push_wifi(
            WifiPage::Other {
                name: NetworkText::new(),
                security: WifiSecurity::Wpa2,
                password: PasswordText::new(),
                choosing: false,
            },
            keys::WIFI_NAME_FIELD,
        );
    }

    /// The name being typed into Other network.
    pub fn wifi_name_mut(&mut self) -> Option<&mut NetworkText> {
        match self.wifi_page()? {
            (WifiPage::Other { name, .. }, _) => Some(name),
            _ => None,
        }
    }

    pub fn choose_wifi_security(&mut self) {
        if let Some((
            WifiPage::Other {
                choosing, security, ..
            },
            focus,
        )) = self.wifi_page()
        {
            *choosing = true;
            let index = OTHER_SECURITY
                .iter()
                .position(|choice| choice == security)
                .unwrap_or(0);
            *focus = FocusState::requesting(keys::wifi_security(index));
        }
    }

    pub fn set_wifi_security(&mut self, index: usize) {
        if let Some((
            WifiPage::Other {
                choosing, security, ..
            },
            focus,
        )) = self.wifi_page()
        {
            *security = OTHER_SECURITY.get(index).copied().unwrap_or(*security);
            *choosing = false;
            *focus = FocusState::requesting(keys::WIFI_SECURITY);
        }
    }

    pub fn cancel_wifi_security(&mut self) {
        if let Some((WifiPage::Other { choosing, .. }, focus)) = self.wifi_page() {
            *choosing = false;
            *focus = FocusState::requesting(keys::WIFI_SECURITY);
        }
    }

    /// Whether Other network has what a join needs.
    #[must_use]
    pub fn other_wifi_ready(page: &WifiPage) -> bool {
        match page {
            WifiPage::Other {
                name,
                security,
                password,
                ..
            } => !name.text().is_empty() && (!security.takes_password() || password.valid()),
            _ => false,
        }
    }

    /// Saves the network typed into Other network, hidden, and joins it.
    pub fn submit_other_wifi(&mut self) {
        let Some((page, _)) = self.wifi_page() else {
            return;
        };
        if !Self::other_wifi_ready(page) {
            return;
        }
        let WifiPage::Other {
            name,
            security,
            password,
            ..
        } = page
        else {
            return;
        };
        let ssid: Ssid = Ssid::from_slice(name.text().as_bytes()).unwrap_or_default();
        let security = *security;
        let password: String<PASSWORD_MAX> = if security.takes_password() {
            password.0.text().try_into().unwrap_or_default()
        } else {
            String::new()
        };
        self.node.save_wifi(&ssid, security, &password, true);
        self.back();
    }

    /// Whether a Wi-Fi page is shown, for the signal to be read.
    #[must_use]
    pub(crate) fn wifi_shown(&self) -> bool {
        matches!(
            self.screen(),
            Screen::Device {
                page: DevicePage::Wifi { .. },
                ..
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_is_never_formatted() {
        let mut text = PasswordText::new();
        for c in "hunter22".chars() {
            text.0.insert(c);
        }
        let page = WifiPage::Password {
            ssid: Ssid::from_slice(b"Home").unwrap(),
            security: WifiSecurity::Wpa2,
            change: false,
            text,
        };
        let shown = alloc_free_format(&page);
        assert!(!shown.contains("hunter"));
    }

    fn alloc_free_format(page: &WifiPage) -> String<256> {
        let mut out = String::new();
        _ = core::fmt::write(&mut out, format_args!("{page:?}"));
        out
    }

    #[test]
    fn names_that_are_not_text_read_as_question_marks() {
        assert_eq!(ssid_text(b"Caf\xC3\xA9").as_str(), "Café");
        assert_eq!(ssid_text(b"a\xFFb").as_str(), "a?b");
        assert_eq!(ssid_text(b"a\x07b").as_str(), "a?b");
    }

    #[test]
    fn the_wifi_pages_fit_in_a_screen() {
        assert!(core::mem::size_of::<Screen>() <= 1192);
    }
}
