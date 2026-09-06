//! What the session holds about the device's Wi-Fi station and its IP
//! stack, and what it leaves to the platform.
//!
//! The split is the point. A station's *configuration* is protocol state:
//! which network to join, how to get an address, which resolvers to use.
//! It is written by a host, saved with the rest of the snapshot, and
//! restored on the next boot, so the session owns it. A station's
//! *behavior* is not: the credential the driver holds, the access points
//! it can hear, the lease it was handed. Those live where the driver
//! lives, and the session reaches them through effects.
//!
//! The one piece that looks like configuration and is not is the network
//! table. It carries credentials, the wire never gives one back, and a
//! device that stores its own passphrases is a device whose Wi-Fi driver
//! already has somewhere to put them. So the table is the platform's, and
//! what the session keeps is the name of the entry to use.

use umsh_ulcp::{ip, wifi};

/// The Wi-Fi hardware a device has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WifiConfig {
    /// Whether the device can join a network, or only hear them.
    ///
    /// A tracker that scans access points to place itself has a receiver
    /// and no station: it advertises `CAP_WIFI_SCAN` alone, answers the
    /// scan properties, and refuses the rest. Every device that can join
    /// can also scan, which is why there is no separate switch for the
    /// scan.
    pub station: bool,
    /// Post-reset value of `PROP_WIFI_ENABLED`.
    ///
    /// Off on anything battery powered, where a station is a larger
    /// continuous load than the mesh radio it sits beside. A mains-powered
    /// bridge whose whole job is the connection says otherwise.
    pub default_enabled: bool,
}

impl WifiConfig {
    /// A station that stays off until asked.
    pub const STATION: Self = Self {
        station: true,
        default_enabled: false,
    };

    /// A station that comes up on its own.
    pub const ALWAYS_ON: Self = Self {
        station: true,
        default_enabled: true,
    };

    /// A receiver that can hear networks and join none of them.
    pub const SCAN_ONLY: Self = Self {
        station: false,
        default_enabled: false,
    };
}

/// The IP families a device runs.
///
/// Separate from [`WifiConfig`] because a stack is not a link: a device
/// reached over Ethernet, or over a cellular modem, has these and no
/// Wi-Fi at all. Nothing here says which link the addresses are on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpConfig {
    pub v4: bool,
    pub v6: bool,
}

impl IpConfig {
    /// Both families, which is what a stack written this decade runs.
    pub const DUAL: Self = Self { v4: true, v6: true };
    pub const V4_ONLY: Self = Self {
        v4: true,
        v6: false,
    };
}

/// Longest `PROP_IP_DNS` this device accepts.
///
/// Three is what a network hands out and more than any operator
/// configures by hand. The receiver rule makes this a drop-with-status
/// rather than a truncation: a host that sends four is told `NOMEM`
/// rather than left believing the fourth is in use.
pub const MAX_RESOLVERS: usize = 3;

/// The device's own choice of resolvers (`PROP_IP_DNS`).
///
/// Held as encoded items rather than as parsed addresses because the two
/// families are different widths and a list may mix them, and because
/// what a host wrote is exactly what it reads back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolvers {
    entries: [[u8; 16]; MAX_RESOLVERS],
    widths: [u8; MAX_RESOLVERS],
    len: usize,
}

impl Default for Resolvers {
    fn default() -> Self {
        Self {
            entries: [[0; 16]; MAX_RESOLVERS],
            widths: [0; MAX_RESOLVERS],
            len: 0,
        }
    }
}

impl Resolvers {
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Each resolver, in the order it was written.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        (0..self.len).map(|index| &self.entries[index][..self.widths[index] as usize])
    }

    /// Append one resolver.
    ///
    /// Used on its own by the snapshot decoder, which sees the list an
    /// option at a time rather than as one value.
    pub fn push(&mut self, resolver: &[u8]) -> Result<(), ResolverError> {
        if !ip::resolver_is_valid(resolver) {
            return Err(ResolverError::NotWellFormed);
        }
        if self.len == MAX_RESOLVERS {
            return Err(ResolverError::TooMany);
        }
        self.entries[self.len][..resolver.len()].copy_from_slice(resolver);
        self.widths[self.len] = resolver.len() as u8;
        self.len += 1;
        Ok(())
    }

    /// Replace the whole list, or refuse it whole.
    ///
    /// Whole-list because that is how a small set of resolvers is edited:
    /// an operator adds one and removes another in the same breath, and a
    /// device left holding half of that would be resolving through a
    /// server nobody meant to keep. A candidate is built first so a
    /// refusal leaves the old list exactly as it was.
    pub fn replace(&mut self, items: &[u8]) -> Result<(), ResolverError> {
        let mut next = Self::default();
        for item in umsh_ulcp::items::prefixed_items(items) {
            let item = item.map_err(|_| ResolverError::Malformed)?;
            next.push(item)?;
        }
        *self = next;
        Ok(())
    }

    /// The list as it goes on the wire, length-prefixed.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut len = 0;
        for resolver in self.iter() {
            len += umsh_ulcp::items::encode_prefixed_item(resolver, out.get_mut(len..)?).ok()?;
        }
        Some(len)
    }
}

/// Why a resolver list was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolverError {
    /// The items do not parse.
    Malformed,
    /// An entry is not four or sixteen octets, or is an address nothing
    /// answers on.
    NotWellFormed,
    /// More entries than this device holds.
    TooMany,
}

/// The name of the stored network the station should use
/// (`PROP_WIFI_NETWORK`).
///
/// Empty is a value and not an absence: it is a host saying "join
/// nothing", which is different from a host that has said nothing at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedNetwork {
    ssid: [u8; wifi::SSID_MAX_LEN],
    len: usize,
}

impl Default for SelectedNetwork {
    fn default() -> Self {
        Self {
            ssid: [0; wifi::SSID_MAX_LEN],
            len: 0,
        }
    }
}

impl SelectedNetwork {
    pub fn as_bytes(&self) -> &[u8] {
        &self.ssid[..self.len]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Take a host's choice, or say it is not an SSID.
    pub fn set(&mut self, ssid: &[u8]) -> Result<(), ()> {
        if ssid.len() > wifi::SSID_MAX_LEN {
            return Err(());
        }
        self.ssid[..ssid.len()].copy_from_slice(ssid);
        self.len = ssid.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn a_resolver_list_takes_both_families_and_refuses_a_fourth() {
        let mut resolvers = Resolvers::default();
        let mut items = Vec::new();
        items.extend_from_slice(&item(&[192, 168, 1, 1]));
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[15] = 1;
        items.extend_from_slice(&item(&v6));
        assert_eq!(resolvers.replace(&items), Ok(()));
        assert_eq!(resolvers.iter().count(), 2);

        let mut too_many = items.clone();
        too_many.extend_from_slice(&item(&[9, 9, 9, 9]));
        too_many.extend_from_slice(&item(&[1, 1, 1, 1]));
        assert_eq!(resolvers.replace(&too_many), Err(ResolverError::TooMany));
        // The refusal left the list it refused to replace alone.
        assert_eq!(resolvers.iter().count(), 2);
    }

    #[test]
    fn a_resolver_nothing_answers_on_is_refused() {
        let mut resolvers = Resolvers::default();
        assert_eq!(
            resolvers.replace(&item(&[0, 0, 0, 0])),
            Err(ResolverError::NotWellFormed)
        );
        // An IPv4 link-local address is a host that failed to get one,
        // not a resolver.
        assert_eq!(
            resolvers.replace(&item(&[169, 254, 1, 1])),
            Err(ResolverError::NotWellFormed)
        );
        assert_eq!(
            resolvers.replace(&item(&[1, 2, 3])),
            Err(ResolverError::NotWellFormed)
        );
    }

    #[test]
    fn an_empty_list_clears_and_round_trips() {
        let mut resolvers = Resolvers::default();
        assert_eq!(resolvers.replace(&item(&[9, 9, 9, 9])), Ok(()));
        assert_eq!(resolvers.replace(&[]), Ok(()));
        assert!(resolvers.is_empty());
        let mut out = [0u8; 64];
        assert_eq!(resolvers.encode(&mut out), Some(0));
    }

    #[test]
    fn the_selected_network_holds_arbitrary_octets_and_the_empty_choice() {
        let mut selected = SelectedNetwork::default();
        assert!(selected.is_empty());
        assert_eq!(selected.set(&[0xFF, 0x00, 0x80]), Ok(()));
        assert_eq!(selected.as_bytes(), [0xFF, 0x00, 0x80]);
        assert_eq!(selected.set(&[]), Ok(()));
        assert!(selected.is_empty());
        assert_eq!(selected.set(&[0x41; 33]), Err(()));
    }
}
