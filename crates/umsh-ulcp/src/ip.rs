//! IP connectivity codecs (`PROP_IPV4_*`, `PROP_IPV6_*`, `PROP_IP_*`).
//!
//! The structures of `docs/protocol/src/ulcp-ip.md`: family readiness,
//! the per-family configuration, the addresses in effect, and the
//! resolvers.
//!
//! The usability predicates here are the boundary the whole subsystem is
//! defined on. [`FamilyState::Ready`] means a usable address, a static
//! configuration is validated against the same rule, and the two are the
//! same function so that they cannot drift: a device that accepted a
//! static address it would then refuse to call ready would be
//! unreachable and say it was fine.

/// Encoded length of a static [`V4Config`]; the other methods encode as
/// one octet.
pub const V4_CONFIG_STATIC_LEN: usize = 10;
/// Encoded length of a static [`V6Config`].
pub const V6_CONFIG_STATIC_LEN: usize = 34;
/// Encoded length of a [`V4Address`]. The property is empty when the
/// family is not ready.
pub const V4_ADDRESS_LEN: usize = 9;
/// Encoded length of a [`V6Item::Address`].
pub const V6_ADDRESS_ITEM_LEN: usize = 18;
/// Encoded length of a [`V6Item::Router`].
pub const V6_ROUTER_ITEM_LEN: usize = 17;

/// Decode or well-formedness failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpError {
    /// The input ended before the structure was complete.
    Truncated,
    /// An unknown enumeration code, or a field of impossible length.
    Malformed,
    /// The value parses but is not one a device may be configured with:
    /// a prefix out of range, an address that is not usable, a gateway
    /// or resolver that is not a unicast host. The
    /// `STATUS_INVALID_ARGUMENT` set.
    NotWellFormed,
    /// The output buffer cannot hold the encoded value.
    BufferTooSmall,
}

/// Readiness of one address family, shared by `PROP_IPV4_STATE` and
/// `PROP_IPV6_STATE`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FamilyState {
    /// `IP_DISABLED`: the family is configured off.
    Disabled = 0,
    /// `IP_NO_LINK`: the link is down, so there is nothing to address.
    #[default]
    NoLink = 1,
    /// `IP_WAITING`: the link is up and the family has no usable
    /// address yet.
    Waiting = 2,
    /// `IP_READY`: the family holds a usable address. An address, not a
    /// route: a device on an isolated network with no gateway is ready.
    Ready = 3,
    /// `IP_CONFLICT`: the configured static address is held by
    /// something else, which is a fault in the configuration this
    /// protocol wrote.
    Conflict = 4,
}

impl FamilyState {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Disabled),
            1 => Some(Self::NoLink),
            2 => Some(Self::Waiting),
            3 => Some(Self::Ready),
            4 => Some(Self::Conflict),
            _ => None,
        }
    }

    /// Whether the device can be reached on this family right now.
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// How a family gets its address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Method {
    /// `IP_METHOD_DISABLED`: the family is not used on the link.
    Disabled = 0,
    /// `IP_METHOD_AUTO`: DHCP for IPv4; router advertisements, and
    /// DHCPv6 where the router asks for it, for IPv6.
    #[default]
    Auto = 1,
    /// `IP_METHOD_STATIC`: the address, prefix, and gateway that
    /// follow.
    Static = 2,
}

impl Method {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Disabled),
            1 => Some(Self::Auto),
            2 => Some(Self::Static),
            _ => None,
        }
    }
}

/// Whether an IPv4 address is a usable host address: unicast, and not
/// link-local.
///
/// This is the definition `IP_READY` is stated in terms of. A
/// self-assigned `169.254` address reaches only the link, exactly as
/// `fe80::` does, and a device that fell back to one is a device whose
/// DHCP failed.
pub const fn ipv4_is_usable_host(address: &[u8; 4]) -> bool {
    let [a, b, _, _] = *address;
    if a == 0 && b == 0 && address[2] == 0 && address[3] == 0 {
        return false; // unspecified
    }
    if a == 127 {
        return false; // loopback
    }
    if a == 169 && b == 254 {
        return false; // link-local
    }
    if a >= 224 && a <= 239 {
        return false; // multicast
    }
    if a == 255 && b == 255 && address[2] == 255 && address[3] == 255 {
        return false; // limited broadcast
    }
    true
}

/// Whether an IPv6 address is a usable host address: unicast, and not
/// link-local.
pub fn ipv6_is_usable_host(address: &[u8; 16]) -> bool {
    if address.iter().all(|&b| b == 0) {
        return false; // unspecified
    }
    if address[..15].iter().all(|&b| b == 0) && address[15] == 1 {
        return false; // loopback
    }
    if address[0] == 0xFF {
        return false; // multicast
    }
    if address[0] == 0xFE && (address[1] & 0xC0) == 0x80 {
        return false; // link-local, fe80::/10
    }
    true
}

/// Whether an IPv6 address is link-local (`fe80::/10`).
pub const fn ipv6_is_link_local(address: &[u8; 16]) -> bool {
    address[0] == 0xFE && (address[1] & 0xC0) == 0x80
}

/// Whether an IPv4 gateway is acceptable: all-zero for "no default
/// route", or a usable host address.
pub const fn ipv4_gateway_is_valid(gateway: &[u8; 4]) -> bool {
    if gateway[0] == 0 && gateway[1] == 0 && gateway[2] == 0 && gateway[3] == 0 {
        return true;
    }
    ipv4_is_usable_host(gateway)
}

/// Whether an IPv6 gateway is acceptable.
///
/// Relaxes the link-local exclusion, unlike the IPv4 form: a router
/// names itself by its link-local address, and a static IPv6 gateway is
/// usually exactly that.
pub fn ipv6_gateway_is_valid(gateway: &[u8; 16]) -> bool {
    if gateway.iter().all(|&b| b == 0) {
        return true;
    }
    ipv6_is_usable_host(gateway) || ipv6_is_link_local(gateway)
}

/// Whether one `PROP_IP_DNS` item is acceptable.
///
/// Four or sixteen octets, a unicast host either way. An IPv6 resolver
/// may be link-local, as one advertised by a home router commonly is,
/// and an IPv4 one may not.
pub fn resolver_is_valid(item: &[u8]) -> bool {
    match item.len() {
        4 => {
            let mut address = [0u8; 4];
            address.copy_from_slice(item);
            ipv4_is_usable_host(&address)
        }
        16 => {
            let mut address = [0u8; 16];
            address.copy_from_slice(item);
            ipv6_is_usable_host(&address) || ipv6_is_link_local(&address)
        }
        _ => false,
    }
}

/// `PROP_IPV4_CONFIG`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V4Config {
    pub method: Method,
    /// Meaningful only under [`Method::Static`].
    pub address: [u8; 4],
    /// Meaningful only under [`Method::Static`]. At most 32.
    pub prefix: u8,
    /// Meaningful only under [`Method::Static`]. All-zero for no
    /// default route.
    pub gateway: [u8; 4],
}

impl Default for V4Config {
    fn default() -> Self {
        Self {
            method: Method::Auto,
            address: [0; 4],
            prefix: 0,
            gateway: [0; 4],
        }
    }
}

impl V4Config {
    /// Whether this configuration is one a device may be given.
    pub fn validate(&self) -> Result<(), IpError> {
        if !matches!(self.method, Method::Static) {
            return Ok(());
        }
        if self.prefix > 32 {
            return Err(IpError::NotWellFormed);
        }
        if !ipv4_is_usable_host(&self.address) {
            return Err(IpError::NotWellFormed);
        }
        if !ipv4_gateway_is_valid(&self.gateway) {
            return Err(IpError::NotWellFormed);
        }
        Ok(())
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, IpError> {
        let len = if matches!(self.method, Method::Static) {
            V4_CONFIG_STATIC_LEN
        } else {
            1
        };
        if out.len() < len {
            return Err(IpError::BufferTooSmall);
        }
        out[0] = self.method.code();
        if len > 1 {
            out[1..5].copy_from_slice(&self.address);
            out[5] = self.prefix;
            out[6..10].copy_from_slice(&self.gateway);
        }
        Ok(len)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IpError> {
        let method = Method::from_code(*bytes.first().ok_or(IpError::Truncated)?)
            .ok_or(IpError::Malformed)?;
        let mut config = Self {
            method,
            ..Self::default()
        };
        if matches!(method, Method::Static) {
            if bytes.len() < V4_CONFIG_STATIC_LEN {
                return Err(IpError::Truncated);
            }
            config.address.copy_from_slice(&bytes[1..5]);
            config.prefix = bytes[5];
            config.gateway.copy_from_slice(&bytes[6..10]);
        }
        Ok(config)
    }
}

/// `PROP_IPV6_CONFIG`: as [`V4Config`] with 16-octet addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V6Config {
    pub method: Method,
    pub address: [u8; 16],
    /// At most 128.
    pub prefix: u8,
    /// All-zero for no default route. May be link-local.
    pub gateway: [u8; 16],
}

impl Default for V6Config {
    fn default() -> Self {
        Self {
            method: Method::Auto,
            address: [0; 16],
            prefix: 0,
            gateway: [0; 16],
        }
    }
}

impl V6Config {
    /// Whether this configuration is one a device may be given.
    ///
    /// A usable static address already held on the link is *not*
    /// rejected here: the device accepts it and reports
    /// [`FamilyState::Conflict`], because a duplicate is discovered on
    /// the wire rather than in the value.
    pub fn validate(&self) -> Result<(), IpError> {
        if !matches!(self.method, Method::Static) {
            return Ok(());
        }
        if self.prefix > 128 {
            return Err(IpError::NotWellFormed);
        }
        if !ipv6_is_usable_host(&self.address) {
            return Err(IpError::NotWellFormed);
        }
        if !ipv6_gateway_is_valid(&self.gateway) {
            return Err(IpError::NotWellFormed);
        }
        Ok(())
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, IpError> {
        let len = if matches!(self.method, Method::Static) {
            V6_CONFIG_STATIC_LEN
        } else {
            1
        };
        if out.len() < len {
            return Err(IpError::BufferTooSmall);
        }
        out[0] = self.method.code();
        if len > 1 {
            out[1..17].copy_from_slice(&self.address);
            out[17] = self.prefix;
            out[18..34].copy_from_slice(&self.gateway);
        }
        Ok(len)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IpError> {
        let method = Method::from_code(*bytes.first().ok_or(IpError::Truncated)?)
            .ok_or(IpError::Malformed)?;
        let mut config = Self {
            method,
            ..Self::default()
        };
        if matches!(method, Method::Static) {
            if bytes.len() < V6_CONFIG_STATIC_LEN {
                return Err(IpError::Truncated);
            }
            config.address.copy_from_slice(&bytes[1..17]);
            config.prefix = bytes[17];
            config.gateway.copy_from_slice(&bytes[18..34]);
        }
        Ok(config)
    }
}

/// `PROP_IPV4_ADDRESS`: what the interface holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct V4Address {
    pub address: [u8; 4],
    pub prefix: u8,
    /// All-zero when there is no default route.
    pub gateway: [u8; 4],
}

impl V4Address {
    /// Whether the family has a way off the link.
    pub fn has_gateway(&self) -> bool {
        self.gateway != [0; 4]
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, IpError> {
        if out.len() < V4_ADDRESS_LEN {
            return Err(IpError::BufferTooSmall);
        }
        out[0..4].copy_from_slice(&self.address);
        out[4] = self.prefix;
        out[5..9].copy_from_slice(&self.gateway);
        Ok(V4_ADDRESS_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IpError> {
        if bytes.len() < V4_ADDRESS_LEN {
            return Err(IpError::Truncated);
        }
        let mut value = Self::default();
        value.address.copy_from_slice(&bytes[0..4]);
        value.prefix = bytes[4];
        value.gateway.copy_from_slice(&bytes[5..9]);
        Ok(value)
    }
}

/// Item kinds of `PROP_IPV6_ADDRESSES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V6ItemKind {
    /// `IPV6_ADDRESS`
    Address = 0,
    /// `IPV6_ROUTER`
    Router = 1,
}

impl V6ItemKind {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Address),
            1 => Some(Self::Router),
            _ => None,
        }
    }
}

/// One item of `PROP_IPV6_ADDRESSES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V6Item {
    /// A stable address the device is reachable at. The link-local
    /// address is never among them, for the reason it does not make the
    /// family ready.
    Address {
        address: [u8; 16],
        /// The prefix the assignment carried. An address assigned by
        /// DHCPv6 reports 128, which means the assignment carried no
        /// prefix rather than that the link is a `/128`.
        prefix: u8,
    },
    /// One router of the stack's default router list.
    Router { address: [u8; 16] },
}

impl V6Item {
    pub const fn kind(&self) -> V6ItemKind {
        match self {
            Self::Address { .. } => V6ItemKind::Address,
            Self::Router { .. } => V6ItemKind::Router,
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, IpError> {
        let len = match self {
            Self::Address { .. } => V6_ADDRESS_ITEM_LEN,
            Self::Router { .. } => V6_ROUTER_ITEM_LEN,
        };
        if out.len() < len {
            return Err(IpError::BufferTooSmall);
        }
        out[0] = self.kind().code();
        match self {
            Self::Address { address, prefix } => {
                out[1..17].copy_from_slice(address);
                out[17] = *prefix;
            }
            Self::Router { address } => out[1..17].copy_from_slice(address),
        }
        Ok(len)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IpError> {
        let kind = V6ItemKind::from_code(*bytes.first().ok_or(IpError::Truncated)?)
            .ok_or(IpError::Malformed)?;
        let mut address = [0u8; 16];
        match kind {
            V6ItemKind::Address => {
                if bytes.len() < V6_ADDRESS_ITEM_LEN {
                    return Err(IpError::Truncated);
                }
                address.copy_from_slice(&bytes[1..17]);
                Ok(Self::Address {
                    address,
                    prefix: bytes[17],
                })
            }
            V6ItemKind::Router => {
                if bytes.len() < V6_ROUTER_ITEM_LEN {
                    return Err(IpError::Truncated);
                }
                address.copy_from_slice(&bytes[1..17]);
                Ok(Self::Router { address })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GLOBAL_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const LINK_LOCAL_V6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    #[test]
    fn family_state_codes_round_trip_strictly() {
        for code in 0..=4u8 {
            let state = FamilyState::from_code(code).expect("allocated");
            assert_eq!(state.code(), code);
        }
        assert_eq!(FamilyState::from_code(5), None);
        assert!(FamilyState::Ready.is_ready());
        assert!(!FamilyState::Waiting.is_ready());
        assert!(!FamilyState::Conflict.is_ready());
    }

    #[test]
    fn method_codes_round_trip_strictly() {
        for code in 0..=2u8 {
            assert_eq!(Method::from_code(code).expect("allocated").code(), code);
        }
        assert_eq!(Method::from_code(3), None);
        // Automatic by default, so a device with nothing configured is
        // on the network the moment it is associated.
        assert_eq!(Method::default(), Method::Auto);
    }

    #[test]
    fn a_link_local_v4_address_is_not_usable() {
        // The whole point of the boundary: DHCP failed, and ready would
        // hide it.
        assert!(!ipv4_is_usable_host(&[169, 254, 3, 4]));
        assert!(ipv4_is_usable_host(&[169, 253, 3, 4]));
        assert!(ipv4_is_usable_host(&[192, 168, 4, 1]));
        assert!(ipv4_is_usable_host(&[8, 8, 8, 8]));
        assert!(!ipv4_is_usable_host(&[0, 0, 0, 0]));
        assert!(!ipv4_is_usable_host(&[127, 0, 0, 1]));
        assert!(!ipv4_is_usable_host(&[224, 0, 0, 1]));
        assert!(!ipv4_is_usable_host(&[239, 255, 255, 250]));
        assert!(!ipv4_is_usable_host(&[255, 255, 255, 255]));
    }

    #[test]
    fn a_link_local_v6_address_is_not_usable() {
        assert!(ipv6_is_usable_host(&GLOBAL_V6));
        assert!(!ipv6_is_usable_host(&LINK_LOCAL_V6));
        assert!(ipv6_is_link_local(&LINK_LOCAL_V6));
        assert!(!ipv6_is_link_local(&GLOBAL_V6));
        assert!(!ipv6_is_usable_host(&[0; 16]));
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        assert!(!ipv6_is_usable_host(&loopback));
        let mut multicast = [0u8; 16];
        multicast[0] = 0xFF;
        assert!(!ipv6_is_usable_host(&multicast));
        // fe80::/10 covers febf:: too.
        let mut high = LINK_LOCAL_V6;
        high[1] = 0xBF;
        assert!(ipv6_is_link_local(&high));
    }

    #[test]
    fn only_the_v6_gateway_may_be_link_local() {
        // A router names itself by its link-local address, so refusing
        // one would refuse the ordinary case.
        assert!(ipv6_gateway_is_valid(&LINK_LOCAL_V6));
        assert!(ipv6_gateway_is_valid(&GLOBAL_V6));
        assert!(ipv6_gateway_is_valid(&[0; 16]));
        assert!(!ipv4_gateway_is_valid(&[169, 254, 0, 1]));
        assert!(ipv4_gateway_is_valid(&[0, 0, 0, 0]));
        assert!(ipv4_gateway_is_valid(&[192, 168, 4, 254]));
    }

    #[test]
    fn a_resolver_is_four_or_sixteen_octets() {
        assert!(resolver_is_valid(&[8, 8, 8, 8]));
        assert!(resolver_is_valid(&GLOBAL_V6));
        // A home router commonly advertises a link-local resolver.
        assert!(resolver_is_valid(&LINK_LOCAL_V6));
        assert!(!resolver_is_valid(&[169, 254, 0, 1]));
        assert!(!resolver_is_valid(&[0, 0, 0, 0]));
        assert!(!resolver_is_valid(&[127, 0, 0, 1]));
        assert!(!resolver_is_valid(&[]));
        assert!(!resolver_is_valid(&[1, 2, 3]));
        assert!(!resolver_is_valid(&[0; 5]));
    }

    #[test]
    fn an_automatic_config_is_one_octet() {
        let config = V4Config::default();
        let mut buf = [0u8; V4_CONFIG_STATIC_LEN];
        assert_eq!(config.encode(&mut buf), Ok(1));
        assert_eq!(buf[0], Method::Auto.code());
        assert_eq!(V4Config::decode(&buf[..1]), Ok(config));

        let v6 = V6Config::default();
        let mut buf = [0u8; V6_CONFIG_STATIC_LEN];
        assert_eq!(v6.encode(&mut buf), Ok(1));
        assert_eq!(V6Config::decode(&buf[..1]), Ok(v6));
    }

    #[test]
    fn a_static_v4_config_round_trips() {
        let config = V4Config {
            method: Method::Static,
            address: [192, 168, 1, 40],
            prefix: 24,
            gateway: [192, 168, 1, 1],
        };
        config.validate().expect("well formed");
        let mut buf = [0u8; V4_CONFIG_STATIC_LEN];
        assert_eq!(config.encode(&mut buf), Ok(V4_CONFIG_STATIC_LEN));
        assert_eq!(V4Config::decode(&buf), Ok(config));
    }

    #[test]
    fn a_static_v6_config_round_trips() {
        let config = V6Config {
            method: Method::Static,
            address: GLOBAL_V6,
            prefix: 64,
            gateway: LINK_LOCAL_V6,
        };
        config.validate().expect("well formed");
        let mut buf = [0u8; V6_CONFIG_STATIC_LEN];
        assert_eq!(config.encode(&mut buf), Ok(V6_CONFIG_STATIC_LEN));
        assert_eq!(V6Config::decode(&buf), Ok(config));
    }

    #[test]
    fn a_static_config_is_validated_against_the_readiness_boundary() {
        let base = V4Config {
            method: Method::Static,
            address: [192, 168, 1, 40],
            prefix: 24,
            gateway: [0; 4],
        };
        assert!(base.validate().is_ok());
        // The same rule IP_READY is stated in terms of, so a device
        // cannot accept an address it would then refuse to call ready.
        assert!(
            V4Config {
                address: [169, 254, 1, 1],
                ..base
            }
            .validate()
            .is_err()
        );
        assert!(V4Config { prefix: 33, ..base }.validate().is_err());
        assert!(
            V4Config {
                gateway: [224, 0, 0, 1],
                ..base
            }
            .validate()
            .is_err()
        );
        // Nothing is validated when the method does not carry a value.
        assert!(
            V4Config {
                method: Method::Auto,
                address: [0; 4],
                prefix: 99,
                gateway: [0; 4],
            }
            .validate()
            .is_ok()
        );
        assert!(
            V6Config {
                method: Method::Static,
                address: GLOBAL_V6,
                prefix: 129,
                gateway: [0; 16],
            }
            .validate()
            .is_err()
        );
        assert!(
            V6Config {
                method: Method::Static,
                address: LINK_LOCAL_V6,
                prefix: 64,
                gateway: [0; 16],
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn a_v4_address_round_trips_with_and_without_a_gateway() {
        let held = V4Address {
            address: [10, 0, 0, 5],
            prefix: 8,
            gateway: [10, 0, 0, 1],
        };
        let mut buf = [0u8; V4_ADDRESS_LEN];
        assert_eq!(held.encode(&mut buf), Ok(V4_ADDRESS_LEN));
        assert_eq!(V4Address::decode(&buf), Ok(held));
        assert!(held.has_gateway());

        // An isolated network that hands out addresses and no gateway
        // is ready, which is the honest reading.
        let isolated = V4Address {
            gateway: [0; 4],
            ..held
        };
        assert_eq!(isolated.encode(&mut buf), Ok(V4_ADDRESS_LEN));
        assert_eq!(V4Address::decode(&buf), Ok(isolated));
        assert!(!isolated.has_gateway());
    }

    #[test]
    fn the_two_v6_item_kinds_round_trip() {
        let address = V6Item::Address {
            address: GLOBAL_V6,
            prefix: 64,
        };
        let mut buf = [0u8; V6_ADDRESS_ITEM_LEN];
        assert_eq!(address.encode(&mut buf), Ok(V6_ADDRESS_ITEM_LEN));
        assert_eq!(V6Item::decode(&buf), Ok(address));
        assert_eq!(address.kind(), V6ItemKind::Address);

        let router = V6Item::Router {
            address: LINK_LOCAL_V6,
        };
        assert_eq!(router.encode(&mut buf), Ok(V6_ROUTER_ITEM_LEN));
        assert_eq!(V6Item::decode(&buf[..V6_ROUTER_ITEM_LEN]), Ok(router));
        assert_eq!(router.kind(), V6ItemKind::Router);

        // A DHCPv6 assignment carries no prefix and reports 128.
        let dhcpv6 = V6Item::Address {
            address: GLOBAL_V6,
            prefix: 128,
        };
        assert_eq!(dhcpv6.encode(&mut buf), Ok(V6_ADDRESS_ITEM_LEN));
        assert_eq!(V6Item::decode(&buf), Ok(dhcpv6));
    }

    #[test]
    fn unknown_codes_and_short_values_are_told_apart() {
        assert_eq!(V4Config::decode(&[]), Err(IpError::Truncated));
        assert_eq!(V4Config::decode(&[7]), Err(IpError::Malformed));
        assert_eq!(
            V4Config::decode(&[Method::Static.code(), 1, 2]),
            Err(IpError::Truncated)
        );
        assert_eq!(V6Item::decode(&[]), Err(IpError::Truncated));
        assert_eq!(V6Item::decode(&[9]), Err(IpError::Malformed));
        assert_eq!(V6Item::decode(&[0, 1, 2]), Err(IpError::Truncated));
        assert_eq!(V4Address::decode(&[0; 8]), Err(IpError::Truncated));
    }

    #[test]
    fn encoders_report_a_buffer_too_small_rather_than_truncating() {
        let mut small = [0u8; 4];
        assert_eq!(
            V4Config {
                method: Method::Static,
                ..V4Config::default()
            }
            .encode(&mut small),
            Err(IpError::BufferTooSmall)
        );
        assert_eq!(
            V4Address::default().encode(&mut small),
            Err(IpError::BufferTooSmall)
        );
        assert_eq!(
            V6Item::Router { address: [0; 16] }.encode(&mut small),
            Err(IpError::BufferTooSmall)
        );
    }
}
