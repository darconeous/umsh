//! Static configuration: the whole of what the daemon knows.
//!
//! The role — server or client — is a property of the file rather than
//! the invocation, so a deployment is one unit file and one config, and
//! `umsh-bridge check` validates the exact artifact that will run.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use umsh_core::RegionCode;

use crate::tls::Address;

/// Default tunnel port: `0x554D`, big-endian ASCII "UM". Unassigned by
/// IANA, and far enough from the usual hand-picked numbers to be
/// unlikely to collide with something else on a shared host.
pub const DEFAULT_PORT: u16 = 21837;

/// Interface name of a participant's own radio. Reserved: a client
/// entry may not take it.
pub const RADIO_INTERFACE: &str = "radio";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// This endpoint's Ed25519 identity, which the tunnel authenticates
    /// with. The server's doubles as the bridge's node identity.
    pub identity: Option<IdentityConfig>,
    pub server: Option<ServerConfig>,
    pub client: Option<ClientConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// File holding the 64-hex Ed25519 seed, readable only by its owner.
    pub key_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: Vec<SocketAddr>,
    #[serde(default)]
    pub radio: RadioConfig,
    #[serde(default)]
    pub forwarding: ForwardingConfig,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    #[serde(default)]
    pub clients: Vec<ClientEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEntry {
    /// Interface name, used in log lines and in other clients'
    /// `allow_to`.
    pub name: String,
    /// This client's identity — the address its `keygen identity`
    /// printed.
    pub address: Address,
    /// Forwarding budget for frames arriving from this client. Absent
    /// means unlimited, which the spec advises against.
    pub max_frames_per_minute: Option<u32>,
    /// Interfaces this client's traffic may be fanned out to. Absent
    /// means all of them.
    pub allow_to: Option<Vec<String>>,
    /// Set when the device backing this client also runs its own
    /// repeater role: its flood re-forward already confirms the previous
    /// hop, so the bridge's own flood confirmation copy is redundant
    /// airtime. Source-routed confirmations are still emitted.
    #[serde(default)]
    pub suppress_flood_confirmations: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// `host:port` of the bridge server. Every address it resolves to is
    /// tried, IPv6 and IPv4 alike.
    pub server: String,
    /// The server's identity — the address its `keygen identity`
    /// printed.
    pub server_address: Address,
    /// SNI name to present. The pinned identity is what authenticates
    /// the server, so this only matters when the server multiplexes on
    /// it.
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub radio: RadioConfig,
    #[serde(default)]
    pub tunnel: TunnelConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardingConfig {
    /// Ceiling applied to `FHOPS_REM` on the way out. The spec's default
    /// is 1 and advises against raising it on internet-tunneled
    /// deployments.
    #[serde(default = "default_exit_clamp")]
    pub exit_clamp: u8,
    /// Region codes this bridge will carry. Empty means no restriction.
    #[serde(default)]
    pub regions: Vec<RegionCodeArg>,
    pub min_rssi: Option<i16>,
    /// Minimum SNR in dB; fractional values are kept to a tenth.
    pub min_snr: Option<f64>,
    #[serde(default = "default_cache_entries")]
    pub cache_entries: usize,
    #[serde(default = "default_confirmation_window")]
    pub confirmation_window_secs: u64,
    /// Window a flood confirmation copy is spread over, roughly two
    /// frame durations at the segment's data rate. Zero sends it
    /// immediately, which is what the integration tests want and what a
    /// segment with no other repeaters can afford.
    #[serde(default = "default_flood_contention")]
    pub flood_contention_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Frames older than this are dropped rather than written; they have
    /// already outlived every forwarding-confirmation retry that could
    /// have wanted them.
    #[serde(default = "default_max_frame_age")]
    pub max_frame_age_secs: u64,
    /// Frames held per tunnel before the oldest is dropped.
    #[serde(default = "default_queue_depth")]
    pub queue_depth: usize,
    #[serde(default = "default_reconnect_min")]
    pub reconnect_min_secs: u64,
    #[serde(default = "default_reconnect_max")]
    pub reconnect_max_secs: u64,
}

/// Which device this participant fronts.
#[derive(Debug, Default)]
pub enum RadioConfig {
    /// A ULCP device on a serial port.
    Serial { port: String, baud: u32 },
    /// A ULCP device over BLE, named or discovered.
    Ble {
        /// Radio name or scan id. Absent discovers, which is only
        /// unambiguous where exactly one radio is in range — name the
        /// radio for an unattended deployment.
        selector: Option<String>,
    },
    /// The UDP-multicast fake radio the examples use. For testing a
    /// bridge without hardware, or without airtime.
    UdpMulticast {
        group: Ipv4Addr,
        port: u16,
        /// Signal quality to synthesize for received frames, since UDP
        /// measures none.
        rssi: i16,
        snr: i8,
    },
    /// No radio at all: a server that only joins clients together.
    #[default]
    None,
}

/// The radio table as written, before it is narrowed to one variant.
///
/// A tagged enum would be the obvious shape, but serde buffers an
/// internally tagged enum's content and `deny_unknown_fields` never
/// reaches the variant — a misspelled key would be silently ignored,
/// which for a daemon's configuration is the worst possible outcome.
/// Reading the table flat also lets a key belonging to the wrong `type`
/// be named in the error.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RadioTable {
    #[serde(rename = "type")]
    kind: String,
    /// A device path for `serial`, a UDP port number for
    /// `udp-multicast`.
    port: Option<toml::Value>,
    baud: Option<u32>,
    selector: Option<String>,
    group: Option<Ipv4Addr>,
    rssi: Option<i16>,
    snr: Option<i8>,
}

impl<'de> Deserialize<'de> for RadioConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let table = RadioTable::deserialize(deserializer)?;
        let reject = |unexpected: &[(&str, bool)]| -> Result<(), D::Error> {
            for (name, present) in unexpected {
                if *present {
                    return Err(D::Error::custom(format!(
                        "\"{name}\" has no meaning for a {} radio",
                        table.kind
                    )));
                }
            }
            Ok(())
        };

        match table.kind.as_str() {
            "serial" => {
                reject(&[
                    ("selector", table.selector.is_some()),
                    ("group", table.group.is_some()),
                    ("rssi", table.rssi.is_some()),
                    ("snr", table.snr.is_some()),
                ])?;
                let port = table
                    .port
                    .as_ref()
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| D::Error::custom("a serial radio needs a string \"port\""))?;
                Ok(Self::Serial {
                    port: port.to_string(),
                    baud: table.baud.unwrap_or_else(default_baud),
                })
            }
            "ble" => {
                reject(&[
                    ("port", table.port.is_some()),
                    ("baud", table.baud.is_some()),
                    ("group", table.group.is_some()),
                    ("rssi", table.rssi.is_some()),
                    ("snr", table.snr.is_some()),
                ])?;
                Ok(Self::Ble {
                    selector: table.selector,
                })
            }
            "udp-multicast" => {
                reject(&[
                    ("baud", table.baud.is_some()),
                    ("selector", table.selector.is_some()),
                ])?;
                let port = match &table.port {
                    None => default_udp_port(),
                    Some(value) => value
                        .as_integer()
                        .and_then(|port| u16::try_from(port).ok())
                        .ok_or_else(|| {
                            D::Error::custom("a udp-multicast \"port\" is a number, 1..=65535")
                        })?,
                };
                let group = table.group.unwrap_or_else(default_udp_group);
                if !group.is_multicast() {
                    return Err(D::Error::custom(format!(
                        "\"{group}\" is not an IPv4 multicast address"
                    )));
                }
                Ok(Self::UdpMulticast {
                    group,
                    port,
                    rssi: table.rssi.unwrap_or_else(default_udp_rssi),
                    snr: table.snr.unwrap_or_else(default_udp_snr),
                })
            }
            "none" => {
                reject(&[
                    ("port", table.port.is_some()),
                    ("baud", table.baud.is_some()),
                    ("selector", table.selector.is_some()),
                    ("group", table.group.is_some()),
                    ("rssi", table.rssi.is_some()),
                    ("snr", table.snr.is_some()),
                ])?;
                Ok(Self::None)
            }
            other => Err(D::Error::custom(format!(
                "unknown radio type \"{other}\"; expected serial, ble, udp-multicast, or none"
            ))),
        }
    }
}

impl RadioConfig {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// How the interface is named in logs.
    pub fn describe(&self) -> String {
        match self {
            Self::Serial { port, baud } => format!("serial {port} @ {baud}"),
            Self::Ble { selector: Some(s) } => format!("ble {s}"),
            Self::Ble { selector: None } => "ble (discover)".to_string(),
            Self::UdpMulticast { group, port, .. } => format!("udp-multicast {group}:{port}"),
            Self::None => "none".to_string(),
        }
    }
}

/// A region code in its textual form: an IATA code (`SJC`), a raw code
/// (`0x7853`), or a region name that is hashed.
#[derive(Clone, Copy, Debug)]
pub struct RegionCodeArg(pub RegionCode);

impl<'de> Deserialize<'de> for RegionCodeArg {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        RegionCode::from_str(&text)
            .map(RegionCodeArg)
            .map_err(|error| serde::de::Error::custom(format!("{error:?}")))
    }
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            exit_clamp: default_exit_clamp(),
            regions: Vec::new(),
            min_rssi: None,
            min_snr: None,
            cache_entries: default_cache_entries(),
            confirmation_window_secs: default_confirmation_window(),
            flood_contention_ms: default_flood_contention(),
        }
    }
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            keepalive_secs: default_keepalive(),
            idle_timeout_secs: default_idle_timeout(),
            max_frame_age_secs: default_max_frame_age(),
            queue_depth: default_queue_depth(),
            reconnect_min_secs: default_reconnect_min(),
            reconnect_max_secs: default_reconnect_max(),
        }
    }
}

fn default_listen() -> Vec<SocketAddr> {
    vec![
        SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)),
        SocketAddr::from(([0u16; 8], DEFAULT_PORT)),
    ]
}

fn default_exit_clamp() -> u8 {
    1
}
fn default_cache_entries() -> usize {
    128
}
fn default_confirmation_window() -> u64 {
    30
}
fn default_flood_contention() -> u64 {
    1_600
}
fn default_keepalive() -> u64 {
    10
}
fn default_idle_timeout() -> u64 {
    30
}
fn default_max_frame_age() -> u64 {
    10
}
fn default_queue_depth() -> usize {
    32
}
fn default_reconnect_min() -> u64 {
    1
}
fn default_reconnect_max() -> u64 {
    60
}
fn default_baud() -> u32 {
    115_200
}
fn default_udp_group() -> Ipv4Addr {
    Ipv4Addr::new(239, 255, 42, 42)
}
fn default_udp_port() -> u16 {
    7373
}
fn default_udp_rssi() -> i16 {
    -40
}
fn default_udp_snr() -> i8 {
    10
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Everything the type system and serde cannot say.
    pub fn validate(&self) -> Result<()> {
        match (&self.server, &self.client) {
            (Some(_), Some(_)) => {
                bail!("give either [server] or [client], not both: one process is one role")
            }
            (None, None) => bail!("no role configured: add a [server] or [client] section"),
            (Some(server), None) => {
                if self.identity.is_none() {
                    bail!("a bridge server owns the bridge's node identity; add [identity]");
                }
                server.validate()
            }
            (None, Some(client)) => {
                if self.identity.is_none() {
                    bail!(
                        "a client authenticates the tunnel with its own identity; add [identity]"
                    );
                }
                client.validate()
            }
        }
    }
}

impl ServerConfig {
    fn validate(&self) -> Result<()> {
        if self.listen.is_empty() {
            bail!("[server] listen is empty; the server would accept nothing");
        }
        if self.clients.is_empty() && self.radio.is_none() {
            bail!("[server] has no clients and no radio; there is nothing to bridge");
        }
        if self.forwarding.exit_clamp > 15 {
            bail!(
                "[server.forwarding] exit_clamp is {}; FHOPS_REM is four bits and holds at most 15",
                self.forwarding.exit_clamp
            );
        }
        if self.forwarding.cache_entries == 0 {
            bail!("[server.forwarding] cache_entries must be at least 1");
        }
        if self.tunnel.queue_depth == 0 {
            bail!("[server.tunnel] queue_depth must be at least 1");
        }
        if self.tunnel.idle_timeout_secs <= self.tunnel.keepalive_secs {
            bail!(
                "[server.tunnel] idle_timeout_secs ({}) must exceed keepalive_secs ({}), or a \
                 healthy peer times out between its own keepalives",
                self.tunnel.idle_timeout_secs,
                self.tunnel.keepalive_secs
            );
        }

        let mut names = HashSet::new();
        let mut addresses = HashSet::new();
        for client in &self.clients {
            if client.name == RADIO_INTERFACE {
                bail!("client name \"{RADIO_INTERFACE}\" is reserved for the server's own radio");
            }
            if client.name.trim().is_empty() {
                bail!("every [[server.clients]] needs a name; it is how policy refers to it");
            }
            if !names.insert(client.name.as_str()) {
                bail!("two [[server.clients]] are both named \"{}\"", client.name);
            }
            if !addresses.insert(client.address) {
                bail!(
                    "client \"{}\" shares an address with another; an identity names exactly \
                     one client",
                    client.name
                );
            }
        }

        for client in &self.clients {
            let Some(allow_to) = &client.allow_to else {
                continue;
            };
            for target in allow_to {
                if target == RADIO_INTERFACE {
                    if self.radio.is_none() {
                        bail!(
                            "client \"{}\" allows forwarding to \"{RADIO_INTERFACE}\", but \
                             [server.radio] is none",
                            client.name
                        );
                    }
                    continue;
                }
                if !names.contains(target.as_str()) {
                    bail!(
                        "client \"{}\" allows forwarding to \"{target}\", which is not a \
                         configured client",
                        client.name
                    );
                }
            }
        }
        Ok(())
    }

    /// Every interface name this server can forward to, radio first.
    pub fn interface_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if !self.radio.is_none() {
            names.push(RADIO_INTERFACE.to_string());
        }
        names.extend(self.clients.iter().map(|client| client.name.clone()));
        names
    }
}

impl ClientConfig {
    fn validate(&self) -> Result<()> {
        if self.radio.is_none() {
            bail!("[client.radio] is none; a client with no radio relays nothing");
        }
        if self.tunnel.queue_depth == 0 {
            bail!("[client.tunnel] queue_depth must be at least 1");
        }
        if self.tunnel.idle_timeout_secs <= self.tunnel.keepalive_secs {
            bail!(
                "[client.tunnel] idle_timeout_secs ({}) must exceed keepalive_secs ({})",
                self.tunnel.idle_timeout_secs,
                self.tunnel.keepalive_secs
            );
        }
        if self.tunnel.reconnect_max_secs < self.tunnel.reconnect_min_secs {
            bail!("[client.tunnel] reconnect_max_secs is below reconnect_min_secs");
        }
        if !self.server.contains(':') {
            bail!(
                "[client] server \"{}\" needs a port; the bridge default is {DEFAULT_PORT}",
                self.server
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real address, since config parsing validates the curve point.
    fn address(seed: u8) -> String {
        use umsh_crypto::NodeIdentity as _;
        umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&[seed; 32])
            .public_key()
            .to_string()
    }

    fn parse(text: &str) -> Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    fn server_config(extra: &str) -> String {
        format!(
            "[identity]\nkey_file = \"/etc/umsh-bridge/identity.key\"\n\
             [server]\n{extra}"
        )
    }

    #[test]
    fn a_minimal_server_takes_every_default() {
        let config = parse(&server_config(
            "[server.radio]\ntype = \"serial\"\nport = \"/dev/ttyACM0\"\n",
        ))
        .unwrap();
        let server = config.server.unwrap();
        assert_eq!(server.listen.len(), 2, "both address families by default");
        assert_eq!(server.forwarding.exit_clamp, 1);
        assert_eq!(server.tunnel.keepalive_secs, 10);
        assert_eq!(server.tunnel.idle_timeout_secs, 30);
        assert!(matches!(
            server.radio,
            RadioConfig::Serial { baud: 115_200, .. }
        ));
    }

    #[test]
    fn each_radio_type_parses() {
        for radio in [
            "type = \"serial\"\nport = \"/dev/ttyACM0\"\nbaud = 921600",
            "type = \"ble\"\nselector = \"UMSH T-Echo\"",
            "type = \"ble\"",
            "type = \"udp-multicast\"\ngroup = \"239.255.42.43\"\nport = 7374",
            "type = \"udp-multicast\"",
        ] {
            let text = server_config(&format!("[server.radio]\n{radio}\n"));
            parse(&text).unwrap_or_else(|error| panic!("{radio}: {error}"));
        }
    }

    #[test]
    fn a_role_is_required_and_exclusive() {
        assert!(parse("[identity]\nkey_file = \"k\"\n").is_err());
        let both = format!(
            "{}\n[client]\nserver = \"h:21837\"\nserver_address = \"{}\"\n",
            server_config("[server.radio]\ntype = \"ble\"\n"),
            address(1)
        );
        assert!(parse(&both).is_err());
    }

    #[test]
    fn either_role_without_an_identity_is_rejected() {
        let text = "[server]\n[server.radio]\ntype = \"ble\"\n";
        let error = parse(text).unwrap_err().to_string();
        assert!(error.contains("[identity]"), "{error}");

        let text = format!(
            "[client]\nserver = \"h:21837\"\nserver_address = \"{}\"\n\
             [client.radio]\ntype = \"ble\"\n",
            address(1)
        );
        let error = parse(&text).unwrap_err().to_string();
        assert!(error.contains("[identity]"), "{error}");
    }

    #[test]
    fn an_address_that_is_not_a_key_fails_the_parse() {
        // 64 hex digits that are not a curve point, found by search.
        let junk = (0u8..=255)
            .map(|byte| {
                let mut key = [0u8; 32];
                key[0] = byte;
                umsh_core::PublicKey(key)
            })
            .find(|key| !umsh_crypto::is_valid_ed25519_public_key(key))
            .unwrap();
        let text = server_config(&format!(
            "[server.radio]\ntype = \"ble\"\n\
             [[server.clients]]\nname = \"myclient\"\naddress = \"{junk:x}\"\n"
        ));
        let error = parse(&text).unwrap_err().to_string();
        assert!(error.contains("Ed25519"), "{error}");
    }

    #[test]
    fn unknown_keys_are_rejected_rather_than_ignored() {
        let text = server_config("[server.radio]\ntype = \"ble\"\nbored = true\n");
        assert!(parse(&text).is_err(), "unknown key inside a radio table");
        let text = server_config("[server.forwarding]\nexit_clamps = 2\n");
        assert!(parse(&text).is_err(), "near-miss key name");
        let text = server_config("[server.radio]\ntype = \"telepathy\"\n");
        assert!(parse(&text).is_err(), "unknown radio type");
    }

    #[test]
    fn a_key_belonging_to_another_radio_type_is_named_in_the_error() {
        let text = server_config("[server.radio]\ntype = \"ble\"\nbaud = 115200\n");
        let error = parse(&text).unwrap_err().to_string();
        assert!(error.contains("baud"), "{error}");
        assert!(error.contains("ble"), "{error}");

        // `port` is a device path for one radio and a number for
        // another, so the type is what decides whether it is well formed.
        let text = server_config("[server.radio]\ntype = \"serial\"\nport = 7373\n");
        assert!(parse(&text).is_err());
        let text = server_config("[server.radio]\ntype = \"udp-multicast\"\nport = \"/dev/x\"\n");
        assert!(parse(&text).is_err());
    }

    #[test]
    fn a_unicast_multicast_group_is_rejected() {
        let text =
            server_config("[server.radio]\ntype = \"udp-multicast\"\ngroup = \"192.168.1.1\"\n");
        assert!(parse(&text).is_err());
    }

    #[test]
    fn allow_to_must_name_a_real_interface() {
        let text = server_config(&format!(
            "[server.radio]\ntype = \"ble\"\n\
             [[server.clients]]\nname = \"cabin\"\naddress = \"{}\"\n\
             allow_to = [\"radio\", \"summit\"]\n",
            address(2)
        ));
        let error = parse(&text).unwrap_err().to_string();
        assert!(error.contains("summit"), "{error}");
    }

    #[test]
    fn allow_to_radio_needs_a_radio() {
        let text = server_config(&format!(
            "[[server.clients]]\nname = \"cabin\"\naddress = \"{}\"\n\
             allow_to = [\"radio\"]\n",
            address(2)
        ));
        assert!(parse(&text).is_err());
    }

    #[test]
    fn one_identity_names_one_client() {
        let text = server_config(&format!(
            "[[server.clients]]\nname = \"cabin\"\naddress = \"{0}\"\n\
             [[server.clients]]\nname = \"summit\"\naddress = \"{0}\"\n",
            address(2)
        ));
        let error = parse(&text).unwrap_err().to_string();
        assert!(error.contains("address"), "{error}");

        let text = server_config(&format!(
            "[[server.clients]]\nname = \"cabin\"\naddress = \"{}\"\n\
             [[server.clients]]\nname = \"cabin\"\naddress = \"{}\"\n",
            address(2),
            address(3)
        ));
        assert!(parse(&text).is_err(), "duplicate names");
    }

    #[test]
    fn the_radio_interface_name_is_reserved() {
        let text = server_config(&format!(
            "[server.radio]\ntype = \"ble\"\n\
             [[server.clients]]\nname = \"radio\"\naddress = \"{}\"\n",
            address(2)
        ));
        assert!(parse(&text).is_err());
    }

    #[test]
    fn a_server_that_bridges_nothing_is_rejected() {
        assert!(parse(&server_config("")).is_err());
    }

    #[test]
    fn an_idle_timeout_must_outlast_a_keepalive() {
        let text = server_config(
            "[server.radio]\ntype = \"ble\"\n\
             [server.tunnel]\nkeepalive_secs = 30\nidle_timeout_secs = 30\n",
        );
        assert!(parse(&text).is_err());
    }

    #[test]
    fn channel_access_is_not_a_deployment_knob() {
        // The backoff procedure is the MAC's, and nodes sharing a
        // segment must share it; a per-deployment override would be a
        // way to be wrong locally.
        let text = server_config(
            "[server.radio]\ntype = \"ble\"\n[server.transmit]\ncca_retry_ms = 15000\n",
        );
        assert!(parse(&text).is_err());
    }

    #[test]
    fn exit_clamp_is_bounded_by_the_field_it_writes() {
        let text =
            server_config("[server.radio]\ntype = \"ble\"\n[server.forwarding]\nexit_clamp = 16\n");
        assert!(parse(&text).is_err());
        let text =
            server_config("[server.radio]\ntype = \"ble\"\n[server.forwarding]\nexit_clamp = 15\n");
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn a_client_needs_a_radio_and_a_port() {
        let client = |server: &str, radio: &str| {
            format!(
                "[identity]\nkey_file = \"/etc/umsh-bridge/identity.key\"\n\
                 [client]\nserver = \"{server}\"\nserver_address = \"{}\"\n{radio}",
                address(1)
            )
        };
        assert!(
            parse(&client(
                "bridge.example.net:21837",
                "[client.radio]\ntype = \"ble\"\n"
            ))
            .is_ok()
        );
        assert!(
            parse(&client(
                "bridge.example.net",
                "[client.radio]\ntype = \"ble\"\n"
            ))
            .is_err()
        );
        assert!(parse(&client("bridge.example.net:21837", "")).is_err());
    }

    #[test]
    fn regions_accept_every_spelling_the_spec_does() {
        let text = server_config(
            "[server.radio]\ntype = \"ble\"\n\
             [server.forwarding]\nregions = [\"SJC\", \"0x7853\", \"Rogue Valley\"]\n",
        );
        let config = parse(&text).unwrap();
        let regions = &config.server.unwrap().forwarding.regions;
        assert_eq!(regions.len(), 3);
        assert_eq!(regions[1].0.as_u16(), 0x7853);
    }
}
