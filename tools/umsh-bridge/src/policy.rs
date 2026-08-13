//! Who may send how much, and where it may go.
//!
//! Two things live here, and they exist for the same reason. An
//! authenticated but misbehaving client is the realistic failure mode of
//! a bridge, so the per-client rate limit is policy rather than a
//! backstop — the device's duty ledger is the backstop. And two clients
//! whose radios share a segment double every fanned-out frame's airtime,
//! which the egress allowlist is the place to prevent.
//!
//! Both are decisions about a connection, not about a packet: the bridge
//! reads neither. What a packet is, whether it has been seen before, and
//! whether it is worth putting on the air are questions for the repeater
//! behind each participant's radio.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::time::Instant;

use crate::config::ServerConfig;
use crate::iface::{InterfaceId, Interfaces};

pub struct Policy {
    /// Indexed by client index, parallel to `ServerConfig::clients`.
    clients: Vec<ClientPolicy>,
}

struct ClientPolicy {
    name: String,
    limit: Option<RateLimit>,
    /// Interfaces this client's traffic may leave through. `None` means
    /// all of them.
    allow_to: Option<HashSet<InterfaceId>>,
}

impl Policy {
    /// Resolve the configured names against the interfaces that exist.
    pub fn build(config: &ServerConfig, interfaces: &Interfaces) -> Result<Self> {
        let clients = config
            .clients
            .iter()
            .map(|client| {
                let allow_to = client
                    .allow_to
                    .as_ref()
                    .map(|names| {
                        names
                            .iter()
                            .map(|name| {
                                interfaces
                                    .all
                                    .iter()
                                    .find(|iface| &iface.name == name)
                                    .map(|iface| iface.id)
                                    .ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "client \"{}\" allows forwarding to \"{name}\", \
                                             which is not an interface",
                                            client.name
                                        )
                                    })
                            })
                            .collect::<Result<HashSet<_>>>()
                    })
                    .transpose()?;
                Ok(ClientPolicy {
                    name: client.name.clone(),
                    limit: client.max_frames_per_minute.map(RateLimit::per_minute),
                    allow_to,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        if config.radio.is_none()
            && clients
                .iter()
                .all(|client| client.allow_to.as_ref().is_some_and(HashSet::is_empty))
        {
            bail!("every client's allow_to is empty; no frame could ever be forwarded");
        }

        Ok(Self { clients })
    }

    /// Spend one from the arrival interface's forwarding budget.
    ///
    /// The server's own radio has no budget: a bridge that rate-limited
    /// its own segment would be throttling the mesh it is part of, not a
    /// remote peer it is protecting itself from.
    pub fn admit(&mut self, interfaces: &Interfaces, arrival: InterfaceId, now: Instant) -> bool {
        let Some(client) = interfaces.get(arrival).client else {
            return true;
        };
        let policy = &mut self.clients[client];
        let Some(limit) = policy.limit.as_mut() else {
            return true;
        };
        if limit.take(now) {
            return true;
        }
        // Once per interval, not once per frame: a client hammering the
        // tunnel must not also flood the log.
        if limit.note_refusal(now) {
            tracing::warn!(
                client = %policy.name,
                "rate limit reached; frames from this client are being dropped"
            );
        }
        false
    }

    /// Whether a frame that arrived on `arrival` may leave through
    /// `exit`.
    pub fn may_forward(
        &self,
        interfaces: &Interfaces,
        arrival: InterfaceId,
        exit: InterfaceId,
    ) -> bool {
        if arrival == exit {
            return false;
        }
        match interfaces.get(arrival).client {
            None => true,
            Some(client) => match &self.clients[client].allow_to {
                None => true,
                Some(allowed) => allowed.contains(&exit),
            },
        }
    }

    /// How the configured egress rules read, for `check` and start-up
    /// logging.
    pub fn describe_fan_out(&self, interfaces: &Interfaces, arrival: InterfaceId) -> String {
        let names: Vec<&str> = interfaces
            .all
            .iter()
            .filter(|iface| self.may_forward(interfaces, arrival, iface.id))
            .map(|iface| iface.name.as_str())
            .collect();
        if names.is_empty() {
            "nothing".to_string()
        } else {
            names.join(", ")
        }
    }
}

/// A token bucket that refills continuously, so a client may burst up to
/// its whole minute's allowance and then settles to the steady rate.
struct RateLimit {
    capacity: f64,
    per_second: f64,
    tokens: f64,
    updated: Option<Instant>,
    last_complaint: Option<Instant>,
}

/// How often a rate-limited client is mentioned in the log.
const COMPLAINT_INTERVAL: Duration = Duration::from_secs(60);

impl RateLimit {
    fn per_minute(frames: u32) -> Self {
        let capacity = f64::from(frames.max(1));
        Self {
            capacity,
            per_second: capacity / 60.0,
            tokens: capacity,
            updated: None,
            last_complaint: None,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        if let Some(updated) = self.updated {
            let elapsed = now.saturating_duration_since(updated).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.per_second).min(self.capacity);
        }
        self.updated = Some(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn note_refusal(&mut self, now: Instant) -> bool {
        let due = self
            .last_complaint
            .is_none_or(|last| now.saturating_duration_since(last) >= COMPLAINT_INTERVAL);
        if due {
            self.last_complaint = Some(now);
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn parse(extra: &str) -> (ServerConfig, Interfaces, Policy) {
        let text = format!("[identity]\nkey_file = \"k\"\n[server]\n{extra}");
        let config: Config = toml::from_str(&text).unwrap();
        config.validate().unwrap();
        let server = config.server.unwrap();
        let interfaces = Interfaces::build(&server);
        let policy = Policy::build(&server, &interfaces).unwrap();
        (server, interfaces, policy)
    }

    /// A pinned-client address the fixtures can use.
    fn address(seed: u8) -> String {
        use umsh_crypto::NodeIdentity as _;
        umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&[seed; 32])
            .public_key()
            .to_string()
    }

    fn two_clients(extra: &str) -> (ServerConfig, Interfaces, Policy) {
        parse(&format!(
            "[server.radio]\ntype = \"ble\"\n\
             [[server.clients]]\nname = \"cabin\"\naddress = \"{}\"\n{extra}\
             [[server.clients]]\nname = \"summit\"\naddress = \"{}\"\n",
            address(0xAA),
            address(0xBB)
        ))
    }

    #[test]
    fn a_frame_never_goes_back_out_the_way_it_came() {
        let (_, interfaces, policy) = two_clients("");
        for iface in &interfaces.all {
            assert!(!policy.may_forward(&interfaces, iface.id, iface.id));
        }
    }

    #[test]
    fn an_absent_allowlist_means_every_other_interface() {
        let (_, interfaces, policy) = two_clients("");
        let cabin = interfaces.by_client(0).unwrap().id;
        assert_eq!(
            policy.describe_fan_out(&interfaces, cabin),
            "radio, summit",
            "the arrival interface is excluded, the rest are not"
        );
    }

    #[test]
    fn an_allowlist_is_the_whole_list() {
        let (_, interfaces, policy) = two_clients("allow_to = [\"radio\"]\n");
        let cabin = interfaces.by_client(0).unwrap().id;
        assert_eq!(policy.describe_fan_out(&interfaces, cabin), "radio");

        // Two clients on the same segment: excluding one from the
        // other's fan-out is how the duplicate airtime is avoided.
        let summit = interfaces.by_client(1).unwrap().id;
        assert!(!policy.may_forward(&interfaces, cabin, summit));
        assert!(
            policy.may_forward(&interfaces, summit, cabin),
            "the rule is per-arrival, not symmetric"
        );
    }

    #[test]
    fn the_servers_own_radio_forwards_everywhere_regardless() {
        let (_, interfaces, policy) = two_clients("allow_to = []\n");
        let radio = interfaces.radio.unwrap();
        assert_eq!(policy.describe_fan_out(&interfaces, radio), "cabin, summit");
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_spends_a_budget_that_refills_over_the_minute() {
        let (_, interfaces, mut policy) = two_clients("max_frames_per_minute = 60\n");
        let cabin = interfaces.by_client(0).unwrap().id;

        // The full minute's allowance is available as a burst.
        for _ in 0..60 {
            assert!(policy.admit(&interfaces, cabin, Instant::now()));
        }
        assert!(!policy.admit(&interfaces, cabin, Instant::now()));

        // One frame per second thereafter.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(policy.admit(&interfaces, cabin, Instant::now()));
        assert!(!policy.admit(&interfaces, cabin, Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn the_servers_own_radio_and_an_unlimited_client_are_never_refused() {
        let (_, interfaces, mut policy) = two_clients("");
        let radio = interfaces.radio.unwrap();
        let cabin = interfaces.by_client(0).unwrap().id;
        for _ in 0..1000 {
            assert!(policy.admit(&interfaces, radio, Instant::now()));
            assert!(policy.admit(&interfaces, cabin, Instant::now()));
        }
    }
}
