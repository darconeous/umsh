//! Bridge client configuration and connection status (device domain).
pub const HOST_MAX: usize = 253;
pub const DEFAULT_PORT: u16 = 21837;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    #[default]
    Disabled = 0,
    Unconfigured = 1,
    WaitingForNetwork = 2,
    Connecting = 3,
    Connected = 4,
    Retrying = 5,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Reason {
    #[default]
    None = 0,
    Dns = 1,
    Tcp = 2,
    Tls = 3,
    Authentication = 4,
    IdleTimeout = 5,
    IdentityUnavailable = 6,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub state: State,
    pub reason: Reason,
}

impl Link {
    pub const fn new(state: State, reason: Reason) -> Self {
        Self { state, reason }
    }
    pub const fn encode(self) -> [u8; 2] {
        [self.state as u8, self.reason as u8]
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let [state, reason] = bytes else {
            return None;
        };
        Some(Self {
            state: match state {
                0 => State::Disabled,
                1 => State::Unconfigured,
                2 => State::WaitingForNetwork,
                3 => State::Connecting,
                4 => State::Connected,
                5 => State::Retrying,
                _ => return None,
            },
            reason: match reason {
                0 => Reason::None,
                1 => Reason::Dns,
                2 => Reason::Tcp,
                3 => Reason::Tls,
                4 => Reason::Authentication,
                5 => Reason::IdleTimeout,
                6 => Reason::IdentityUnavailable,
                _ => return None,
            },
        })
    }
}

/// DNS A-label hostname or unbracketed IP literal; empty clears the endpoint.
pub fn valid_host(host: &str) -> bool {
    if host.is_empty() {
        return true;
    }
    if host.len() > HOST_MAX || !host.is_ascii() {
        return false;
    }
    if host.contains(':') {
        return host.parse::<core::net::Ipv6Addr>().is_ok();
    }
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return host.parse::<core::net::Ipv4Addr>().is_ok();
    }
    host.strip_suffix('.')
        .unwrap_or(host)
        .split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hosts_are_endpoints_not_urls() {
        for host in [
            "",
            "bridge.example.net",
            "bridge.example.net.",
            "127.0.0.1",
            "::1",
            "2001:db8::1",
        ] {
            assert!(valid_host(host), "{host}");
        }
        for host in [
            "https://bridge",
            "bridge:21837",
            "[::1]",
            "a..b",
            "-a",
            "a-",
            "999.0.0.1",
            "a\0b",
            "b ridge",
        ] {
            assert!(!valid_host(host), "{host}");
        }
    }
    #[test]
    fn status_round_trips_and_rejects_unknown_codes() {
        let link = Link::new(State::Retrying, Reason::Authentication);
        assert_eq!(Link::decode(&link.encode()), Some(link));
        for bytes in [&[][..], &[0], &[6, 0], &[0, 7], &[0, 0, 0]] {
            assert!(Link::decode(bytes).is_none());
        }
    }
}
