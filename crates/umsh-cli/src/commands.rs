//! Parsed-command enum and parser. The dispatcher lives in
//! [`crate::session`].

use alloc::string::String;

/// A parsed CLI input line. Borrows from the input buffer — the caller is
/// expected to own that buffer on the stack while dispatching.
#[derive(Debug, PartialEq, Eq)]
pub enum Command<'a> {
    Help(Option<&'a str>),
    Quit,
    WhoAmI,

    PeerAdd { pubkey: &'a str, alias: Option<&'a str> },
    PeerAlias { peer: &'a str, alias: &'a str },
    PeerRm { peer: &'a str },
    Peers,

    Query { peer: &'a str },
    Msg { peer: &'a str, text: &'a str },
    Text { body: &'a str }, // bare line → current peer
    Me { action: &'a str },

    Ping { peer: &'a str, bytes: Option<u16> },

    PfsStart { peer: &'a str, minutes: Option<u16> },
    PfsEnd { peer: &'a str },
    PfsStatus { peer: Option<&'a str> },

    Beacon,

    ChannelJoin { name: &'a str, key: &'a str },
    ChannelLeave { name: &'a str },
    ChannelSend { name: &'a str, text: &'a str },
    Channels,

    Stats,
    Counters,
    Log { level: &'a str },
    SetShow,                              // `/set` (no args)
    Set { var: &'a str, val: &'a str },
    Raw { peer: &'a str, hex: &'a str },

    PowerOff,
    Reboot,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    UnknownCommand(String),
    MissingArg(&'static str),
    BadNumber,
}

/// Parse one input line. Bare text lines (no leading `/`) become `Text`.
pub fn parse(line: &str) -> Result<Command<'_>, ParseError> {
    let line = line.trim();
    if line.is_empty() {
        return Err(ParseError::Empty);
    }
    if !line.starts_with('/') {
        return Ok(Command::Text { body: line });
    }
    let (head, rest) = split_one(&line[1..]);
    match head {
        "help" | "?" => Ok(Command::Help(if rest.is_empty() { None } else { Some(rest) })),
        "quit" | "exit" => Ok(Command::Quit),
        "whoami" => Ok(Command::WhoAmI),

        "peer" => parse_peer(rest),
        "peers" => Ok(Command::Peers),
        "query" => {
            let (peer, _) = split_one(rest);
            require(peer, "peer-ref")?;
            Ok(Command::Query { peer })
        }
        "msg" => {
            let (peer, tail) = split_one(rest);
            require(peer, "peer-ref")?;
            require(tail, "text")?;
            Ok(Command::Msg { peer, text: tail })
        }
        "me" => {
            require(rest, "action")?;
            Ok(Command::Me { action: rest })
        }
        "ping" => {
            let (peer, tail) = split_one(rest);
            require(peer, "peer-ref")?;
            let bytes = if tail.is_empty() {
                None
            } else {
                Some(tail.parse::<u16>().map_err(|_| ParseError::BadNumber)?)
            };
            Ok(Command::Ping { peer, bytes })
        }
        "pfs" => parse_pfs(rest),
        "beacon" => Ok(Command::Beacon),
        "channel" => parse_channel(rest),
        "channels" => Ok(Command::Channels),
        "stats" => Ok(Command::Stats),
        "counters" => Ok(Command::Counters),
        "log" => {
            require(rest, "level")?;
            Ok(Command::Log { level: rest })
        }
        "set" => {
            if rest.is_empty() {
                return Ok(Command::SetShow);
            }
            let (var, val) = split_one(rest);
            require(var, "var")?;
            require(val, "value")?;
            Ok(Command::Set { var, val })
        }
        "raw" => {
            let (peer, hex) = split_one(rest);
            require(peer, "peer-ref")?;
            require(hex, "hex")?;
            Ok(Command::Raw { peer, hex })
        }
        "poweroff" | "off" => Ok(Command::PowerOff),
        "reboot" => Ok(Command::Reboot),

        other => {
            let mut s = String::new();
            s.push_str(other);
            Err(ParseError::UnknownCommand(s))
        }
    }
}

fn parse_peer(rest: &str) -> Result<Command<'_>, ParseError> {
    let (sub, tail) = split_one(rest);
    match sub {
        "add" => {
            let (pubkey, alias_part) = split_one(tail);
            require(pubkey, "pubkey")?;
            let alias = if alias_part.is_empty() { None } else { Some(alias_part) };
            Ok(Command::PeerAdd { pubkey, alias })
        }
        "alias" => {
            let (peer, alias) = split_one(tail);
            require(peer, "peer-ref")?;
            require(alias, "alias")?;
            Ok(Command::PeerAlias { peer, alias })
        }
        "rm" | "remove" => {
            let (peer, _) = split_one(tail);
            require(peer, "peer-ref")?;
            Ok(Command::PeerRm { peer })
        }
        _ => Err(ParseError::UnknownCommand(format_str("peer ", sub))),
    }
}

fn parse_pfs(rest: &str) -> Result<Command<'_>, ParseError> {
    let (sub, tail) = split_one(rest);
    match sub {
        "start" => {
            let (peer, mins_part) = split_one(tail);
            require(peer, "peer-ref")?;
            let minutes = if mins_part.is_empty() {
                None
            } else {
                Some(mins_part.parse::<u16>().map_err(|_| ParseError::BadNumber)?)
            };
            Ok(Command::PfsStart { peer, minutes })
        }
        "end" => {
            let (peer, _) = split_one(tail);
            require(peer, "peer-ref")?;
            Ok(Command::PfsEnd { peer })
        }
        "status" => {
            let (peer, _) = split_one(tail);
            Ok(Command::PfsStatus {
                peer: if peer.is_empty() { None } else { Some(peer) },
            })
        }
        _ => Err(ParseError::UnknownCommand(format_str("pfs ", sub))),
    }
}

fn parse_channel(rest: &str) -> Result<Command<'_>, ParseError> {
    let (sub, tail) = split_one(rest);
    match sub {
        "join" => {
            let (name, key) = split_one(tail);
            require(name, "channel name")?;
            require(key, "key")?;
            Ok(Command::ChannelJoin { name, key })
        }
        "leave" => {
            let (name, _) = split_one(tail);
            require(name, "channel name")?;
            Ok(Command::ChannelLeave { name })
        }
        "send" => {
            let (name, text) = split_one(tail);
            require(name, "channel name")?;
            require(text, "text")?;
            Ok(Command::ChannelSend { name, text })
        }
        _ => Err(ParseError::UnknownCommand(format_str("channel ", sub))),
    }
}

fn require(s: &str, name: &'static str) -> Result<(), ParseError> {
    if s.is_empty() {
        Err(ParseError::MissingArg(name))
    } else {
        Ok(())
    }
}

fn split_one(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    match s.find(|c: char| c.is_whitespace()) {
        Some(idx) => (&s[..idx], s[idx..].trim_start()),
        None => (s, ""),
    }
}

fn format_str(prefix: &str, s: &str) -> String {
    let mut out = String::new();
    out.push_str(prefix);
    out.push_str(s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_text() {
        assert_eq!(parse("hello world"), Ok(Command::Text { body: "hello world" }));
    }

    #[test]
    fn quit_and_aliases() {
        assert_eq!(parse("/quit"), Ok(Command::Quit));
        assert_eq!(parse("/exit"), Ok(Command::Quit));
    }

    #[test]
    fn peer_add_with_alias() {
        assert_eq!(
            parse("/peer add ABCDEF bob"),
            Ok(Command::PeerAdd { pubkey: "ABCDEF", alias: Some("bob") })
        );
    }

    #[test]
    fn peer_alias() {
        assert_eq!(
            parse("/peer alias bob alice"),
            Ok(Command::PeerAlias { peer: "bob", alias: "alice" })
        );
    }

    #[test]
    fn ping_with_bytes() {
        assert_eq!(
            parse("/ping bob 64"),
            Ok(Command::Ping { peer: "bob", bytes: Some(64) })
        );
    }

    #[test]
    fn set_show_vs_set() {
        assert_eq!(parse("/set"), Ok(Command::SetShow));
        assert_eq!(parse("/set flood_hops 3"),
                   Ok(Command::Set { var: "flood_hops", val: "3" }));
    }

    #[test]
    fn counters() {
        assert_eq!(parse("/counters"), Ok(Command::Counters));
    }

    #[test]
    fn reboot() {
        assert_eq!(parse("/reboot"), Ok(Command::Reboot));
    }

    #[test]
    fn unknown_cmd() {
        assert!(matches!(parse("/wut"), Err(ParseError::UnknownCommand(_))));
    }
}
