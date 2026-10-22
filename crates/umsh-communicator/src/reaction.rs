//! Reactions: emotes about a message, folded into it.
//!
//! On the wire a reaction is a status message regarding its target, its
//! body one of UMSH's emote tokens or an emoji; an empty body withdraws
//! the sender's earlier one. The store keeps the latest from each sender
//! inside the target, and counts them by reaction when the message is
//! read.

use alloc::vec::Vec;
use core::fmt;

/// The longest grapheme cluster a reaction keeps, in bytes: room for a
/// joined family or a subdivision's flag.
pub const CLUSTER_MAX: usize = 31;

/// The most kinds of reaction a message counts.
pub const REACTIONS: usize = 8;

/// One grapheme cluster, held in place so a reaction stays `Copy`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cluster {
    len: u8,
    bytes: [u8; CLUSTER_MAX],
}

impl Cluster {
    /// `cluster`, unless it is longer than [`CLUSTER_MAX`].
    #[must_use]
    pub fn new(cluster: &str) -> Option<Self> {
        let mut bytes = [0; CLUSTER_MAX];
        bytes
            .get_mut(..cluster.len())?
            .copy_from_slice(cluster.as_bytes());
        Some(Self {
            len: cluster.len() as u8,
            bytes,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or_default()
    }
}

impl fmt::Debug for Cluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

/// A reaction: one of UMSH's emote tokens, or another emoji.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reaction {
    Heart,
    ThumbsUp,
    ThumbsDown,
    Laugh,
    Exclaim,
    Question,
    /// Any other: the first grapheme cluster of its body.
    Other(Cluster),
}

impl Reaction {
    /// The palette, in the order it is offered.
    pub const ALL: [Self; 6] = [
        Self::Heart,
        Self::ThumbsUp,
        Self::ThumbsDown,
        Self::Laugh,
        Self::Exclaim,
        Self::Question,
    ];

    /// The reaction's body on the air: an emote's token, or the cluster.
    #[must_use]
    pub fn body(&self) -> &str {
        match self {
            Self::Heart => "<3",
            Self::ThumbsUp => "+1",
            Self::ThumbsDown => "-1",
            Self::Laugh => "ha",
            Self::Exclaim => "!",
            Self::Question => "?",
            Self::Other(cluster) => cluster.as_str(),
        }
    }

    /// The reaction a body stands for.
    ///
    /// Reading is looser than writing, as it is on iOS: the tokens, their
    /// longer spellings, and the emoji other clients send all count as
    /// their emote, and a body that is none of them counts as its first
    /// grapheme cluster, so 👍🏽 stays whole. A cluster that is a letter or
    /// a digit, as in a word, is no reaction.
    pub fn from_body(body: &str) -> Option<Self> {
        let trimmed = body.trim();
        let first = umsh_grapheme::first_cluster(trimmed)?;
        Self::spelled(trimmed)
            .or_else(|| Self::spelled(first))
            .or_else(|| {
                // A keycap starts with its digit.
                let pictured = first.contains(['\u{FE0F}', '\u{20E3}'])
                    || !first.starts_with(char::is_alphanumeric);
                pictured
                    .then(|| Cluster::new(first))
                    .flatten()
                    .map(Self::Other)
            })
    }

    fn spelled(body: &str) -> Option<Self> {
        let mut lower = [0u8; 16];
        let body = ascii_lowercase(body, &mut lower)?;
        Some(match body {
            "<3" | "\u{2665}" | "\u{2665}\u{fe0e}" | "\u{2764}" | "\u{2764}\u{fe0f}"
            | "\u{1fa77}" => Self::Heart,
            "+1" | "\u{1f44d}" => Self::ThumbsUp,
            "-1" | "\u{1f44e}" => Self::ThumbsDown,
            "ha" | "haha" | "hahaha" | "lol" | "lmao" | "\u{1f923}" => Self::Laugh,
            "!" | "!!" | "\u{2757}" | "\u{2755}" | "\u{203c}\u{fe0f}" | "\u{203c}" => Self::Exclaim,
            "?" | "??" | "\u{2753}" | "\u{2754}" => Self::Question,
            _ => match strip_skin_tone(body) {
                "\u{1f44d}" => Self::ThumbsUp,
                "\u{1f44e}" => Self::ThumbsDown,
                _ => return None,
            },
        })
    }
}

/// `body` lowercased, when it is short enough to be a spelling at all.
fn ascii_lowercase<'b>(body: &str, out: &'b mut [u8; 16]) -> Option<&'b str> {
    let bytes = body.as_bytes();
    let out = out.get_mut(..bytes.len())?;
    out.copy_from_slice(bytes);
    out.make_ascii_lowercase();
    core::str::from_utf8(out).ok()
}

/// A thumb without the skin-tone modifier after it.
fn strip_skin_tone(body: &str) -> &str {
    let mut chars = body.char_indices();
    match (chars.next(), chars.next(), chars.next()) {
        (Some(_), Some((at, '\u{1f3fb}'..='\u{1f3ff}')), None) => &body[..at],
        _ => body,
    }
}

/// Everyone who reacted to a message one way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reacted {
    pub reaction: Reaction,
    pub count: u16,
    /// One of them is this node.
    pub mine: bool,
}

/// A message's reactions, one entry per reaction, in the order each first
/// appeared: at most [`REACTIONS`]. Kept on the heap, as a record holds
/// none until it is read.
pub type Reactions = Vec<Reacted>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_token_reads_as_itself() {
        for reaction in Reaction::ALL {
            assert_eq!(Reaction::from_body(reaction.body()), Some(reaction));
        }
    }

    #[test]
    fn other_spellings_read_as_the_emote_they_mean() {
        assert_eq!(
            Reaction::from_body("\u{2764}\u{fe0f}"),
            Some(Reaction::Heart)
        );
        assert_eq!(Reaction::from_body(" LOL "), Some(Reaction::Laugh));
        assert_eq!(
            Reaction::from_body("\u{1f44d}\u{1f3fd}"),
            Some(Reaction::ThumbsUp)
        );
        assert_eq!(Reaction::from_body("??"), Some(Reaction::Question));
        // A sentence counts as its first cluster.
        assert_eq!(Reaction::from_body("!nice"), Some(Reaction::Exclaim));
        assert_eq!(
            Reaction::from_body("\u{1f44d}\u{1f3fd} nice"),
            Some(Reaction::ThumbsUp)
        );
        assert_eq!(Reaction::from_body("nice"), None);
        assert_eq!(Reaction::from_body(""), None);
    }

    #[test]
    fn any_other_emoji_is_its_own_reaction() {
        let fire = Reaction::from_body("\u{1f525} nice").unwrap();
        assert_eq!(fire, Reaction::Other(Cluster::new("\u{1f525}").unwrap()));
        assert_eq!(fire.body(), "\u{1f525}");
        // Joined, toned, and keycap sequences stay whole.
        for body in [
            "\u{1f469}\u{200d}\u{1f4bb}",
            "\u{1f44b}\u{1f3fd}",
            "1\u{fe0f}\u{20e3}",
            "\u{2605}",
        ] {
            assert_eq!(Reaction::from_body(body).unwrap().body(), body);
        }
        assert_eq!(Reaction::from_body("\u{e9}t\u{e9}"), None);
        // Too long to keep: a family of four, toned.
        let family = "\u{1f468}\u{1f3fb}\u{200d}\u{1f469}\u{1f3fb}\u{200d}\u{1f467}\u{1f3fb}\u{200d}\u{1f466}\u{1f3fb}";
        assert_eq!(Reaction::from_body(family), None);
    }
}
