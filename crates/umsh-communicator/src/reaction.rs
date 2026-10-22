//! Reactions: emotes about a message, folded into it.
//!
//! On the wire a reaction is a status message regarding its target, its
//! body one of UMSH's emote tokens; an empty body withdraws the sender's
//! earlier one. The store keeps the latest from each sender inside the
//! target, and counts them by token when the message is read.

use heapless::Vec;

/// One of UMSH's emote tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reaction {
    Heart,
    ThumbsUp,
    ThumbsDown,
    Laugh,
    Exclaim,
    Question,
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

    /// The emote's body on the air.
    pub const fn token(self) -> &'static str {
        match self {
            Self::Heart => "<3",
            Self::ThumbsUp => "+1",
            Self::ThumbsDown => "-1",
            Self::Laugh => "ha",
            Self::Exclaim => "!",
            Self::Question => "?",
        }
    }

    /// The emote a reaction's body stands for.
    ///
    /// Reading is looser than writing, as it is on iOS: the tokens, their
    /// longer spellings, and the emoji other clients send all count, and
    /// a body that is none of them counts as its first grapheme cluster,
    /// so 👍🏽 stays whole. Anything else stands for no emote this palette
    /// has.
    pub fn from_body(body: &str) -> Option<Self> {
        let trimmed = body.trim();
        Self::spelled(trimmed).or_else(|| Self::spelled(umsh_grapheme::first_cluster(trimmed)?))
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

/// A message's reactions, one entry per emote, in the order each emote
/// first appeared.
pub type Reactions = Vec<Reacted, { Reaction::ALL.len() }>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_token_reads_as_itself() {
        for reaction in Reaction::ALL {
            assert_eq!(Reaction::from_body(reaction.token()), Some(reaction));
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
}
