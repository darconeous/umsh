//! What a picker needs: each glyph's sequence as it is sent, the words it
//! is found by, and the groups glyphs fall in.

use crate::{Id, SEQUENCE_ENDS, SEQUENCES, WORD_ENDS, WORDS};

/// A run of glyphs in one CLDR group, such as Smileys & Emotion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group {
    pub name: &'static str,
    /// Its first glyph.
    pub start: Id,
    /// The glyph after its last.
    pub end: Id,
}

/// How well words match what was typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Match {
    /// By the word that says what it is: the last of its name, as
    /// "heart" in "red heart", or an alias.
    Head,
    /// By another word.
    Word,
}

/// Glyph `id`'s sequence as it is sent: fully qualified, with U+FE0F
/// where the manifest has it.
#[must_use]
pub fn sequence(id: Id) -> &'static str {
    part(SEQUENCES, &SEQUENCE_ENDS, id)
}

/// The words glyph `id` is found by: its CLDR name, lowercased, and then,
/// after a `|`, any aliases.
#[must_use]
pub fn words(id: Id) -> &'static str {
    part(WORDS, &WORD_ENDS, id)
}

fn part(pool: &'static str, ends: &[u16], id: Id) -> &'static str {
    let id = usize::from(id);
    let start = id.checked_sub(1).map_or(0, |prev| usize::from(ends[prev]));
    ends.get(id)
        .and_then(|&end| pool.get(start..usize::from(end)))
        .unwrap_or_default()
}

/// How `words`, as [`words`] gives them, match `query`: each word of the
/// query must begin one of theirs, in any order, without regard to ASCII
/// case. A name's words are split at spaces and hyphens.
#[must_use]
pub fn matching(words: &str, query: &str) -> Option<Match> {
    let (name, aliases) = words.split_once('|').unwrap_or((words, ""));
    let tokens = || {
        name.split([' ', '-'])
            .chain(aliases.split(' '))
            .filter(|t| !t.is_empty())
    };
    let mut last = None;
    for word in query.split_whitespace() {
        if !tokens().any(|t| begins(t, word)) {
            return None;
        }
        last = Some(word);
    }
    let last = last?;
    let head = name.rsplit([' ', '-']).next().unwrap_or_default();
    if begins(head, last) || aliases.split(' ').any(|t| begins(t, last)) {
        Some(Match::Head)
    } else {
        Some(Match::Word)
    }
}

fn begins(token: &str, word: &str) -> bool {
    token
        .as_bytes()
        .get(..word.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(word.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{COUNT, GROUPS, find};

    #[test]
    fn a_sequence_is_sent_as_the_manifest_has_it() {
        let heart = find("\u{2764}").unwrap();
        assert_eq!(sequence(heart), "\u{2764}\u{FE0F}");
        assert_eq!(words(heart), "red heart|<3 love");
        assert_eq!(sequence(COUNT), "");
    }

    #[test]
    fn groups_cover_every_glyph_in_order() {
        assert_eq!(GROUPS[0].name, "Smileys & Emotion");
        assert_eq!(GROUPS[0].start, 0);
        for pair in GROUPS.windows(2) {
            assert_eq!(pair[0].end, pair[1].start);
        }
        assert_eq!(GROUPS.last().unwrap().end, COUNT);
    }

    #[test]
    fn a_query_matches_the_starts_of_words() {
        assert_eq!(matching("red heart|<3 love", "hea"), Some(Match::Head));
        assert_eq!(matching("red heart|<3 love", "RED"), Some(Match::Word));
        assert_eq!(matching("red heart|<3 love", "<3"), Some(Match::Head));
        assert_eq!(
            matching("smiling face with heart-eyes", "hea"),
            Some(Match::Word)
        );
        assert_eq!(matching("headphone", "hea"), Some(Match::Head));
        assert_eq!(matching("red heart", "eart"), None);
        assert_eq!(matching("red heart", "heart blue"), None);
        assert_eq!(matching("red heart", "  "), None);
    }
}
