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
    /// Whole: what was typed is its name, or an alias.
    Name,
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

/// The words glyph `id` is found by: its CLDR name, as [`name`] gives it,
/// and then, after a `|`, any aliases.
#[must_use]
pub fn words(id: Id) -> &'static str {
    part(WORDS, &WORD_ENDS, id)
}

/// Glyph `id`'s CLDR short name, as a title shows it: its first letter
/// capitalized, as "Fire" or "OK hand".
#[must_use]
pub fn name(id: Id) -> &'static str {
    let words = words(id);
    words.split_once('|').map_or(words, |(name, _)| name)
}

/// Where a name's words break.
const BREAKS: [char; 6] = [' ', '-', ':', ',', '\u{201C}', '\u{201D}'];

fn part(pool: &'static str, ends: &[u16], id: Id) -> &'static str {
    let id = usize::from(id);
    let start = id.checked_sub(1).map_or(0, |prev| usize::from(ends[prev]));
    ends.get(id)
        .and_then(|&end| pool.get(start..usize::from(end)))
        .unwrap_or_default()
}

/// How `words`, as [`words`] gives them, match `query`: each word of the
/// query must begin one of theirs, in any order, without regard to ASCII
/// case. A name's words are split at spaces, hyphens, and punctuation.
#[must_use]
pub fn matching(words: &str, query: &str) -> Option<Match> {
    let (name, aliases) = words.split_once('|').unwrap_or((words, ""));
    let name_words = || name.split(BREAKS).filter(|t| !t.is_empty());
    let tokens = || name_words().chain(aliases.split(' ').filter(|t| !t.is_empty()));
    let mut last = None;
    for word in query.split_whitespace() {
        if !tokens().any(|t| begins(t, word)) {
            return None;
        }
        last = Some(word);
    }
    let last = last?;
    let typed = query.trim();
    // The name's words, all of them, whatever punctuation is left out.
    let whole = name_words().count() == query.split_whitespace().count()
        && name_words()
            .zip(query.split_whitespace())
            .all(|(theirs, typed)| theirs.eq_ignore_ascii_case(typed));
    if whole || aliases.split(' ').any(|a| a.eq_ignore_ascii_case(typed)) {
        return Some(Match::Name);
    }
    let head = name_words().last().unwrap_or_default();
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
        assert_eq!(words(heart), "Red heart|<3 love");
        assert_eq!(sequence(COUNT), "");
    }

    #[test]
    fn a_name_is_cased_for_a_title() {
        assert_eq!(name(find("\u{1F525}").unwrap()), "Fire");
        assert_eq!(name(find("\u{2764}").unwrap()), "Red heart");
        assert_eq!(name(find("\u{1F44C}").unwrap()), "OK hand");
        assert_eq!(name(find("\u{1F996}").unwrap()), "T-Rex");
        assert_eq!(name(find("1\u{20E3}").unwrap()), "Keycap: 1");
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
        assert_eq!(matching("fire", "Fire"), Some(Match::Name));
        assert_eq!(matching("heart on fire", "fire"), Some(Match::Head));
        assert_eq!(matching("red heart|<3 love", "<3"), Some(Match::Name));
        assert_eq!(matching("red heart|<3 love", "hea"), Some(Match::Head));
        assert_eq!(matching("red heart|<3 love", "RED"), Some(Match::Word));
        assert_eq!(
            matching("smiling face with heart-eyes", "hea"),
            Some(Match::Word)
        );
        assert_eq!(matching("headphone", "hea"), Some(Match::Head));
        assert_eq!(matching("red heart", "eart"), None);
        assert_eq!(matching("red heart", "heart blue"), None);
        assert_eq!(matching("red heart", "  "), None);
        assert_eq!(matching("Keycap: 1", "keycap 1"), Some(Match::Name));
        assert_eq!(matching("OK hand", "ok"), Some(Match::Word));
        assert_eq!(
            matching("Japanese \u{201C}here\u{201D} button", "here"),
            Some(Match::Word)
        );
    }
}
