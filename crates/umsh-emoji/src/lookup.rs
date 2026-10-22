//! What a grapheme cluster is drawn as.

use crate::Id;

const VS16: char = '\u{FE0F}';
const ZWJ: char = '\u{200D}';
const BLACK_FLAG: char = '\u{1F3F4}';
const TAG_END: char = '\u{E007F}';
/// The longest cluster looked up, in bytes. Every sequence in the
/// manifest is shorter.
const LONGEST: usize = 64;
/// The most parts of a joined sequence drawn side by side.
pub const MAX_PARTS: usize = 4;

/// How a cluster is drawn, from the best result to the last resort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shown {
    /// Its own glyph, or, for a skin-toned emoji, its base's.
    Glyph(Id),
    /// A joined sequence the manifest lacks, as those of its parts that it
    /// has, side by side.
    Parts([Id; MAX_PARTS], u8),
    /// A flag the manifest lacks, as its region's code: `FR`, `GB-SCT`.
    Flag(Region),
    /// Pictographic, but nothing the manifest has: the placeholder.
    Placeholder,
    /// Not an emoji: text, for the text face to draw.
    Text,
    /// Selectors, joiners, or tags on their own, which draw nothing.
    Nothing,
}

/// A flag's region code, in ASCII capitals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    letters: [u8; 7],
    len: u8,
}

impl Region {
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.letters[..usize::from(self.len)]).unwrap_or_default()
    }

    fn push(&mut self, b: u8) -> Option<()> {
        *self.letters.get_mut(usize::from(self.len))? = b;
        self.len += 1;
        Some(())
    }
}

/// The glyph for `sequence`, written without U+FE0F.
#[must_use]
pub fn find(sequence: &str) -> Option<Id> {
    let keys = crate::KEYS.as_bytes();
    let index = &crate::INDEX;
    let key_at = |i: usize| {
        let start = usize::from(index[i].0);
        let end = index
            .get(i + 1)
            .map_or(keys.len(), |next| usize::from(next.0));
        &keys[start..end]
    };
    let mut low = 0;
    let mut high = index.len();
    while low < high {
        let mid = (low + high) / 2;
        match key_at(mid).cmp(sequence.as_bytes()) {
            core::cmp::Ordering::Less => low = mid + 1,
            core::cmp::Ordering::Greater => high = mid,
            core::cmp::Ordering::Equal => return Some(index[mid].1),
        }
    }
    None
}

/// What is always drawn as the placeholder: U+FFFC OBJECT REPLACEMENT
/// CHARACTER, which stands for something that cannot be shown.
pub const PLACEHOLDER: &str = "\u{FFFC}";

/// How `cluster`, one extended grapheme cluster, is drawn.
#[must_use]
pub fn shown(cluster: &str) -> Shown {
    if cluster == PLACEHOLDER {
        return Shown::Placeholder;
    }
    let mut buffer = [0; LONGEST];
    // 1. The sequence itself, without U+FE0F.
    let Some(key) = without(cluster, &mut buffer, |c| c == VS16) else {
        return if cluster.chars().any(is_pictographic) {
            Shown::Placeholder
        } else {
            Shown::Text
        };
    };
    if let Some(id) = find(key) {
        return Shown::Glyph(id);
    }
    if key.chars().all(|c| c == ZWJ || is_tag(c)) {
        return Shown::Nothing;
    }
    // 2. A skin-toned emoji, as its base.
    let mut toneless = [0; LONGEST];
    let Some(key) = without(key, &mut toneless, is_skin_tone) else {
        return Shown::Placeholder;
    };
    if let Some(id) = find(key) {
        return Shown::Glyph(id);
    }
    // 3. A joined sequence, as its parts.
    if key.contains(ZWJ) {
        let mut parts = [0; MAX_PARTS];
        let mut count = 0;
        for part in key.split(ZWJ) {
            if let Some(id) = find(part)
                && count < MAX_PARTS
            {
                parts[count] = id;
                count += 1;
            }
        }
        if count > 0 {
            return Shown::Parts(parts, count as u8);
        }
    }
    // 4. A flag, as its region's code.
    if let Some(region) = region(key) {
        return Shown::Flag(region);
    }
    // 5. Anything else pictographic.
    if key.chars().any(is_pictographic) {
        Shown::Placeholder
    } else {
        Shown::Text
    }
}

/// `text` without the characters `drop` picks, in `buffer`.
fn without<'b>(
    text: &str,
    buffer: &'b mut [u8; LONGEST],
    drop: impl Fn(char) -> bool,
) -> Option<&'b str> {
    let mut len = 0;
    for c in text.chars().filter(|&c| !drop(c)) {
        len += c
            .encode_utf8(buffer.get_mut(len..len + c.len_utf8())?)
            .len();
    }
    core::str::from_utf8(&buffer[..len]).ok()
}

fn is_skin_tone(c: char) -> bool {
    ('\u{1F3FB}'..='\u{1F3FF}').contains(&c)
}

fn is_tag(c: char) -> bool {
    ('\u{E0020}'..='\u{E007F}').contains(&c)
}

fn is_regional_indicator(c: char) -> bool {
    ('\u{1F1E6}'..='\u{1F1FF}').contains(&c)
}

/// The region a flag stands for: a pair of regional indicators, or the
/// black flag and a tag sequence (`gbsct` for Scotland).
fn region(key: &str) -> Option<Region> {
    let mut region = Region {
        letters: [0; 7],
        len: 0,
    };
    let mut chars = key.chars();
    let first = chars.next()?;
    if is_regional_indicator(first) {
        let second = chars.next().filter(|&c| is_regional_indicator(c))?;
        if chars.next().is_some() {
            return None;
        }
        for c in [first, second] {
            region.push(b'A' + (u32::from(c) - 0x1F1E6) as u8)?;
        }
        return Some(region);
    }
    if first != BLACK_FLAG {
        return None;
    }
    for (i, c) in chars.enumerate() {
        if c == TAG_END {
            return (region.len > 2).then_some(region);
        }
        let ascii = u32::from(c).checked_sub(0xE0000)?;
        let ascii = u8::try_from(ascii).ok().filter(u8::is_ascii_alphanumeric)?;
        if i == 2 {
            region.push(b'-')?;
        }
        region.push(ascii.to_ascii_uppercase())?;
    }
    None
}

/// Whether `c` is drawn as a picture rather than as a letter: a close
/// cover of `Extended_Pictographic` and the regional indicators.
fn is_pictographic(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00A9 | 0x00AE | 0x203C | 0x2049 | 0x2122 | 0x2139
            | 0x2194..=0x21AA
            | 0x231A..=0x23FF
            | 0x24C2
            | 0x25AA..=0x25FE
            | 0x2600..=0x27BF
            | 0x2934..=0x2935
            | 0x2B05..=0x2B55
            | 0x3030 | 0x303D | 0x3297 | 0x3299
            | 0x1F000..=0x1FAFF
            | 0x1FC00..=0x1FFFD
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(sequence: &str) -> Id {
        find(sequence).unwrap_or_else(|| panic!("{sequence} is not in the manifest"))
    }

    #[test]
    fn a_sequence_is_found_with_or_without_fe0f() {
        assert_eq!(shown("\u{1F600}"), Shown::Glyph(id("\u{1F600}")));
        assert_eq!(shown("\u{2764}\u{FE0F}"), Shown::Glyph(id("\u{2764}")));
        assert_eq!(shown("\u{2764}"), Shown::Glyph(id("\u{2764}")));
    }

    #[test]
    fn the_placeholder_has_a_character_of_its_own() {
        assert_eq!(shown(PLACEHOLDER), Shown::Placeholder);
    }

    #[test]
    fn a_skin_tone_falls_back_to_its_base() {
        assert_eq!(shown("\u{1F44D}\u{1F3FD}"), Shown::Glyph(id("\u{1F44D}")));
    }

    #[test]
    fn a_missing_joined_sequence_shows_its_parts() {
        // A man and a laptop make a technologist, which the set leaves out.
        let technologist = "\u{1F468}\u{200D}\u{1F4BB}";
        assert_eq!(find(technologist), None);
        assert_eq!(
            shown(technologist),
            Shown::Parts([id("\u{1F468}"), id("\u{1F4BB}"), 0, 0], 2)
        );
    }

    #[test]
    fn a_flag_shows_its_region() {
        let Shown::Flag(region) = shown("\u{1F1EB}\u{1F1F7}") else {
            panic!("not a flag");
        };
        assert_eq!(region.as_str(), "FR");
        let scotland = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
        let Shown::Flag(region) = shown(scotland) else {
            panic!("not a flag");
        };
        assert_eq!(region.as_str(), "GB-SCT");
    }

    #[test]
    fn the_rest_is_a_placeholder_or_text() {
        // A pregnant man is not in the set.
        assert_eq!(shown("\u{1FAC3}"), Shown::Placeholder);
        assert_eq!(shown("a"), Shown::Text);
        assert_eq!(shown("e\u{301}"), Shown::Text);
        assert_eq!(shown("\u{FE0F}"), Shown::Nothing);
    }
}
