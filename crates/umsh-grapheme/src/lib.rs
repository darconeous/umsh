//! Grapheme-cluster boundaries for UMSH text.
//!
//! An emoji can be several code points: 👍🏽 is a thumbs up and a skin tone,
//! 🇫🇷 is two regional indicators, and 👨‍👩‍👧 is five code points joined by
//! zero-width joiners. Text that is shortened to fit a byte limit, or that
//! gives up its first character for an avatar or a reaction, is cut between
//! extended grapheme clusters (UAX #29), so none of these is ever split.
//!
//! Message fragmentation is not shortening: it splits a body at byte
//! boundaries, and its reassembly restores the text.

#![no_std]

use unicode_segmentation::UnicodeSegmentation;

/// The extended grapheme clusters of `text`, in order.
pub fn clusters(text: &str) -> impl DoubleEndedIterator<Item = &str> + Clone {
    text.graphemes(true)
}

/// The longest prefix of `text` that is at most `max` bytes long and ends
/// between clusters.
#[must_use]
pub fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = 0;
    for cluster in clusters(text) {
        let next = end + cluster.len();
        if next > max {
            break;
        }
        end = next;
    }
    &text[..end]
}

/// The length of the longest prefix of `bytes` that is at most `max` bytes
/// of UTF-8 and ends between clusters. Bytes that are not UTF-8 have none.
#[must_use]
pub fn cut_len(bytes: &[u8], max: usize) -> usize {
    core::str::from_utf8(bytes).map_or(0, |text| cut(text, max).len())
}

/// The first cluster of `text`, such as an avatar's initial or the emoji a
/// reaction is drawn from.
#[must_use]
pub fn first_cluster(text: &str) -> Option<&str> {
    clusters(text).next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_keeps_clusters_whole() {
        // 👍🏽 is 8 bytes: U+1F44D and U+1F3FD.
        assert_eq!(cut("ab👍🏽", 9), "ab");
        assert_eq!(cut("ab👍🏽", 10), "ab👍🏽");
        assert_eq!(cut("ab👍🏽", 100), "ab👍🏽");
        // 🇫🇷 is two regional indicators, 4 bytes each.
        assert_eq!(cut("🇫🇷🇬🇧", 12), "🇫🇷");
        // A combining accent stays with its letter.
        assert_eq!(cut("ae\u{301}", 2), "a");
        assert_eq!(cut("", 4), "");
        assert_eq!(cut("abc", 0), "");
    }

    #[test]
    fn cut_len_refuses_what_is_not_utf8() {
        assert_eq!(cut_len("ab👍🏽".as_bytes(), 9), 2);
        assert_eq!(cut_len(&[0x61, 0xff], 2), 0);
    }

    #[test]
    fn first_cluster_is_whole() {
        assert_eq!(first_cluster("👨‍👩‍👧 family"), Some("👨‍👩‍👧"));
        assert_eq!(first_cluster("🔥 Crew"), Some("🔥"));
        assert_eq!(first_cluster(""), None);
    }
}
