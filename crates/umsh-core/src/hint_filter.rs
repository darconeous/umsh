use crate::{PublicKey, base58};

mod data;

pub use data::FILTER;

pub const FILTER_BITS: usize = 4096;

pub const BITS_PER_LOOKUP: u32 = 5;

const INDEX_BITS: u32 = FILTER_BITS.trailing_zeros();

pub const REJECTION_BUDGET: f64 = 0.025;

pub const SIX: u8 = 26;

pub const PAD: u8 = 27;

pub const PREFIXES: u32 = 3_361_702;

const LAST_PREFIX_WEIGHT: f64 = 0.496_359_013_772_211_6;

const PREFIX_WEIGHT: f64 = (PREFIXES - 1) as f64 + LAST_PREFIX_WEIGHT;

pub const fn fold(c: u8) -> Option<u8> {
    let letter = match c {
        b'a'..=b'z' => c,
        b'A'..=b'Z' => c.to_ascii_lowercase(),
        b'0' => b'o',
        b'1' => b'i',
        b'2' => b'z',
        b'3' => b'e',
        b'4' => b'a',
        b'5' => b's',
        b'6' => return Some(SIX),
        b'7' => b't',
        b'8' => b'b',
        b'9' => b'g',
        _ => return None,
    };
    let letter = if letter == b'l' { b'i' } else { letter };
    Some(letter - b'a')
}

pub const fn four_letter_key(symbols: [u8; 4]) -> u32 {
    (symbols[0] as u32) << 15
        | (symbols[1] as u32) << 10
        | (symbols[2] as u32) << 5
        | symbols[3] as u32
}

pub const fn three_letter_key(symbols: [u8; 3]) -> u32 {
    four_letter_key([symbols[0], symbols[1], symbols[2], PAD])
}

pub fn text_key(text: &[u8]) -> Option<u32> {
    let mut symbols = [PAD; 4];
    if !(3..=4).contains(&text.len()) {
        return None;
    }
    for (symbol, &c) in symbols.iter_mut().zip(text) {
        *symbol = fold(c)?;
    }
    Some(four_letter_key(symbols))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    pub salt: u64,
    pub bits: [u8; FILTER_BITS / 8],
}

impl Filter {
    pub const fn empty(salt: u64) -> Self {
        Self {
            salt,
            bits: [0; FILTER_BITS / 8],
        }
    }

    pub fn insert(&mut self, key: u32) {
        for index in indexes(key, self.salt) {
            self.bits[index / 8] |= 1 << (index % 8);
        }
    }

    pub fn contains(&self, key: u32) -> bool {
        indexes(key, self.salt).all(|index| self.bits[index / 8] & (1 << (index % 8)) != 0)
    }

    pub fn matches(&self, symbols: [u8; 4]) -> bool {
        self.contains(four_letter_key(symbols))
            || self.contains(three_letter_key([symbols[0], symbols[1], symbols[2]]))
    }

    pub fn avoids(&self, key: &PublicKey) -> bool {
        let digits = base58::encode(&key.0);
        self.matches(core::array::from_fn(|i| fold(digits[i]).unwrap_or(PAD)))
    }

    pub fn rejection_rate(&self) -> f64 {
        let mut rejected = 0.0;
        for_each_prefix(|symbols, weight| {
            if self.matches(symbols) {
                rejected += weight;
            }
        });
        rejected / PREFIX_WEIGHT
    }
}

pub fn is_avoided(key: &PublicKey) -> bool {
    FILTER.avoids(key)
}

pub fn for_each_prefix(mut visit: impl FnMut([u8; 4], f64)) {
    const FOLDED: [u8; 58] = {
        let mut folded = [0; 58];
        let mut i = 0;
        while i < 58 {
            folded[i] = match fold(base58::ALPHABET[i]) {
                Some(symbol) => symbol,
                None => panic!("every base58 digit folds"),
            };
            i += 1;
        }
        folded
    };
    for prefix in 0..PREFIXES {
        let digit = |place: u32| FOLDED[(prefix / 58u32.pow(place) % 58) as usize];
        let weight = if prefix == PREFIXES - 1 {
            LAST_PREFIX_WEIGHT
        } else {
            1.0
        };
        visit([digit(3), digit(2), digit(1), digit(0)], weight);
    }
}

fn indexes(key: u32, salt: u64) -> impl Iterator<Item = usize> {
    let mut z = salt.wrapping_add(u64::from(key).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let hash = z ^ (z >> 31);
    (0..BITS_PER_LOOKUP).map(move |i| (hash >> (i * INDEX_BITS)) as usize & (FILTER_BITS - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_with_prefix(prefix: &str) -> PublicKey {
        let mut digits = [b'1'; base58::ENCODED_LEN];
        digits[..prefix.len()].copy_from_slice(prefix.as_bytes());
        PublicKey(base58::decode(&digits).unwrap())
    }

    #[test]
    fn fold_known_answers() {
        for c in *b"aA4" {
            assert_eq!(fold(c), Some(0), "{}", c as char);
        }
        for c in *b"1iIlL" {
            assert_eq!(fold(c), Some(b'i' - b'a'), "{}", c as char);
        }
        for c in *b"0oO" {
            assert_eq!(fold(c), Some(b'o' - b'a'), "{}", c as char);
        }
        assert_eq!(fold(b'6'), Some(SIX));
        assert_eq!(fold(b'7'), fold(b'T'));
        assert_eq!(fold(b'*'), None);
        assert_eq!(fold(b' '), None);
    }

    #[test]
    fn key_known_answers() {
        assert_eq!(four_letter_key([0, 1, 2, 3]), 1091);
        assert_eq!(text_key(b"aBcD"), Some(1091));
        assert_eq!(text_key(b"abc"), Some(three_letter_key([0, 1, 2])));
        assert_ne!(text_key(b"abc"), text_key(b"abca"));
        assert_eq!(text_key(b"ab"), None);
        assert_eq!(text_key(b"abcde"), None);
        assert_eq!(text_key(b"ab-c"), None);
    }

    #[test]
    fn hash_known_answers() {
        let collect = |key, salt| {
            let mut out = [0; BITS_PER_LOOKUP as usize];
            for (slot, index) in out.iter_mut().zip(indexes(key, salt)) {
                *slot = index;
            }
            out
        };
        assert_eq!(collect(1091, 0), [1571, 3005, 207, 1026, 2431]);
        assert_eq!(
            collect(1091, 0x0123_4567_89AB_CDEF),
            [2096, 3258, 3898, 3480, 1436]
        );
    }

    #[test]
    fn prefixes_span_the_key_space() {
        let mut last = [0u8; 4];
        let digits = base58::encode(&[0xFF; 32]);
        for (slot, &c) in last.iter_mut().zip(&digits) {
            *slot = fold(c).unwrap();
        }
        let mut seen = None;
        for_each_prefix(|symbols, _| seen = Some(symbols));
        assert_eq!(seen, Some(last));
        assert_eq!(&digits[..1], b"J");
    }

    #[test]
    fn inserted_keys_match_their_prefixes() {
        let mut filter = Filter::empty(7);
        filter.insert(text_key(b"bvq").unwrap());
        filter.insert(text_key(b"fjxw").unwrap());

        for prefix in ["Bvq1", "BVQz", "8vq9", "8VQJ"] {
            assert!(filter.avoids(&key_with_prefix(prefix)), "{prefix}");
        }
        for prefix in ["Fjxw", "FJXW", "FjXw"] {
            assert!(filter.avoids(&key_with_prefix(prefix)), "{prefix}");
        }
        for prefix in ["Fjx1", "Bvr1", "Cvq1", "1Bvq"] {
            assert!(!filter.avoids(&key_with_prefix(prefix)), "{prefix}");
        }
    }

    #[test]
    fn rejection_rate_counts_prefixes_exactly() {
        assert_eq!(Filter::empty(0).rejection_rate(), 0.0);

        let full = Filter {
            salt: 0,
            bits: [0xFF; FILTER_BITS / 8],
        };
        assert!((full.rejection_rate() - 1.0).abs() < 1e-12);

        let mut filter = Filter::empty(0);
        filter.insert(text_key(b"fjxw").unwrap());
        let prefixes = filter.rejection_rate() * PREFIX_WEIGHT;
        assert!((prefixes - 8.0).abs() < 1e-6, "{prefixes}");
    }

    #[test]
    fn committed_filter_is_within_budget() {
        let rate = FILTER.rejection_rate();
        assert!(rate <= REJECTION_BUDGET, "rejection rate {rate}");
    }
}
