//! Raw DEFLATE (RFC 1951), decoded whole into a buffer.
//!
//! After Mark Adler's `puff`: canonical Huffman codes decoded a bit at a
//! time from per-length counts. It is slower than a table-driven decoder,
//! but its whole state is the [`Tables`] here, about a kilobyte, where a
//! table-driven one needs eleven. A block of glyphs is about ten kilobytes,
//! and is inflated once before its glyphs are cached.

const MAX_BITS: usize = 15;
const MAX_LITERALS: usize = 288;
const MAX_DISTANCES: usize = 30;

/// A canonical Huffman code: how many codes there are of each length, and
/// the symbols in code order.
struct Huffman<const N: usize> {
    counts: [u16; MAX_BITS + 1],
    symbols: [u16; N],
}

impl<const N: usize> Huffman<N> {
    const EMPTY: Self = Self {
        counts: [0; MAX_BITS + 1],
        symbols: [0; N],
    };

    /// Builds the code from each symbol's code length. Returns `None` for
    /// lengths that over-subscribe the code.
    fn build(&mut self, lengths: &[u8]) -> Option<()> {
        self.counts = [0; MAX_BITS + 1];
        for &length in lengths {
            self.counts[usize::from(length)] += 1;
        }
        let mut left: i32 = 1;
        for &count in &self.counts[1..] {
            left = (left << 1) - i32::from(count);
            if left < 0 {
                return None;
            }
        }
        let mut offsets = [0u16; MAX_BITS + 1];
        for length in 1..MAX_BITS {
            offsets[length + 1] = offsets[length] + self.counts[length];
        }
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != 0 {
                let at = &mut offsets[usize::from(length)];
                *self.symbols.get_mut(usize::from(*at))? = symbol as u16;
                *at += 1;
            }
        }
        Some(())
    }
}

/// Everything decoding keeps, apart from its input and output.
pub(crate) struct Tables {
    literals: Huffman<MAX_LITERALS>,
    distances: Huffman<MAX_DISTANCES>,
    lengths: [u8; MAX_LITERALS + MAX_DISTANCES],
}

impl Tables {
    pub(crate) const EMPTY: Self = Self {
        literals: Huffman::EMPTY,
        distances: Huffman::EMPTY,
        lengths: [0; MAX_LITERALS + MAX_DISTANCES],
    };
}

struct Bits<'a> {
    input: &'a [u8],
    at: usize,
    buffer: u32,
    count: u32,
}

impl Bits<'_> {
    fn take(&mut self, need: u32) -> Option<u32> {
        while self.count < need {
            let byte = *self.input.get(self.at)?;
            self.at += 1;
            self.buffer |= u32::from(byte) << self.count;
            self.count += 8;
        }
        let value = self.buffer & ((1 << need) - 1);
        self.buffer >>= need;
        self.count -= need;
        Some(value)
    }

    fn decode<const N: usize>(&mut self, code: &Huffman<N>) -> Option<u16> {
        let (mut value, mut first, mut index) = (0i32, 0i32, 0i32);
        for &count in &code.counts[1..] {
            value |= self.take(1)? as i32;
            let count = i32::from(count);
            if value - count < first {
                return code.symbols.get((index + value - first) as usize).copied();
            }
            index += count;
            first = (first + count) << 1;
            value <<= 1;
        }
        None
    }
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// The order code-length code lengths are sent in.
const ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Inflates `input` into `out`, returning how much of `out` it filled, or
/// `None` when the stream is malformed or `out` is too short.
pub(crate) fn inflate(input: &[u8], out: &mut [u8], tables: &mut Tables) -> Option<usize> {
    let mut bits = Bits {
        input,
        at: 0,
        buffer: 0,
        count: 0,
    };
    let mut written = 0;
    loop {
        let last = bits.take(1)? == 1;
        match bits.take(2)? {
            0 => written = stored(&mut bits, out, written)?,
            1 => {
                fixed(tables);
                written = codes(&mut bits, out, written, tables)?;
            }
            2 => {
                dynamic(&mut bits, tables)?;
                written = codes(&mut bits, out, written, tables)?;
            }
            _ => return None,
        }
        if last {
            return Some(written);
        }
    }
}

fn stored(bits: &mut Bits<'_>, out: &mut [u8], written: usize) -> Option<usize> {
    bits.buffer = 0;
    bits.count = 0;
    let header = bits.input.get(bits.at..bits.at + 4)?;
    let length = u16::from_le_bytes([header[0], header[1]]);
    if length != !u16::from_le_bytes([header[2], header[3]]) {
        return None;
    }
    bits.at += 4;
    let length = usize::from(length);
    let data = bits.input.get(bits.at..bits.at + length)?;
    out.get_mut(written..written + length)?
        .copy_from_slice(data);
    bits.at += length;
    Some(written + length)
}

fn fixed(tables: &mut Tables) {
    let lengths = &mut tables.lengths;
    lengths[..144].fill(8);
    lengths[144..256].fill(9);
    lengths[256..280].fill(7);
    lengths[280..MAX_LITERALS].fill(8);
    // The fixed code is complete, so it always builds.
    let _ = tables.literals.build(&lengths[..MAX_LITERALS]);
    lengths[..MAX_DISTANCES].fill(5);
    let _ = tables.distances.build(&lengths[..MAX_DISTANCES]);
}

fn dynamic(bits: &mut Bits<'_>, tables: &mut Tables) -> Option<()> {
    let literals = bits.take(5)? as usize + 257;
    let distances = bits.take(5)? as usize + 1;
    let code_lengths = bits.take(4)? as usize + 4;
    if literals > MAX_LITERALS || distances > MAX_DISTANCES {
        return None;
    }
    let lengths = &mut tables.lengths;
    lengths[..19].fill(0);
    for &symbol in &ORDER[..code_lengths] {
        lengths[symbol] = bits.take(3)? as u8;
    }
    // The code-length code borrows the literal table.
    tables.literals.build(&lengths[..19])?;
    let mut at = 0;
    while at < literals + distances {
        let symbol = bits.decode(&tables.literals)?;
        let (value, repeat) = match symbol {
            0..=15 => (symbol as u8, 1),
            16 => (
                *lengths.get(at.checked_sub(1)?)?,
                3 + bits.take(2)? as usize,
            ),
            17 => (0, 3 + bits.take(3)? as usize),
            18 => (0, 11 + bits.take(7)? as usize),
            _ => return None,
        };
        lengths.get_mut(at..at + repeat)?.fill(value);
        at += repeat;
    }
    if lengths[256] == 0 {
        return None;
    }
    tables.literals.build(&lengths[..literals])?;
    tables
        .distances
        .build(&lengths[literals..literals + distances])?;
    Some(())
}

fn codes(
    bits: &mut Bits<'_>,
    out: &mut [u8],
    mut written: usize,
    tables: &Tables,
) -> Option<usize> {
    loop {
        let symbol = usize::from(bits.decode(&tables.literals)?);
        if symbol < 256 {
            *out.get_mut(written)? = symbol as u8;
            written += 1;
        } else if symbol == 256 {
            return Some(written);
        } else {
            let index = symbol - 257;
            let length = usize::from(*LENGTH_BASE.get(index)?)
                + bits.take(u32::from(LENGTH_EXTRA[index]))? as usize;
            let index = usize::from(bits.decode(&tables.distances)?);
            let distance = usize::from(*DISTANCE_BASE.get(index)?)
                + bits.take(u32::from(DISTANCE_EXTRA[index]))? as usize;
            let from = written.checked_sub(distance)?;
            if written + length > out.len() {
                return None;
            }
            // Byte by byte: a copy may overlap what it writes.
            for i in 0..length {
                out[written + i] = out[from + i];
            }
            written += length;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;

    fn sample() -> Vec<u8> {
        // Repetitive enough for back-references, varied enough for a
        // dynamic code.
        (0..20_000u32)
            .map(|i| ((i * 7) % 31 + (i / 100) % 5) as u8)
            .collect()
    }

    #[test]
    fn inflates_what_miniz_deflates() {
        let data = sample();
        let mut tables = Tables::EMPTY;
        for level in [0, 1, 6, 10] {
            let packed = miniz_oxide::deflate::compress_to_vec(&data, level);
            let mut out = std::vec![0; data.len()];
            assert_eq!(
                inflate(&packed, &mut out, &mut tables),
                Some(data.len()),
                "level {level}"
            );
            assert_eq!(out, data, "level {level}");
        }
    }

    #[test]
    fn a_short_buffer_is_refused() {
        let data = sample();
        let packed = miniz_oxide::deflate::compress_to_vec(&data, 6);
        let mut out = std::vec![0; data.len() - 1];
        let mut tables = Tables::EMPTY;
        assert_eq!(inflate(&packed, &mut out, &mut tables), None);
    }

    #[test]
    fn a_truncated_stream_is_refused() {
        let data = sample();
        let packed = miniz_oxide::deflate::compress_to_vec(&data, 6);
        let mut out = std::vec![0; data.len()];
        let mut tables = Tables::EMPTY;
        assert_eq!(
            inflate(&packed[..packed.len() / 2], &mut out, &mut tables),
            None
        );
    }
}
