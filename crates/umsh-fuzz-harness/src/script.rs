//! The script format stateful targets read: a run of `[op][len-hi][len-lo][bytes]`
//! records.
//!
//! A format of our own rather than `arbitrary` so a seed can be written from
//! the real encoders. Reading is total, because the fuzzer corrupts lengths
//! as readily as anything else: a length past the end of the input clamps to
//! what is left rather than rejecting the input, so a damaged record still
//! runs and everything before it still counts.

/// Bytes of a record ahead of its body.
pub const RECORD_HEADER: usize = 3;

/// One record of a script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub op: u8,
    pub body: &'a [u8],
}

/// The records of a script, in order.
pub fn records(data: &[u8]) -> Records<'_> {
    Records { rest: data }
}

/// Iterator returned by [`records`].
#[derive(Clone)]
pub struct Records<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Record<'a>> {
        let (&op, rest) = self.rest.split_first()?;
        let declared = match *rest {
            [] => 0,
            [only] => usize::from(only),
            [high, low, ..] => usize::from(u16::from_be_bytes([high, low])),
        };
        let rest = rest.get(2..).unwrap_or(&[]);
        let (body, rest) = rest.split_at(declared.min(rest.len()));
        self.rest = rest;
        Some(Record { op, body })
    }
}

/// Append a record. Bodies longer than a record can declare are cut.
pub fn push_record(out: &mut Vec<u8>, op: u8, body: &[u8]) {
    let len = body.len().min(usize::from(u16::MAX));
    out.push(op);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&body[..len]);
}

/// Where each record of `data` starts, followed by `data.len()`.
fn boundaries(data: &[u8]) -> Vec<usize> {
    let mut starts = vec![0];
    let mut records = records(data);
    while records.next().is_some() {
        starts.push(data.len() - records.rest.len());
    }
    starts
}

/// Splice two scripts on record boundaries: a leading run of `a` followed by
/// a trailing run of `b`, as much as fits `out`. Returns the length written.
///
/// libFuzzer's own crossover cuts at byte offsets, which lands inside a
/// record and turns the rest of the script into noise.
pub fn crossover(a: &[u8], b: &[u8], out: &mut [u8], seed: u32) -> usize {
    let a_cuts = boundaries(a);
    let b_cuts = boundaries(b);
    let [low, high] = [seed as u16, (seed >> 16) as u16];
    let a_cut = a_cuts[usize::from(low) % a_cuts.len()];
    let b_cut = b_cuts[usize::from(high) % b_cuts.len()];
    let head = a_cut.min(out.len());
    out[..head].copy_from_slice(&a[..head]);
    let tail = (b.len() - b_cut).min(out.len() - head);
    out[head..head + tail].copy_from_slice(&b[b_cut..b_cut + tail]);
    head + tail
}

/// Fixed-layout fields at the front of a record body, read without failing:
/// a body that runs out reads as zeros.
#[derive(Clone, Copy)]
pub struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Fields<'a> {
    pub fn new(body: &'a [u8]) -> Self {
        Self { rest: body }
    }

    pub fn u8(&mut self) -> u8 {
        match self.rest.split_first() {
            Some((&byte, rest)) => {
                self.rest = rest;
                byte
            }
            None => 0,
        }
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.u8(), self.u8()])
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    /// Everything not yet read.
    pub fn rest(self) -> &'a [u8] {
        self.rest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(records: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (op, body) in records {
            push_record(&mut out, *op, body);
        }
        out
    }

    #[test]
    fn records_read_back_as_written() {
        let data = script(&[(1, b"ab"), (2, b""), (3, b"c")]);
        let read: Vec<_> = records(&data).map(|r| (r.op, r.body.to_vec())).collect();
        assert_eq!(
            read,
            [(1, b"ab".to_vec()), (2, Vec::new()), (3, b"c".to_vec())]
        );
    }

    #[test]
    fn a_length_past_the_end_clamps() {
        assert_eq!(
            records(&[7, 0xFF, 0xFF, 1, 2]).collect::<Vec<_>>(),
            [Record {
                op: 7,
                body: &[1, 2]
            }]
        );
        assert_eq!(
            records(&[7, 9]).collect::<Vec<_>>(),
            [Record { op: 7, body: &[] }]
        );
    }

    #[test]
    fn crossover_cuts_on_record_boundaries() {
        let a = script(&[(1, b"aa"), (2, b"bb")]);
        let b = script(&[(3, b"cc"), (4, b"dd")]);
        let mut out = [0u8; 64];
        for seed in 0..64u32 {
            let seed = (seed & 7) | ((seed >> 3) << 16);
            let len = crossover(&a, &b, &mut out, seed);
            for record in records(&out[..len]) {
                assert!(matches!(record.op, 1..=4));
                assert_eq!(record.body.len(), 2);
            }
        }
    }

    #[test]
    fn crossover_fits_a_small_buffer() {
        let a = script(&[(1, &[0; 40])]);
        let b = script(&[(2, &[0; 40])]);
        let mut out = [0u8; 8];
        assert!(crossover(&a, &b, &mut out, 0x0001_0000) <= out.len());
        assert_eq!(crossover(&[], &[], &mut out, 7), 0);
    }

    #[test]
    fn fields_read_zero_past_the_end() {
        let mut fields = Fields::new(&[1, 2, 3]);
        assert_eq!(fields.u16(), 0x0102);
        assert_eq!(fields.u16(), 0x0300);
        assert_eq!(fields.u8(), 0);
        assert!(fields.rest().is_empty());
    }
}
