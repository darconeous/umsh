//! The option codec and the Trace option a repeater rewrites.

use umsh_core::RouterHint;
use umsh_core::options::{
    HopSignal, OptionDecoder, OptionEncoder, TraceForm, TraceRecord, TraceRef, option_record_len,
};

use crate::script::Fields;

const MAX: usize = 512;

/// Every option in a block, and how much of the block they took.
type Decoded<'a> = (Vec<(u16, &'a [u8])>, usize);

fn decoded(data: &[u8]) -> Option<Decoded<'_>> {
    let mut decoder = OptionDecoder::new(data);
    let mut options = Vec::new();
    for entry in decoder.by_ref() {
        options.push(entry.ok()?);
    }
    Some((options, decoder.position()))
}

fn round_trip(data: &[u8]) {
    let Some((options, _)) = decoded(data) else {
        return;
    };
    // The encoding is not canonical on the way in, so compare what the
    // options say rather than their bytes.
    let mut out = vec![0u8; data.len() * 2 + 16];
    let mut encoder = OptionEncoder::new(&mut out);
    for (number, value) in &options {
        encoder.put(*number, value).expect("room for every option");
    }
    let len = encoder.finish();
    let (again, consumed) = decoded(&out[..len]).expect("an encoded block decodes");
    assert_eq!(options, again);
    assert_eq!(consumed, len);
}

fn trace(mut fields: Fields<'_>) {
    let own = TraceRecord {
        hint: RouterHint([fields.u8(), fields.u8()]),
        signal: HopSignal::from_bytes([fields.u8(), fields.u8()]),
    };
    let budget = usize::from(fields.u8());
    let value = fields.rest();
    let Some(trace) = TraceRef::parse(value) else {
        return;
    };
    assert_eq!(trace.entries().count(), trace.len());
    let mut out = [0u8; MAX];
    let Some(len) = trace.forwarded(own, budget, &mut out) else {
        return;
    };
    assert!(option_record_len(len) <= budget, "over the budget");
    let forwarded = TraceRef::parse(&out[..len]).expect("a forwarded trace parses");
    // The newest hop is this one, unless the budget left room for nothing
    // but the marker of a truncated trace. Forms only degrade.
    if !forwarded.is_empty() {
        assert_eq!(forwarded.entries().next().map(|e| e.hint), Some(own.hint));
    }
    if trace.form() == TraceForm::Truncated {
        assert_eq!(forwarded.form(), TraceForm::Truncated);
    }
    if trace.form() == TraceForm::HintsOnly {
        assert_ne!(forwarded.form(), TraceForm::Signal);
    }
}

pub fn run(data: &[u8]) {
    if data.len() > MAX {
        return;
    }
    round_trip(data);
    trace(Fields::new(data));
}
