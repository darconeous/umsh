//! Flatten a corpus into the file `umshctl replay` reads.
//!
//! `cargo run -p umsh-fuzz-harness --example export_replay -- OUT DIR...`
//!
//! The file is the script format with two kinds of record: 1, a frame for a
//! board's host link, and 2, a frame for the air. `umshctl` reads it with no
//! dependency on this crate. Radio frames are sealed for the harness's keys,
//! so the file opens with the provisioning that makes a board hear them.

use std::fs;

use umsh_fuzz_harness::fixup;
use umsh_fuzz_harness::script::{Fields, push_record, records};
use umsh_fuzz_harness::targets::ulcp_device as dev;
use umsh_ulcp::frame::FRAME_IN_MAX;
use umsh_ulcp::hdlc;

const KIND_HOST: u8 = 1;
const KIND_RADIO: u8 = 2;

fn export(out: &mut Vec<u8>, script: &[u8]) {
    let mut decoder = hdlc::Decoder::<FRAME_IN_MAX>::new();
    for record in records(script) {
        match record.op {
            dev::OP_FRAME | dev::OP_DEVICE if record.body.len() <= FRAME_IN_MAX => {
                push_record(out, KIND_HOST, record.body);
            }
            dev::OP_BYTES => {
                for &byte in record.body {
                    if let Some(Ok(frame)) = decoder.push(byte) {
                        push_record(out, KIND_HOST, frame);
                    }
                }
            }
            dev::OP_RADIO => {
                let mut fields = Fields::new(record.body);
                let selector = fields.u8();
                let _ = (fields.u8(), fields.u8(), fields.u8());
                push_record(out, KIND_RADIO, &fixup::apply(fields.rest(), selector));
            }
            _ => {}
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("an output file, then corpus directories");
    let mut out = Vec::new();
    for frame in dev::provisioning() {
        push_record(&mut out, KIND_HOST, &frame);
    }
    let mut inputs = 0;
    for directory in args {
        let mut entries: Vec<_> = fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("{directory}: {error}"))
            .map(|entry| entry.expect("a readable directory").path())
            .collect();
        entries.sort();
        for entry in entries {
            export(&mut out, &fs::read(entry).expect("a readable input"));
            inputs += 1;
        }
    }
    fs::write(&path, &out).expect("a writable output");
    println!("{inputs} inputs, {} bytes, in {path}", out.len());
}
