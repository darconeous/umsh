//! Print a Mac script and what each run of it delivered, for triage.
//!
//! `cargo run -p umsh-fuzz-harness --example explain_mac -- <file>`

use umsh_core::PacketHeader;
use umsh_fuzz_harness::mac::{self, Mode, Oracles};
use umsh_fuzz_harness::script::records;

const OPS: [&str; 7] = ["config", "rx", "advance", "send", "ack", "answer", "fault"];

fn main() {
    let path = std::env::args().nth(1).expect("a script file");
    let data = std::fs::read(path).expect("a readable script");
    for record in records(&data) {
        let op = OPS[usize::from(record.op % 7)];
        if op == "rx" && record.body.len() > 6 {
            let selector = record.body[0];
            let frame = &record.body[6..];
            let dt = u16::from_be_bytes([record.body[1], record.body[2]]);
            let origin = record.body[5] % 8;
            println!("rx selector={selector:#x} dt={dt} origin={origin} frame={frame:02x?}");
            match PacketHeader::parse(frame) {
                Ok(header) => println!(
                    "   {:?} counter={:?} ack={}",
                    header.packet_type(),
                    header.sec_info.map(|info| info.frame_counter),
                    header.ack_requested()
                ),
                Err(error) => println!("   unparsed: {error:?}"),
            }
        } else {
            println!("{op} {:02x?}", record.body);
        }
    }
    for omit_raw in [false, true] {
        let outcome = mac::run(&data, Mode::Sealed, Oracles::Compare { omit_raw });
        println!("omit_raw={omit_raw}");
        for delivered in &outcome.received {
            println!("   {delivered:02x?}");
        }
        println!("   {} peers", outcome.peers.len());
    }
}
