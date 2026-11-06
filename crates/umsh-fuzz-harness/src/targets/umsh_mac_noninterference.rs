//! Traffic that fails its MIC changes nothing an honest party can see: a
//! script runs twice, the second time without those frames, and must deliver
//! the same things and hold the same peers.

use crate::mac::{self, Mode, Oracles};

pub fn run(data: &[u8]) {
    let with = mac::run(data, Mode::Sealed, Oracles::Compare { omit_raw: false });
    let without = mac::run(data, Mode::Sealed, Oracles::Compare { omit_raw: true });
    assert_eq!(
        with.received, without.received,
        "unauthenticated frames changed what was delivered"
    );
    assert_eq!(
        with.peers, without.peers,
        "unauthenticated frames changed who is known"
    );
}
