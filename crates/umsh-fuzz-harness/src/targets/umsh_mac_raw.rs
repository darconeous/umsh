//! A repeater hearing whatever is on the air, with no keys in play.
//! Forwarding needs none, so this reaches real work on raw mutation.

use crate::mac::{self, Mode, Oracles};

pub fn run(data: &[u8]) {
    mac::run(data, Mode::Raw, Oracles::Termination);
}
