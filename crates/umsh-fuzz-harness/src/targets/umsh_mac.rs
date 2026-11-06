//! The whole node: frames sealed for known parties, local sends, acks,
//! counter resync, and an honest peer at the end to prove nothing was lost.

use crate::mac::{self, Mode, Oracles};

pub fn run(data: &[u8]) {
    mac::run(data, Mode::Sealed, Oracles::All);
}
