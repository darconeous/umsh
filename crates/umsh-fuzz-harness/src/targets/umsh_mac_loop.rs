//! Two whole nodes over a link that loses and repeats frames.

use crate::mac;

pub fn run(data: &[u8]) {
    mac::run_loop(data);
}
