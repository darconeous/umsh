#![no_main]

use libfuzzer_sys::fuzz_target;
use umsh_fuzz_harness::targets::umsh_packet;

fuzz_target!(|data: &[u8]| umsh_packet::run(data));
