#![no_main]

use libfuzzer_sys::fuzz_target;
use umsh_fuzz_harness::targets::lan_bridge;

fuzz_target!(|data: &[u8]| lan_bridge::run(data));
