#![no_main]

use libfuzzer_sys::fuzz_target;
use umsh_fuzz_harness::targets::ulcp_frame;

fuzz_target!(|data: &[u8]| ulcp_frame::run(data));
