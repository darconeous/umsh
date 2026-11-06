#![no_main]

use libfuzzer_sys::fuzz_target;
use umsh_fuzz_harness::targets::ulcp_hdlc;

fuzz_target!(|data: &[u8]| ulcp_hdlc::run(data));
