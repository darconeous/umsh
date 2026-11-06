#![no_main]

use libfuzzer_sys::fuzz_target;
use umsh_fuzz_harness::targets::node_mgmt_envelope;

fuzz_target!(|data: &[u8]| node_mgmt_envelope::run(data));
