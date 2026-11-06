#![no_main]

use libfuzzer_sys::fuzz_target;
use umsh_fuzz_harness::targets::uri_base58;

fuzz_target!(|data: &[u8]| uri_base58::run(data));
