#![no_main]

use libfuzzer_sys::fuzz_target;
use umsh_fuzz_harness::targets::ulcp_gatt;

fuzz_target!(|data: &[u8]| ulcp_gatt::run(data));
