#![no_main]

use libfuzzer_sys::fuzz_target;
use umsh_fuzz_harness::targets::umsh_options;

fuzz_target!(|data: &[u8]| umsh_options::run(data));
