#![no_main]

use libfuzzer_sys::fuzz_target;
use umsh_fuzz_harness::targets::text_codec;

fuzz_target!(|data: &[u8]| text_codec::run(data));
