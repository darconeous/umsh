#![no_main]

use libfuzzer_sys::{fuzz_crossover, fuzz_target};
use umsh_fuzz_harness::{script, targets::text_engine};

fuzz_target!(|data: &[u8]| text_engine::run(data));

fuzz_crossover!(|a: &[u8], b: &[u8], out: &mut [u8], seed: u32| {
    script::crossover(a, b, out, seed)
});
