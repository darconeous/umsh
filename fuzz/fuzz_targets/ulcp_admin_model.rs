#![no_main]
use libfuzzer_sys::{fuzz_crossover, fuzz_target};
use umsh_fuzz_harness::{script, targets::ulcp_admin_model};

fuzz_target!(|data: &[u8]| ulcp_admin_model::run(data));
fuzz_crossover!(|a: &[u8], b: &[u8], out: &mut [u8], seed: u32| {
    script::crossover(a, b, out, seed)
});
