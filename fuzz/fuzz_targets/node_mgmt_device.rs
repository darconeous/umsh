#![no_main]
use libfuzzer_sys::{fuzz_crossover, fuzz_target};
use umsh_fuzz_harness::{script, targets::node_mgmt_device};

fuzz_target!(|data: &[u8]| node_mgmt_device::run(data));
fuzz_crossover!(|a: &[u8], b: &[u8], out: &mut [u8], seed: u32| {
    script::crossover(a, b, out, seed)
});
