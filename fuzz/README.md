# Fuzzing

Coverage-guided fuzzers for UMSH and ULCP. The targets themselves live in
`crates/umsh-fuzz-harness`; this directory holds only thin `fuzz_target!`
wrappers, in a workspace of its own so the root's size-tuned release profile
stays out of the way.

Nothing here runs on stable, and nothing else depends on it. `cargo test`
replays every committed seed and regression without libFuzzer.

## Running

```bash
cargo install cargo-fuzz --locked
```

```bash
make fuzz TARGET=text_engine FUZZ_SECONDS=600
```

`FUZZ_SANITIZER` defaults to `none`: these crates have no `unsafe` of their own
to watch, and it doubles the speed. `FUZZ_SANITIZER=address` covers
dependencies. The list of targets is in `crates/umsh-fuzz-harness/src/targets/mod.rs`.

On macOS the Makefile passes `-undefined dynamic_lookup` to the linker: two
dependencies declare `cdylib`, and the instrumentation's symbols stay unresolved
in those until the fuzz binary supplies them. Set the same `RUSTFLAGS` when
calling `cargo fuzz` by hand.

## A crash

Rank it by who can reach it: the radio with no keys, a channel member, a known
peer or admin, the local host, or a misbehaving device talking to its host.

A crash may be the oracle's fault rather than the code's, so read what the
target asserted before changing product code.

A hang counts as a crash. A Mac spin panics with `the node never went idle`;
anything else past `FUZZ_TIMEOUT` seconds is saved as `timeout-...`, and in
`cargo test` the replay watchdog stops the run and names the input.

1. Shrink it.

   ```bash
   make fuzz-min TARGET=text_engine INPUT=artifacts/text_engine/crash-...
   ```

2. Commit the result as `crates/umsh-fuzz-harness/regressions/<target>/<what-it-is>`.
   It fails `cargo test` until the bug is fixed, and guards it from then on.

3. Fix the cause, with a focused unit test beside the code. An overflow that
   only panics with checks on still gets fixed, because the wrapped value is
   still wrong. An error that is expected in normal operation is handled by
   dropping the bad item, never by a reset.

## Seeds

`make fuzz-seeds` regenerates `crates/umsh-fuzz-harness/seeds/` from the real
encoders and the dissector's captures. Run it after changing a wire format.
The evolved corpus is not committed. It lives in the nightly job's cache, and
locally under `fuzz/corpus/`.

## Scripts

Stateful targets read a script of `[op][len-hi][len-lo][bytes]` records rather
than `arbitrary` input, so seeds can come from real encoders. Reading is total:
a corrupt length clamps instead of rejecting. Those targets splice scripts on
record boundaries with `fuzz_crossover!`.

## Reaching code behind the MIC

Product code has no fuzzing bypass. An rx op carries selector bytes, and the
harness treats its frame as plaintext, stamps it for a key it knows, and seals
it through the public API. One selector value leaves the frame raw.

## On a real board

Host fuzzing cannot see stack overflow, flash wear, or a real driver's limits.
To put a corpus onto a board set aside for it:

```bash
cargo run -p umsh-fuzz-harness --example export_replay -- replay.bin fuzz/corpus/ulcp_device
```

```bash
umshctl -p PORT replay replay.bin --bench KEY
```

This scrambles the board's settings, and `--bench` names the board it may run
on. Reboots, factory resets, DFU, bus transfers, and identity changes are held
back, and saves are rate-limited. A probe that goes unanswered stops the run and
writes the last frames to `replay-failure.bin`, which replays the same way.

`--watch PORT` puts the radio frames on the air from the attached board and
probes the bench board on `PORT`. Keep that within the region's duty limits,
and use an attenuator or a dummy load if you can.
