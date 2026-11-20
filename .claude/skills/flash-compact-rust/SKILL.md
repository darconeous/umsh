---
name: flash-compact-rust
description: Write and review Rust that ships in the flash-constrained nRF52840 images (and the shared crates they link, such as umsh-ulcp-runtime, umsh-ulcp-device, umsh-mac and umsh-node) without wasting flash, and find and measure what an image is paying for. Use when adding code to those crates, when an nRF52 image overflows or grows, or when asked to shrink one.
---

# Flash-compact Rust

The nRF52840 images run close to their application flash window. The T-Echo
(760 KB) and the Wio Tracker L1 (756 KB) are the tightest, so measure one of
them, not only the T1000-E. The ESP32 images matter less.

The release profile is already `opt-level = "z"`, fat LTO, one codegen unit,
and `--icf=all` (root `Cargo.toml`, `firmware/*/.cargo/config.toml`). Leave
those alone: fat LTO at `opt-level = 3` made the image larger than no LTO at
all.

## Measure, never guess

Inlining is not local. One type change (a `{bool, Option<Enum>}` struct
replaced by a niche-packed enum) grew `run_with_storage` by 760 bytes, and a
callback type cost 13.7 KB in a function nobody looked at. Attribute every
change by its symbol diff.

1. Build from the board's own directory, in release (dev overflows flash):
   `cd firmware/techo && cargo build --release`. Building from the root with
   `-p` drops the target flags. An incremental rebuild takes about 20 s.
2. Keep the baseline: `arm-none-eabi-nm -S -C <elf> > base.nm` (or copy the
   ELF) before changing anything. The ELF is at
   `target/thumbv7em-none-eabihf/release/firmware-<board>`.
3. Change one thing, rebuild, and diff:
   `python3 .claude/skills/flash-compact-rust/scripts/flash_symbols.py diff base.nm <elf>`.
4. Report `arm-none-eabi-size` too: flash used is `text + data`, against
   `FLASH LENGTH` in the board's `memory.x`.

The same script lists the largest symbols (`top`) and functions instantiated
more than once (`dups`). `arm-none-eabi-objdump -d --no-show-raw-insn
--start-address=… --stop-address=…` on one function, piped through `grep bl`,
shows what it calls and how often.

## Rules, by measured payoff

### 1. A callback on a large method is `&mut dyn FnMut`, not `impl FnMut`

Each closure literal is its own type, so every call site instantiates its own
copy of the generic method and of everything it inlines. `Session` took
`emit: &mut impl FnMut(&[u8])` on 88 methods, and the driver passed a fresh
`&mut |frame| emitter.push(frame)` at each call. Switching to
`&mut dyn FnMut(&[u8])` saved **13,692 bytes** on a T1000-E: `serve_frame`
held inlined copies of `dispatch_frame`, `prop_set` and `apply_prop_set`.
The cost is one indirect call per invocation.

Most of the duplication was inlined, so `dups` showed only the tip (about
1.4 KB of small `complete`/`send_prop_is` siblings). A small method
appearing several times with `::<…{closure#0}…>` arguments, beside one huge
caller, is the sign. Keep `impl FnMut` only for a small hot function called
from one place.

### 2. A method that only forwards a future returns it

`async fn x(&self) -> T { self.inner.x().await }` builds a state machine per
instance just to poll another one. Write
`fn x(&self) -> impl Future<Output = T> { self.inner.x() }` instead.
- It is allowed where the trait declares `async fn` or `-> impl Future`.
- In edition 2024 the returned future captures the same lifetimes.
- The arguments are evaluated at the call rather than at the first poll. That
  is harmless when the inner method is itself an `async fn`, which does
  nothing before it is polled.

Measured: `Borrowed`, one `exec` wrapper per HCI command type, 1,260 bytes;
the `MacBackend` impl for `MacHandle`, 1,596; the `LocalNode` forwarders, 200
(mostly inlined already). `async fn owe() { self.frames.send(copy).await }`
cost 92 bytes more than returning the `SendFuture`. Leave a one-line comment
over such methods: they look like something to tidy back into `async fn`.

### 3. A fact fixed at build time is a cargo feature, not a runtime `Option` or `bool`

A path that never runs because a field is `None` is still compiled, and an
`.await` on it costs flash even though it never runs: its resume state stays
in the state machine. Making `DeviceLink::publish` async for one build added
an await to four call sites in every build (+92); the `publish!` macro in
`driver.rs` makes the await itself conditional instead. Gating the device's
own interface behind `device-link` saved 1,992 bytes. The pattern:

- Put `#[cfg]` on the enum variants whose arms await (`InEvent::Device`,
  `ReplySink::Device`), and on those arms.
- Read the remaining fields through a `cfg!` constant, as `linked()` and
  `DeviceRuntime::device()` do, so the compiler folds the branches away
  without `cfg` on every constructor and test. A value read back out of a
  struct inside another function is not folded: apply the helper at that
  read site too.
- Make the type impossible to construct without the feature
  (`DeviceLink::new` is gated). Otherwise a board could pass `Some(..)`, and
  the link would be silently ignored.
- Give tests that need the feature `#[cfg(feature = …)]` and a CI line
  that names it. Feature unification across the workspace is not coverage.

### 4. Await once, but look first

Computing a value in each branch and awaiting it once saved 24 bytes in one
case. Do not restructure on faith: the ~25 `emitter.flush(sink).await` calls
in `serve_frame` had already been merged by LLVM into 2 call sites. Count the
`bl` calls in the disassembly before hand-merging.

### 5. Watch what the standard library brings in

- `slice::sort_by_key` (driftsort) cost 3.0 KB for one small slice of
  `(u64, MergedPeerRepeater)` in `peer_repeaters.rs`. For a handful of
  elements, a short insertion sort is a few hundred bytes at most.
- Symbols matching `fmt` add up to roughly 17 KB of the T1000-E, partly
  for persisting panic messages. Every `{:?}` that survives pulls in that
  type's `Debug` impl. The firmware's own `debug_log` in `main.rs` ignores
  its arguments unless `ble-debug` is on, so a line written through it
  directly should cost nothing. The shared crates'
  `umsh_ulcp_runtime::log::debug_log` calls a sink installed at run time
  through a function pointer, so the compiler cannot drop what it formats.
  Both points are reasoned from the code, not measured.

## Before calling a change done

- Diff the nm against the previous commit on the T-Echo or Wio Tracker L1,
  and give the byte count with the change.
- Say which numbers are measured and which are reasoned.
- Check the build with the feature off and on, and an image that enables it
  (a XIAO `ulcp-uart` build, an ESP32 `communicator` build).
