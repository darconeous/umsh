# UMSH

Experimental, LoRa-oriented mesh protocol with strong cryptography, strict layer
separation, and tight bandwidth discipline. Inspired by MeshCore but redesigned:
endpoints are identified by Ed25519 public keys, multicast uses shared symmetric
channel keys, and the MAC layer is timestamp-free (monotonic frame counters for
replay protection) with AES-SIV-style nonce-misuse-resistant encryption. The repo
holds the protocol **spec**, a Rust **reference implementation**, embedded
**firmware** for several LoRa boards, an **iOS app**, and a **Wireshark dissector**.

Spec: `docs/protocol/` (mdBook). Everything here was written with heavy LLM
assistance and is explicitly experimental — expect code smells and WIP APIs.

There is no significant installed user base, so versioning and migration are a matter
of immediate convenience and not mandatory at this time. Carefully weigh the design
costs of migration before considering implementing it.

## Repository layout

- `crates/` — host-side + `no_std` library crates (the reference implementation):
  - `umsh-core` — wire-format types, packet parse/build
  - `umsh-crypto` — crypto traits + UMSH key/packet ops (Ed25519, AES-SIV-style, HKDF)
  - `umsh-mac` — MAC-layer coordinator + state
  - `umsh-node` — application-facing node layer atop the MAC
  - `umsh-hal` — minimal hardware abstraction traits (standalone, no workspace deps)
  - `umsh-text` / `umsh-chat-room` — application protocols
  - `umsh-uri` — URI/address parsing & formatting (fixed-44 base58 + star-truncated hints)
  - `umsh-sync` — single-threaded async primitives (`AsyncRefCell`, `AsyncCondition`)
  - `umsh-ulcp` / `-ulcp-device` / `-ulcp-runtime` — ULCP (local control protocol) wire/session/runtime
  - `umsh-mobile-core` — stable value-oriented facade for mobile apps (UniFFI)
  - `umsh-flash-store` / `umsh-journal-store` — sequential-storage NV storage + power-safe journals
  - `umsh-radio-loraphy` — `umsh-hal::Radio` over any `lora-phy` RadioKind
  - `umsh-bsp-*` — board support: `nrf52840` (shared base), `t1000e`, `techo`, `wio-tracker-l1`, `sensecap-solar`
  - `umsh-ux-tracker` — single-button/LED/buzzer UX for tracker boards
  - `umsh-ux-display-tracker` — menu + display-attention + input-gate UX shared by display trackers (t-echo, heltec-v3, wio-tracker-l1)
  - `umsh-cli` / `umsh-app-ulcp-cli` — host CLI + CLI-console firmware logic
- `umsh/` — umbrella crate re-exporting the workspace; defines the `Platform` trait + Tokio/Embassy adapters. **Library only** — host binaries live in `tools/`, which is what keeps clap/rustyline out of the umbrella's dependency tree.
- `firmware/` — nRF52840 firmware (thumbv7em, UF2/DFU). **One shipping image per board** (t1000e / techo / sensecap-solar / wio-tracker-l1) — there is no separate repeater build; role is configuration. All four are thin manifests over the shared `firmware/nrf52-tracker/src/main.rs`, differing only by their `board-*` feature. The `*-console` builds are per-board bringup harnesses, not products.
- `firmware-esp32/` — **separate cargo workspace** for Xtensa boards (Heltec LoRa32 V2 parked, V3 active). Own `rust-toolchain.toml` pinning `channel = "esp"`.
- `apps/ios/` — SwiftUI app; `packages/UMSHMobileCore` — UniFFI Swift package.
- `tools/` — host binaries and dev tooling (`crates/` is reserved for library crates):
  - `umshctl` — the radio tool (clap + rustyline; capture is a subcommand)
  - `umsh-bridge` — the internet bridge daemon (`docs/protocol/src/internet-bridging.md`); lib+bin split so the integration tests can stand a whole bridge up in one process. TOML config + `tracing`, its own dependency table
  - `ulcp-web-debugger`, `uniffi-bindgen`
- `docs/` — protocol spec (`protocol/`), per-board hardware docs, firmware/feature plans, UX.
- `dissectors/umsh/` — Wireshark Lua dissector. `diag/`, `contrib/systemd/`, `scripts/flash.py`.

## Build / test

- **Formatting**: enable the checked-in pre-commit hook once per clone with `git config core.hooksPath .githooks`. It rejects commits that aren't rustfmt-clean in either workspace; CI checks the same two. `firmware-esp32/` needs `cargo +stable fmt --all` (its `rust-toolchain.toml` pins the `esp` channel; stable rustfmt gives identical output).

- Host: `cargo build` / `cargo test` / `cargo check` from root — **skips `firmware/*`** by design (`default-members`); host crates only.
- Firmware crates are **excluded from default builds** and must be built from inside their own directory so the per-firmware `.cargo/config.toml` (target triple + linker flags) is picked up. Building with `--manifest-path`/`-p` from root silently drops those flags and yields a broken ELF.
- nRF52840 firmware **only links in `--release`** (dev overflows flash). `cargo check` is fine at any profile.
- No bindgen env vars needed — plain `cargo build --release` works (do NOT set LIBCLANG_PATH/BINDGEN_EXTRA_CLANG_ARGS).

## Flashing (use the Makefile — don't invoke objcopy/uf2conv/espflash by hand)

nRF52840 (UF2/DFU via `scripts/flash.py`; device must be in DFU mode: 1200-baud touch, double-tap reset, or hold-boot-while-plugging):
- `make flash-techo-console`, `make flash-techo`
- `make flash-wio-tracker-l1-console`, `make flash-wio-tracker-l1` (UF2 drive `/Volumes/TRACKER L1`; app base `0x27000` — S140 v7.3.0, **not** the T-Echo's `0x26000`)
- `make flash-t1000e-console` (UF2 drive) or `make flash-t1000e-console-serial` (T1000-E button-bootloader exposes only serial; override `DFU_SERIAL_PORT=/dev/tty.usbmodemN`)
- `make flash-sensecap-solar` (shipping image) or `make flash-sensecap-solar-console`

ESP32 (build from `firmware-esp32/`; needs espup toolchain: `cargo install espup espflash && espup install`). Flash via ROM serial bootloader — cannot be bricked, stays attached as monitor:
- `make flash-heltec-v3`, `make flash-heltec-v3-console` (override `ESPFLASH_PORT=...`)
- ESP32 flashes rewrite the partition table (`partitions-umsh.csv`, carries the 64 KB `umsh` data partition) — reflashing loses data past the old factory partition.

Docs: `make docs` (mdBook), `make rust-docs`, `make docs-serve`, `make web-debugger` (wasm).

## Quirks & conventions

- **Serial ports**: never use shell redirection (`<`/`>`/`exec`) against `/dev/cu.usbmodem*` — use kermit/screen or ask the user. Before diagnosing "dead" hardware, check `ps` for orphaned background serial watchers holding the port.
- **Prefer native tools** (Read/Grep/Glob) over `cat`/`sed`/`grep`/`find`; avoid `&&`/`;` command chains — both cause approval prompts / cache-expiry cost.
- **RNG**: no non-crypto RNG anywhere. nRF boards use the hardware TRNG (`Nrf52840Rng`); `FicrXorShift64Rng` is considered radioactive.
- **Wire encoding**: big-endian numerics; hashes/keys/signatures as canonical bytes; CoAP-style delta-length option encoding (0xFF end-marker only when data follows options).
- **Receiver tolerance**: wire limits are sender MUST-NOTs; over-limit receivers drop-with-accounting, never "MUST drop".
- **Big statics**: build the ~37K `Mac` via `StaticCell::init_with` in one expression, never on the stack (256K budget minus statics).
- **Async**: shared-`AsyncRefCell` poll_fn drivers must use `poll_with_mut` (register-before-borrow self-wakes into a 100% CPU spin). `Spawner` accepts `!Send` tasks; only `SendSpawner` needs `Send`.
- **Spec tone**: no historical/changelog framing, no over-clarifying, no prescriptive unimplemented features. UMSH is more than a MAC layer — avoid "strictly/only the MAC layer".
- **Git**: commit only when asked; batch changes. Board bringup status, storage decisions, and many hardware gotchas live in the persistent memory index (`memory/MEMORY.md`) — consult it for board-specific detail.
- **Questions are not calls to action**: Do not assume that the user asking a question implies that you should take action. Answer the question. Do not make code changes unless that was explicitly requested by the user.
- **Remember your current directory**: Avoid unnecessarily prepending `cd <PROJECTDIR> &&` to bash commands,  as this causes unnecessary permission prompts.
- **Use the label `LLM: ...` instead of `Co-Authored-By: ...` in commit logs**: `Co-Authored-By` attributions cause a Claude logo to appear on our GitHub project which is unacceptable.
- **Don't take credit for stuff you aren't sure you wrote**: Unless you are absolutely certain the changes are yours, DO NOT add a "LLM: ..." line in the git commit log.