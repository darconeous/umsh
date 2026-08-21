# UMSH

Experimental, LoRa-oriented mesh protocol with strong cryptography, strict layer
separation, and tight bandwidth discipline. Inspired by MeshCore but redesigned:
endpoints are identified by Ed25519 public keys, multicast uses shared symmetric
channel keys, and the MAC layer is timestamp-free (monotonic frame counters for
replay protection) with AES-SIV (RFC 5297) nonce-misuse-resistant encryption. The repo
holds the protocol **spec**, a Rust **reference implementation**, embedded
**firmware** for several LoRa boards, an **iOS app**, and a **Wireshark dissector**.

Spec: `docs/protocol/` (mdBook). Everything here was written with heavy LLM
assistance and is explicitly experimental — expect code smells and WIP APIs.

There is no significant installed user base, so versioning and migration are a matter
of immediate convenience and not mandatory at this time. Carefully weigh the design
costs of migration before considering implementing it.

## Repository layout

- `crates/` — host-side + `no_std` library crates (the reference implementation).
  `umsh-hal` is standalone (no workspace deps); `umsh-bsp-*` are board support over a
  shared `nrf52840` base.
- `umsh/` — umbrella crate re-exporting the workspace; defines the `Platform` trait + Tokio/Embassy adapters. **Library only** — host binaries live in `tools/`, which is what keeps clap/rustyline out of the umbrella's dependency tree.
- `firmware/` — nRF52840 firmware (thumbv7em, UF2/DFU). **One shipping image per board** (t1000e / techo / sensecap-solar / wio-tracker-l1 / xiao-nrf52) — there is no separate repeater build; role is configuration. All five are thin manifests over the shared `firmware/nrf52-tracker/src/main.rs`, differing only by their `board-*` feature. The existing `*-console` builds are per-board bringup harnesses, not products; **new boards do not get one** (xiao-nrf52 ships the device image only).
- `firmware-esp32/` — **separate cargo workspace** for Xtensa boards (Heltec LoRa32 V2 parked, V3 active). See `firmware-esp32/CLAUDE.md` for its toolchain.
- `apps/ios/` — SwiftUI app; `packages/UMSHMobileCore` — UniFFI Swift package.
- `tools/` — host binaries and dev tooling (`crates/` is reserved for library crates):
  - `umshctl` — the radio tool (clap + rustyline; capture is a subcommand)
  - `umsh-bridge` — the internet bridge daemon (`docs/protocol/src/internet-bridging.md`); lib+bin split so the integration tests can stand a whole bridge up in one process. TOML config + `tracing`, its own dependency table
  - `regiondb-build` — the region-database compiler. **Python, not Rust**, and the repo's only
    packaged Python (`pyproject.toml` + `uv.lock`, run through `uv`); `scripts/` stays
    stdlib-only because building firmware must need nothing but a Rust toolchain
  - `ulcp-web-debugger`, `uniffi-bindgen`
- `regions/` — source data and manifests for the geographic region database, plus the
  committed test fixture. Three stages with distinct commit policies: `regions-fetch`
  (network → gitignored `vendor/`), `regions-update` (→ **committed** `extracts/`), and
  `regions-build` (committed tree → `dist/`). The global country boundary layer is the one
  layer too large to commit and stays on the fetch path. See `regions/README.md` and
  `regions/FORMAT.md`.
- `docs/` — protocol spec (`protocol/`), per-board hardware docs, firmware/feature plans, UX.
- `dissectors/umsh/` — Wireshark Lua dissector. `diag/`, `contrib/systemd/`, `scripts/` (`mkuf2.py` builds the UF2, `flash.py` only flashes one, board table in `firmware_image.py`).

## Build / test

- **Formatting**: enable the checked-in pre-commit hook once per clone with `git config core.hooksPath .githooks`. It rejects commits that aren't rustfmt-clean in either workspace; CI checks the same two. `firmware-esp32/` needs `cargo +stable fmt --all` (its `rust-toolchain.toml` pins the `esp` channel; stable rustfmt gives identical output).

- Host: `cargo build` / `cargo test` / `cargo check` from root — **skips `firmware/*`** by design (`default-members`); host crates only.
- Firmware crates are **excluded from default builds** and must be built from inside their own directory so the per-firmware `.cargo/config.toml` (target triple + linker flags) is picked up. Building with `--manifest-path`/`-p` from root silently drops those flags and yields a broken ELF.
- nRF52840 firmware **only links in `--release`** (dev overflows flash). `cargo check` is fine at any profile.
- No bindgen env vars needed — plain `cargo build --release` works (do NOT set LIBCLANG_PATH/BINDGEN_EXTRA_CLANG_ARGS).
- Region database: `make regions-test` (ruff + pytest + `cargo test -p umsh-regiondb`) and
  `make regions-check` both run offline against the **committed** `regions/tests/fixture/`
  database. `cargo test` never builds one — regenerate it with `make regions-build-fixture`
  after changing the fixture tree or the compiled format, and regenerate
  `regions/tests/conformance.json` with it.

## Flashing

Use the Makefile — don't invoke objcopy/uf2conv/espflash by hand. Per-board targets, DFU
entry, UF2 families, and flash-layout gotchas: see the `flashing` skill.

Docs: `make docs` (mdBook), `make rust-docs`, `make docs-serve`, `make web-debugger` (wasm).

## Releasing firmware

Tagged `fw-YYYY.MM.NN` (annotated), cut locally: tag HEAD, then `make release-artifacts`,
then `release-publish` and `release-mirror`. GitHub Releases are the archive;
`umsh.dev/firmware/` mirrors what the web flasher can actually `fetch()`, because
GitHub's release assets send no CORS headers. Runbook, artifact table, manifest
schema, and the hardware checklist: `docs/firmware-releases.md`.

## Quirks & conventions

- **Serial ports**: never use shell redirection (`<`/`>`/`exec`) against `/dev/cu.usbmodem*` — use kermit/screen or ask the user. Before diagnosing "dead" hardware, check `ps` for orphaned background serial watchers holding the port.
- **Prefer native tools** (Read/Grep/Glob) over `cat`/`sed`/`grep`/`find`; avoid `&&`/`;` command chains — both cause approval prompts / cache-expiry cost.
- **RNG**: no non-crypto RNG anywhere. nRF boards use the hardware TRNG (`Nrf52840Rng`); `FicrXorShift64Rng` is considered radioactive.
- **Wire encoding**: big-endian numerics; hashes/keys/signatures as canonical bytes; CoAP-style delta-length option encoding (0xFF end-marker only when data follows options).
- **Receiver tolerance**: wire limits are sender MUST-NOTs; over-limit receivers drop-with-accounting, never "MUST drop".
- **Big statics**: build the ~37K `Mac` via `StaticCell::init_with` in one expression, never on the stack (256K budget minus statics).
- **Async**: shared-`AsyncRefCell` poll_fn drivers must use `poll_with_mut` (register-before-borrow self-wakes into a 100% CPU spin). `Spawner` accepts `!Send` tasks; only `SendSpawner` needs `Send`.
- **American English**, everywhere: prose, comments, commit messages, UI strings. It is *license*, *center*, *color*, *meters*, *airplane mode*, *analyze*, *labeled*. This has gone wrong before — a whole page of site copy came out British (*licence*, *metres*, *aeroplane mode*) because the formal register carried the orthography with it. Writing in a more literary voice is not a reason to switch dialects; if the prose starts sounding like a magazine, check the spelling.
- **Em dashes are unspaced**: `like this—not like this`. This is the user's personal style; the whole site was written the wrong way and had to be converted. Title/tab separators (`{{ page.title }} — UMSH`) and aligned definition lists in comments are delimiters, not prose, and keep their spaces.
- **Spec tone**: no historical/changelog framing, no over-clarifying, no prescriptive unimplemented features. UMSH is more than a MAC layer — avoid "strictly/only the MAC layer".
- **Git**: commit only when asked; batch changes. Board bringup status, storage decisions, and many hardware gotchas live in the persistent memory index (`memory/MEMORY.md`) — consult it for board-specific detail.
- **Questions are not calls to action**: Do not assume that the user asking a question implies that you should take action. Answer the question. Do not make code changes unless that was explicitly requested by the user.
- **Remember your current directory**: Avoid unnecessarily prepending `cd <PROJECTDIR> &&` to bash commands,  as this causes unnecessary permission prompts.
- **Use the label `LLM: ...` instead of `Co-Authored-By: ...` in commit logs**: `Co-Authored-By` attributions cause a Claude logo to appear on our GitHub project which is unacceptable.
- **Don't take credit for stuff you aren't sure you wrote**: Unless you are absolutely certain the changes are yours, DO NOT add a "LLM: ..." line in the git commit log.
- **Use tools to make edits instead of writing inline python scripts**: Unless it is for an unusually large edit, prefer using the normal file editing tools instead of writing in-line python scripts.
- **Avoid quick, non-ideomatic fixes that don't address real underlying problems**: If you are trying to fix a bug that was reported by the user, once you have identified the root cause think carefully about if there is an underlying structural issue that should be addressed rather than just directly addressing the symptom.
- **Do not blindly run the full test suite**: The full test suite takes too long. Only run the tests relevant to what you have changed. Leave it to CI to run the full test suite.