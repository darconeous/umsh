# firmware-esp32 — classic-ESP32 (Xtensa) sibling workspace

Firmware and BSPs for Espressif targets, currently the
[Heltec WiFi LoRa 32 V2](../docs/heltec-lora32-v2-hardware.md). This is a
separate cargo workspace because classic ESP32 needs the Xtensa Rust fork
(`rust-toolchain.toml` here pins `channel = "esp"`), which cannot coexist
with the root workspace's toolchain file — see the decision table in
[firmware-architecture.md](../docs/firmware-architecture.md) and the plan in
[firmware-plan-heltec-lora32-v2.md](../docs/firmware-plan-heltec-lora32-v2.md).

## Toolchain setup (once per machine)

```sh
cargo install espup espflash
espup install          # installs the `esp` rustup toolchain (Xtensa fork)
```

`espup update` refreshes the toolchain; esp-radio currently needs the fork
at rustc ≥ 1.95. Bare-metal builds do not need the `export-esp.sh`
environment file (that is only for esp-idf/std builds).

## Building and flashing

From the repo root, via the Makefile (preferred):

```sh
make build-hello-heltec-v2
make flash-hello-heltec-v2       # espflash over the CP2102, then monitor
make flash-ble-spike-heltec-v2 ESPFLASH_PORT=/dev/cu.usbserial-0001
```

Or from this directory: `cargo build --release`, and `cargo run --release
-p <firmware>` to flash+monitor (the workspace `.cargo/config.toml` sets
the xtensa target and the espflash runner). Flashing uses the mask-ROM
serial bootloader with DTR/RTS auto-entry — there is no bootloader to
brick and no DFU/UF2 machinery.

## Version pins

The whole esp-hal family (esp-hal, esp-rtos, esp-radio, esp-alloc,
esp-println, esp-bootloader-esp-idf) is pinned to a single git rev of
esp-rs/esp-hal in this workspace's `[patch.crates-io]` — the published
esp-radio 1.0.0-beta.0 speaks bt-hci 0.8 while our audited trouble-host
fork requires bt-hci 0.9; main carries the 0.9 bump. All family members
must move together (they share in-repo path dependencies). Drop the block
when esp-radio > beta.0 ships. `lora-phy`/`lora-modulation`/`trouble-host`
patches mirror the root workspace and must stay in lockstep with it.
