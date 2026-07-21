# firmware-esp32 — Espressif (Xtensa) sibling workspace

Firmware and BSPs for Espressif targets: the
[Heltec WiFi LoRa 32 V3](../docs/heltec-lora32-v3-hardware.md) (ESP32-S3,
active) and the [Heltec WiFi LoRa 32 V2](../docs/heltec-lora32-v2-hardware.md)
(classic ESP32, parked). This is a separate cargo workspace because the
Xtensa chips need the Xtensa Rust fork (`rust-toolchain.toml` here pins
`channel = "esp"`), which cannot coexist with the root workspace's toolchain
file — see the decision table in
[firmware-architecture.md](../docs/firmware-architecture.md) and the plans in
[firmware-plan-heltec-lora32-v3.md](../docs/firmware-plan-heltec-lora32-v3.md)
/ [firmware-plan-heltec-lora32-v2.md](../docs/firmware-plan-heltec-lora32-v2.md).

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
make build-hello-heltec-v3
make flash-hello-heltec-v3       # espflash over the CP2102, then monitor
make flash-ble-spike-heltec-v3 ESPFLASH_PORT=/dev/cu.usbserial-0001
```

(`*-heltec-v2` targets are the parked classic-ESP32 equivalents.)

The workspace `.cargo/config.toml` carries only chip-agnostic settings
(espflash runner, linker flags, build-std); each firmware selects its
own target triple — plus any chip-quirk env overrides, like the Heltec
V2's ancient-silicon `ESP_HAL_CONFIG_MIN_CHIP_REVISION` floor — in a
per-firmware `.cargo/config.toml`. Per-directory configs only apply when
cargo runs from inside the directory, so build each firmware **from
inside its own directory** (`cargo build --release` there, or `cargo run
--release` to flash+monitor) — the Makefile targets do exactly that.
Flashing uses the mask-ROM serial bootloader with DTR/RTS auto-entry —
there is no bootloader to brick and no DFU/UF2 machinery.

## Version pins

The whole esp-hal family (esp-hal, esp-rtos, esp-radio, esp-alloc,
esp-println, esp-bootloader-esp-idf) is pinned to a single git rev of
esp-rs/esp-hal in this workspace's `[patch.crates-io]` — the published
esp-radio 1.0.0-beta.0 speaks bt-hci 0.8 while our audited trouble-host
fork requires bt-hci 0.9; main carries the 0.9 bump. All family members
must move together (they share in-repo path dependencies). Drop the block
when esp-radio > beta.0 ships. `lora-phy`/`lora-modulation`/`trouble-host`
patches mirror the root workspace and must stay in lockstep with it.
