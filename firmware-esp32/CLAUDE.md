# firmware-esp32

A **separate cargo workspace** for Xtensa boards (Heltec LoRa32 V2 parked, V3 active).
Own `rust-toolchain.toml` pinning `channel = "esp"`.

- You may run into problems building ESP32 targets unless you source the file
  `~/export-esp.sh` (assuming it exists).
- Formatting here needs `cargo +stable fmt --all` — the pinned `esp` channel's rustfmt
  isn't what CI checks, and stable rustfmt gives identical output.
- Flashing: see the `flashing` skill.
