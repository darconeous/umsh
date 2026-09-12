# firmware-esp32—Espressif (Xtensa) sibling workspace

Firmware and BSPs for Espressif targets: the
[Heltec WiFi LoRa 32 V3](../docs/hardware/heltec-lora32-v3-hardware.md) and the
[LILYGO T-Beam Supreme](../docs/hardware/lilygo-t-beam-supreme-hardware.md)
(both ESP32-S3), and the
[Heltec WiFi LoRa 32 V2](../docs/hardware/heltec-lora32-v2-hardware.md)
(classic ESP32). This is a separate cargo workspace because the
Xtensa chips need the Xtensa Rust fork (`rust-toolchain.toml` here pins
`channel = "esp"`), which cannot coexist with the root workspace's toolchain
file—see the decision table in
[firmware-architecture.md](../docs/firmware-architecture.md).

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
make build-heltec-v3
make flash-heltec-v3             # espflash over the CP2102, then monitor
make flash-heltec-v3-console ESPFLASH_PORT=/dev/cu.usbserial-0001
make build-heltec-v2
make flash-heltec-v2
make build-tbeam-supreme
make flash-tbeam-supreme     # espflash over native USB, then monitor
```

The workspace `.cargo/config.toml` carries only chip-agnostic settings
(espflash runner, linker flags, build-std); each firmware selects its
own target triple—plus any chip-quirk env overrides, like the Heltec
V2's ancient-silicon `ESP_HAL_CONFIG_MIN_CHIP_REVISION` floor—in a
per-firmware `.cargo/config.toml`. Per-directory configs only apply when
cargo runs from inside the directory, so build each firmware **from
inside its own directory** (`cargo build --release` there, or `cargo run
--release` to flash+monitor)—the Makefile targets do exactly that.
Flashing uses the mask-ROM serial bootloader with DTR/RTS auto-entry—
there is no bootloader to brick and no DFU/UF2 machinery.

### WiFi on ESP32-S3

The normal T-Beam Supreme build includes WiFi and PSRAM. WiFi remains opt-in
on Heltec V3. From the repo root:

```sh
make flash-heltec-v3 ESP32_CARGO_FLAGS=--features=wifi ESPFLASH_PORT=/dev/cu.usbserial-0001
make flash-tbeam-supreme
```

Add `ble-debug` (`--features=wifi,ble-debug`) for serial connection diagnostics,
sampled heap minima, largest free allocation, and a main-stack watermark.
These measurements do not replace sustained load and radio-task stack testing.
The build targets reject individual Xtensa frames that exceed the available
main stack minus an 8 KiB reserve; nested calls still require measurement.

The Heltec V3 uses internal session storage and a 112 KiB internal heap. The
T-Beam uses a 128 KiB internal heap and, with its default `psram` feature,
explicit PSRAM storage for the protocol session and snapshot buffer. WiFi
does not require PSRAM as a feature dependency. Neither WiFi nor PSRAM is
enabled in the default Heltec build; WiFi is unsupported on the Heltec V2.

#### Upstream dependency support and remaining work

WiFi uses the unmodified `esp-radio` source at the workspace's existing
esp-hal revision and crates.io `embassy-net 0.8.0`, fetched by Cargo. There
are no local WiFi dependency copies or custom dependency APIs.

The station supports Open and WPA/WPA2/WPA3 Personal passwords, four saved
networks, reconnect backoff from 1 to 60 seconds, scans, DHCPv4, and static
IPv4. Connection attempts use the driver's authentication threshold without
an application prescan; the negotiated authentication is checked before
publishing the link as up. The driver chooses APs by signal strength, so
preference for the strongest security across separate BSSIDs is not guaranteed.
WPA3-only upgrades and refusal of weaker modes still need hardware qualification.

The following limitations apply to both ESP32-S3 boards:

- Raw PMKs, non-UTF-8 SSIDs, SSIDs containing NUL, OWE, and WPA3 passwords
  over 63 UTF-8 octets return `STATUS_UNIMPLEMENTED`. Unicode SSIDs remain
  supported. Scan records with a truncated UTF-8 prefix are omitted rather
  than published with that prefix as a different name. Embedded-NUL scan
  names cannot be faithfully represented by the upstream driver.
- Cancellation finishes the current channel scan, discards subsequent
  results, and preserves previously published results. Both general and
  hidden-network scans visit channels 1–11. The driver's own association
  scan still uses its upstream channels 1–13 range; selecting `US` does
  not override that hardcoded range. The plan's strict station-wide 1–11
  restriction remains unmet.
- Address readiness follows upstream configuration state. Static address
  conflict detection and DHCP DECLINE/recovery are not implemented.
- DHCP-learned resolvers (up to three) are published. Nonempty manual DNS
  writes return `STATUS_UNIMPLEMENTED`; clearing the list succeeds. There
  is no DNS query client or DNS socket allocated in this firmware.
- When restoring snapshots created with broader driver support, unsupported
  WiFi profiles and manual resolvers remain saved and readable, but are
  inactive. Other settings still restore. A selected unsupported profile
  reports a rejected connection; another network is never selected implicitly.
  Effective resolver publications contain only the DHCP-learned addresses,
  even if the saved configuration contains an inactive manual override.

These limitations leave parts of the WiFi implementation plan incomplete.

Upstream-only validation on 2026-09-12 passed the normal T-Beam build,
Heltec V3 builds with and without WiFi, and the nRF T-Echo build. The shared
device and WiFi runtime suites passed 246 and 29 tests respectively.
T-Beam USB tests preserved the identity and saved configuration across the
update, acquired DHCP on the saved network, completed and canceled scans,
refused unsupported settings atomically, and preserved the identity and
lease through four BLE off/on cycles. Two WiFi disable/re-enable cycles
recovered, but DHCP readiness took about 21 and 55 seconds. That delay
remains unresolved. These checks used a diagnostic build. The final normal
build was also flashed and preserved the identity and saved settings; it
rejoined the saved network and obtained IPv4, with a further DHCP wait of
about 64 seconds after the USB check began. Local mesh pings with a full
source identity returned 2/2 replies; initial compact-source pings timed
out. Security-mode qualification, AP-outage tests, iOS retesting, and
endurance remain pending.

## Version pins

The whole esp-hal family (esp-hal, esp-rtos, esp-radio, esp-alloc,
esp-println, esp-bootloader-esp-idf) is pinned to a single git rev of
esp-rs/esp-hal in this workspace's `[patch.crates-io]`—the published
esp-radio 1.0.0-beta.0 speaks bt-hci 0.8 while our audited trouble-host
fork requires bt-hci 0.9; main carries the 0.9 bump. All family members
must move together (they share in-repo path dependencies). Drop the block
when esp-radio > beta.0 ships. `lora-phy`/`lora-modulation`/`trouble-host`
patches mirror the root workspace and must stay in lockstep with it.
