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
make flash-heltec-v3-bridge      # the same board as an internet bridge
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

### Images and features

The device images are thin manifests over one set of sources in
`firmware/esp32-tracker/`. Each manifest carries the same `[features]` table
and differs in `default`; `scripts/check_esp32_manifests.py` (run in CI) fails
when a copy drifts.

| Image | Board | Default radios |
|---|---|---|
| `heltec-v3` | Heltec V3 | BLE |
| `heltec-v3-bridge` | Heltec V3 | Wi-Fi, bridge client |
| `heltec-v2` | Heltec V2 | BLE |
| `tbeam-supreme` | T-Beam Supreme | BLE, Wi-Fi, bridge client |
| `tlora-pager` | T-LoRa Pager | BLE, Wi-Fi, bridge client |

The radio features:

- `ble`—the BLE transport, its GATT host, and its bond journal. An image
  without it advertises no Bluetooth capability and shows no Bluetooth menu.
- `wifi`—the Wi-Fi station and IPv4.
- `coex`—Wi-Fi and BLE in one image. Required whenever both are on.
- `bridge-client`—the [internet bridge](../docs/protocol/src/internet-bridging.md)
  client. Its buffers live in PSRAM with `psram`, and in internal RAM, trimmed,
  without.
- `debug-log`—diagnostic lines on the wired port. `ble-debug` adds the BLE
  security trace and keeps advertising open.

At least one of `ble` and `wifi` is required: the TRNG needs a live radio.

The Heltec V3 has no PSRAM, and the BLE host and the bridge client do not fit
in its internal RAM together. `heltec-v3-bridge` is the same board built with
Wi-Fi and the bridge client and without BLE. It is set up over USB with
`umshctl`, or over the mesh from another radio. Both images keep the device
identity, frame counters, entropy seed, and BLE bonds in the same journals, so
either can be flashed over the other and the board stays the same node; the
bridge image leaves the bonds alone. Saved settings carry over from the
standard image to the bridge image. In the other direction they do not: an
image without Wi-Fi does not read the full-page snapshot records an image
with Wi-Fi writes, and starts from defaults.

### Entropy

The chip's TRNG is true-random only while RF is live, so nothing draws from it
directly. A pool seeded from flash (`umsh_crypto::pool`) makes every boot
cryptographically strong without a radio, and `entropy.rs` keeps that pool fed:

- **Boot.** The stored seed and per-boot salt give the pool its key, the next
  boot's seed is committed, and only then is anything drawn. With no stored
  seed—a first boot or a factory reset—the pool starts from a TRNG read
  through a radio brought up for the purpose (BLE where present, otherwise
  Wi-Fi), and the boot stops if that fails.
- **Harvest.** Each radio driver reads 32 octets from the TRNG when it can
  prove RF is on: the BLE supervisor between stacks, through a controller
  with modem sleep off, and the Wi-Fi task with its controller up and the PHY
  held on. A driver harvests when one is cheap and the last is an hour old.
  After six hours without one, an idle BLE advertiser restarts its stack for
  it, and an image without BLE brings Wi-Fi up briefly. A connected host is
  never interrupted. Harvests continue while a radio is switched off.
- **Reseed.** Every harvest rekeys the running generators: the device node's
  (ephemeral keys), the session's, the BLE privacy generator, and the bridge's
  TLS generator.
- **Persist.** The first harvest of a boot is written to the seed journal at
  once. Later ones go out with another journal write once the last seed write
  is an hour old, and by themselves at six hours.

Timing of LoRa interrupts and button presses is mixed in alongside, and
`entropy-sar-adc` adds a read of the SAR ADC noise source at boot on images
whose ADC1 is free then. Neither is trusted alone.

### Bluetooth power management

The Heltec V3, T-Beam Supreme, and T-LoRa Pager enable BLE modem sleep.
The controller turns the PHY off between events and coordinates automatic MCU
light sleep through its wake source, sleep veto, and next-event deadline. The
CPU runs at 80 MHz while awake. BLE timing uses the main crystal, which remains
powered through sleep; no external 32 kHz crystal is required. The esp-hal
driver fork below fixes controller initialization and teardown sleep boundaries.
The original ESP32/Heltec V2 and the bring-up console keep modem sleep disabled.

`EspCryptoRng` owns a BLE controller with modem sleep disabled and holds the
Bluetooth peripheral exclusively for its lifetime. The tracker uses it only
for short entropy harvests, dropping it before the operational BLE controller
starts. The persisted entropy pool seeds software CSPRNGs, so normal
randomness generation does not keep RF awake. A failed harvest or seed write
leaves the committed pool usable and is retried; see [Entropy](#entropy).

USB and GNSS/UART wake locks still prevent MCU light sleep when those peripherals
are active. In particular, Heltec V3 retains its UART0 serial receiver for the
whole boot, including on battery: it can use BLE modem sleep, but this existing
wake lock still blocks MCU light sleep. T-Beam and Pager release their native
USB transport on battery and can light-sleep with GNSS and WiFi disabled.
WiFi remains in `PowerSaveMode::None`; WiFi light-sleep policy and
CPU/cache-retention optimizations are separate work.

For a battery comparison, disconnect USB, disable GNSS and WiFi, put the display
in its normal idle state, close the pairing window, and wait at least 30 seconds
after boot for fast advertising to finish. Compare Bluetooth disabled, ordinary
advertising, an idle bonded connection, and active traffic with the same LoRa
configuration. Build and stack checks establish software compatibility, not
current consumption or battery life.

Hardware qualification should cover:

- Bonded reconnect, pairing/PIN, privacy-address rotation, and Bluetooth toggles.
- LoRa traffic and GPIO wake while advertising and while connected.
- Elapsed-time accuracy across idle periods, and USB/GNSS off/on transitions.
- WiFi scans, reconnects, and traffic alongside BLE with WiFi power saving off.
- First boot, normal stored-seed boot, and restart after a failed seed write.
- An hourly harvest on reconnect, the six-hour forced harvest while idle and
  while Bluetooth is disabled, and a session established after a reseed.
- Combined BLE/WiFi traffic (plus bridge traffic where supported), recording
  heap minima and stack watermarks against the required stack reserves.

#### Controller lifecycle fork

The [driver fork](https://github.com/darconeous/esp-hal/tree/codex/ble-awake-teardown)
adds two lifecycle protections to the upstream sleep support:

- Hold a temporary MCU wake lock during controller initialization, until the
  BLE sleep veto is registered.
- Prevent new modem sleep, wake the BTDM controller with its sleep callbacks
  still active, and wait for its active state before teardown. A temporary
  MCU wake lock protects teardown after the BLE wake source is released.

Resetting a sleeping S3 baseband can hang in `r_rwble_hw_disable`.
The fork follows Espressif's
[reference wake-before-shutdown sequence](https://github.com/espressif/esp-idf/blob/v5.5.1/components/bt/controller/esp32c3/bt.c#L2060-L2070)
and includes a regression test for asleep teardown followed by awake-controller
reinitialization. Keep the fork delta limited to these lifecycle protections
and their tests; return the dependency family to upstream when it includes
equivalent fixes.

### WiFi on ESP32-S3

The normal T-Beam Supreme build includes WiFi and PSRAM. On the Heltec V3,
WiFi is in the bridge image, and opt-in alongside BLE in the standard one.
From the repo root:

```sh
make flash-heltec-v3-bridge ESPFLASH_PORT=/dev/cu.usbserial-0001
make flash-heltec-v3 ESP32_CARGO_FLAGS=--features=wifi,coex ESPFLASH_PORT=/dev/cu.usbserial-0001
make flash-tbeam-supreme
```

Add `debug-log` (`--features=debug-log`) for serial connection diagnostics,
sampled heap minima, largest free allocation, and a main-stack watermark.
These measurements do not replace sustained load and radio-task stack testing.
The build targets reject individual Xtensa frames that exceed the available
main stack minus a nested-call reserve: 20 KiB on T-Beam and the Heltec V3
bridge image, 32 KiB on Pager, and 8 KiB on the standard Heltec image. These
checks do not replace stack measurements under load.

The Heltec V3 uses internal session storage and a 104 KiB internal heap. The
T-Beam uses a 108 KiB internal heap and, with its default `psram` feature,
explicit PSRAM storage for the protocol session and snapshot buffer. WiFi
does not require PSRAM as a feature dependency. Neither WiFi nor PSRAM is
enabled in the standard Heltec build; WiFi is unsupported on the Heltec V2.

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
The pinned high-level authentication enum omits WPA3. An application-side
adapter uses the same upstream `esp-wifi-sys-esp32s3` bindings to raise only the
station's authentication threshold to WPA3 before connecting. Failed reads or
writes prevent the connection attempt; credentials are never tried with a
weaker threshold. Remove this adapter once the high-level API exposes WPA3.
WPA3-only upgrades and refusal of weaker modes still need hardware qualification.

The following limitations apply to the ESP32-S3 boards:

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

The whole esp-hal family (including esp-storage) is pinned to the
`darconeous/esp-hal` fork at `5a55bb86021934c83be40d25b45a26922898ad91` in this
workspace's `[patch.crates-io]`. Its upstream base, `76a0e71d5ea8`, includes BLE
modem sleep (#6376), BLE-aware light sleep (#6378), and the bt-hci 0.9 transport
required by our audited trouble-host fork. The only fork changes are the BLE
lifecycle wake boundaries and regression test described above, and an esp-rtos
fix that disarms the scheduler's standing wake deadline before deep sleep.
All family members must move together because they share in-repository path
dependencies. Return to upstream and then released crates when they contain
these capabilities and lifecycle fixes.
`lora-phy`/`lora-modulation`/`trouble-host` patches mirror the root workspace
and must stay in lockstep with it.
