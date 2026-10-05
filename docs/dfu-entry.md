# DFU entry

`umshctl dfu [default|serial|uf2|ble] --yes` enters the connected radio's
bootloader. `umshctl manage <target> dfu [mode] --yes` addresses an
administrator-authorized node over the mesh. Both forms also work in the
interactive shell, which prompts when `--yes` is omitted. Firmware transfer
is a separate operation. iOS offers **Enter DFU Mode…** in device management
with a method picker and a destructive confirmation sheet.

## Protocol

[`CMD_DFU = 17`](protocol/src/ulcp-core.md#cmd-dfu) carries zero or one mode
byte: Default (0), Serial/USB-CDC (1), UF2 (2), or BLE (3). Omission means
Default. Defined but unsupported modes return `UNIMPLEMENTED`; undefined
values return `INVALID_ARGUMENT`, and extra payload returns `PARSE_ERROR`.
A direct TID-zero command records `INVALID_ARGUMENT` and cannot enter DFU.
Mesh administration uses the existing TID-zero/token response convention.
There is no capability property or protocol-version change. Clients treat
legacy `INVALID_COMMAND` as unsupported.

Success means the device has prepared to enter DFU after transmitting the
response. It does not mean an update was installed, or promise return to
UMSH. A timeout or disconnect before the response leaves entry unconfirmed.
The iOS companion connection disables automatic reconnection after confirmed
entry while keeping its saved identity and pairing. Remote entry keeps the
companion connected and ends management of the target.

## Platform contracts

The shipping board feature selects an internal profile in
`firmware/nrf52-tracker/src/dfu.rs`. These profiles target the documented
Adafruit-derived bootloaders, not arbitrary replacement bootloaders.
All select UF2 for Default, regardless of the command's transport. ESP32
and platforms without a hook return `UNIMPLEMENTED`.

Profile | Documented bootloader contract
--------|-------------------------------
T-Echo | Adafruit-derived build `1224915`, `nRF52840-TEcho-v1`; shared BSP entry markers
T1000-E | Seeed/Adafruit nRF52 DFU, [board notes](hardware/t1000e-hardware.md)
SenseCAP Solar | `0.9.2-OTAFIX2.2-BP1.3`, [board notes](hardware/sensecap-solar-node-p1-pro-hardware.md)
Wio Tracker L1 / L1 Pro | `0.9.2-dirty`, `TRACKER L1`, S140 7.3.0, [board notes](hardware/seeed-wio-tracker-l1-pro-hardware.md)
XIAO | `0.6.1`, `Seeed_XIAO_nRF52840_Sense`, [board notes](hardware/seeed-xiao-nrf52840-wio-sx1262-kit-hardware.md)

The shared nRF52840 BSP writes GPREGRET and resets: `0x57` for UF2 plus
CDC, `0x4E` for serial DFU, and `0xA8` for BLE with bootloader SoftDevice
initialization. The BLE method uses the reset path in
[Adafruit bootloader 0.6.1](https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/0.6.1/src/main.c),
not its `0xB1` warm jump. No bootloader changes or runtime identification
are included. Bootloader timeouts, USB power requirements, and watchdog
handling must be qualified on each installed bootloader.
The Wio's installed bootloader also exposes its UF2 volume for `0x4E`;
requesting the serial interface does not promise that other interfaces are
absent.

## Response completion

Fallible preparation resolves the mode and flushes replay counters before
emitting success. Persistent settings, identity, and bonds are not changed.
An expiring completion token belongs to the response; the runtime waits for
it before calling the final, infallible platform handoff.

- USB waits for the last HDLC packet's acknowledgment. The nRF driver loads
  the current packet after waiting for the previous packet, so a final empty
  transfer fences the response without changing its bytes.
- BLE tracks the final notification through controller ACL completion,
  including segmentation. Completion observed before disconnection remains
  valid; credits returned after disconnect do not authorize entry.
- Mesh returns the administrative reply to the responder before waiting,
  then follows its local transmission receipt without adding a wire ACK.
  Failure cancels queued sends and replaces retained success with failure.
  A retry uses the retained reply and cannot execute another transition.

Local completion waits expire after 10 seconds; mesh waits expire after
60 seconds. Failure or expiry leaves the application running. Stale tokens
and stale transport generations cannot authorize a new handoff.

## Hardware qualification

Build and software-test results do not qualify a bootloader interface.
Qualification must observe success before disconnection, identify the
requested interface, and recover the original device. Repeat BLE entry
over direct BLE and mesh administration. Include battery-only residency,
watchdog behavior, and preservation of saved identity/settings/bonds.

### Wio L1 Pro

The accessible Wio L1 Pro on 2026-10-04 reports `0.9.2-dirty`, build date
May 15 2025, `TRACKER L1`, S140 7.3.0. Default entry over USB returned
success and exposed the expected UF2 volume. Recovery through the normal
Make flash target preserved its device identity, name, saved radio
settings, and disabled GNSS setting. Explicit UF2 entry also passed:

```text
host→device Dfu tid=5 mode=Ok(Uf2)
device→host PropIs tid=5 PROP_LAST_STATUS = Status::OK
```

Serial entry also returned success and exposed the bootloader CDC port
(`/dev/cu.usbmodem101`) together with the UF2 volume. A single RESET
returned it to UMSH. BLE entry returned success before USB disappeared;
the Mac and the user's nRF Connect app observed the `AdaDFU` advertisement.
The Mac reported service `00001530-1212-EFDE-1523-785FEABCD123`.
The application USB port returned after recovery. The user reported that
the screen did not update after the first RESET despite a visible heartbeat
flash, and required a second RESET. The first reset's application/display
state was not captured. Subsequent reads confirmed the original identity
and saved settings.
The final application image was installed with `make flash-wio-tracker-l1`
and normal USB management was confirmed afterward. Firmware transfer via
the serial DFU interface was not exercised.

#### BLE application transfer

A command-line transfer used the Mac's built-in Bluetooth with
[`nrf_dfu_py`](https://github.com/recrof/nrf_dfu_py/tree/409e4b75d55c8d75859022217dfba0db33730f16)
and Bleak 3.0.2 in an isolated temporary environment. The test runner called
the library's update operation directly against the identified Wio
bootloader, since ULCP had already entered DFU. No Makefile target or
repository dependency was added.

The existing package target built an application-only ZIP with
`UMSH_FW_VERSION=ble-dfu-test-20261004`, `VERSION=ble-dfu-test-20261004`, and
the S140 7.3.0 requirement (`0x0123`). The application was 661,028 bytes,
SHA-256 `ca8a48a38679d50f057fc6327a9f3825973bf2a3992ce86713428957c2a4dafe`.
The transfer used 20-byte packets and a receipt notification every eight
packets. It completed in 308.8 seconds, including preparation, with success
responses for Start, Init, Receive, and Validate, followed by Activate and
Reset. No retries or receipt timeouts occurred.

The user observed UMSH boot automatically without pressing RESET. The DFU
advertisement disappeared, but the USB port did not return automatically;
unplugging and reconnecting USB did not restore it. One physical RESET
restored USB. Both the user's display and a subsequent ULCP read confirmed
`umsh/ble-dfu-test-20261004`, independently establishing that the BLE image
was installed. The device identity, name, saved radio settings, forwarding
policy, and disabled GNSS setting were preserved. BLE transfer and
automatic application boot passed; automatic USB recovery did not.
After verification, the normal version-labeled UMSH build was restored
through the existing UF2 Make target and its version and retained settings
were read back successfully.

Wio check | Result
----------|-------
Default over USB → UF2 + CDC | Verified
Explicit UF2 over USB → UF2 + CDC | Verified
Serial entry and recovery | Verified; CDC and UF2 both exposed
BLE entry | Verified; `AdaDFU` and Nordic DFU service observed
BLE recovery | UMSH USB restored; user needed a second RESET for the screen
BLE application transfer | Receipt, validation, installed version, and retained settings verified
Automatic boot after BLE update | UMSH boot observed; USB needed a physical RESET
Entry over direct BLE and mesh | Pending
Battery-only residency and watchdog | Pending

### XIAO nRF52840 + Wio-SX1262 kit

The attached `Gray Custom Solar Unit` on 2026-10-04 reported firmware
`umsh/fw-2026.10.01-5-gc1279cbe2`. A USB update through
`make flash-xiao-nrf52` installed `umsh/fw-2026.10.4-1-g09e856834-dirty`
and preserved its identity and saved repeater configuration. Its bootloader
reported `0.6.1`, build date November 12 2021,
`Seeed_XIAO_nRF52840_Sense`, and S140 7.3.0.

`CMD_DFU(BLE)` returned `STATUS_OK` before the `AdaDFU` advertisement
appeared. The same temporary Mac Bluetooth uploader transferred an
application-only ZIP from `make dfu-zip-xiao-nrf52`, with
`UMSH_FW_VERSION=ble-dfu-test-20261004-xiao` and the matching `VERSION`.
The application was 608,324 bytes, SHA-256
`64d22514b4674158f259a5fdf793a9a4be6c92f732e42c95101e5ef958c8ab01`.
Start, Init, Receive, and Validate all returned success. Activation followed
after 313.6 seconds, with no retries or receipt timeouts. The DFU
advertisement disappeared, but USB did not return automatically.
The user observed the normal heartbeat before pressing RESET. One physical
RESET restored USB, and ULCP reported `umsh/ble-dfu-test-20261004-xiao`.
The original identity, name, saved PHY settings, fixed mobility, forwarding
enablement, regions, and tags were preserved. BLE transfer and application
startup passed; automatic USB recovery did not, matching the Wio result.
After verification, the normal UMSH build was restored through
`make flash-xiao-nrf52`; its version, identity, and retained settings were
read back successfully.

### Remaining qualification

T-Echo, T1000-E, and SenseCAP Solar require accessible hardware for qualification.
Neither their successful builds nor the common GPREGRET contract establish
their BLE residency or recovery behavior.
Direct BLE and mesh command delivery, battery-only residency, and watchdog
behavior remain unqualified on the XIAO.
The iOS confirmation sheet's physical interaction and direct reconnection
suppression still need device testing; the software smoke checks exercise
the session response/disconnect paths.

## Software validation

Focused Rust tests cover mode parsing, direct/administrative TIDs,
preparation refusal, unchanged snapshots, completion ordering and expiry,
stale tokens, retained-reply invalidation, BLE segmentation/disconnection,
local mesh transmission receipts and CAD abandonment, and client parsing
and response handling. The iOS recovery smoke harness exercises confirmed
entry followed immediately by disconnect, retained ordinary connections,
unsupported firmware, and ambiguous failure messages.

Validation commands include:

```sh
cargo test -p umsh-ulcp --lib
cargo test -p umsh-ulcp-device -p umsh-mac -p umsh-node-mgmt -p umsh-mobile-core --lib dfu
cargo test -p umsh-ulcp-runtime --features device-node,ble-host --lib
cargo test -p umshctl --bin umshctl dfu
cargo test -p umsh --features tokio-support --test ulcp_full_protocol --test ulcp_over_mesh dfu
scripts/ios/build-mobile-core.sh
scripts/ios/verify-device-management.sh
scripts/ios/verify-radio-session-recovery.sh
make build-techo build-t1000e build-sensecap-solar build-wio-tracker-l1 build-xiao-nrf52
make build-heltec-v2 build-heltec-v3
make docs
cargo fmt --all --check
cargo +stable fmt --all --check --manifest-path firmware-esp32/Cargo.toml
git diff --check
```

The iOS app also builds with Xcode's generic iOS Simulator destination and
code signing disabled. Firmware builds use the Make targets so each
firmware's linker configuration is applied.
