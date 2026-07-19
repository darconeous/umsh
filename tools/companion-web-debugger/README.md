# UMSH companion web debugger

This directory contains the first working slice of the static companion-radio
debugger described in [`docs/companion-web-debugger-design.md`](../../docs/companion-web-debugger-design.md):

- `engine/` is a sans-IO Rust state machine used on the host and in WebAssembly.
- `www/protocol-session.js` is a DOM-free bridge between that engine and a byte link.
- `www/transports/` owns Web Serial and Web Bluetooth browser APIs.
- `www/` contains the debugger-specific presentation.

The separation is intentional: a future chat or management page can reuse the
engine, `ProtocolSession`, and transports without importing debugger UI policy.

The “Try simulated radio” link runs the production
`umsh-companion-ncp::Session` in WebAssembly with deterministic RAM-backed
storage and radio effects. It uses the same virtual HDLC link, host engine, and
trace path as a USB device, so it is useful for UI work and demonstrations
without hardware.

The primary interface is a capability-aware table of named properties. It
automatically fetches supported state after attach, updates rows for every
`PROP_IS`, renders protocol types and units, and provides typed editors for
ordinary writable settings. Settings with a finite set of supported values,
including LoRa bandwidth, spreading factor, and coding rate, use choices from
the shared property schema instead of debugger-specific UI logic. Arbitrary
hexadecimal property operations remain available in the collapsed advanced
section.

The common-command panel provides queue drain, save, restore, reset, and clear
operations. Capability-dependent commands are enabled only when the attached
radio advertises support, and commands that discard or erase state require
confirmation.

Battery-capable radios are sampled automatically after attach. Their decoded
voltage, level, and charge state appear in the top dashboard and in the Device
property group; the dashboard also provides an explicit refresh control.

`STR_PHY_RAW` receive events feed a bounded packet-capture model that is
independent of the debugger DOM. The capture UI can pause/resume, filter, and
inspect packets while retaining both raw bytes and decoded UMSH MAC details:
addresses, channel/counter, security and payload classification, frame layout,
options, RSSI/LQI/SNR, and buffered/acknowledged state. Captures export as
structured JSON or Wireshark-compatible PCAP using the same radio-layer
Ethernet/IPv4/UDP encapsulation as `umsh-capture`. In simulator mode, “Inject
simulator demo” enables the PHY and puts a production-built broadcast through
the real NCP receive path.

## Build and run

Install `wasm-pack` once, then from the workspace root run:

```sh
make web-debugger
python3 -m http.server --directory tools/companion-web-debugger/www 8000
```

Open `http://localhost:8000`. Hardware APIs require a secure context; browsers
treat `localhost` as secure. Chromium-family browsers are required for hardware
access. Android Chrome supports Web Bluetooth but not Web Serial.

Attaching is disruptive: enabling the Bluetooth notification or opening the
serial session detaches any current companion host. The debugger performs only
the non-destructive `attach_existing` reads and never resets radio state.

## Tests

The engine is ordinary host-testable Rust:

```sh
cargo test -p umsh-companion-web-engine
```

The generated `www/pkg/` output is ignored. Run `make web-debugger` again after
changing the engine. The static shell has no npm dependencies or build step.

The DOM-free capture model has Node tests:

```sh
node --test tools/companion-web-debugger/www/packet-capture.test.mjs
```

The simulator is enabled by the engine crate's default `sim-ncp` feature. Build
with `--no-default-features` when embedding only the smaller host engine in a
different application.
