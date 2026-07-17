# Companion Radio Web Debugger — Design

Status: proposed (2026-07-16). Companion documents:
[companion-ble-plan.md](companion-ble-plan.md) (implementation
history), the protocol chapters
[companion-radio-minimal](protocol/src/companion-radio-minimal.md),
[companion-radio-full](protocol/src/companion-radio-full.md), and
[companion-radio-ble](protocol/src/companion-radio-ble.md).

## Motivation

Every CRP debugging aid we have today requires a Rust toolchain and a
terminal: `umsh-capture`, `umsh-companionctl`, the validation phases.
That is fine for us and useless for anyone else — a tester with a
T-1000E and a laptop cannot look at what their radio is doing without
building the workspace. A static web page that connects over Web
Bluetooth or Web Serial turns "install a toolchain" into "click a
link", works on a Chromebook or an Android phone, and doubles as a
living demonstration of the protocol: the same page can run a
simulated NCP entirely in the browser, because the real session engine
is `no_std` Rust and compiles to WebAssembly.

The tool is a **protocol debugger**, not a chat client and not a
replacement for `umsh-companionctl`: its job is to make frames,
properties, and NCP state visible and pokeable.

## Goals

* Connect to a real NCP over **Web Bluetooth** (Companion Link
  Service) or **Web Serial** (HDLC-Lite over USB-CDC), from a static
  page with no server component.
* Show a **live, decoded frame trace** in both directions, with raw
  hex on demand and export for offline analysis.
* Provide an **attach dashboard** (protocol/NCP versions, boot status,
  capabilities, MTU) and a **property inspector** — get/set/insert/
  remove any property by name or number, with unsolicited updates
  surfaced as they arrive.
* Decode what the protocol carries: buffered RX metadata (RSSI, SNR,
  flags), UMSH MAC packet headers in queued frames, filter tables,
  digest lists.
* Run the **same protocol code** the firmware and native tools run.
  No JavaScript reimplementation of frame parsing, HDLC, or SAR —
  those compile to wasm from the existing crates, so the debugger can
  never drift from the spec independently of the implementation.
* Work with **zero hardware** via a browser-resident simulated NCP
  (the real `umsh-companion-ncp` `Session` behind a virtual link),
  for demos, UI development, and CI.

## Non-goals

* Not a management workflow. Provisioning real operator keys, identity
  ceremonies, and fleet operations stay in `umsh-companionctl`; the
  debugger's mutations are raw property operations aimed at protocol
  work. (A later phase may add guarded convenience buttons for
  save/restore/clear/reset.)
* Not a chat or messaging client. No MAC-layer host, no identity, no
  text protocols.
* No support target beyond Chromium-family browsers (see platform
  constraints); we detect and explain, we do not polyfill.
* No server, no accounts, no telemetry. The page is static files.

## Platform constraints (and what they force)

**Browser support.** Web Bluetooth and Web Serial ship in
Chromium-family browsers (Chrome, Edge, Opera) on desktop; Android
Chrome has Web Bluetooth but not Web Serial; Firefox and Safari have
neither. The page must feature-detect both APIs independently and
degrade to an explanation plus the simulated-NCP mode, which runs
anywhere wasm does.

**Secure context.** Both APIs require HTTPS or `localhost`, and both
require a user gesture to open the device chooser. This fits static
hosting on the existing docs site (`darconeous.github.io/umsh/…`) and
`cargo`/`python -m http.server` style local development.

**BLE security is OS-mediated.** The spec requires LESC bonding and
encrypted characteristic access ((#ble-security) in the BLE chapter).
A browser cannot and should not implement any of that: Chromium
triggers the platform pairing ceremony when a GATT operation fails
with insufficient authentication, the OS renders the passkey dialog
when the NCP requests Passkey Entry, and the bond is stored by the OS.
The debugger therefore contains **no pairing code** — only UX: surface
"pairing required" states clearly, explain pairing mode and the
passkey-lockout behavior, and never treat a security error as a
protocol error.

**ATT_MTU is opaque to Web Bluetooth.** The SAR transport is correct
at any MTU, but the page cannot query the negotiated value, and a
write larger than MTU−3 either fails or degrades into a GATT long
write the NCP does not support. The debugger defaults to conservative
20-octet segment payloads (correct at the 23-octet floor) with an
advanced setting, and may probe upward by attempting a larger
`writeValueWithoutResponse` and catching the failure. Host→NCP
throughput is irrelevant for a debugger; NCP→host notifications are
segmented by the NCP against the real negotiated MTU and reassemble
correctly regardless.

**Attaching displaces the attached host.** Per the BLE chapter's
attach semantics, enabling Frame Out notifications silently resets the
NCP's protocol session and detaches any other host, USB included; the
serial transports behave equivalently on open. The debugger must say
so before connecting — it is a debugging tool pointed at radios that
may be autonomously serving another host. After attach it follows the
full-protocol discipline: fetch, never assume, never reset
(`attach_existing` semantics, not the minimal-protocol resetting
attach).

## Architecture

Two layers with a hard boundary:

```
┌────────────────────────────────────────────────┐
│ JS shell (vanilla, no framework, no npm deps)  │
│  • Web Bluetooth / Web Serial ownership        │
│  • DOM: dashboard, trace, property inspector   │
│  • bytes in ↔ bytes out, events ↔ commands     │
└──────────────────┬─────────────────────────────┘
                   │ wasm-bindgen
┌──────────────────┴─────────────────────────────┐
│ DebuggerEngine (Rust → wasm, sans-IO)          │
│  • HDLC encode/decode      (umsh-companion)    │
│  • SAR segment/reassemble  (umsh-companion)    │
│  • frame parse + describe  (umsh-companion)    │
│  • TID allocation, transaction correlation,    │
│    attach handshake, sync procedure            │
│  • MAC header / meta decode (umsh-core, meta)  │
│  • optional: simulated NCP (umsh-companion-ncp)│
└────────────────────────────────────────────────┘
```

**The JS shell owns the browser APIs and the DOM, and nothing else.**
Web Bluetooth and Web Serial are promise/stream APIs that are natural
in JS and unstable-flagged in `web-sys`; keeping them in hand-written
JS avoids the `--cfg web_sys_unstable_apis` toolchain wart and keeps
the wasm crate buildable and testable on the host. The shell moves
opaque byte arrays and structured events; it never inspects a frame.

**The Rust core is sans-IO,** in the style of the NCP-side `Session`:
feed it bytes/frames, ask it for bytes/frames to send, and it returns
typed events. It has no async runtime, no timers of its own (the shell
supplies "now" and schedules timeouts), and therefore runs identically
under `cargo test` on the host and under wasm in the page. This is
deliberately **not** a port of the tokio `CompanionRadio` driver: that
driver's value is its async transaction plumbing, which is exactly the
part that doesn't translate. What must be shared is the byte-level
grammar and the state-machine rules, and those already live in
`no_std` crates.

Interface sketch (wasm-bindgen surface, JSON-serializable events):

```
engine.set_transport(SerialHdlc | BleSar)
engine.ingest(bytes)            -> [Event]     // from the wire
engine.take_outbound()          -> [bytes]     // to the wire
engine.attach()                                // queues the handshake
engine.prop_get(key) / prop_set(key, bytes) / insert / remove
engine.command(reset | save | restore | clear | noop)
engine.tick(now_ms)             -> [Event]     // timeouts

Event = Attached{versions, mtu, boot_status}
      | Trace{dir, summary, raw}
      | PropIs{key, name, value, unsolicited}
      | Inserted{..} | Removed{..} | Status{..}
      | StreamRx{stream, data, meta}           // decoded meta attached
      | ProtocolError{..} | NeedsPairing | Detached{reason}
```

### Crate and directory layout

```
tools/companion-web-debugger/
  engine/          # Rust: cdylib+rlib, workspace member
  www/             # index.html, style.css, shell.js, transports/*.js
  README.md        # build + serve instructions
```

The engine crate depends on `umsh-companion` (frame, hdlc, gatt, ids,
meta, items), `umsh-core` (PacketHeader, PublicKey base58 display),
and optionally `umsh-companion-ncp` + `umsh-crypto/software-crypto`
behind a `sim-ncp` feature. All logic is target-independent; only the
thin `#[wasm_bindgen]` export layer is `cfg(target_arch = "wasm32")`.
Host-side unit and integration tests exercise the same engine the
browser runs.

### Prep refactor: graduate the frame describer

`describe_frame()` and the property-name table live in the tokio-gated
`umsh::companion_radio` today. They are pure functions of frame bytes
and belong in `umsh-companion` (behind an `alloc` feature or recast to
`fmt::Display` writers), where the native driver, `umsh-companionctl`,
and the web engine all share one decoder. This is a small,
independently landable change and the only prerequisite touching
existing code.

## Transports

**Web Serial.** `navigator.serial.requestPort()` → open 115 200 8N1 →
pump `ReadableStream` chunks into `engine.ingest()`, write
`engine.take_outbound()` frames HDLC-encoded by the engine. The
serial path is byte-oriented; cancellation/backpressure are handled by
the streams API. This transport also covers the RAK4631-style targets
later without page changes.

**Web Bluetooth.** `requestDevice({filters: [{services:
[COMPANION_LINK_SERVICE]}]})` — discovery by service UUID per the
advertising section, with the device-name string as the human label.
Connect → get Frame In (write) and Frame Out (notify) characteristics
→ `startNotifications()` (this is the attach). Notifications feed the
engine's SAR reassembler; outbound frames leave as SAR segments via
write-with-response for the spec's flow-control pacing (the advanced
setting may switch to write-without-response). Disconnection surfaces
as `Detached`; reconnect is a fresh attach with full re-sync, matching
the spec's "attach implies no known state".

**Simulated NCP.** A third "transport" that instantiates the real
`Session<SoftwareAes, SoftwareSha256>` with RAM-backed journals inside
the wasm module and loops frames back through the same engine paths,
with a fake radio that can inject canned UMSH packets. This is the
demo mode, the UI-development mode, and the browser-independent test
harness — the same trick as `umsh/tests/companion_full_protocol.rs`,
compiled for the page.

## Feature phases

**Phase 1 — connect and see.** Transport picker with feature
detection and the displacement warning; attach handshake; dashboard
(versions, boot status, capability names, MTU); live trace with
direction, timestamp, `describe_frame` summary, expandable raw hex;
trace filter and clear; JSON export of the trace. Simulated NCP behind
the same picker. This alone replaces "flash a debug build and read
RTT" for protocol-level questions.

**Phase 2 — inspect and poke.** Property inspector: the full known-ID
table (names from `ids`), typed rendering for the properties the sync
procedure knows (enables, frequencies, tables, digests), raw hex
get/set for everything, insert/remove for multi-value properties,
unsolicited updates highlighted in place. RX-queue panel: drain,
decoded `BufferedRxMeta` (RSSI/SNR/flags, ACKED badge), MAC header
summary per frame (type, hints, counter) via `umsh-core`. Raw TX
(`STR_SEND` hex entry) for prodding a peer under test.

**Phase 3 — state operations and capture parity.** Guarded buttons
for save/restore/clear/reset with the same confirmation posture as
`umsh-companionctl` (`factory-reset`-grade actions spell out what they
erase); pairing-PIN set/clear (masked entry, never logged); pcapng
export of the trace in the same companion-layer encapsulation
`umsh-capture` writes, so a browser session and a native capture open
in Wireshark identically.

Deliberately unphased: anything requiring the operator's real secrets
(host provisioning with production channel/peer keys). The protocol's
write-only-with-digest design means the debugger can *display* any
NCP's state without being able to leak key material, and that property
is worth preserving by simply not building secret entry into a web
page until there is a concrete need.

## Security and privacy posture

* **The protocol already protects secrets on the wire we expose.**
  Key-bearing properties are write-only; reads return digest forms.
  The trace can therefore show full raw frames by default, with one
  exception: host→NCP writes of key-bearing property IDs render
  value-length-only summaries (the `describe_frame` convention) even
  in raw view, so a screen-shared debugging session cannot leak a key
  someone typed.
* An attached debugger is a **privileged radio controller**
  (transmission under the operator's regulatory responsibility, RX
  metadata visibility, denial of service to the real host). The
  BLE bond/OS pairing ceremony is the entire authentication boundary,
  exactly as for any other host; the page adds no attack surface
  beyond what a bonded host already has, but the README and UI should
  say plainly that connecting a browser *is* attaching a host.
* Static files, no network egress: CSP `default-src 'self'` with no
  connect-src, so the page provably talks only to the chosen device.
  No storage of anything device-derived beyond an optional
  session-trace download the user explicitly saves.

## Build, hosting, and testing

* **Build:** `wasm-pack build --target web` (or plain
  `cargo build --target wasm32-unknown-unknown` + `wasm-bindgen`),
  output copied next to `www/`. No npm, no bundler; the shell is
  hand-written ES modules. A `Makefile` target (`make web-debugger`)
  matching the existing build conventions.
* **Hosting:** the docs site is already published HTTPS static
  hosting; the debugger publishes as `…/umsh/debugger/`. Local dev is
  any static server on `localhost`.
* **Testing:** engine unit tests on the host (transaction
  correlation, SAR/HDLC round-trips through the same entry points the
  shell uses); integration tests driving the engine against the real
  `Session` in-process, mirroring `companion_full_protocol.rs`;
  hardware smoke = phase-1 dashboard + trace against the T-1000E and
  T-Echo over both transports. Browser-automation E2E (Chromium's
  fake-Bluetooth WebDriver surface) is possible but not load-bearing
  given the sim-NCP path exercises everything above the transport.

## Open questions

1. **MTU probing** — is adaptive segment sizing worth it, or should
   the NCP advertise a preferred segment payload (a future property,
   spec change) so hosts stop guessing? Conservative-fixed is correct
   meanwhile.
2. **pcapng encapsulation** — settle the exact companion-layer link
   type with `umsh-capture` before phase 3 so the two tools never
   diverge (capture currently writes an Ethernet/IPv4/UDP wrapping or
   raw-LoRa with an explicit linktype).
3. **Where the simulated NCP's radio ends** — canned packet injection
   is cheap; simulating a second peer (for ack-delegation demos) drags
   in MAC-layer construction. Probably worth it later as a spec
   demonstration, not for phase 1.
4. **Publication timing** — the page is also an implicit protocol
   disclosure; publish alongside the spec chapters or keep it in-repo
   until the spec is public-ready.
