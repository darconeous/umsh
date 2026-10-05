# Embedded bridge client validation

Implementation and qualification checkpoint: September 12, 2026.

## Implemented

- Cargo-managed `embedded-tls` 0.19 with a device-seed Ed25519 signer,
  an in-memory certificate, and pinned server handshake verification.
- ULCP capability 58, properties 4928–4932, device snapshot persistence,
  asynchronous status, and independent host attachment lifetime.
- A dedicated node-only multiplexer port, bounded drop-oldest queues, frame
  expiration, HDLC-Lite framing, IPv4 DNS/TCP, timeouts, keepalives, cancellation,
  and jittered reconnects. Large byte buffers and queues use PSRAM where the
  board has it.
- A no-PSRAM configuration: frames are stored at the size a LoRa frame can
  reach rather than the tunnel's decode limit, TLS records are limited to 4096
  octets of plaintext by the bridge specification, and the client's buffers
  (about 10 KiB) sit in internal RAM. The `heltec-v3-bridge` image is the
  Heltec V3 built this way, with Wi-Fi and without BLE.
- `umshctl bridge` and the capability-gated iOS Bridge screen, including
  generated bindings, device identity display, and fake-device data.

The CLI uses `--server-port` for bridge TCP configuration because the existing
global `--port` selects the serial device. Both remain usable in one command.

## Passed checks

| Area | Evidence |
|------|----------|
| Authentication | The firmware provider authenticates as its device key against the production bridge server verifier; wrong pins, unauthorized clients, and incompatible ALPN offers are rejected. |
| TLS records | Fragmented duplex I/O with a 97-byte transport buffer; a 16 KiB server write arriving intact as 4096-octet records through the smallest receive buffer a client may use (4352 bytes). |
| Tunnel | Little-endian packet length, escaped/coalesced HDLC frames, bare flags, decoder reset, PHY bounds, queue overflow, expiration, and clearing. |
| ULCP device | 248 device tests with bridge and Wi-Fi features; defaults, capability prerequisites, invalid writes, read-only status, detach independence, reset/restore, and maximum snapshot capacity. Session memory-budget check passes. |
| Multiplexer | 13 focused mux tests, including node-only bridge ingress during physical TX, full node queues, independent host backhaul, and unchanged radio accounting. |
| MobileCore and CLI | 233 MobileCore tests and 144 CLI tests; bridge codecs, write ordering, port collision prevention, and save flag parsing. |
| Swift | Generated device/simulator libraries, iOS simulator app build, and Swift binding smoke checks including bridge writes. |
| iOS interaction | Simulator companion fixture: endpoint/pin/enable Apply and authoritative readback, Connected status after refresh, unsaved host preserved during refresh, invalid port refused, and canonical device identity with a copy action. |
| Boards | Normal T-Beam Supreme release build and Xtensa stack check; non-bridge Heltec V3 release/stack check; `heltec-v3-bridge` release build and stack check with a 20 KiB reserve; XIAO nRF52840 firmware check. |
| Hardware management | T-Beam flashed and queried; its identity and saved configuration survived. Live bridge settings survived USB detach and reported Waiting for network while the node remained a leaf. Disable/re-enable reconnected; final readback was Connected with the current snapshot saved. |
| Live authentication | Once the configured hotspot became available, the T-Beam obtained IPv4 and connected to the supplied bridge server using its configured identity pin. The device identity was unchanged. |
| Live forwarding | The user successfully pinged a node from their phone through the bridge. Repeater and PHY were enabled at final readback. This is user-reported end-to-end hardware validation. |
| Documentation | Protocol mdBook builds. |

The successful live ping establishes a working forwarding path. It does not
replace sustained concurrency, pressure, and failure testing on the ESP32.

## Dependency decision

Keep unmodified, Cargo-managed `embedded-tls` 0.19. The client offers the ALPN
identifier recommended by the bridge specification. Checking the server's ALPN
selection is additional hardening, not a requirement of the current specification.
Some authentication refusals lose their specific reason but still terminate the
connection. An upstream panic branch for unexpected application-phase handshake
messages merits a targeted robustness investigation; normal bridge operation has
not reproduced it. These findings do not establish a need for a dependency fork.
See [upstream TLS behavior](../crates/umsh-bridge-client/README.md).

## Remaining qualification

1. **Memory instrumentation.** A diagnostic image with `ble-debug` and allocator
   statistics stopped answering ULCP. The normal image was restored and answers
   again. Peak internal RAM, PSRAM, and runtime stack measurements under TLS
   load remain unmeasured. The diagnostic feature experiment was removed.
2. **Hardware traffic.** Beyond the successful phone ping and disable/re-enable
   cycle, explicit two-hop crossings, duplicate echoes, leaf traffic, sustained
   concurrent Wi-Fi/BLE/LoRa, stalled writes, and repeated reconnects still require
   live qualification. Host mux tests cover routing boundaries but do not replace
   these hardware checks.
3. **iOS transports.** Basic editing and readback passed with the simulator's
   companion fixture. Partial device refusals and unsolicited status pushes
   across companion, administrative BLE, and mesh-management transports still
   need interactive qualification.
4. **Heltec V3 bridge image.** The bridge is user-reported working on a
   Heltec V3. Open: first boot from an erased `umsh` partition (the entropy
   bootstrap goes through Wi-Fi and the SAR ADC source instead of BLE);
   battery voltage and die temperature against the standard image, since the
   SAR ADC source resets the ADC block before the sampler is built; heap
   minimum and main-stack high-water during the TLS handshake from a
   `debug-log` build, which sets the final stack reserve; and the harvest,
   reseed, and seed-write cadence, including the six-hour forced harvest with
   Wi-Fi disabled.

Runtime enablement defaults to off. IPv6 remains outside this implementation.
