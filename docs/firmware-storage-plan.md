# Firmware Non-Volatile Storage Plan

Persistent storage design for the nRF52840-based firmwares (T-Echo and Wio
Tracker L1 today; T1000-E and others later). Captures both the architectural
decision and the implementation plan.

This is a planning document. Once implemented, the per-firmware plans should
link back here for storage details rather than duplicating them.

## What we store

| Logical item        | Purpose                                          | Commit rate                       | Approx. size |
|---------------------|--------------------------------------------------|-----------------------------------|--------------|
| Identity            | Local Ed25519 private key                        | Once on first boot                | ~32 B        |
| Peer records        | Pubkey, alias, location, signal stats            | Lazy-batched (debounced ~5 s)     | ~180 B each  |
| Channel keys        | Symmetric room/multicast keys                    | Rare                              | ~80 B each   |
| MAC TX counters     | Per-local-identity TX reservation boundary       | Every `COUNTER_PERSIST_BLOCK_SIZE` (128) TXs | ~30 B each  |
| Peer RX counters    | Per-peer replay-window persistence boundary      | Every ~128–256 RX frames per peer | ~30 B each  |

Realistic logical maximum: ~25–45 KB (200 peers + 64 channels + counters).

## Counter persistence model

Frame counters are committed in **blocks**, not per frame. This is critical
for flash longevity: writing every TX would burn out internal NVMC in
months. The MAC layer already implements this for the TX side; the RX
side will need the same treatment when we wire up peer-counter persistence.

### TX-side (already implemented in `umsh-mac`)

[`crates/umsh-mac/src/coordinator.rs`](../crates/umsh-mac/src/coordinator.rs)
defines `COUNTER_PERSIST_BLOCK_SIZE = 128`. Each `IdentitySlot` tracks
three values:

- `frame_counter` — live, advances on every secured send.
- `persisted_counter` — last boundary safely committed to the
  `CounterStore`.
- `pending_persist_target` — scheduled future boundary, flushed by
  `Mac::service_counter_persistence()`.

On first TX after boot the slot schedules a new reservation
`persisted_counter + 128`. As the live counter approaches that boundary,
another reservation is scheduled. If the live counter would exceed the
persisted boundary without a successful flush, secure sends block with
`SendError::CounterPersistenceLag`. The store sees ~1 write per 128 TXs
per local identity.

### RX-side (planned, not yet in `umsh-mac`)

Peer-side replay protection lives in `PeerCryptoState::replay_window`
([`crates/umsh-mac/src/peers.rs`](../crates/umsh-mac/src/peers.rs)) as
an in-memory `ReplayWindow` tracking `last_accepted: u32`. On reboot
it resets to zero — replay of previously-seen frames from a peer is
not currently detected across reboots.

The fix mirrors the TX-side design:

- Track `last_accepted` in memory as today.
- Maintain a `persisted_last_accepted` per peer and commit a new boundary
  to the `CounterStore` only when `last_accepted - persisted_last_accepted >= N`
  (start with `N = 128`, tune later).
- On reboot, load the persisted boundary and seed the replay window's
  `last_accepted` with it. The peer's TX counter has continued to
  advance during downtime, so subsequent frames are above the boundary
  and accepted normally.

**Trade-off:** a window of up to `N` frames per peer where replay is
undetectable after a reboot. Same compromise the TX side already makes,
and acceptable for our threat model. Adjust `N` per side independently
if needed (RX may tolerate a larger window than TX).

This RX mechanism is **planned, not in scope for the initial storage
bringup phases.** Phase 1–3 build the underlying store; the RX-counter
persistence layer is a follow-up to `umsh-mac` once the store exists.

## What we explicitly are not solving yet

- **Bad-block handling.** `sequential-storage` does not detect or skip failed
  pages. Acceptable for current scope; revisit before shipping production
  hardware that will live in the field for years.
- **Encryption at rest.** Keys are stored plaintext, matching Meshtastic and
  MeshCore. Future concern, not blocking.
- **External QSPI flash.** The P25Q16H on both boards is the natural capacity
  upgrade path but is not in scope here. Identity will live on internal NVMC
  regardless, so the eventual two-tier layout doesn't change the identity
  storage path.

## Architecture decision: `sequential-storage` on internal NVMC

[`sequential-storage`](https://crates.io/crates/sequential-storage) (by
tweedegolf) is a pure-Rust, async-native, wear-leveling key-value store
designed for raw NOR flash. It uses an append-with-tombstones design and
periodic page compaction.

### Why sequential-storage

- Pure Rust, no C toolchain dependency.
- Async-native via `embedded-storage-async`.
- Stable on-disk format.
- Per-key updates are appends, not erases — friendly for frequent small
  updates like peer location.
- Page erase only on compaction, not on every write.
- Sufficient for our scale; LSM-tree advantages don't kick in below ~1000 keys.

### Why not littlefs2

- littlefs2 has no in-place file modification: every value update rewrites
  the whole file. Bad for mobile-peer location updates.
- One-file-per-peer works around this but creates directory-scaling issues
  in littlefs2; littlefs3 fixes this with inline files, but is not yet
  stabilised.
- Meshtastic's nRF52 port has a documented power-loss vulnerability
  ([meshtastic/firmware#4447](https://github.com/meshtastic/firmware/issues/4447))
  caused by configuring littlefs `block_size = 128` against a 4096-byte
  flash page. Adafruit made this trade deliberately to fit a small flash
  window, but a single page erase can corrupt up to 32 littlefs blocks
  instead of the in-flight one. `sequential-storage` is page-aligned by
  construction and isn't susceptible.

### Why not ekv

- Each write transaction triggers a full page erase. Exact opposite of
  our update pattern — every peer-location update would cost ~85 ms of
  CPU stall.
- On-disk format explicitly unstable across major versions; bad for shipped
  firmware that needs upgrade-safe storage.
- LSM-tree O(log n) advantage doesn't apply at our key count.

### Why not Nordic FDS

- C-only, tied to the Nordic SDK. We are not bringing the SDK in.

## Accepted limitations

### CPU stalls during NVMC page erase

The nRF52840 Product Specification is explicit: the CPU is halted by the
NVMC hardware while a flash erase or write is in progress. A 4 KB page
erase takes roughly 85 ms. During that time:

- No async task runs.
- USB CDC is not serviced.
- The LoRa MAC is not polled.

No software threading model (Embassy `InterruptExecutor`, FreeRTOS, Zephyr)
can preempt this — the stall is a hardware constraint, not a scheduling
one. The only way to avoid it is to move storage to a peripheral that
operates via DMA (i.e. the QSPI external flash).

Both Meshtastic and MeshCore accept this stall on internal flash. We accept
it too, for now, with one mitigation:

**Lazy-write debounce.** For high-frequency updates (peer location in
particular), batch writes with a short debounce (MeshCore uses ~5 s). One
page erase amortised across many logical updates is far better than one
per update. Implemented at the application layer above `KeyValueStore`,
not inside the store itself.

If real-time disruption becomes intolerable, the migration path is
external QSPI (DMA-based, truly async via `embassy-nrf::qspi`) for the
peer/counter store, with identity remaining on internal NVMC because it
must be readable before QSPI initialises.

### No bad-block handling

If a page's erase or write fails persistently (bit rot, voltage stress,
manufacturing defect), `sequential-storage` will return an error. There
is no built-in mechanism to mark a page bad and continue. For long-lived
field deployment we will need either Nordic FDS, a custom bad-block layer
on top of `sequential-storage`, or a recovery / re-provisioning workflow.
Not blocking for bringup.

## Flash layout

Both boards share an identical bootloader boundary at `0xF4000`. We
reserve **64 KB** (16 × 4 KB pages) at the top of the app flash window
for the storage region.

```
0x00000  ┌────────────────────────────────────┐
         │  MBR + SoftDevice slot (reserved)  │
         ├────────────────────────────────────┤  <- 0x26000 (T-Echo) / 0x27000 (Wio)
         │                                    │
         │  Application (.text/.rodata/etc.)  │
         │                                    │
         ├────────────────────────────────────┤  <- 0xE4000
         │  sequential-storage region (64 KB) │
         ├────────────────────────────────────┤  <- 0xF4000
         │  Bootloader + UICR                 │
0xFFFFF  └────────────────────────────────────┘
```

Updated `memory.x`:

- T-Echo:       `FLASH : ORIGIN = 0x00026000, LENGTH = 760K` (was 824K)
- Wio Tracker:  `FLASH : ORIGIN = 0x00027000, LENGTH = 756K` (was 820K)

The current release builds use ~360 KB, so we keep ~400 KB of app headroom
even after the reservation.

### Sizing rationale

- 64 KB = 16 pages.
- ~25–45 KB logical → 16 pages gives roughly 2× headroom for tombstones
  before compaction, which keeps erase frequency (and the 85 ms stalls)
  to a minimum.
- 16 erase-targets distributes wear comfortably. At reasonable update
  rates (peer locations every few minutes) the expected lifetime is on
  the order of a decade per page, well above device service life.
- Minimum for the crate to operate is ~4 pages (compaction needs a fresh
  page to move live entries to). 64 KB gives generous margin.

## Stored key namespace

Single shared `sequential-storage::Map`, keys are short ASCII prefixes:

| Key                  | Value                                                       |
|----------------------|-------------------------------------------------------------|
| `id.sk`              | 32-byte Ed25519 secret scalar                               |
| `peer:<pubkey>`      | Serialised peer record (alias, location, signal stats, …)   |
| `ch:<channel-id>`    | Channel name + symmetric key + flags                        |
| `mac.tx:<local-pk>`  | TX reservation boundary for a local identity (u32)          |
| `mac.rx:<peer-pk>`   | RX replay-window boundary for a peer (u32, future)          |

Keys are pubkey-addressed wherever an entity has a stable cryptographic
identity. Specifically:

- `<pubkey>`, `<peer-pk>`, `<local-pk>` are the **raw 32-byte** Ed25519
  public key bytes appended after the ASCII prefix — not hex-encoded.
  `sequential-storage` keys are arbitrary byte slices, so hex would just
  double the per-entry key overhead (32 → 64 bytes) for no operational
  benefit.
- This makes insertion idempotent (same peer ⇒ same storage key), avoids
  any "next free index" bookkeeping, and decouples storage from the
  in-memory `PeerId` slot assignments (which are `u8` indices into the
  `PeerCryptoMap` and re-assigned on every boot).
- `<channel-id>` is whatever stable identifier we settle on for channels
  (likely a hash of the channel key, or a short user-assigned name);
  TBD when we wire up the channel layer.

The `mac.tx:` and `mac.rx:` namespaces feed `umsh_hal::CounterStore`;
everything else goes through `umsh_hal::KeyValueStore`. Both back onto
the same underlying `sequential-storage::Map`; the prefix is what keeps
them logically separate.

## Implementation plan

### Phase 1 — foundation in `umsh-bsp-nrf52840`

1. Reduce `FLASH` length in both `firmware/*/memory.x` by 64 KB.
2. Add `sequential-storage` and `embedded-storage-async` to
   `umsh-bsp-nrf52840` (gated on `target_os = "none"`).
3. Create `umsh-bsp-nrf52840/src/flash_store.rs`:
   - `NvmcStorage` wrapping `embassy_nrf::nvmc::Nvmc` plus the fixed
     `0xE4000..=0xF3FFF` range. If `Nvmc` only implements the blocking
     `NorFlash`, bridge to async via the `BlockingAsync` adapter (or use
     `embassy-embedded-hal`'s shim). Verify which path is needed once
     coding starts; don't pre-commit.
   - `NvmcKeyValueStore` implementing `umsh_hal::KeyValueStore` on top of
     `sequential_storage::map`.
   - `NvmcCounterStore` implementing `umsh_hal::CounterStore`, sharing
     the same flash range (the namespacing is by key prefix).

### Phase 2 — identity persistence

4. On boot:
   - Try to load `id.sk` from the store.
   - If missing, generate a fresh Ed25519 key from the **hardware TRNG**
     (`embassy_nrf::rng::Rng` with bias correction enabled — see
     "Entropy requirement" below) and persist it. This will cost one
     85 ms stall on first boot only.
   - If present, reconstruct the identity from the stored scalar.
5. Replace the current `WioRng::from_ficr()` FICR-seeded identity in both
   firmwares with the persistent path. **Do not fall back to FICR** if
   storage init fails — that would silently downgrade the device to a
   predictable key. Surface the error and refuse to operate the secure
   send path instead.

#### Entropy requirement

The persisted private key is the device's long-term secret. It MUST be
generated from a true entropy source — not from FICR DEVICEID, not from
a PRNG seeded by FICR, and not from any input known to or derivable by
an attacker who has the device's part number and serial.

Concretely, on nRF52840:

- Use `embassy_nrf::rng::Rng`, the hardware TRNG peripheral.
- Enable bias correction (`set_bias_correction(true)`). The unbiased
  output is slower but suitable for cryptographic key generation. The
  raw biased output is **not** suitable.
- Block until enough entropy has been gathered to fill the full key
  buffer. First-boot key generation is allowed to be slow — it happens
  once.
- Do not mix in FICR DEVICEID, RTC values, or other low-entropy public
  inputs in a way that would let the attacker invert the seed. If we
  want defence-in-depth, mix RNG output with another independent
  entropy source (e.g. radio noise samples) using HKDF — but the RNG
  alone is sufficient and is the baseline requirement.

The existing `WioRng` / `TeChoRng` types in the bringup firmwares are
XorShift64 PRNGs seeded from FICR. They are explicitly **not** suitable
for identity generation. They also incorrectly implement `TryCryptoRng`
despite an in-source comment acknowledging they are non-cryptographic —
worth fixing as a separate cleanup (untyped `TryRng` is fine for MAC
backoff jitter, which is their actual purpose).

### Phase 3 — wire into firmwares

6. `firmware/hello-techo/src/main.rs`:
   - Construct the `NvmcStorage` after `Bsp::init`.
   - Pass the `KeyValueStore` and `CounterStore` to the `Mac` platform
     (currently `DummyKeyValueStore` / `DummyCounterStore`).
   - Use the store for the identity load/save in step 4.
7. `firmware/hello-wio-tracker-l1/src/main.rs`: same.

### Phase 4 — peer / channel persistence

8. Hook `LocalNode` / CLI peer-add to write through to the store.
9. On boot, scan the `peer:*` namespace and hydrate `LocalNode`.
10. Channel keys similarly via `ch:*` (lower priority — channels aren't
    user-added yet).

### Phase 5 — lazy-write batching (optional follow-up)

11. Add a debounced "dirty" set in the firmware binary for peer-location
    updates. Flush on a short timer (start at 5 s, tune later) and on
    clean shutdown.
12. Make sure the watchdog timeout window is comfortably larger than
    `flush_interval + worst-case erase time`.

### Phase 6 — RX-side peer counter persistence (follow-up to `umsh-mac`)

13. Extend `PeerCryptoState` with `persisted_last_accepted: u32`.
14. After each accepted RX frame, if `last_accepted - persisted_last_accepted >= N`,
    schedule a commit through the `CounterStore` (key `mac.rx:<peer>`).
    Start with `N = 128`, tune from telemetry.
15. On boot, load each peer's persisted boundary and seed the replay
    window's `last_accepted` with it.
16. Add a corresponding `SendError`-style backstop only if telemetry
    shows commits falling behind under load.

### Verification

- Cold flash, observe identity generation on first boot (one ~85 ms
  pause), confirm `/whoami` shows the new key.
- Power-cycle the board, confirm `/whoami` shows the same key.
- `/peer add` a peer, power-cycle, confirm `/peers` still lists it.
- Repeat on both T-Echo and Wio Tracker.

## Open items to resolve during implementation

- Does `embassy-nrf` ship a true async NVMC, or do we wrap the blocking
  one with `BlockingAsync` / `embassy_embedded_hal::adapter::BlockingAsync`?
  Either is workable; affects only the adapter layer in `flash_store.rs`.
- Does `umsh-node` want to own the identity load/save logic (so it's
  reusable across firmwares), or does each firmware binary do it? Lean
  towards `umsh-node` for reuse, but it's a small detail.
- Lazy-write batching belongs at the application layer; pick a home for
  it (likely in `umsh-cli` or `umsh-node`) when Phase 5 starts.
