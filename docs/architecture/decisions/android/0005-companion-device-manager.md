# ADR 0005: CompanionDeviceManager for radio pairing and inventory

- Status: Accepted; emulator-verified on API 31 and 36, Pixel unverified
- Phase: 2

The Android counterpart of iOS [ADR 0008](../ios/0008-accessory-setup.md)
(AccessorySetupKit).

## Decision

Every companion radio is a single-device CompanionDeviceManager (CDM)
association. The association is the app's inventory of radios, and what
grants presence wake-ups and the background exemptions in
[ADR 0006](0006-background.md).

### Adding a radio

1. Connect a radio and Choose a radio list radios in pairing mode: the
   general-discoverable flag or the `0xFFFF` model element in the primary
   packet. The name fills in from the scan response without reordering.
   Choose a radio also lists a radio that is already associated and
   advertises the service, and pins the current radio at the top.
2. Tapping an unassociated radio asks CDM to associate it, filtered to the
   ULCP service and the scanned address (`BluetoothLeDeviceFilter`):
   - API 33+: `associate(request, executor, callback)`; the inventory is
     `getMyAssociations()`, keyed by association ID.
   - API 31–32: `associate(request, callback, handler)` through the page's
     activity (the application's manager throws there); the inventory is
     `getAssociations()`, keyed by MAC string. IDs recorded this way are
     resolved by address after an upgrade to 33+.
   - The manifest declares `uses-feature android.software.companion_device_setup`
     (`required="false"`); API 31 refuses every CDM call without it.
   - Don't allow changes nothing. A dialog that finds no device, or a wait
     past 30 s, ends as "Open the radio's pairing window and add it again."
     An association that arrives after the attempt was left is removed.
3. Connect, then bond: `connectGatt(TRANSPORT_LE)` on the scan's own
   `BluetoothDevice`, then `createBond()` on the connected device. The radios
   offer Just Works, or a fixed passkey when a PIN is set; no radio offers
   numeric comparison.
4. Attach and claim (ADR 0004). The registry records the radio's link ID (the
   address Android reports after bonding, stored as reported), association
   ID, model ID from the advertisement, and `autoConnect`. Until the radio
   first attaches the entry is marked pending; a process that ends first
   leaves it to the next start, which undoes the attempt as the attempt
   would have (the entry, and an association made for it) instead of
   connecting it. Presence and the service ignore a pending entry.

Confirmation comes before the current radio is released, so Don't allow
leaves the current radio connected. Once confirmed, the current radio's host
key is released before the new radio connects; the released radio stays
associated, so choosing it again needs no dialog. A failed choice releases
only the new association.

### Forgetting and losing a radio

- Forget: the driver releases the host key, the link goes down, then on API
  36+ `CompanionDeviceManager.removeBond(associationId)`, then `disassociate`,
  then the registry is cleared. On API 31–35 the system bond is kept; the
  hidden `BluetoothDevice.removeBond` is never called.
- A radio factory reset accepted by the radio (`abandonBinding`): the
  registry is cleared at once and the association released once the link
  drops.
- DFU: the binding, association and bond are kept; nothing reconnects.
- A known radio that refuses this phone's keys loses its association (and on
  36 its bond) when an attempt fails, so adding it again from its pairing
  window can succeed.

## Verification

Emulator, against the Bumble peripheral, with a gated UiAutomator test
(`BlePairingTest`, `-e ble pairing`) driving the CDM and pairing dialogs:

- Just Works and passkey pairing on API 31 and 36, association ID matching
  CDM's inventory.
- Advertising stopped under the CDM dialog ends as "Open the radio's pairing
  window and add it again." (API 36).
- Forget removes the bond on API 36 and keeps it on API 31.
- A radio forgotten by the radio side, re-added from its pairing window (API
  36).

Differences seen between the levels: API 36 bonds an associated Just Works
radio with no dialog; API 31 shows the passkey request as a notification the
user must open within 30 s. The CDM dialog's wording is the system's and does
not match the board.

Not verified: CDM discovery timing and address filtering on a Pixel
controller, real radios' behavior out of their pairing window, two radios
switched on a phone, stale bonds accumulating on API 31–35. These are in the
Pixel checklist (Pairing and inventory group).

## Consequences

Released radios stay associated until Forget. Clearing the app's data drops
every association but not the system bonds. Pairing on API 31–35 leaves one
stale system bond per factory reset or re-add, since no public API removes
it.
