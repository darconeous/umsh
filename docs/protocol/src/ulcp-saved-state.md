# ULCP: Saved State

A radio that only works while a phone is talking to it is a peripheral. A
radio that comes back after a power cut still configured, still
forwarding, with nobody present, is infrastructure. Saved state is the
difference: a device snapshots its device-domain configuration to
non-volatile storage and restores it at boot before anything else
happens.

## Capabilities

Code | Name       | Grants
-----|------------|--------
36   | `CAP_SAVE` | `CMD_SAVE`, `CMD_RESTORE`, `PROP_SAVED`, and boot-time restoration of saved state

`CMD_CLEAR` is available regardless of capabilities: a device with nothing
persisted succeeds trivially.

## Saved State {#saved-state}

A device advertising `CAP_SAVE` can snapshot its provisioning to
non-volatile storage so that it can operate autonomously across power
cycles — the radio can be powered on in the morning with no phone present,
restore its configuration, enable the PHY, and resume queueing and
acknowledging on the host's behalf.

* [`CMD_SAVE`](ulcp-saved-state.md#cmd-save) atomically writes the current **device
  domain** configuration — including the RF configuration and the current
  value of `PROP_PHY_ENABLED` — to non-volatile storage, replacing any
  previous snapshot.

  The host domain is **never** part of a snapshot (see [Host Domain](ulcp-core.md#host-domain)): a
  radio's autonomy is its own configuration, and whichever host it is
  serving re-establishes its keys, filters and delegation policy on every
  attach. Dynamic read-only state, including queue contents and
  `PROP_BATTERY`, is likewise never saved. The device identity keypair is
  excluded for a different reason: it is independently persisted the
  moment it is installed or generated (see [`PROP_DEV_PRIVATE_KEY`](ulcp-device.md#prop-dev-private-key)) and is
  changed only by explicit provisioning or `CMD_CLEAR` — neither
  `CMD_RESTORE` nor a reboot can revert the device identity to an earlier
  key.

  Traffic statistics (`PROP_STAT_*`) are also excluded. They are live
  hardware history since boot or the last explicit counter reset, not
  configuration a snapshot can restore.

  [`PROP_TIME`](ulcp-device.md#prop-time) is excluded for a third reason:
  a stored epoch is wrong by however long the device was off, by an amount
  nothing can bound, so restoring one would be restoring a confidently
  incorrect clock. A device recovers the time from a real source or
  reports that it does not know it. Its time *zone* is ordinary
  configuration and is saved.
* At boot, if a snapshot exists, the device **MUST** restore it and resume
  operation accordingly *before* processing any host command: the RF
  configuration is applied and the PHY is re-enabled if it was enabled
  when saved, so a repeater is forwarding before anything else happens.
  Host-domain behavior — filtering, queueing, acknowledgement delegation —
  does *not* resume, because there is no host domain until a host provides
  one. If no snapshot exists, all properties take their documented
  post-reset values.
* [`CMD_RESTORE`](ulcp-saved-state.md#cmd-restore) reverts the device domain to the
  snapshot on demand, letting the host abort uncommitted configuration
  changes — without rebooting the hardware or dropping the ULCP link.
  It is observable either as a protocol reset (`STATUS_RESET_RESTORED`) or
  as a series of property-update publications; hosts handle both.
* [`CMD_CLEAR`](ulcp-saved-state.md#cmd-clear) erases the snapshot and all other
  persisted provisioning, including the device identity private key. It
  does not modify live (in-RAM) state; a subsequent `CMD_RST` completes a
  factory reset. Transport-level state such as BLE bonds is not affected.
* [`PROP_SAVED`](ulcp-saved-state.md#prop-saved) reports the state of the stored
  snapshot, which is not simply whether one exists — see
  [Snapshot Integrity](ulcp-saved-state.md#snapshot-integrity).

Saving is explicit rather than automatic: nothing is written to
non-volatile storage when properties change (the exceptions are the device
identity and `PROP_BLE_PAIRING_PIN`). This gives the host control over
flash wear and a well-defined "known good" configuration, and it means a
radio never persists provisioning its host did not deliberately ask to
keep.

Two consequences deserve emphasis:

* **Post-reset values come from the snapshot.** `CMD_RST` reverts
  properties to their post-reset values, as always — but on a device with a
  snapshot, the post-reset value of every saved property is its saved
  value, not its documented default. This applies to the device domain
  only; the host domain has no saved value and always returns to its
  documented defaults. Factory defaults are restored by `CMD_CLEAR`
  followed by `CMD_RST`. A host that expects documented defaults after
  `CMD_RST` will find the PHY already configured and enabled on a radio
  that was provisioned for autonomous operation; such a host still works
  if it explicitly sets the properties it cares about.
* **Queue contents and replay baselines are not saved.** Frames queued
  before a power loss are gone afterward, even if they were acknowledged
  on the host's behalf — the sender believes them delivered. Likewise the
  per-peer frame-counter baselines used by acknowledgement delegation
  restart (see [Counter Resynchronization](security.md#counter-resynchronization)).
  These share the host domain's lifetime, which is why re-provisioning
  after a power cycle is a resynchronization point rather than an
  inconvenience. Implementations MAY persist the queue to narrow this
  window, but hosts **MUST NOT** rely on it.

### Snapshot Integrity {#snapshot-integrity}

The snapshot is the one piece of state whose loss is silent and remote.
A device configured to operate unattended comes back from a rejected
snapshot deaf and non-forwarding, with nobody attached to be told, and
recovery requires physically visiting it. The requirements below exist
for that case.

* A snapshot **MUST** be self-describing enough that a device can
  distinguish a payload it cannot read from an absent one. A device
  **MUST NOT** apply a payload it does not fully understand.
* Devices **MUST NOT** silently boot bare after rejecting a snapshot.
  Where the storage retains earlier generations, the device **MUST**
  fall back to the newest generation that does decode, in preference to
  booting with documented defaults. A device **MAY** bound how far back
  it walks.
* `PROP_SAVED` **MUST** report a fallback and an unreadable snapshot
  distinguishably from both "saved" and "nothing saved" (see
  [`PROP_SAVED`](ulcp-saved-state.md#prop-saved)). Devices with a local indicator **SHOULD** signal it
  there as well, since the host-visible report reaches nobody on an
  unattended device.
* A device that restored an older generation is otherwise in normal
  operation: nothing is refused, and `CMD_SAVE` replaces the stored
  snapshot and clears the condition.

Only forward compatibility is required. Newer firmware **MUST** read
snapshots written by older firmware, taking the documented default for
anything the older writer did not record, and **MUST** ignore content it
does not recognize. Firmware downgrade is out of scope: an older image
reading a newer snapshot has no defined behavior, and saving from a
downgraded image is destructive by design.

## Commands

Id | Mnemonic            | Dir          | Description
---|---------------------|--------------|-------------
12 | `CMD_SAVE`          | Host->Device | Save state to non-volatile storage
13 | `CMD_CLEAR`         | Host->Device | Erase all saved state
14 | `CMD_RESTORE`       | Host->Device | Restore state from the saved snapshot
15 | `CMD_FACTORY_RESET` | Host->Device | Erase **all** mutable state (incl. bonds) and reboot

### CMD 12: (Host -> Device) `CMD_SAVE` {#cmd-save}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |    CMD_SAVE   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_SAVE`

Save state. Commands the device to atomically write the current device-domain
configuration to non-volatile storage as described in [Saved State](ulcp-saved-state.md#saved-state),
replacing any existing snapshot. The command payload SHOULD be empty and
MUST be ignored.

The response is a `CMD_PROP_IS` for `PROP_LAST_STATUS` with the command's
TID: `STATUS_OK` once the snapshot is durably stored, or an appropriate
error status (for example `STATUS_NOMEM`) if it is not; on failure the
previous snapshot, if any, MUST remain intact.

This command is only available on devices advertising `CAP_SAVE`; otherwise
it fails with `STATUS_UNIMPLEMENTED`.

### CMD 13: (Host -> Device) `CMD_CLEAR` {#cmd-clear}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |   CMD_CLEAR   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_CLEAR`

Clear saved state. Commands the device to erase from non-volatile storage the
saved snapshot and all other persisted provisioning, including the device
identity private key. Live (in-RAM) state is unaffected; transport-level
state such as BLE bonds and `PROP_BLE_PAIRING_PIN` is also unaffected. A
`CMD_CLEAR` followed by `CMD_RST` restores factory protocol behavior.

Because a device identity always exists (see [The Device Identity](ulcp-device.md#device-identity)), the
`CMD_RST` that completes the sequence **MUST** generate and persist a new
one rather than leave the device with none — the same thing a factory-fresh
power-on does, and for the same reason. `PROP_DEV_KEY` therefore reports a
*different* key after the sequence, never an empty one.

The previous identity is gone from the moment `CMD_RST` completes, but
anything the device built around it — a running device node, in particular —
**MUST NOT** continue to originate traffic under it, even where that state
survives until the next boot.

The command payload SHOULD be empty and MUST be ignored. The response is a
`CMD_PROP_IS` for `PROP_LAST_STATUS` with the command's TID.

Unlike `CMD_SAVE`, this command is available regardless of capabilities;
a device with nothing persisted succeeds trivially.

### CMD 14: (Host -> Device) `CMD_RESTORE` {#cmd-restore}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |  CMD_RESTORE  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_RESTORE`

Restore saved state. Commands the device to revert its **device-domain**
configuration to the contents of the saved snapshot (see [Saved State](ulcp-saved-state.md#saved-state)).
Regardless of how completion is reported (below), the resulting state is
the same:

* saved device-domain properties take their saved values, and the saved
  RF configuration and PHY enable state are applied;
* the hardware is not reset, and the transport link and attach state are
  preserved;
* the host domain is **not** touched: it is not part of a snapshot, so a
  restore has nothing to revert it to. The inbound queue contents,
  per-peer replay baselines, filters and delegation policy all survive
  unconditionally;
* independently persisted state outside the snapshot — the device
  identity keypair and `PROP_BLE_PAIRING_PIN` — is not affected; and
* the saved snapshot itself is not modified.

**A restore never enables the PHY under an identity the snapshot was not
taken for.** A snapshot records which device identity was live when it
was written. If that does not match the live `PROP_DEV_KEY`, the device
**MUST** apply the restore with `PROP_PHY_ENABLED` false, whatever the
snapshot says.

This is the replacement-hardware case, and it is the one path where a
freshly generated identity can reach the air. Restoring a repeater's
saved domain onto a new board before installing that repeater's key (see
[`PROP_DEV_PRIVATE_KEY`](ulcp-device.md#prop-dev-private-key)) would otherwise bring the radio up advertising
as the node the snapshot describes, signing as a key nobody has ever
seen. Installing the key first, then restoring, is the intended order and
enables the PHY normally; the rule is what makes the wrong order safe
rather than merely discouraged. A snapshot that does not record an
identity is treated as matching.

Together with `CMD_SAVE`, this provides a commit/abort pattern: the host
can make live configuration changes and either persist them with
`CMD_SAVE` or discard them with `CMD_RESTORE`.

The command payload SHOULD be empty and SHOULD NOT be processed. A device
reports a successful restore in one of two forms, both valid; the two
forms differ only in reporting and in session-state handling, never in
the resulting configuration or retained data:

* **Reset form** — the device additionally resets its protocol session
  state (transaction bookkeeping and session-scoped properties), as on
  attach. As with `CMD_RST`, the TID is ignored; completion is signaled
  by an unsolicited `CMD_PROP_IS` for `PROP_LAST_STATUS` carrying the
  reset code `STATUS_RESET_RESTORED` (see [Reset Codes](ulcp-core.md#reset-codes)). On
  receiving it, the host discards its cached view of all properties and
  assumes saved properties hold their saved values; dynamic read-only
  properties (such as `PROP_HOST_RX_QUEUE_COUNT`) reflect live state and
  are re-fetched.

* **Update form** — the device applies the revert in place, emitting an
  unsolicited `CMD_PROP_IS` (with key material omitted, where applicable) for
  **every property whose value changed**, and then reports completion
  with `CMD_PROP_IS` for `PROP_LAST_STATUS` carrying `STATUS_OK` and the
  command's TID. Session state is not reset in this form.

A host **MUST** handle both forms: it treats `STATUS_RESET_RESTORED` as
full reversion to saved values, applies any unsolicited property updates,
and recognizes completion by either the reset notification or the
matching-TID `STATUS_OK`. This is not an extra burden in practice — hosts
must already tolerate unsolicited `CMD_PROP_IS` value changes at any time
(see [Attach, Detach, and Synchronization](ulcp-core.md#attach-sync)). A host that does not know the snapshot's contents
(for example, because a previous session saved it) re-fetches the
properties it depends on, exactly as in the post-attach procedure.

If an error occurs — in particular `STATUS_INVALID_STATE` when no snapshot
exists (see `PROP_SAVED`) — the value of the emitted `PROP_LAST_STATUS`
will be set accordingly, no state is modified, and no reset code is
emitted.

### CMD 15: (Host -> Device) `CMD_FACTORY_RESET` {#cmd-factory-reset}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |CMD_FACTORY_RST|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_FACTORY_RESET`

Return the radio to a blank factory state. Commands the device to erase
**every** piece of mutable state it holds — both the persisted state
`CMD_CLEAR` erases (the saved snapshot, all persisted provisioning, and
the device identity private key) **and** the transport-level state
`CMD_CLEAR` deliberately preserves: all BLE bonds and the configured
`PROP_BLE_PAIRING_PIN` — and then reboot. After the reboot the radio is
indistinguishable from one that has never been provisioned or paired.

This differs from `CMD_CLEAR` + `CMD_RST` in two ways: it also clears
transport-level pairing state (bonds and PIN), and it performs a hardware
reboot rather than only a protocol-session reset.

The command payload SHOULD be empty and MUST be ignored. Unlike every
other command, `CMD_FACTORY_RESET` **has no response**: the device wipes its
storage and reboots, which drops the transport link. A host treats the
ensuing disconnect (and the radio's subsequent reappearance in a factory
state) as completion; it **MUST NOT** wait for a `PROP_LAST_STATUS`. The
TID is therefore irrelevant.

Because clearing the bonds invalidates the encrypted link the command
arrived on, a host that issues `CMD_FACTORY_RESET` over a bonded transport
should also discard its own pairing to the radio.

This command is available regardless of capabilities.

## Properties

Id | Mnemonic     | Commands | Description
---|--------------|----------|-------------
49 | `PROP_SAVED` | Get      | Saved-snapshot state

### PROP 49: `PROP_SAVED` {#prop-saved}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_SAVE`
* Value Type: UINT8

Whether a saved snapshot is in effect (see [Saved State](ulcp-saved-state.md#saved-state)) — that is,
whether the device is armed for autonomous operation across a power cycle —
and, when the answer is qualified, how:

Value | Meaning
---|---
0 | Nothing is saved. Every property holds its documented default.
1 | The most recently saved snapshot is in effect.
2 | A saved snapshot is in effect, but a **newer** stored generation was rejected at boot and this is an earlier one. The device is operating on configuration older than what was last saved.
3 | A snapshot exists but **no** stored generation could be read. The device booted with documented defaults despite having been saved.

Values 2 and 3 are conditions to report to the operator, not errors to
recover from automatically: the configuration the device is running is not
the configuration that was last written, and only whoever wrote it can
say what should replace it. A successful `CMD_SAVE` returns the value to
1. Values 2 and 3 persist for the remainder of the power cycle and
**MUST NOT** be cleared by `CMD_RST` or `CMD_RESTORE`, neither of which
re-reads storage.

A host that treats any non-zero value as "saved" behaves correctly, and
loses only the warning.
