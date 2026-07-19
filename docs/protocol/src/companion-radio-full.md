# Full Companion Radio Protocol

This chapter defines the **full** companion-radio protocol: a strict superset
of the [Minimal Companion Radio Protocol](companion-radio-minimal.md). An NCP
implementing this chapter implements everything in the minimal protocol —
the frame format, packed unsigned integers, commands, properties, status
codes, reset codes, and capabilities defined there apply here unchanged and
are not repeated. The protocol version remains **6.0**; a host discovers
which full-protocol features an NCP implements through `PROP_CAPS`
(see (#full-capabilities)), not through the version number.

The minimal protocol treats the NCP as a raw radio pipe: the host runs the
entire UMSH MAC and the NCP moves frames. The full protocol keeps that
division of labor — the host still owns the MAC and its own private keys —
and adds narrowly scoped **assistance** so the NCP can be useful while the
host is asleep or disconnected:

* **Receive filtering** — the NCP learns which frames are relevant so it does
  not deliver (or wake the host for) unrelated traffic.
* **Inbound queueing** — frames received while no host is attached are
  retained and delivered when the host asks for them.
* **Key provisioning** — the host installs channel keys and pairwise peer
  keys so the NCP can recognize traffic for the host's identity, including
  blind unicast, and authenticate it.
* **Acknowledgement delegation** — for peers whose pairwise keys are
  provisioned, the NCP can send MAC acks on the host's behalf while the host
  is away.
* **Saved state** — the NCP can snapshot its configuration to non-volatile
  storage and resume autonomous operation after a power cycle with no host
  present.

There is no outbound queueing. A transmit either happens or fails while the
host is attached to observe the result.

## Identity Model {#identity-model}

The full protocol supports exactly two node identities:

* **The device identity** — a node belonging to the companion radio itself,
  used for in-band management, diagnostics, and (in future revisions)
  repeater and advertisement behavior. Its Ed25519 private key is held by
  the NCP: it is either generated on the device or installed once by the
  host (see (#prop-dev-private-key)), and it is never readable through this
  protocol.

* **The tethered host identity** — the single UMSH identity owned by the
  attached host. Of the identity keypair itself, the NCP holds only the
  32-byte public key; the host's private key **MUST NOT** be transferred
  to the NCP, and this protocol provides no mechanism for doing so (see
  [Security Boundary](companion-radio.md#security-boundary)). The NCP may
  additionally hold host-domain state derived or delegated by the host —
  channel keys, per-peer symmetric keys, filters, and queued traffic — as
  defined in this chapter.

Because the NCP never holds the host's private key, it cannot perform ECDH
on the host's behalf. All pairwise key material the NCP uses for the host
identity is derived by the host and explicitly provisioned per peer (see
(#prop-host-peer-keys)). The device identity is different: the NCP holds
that private key, so it performs its own key agreement and needs only peer
*public* keys (see (#prop-dev-peers)).

## State Classes {#state-classes}

Every piece of NCP state belongs to exactly one of three classes. The
classes determine what survives a host attach, a change of host, and a
power cycle.

### Session State

State that exists only while a host is attached: transaction (TID)
correlation, transport reassembly buffers, and session-scoped properties —
currently only `PROP_MAC_PROMISCUOUS`. Session state is reset to defaults
on every attach. Resetting it never affects radio operation.

### Device Domain

State that belongs to the companion radio itself, independent of which
host is attached:

* the device identity keypair (independently persisted; never part of
  the saved snapshot — see (#saved-state))
* the device identity's channel keys ((#prop-dev-channel-keys)) and peer
  list ((#prop-dev-peers))
* the RF configuration (`PROP_PHY_*`), including `PROP_PHY_ENABLED`, and
  the duty-cycle limit
* the human-readable device name (`PROP_DEV_NAME`)
* live battery telemetry (`PROP_BATTERY`), when `CAP_BATTERY` is present
* device behavior settings (property identifiers 70–95, reserved for
  future definition: repeater policy, positioning, periodic advertisement
  of the device identity, and similar)
* transport configuration such as `PROP_BLE_PAIRING_PIN`

The RF configuration is deliberately device-domain: a site repeater keeps
its frequency and regulatory limits no matter which phone pairs with it.
An attached host may still reconfigure it at any time.

### Host Domain

State that belongs to the currently configured tethered host identity:

* `PROP_HOST_KEY` itself
* the host's channel keys and peer keys
* the receive filter table and acknowledgement-delegation policy
* the inbound queue: its configuration and its contents

### Host Replacement {#host-replacement}

The host domain is keyed by `PROP_HOST_KEY`. Setting `PROP_HOST_KEY` to a
value **different** from its current value — including setting it to empty
— **MUST** atomically reset the entire host domain to defaults: the key
tables and filter table are cleared, `PROP_HOST_AUTO_ACK` reverts to
false, and the inbound queue is discarded. The wipe **MUST** also apply to
the host-domain portion of any saved state (see (#saved-state)), so that a
power cycle cannot resurrect a previous host's provisioning.

Setting `PROP_HOST_KEY` to its current value is idempotent and has no side
effects.

This rule is what makes re-pairing safe: when a companion radio is paired
with a different phone, the new host configures its own identity and the
previous host's keys, filters, and queued traffic cease to exist — while
the device domain (the radio's own identity, channels, and settings) is
untouched.

## Attach, Detach, and Synchronization {#attach-sync}

How attach and detach are detected is defined by the transport binding:

* **BLE** — enabling/disabling notifications on Frame Out, as specified in
  [Companion Radio over BLE](companion-radio-ble.md#attach-semantics).
* **USB-CDC** — assertion and deassertion of DTR on the companion
  interface.
* **Bare UART** — implementation-defined. An NCP with no way to detect
  host presence MAY treat the host as permanently attached, in which case
  it never enters detached operation and offline assistance
  ((#inbound-queueing), (#ack-delegation)) is unavailable on that
  transport.

On attach, the NCP **MUST** reset session state (see (#state-classes)) and
**MUST NOT** modify the device or host domains in any way. In particular,
the PHY is not disabled and no property outside session state changes
value. The NCP **MUST NOT** emit any frame before attach, and emits no
unsolicited notification as a result of the attach itself.

Because attach no longer implies any known default state, the host
synchronizes by *fetching*, not by assuming. The following post-attach
procedure is **RECOMMENDED**:

1. `CMD_PROP_GET` for `PROP_LAST_STATUS`. If it returns a reset code (see
   [Reset Codes](companion-radio-minimal.md#reset-codes)), the NCP has
   reset since the last host command, so any state that is not restored
   from saved state (notably queue contents) has been lost.
2. `CMD_PROP_GET` for `PROP_HOST_KEY`, and verify it matches the host's
   own identity. If it does not, another host has taken over the radio
   since this host last attached; the queue and provisioning belong to
   that identity, and this host must decide whether to take the radio
   over (see (#host-replacement)) before doing anything else.
3. `CMD_PROP_GET` for the device-domain and host-domain properties the
   host depends on (`PROP_SAVED`, the `PROP_PHY_*` configuration,
   `PROP_HOST_RX_QUEUE_COUNT`, and the digest forms of the key tables),
   reconciling or re-provisioning as needed.
4. Issue `CMD_QUEUE_DRAIN` when actually ready to process backlogged
   traffic.

More generally, a host **MUST** tolerate unsolicited `CMD_PROP_IS`,
`CMD_PROP_INSERTED`, and `CMD_PROP_REMOVED` notifications at any time
while attached, updating its view of the affected property accordingly:
NCP state can change for reasons the host did not initiate, and
publication of the new authoritative value is how the protocol reports
that.

On detach, the NCP discards session state, keeps operating with the
current device- and host-domain state, and begins detached operation:
accepted frames are queued rather than delivered, and acknowledgement
delegation (if enabled) becomes active.

## Saved State {#saved-state}

An NCP advertising `CAP_SAVE` can snapshot its provisioning to
non-volatile storage so that it can operate autonomously across power
cycles — the radio can be powered on in the morning with no phone present,
restore its configuration, enable the PHY, and resume queueing and
acknowledging on the host's behalf.

* `CMD_SAVE` (see (#cmd-save)) atomically writes the current device
  domain and host domain **configuration** — including the RF configuration
  and the current value of `PROP_PHY_ENABLED` — to non-volatile storage,
  replacing any previous snapshot. Dynamic read-only state, including
  queue contents and `PROP_BATTERY`, is never part of a snapshot. The
  device identity keypair is also excluded: it is independently persisted
  the moment it is installed or generated (see (#prop-dev-private-key)) and
  is changed only by explicit provisioning or `CMD_CLEAR` — neither
  `CMD_RESTORE` nor a reboot can revert the device identity to an earlier
  key.
* At boot, if a snapshot exists, the NCP **MUST** restore it and resume
  operation accordingly *before* processing any host command: the RF
  configuration is applied, the PHY is re-enabled if it was enabled when
  saved, and detached operation (filtering, queueing, acknowledgement
  delegation) begins immediately. If no snapshot exists, all properties
  take their documented post-reset values.
* `CMD_RESTORE` (see (#cmd-restore)) reverts to the snapshot on demand,
  letting the host abort uncommitted configuration changes — without
  rebooting the hardware or dropping the companion link. It is observable
  either as a protocol reset (`STATUS_RESET_RESTORED`) or as a series of
  property-update publications; hosts handle both.
* `CMD_CLEAR` (see (#cmd-clear)) erases the snapshot and all other
  persisted provisioning, including the device identity private key. It
  does not modify live (in-RAM) state; a subsequent `CMD_RST` completes a
  factory reset. Transport-level state such as BLE bonds is not affected.
* `PROP_SAVED` (see (#prop-saved)) reports whether a snapshot exists.

Saving is explicit rather than automatic: nothing is written to
non-volatile storage when properties change (the exceptions are the device
identity, `PROP_BLE_PAIRING_PIN`, and the durable host-domain wipe of
(#host-replacement)). This gives the host control over flash wear and a
well-defined "known good" configuration, and it means a radio never
persists provisioning its host did not deliberately ask to keep.

Two consequences deserve emphasis:

* **Post-reset values come from the snapshot.** `CMD_RST` reverts
  properties to their post-reset values, as always — but on an NCP with a
  snapshot, the post-reset value of every saved property is its saved
  value, not its documented default. Factory defaults are restored by
  `CMD_CLEAR` followed by `CMD_RST`. A host that implements only the
  minimal protocol and expects documented defaults after `CMD_RST` will
  find the PHY already configured and enabled on a radio that was
  provisioned for autonomous operation; such a host still works if it
  explicitly sets the properties it cares about.
* **Queue contents and replay baselines are not saved.** Frames queued
  before a power loss are gone afterward, even if they were acknowledged
  on the host's behalf — the sender believes them delivered. Likewise the
  per-peer frame-counter baselines used by acknowledgement delegation
  restart (see [Counter Resynchronization](security.md#counter-resynchronization)).
  Implementations MAY persist the queue to narrow this window, but hosts
  **MUST NOT** rely on it.

## Additional Commands

The full protocol assigns the four command identifiers reserved by the
minimal protocol for table operations, and adds three more:

Id | Mnemonic            | Dir       | Description
---|---------------------|-----------|-------------
4  | `CMD_PROP_INSERT`   | Host->NCP | Insert an item into a multi-value property
5  | `CMD_PROP_REMOVE`   | Host->NCP | Remove an item from a multi-value property
7  | `CMD_PROP_INSERTED` | NCP->Host | Item-inserted notification
8  | `CMD_PROP_REMOVED`  | NCP->Host | Item-removed notification
11 | `CMD_QUEUE_DRAIN`   | Host->NCP | Deliver queued inbound frames
12 | `CMD_SAVE`          | Host->NCP | Save state to non-volatile storage
13 | `CMD_CLEAR`         | Host->NCP | Erase all saved state
14 | `CMD_RESTORE`       | Host->NCP | Restore state from the saved snapshot

### CMD 4: (Host -> NCP) `CMD_PROP_INSERT` {#cmd-prop-insert}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ITEM VALUE ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_INSERT`

Insert item into property. Commands the NCP to add the given item to the
given multi-value property, and to emit a `CMD_PROP_INSERTED` command for
that property if successful.

The payload for this command is the property identifier encoded in the
packed unsigned integer format, followed by exactly one item encoded in the
property's **item form** (see (#multi-value-properties)). The item is
**not** preceded by a length prefix, regardless of whether the property
uses item length prefixes in its multi-item value form; the framing layer
bounds the item.

If the item is already present the command fails with `STATUS_ALREADY`,
except where a property defines replacement semantics for matching items
(see, e.g., (#prop-host-peer-keys)). If the property exists but is not a
multi-value property, the command fails with `STATUS_INVALID_ARGUMENT`.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 5: (Host -> NCP) `CMD_PROP_REMOVE` {#cmd-prop-remove}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ITEM SELECTOR ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_REMOVE`

Remove item from property. Commands the NCP to remove the item matching the
given selector from the given multi-value property, and to emit a
`CMD_PROP_REMOVED` command for that property if successful.

The payload for this command is the property identifier encoded in the
packed unsigned integer format, followed by an item selector. Each
multi-value property documents its selector form; unless stated otherwise
it is the full item value.

If no matching item is present, the command fails with
`STATUS_ITEM_NOT_FOUND`. If the property exists but is not a multi-value
property, the command fails with `STATUS_INVALID_ARGUMENT`.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 7: (NCP -> Host) `CMD_PROP_INSERTED` {#cmd-prop-inserted}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ITEM DIGEST ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_INSERTED`

Item-inserted notification. Sent by the NCP in response to a successful
`CMD_PROP_INSERT` (with the TID of that command), or unsolicited with a TID
of zero when the NCP adds an item to a multi-value property for its own
reasons.

The payload is the property identifier followed by the inserted item in the
property's **digest form** (see (#multi-value-properties)) — never in a
form containing key material.

### CMD 8: (NCP -> Host) `CMD_PROP_REMOVED` {#cmd-prop-removed}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ITEM DIGEST ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_REMOVED`

Item-removed notification. Sent by the NCP in response to a successful
`CMD_PROP_REMOVE` (with the TID of that command), or unsolicited with a TID
of zero when the NCP removes an item from a multi-value property for its
own reasons.

The payload is the property identifier followed by the removed item in the
property's digest form.

### CMD 11: (Host -> NCP) `CMD_QUEUE_DRAIN` {#cmd-queue-drain}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |CMD_QUEUE_DRAIN|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_QUEUE_DRAIN`

Deliver queued inbound frames. Commands the NCP to deliver every frame
currently held in the inbound queue (see (#inbound-queueing)), oldest
first, as ordinary `CMD_STR_RECV` commands on `STR_PHY_RAW` carrying the
buffered-frame metadata described in (#buffered-metadata). The command
payload SHOULD be empty and MUST be ignored.

Queued frames are **only** delivered in response to this command; attaching
to the NCP does not by itself cause queued frames to be delivered (see
(#inbound-queueing)). This lets the host finish synchronizing its session
and signal that it is actually ready to process backlogged traffic.

The drain covers exactly the frames held in the queue when the command is
received. Because accepted frames are always delivered live while a host
is attached, the queue cannot grow while a drain is in progress: the drain
always covers a fixed set of frames and always terminates. If the command
was sent with a non-zero TID, the NCP reports completion by emitting
`CMD_PROP_IS` for `PROP_LAST_STATUS` with `STATUS_OK` and the matching TID
immediately after delivering the last covered frame. Draining an empty
queue succeeds immediately.

Frames that arrive while a drain is in progress are not part of it: they
are delivered live, and MAY therefore interleave with the buffered
deliveries. `RX_FLAG_BUFFERED` distinguishes the two, and UMSH does not
guarantee in-order delivery in any case (see (#inbound-queueing)).

If the NCP does not implement queueing (`CAP_HOST_RX_QUEUE` not
advertised), the command fails with `STATUS_UNIMPLEMENTED`.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 12: (Host -> NCP) `CMD_SAVE` {#cmd-save}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |    CMD_SAVE   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_SAVE`

Save state. Commands the NCP to atomically write the current device domain
and host domain to non-volatile storage as described in (#saved-state),
replacing any existing snapshot. The command payload SHOULD be empty and
MUST be ignored.

The response is a `CMD_PROP_IS` for `PROP_LAST_STATUS` with the command's
TID: `STATUS_OK` once the snapshot is durably stored, or an appropriate
error status (for example `STATUS_NOMEM`) if it is not; on failure the
previous snapshot, if any, MUST remain intact.

This command is only available on NCPs advertising `CAP_SAVE`; otherwise
it fails with `STATUS_UNIMPLEMENTED`.

### CMD 13: (Host -> NCP) `CMD_CLEAR` {#cmd-clear}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |   CMD_CLEAR   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_CLEAR`

Clear saved state. Commands the NCP to erase from non-volatile storage the
saved snapshot and all other persisted provisioning, including the device
identity private key. Live (in-RAM) state is unaffected; transport-level
state such as BLE bonds and `PROP_BLE_PAIRING_PIN` is also unaffected. A
`CMD_CLEAR` followed by `CMD_RST` restores factory protocol behavior.

The command payload SHOULD be empty and MUST be ignored. The response is a
`CMD_PROP_IS` for `PROP_LAST_STATUS` with the command's TID.

Unlike `CMD_SAVE`, this command is available regardless of capabilities;
an NCP with nothing persisted succeeds trivially.

### CMD 14: (Host -> NCP) `CMD_RESTORE` {#cmd-restore}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |  CMD_RESTORE  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_RESTORE`

Restore saved state. Commands the NCP to revert its device-domain and
host-domain **configuration** to the contents of the saved snapshot (see
(#saved-state)). Regardless of how completion is reported (below), the
resulting state is the same:

* saved properties take their saved values, and the saved RF
  configuration and PHY enable state are applied;
* the hardware is not reset, and the transport link and attach state are
  preserved;
* the inbound queue contents and per-peer replay baselines are preserved
  — except that if the snapshot's host key differs from the live
  `PROP_HOST_KEY`, the host-replacement rule (see (#host-replacement))
  applies as part of the revert;
* independently persisted state outside the snapshot — the device
  identity keypair and `PROP_BLE_PAIRING_PIN` — is not affected; and
* the saved snapshot itself is not modified.

Together with `CMD_SAVE`, this provides a commit/abort pattern: the host
can make live configuration changes and either persist them with
`CMD_SAVE` or discard them with `CMD_RESTORE`.

The command payload SHOULD be empty and SHOULD NOT be processed. An NCP
reports a successful restore in one of two forms, both valid; the two
forms differ only in reporting and in session-state handling, never in
the resulting configuration or retained data:

* **Reset form** — the NCP additionally resets its protocol session
  state (transaction bookkeeping and session-scoped properties), as on
  attach. As with `CMD_RST`, the TID is ignored; completion is signaled
  by an unsolicited `CMD_PROP_IS` for `PROP_LAST_STATUS` carrying the
  reset code `STATUS_RESET_RESTORED` (see (#full-reset-codes)). On
  receiving it, the host discards its cached view of all properties and
  assumes saved properties hold their saved values; dynamic read-only
  properties (such as `PROP_HOST_RX_QUEUE_COUNT`) reflect live state and
  are re-fetched.

* **Update form** — the NCP applies the revert in place, emitting an
  unsolicited `CMD_PROP_IS` (in digest form, where applicable) for
  **every property whose value changed**, and then reports completion
  with `CMD_PROP_IS` for `PROP_LAST_STATUS` carrying `STATUS_OK` and the
  command's TID. Session state is not reset in this form.

A host **MUST** handle both forms: it treats `STATUS_RESET_RESTORED` as
full reversion to saved values, applies any unsolicited property updates,
and recognizes completion by either the reset notification or the
matching-TID `STATUS_OK`. This is not an extra burden in practice — hosts
must already tolerate unsolicited `CMD_PROP_IS` value changes at any time
(see (#attach-sync)). A host that does not know the snapshot's contents
(for example, because a previous session saved it) re-fetches the
properties it depends on, exactly as in the post-attach procedure.

If an error occurs — in particular `STATUS_INVALID_STATE` when no snapshot
exists (see `PROP_SAVED`) — the value of the emitted `PROP_LAST_STATUS`
will be set accordingly, no state is modified, and no reset code is
emitted.

This command is only available on NCPs advertising `CAP_SAVE`; otherwise
it fails with `STATUS_UNIMPLEMENTED`.

## Multi-Value Properties {#multi-value-properties}

A **multi-value property** holds an unordered set of items rather than a
single value. The minimal protocol already contains one (`PROP_CAPS`, which
is constant); the full protocol adds mutable ones.

Each multi-value property defines two encodings for its items:

* the **item form**, used when the host writes items (`CMD_PROP_SET`,
  `CMD_PROP_INSERT`); and
* the **digest form**, used whenever the NCP reports items
  (`CMD_PROP_IS`, `CMD_PROP_INSERTED`, `CMD_PROP_REMOVED`).

For most properties the two forms are identical. They differ exactly where
the item form contains symmetric key material: the digest form of such a
property omits or replaces the key material so that secrets can never be
read back (see (#provisioning-security)).

The commands valid on a mutable multi-value property are:

* `CMD_PROP_GET` — the NCP replies with `CMD_PROP_IS` whose value is the
  concatenation of all items in digest form. If the property is documented
  as having an item length prefix, each item is preceded by its length in
  octets encoded as a packed unsigned integer; properties whose reported
  items are fixed-size omit the prefix.
* `CMD_PROP_SET` — replaces the entire contents with the items encoded in
  the value, each in item form (with the same length-prefix rule). Setting
  an empty value clears the property. Success is reported with a
  `CMD_PROP_IS` carrying the new complete value in digest form.
* `CMD_PROP_INSERT` / `CMD_PROP_REMOVE` — add or remove one item, as
  defined above.

Hosts manipulating large tables **SHOULD** prefer `Insert`/`Remove` over
whole-table `Set`, since a full table may not fit comfortably in one frame
on all transports.

## Mutation Atomicity {#mutation-atomicity}

State-changing operations in this protocol are transactional and fail
closed:

* The NCP **MUST** validate a complete request before changing any state.
  A whole-table `CMD_PROP_SET` whose value contains any invalid item fails
  without applying any of it.
* Whole-table replacement is atomic: no observer of NCP behavior (frame
  filtering, acknowledgement decisions) sees a mixture of the old and new
  contents.
* Operations that include durable writes — `CMD_SAVE`, `CMD_CLEAR`,
  installing or generating the device identity, setting
  `PROP_BLE_PAIRING_PIN`, and the durable host-domain wipe of
  (#host-replacement) — **MUST NOT** report success before the durable
  write has completed.
* On any failure, the prior live and durable state remains unchanged, and
  the NCP **MUST NOT** emit `CMD_PROP_IS`, `CMD_PROP_INSERTED`, or
  `CMD_PROP_REMOVED` notifications describing a partially applied change.
* Host replacement is atomic in the same sense: at no point may the NCP
  operate with a mixture of the old and new hosts' keys, filters, or
  policy. If the durable wipe of the old host domain cannot be completed,
  the `CMD_PROP_SET` of `PROP_HOST_KEY` **MUST** fail, leaving the old
  host domain fully in effect and the new host key not installed.

## Property Allocation {#property-allocation}

The full protocol allocates property identifiers by state class:

Range   | Class
--------|--------------------------------------------
48–63   | Session-scoped and global protocol state
64–95   | Device domain
96–127  | Host domain (`PROP_HOST_*`)

Unassigned identifiers in these ranges are reserved.

Id  | Mnemonic                      | Commands                 | Description
----|-------------------------------|--------------------------|-------------
48  | `PROP_MAC_PROMISCUOUS`        | Get, Set                 | Deliver all frames (session-scoped)
49  | `PROP_SAVED`                  | Get                      | Saved snapshot exists
64  | `PROP_DEV_KEY`                | Get                      | Device identity public key
65  | `PROP_DEV_PRIVATE_KEY`        | Set                      | Device identity private key (write-only)
66  | `PROP_DEV_CHANNEL_KEYS`       | Get, Set, Insert, Remove | Device identity channel keys
67  | `PROP_DEV_PEERS`              | Get, Set, Insert, Remove | Device identity peer list
68  | `PROP_DEV_NAME`               | Get, Set                 | Human-readable device name
69  | `PROP_BATTERY`                | Get, Is                  | Battery status snapshot
96  | `PROP_HOST_KEY`               | Get, Set                 | Tethered host identity public key
97  | `PROP_HOST_CHANNEL_KEYS`      | Get, Set, Insert, Remove | Host channel keys
98  | `PROP_HOST_PEER_KEYS`         | Get, Set, Insert, Remove | Host pairwise peer keys
99  | `PROP_HOST_RX_FILTERS`        | Get, Set, Insert, Remove | Host receive filter table
100 | `PROP_HOST_AUTO_ACK`          | Get, Set                 | Acknowledgement delegation enable
101 | `PROP_HOST_RX_QUEUE_COUNT`    | Get                      | Frames currently queued
102 | `PROP_HOST_RX_QUEUE_CAPACITY` | Get, Set                 | Queue capacity in frames
103 | `PROP_HOST_RX_QUEUE_DROPPED`  | Get                      | Frames dropped from the queue

### PROP 48: `PROP_MAC_PROMISCUOUS` {#prop-mac-promiscuous}

* Type: Single-Value, Read-Write, Session-Scoped
* Asynchronous Updates: No
* Required: `CAP_HOST_FILTER`
* Value Type: BOOL
* Post-Attach Value: 0 (false)

When true, every frame the PHY successfully receives is delivered to the
host over `STR_PHY_RAW`, bypassing receive filtering. This is a live-session
diagnostic mode: frames that are delivered *only* because of promiscuous
mode are never queued while the host is detached, and never acknowledged on
the host's behalf.

This is the only session-scoped property: it reverts to false on every
attach.

### PROP 49: `PROP_SAVED` {#prop-saved}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_SAVE`
* Value Type: BOOL

True if a saved snapshot exists in non-volatile storage (see
(#saved-state)) — that is, if the NCP is armed for autonomous operation
across a power cycle.

### PROP 64: `PROP_DEV_KEY` {#prop-dev-key}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_DEV_IDENTITY`
* Value Type: 32 octets, or empty
* Post-Reset Value: Persisted

The Ed25519 public key of the companion radio's **device identity**
(see (#identity-model)), or an empty value if no device identity is
configured. The public key is also emitted as the success response when the
private key is installed or generated (see (#prop-dev-private-key)).

Frames addressed to the device identity are processed by the NCP itself.
They are additionally delivered or queued to the host only if they
independently match the host's receive filtering (see (#receive-filtering)).

### PROP 65: `PROP_DEV_PRIVATE_KEY` {#prop-dev-private-key}

* Type: Single-Value, Write-Only
* Asynchronous Updates: No
* Required: `CAP_DEV_IDENTITY`
* Value Type: 32 octets, or empty
* Post-Reset Value: Persisted

Installs or generates the device identity private key:

* Setting a 32-octet value installs it as the device identity's Ed25519
  private key.
* Setting an **empty** value commands the NCP to generate a fresh private
  key entirely on-device from its cryptographically secure random number
  generator. On-device generation is **RECOMMENDED** over installation,
  since a generated key never exists anywhere but the radio.

In both cases, success is reported by emitting `CMD_PROP_IS` for
**`PROP_DEV_KEY`** — carrying the resulting *public* key — with the
command's TID. The private key itself is never emitted. Success **MUST NOT**
be reported before the new identity is in effect and durably stored.
Replacing an existing device identity is permitted; implementations
**SHOULD** treat the device identity's peer list and channel keys as
still valid, since they are not derived from the identity key.

This property is write-only: `CMD_PROP_GET` **MUST** fail with
`STATUS_UNIMPLEMENTED` and **MUST NOT** disclose the value or whether an
identity is configured (use `PROP_DEV_KEY` for that).

The device identity is **not** part of the saved snapshot (see
(#saved-state)): it is durably persisted as soon as it is installed or
generated, and it is changed only by another set of this property or by
`CMD_CLEAR`. `CMD_RESTORE` never reverts it.

Installing a private key is subject to the same transport security
requirements as all key provisioning (see (#provisioning-security)).

### PROP 66: `PROP_DEV_CHANNEL_KEYS` {#prop-dev-channel-keys}

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: No
* Asynchronous Updates: No
* Required: `CAP_DEV_IDENTITY`
* Item Form: 32 octets (the channel key)
* Digest Form: 2 octets (the derived channel identifier)
* Remove Selector: the 32-octet channel key
* Post-Reset Value: Empty, or restored from saved state

The set of [channel keys](multicast-channels.md#channel-keys) belonging to
the **device identity** — channels the radio's own node participates in
(for example, a site-infrastructure management channel). These are
independent of the host domain: they survive host replacement and are
distinct from `PROP_HOST_CHANNEL_KEYS`.

For each key the NCP derives the 2-byte
[channel identifier](packet-types.md#channel-identifier-derivation) and the
channel's `K_enc`/`K_mic`
(see [Multicast Packet Keys](security.md#multicast-packet-keys)). The
digest form reported for each entry is that derived channel identifier;
the key itself is never read back.

Device channel keys do **not** create implicit host receive filters:
frames on these channels are consumed by the device node and reach the
host only through the host's own filtering.

### PROP 67: `PROP_DEV_PEERS` {#prop-dev-peers}

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: No
* Asynchronous Updates: No
* Required: `CAP_DEV_IDENTITY`
* Item Form: 32 octets (the peer's Ed25519 public key)
* Digest Form: identical to the item form
* Remove Selector: the 32-octet public key
* Post-Reset Value: Empty, or restored from saved state

The **device identity's** peer list: the set of peer public keys the
device node recognizes and may communicate with securely. Because the NCP
holds the device identity's private key, it performs its own key agreement
([Unicast Key Agreement](security.md#unicast-key-agreement)) for these
peers — no symmetric keys are provisioned, and the entries contain no
secret material.

How the device node uses this list (management access control, secure
diagnostics, and so on) is application behavior outside the scope of this
protocol.

### PROP 68: `PROP_DEV_NAME` {#prop-dev-name}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_DEV_NAME`
* Value Type: 1–64 octets of UTF-8, without U+0000
* Post-Reset Value: Implementation-defined default, or restored from saved state

The operator-assigned, human-readable name of the physical companion-radio
device. It is independent of the device and host cryptographic identities and
**MUST NOT** be derived from a bonded host or other host-domain state.

Setting the property changes the live name immediately. Like other ordinary
device-domain configuration, it is included in a `CMD_SAVE` snapshot but is
not independently persisted merely by being set. Applications and transports
that present the device to a person **SHOULD** use this value when practical.
They **MAY** shorten it to fit a constrained presentation, but **MUST NOT**
split a UTF-8 code point when doing so.

The name is intentionally public metadata. Operators should assume that any
value used in discovery advertisements can be observed by nearby devices.

### PROP 69: `PROP_BATTERY` {#prop-battery}

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_BATTERY`
* Value Type: Battery status snapshot (see below), or empty
* Post-Reset Value: Current measurement, or empty if reporting is
  unsupported

An NCP advertising `CAP_BATTERY` has a battery capable of powering its
operation and recognizes this property. The capability does not require the
hardware to support reporting any measurement: an implementation that cannot
report battery status at all answers `CMD_PROP_GET` successfully with an
**empty value**.

A non-empty value is a snapshot of the battery measurements the platform
supports, taken as one measurement event:

Octets | Field
-------|--------------------------------------------------
1      | Field flags
0 or 2 | Battery voltage, UINT16_LE, millivolts
0 or 1 | Battery level, UINT8, percent (0–100)
0+     | Charge state, PUI

Bits 0 (voltage), 1 (level), and 2 (charge state) of the field flags octet
indicate which fields are present; present fields follow in the order above.
Bits 3–7 are reserved and **MUST** be zero; a host **MUST** treat a value
with a reserved bit set, or whose length does not match its field flags, as
malformed.

Which fields are reported is fixed for a given hardware and firmware
configuration: the field flags do not change while a session is attached. An
absent field indicates only that the implementation cannot report that
measurement. It **MUST NOT** be used to indicate a depleted, disconnected,
or temporarily unreadable battery: an implementation that normally reports a
field but cannot currently obtain a measurement fails the `CMD_PROP_GET`
with `STATUS_FAILURE` rather than omitting the field or returning an empty
value.

The value returned by `CMD_PROP_GET` reflects a measurement performed when
the request is serviced, not a previously cached reading; concurrent
requests **MAY** share one measurement. How each field is produced is
platform-defined — in particular, the level estimate is not necessarily
derived from the voltage measurement, and a platform with a fuel gauge may
report a level without reporting a voltage at all.

The fields:

**Battery voltage**
: The measured voltage at the battery terminals, in millivolts. This is the
  battery voltage, not an external-power input or regulated system voltage;
  it may therefore reflect the normal voltage elevation that occurs while
  the battery is charging.

**Battery level**
: The implementation's estimate of the battery's state of charge, as an
  integer percentage from 0 through 100 inclusive. A host **MUST NOT**
  derive this value from the voltage field or assume that successive
  estimates change monotonically.

**Charge state**
: The current battery charge state:

Value | Name
------|-------------------------------------
0     | `BATTERY_CHARGE_STATE_DISCHARGING`
1     | `BATTERY_CHARGE_STATE_CHARGING`
2     | `BATTERY_CHARGE_STATE_CHARGED`

`BATTERY_CHARGE_STATE_DISCHARGING`
: The charging system reports neither active charging nor charge completion.
  This is the charge state used for a disconnected battery when the
  implementation can detect that condition; an absent field remains reserved
  exclusively for unsupported reporting.

`BATTERY_CHARGE_STATE_CHARGING`
: The charging system reports that the battery is actively receiving charge.

`BATTERY_CHARGE_STATE_CHARGED`
: External power is present and the charging system reports that charging has
  completed. A battery at 100 percent while operating without external power
  remains in `BATTERY_CHARGE_STATE_DISCHARGING`.

The property contains live, read-only state. It is never included in a
saved snapshot and is not changed by `CMD_RESTORE`. An NCP **MAY** emit
unsolicited `CMD_PROP_IS` updates when the reported snapshot changes. Such
updates **SHOULD** be coalesced or rate-limited so that measurement noise
does not produce excessive companion traffic.

### PROP 96: `PROP_HOST_KEY` {#prop-host-key}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_HOST_FILTER`
* Value Type: 32 octets, or empty
* Post-Reset Value: Empty, or restored from saved state

The Ed25519 public key of the **tethered host identity**. Setting this
property tells the NCP which node identity it is assisting; an empty value
means no host identity is configured.

Setting this property to a value different from its current value resets
the entire host domain, durably, as specified in (#host-replacement).
Setting it to its current value is idempotent.

A configured host key acts as an implicit destination-hint receive filter
(see (#receive-filtering)).

### PROP 97: `PROP_HOST_CHANNEL_KEYS` {#prop-host-channel-keys}

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: No
* Asynchronous Updates: No
* Required: `CAP_HOST_KEYS`
* Item Form: 32 octets (the channel key)
* Digest Form: 2 octets (the derived channel identifier)
* Remove Selector: the 32-octet channel key
* Post-Reset Value: Empty, or restored from saved state

The set of [channel keys](multicast-channels.md#channel-keys) provisioned
for the **host identity**. For each key the NCP derives the channel
identifier and the channel `K_enc`/`K_mic`; the digest form is the derived
channel identifier, and the key itself is never read back.

Each derived channel identifier acts as an implicit channel receive filter
(see (#receive-filtering)). Host channel keys serve two assistance
purposes:

* recognizing multicast traffic on the host's channels while the host is
  detached, so it can be queued; and
* recognizing **blind unicast** traffic addressed to the host identity,
  which requires the channel key to decrypt the concealed
  destination/source addresses (see
  [Blind Unicast Processing](packet-types.md#blind-unicast-processing)) and
  to form the combined
  [blind unicast payload keys](security.md#blind-unicast-payload-keys) used
  for authentication and acknowledgement.

Channel keys are group-membership credentials, not host private keys, so
provisioning them is consistent with the
[security boundary](companion-radio.md#security-boundary). They still grant
whoever holds the NCP the ability to read and send traffic on those
channels; see (#provisioning-security).

### PROP 98: `PROP_HOST_PEER_KEYS` {#prop-host-peer-keys}

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: No
* Asynchronous Updates: No
* Required: `CAP_HOST_KEYS`
* Item Form: Structure, 64 octets
* Digest Form: 32 octets (the peer's public key)
* Remove Selector: the 32-octet peer public key
* Post-Reset Value: Empty, or restored from saved state

Pairwise symmetric key material provisioned for specific already-known
peers of the host identity. The item form is:

~~~
+---------------------+-----------+-----------+
| PEER_PUBLIC_KEY     |   K_ENC   |   K_MIC   |
+---------------------+-----------+-----------+
        32 B              16 B        16 B
~~~
Figure: Peer key entry item form

Where `PEER_PUBLIC_KEY` is the peer's Ed25519 public key and `K_ENC` and
`K_MIC` are the stable pairwise keys for the (host, peer) pair, derived by
the **host** as described in
[HKDF Inputs for Unicast](security.md#hkdf-inputs-for-unicast). The NCP
never derives these itself — it cannot, because it does not hold the host's
private key.

As an exception to the usual `CMD_PROP_INSERT` duplicate rule, inserting an
entry whose `PEER_PUBLIC_KEY` matches an existing entry replaces that
entry. Replacement updates only the stored key material: the peer's replay
baseline (see (#ack-delegation)) and any frames already queued from that
peer are unaffected, since both are keyed by the peer's identity rather
than by the key values. The digest form is the peer public key alone:
`K_ENC` and `K_MIC` are never read back.

Provisioned peer keys let the NCP authenticate inbound unicast and blind
unicast from those specific peers and acknowledge it on the host's behalf
(see (#ack-delegation)). They grant no capability regarding any other peer,
and do not allow the NCP to establish new pairwise relationships.

### PROP 99: `PROP_HOST_RX_FILTERS` {#prop-host-rx-filters}

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: Yes
* Asynchronous Updates: No
* Required: `CAP_HOST_FILTER`
* Item Form: Structure
* Digest Form: identical to the item form
* Remove Selector: the full item
* Post-Reset Value: Empty, or restored from saved state

The explicit receive filter table. Each item is a filter entry:

~~~
+-------------+----------------------+
| FILTER_TYPE | FILTER_VALUE ...
+-------------+----------------------+
     1 B          type-specific
~~~
Figure: Filter entry format

Type | Name                 | Value       | Matches
-----|----------------------|-------------|---------
0    | `FILTER_DEST_HINT`   | 3 octets    | Frames whose destination hint field equals the value
1    | `FILTER_CHANNEL_ID`  | 2 octets    | Channel-addressed frames (`MCST`, `BUNI`, `BUAR`) whose channel identifier equals the value
2    | `FILTER_PKT_TYPE`    | 1 octet     | Frames whose FCF packet-type field equals the value (0–7)

Entries with an unrecognized `FILTER_TYPE`, or whose value length does not
match the type, fail with `STATUS_INVALID_ARGUMENT`.

See (#receive-filtering) for how this table combines with the implicit
filters derived from `PROP_HOST_KEY` and `PROP_HOST_CHANNEL_KEYS`.

### PROP 100: `PROP_HOST_AUTO_ACK` {#prop-host-auto-ack}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_HOST_AUTO_ACK`
* Value Type: BOOL
* Post-Reset Value: 0 (false), or restored from saved state

When true, the NCP sends MAC acknowledgements on behalf of the host
identity for qualifying frames received while the host is detached, as
specified in (#ack-delegation). When false, the NCP never transmits on the
host identity's behalf.

### PROP 101: `PROP_HOST_RX_QUEUE_COUNT` {#prop-host-rx-queue-count}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_HOST_RX_QUEUE`
* Value Type: UINT16_LE
* Units: frames
* Post-Reset Value: 0

The number of frames currently held in the inbound queue. The host
typically reads this right after attaching to decide whether (and when) to
issue `CMD_QUEUE_DRAIN`.

### PROP 102: `PROP_HOST_RX_QUEUE_CAPACITY` {#prop-host-rx-queue-capacity}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_HOST_RX_QUEUE` (`CMD_PROP_SET` support is **OPTIONAL**)
* Value Type: UINT16_LE
* Units: frames
* Post-Reset Value: Implementation-Specific, or restored from saved state

The maximum number of frames the inbound queue can hold. NCPs with a fixed
queue size fail `CMD_PROP_SET` with `STATUS_UNIMPLEMENTED`; NCPs that allow
adjustment fail values they cannot honor with `STATUS_INVALID_ARGUMENT`.

### PROP 103: `PROP_HOST_RX_QUEUE_DROPPED` {#prop-host-rx-queue-dropped}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_HOST_RX_QUEUE`
* Value Type: UINT32_LE
* Units: frames
* Post-Reset Value: 0

The cumulative number of frames discarded from the inbound queue — evicted
by the circular queue-full policy or otherwise not retained (see
(#inbound-queueing)) — since the NCP last reset. A non-zero increase
across a detached interval tells the host that its view of that interval
is incomplete. The counter wraps modulo 2^32.

## Receive Filtering {#receive-filtering}

Receive filtering determines which successfully received frames are
**accepted** for the host — delivered live when the host is attached, or
queued when it is not.

The NCP evaluates each received frame against the union of:

* the **explicit filters** in `PROP_HOST_RX_FILTERS`;
* an **implicit destination-hint filter** for the first 3 bytes of
  `PROP_HOST_KEY`, when a host key is configured; and
* an **implicit channel filter** for the derived channel identifier of each
  key in `PROP_HOST_CHANNEL_KEYS`.

A frame matching any filter is accepted. Hints and channel identifiers are
prefilters, not proof (see [Addressing](addressing.md)); filtering by them
can only over-accept, never mis-reject, and the host performs full
cryptographic verification as usual.

The implicit destination-hint filter matches unicast traffic addressed to
the host identity and also [MAC Ack](packet-types.md#mac-ack-packet)
packets returning to it, since a MAC ack's `DST` field carries the same
3-byte public-key prefix. Encrypted blind unicast addressed to the host is
matched through its channel filter (its destination hint is concealed on
the wire); the NCP MAY additionally use a provisioned channel key to
decrypt the address block and narrow the match.

Traffic the implicit filters do not cover — broadcasts and beacons, for
example — must be requested explicitly (e.g., a `FILTER_PKT_TYPE` entry
with value 0). Device-domain state never creates implicit host filters:
frames for the device identity or its channels reach the host only if the
host's own filtering matches them.

**Compatibility rule:** when no host key is configured, no host channel
keys are provisioned, and the explicit filter table is empty, filtering is
considered unconfigured and **every** successfully received frame is
accepted. This is exactly the minimal protocol's behavior, so a host that
implements only the minimal protocol observes no difference on a
full-protocol NCP in its factory state. As soon as any filter (implicit or
explicit) exists, only matching frames are accepted.

Promiscuous mode (see (#prop-mac-promiscuous)) bypasses filtering for live
delivery only.

## Inbound Queueing {#inbound-queueing}

When `CAP_HOST_RX_QUEUE` is supported and the host is **detached**,
accepted frames are placed in a FIFO inbound queue instead of being
discarded. Each queue entry records the frame, its receive metadata (RSSI,
LQI, SNR), the time of reception, and whether the NCP acknowledged it (see
(#ack-delegation)).

When the host is **attached**, accepted frames are delivered live over
`STR_PHY_RAW` exactly as in the minimal protocol. Attaching does not flush
the queue: frames queued while the host was away remain queued until the
host issues `CMD_QUEUE_DRAIN` (see (#cmd-queue-drain)). Frames received
after attach are therefore delivered live even while older frames remain
queued, and live deliveries MAY interleave with buffered deliveries during
a drain (`RX_FLAG_BUFFERED` distinguishes them). A host that wants to
process the backlog first drains promptly after attaching and MAY defer
its processing of interleaved live deliveries; `RX_AGE` in the
buffered-frame metadata gives coarse (one-second) relative timing but is
not sufficient to reconstruct a strict total order — and UMSH itself does
not guarantee in-order delivery in any case.

The queue is **circular**: when a new frame is accepted and the queue is
full, the oldest queued frame is discarded and the new frame is appended.
The queue therefore always holds the most recent accepted traffic. Every
frame discarded by this eviction increments
`PROP_HOST_RX_QUEUE_DROPPED`.

Eviction can discard a frame that was already acknowledged on the host's
behalf — the sender believes it delivered, but the host will never
receive it. This is the same best-effort custody semantic that applies to
power loss (see (#ack-delegation) and (#saved-state)): a delegated ack
asserts volatile custody, not guaranteed delivery.

Duplicate detection for queueing uses the standard final-destination
mechanisms of [replay detection](security.md#replay-detection): per-peer
frame-counter state and the recent accepted-MIC cache used for the
backward window, where the NCP holds the keys to apply them. A frame
identified as a previously accepted frame **MUST NOT** consume an
additional queue slot; it is coalesced with the existing entry. A
[Route Retry](packet-options.md#route-retry-option-6) form of a queued
frame is the same logical packet (same MIC and frame counter) and
coalesces with it. Coalescing a duplicate is separate from acknowledging
it — a coalesced duplicate may still have its ack retransmitted under the
duplicate-acknowledgement window (see (#ack-delegation)). For frames the
NCP cannot authenticate (no provisioned keys), no protocol-defined
duplicate detection applies and each received frame occupies its own
entry.

### Buffered-Frame Metadata {#buffered-metadata}

The `Recv` metadata of `STR_PHY_RAW`
(see [Metadata for Recv](companion-radio-minimal.md#str-radio-raw)) is
extended with two trailing fields:

* `RX_FLAGS` (`u8`): Buffered-frame flags
  * `RX_FLAG_BUFFERED` Bit 0: The frame was held in the inbound queue and
    is being delivered by `CMD_QUEUE_DRAIN`.
  * `RX_FLAG_ACKED` Bit 1: The NCP already transmitted a MAC ack for this
    frame on the host's behalf. The host **MUST NOT** send another ack for
    it.
  * All other bits: *RESERVED*, transmitted as zero
* `RX_AGE` (`u32`, little-endian): Seconds elapsed between reception of the
  frame and its delivery to the host. Zero for live delivery.

As with the existing metadata fields, the metadata may be truncated at any
field boundary; absent fields are treated as zero. Live deliveries MAY
therefore continue to omit these fields entirely, which keeps the encoding
byte-compatible with the minimal protocol.

## Acknowledgement Delegation {#ack-delegation}

With `PROP_HOST_AUTO_ACK` enabled, the NCP acknowledges qualifying inbound
frames so that senders' retransmission logic is satisfied while the host is
away. The NCP **MUST** transmit a MAC ack for a received frame if and only
if all of the following hold:

1. `PROP_HOST_AUTO_ACK` is true and no host is attached.
2. The frame's packet type requests acknowledgement: `UNAR`, or `BUAR`
   where the NCP also holds the frame's channel key.
3. The frame is addressed to the host identity: its (possibly decrypted)
   destination hint matches `PROP_HOST_KEY`, and its source resolves to
   an entry in `PROP_HOST_PEER_KEYS` — by full public key when the `S`
   flag is set, or by unique 3-byte prefix match otherwise.
4. The frame authenticates: its MIC verifies under the pairwise `K_MIC`
   for `UNAR`, or under the combined
   [blind unicast payload keys](security.md#blind-unicast-payload-keys)
   for `BUAR`.
5. The frame is accepted as new by the
   [replay-detection rules](security.md#replay-detection), applied per
   provisioned peer. The NCP advances a peer's replay baseline only when
   it accepts a frame from that peer into the queue; a frame it fails to
   store leaves the baseline unchanged, so its retransmissions remain
   acceptable later.
6. The frame was placed in the inbound queue (see (#inbound-queueing)).
   Because the queue is circular, placement normally succeeds by evicting
   the oldest entry when full; a frame that nevertheless cannot be stored
   (for example, one exceeding the NCP's buffer) is not acknowledged, so
   the sender keeps retrying until the host returns.

**Duplicates.** An authenticated frame that replay detection identifies as
a previously accepted frame — typically a retransmission whose original
ack was lost — is not queued again, but the NCP **MAY** retransmit its
acknowledgement under the core
[duplicate-acknowledgement window](security.md#duplicate-acknowledgement-window):
only when the frame authenticates and its counter is no more than 8 behind
the peer's baseline, and without advancing or otherwise modifying the
replay baseline. Re-acknowledging a duplicate is independent of queue
coalescing (see (#inbound-queueing)) and does not mark anything newly
accepted. Frames farther behind the baseline **MUST NOT** be acknowledged.

**Reboot.** Per-peer replay baselines are not saved (see (#saved-state)).
After an NCP reset, the first authenticated frame accepted from a
provisioned peer re-establishes that peer's baseline at face value,
exactly as on first contact (see
[Counter Resynchronization](security.md#counter-resynchronization)). The
consequence is that after a reboot, previously captured authenticated
frames may be accepted, queued, and acknowledged if replayed in a counter
sequence acceptable from the newly established baseline. The host MAC
remains authoritative for duplicate suppression when the frames are
eventually delivered, so this creates a limited availability and
resource-consumption window (queue slots and delegated acks), but it does
not permit forgery or duplicate application delivery. Implementations
concerned about this threat **MAY** persist a compact per-peer counter
watermark (batched or range-reserved to limit flash wear), but hosts
**MUST NOT** assume they do.

**Custody.** A delegated ack acknowledges *volatile* custody by default:
the frame is held in RAM until drained, and the loss window on power
failure is documented in (#saved-state). Implementations that persist the
queue provide durable custody, but hosts and application protocols
**MUST NOT** rely on it.

The acknowledgement is an ordinary
[MAC Ack packet](packet-types.md#mac-ack-packet): `DST` is the first 3
bytes of the peer's public key, and the 8-byte ack tag is computed as
specified in [Ack Tag Construction](security.md#ack-tag-construction),
using the provisioned pairwise keys (combined with the channel keys for
`BUAR`). If the original frame carried a flood hop count, the ack's
`FHOPS_REM` is initialized from the original frame's `FHOPS_ACC`.

Delegated ack transmissions use the NCP's normal transmit path and are
subject to the configured duty-cycle limit; the NCP **MUST NOT** exceed the
limit to send an ack. An ack that cannot be sent leaves the queued frame
marked unacknowledged.

Frames that are accepted but fail any of conditions 2–5 — no peer key, no
channel key, authentication impossible to evaluate — are still queued
(subject to filtering); they are simply not acknowledged. The host
performs its own verification after draining and may ack late if the
application finds that useful.

While a host is attached, the NCP never acks on its behalf: live-delivered
frames are the host's responsibility. Acks generated by the **device
identity** for its own traffic are ordinary device-node behavior and are
not governed by this section.

## Provisioning Security {#provisioning-security}

Provisioning moves real key material onto the NCP, within the limits of the
[security boundary](companion-radio.md#security-boundary): channel keys and
per-peer symmetric keys — and the device identity's own private key —
but never the host's private key. The rules:

* **All symmetric key material, and the device identity private key, is
  write-only.** `CMD_PROP_GET` and all NCP-emitted notifications report
  key-bearing properties in their digest forms
  (see (#multi-value-properties)): peer public keys without `K_ENC`/`K_MIC`,
  derived channel identifiers instead of channel keys, and never the
  device private key. This holds for **both** identities' key tables.
  Digest forms let the host verify *what* is provisioned after a
  reconnect without any secret ever crossing the link a second time —
  which matters because more than one host may be able to attach over the
  radio's lifetime (transport bonds are possession credentials, not
  identity credentials), and a later host must not be able to extract an
  earlier host's keys.
* Commands that carry key material — `CMD_PROP_SET` and `CMD_PROP_INSERT`
  for the key tables, and any set of `PROP_DEV_PRIVATE_KEY` — **MUST NOT**
  be carried over a transport that does not meet the requirements of the
  transport's security binding: physical possession for serial transports,
  or an encrypted bonded LESC link as specified in
  [Companion Radio over BLE](companion-radio-ble.md#ble-security).
* A compromised or stolen NCP exposes the provisioned channels, the
  provisioned pairwise conversations, and its own device identity, but
  cannot impersonate the host to any new peer, cannot sign as the host,
  and cannot decrypt traffic for peers or channels that were never
  provisioned.
* Hosts **SHOULD** provision the minimum useful set of peers and channels,
  **SHOULD** remove entries that are no longer needed, and **SHOULD**
  prefer on-device generation of the device identity over installing one.
* An NCP advertising `CAP_SAVE` **MUST** store persisted key material in
  the most protected storage available to it.

## Additional Status Codes

The full protocol assigns two additional status codes
(see [Status Codes](companion-radio-minimal.md#status-codes)):

Id | Name
---|----------------------------------
19 | `STATUS_ALREADY`
20 | `STATUS_ITEM_NOT_FOUND`

`STATUS_ALREADY`
: The requested state is already in effect; in particular, the item passed
  to `CMD_PROP_INSERT` is already present in the property.

`STATUS_ITEM_NOT_FOUND`
: The item or selector passed to `CMD_PROP_REMOVE` does not match any item
  in the property.

## Additional Reset Codes {#full-reset-codes}

The full protocol assigns one additional reset code
(see [Reset Codes](companion-radio-minimal.md#reset-codes)):

Id  | Name
----|------------------------
115 | `STATUS_RESET_RESTORED`

`STATUS_RESET_RESTORED`
: Protocol reset into the saved snapshot, emitted when an NCP completes
  `CMD_RESTORE` in its reset form (see (#cmd-restore)). Unlike the other
  reset codes, this one does not indicate a hardware or firmware restart:
  the transport link and attach state survive it. Like
  `STATUS_RESET_SOFTWARE`, it is emitted during normal operation and does
  not indicate a problem.

## Additional Capabilities {#full-capabilities}

The full protocol assigns the following capability codes
(see [Capabilities](companion-radio-minimal.md#capabilities)):

Code | Name                | Requires          | Grants
-----|---------------------|-------------------|--------
32   | `CAP_HOST_FILTER`   | —                 | `PROP_HOST_KEY`, `PROP_MAC_PROMISCUOUS`, `PROP_HOST_RX_FILTERS`, and the receive-filtering behavior
33   | `CAP_HOST_RX_QUEUE` | `CAP_HOST_FILTER` | The inbound queue, its properties, `CMD_QUEUE_DRAIN`, and the buffered-frame metadata
34   | `CAP_HOST_KEYS`     | `CAP_HOST_FILTER` | `PROP_HOST_CHANNEL_KEYS` and `PROP_HOST_PEER_KEYS`
35   | `CAP_HOST_AUTO_ACK` | `CAP_HOST_KEYS`, `CAP_HOST_RX_QUEUE` | `PROP_HOST_AUTO_ACK` and acknowledgement delegation
36   | `CAP_SAVE`          | —                 | `CMD_SAVE`, `CMD_RESTORE`, `PROP_SAVED`, and boot-time restoration of saved state
37   | `CAP_DEV_IDENTITY`  | —                 | The device identity: `PROP_DEV_KEY`, `PROP_DEV_PRIVATE_KEY`, `PROP_DEV_CHANNEL_KEYS`, `PROP_DEV_PEERS`
38   | `CAP_DEV_NAME`      | —                 | `PROP_DEV_NAME`
39   | `CAP_BATTERY`       | —                 | Battery-powered operation and `PROP_BATTERY`

An NCP **MUST NOT** advertise a capability without also advertising the
capabilities it requires. `CMD_PROP_INSERT`/`CMD_PROP_REMOVE`, `CMD_CLEAR`,
and the two additional status codes are part of the base protocol and need
no capability; an NCP that defines no mutable multi-value properties simply
has nothing to apply them to.
