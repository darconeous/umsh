# ULCP: Device Domain

The device domain is everything that belongs to the radio itself: its own
node identity, the settings that make it behave the way its operator
commissioned it, and the telemetry it can report about its own hardware.
None of it is keyed by the attached host, and none of it is disturbed when
one host replaces another (see
[State Classes](ulcp-core.md#state-classes)).

Commissioning a repeater is exactly this: writing device-domain state and
saving it. It is also the reason a host that is merely *administering* a
device writes nothing in the
[host domain](ulcp-host.md) — see
[Two Kinds of Attach](ulcp.md#attach-relationships).

## The Device Identity {#device-identity}

The device hosts a node belonging to the device itself, used for in-band
management, diagnostics, repeater forwarding (see
[`PROP_MAC_REPEATER_ENABLED`](ulcp-device.md#prop-mac-repeater-enabled)),
and (in future revisions) periodic advertisement behavior. Its Ed25519
private key is held by the device and is never readable through this
protocol.

**A device identity always exists.** A device advertising
`CAP_DEV_IDENTITY` that finds no stored keypair at power-on **MUST**
generate one from a cryptographic random source and persist it before
processing any host command; `PROP_DEV_KEY` therefore never reports an
empty value on a running device. Provisioning an identity is not a
commissioning step: a factory-fresh radio is already a node, and
[`PROP_DEV_PRIVATE_KEY`](ulcp-device.md#prop-dev-private-key) exists to install
a *particular* identity — restoring a known repeater onto replacement
hardware — not to bring one into being.

The corollary is that a radio holds a throwaway identity from first
power-on until a specific one is installed. This is safe because it never
reaches the air: `PROP_PHY_ENABLED` is false post-reset, and a radio with
nothing saved boots with the PHY disabled. It is not safe automatically on
the restore path — see [`CMD_RESTORE`](ulcp-saved-state.md#cmd-restore).

Because the device holds this identity's private key, it performs its own
key agreement and needs only peer *public* keys (see [`PROP_DEV_PEERS`](ulcp-device.md#prop-dev-peers)).
That is the opposite of the host identity, for which the device holds no
private key and every pairwise key must be provisioned explicitly (see
[Tethered Host Services](ulcp-host.md)).

## Capabilities

Code | Name               | Requires           | Grants
-----|--------------------|--------------------|--------
37   | `CAP_DEV_IDENTITY` | —                  | The device identity: `PROP_DEV_KEY`, `PROP_DEV_PRIVATE_KEY`, `PROP_DEV_CHANNEL_KEYS`, `PROP_DEV_PEERS`
38   | `CAP_DEV_NAME`     | —                  | `PROP_DEV_NAME`
39   | `CAP_BATTERY`      | —                  | Battery-powered operation and `PROP_BATTERY`
40   | `CAP_REPEATER`     | `CAP_DEV_IDENTITY` | Autonomous repeater forwarding by the device identity: `PROP_MAC_REPEATER_ENABLED`, `PROP_MAC_REPEATER_REGIONS`, `PROP_MAC_REPEATER_DEFAULT_REGION`, `PROP_MAC_REPEATER_MIN_RSSI`, `PROP_MAC_REPEATER_MIN_SNR`
41   | `CAP_IDENT`        | `CAP_DEV_IDENTITY` | `PROP_IDENT`, `PROP_IDENT_ROLE`, `PROP_IDENT_MOBILE` — serving and configuring the device identity's advertised node identity
42   | `CAP_ALERT`        | —                  | Some means of making the device physically conspicuous on demand, and `PROP_ALERT`
44   | `CAP_TIME`         | —                  | A wall clock: `PROP_TIME`, `PROP_TZ_OFFSET`
45   | `CAP_GNSS`         | `CAP_TIME`         | A GNSS receiver: `PROP_GNSS_ENABLED`, `PROP_GNSS_LOCATION`, `PROP_GNSS_ALTITUDE`, `PROP_GNSS_FIX`, `PROP_GNSS_PRECISION`, `PROP_GNSS_SATELLITES`, `PROP_GNSS_IDENT_UPDATE`, `PROP_GNSS_IDENT_PRECISION`, `PROP_GNSS_TIME_TRUST`
46   | `CAP_ADVERT`       | `CAP_DEV_IDENTITY` | Announcing itself on a schedule of its own: `PROP_ADVERT_INTERVAL`, `PROP_BEACON_INTERVAL`, `PROP_STARTUP_BEACON`

`CAP_ADVERT` requires `CAP_DEV_IDENTITY` because what a scheduled
advertisement carries *is* the device identity, and a beacon's source
address names it.

`CAP_TIME` states that the device keeps a wall clock and nothing else. It
says nothing about where the time comes from, how accurate it is, or how
much of a power cycle it survives — a device that has one and does not
currently know what time it is is a normal state, reported by the empty
[`PROP_TIME`](ulcp-device.md#prop-time).

`CAP_GNSS` requires `CAP_TIME` because a receiver is, among other things,
a clock: a device advertising one without the other would be claiming a
time source for a clock it does not have.

## Properties

The device domain occupies property identifiers 64–95. Identifiers 70–95
are the device-behavior range: 70–78 are the repeater policy and
advertised node identity settings, 79 is the locate alert, 80–87 are the
advertisement policy — 80–82 allocated, 83–87 reserved — and 88–95 are
positioning: 88 the receiver switch, 89–93 the fix telemetry, 94–95
reserved.

A single-octet identifier is the scarce resource, so the positioning
range holds the properties a host reads and the device announces
continually. The positioning **configuration** — which is written during
commissioning and rarely again — lives at 4868–4870 in the extended
device range, alongside the wall clock at 4866–4867.

Id | Mnemonic                    | Commands                 | Description
---|-----------------------------|--------------------------|-------------
64 | `PROP_DEV_KEY`              | Get                      | Device identity public key
65 | `PROP_DEV_PRIVATE_KEY`      | Set                      | Device identity private key (write-only)
66 | `PROP_DEV_CHANNEL_KEYS`     | Get, Set, Insert, Remove | Device identity channel keys
67 | `PROP_DEV_PEERS`            | Get, Set, Insert, Remove | Device identity peer list
68 | `PROP_DEV_NAME`             | Get, Set                 | Human-readable device name
69 | `PROP_BATTERY`              | Get, Is                  | Battery status snapshot
70 | `PROP_MAC_REPEATER_ENABLED` | Get, Set                 | Autonomous repeater forwarding enable
71 | `PROP_IDENT`                | Get                      | Signed node identity of the device identity
72 | `PROP_IDENT_ROLE`           | Get, Set                 | Advertised node role, or empty to derive it
73 | `PROP_IDENT_MOBILE`         | Get, Set                 | Advertise the mobile capability bit
74 | `PROP_MAC_REPEATER_REGIONS` | Get, Set                | Region codes the device forwards for
75 | `PROP_MAC_REPEATER_DEFAULT_REGION` | Get, Set         | Region code inserted into untagged flood packets
76 | `PROP_MAC_REPEATER_MIN_RSSI` | Get, Set                | Minimum received RSSI for flood forwarding
77 | `PROP_MAC_REPEATER_MIN_SNR` | Get, Set                 | Minimum received SNR for flood forwarding
78 | `PROP_DEV_DISCOVERABLE`     | Get, Set                 | Whether the device identity answers Identity Requests
79 | `PROP_ALERT`                | Get, Set, Is             | Locate alert state
80 | `PROP_ADVERT_INTERVAL`      | Get, Set                 | Seconds between unsolicited advertisements
81 | `PROP_BEACON_INTERVAL`      | Get, Set                 | Seconds between unsolicited beacons
82 | `PROP_STARTUP_BEACON`       | Get, Set                 | Whether a beacon goes out at bring-up
88 | `PROP_GNSS_ENABLED`         | Get, Set                 | Whether the GNSS receiver is powered
89 | `PROP_GNSS_LOCATION`        | Get, Is                  | Position of the last fix
90 | `PROP_GNSS_ALTITUDE`        | Get                      | Altitude of the last fix
91 | `PROP_GNSS_FIX`             | Get, Is                  | Fix quality
92 | `PROP_GNSS_PRECISION`       | Get                      | Estimated horizontal accuracy of the last fix
93 | `PROP_GNSS_SATELLITES`      | Get                      | Satellites used, and optionally in view
4866 | `PROP_TIME`               | Get, Set, Is             | Wall clock, or empty when unknown
4867 | `PROP_TZ_OFFSET`          | Get, Set                 | Local time-zone offset from UTC
4868 | `PROP_GNSS_IDENT_UPDATE`  | Get, Set                 | Whether fixes update the advertised node identity
4869 | `PROP_GNSS_IDENT_PRECISION` | Get, Set               | Precision the advertised location is clamped to
4870 | `PROP_GNSS_TIME_TRUST`    | Get, Set                 | Whether receiver-derived time may set the clock

The RF configuration is also device-domain state, but is specified in
[Radio Control](ulcp-radio.md); so is the transport configuration in
[ULCP over BLE](ulcp-ble.md).

### PROP 64: `PROP_DEV_KEY` {#prop-dev-key}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_DEV_IDENTITY`
* Value Type: 32 octets, or empty
* Post-Reset Value: Persisted

The Ed25519 public key of the **device identity**
(see [The Device Identity](ulcp-device.md#device-identity)). The public key is also emitted as the success
response when the private key is installed or generated (see
[`PROP_DEV_PRIVATE_KEY`](ulcp-device.md#prop-dev-private-key)).

An empty value means the device has no device identity. A conforming device does
not report one in normal operation — an identity is generated at first
boot if none is stored — so hosts **SHOULD** treat an empty value as a
fault to surface rather than as an invitation to provision one.

Frames addressed to the device identity are processed by the device itself.
They are additionally delivered or queued to the host only if they
independently match the host's receive filtering (see [Receive Filtering](ulcp-host.md#receive-filtering)).

### PROP 65: `PROP_DEV_PRIVATE_KEY` {#prop-dev-private-key}

* Type: Single-Value, Write-Only
* Asynchronous Updates: No
* Required: `CAP_DEV_IDENTITY`
* Value Type: 32 octets, or empty
* Post-Reset Value: Persisted

Installs or generates the device identity private key. An identity always
exists already (see [The Device Identity](ulcp-device.md#device-identity)), so both forms **replace** one:

* Setting a 32-octet value installs it as the device identity's Ed25519
  private key. This is the recovery path — moving a known repeater's
  identity onto replacement hardware — not a commissioning step.
* Setting an **empty** value commands the device to generate a fresh private
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
[Saved State](ulcp-saved-state.md#saved-state)): it is durably persisted as soon as it is installed or
generated, and it is changed only by another set of this property or by
`CMD_CLEAR`. `CMD_RESTORE` never reverts it — though it does read the
identity a snapshot was taken under, and refuses to enable the PHY when
it does not match (see [`CMD_RESTORE`](ulcp-saved-state.md#cmd-restore)).

Replacing the identity takes effect for the property surface immediately
and for anything the device built around the old key at the next boot. The
old key stops being one the device claims at once, so a device running a
device node **MUST** stop originating traffic under it rather than
continue until the reboot.

Installing a private key is subject to the same transport security
requirements as all key provisioning (see [Provisioning Security](ulcp-core.md#provisioning-security)).

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

For each key the device derives the 2-byte
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
* Remove Selector: the 32-octet public key
* Post-Reset Value: Empty, or restored from saved state

The **device identity's** peer list: the set of peer public keys the
device node recognizes and may communicate with securely. Because the device
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

The operator-assigned, human-readable name of the physical
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

A device advertising `CAP_BATTERY` has a battery capable of powering its
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

Which fields a platform can report is fixed for a given hardware and firmware
configuration; an individual snapshot carries those it can currently
substantiate. A field is absent either because the implementation never
reports that measurement, or because the value is not derivable in the
device's present state — a level estimated from resting terminal voltage is
not obtainable while the pack is charging, and a charger that reports no
completion signal offers no moment at which to recalibrate one. An
implementation **MUST NOT** report a value it knows to be unreliable in place
of omitting the field.

Absence **MUST NOT** be used to indicate a depleted or disconnected battery,
and it is not how a failed measurement is reported: an implementation whose
attempt to take a reading fails answers `CMD_PROP_GET` with `STATUS_FAILURE`.

A host **MUST** treat an absent field as unknown at that instant, and **MUST
NOT** carry a value forward from an earlier snapshot in its place.

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
  implementation can detect that condition; an absent field never carries
  that meaning.

`BATTERY_CHARGE_STATE_CHARGING`
: The charging system reports that the battery is actively receiving charge.

`BATTERY_CHARGE_STATE_CHARGED`
: External power is present and the charging system reports that charging has
  completed. A battery at 100 percent while operating without external power
  remains in `BATTERY_CHARGE_STATE_DISCHARGING`.

The property contains live, read-only state. It is never included in a
saved snapshot and is not changed by `CMD_RESTORE`. A device **MAY** emit
unsolicited `CMD_PROP_IS` updates when the reported snapshot changes. Such
updates **SHOULD** be coalesced or rate-limited so that measurement noise
does not produce excessive ULCP traffic.

### PROP 70: `PROP_MAC_REPEATER_ENABLED` {#prop-mac-repeater-enabled}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_REPEATER`
* Value Type: BOOL
* Post-Reset Value: Persisted

The first of the device-behavior settings (property identifiers 70–78),
and the master switch for the repeater policy in
`PROP_MAC_REPEATER_REGIONS`, `PROP_MAC_REPEATER_DEFAULT_REGION`,
`PROP_MAC_REPEATER_MIN_RSSI`, and `PROP_MAC_REPEATER_MIN_SNR`, which are
configurable while forwarding is disabled and take effect when it is
enabled. When true, the **device identity** acts as an
autonomous mesh repeater: its on-board node forwards overheard routable
frames according to [Repeater Operation](repeater-operation.md), and it
sets the repeater capability bit in its [node
identity](node-identity.md). When false, the device identity does not
forward and the bit is clear.

The capability bit is a statement of fact and **MUST** track the live
forwarding state. The advertised *role* is a separate matter: it is
configuration, set through [`PROP_IDENT_ROLE`](ulcp-device.md#prop-ident-role),
and defaults to being derived from this flag rather than being fixed by
it. A mobile repeater and a fixed tracker are both expressible.

This property governs only the *forwarding behavior* of the device
identity. It is independent of `PROP_MAC_PROMISCUOUS` (a session-scoped
host-delivery mode) and of the host identity, which never forwards.

The flag is device-domain state: it is part of the saved snapshot, so a
`CMD_SAVE` arms an unattended repeater across power cycles, and it
survives a change of host.

Flood-contention tuning — the forwarding delay window, deferral count,
and similar timing parameters — is not exposed; a repeater applies its
local defaults.

### PROP 71: `PROP_IDENT` {#prop-ident}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_IDENT`
* Value Type: Signed node-identity payload

The device identity's complete signed [node
identity](node-identity.md): the canonical payload encoding — role,
capabilities, and the descriptive options the device advertises —
followed by its 64-octet detached EdDSA signature over that encoding.

This is the same statement the device makes over the air, in its
standalone framing. A device **MUST** build it from the same values it
would advertise in an Identity Request response, so a host reading it
locally and a peer hearing it on the mesh cannot disagree about what the
device is. It differs from that response in exactly two ways, both
structural: it carries no request nonce, and it is authenticated by the
signature rather than by an enclosing authenticated unicast.

The contents are nonce-free and timestamp-free, so the value is a
function of the device's configuration alone. A device **MAY** cache it,
but is not required to: reading this property is an operator-scale
event.

### PROP 72: `PROP_IDENT_ROLE` {#prop-ident-role}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_IDENT`
* Value Type: UINT8, or empty
* Post-Reset Value: Empty, or restored from saved state

The `ROLE` byte the device identity advertises (see [Node
Primary Role](node-identity.md#node-primary-role)).

An **empty** value — the factory default — means the device derives the
role from what it is actually doing: `Repeater` while
`PROP_MAC_REPEATER_ENABLED` is set, `Tracker` otherwise. Any other value
is advertised verbatim.

Role and forwarding are deliberately separate. Forwarding is a fact,
reported through the repeater capability bit; the role is how the device
presents itself, which is the operator's choice. Deriving it by default
keeps the common cases right without a configuration step, and setting
it explicitly expresses the ones derivation cannot reach — a repeater
that is also mobile, a fixed node that is not a repeater.

**Tethering does not appear here, or anywhere in a node identity.**
Whether some host is currently attached over the local control link is a
transient local relationship, not a durable characteristic of the node,
and the mesh has no business knowing it.

### PROP 73: `PROP_IDENT_MOBILE` {#prop-ident-mobile}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_IDENT`
* Value Type: BOOL
* Post-Reset Value: 0 (false), or restored from saved state

Whether the device identity advertises the mobile capability bit: true
for a device that moves, false for one installed in a fixed location.

Orthogonal to `PROP_IDENT_ROLE` and to `PROP_MAC_REPEATER_ENABLED`, and
orthogonal to whether a host is tethered. A hand-carried repeater and a
pole-mounted sensor are both ordinary configurations.

### PROP 74: `PROP_MAC_REPEATER_REGIONS` {#prop-mac-repeater-regions}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_REPEATER`
* Value Type: Concatenated 2-octet [region codes](packet-options.md#region-code-encoding)
* Post-Reset Value: Empty, or restored from saved state

The set of regions the device identity flood-forwards for, as the codes
themselves concatenated with no delimiter — byte-for-byte the encoding of
the [Supported Regions](node-identity.md#supported-regions-option-4)
identity option. The value length is therefore always even; a device
**MUST** reject an odd-length write with `STATUS_INVALID_ARGUMENT`, and
**MAY** reject a write that exceeds the number of entries it can hold.

The list is the filter applied at the region-policy step of the [forwarding
procedure](repeater-operation.md#forwarding-procedure): a flood packet
carrying region codes is forwarded only if at least one of them appears
here. An **empty** list — the factory default — imposes no regional
restriction, so a tagged packet is forwarded whatever its region.

A device with forwarding enabled and a non-empty list **SHOULD** advertise
the same codes in its node identity, so that a peer choosing a route can
see what a repeater will carry. A device that is not forwarding makes no
such claim and omits the option.

Whether an untagged packet is tagged on the way out is a separate
decision, governed by `PROP_MAC_REPEATER_DEFAULT_REGION`.

### PROP 75: `PROP_MAC_REPEATER_DEFAULT_REGION` {#prop-mac-repeater-default-region}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_REPEATER`
* Value Type: One 2-octet [region code](packet-options.md#region-code-encoding), or empty
* Post-Reset Value: Empty, or restored from saved state

The region code the device inserts into a flood packet that carries none,
as permitted at the region-policy step of the [forwarding
procedure](repeater-operation.md#forwarding-procedure). An **empty**
value — the factory default — means the device never tags: untagged
packets are forwarded untagged. Any other value **MUST** be exactly two
octets; a device rejects other lengths with `STATUS_INVALID_ARGUMENT`.

Tagging is opt-in because it is a claim about where the packet is, not
merely about where the repeater is willing to forward. A repeater that
filters on a region list without asserting one leaves the decision to
whoever originated the packet.

The configured code **SHOULD** be one of the codes in
`PROP_MAC_REPEATER_REGIONS` when that list is non-empty, so that the
repeater will itself forward what it tags. A device does not enforce this
across the two writes, and the two properties may be set in either order.

Only untagged packets are affected: an already-tagged packet is forwarded
with its codes unchanged, and a second code is never added.

### PROP 76: `PROP_MAC_REPEATER_MIN_RSSI` {#prop-mac-repeater-min-rssi}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_REPEATER`
* Value Type: INT16 in dBm, or empty
* Post-Reset Value: Empty, or restored from saved state

The weakest signal the device will flood-forward, in dBm. An **empty**
value — the factory default — imposes no threshold. Any other value
**MUST** be exactly two octets.

The threshold is the repeater's half of step 7 of the [forwarding
procedure](repeater-operation.md#forwarding-procedure): where the packet
also carries a minimum, the higher of the two applies. Raising it trades
reach for a quieter mesh, which is what a dense deployment wants from a
repeater sitting at the edge of everyone's range.

Applies to flood forwarding only. Source-routed packets are forwarded on
the strength of the route, not the link.

### PROP 77: `PROP_MAC_REPEATER_MIN_SNR` {#prop-mac-repeater-min-snr}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_REPEATER`
* Value Type: INT8 in whole dB, or empty
* Post-Reset Value: Empty, or restored from saved state

The lowest signal-to-noise ratio the device will flood-forward, in whole
dB. An **empty** value — the factory default — imposes no threshold. Any
other value **MUST** be exactly one octet.

The threshold is the repeater's half of step 8 of the [forwarding
procedure](repeater-operation.md#forwarding-procedure), combined with any
packet-imposed minimum the same way `PROP_MAC_REPEATER_MIN_RSSI` is. On
spreading factors that decode well below the noise floor, this is the
more meaningful of the two thresholds.

Applies to flood forwarding only.

### PROP 78: `PROP_DEV_DISCOVERABLE` {#prop-dev-discoverable}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_DEV_IDENTITY`
* Value Type: BOOL
* Post-Reset Value: 1 (true), or restored from saved state

Whether the device identity answers [Identity
Requests](mac-commands.md#identity-request-command-1) addressed to it,
including broadcast solicitations whose filters select it. When false,
the device identity ignores every Identity Request.

Discoverability defaults on: a deployed device is infrastructure, and
being askable is most of what makes it administrable in the field. The
property is the opt-out for deployments where the device should not
volunteer its identity to arbitrary nearby askers.

Affects only Identity Request responses. Unsolicited advertisements and
beacons are governed by the [advertisement
policy](#prop-advert-interval), and the device's participation in
forwarding by `PROP_MAC_REPEATER_ENABLED`; neither is changed by this
property. A device that is not discoverable still advertises on its own
schedule if it has one — declining to answer strangers and declining to
speak are different decisions.

### PROP 79: `PROP_ALERT` {#prop-alert}

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_ALERT`
* Value Type: PUI
* Post-Reset Value: 0 (`ALERT_NONE`)

What the device is currently doing to draw a person's attention to where
it physically is. A radio that has been set down in the wrong place is
found by making it announce itself.

Value | Name
------|----------------
0     | `ALERT_NONE`
1     | `ALERT_LOCATE`

`ALERT_NONE`
: The nominal state. The device draws no attention to itself beyond
  whatever its ordinary operation involves.

`ALERT_LOCATE`
: The device makes itself as conspicuous as its hardware allows, and
  keeps doing so until the alert is cleared.

Values other than these are rejected with `STATUS_INVALID_ARGUMENT`.

**The presentation is board-defined.** The property carries intent, not
presentation: a device with a buzzer sounds it, a device with only an
indicator LED flashes it, a device with a display can say so on the
screen. `CAP_ALERT` states that the device has *some* means of making
itself conspicuous and nothing more, so a host **MUST NOT** assume that
an alert is audible, or that two devices alert alike. Because the alert
runs unattended on a device that may already be low, it is expected to be
intermittent rather than continuous, and it does not defer or inhibit a
protective shutdown.

**The alert overrides local quiet settings.** A device whose buzzer has
been silenced through a local control still sounds `ALERT_LOCATE`:
locating a misplaced radio is precisely the case that silencing must not
defeat. The alert *suspends* the local setting rather than changing it,
so clearing the alert leaves the device as quiet as it was before.

A device returns to `ALERT_NONE` three ways:

1. The host writes `ALERT_NONE`.
2. Local user input cancels it. A device with any user input at all
   **MUST** offer a way to cancel an alert from the device itself —
   whoever finds the radio is rarely holding the phone that set it off.
   The input that cancels performs none of its other functions, so that
   fumbling for a beeping radio cannot change its configuration; a
   deliberate gesture such as hold-to-power-off **MAY** remain
   reachable while an alert is active.
3. The deadline expires. A device **MUST** bound how long it will remain
   in `ALERT_LOCATE`; a few minutes is **RECOMMENDED**. Writing
   `ALERT_LOCATE` while it is already in effect succeeds and restarts the
   deadline, which is how a host holds an alert open for a longer search.

### PROP 80: `PROP_ADVERT_INTERVAL` {#prop-advert-interval}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_ADVERT`
* Value Type: UINT32
* Post-Reset Value: 14400 (four hours), or restored from saved state

Seconds between unsolicited [advertisements](beacons.md) — broadcasts
carrying the device's signed [node identity](node-identity.md). Zero
sends none.

An automatic advertisement is sent with no flood hops and no source
route, so it reaches the nodes that can hear the device directly and
stops there. It is the largest frame the device originates, and what it
carries is a standing statement rather than news; repeating that
statement across the whole mesh every interval would spend airtime out
of all proportion to what a distant listener learns. A device that wants
to be findable further away publishes a path with
[`PROP_BEACON_INTERVAL`](#prop-beacon-interval) instead, which costs a
fraction as much.

Because the advertisement is a signed broadcast, it carries its source
in full-key form (§[Node Identity](node-identity.md)).

A device **MUST** reject a non-zero interval outside 1200 seconds
(twenty minutes) to 86400 seconds (twenty-four hours) with
`STATUS_INVALID_ARGUMENT`. Neither bound is an airtime control — the
[duty limit](ulcp-radio.md#prop-phy-duty-limit) is that — but the two
ends fail differently. Below the floor a device spends the mesh's
airtime restating what it already said; above the ceiling the schedule
has stopped being one, and zero says so more plainly.

The interval is a minimum rather than an exact cadence: each period is
[scattered](beacons.md#announcing-on-a-schedule) later by a random
fraction of it, never earlier, so the configured value is the shortest
gap between two unsolicited announcements.

Scheduled sends are subject to the same duty accounting and channel
access as any other transmission: a send the device cannot make when it
falls due is skipped, not queued.

### PROP 81: `PROP_BEACON_INTERVAL` {#prop-beacon-interval}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_ADVERT`
* Value Type: UINT32
* Post-Reset Value: 3600 (one hour), or restored from saved state

Seconds between unsolicited [beacons](beacons.md) — broadcasts with no
payload at all. Zero sends none.

A beacon is sent with a flood budget and both the [Trace
Route](packet-options.md#trace-route-option-2) and [Trace
Signal](packet-options.md#trace-signal-option-10) options, so what
arrives at a distant node is a usable path back to the device and the
signal quality of every hop along it. What it does not carry is any
statement of who the device is: that is what an advertisement is for,
and a listener that has never met this device learns only that something
with a given source hint is reachable.

The two intervals are independent because they announce different things
at very different costs. A mesh usually wants the path refreshed often
and the identity restated rarely.

The accepted range, the per-period scatter, and the duty accounting are
as described for [`PROP_ADVERT_INTERVAL`](#prop-advert-interval).

### PROP 82: `PROP_STARTUP_BEACON` {#prop-startup-beacon}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_ADVERT`
* Value Type: BOOL
* Post-Reset Value: 1 (true), or restored from saved state

Whether the device emits one beacon once it has come up. On by default:
a node that has just restarted is exactly the node whose neighbours hold
the stalest paths to it, and a single empty broadcast is the cheapest
correction available.

The beacon is emitted after the device's own configuration has been
applied, so it reflects the device as it will actually run rather than
as it booted. Unlike a scheduled period it is not scattered: devices do
not restart in unison, so bring-up is already spread out by whatever
staggered it.

### PROP 88: `PROP_GNSS_ENABLED` {#prop-gnss-enabled}

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_GNSS`
* Value Type: BOOL
* Post-Reset Value: device-defined, conventionally 0 (false), or restored
  from saved state

Whether the GNSS receiver is powered.

Asynchronous because a device **MAY** offer the receiver as a control the
operator can reach — a button, a menu entry — and a switch someone can
flip is a value that moves without the host asking. A device that flips
it locally **MUST** publish the new value like any other transition the
host did not command.

False means the lowest power state the board can put the receiver in, not
merely an idle one: on a battery-powered node the receiver is typically
the largest continuous load there is, and a property that only stopped
*reporting* would be a property that solved nothing.

The post-reset value is the device's to choose, and it **SHOULD** be
false: a device that has never been told to care where it is should not
be spending a battery finding out. A device whose purpose is to know
where it is — a fixed outdoor node with a panel rather than a pocket
tracker on a cell — **MAY** default it true instead, and **SHOULD**
document that it does. Either way the value is only a starting point:
saved state overrides it in both directions, and a host that wants a
particular state sets it rather than assuming one.

Disabling the receiver does not clear the wall clock. Time already
obtained stays as good as the device's oscillator keeps it, which is the
whole point of having acquired it.

One exception is permitted, and only for boards where the receiver's own
real-time-clock domain is the *only* clock the board has: that domain
**MAY** remain powered while this property is false, and the device
**MAY** briefly power the receiver at boot to read the time back out of
it. That is a clock operation, not a positioning one — position data
observed during it is discarded, and it is governed by
[`PROP_GNSS_TIME_TRUST`](ulcp-device.md#prop-gnss-time-trust) rather than
by this property.

### PROP 89: `PROP_GNSS_LOCATION` {#prop-gnss-location}

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_GNSS`
* Value Type: 0–7 octets
* Post-Reset Value: Empty

The position of the most recent fix, in the [variable-precision
location](node-identity.md#variable-precision-location-format) encoding — the same nibble-interleaved
grid code node identities carry, so a host never has to convert between
two position formats.

An **empty** value means no fix has been obtained since the receiver was
last powered. The device reports the position it actually has rather than
the last one it remembers across a power cycle: a position that was true
somewhere else is worse than no position at all.

The length is the device's own honest precision for that fix and **MAY**
vary between reads. A host **MUST NOT** read more precision into a value
than its length carries; the encoding's truncation property means a
shorter value is a correct lower-precision statement of the same
position, never a different one.

A device **MUST** generally avoid announcing this property, and a host
that wants a position **MUST** be prepared to read one. A receiver
produces a fix about once a second, and at fine precision the readings
of a receiver standing perfectly still still differ from each other, so
a device that published every change would transmit continuously — and
wake its host every time — on behalf of a host that may not be looking.
No threshold rescues this: the one that would be quiet enough to be
worth having is coarse enough that the announcements it does send are
too late to be the point.

A host **SHOULD** nonetheless accept an announcement that arrives. The
value carries what a read would have returned, a device may have its own
reason to volunteer one, and a host that treats it as a protocol error
gains nothing for the strictness.

Read-only in this revision. A manually-placed fixed node is a real use,
but writing a position requires a rule for which source wins when the
receiver also has one, and this revision does not define that rule.

### PROP 90: `PROP_GNSS_ALTITUDE` {#prop-gnss-altitude}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_GNSS`
* Value Type: `INT32_LE`, or empty
* Post-Reset Value: Empty

Altitude of the most recent fix, in meters, in the same units and
reference as the node identity's altitude option, so the two are directly
interchangeable.

Empty when there is no three-dimensional fix — including while the
receiver holds a two-dimensional one, which has a position but no
altitude. Read-only for the same reason as
[`PROP_GNSS_LOCATION`](ulcp-device.md#prop-gnss-location).

### PROP 91: `PROP_GNSS_FIX` {#prop-gnss-fix}

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_GNSS`
* Value Type: `UINT8`
* Post-Reset Value: 0

The quality of the current position solution.

Value | Meaning
------|---------
0     | No fix
1     | Two-dimensional fix — position without altitude
2     | Three-dimensional fix

Unlike the three properties that describe a position, this one is never
empty: a device that is not fixed **knows** it is not fixed, so it reports
0. A receiver that is switched off reports 0 for the same reason. This is
the distinction the whole positioning surface rests on — zero for the
facts the device is sure of, empty for the position it does not have.

This is the positioning property a device **SHOULD** announce, and the
reason it is the exception to
[`PROP_GNSS_LOCATION`](ulcp-device.md#prop-gnss-location)'s silence is
that it is not a measurement. It changes when the receiver acquires or
loses a solution, which is a few times in a session rather than a few
times a second, and it is what tells a host whether reading a position
is worth anything at all.

### PROP 92: `PROP_GNSS_PRECISION` {#prop-gnss-precision}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_GNSS`
* Value Type: `UINT16_LE`, or empty
* Post-Reset Value: Empty

Estimated horizontal accuracy of the current fix, in decimeters. Empty
when there is no fix.

An **estimate**, not a measured error bound. Receivers generally report a
dilution of precision, which becomes a distance only after multiplying by
an assumed range error; a device that has a real accuracy figure
**SHOULD** report that instead. Hosts **MUST** treat the value as
indicative and **MUST NOT** present it as a guarantee.

Deliberately distinct from the length of
[`PROP_GNSS_LOCATION`](ulcp-device.md#prop-gnss-location): that is how
precisely the device is *willing to say* where it is, and this is how
precisely it *knows*. The two move independently.

### PROP 93: `PROP_GNSS_SATELLITES` {#prop-gnss-satellites}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_GNSS`
* Value Type: `UINT8`, optionally followed by a second `UINT8`
* Post-Reset Value: 0

The number of satellites contributing to the current solution, optionally
followed by the number the receiver can see at all.

A device that cannot distinguish the two reports only the first octet. As
with [`PROP_GNSS_FIX`](ulcp-device.md#prop-gnss-fix), a receiver that is
off or searching reports 0 rather than the empty value.

Chiefly a diagnostic: it is what distinguishes an antenna fault from a
sky that is simply obstructed, which is otherwise invisible to anyone not
holding the device.

### PROP 4866: `PROP_TIME` {#prop-time}

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_TIME`
* Value Type: `UINT32_LE`, or empty
* Post-Reset Value: Unchanged

The device's wall clock, as seconds since the Unix epoch, UTC.

The count is **unsigned**, which puts the end of the representable range
at 2106-02-07T06:28:15Z rather than at the 2038 rollover of the signed
encoding. Nothing in this revision needs to handle a wrap.

An **empty** value means the device does not know what time it is. This
is a normal state, not a fault: a device with no receiver, no
battery-backed clock, and no host to ask has genuinely never been told.
A device **MUST** report the empty value rather than an invented one, a
zero, or a build timestamp.

**A device that does not know the time MUST NOT display a clock**, or any
other indication of the current time, on any local user interface. A
plausible-looking wrong time is worse than a blank space: an operator
reads a displayed clock as a fact about the device, and a device with a
screen is exactly the device somebody will trust.

Setting the property sets the clock. Setting the **empty** value returns
the device to not knowing — the operator's way of saying that whatever
the device believes is wrong. A host-supplied time outranks every
receiver-derived one, including while
[`PROP_GNSS_TIME_TRUST`](ulcp-device.md#prop-gnss-time-trust) is clear:
the operator is the more authoritative source by definition.

The clock is **not** part of the saved snapshot. An epoch written to
flash accumulates unbounded error while the device is off, so a clock is
restored from a real time source — a receiver, a battery-backed
real-time clock, or a host — or not at all. `CMD_RST` does not clear it;
only an empty write does.

Devices announce this asynchronously. The transition from not knowing to
knowing is the one worth announcing; a routine re-synchronization that
agrees with the current value is not, and a device **SHOULD NOT** publish
one.

### PROP 4867: `PROP_TZ_OFFSET` {#prop-tz-offset}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_TIME`
* Value Type: `INT16_LE`
* Post-Reset Value: 0, or restored from saved state

The local time-zone offset from UTC, in minutes east of UTC. Negative
values are west.

Unlike [`PROP_TIME`](ulcp-device.md#prop-time) this **always** has a
value. Where a device is meant to be is configuration and is known from
the moment it is commissioned; what time it is is a measurement and may
not be. Separating them is what lets a device render a local time the
instant it acquires a clock, with no second round trip.

A minute offset rather than an hour one, because several real zones are
not whole hours. Values outside the range of real civil offsets
(−720 through +840) are rejected with `STATUS_INVALID_ARGUMENT`: outside
it, a value is a unit or byte-order mistake, and a device that accepted
one would display a confidently wrong local time.

Carries an offset and not a zone identifier. Devices do not carry a
zone database, so daylight-saving transitions are the host's business:
whatever adjusts the device's clock adjusts its offset.

### PROP 4868: `PROP_GNSS_IDENT_UPDATE` {#prop-gnss-ident-update}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_GNSS`
* Value Type: BOOL
* Post-Reset Value: 0 (false), or restored from saved state

Whether position fixes refresh the location the device identity
advertises in its [node identity](node-identity.md).

Off by default. Broadcasting where you are is a decision, and a device
that started doing it because a receiver was switched on would be making
that decision on the operator's behalf.

When on, the device clamps each fix to
[`PROP_GNSS_IDENT_PRECISION`](ulcp-device.md#prop-gnss-ident-precision)
before advertising it. A device **SHOULD** act on a fix only when the
clamped position actually changes, rather than on every fix: at a coarse
precision a stationary node's fixes all land in the same cell, and
re-advertising each one spends airtime to say nothing.

Switching it off **retracts** the advertised position rather than
freezing the last one. So does switching the receiver off. A position
that nothing is refreshing any more is a claim the device cannot
support, and it ages into a false one at whatever speed the device
moves; a device therefore drops the location and the altitude together
when it stops updating them.

Note that the [Unix Timestamp](node-identity.md#unix-timestamp-option-3)
option dates the identity payload, not the position — a node that has
been stationary for a day still stamps each payload with the moment it
was built.

### PROP 4869: `PROP_GNSS_IDENT_PRECISION` {#prop-gnss-ident-precision}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_GNSS`
* Value Type: `UINT8`
* Post-Reset Value: 5, or restored from saved state

How many octets of [variable-precision
location](node-identity.md#variable-precision-location-format) the advertised position is clamped
to, 1 (coarsest) through 7 (finest).

The default of 5 is a cell of roughly 38 × 19 m at the equator: fine
enough to place a node on a street, coarse enough not to place it in a
room. That trade — not the receiver's accuracy — is what this property
exists to control, which is why it is separate from
[`PROP_GNSS_PRECISION`](ulcp-device.md#prop-gnss-precision).

0 is rejected with `STATUS_INVALID_ARGUMENT` rather than read as
"advertise nothing":
[`PROP_GNSS_IDENT_UPDATE`](ulcp-device.md#prop-gnss-ident-update) is how
the advertisement is switched off, and a precision that silently meant
the opposite of a precision would be a trap. Values above 7 are rejected
for the same reason the encoding stops there.

Writable while auto-update is off, so a whole positioning policy can be
staged and enabled last.

### PROP 4870: `PROP_GNSS_TIME_TRUST` {#prop-gnss-time-trust}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_GNSS`
* Value Type: BOOL
* Post-Reset Value: 1 (true), or restored from saved state

Whether time derived from the GNSS receiver may set the wall clock.

On by default: the sky is normally the best clock a device of this class
has, and a node that sets itself needs no operator at all.

When clear, **no** receiver-derived time touches
[`PROP_TIME`](ulcp-device.md#prop-time) — not a fix's time, and not a
read of the receiver's own real-time clock at boot. This is the opt-out
for a receiver whose time cannot be trusted: a jammed or spoofed sky can
carry a plausible and badly wrong time, and a clock silently reset to it
is worse than a clock that has stopped, because everything downstream
will believe it.

Position reporting is unaffected. The two are separable, and an operator
who distrusts the time may still want to know where the device thinks it
is — including in order to notice that it is wrong.

Every transition to `ALERT_NONE` that the host did not command **MUST**
be reported with an unsolicited `CMD_PROP_IS`.

The deadline is the only bound. In particular, the alert is **not**
cleared on detach: the link to the searching host drops as soon as the
searcher walks out of range, which is the moment the alert becomes most
useful. It is likewise unaffected by `CMD_RST`, which resets session
state and not the physical behavior of the device.

The property is live device-domain state. It is never included in a saved
snapshot, is not changed by `CMD_RESTORE`, and is `ALERT_NONE` after
every reset — a device that loses power mid-alert comes back quiet.
