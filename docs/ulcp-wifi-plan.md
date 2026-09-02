# ULCP Wi-Fi Station: Protocol Sketch

A sketch of the ULCP surface for a Wi-Fi station: turning it on and off,
scanning, joining and leaving a network, and reporting what the link and
the interface are doing. This is the protocol only. What the device does
with the connection once it has one (a bridge tunnel, a time source, a
local ULCP binding) is separate work and gets its own capability when it
comes.

The shape follows the [BLE binding](protocol/src/ulcp-ble.md): one
capability, no commands, and every control a property, because every
control on the list is a state with more than one way out.

## Model

The device has a Wi-Fi **station** interface. It holds a small table of
**known networks**, each a name, a security mode, and a credential the
device keeps and never reads back. At most one of them is **selected**;
while the station is enabled and a network is selected the device tries
to be on that network, and keeps trying, without a host present. That
last clause is the reason the whole design is properties: a device on
Wi-Fi is infrastructure, and infrastructure that needs a phone to get
back on the network after a power cut is not.

Everything the host can ask for falls into two piles:

* **Configuration**, which is device-domain state, part of the saved
  snapshot, and untouched by attach and detach: whether the station is
  enabled, the known-network table, and which network is selected.
* **Live state**, which is read-only, never saved, and which `CMD_RST`
  touches only through the configuration it reverts: whether a scan is
  running and what it found, the link state, the association's signal,
  the station's MAC. Its post-reset value is declared the way the BLE
  binding declares the link and the bond count, as whatever the live
  fact is, so "reverts to its post-reset value" and "is left alone" are
  the same statement.

There is no auto-join across the table. The device joins the network it
was told to and no other; selection is a decision the operator makes,
saved so the device can carry it out unattended. A device that picks
networks by itself is a device whose behavior depends on what is in the
air around it, which is the wrong property for a repeater on a wall.

## Why No Commands

Scan, connect, disconnect, and on/off all describe states that persist
after the frame is handled, and each of them has a self-directed exit: a
scan finishes on its own, a link drops on its own, a menu on the device
can flip the switch. A command can start any of these and observe none
of them. As properties, every one of them is readable, writable in both
directions, and published when the device moves it by itself, for the
price of the property machinery that already exists.

The test is whether a thing is a state or an act, and the answer is not
forced either way. The one genuinely command-shaped act in the vicinity,
"try the join again right now", is deliberately **not** disguised as a
property: a property write that has a side effect when written with the
value it already holds is a command wearing a costume, and it breaks the
moment a host replays its configuration. It is also not needed. The
device retries on its own, and the case that wants an immediate attempt,
a corrected passphrase, gets one because replacing the selected entry
restarts the join. If a reconnect kick ever turns out to be needed, it
is a command, and it is the only one this surface would have.

## Capability

Code | Name       | Requires | Grants
-----|------------|----------|--------
53   | `CAP_WIFI` | —        | A Wi-Fi station the device can enable, scan with, and join networks with: `PROP_WIFI_ENABLED`, `PROP_WIFI_NETWORKS`, `PROP_WIFI_NETWORK`, `PROP_WIFI_SCANNING`, `PROP_WIFI_SCAN_RESULTS`, `PROP_WIFI_LINK`

One capability, and everything else discovered by asking. The six
properties it grants are the ones a host needs to find a network, join
it, and know whether it did; a device advertising `CAP_WIFI` **MUST**
serve all six. The other two, `PROP_WIFI_RSSI` and `PROP_WIFI_MAC`,
report things a stack may not expose, and a device that cannot answers
`STATUS_PROP_NOT_FOUND` in the same exchange the host was already
making, by the argument the BLE binding makes for itself.

`CAP_WIFI` does not require `CAP_SAVE`. Without it the station's
configuration is volatile and the device is back to knowing no networks
after a power cycle, which is a worse device but a conforming one.

## Properties

Allocated from the extended device and transport configuration range,
in a block of sixteen after the BLE transport's, so the station has room
to grow without interleaving.

Id   | Mnemonic                 | Commands                 | Class         | Description
-----|--------------------------|--------------------------|---------------|-------------
4880 | `PROP_WIFI_ENABLED`      | Get, Set, Is             | Configuration | Whether the station is up
4881 | `PROP_WIFI_NETWORKS`     | Get, Set, Insert, Remove | Configuration | Known networks and their credentials
4882 | `PROP_WIFI_NETWORK`      | Get, Set, Is             | Configuration | The selected network, or empty
4883 | `PROP_WIFI_SCANNING`     | Get, Set, Is             | Live          | Whether a scan is in progress
4884 | `PROP_WIFI_SCAN_RESULTS` | Get, Is, Inserted        | Live          | What the current or last scan has found
4885 | `PROP_WIFI_LINK`         | Get, Is                  | Live          | Link state, failure reason, and association
4886 | `PROP_WIFI_RSSI`         | Get                      | Live          | Signal of the current association
4887 | `PROP_WIFI_MAC`          | Get                      | Constant      | The station's MAC address

4888–4895 are reserved for the station.

### PROP 4880: `PROP_WIFI_ENABLED`

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_WIFI`
* Value Type: BOOL
* Post-Reset Value: 0 (false), or restored from saved state

Whether the station is up. Cleared, the device drops any association,
abandons any scan in progress, and puts the Wi-Fi hardware into the
lowest power state the platform offers. This is the GNSS receiver's
argument, not the BLE transport's: on a battery-powered node a Wi-Fi
radio that is merely idle is still the largest load on the board, and a
property that only stopped *reporting* would solve nothing.

Set again, the device comes back up and, if a network is selected,
starts joining it. The known-network table and the selection are
configuration and are not disturbed in either direction, so turning the
station off and on is not a way to forget anything.

Off by default, for the reason `PROP_GNSS_ENABLED` is: a device that has
never been given a network has nothing to spend the power on. Saved
state overrides the default, which is how a commissioned device comes up
connected.

Asynchronous because a device with a screen may offer the switch on it,
and a switch someone can flip is a value that moves without the host
asking.

A write of `1` answers `STATUS_INVALID_STATE` on a platform that cannot
run the station alongside another radio it currently has on. The device
must not silently take the other radio down to honor the write; the host
turns that one off first. Whether this ever arises is the platform's
business, and a platform that coexists answers the write like any other.

### PROP 4881: `PROP_WIFI_NETWORKS`

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: Yes
* Asynchronous Updates: No
* Required: `CAP_WIFI`
* Item Form: structure below
* Reported Form: the item with its credential omitted
* Remove Selector: the SSID
* Post-Reset Value: Empty, or restored from saved state

The networks the device knows. Each item:

~~~
+-------+----------+----------+----------+------------------+
| FLAGS | SECURITY | SSID_LEN |   SSID   |  CREDENTIAL ...  |
+-------+----------+----------+----------+------------------+
   1 B      1 B        1 B      1–32 B    security-defined
~~~

**FLAGS**: bit 0 set means the network hides its SSID and the device must
probe for it by name rather than wait to hear it. Bit 1 set means the
credential is a raw 32-octet pairwise master key rather than a
passphrase, which is valid only for the modes that derive one; a host
that holds the key need never hand the device the passphrase, and a
device never has to run the derivation. Bits 2–7 are reserved and must
be zero.

**SECURITY** is one mode:

Value | Name                    | Credential
------|-------------------------|------------
0     | `WIFI_SEC_OPEN`         | none
1     | `WIFI_SEC_OWE`          | none
2     | `WIFI_SEC_WPA2`         | passphrase of 8–63 octets, or a key
3     | `WIFI_SEC_WPA3`         | password of 1–128 octets
4     | `WIFI_SEC_WPA`          | passphrase of 8–63 octets, or a key
5     | `WIFI_SEC_WEP`          | none defined
6     | `WIFI_SEC_WPA2_ENT`     | none defined
7     | `WIFI_SEC_WPA3_ENT`     | none defined
8     | `WIFI_SEC_WPA3_ENT_192` | none defined

Values 9–15 are reserved; SAE-PK is the likeliest occupant. Sixteen is
the ceiling because the scan result reports these as a 16-bit set.

`WIFI_SEC_OPEN` is no security at all. `WIFI_SEC_OWE` is Enhanced Open:
encrypted against anyone listening, authenticated against nobody, with
no credential, and the only credential-free mode permitted on 6 GHz. An
OWE entry names the network as the operator sees it. Where that is a
plain OWE network the device joins it; where it is the visible half of
an OWE transition deployment, the device follows the transition element
to the hidden companion BSS and joins that. `PROP_WIFI_LINK` then
reports the companion's BSSID and frequency, which is all it ever
reports of any association, while `PROP_WIFI_NETWORK` goes on naming the
visible network the operator selected. The entry never names the
companion, because the operator never saw it. `WIFI_SEC_WPA2` is
WPA2-Personal and covers the
WPA/WPA2 mixed networks that negotiate CCMP; `WIFI_SEC_WPA` is the
TKIP-only remainder, which a device **MAY** decline to join.
`WIFI_SEC_WPA3` is WPA3-Personal, SAE, whose password is not a WPA2
passphrase: SAE puts no bounds on it, so the 8–63 rule does not apply,
and the table admits up to 128 octets, which is where the more generous
stacks stop. A device whose stack holds a shorter limit refuses a longer
password with `STATUS_UNIMPLEMENTED`, since the entry is well-formed and
the device is what cannot hold it. A password shared with a transition
network's WPA2 side is 8–63 octets by that side's rule, which is the
host's to know. The remaining four exist so scan
results can say what they heard. WEP is not worth a credential form, and
the three enterprise modes are a provisioning surface this sketch does
not open; they are numbered now so that opening it later does not
renumber anything.

A passphrase or password is the UTF-8 encoding of what the operator
typed, with no terminator and no U+0000, and its length bounds count
octets. The device derives keys from exactly those octets: the PBKDF2
of 802.11 Annex J for `WIFI_SEC_WPA2` and `WIFI_SEC_WPA`, and SAE over
the octets directly. An ASCII passphrase therefore yields what every
router yields, and a non-ASCII one yields what a router that accepted
UTF-8 yielded; in both cases the host's job is to hand over the same
octets the router's operator entered, and the device's is not to
reinterpret them. A raw key, `FLAGS` bit 1, is exactly 32 octets and
skips the derivation.

An insert is refused with `STATUS_INVALID_ARGUMENT` when it is not
well-formed: an empty SSID, a mode with no credential form, a credential
of the wrong length or kind for its mode, a reserved mode. The SSID is
never empty because an empty `PROP_WIFI_NETWORK` means no selection, so
an entry with no name could be stored and never chosen; a hidden network
has a real name, it is only the advertisement that is blank. It is
refused with
`STATUS_UNIMPLEMENTED` when it is well-formed and this device cannot do
it, a WPA3 entry on a chip without SAE, or a WPA entry on a device that
declines TKIP. The two are different answers because a host acts on them
differently: the first is a bug in the host, the second is a reason to
pick the next mode the network offers.

The security mode is exact: it is the mode the device uses, not a
ceiling it negotiates down from. An entry marked `WIFI_SEC_WPA3` joins a
WPA2/WPA3 transition network with SAE and fails against a WPA2-only one;
an entry marked `WIFI_SEC_WPA2` joins either with PSK; an entry marked
`WIFI_SEC_OWE` never falls back to open. A device **MUST NOT** negotiate
a mode other than the one the entry names, so a host that takes the
mode out of a scan result gets exactly the network it saw and an evil
twin advertising a weaker one gets nothing. Where the passphrase is the
same across a transition network's modes, which it usually is, the host
writes the strongest one the device accepts.

Items are keyed by SSID: the table holds at most one entry per network,
and an insert whose SSID matches an existing entry **replaces** it and
reports the item as inserted. That is the path for a wrong passphrase, a
changed one, or a mode upgrade, and it never needs a remove. The SSID
is octets, not text; a device compares it bytewise. A whole-table
`CMD_PROP_SET` carrying two entries with the same SSID is refused with
`STATUS_INVALID_ARGUMENT` before anything changes, under [Mutation
Atomicity](protocol/src/ulcp-core.md#mutation-atomicity): the value is
an unordered set, so neither entry has standing to win, and a host that
wrote both did not mean either.

The credential is write-only, under the rules of [Provisioning
Security](protocol/src/ulcp-core.md#provisioning-security): the reported
form is the item through its SSID, and neither `CMD_PROP_GET` nor any
notification ever carries a passphrase. This is why replacing an entry is
the only way to change its credential: a host cannot read one back to
compare it. Writes that carry a credential are subject to the same
transport requirement as key material.

A device bounds the table and refuses an insert past its capacity with
`STATUS_NOMEM`; four entries is enough for anything a device of this
class does and a device **SHOULD** hold at least that many. The bound
**MUST** also keep the complete reported table, every entry in its
redacted form, inside one frame on every transport the device exposes,
as the scan results are bounded, so a `CMD_PROP_GET` always answers in
one piece. At under forty octets per reported entry that constrains
nothing a device would want.

Removing the selected network, whether by `CMD_PROP_REMOVE` or a
whole-table `CMD_PROP_SET` that omits it, clears the selection: the
device drops the association, publishes `PROP_WIFI_NETWORK` as empty, and
publishes the link going down. Replacing the selected network's entry
drops any association it holds and starts a fresh join with the new
entry at once: a host that has just corrected a passphrase should not
wait out a backoff to learn whether it worked.

The table is device-domain configuration and is part of the saved
snapshot, credentials included, which is what lets the device rejoin
unattended. `CMD_CLEAR` erases the persisted copy with everything else
and, as with everything else, leaves the live table alone: the device
stays on its network until the `CMD_RST` that completes a factory reset
reverts the table to its now-empty post-reset value. A device
advertising `CAP_SAVE` stores it as it stores key material.

### PROP 4882: `PROP_WIFI_NETWORK`

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_WIFI`
* Value Type: 1–32 octets (an SSID), or empty
* Post-Reset Value: Empty, or restored from saved state

The network the device is on, or is to be on: the SSID of one entry in
`PROP_WIFI_NETWORKS`. This is "connect" and "disconnect" both.

Writing an SSID selects that network. If the station is enabled, the
device drops any current association and starts joining the new one;
if it is not, the selection waits for it, so a whole configuration can be
staged and the station enabled last. Writing the SSID that is already
selected changes nothing and disturbs nothing, like any other property
written with its own value. An SSID not in the table is refused with
`STATUS_ITEM_NOT_FOUND`: the credential lives in the table, and the
selection only names it. The core chapter defines that status for an
unmatched `CMD_PROP_REMOVE`, and this is the same fact about a
`CMD_PROP_SET`, a value that names no item in the property it refers
to; the definition broadens to say so when this lands, because a host
acts on it differently from `STATUS_INVALID_ARGUMENT`. One is "insert it
first" and the other is a bug.

Writing the **empty** value deselects: the device leaves the network and
associates with nothing until something is selected again. This is a
stable state, not a moment. The station stays up, scans on request, and
joins nothing, which is what a phone with Wi-Fi on and no network in
range is doing. A device **MUST NOT** re-select a network on its own,
because a disconnect the device undoes by itself is not one.

The device publishes the property when it changes it: a removal from the
table that empties the selection, or a picker on the device's own screen.

The selection is the network the device will spend its unattended life
trying to reach, so it is saved with the table. A device restored from a
snapshot comes up joining what it was joining.

### PROP 4883: `PROP_WIFI_SCANNING`

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_WIFI`
* Value Type: BOOL
* Post-Reset Value: whether a scan is running

Whether a scan is in progress. Writing `1` starts one; the device answers
with `1`, reports each access point as it is heard through
`PROP_WIFI_SCAN_RESULTS`, and publishes `0` when the scan completes.
Writing `0` abandons a scan in progress and leaves in the results
whatever had been found by then.

The frames of a scan go out in a fixed order, so a host can never
misattribute one:

1. `CMD_PROP_IS` for `PROP_WIFI_SCAN_RESULTS` carrying the empty value:
   the previous results are gone.
2. `CMD_PROP_IS` for this property carrying `1`, as the reply to the
   host's write or unsolicited when the device started the scan itself.
3. One `CMD_PROP_INSERTED` per access point heard, in the order heard.
4. `CMD_PROP_IS` for this property carrying `0`, after the last of them.

The clear goes first so that every insert lands in a table the host
knows to be empty, and the completion goes last so that a host seeing
`0` holds the whole list without reading it.

This is the pairing window's shape exactly: a state the host can enter,
that ends by itself, and that a device with a screen can enter without
the host. A device **MUST** bound a scan's duration; a few seconds is
what the hardware takes.

A write of `1` answers `STATUS_INVALID_STATE` while the station is
disabled, and **MAY** answer `STATUS_BUSY` while a join is in the middle
of its handshake, which resolves by itself. Writing `1` during a scan
succeeds and answers `1`; there is nothing to restart. A write of `0`
always succeeds.

A device **MAY** scan while associated, at the cost of the association's
traffic while it is off-channel. Whether the scan is active or passive,
and on which channels, is the device's business, except that a hidden
network in the table is probed by name so it can appear.

A scan the device starts from its own menu is reported the same way,
inserts and all. An attached host pays twenty-odd small frames once per
scan, which is nothing against the scan itself, and a picker that
appears as networks are heard is the difference between a list that
fills in and a spinner.

### PROP 4884: `PROP_WIFI_SCAN_RESULTS`

* Type: Multiple-Value, Read-Only
* Has Item Length Prefix: Yes
* Asynchronous Updates: Yes (`Is`, `Inserted`)
* Required: `CAP_WIFI`
* Post-Reset Value: what the station has found; empty after a power-on

What the scan in progress has found so far, or what the last one found.
Each item:

~~~
+-------+-----------+------+--------+-----------+
| MODES | FREQUENCY | RSSI | BSSID  |  SSID ... |
+-------+-----------+------+--------+-----------+
  2 B     2 B, MHz    1 B     6 B      0–32 B
~~~

**MODES** is a 16-bit little-endian set of the security modes the access
point offers, bit *n* standing for mode *n* of the enumeration above. A
WPA2/WPA3 transition network sets both bits. An OWE transition network
is two BSSs, a visible open one and a hidden OWE companion that the open
one's transition element names by BSSID and SSID; the device reads the
element and reports the **visible** BSS with both the open and the OWE
bit set, so the host sees one network offering two modes and picks
between them like any other. The companion is reported as itself, under
the SSID the element gave it, and nothing depends on it. The set
rather than a single "strongest" value, because which of the offered
modes the host should write depends on what the device can do, and the
scan result is not the place to guess: the host writes the strongest bit
it likes and steps down on `STATUS_UNIMPLEMENTED`. **FREQUENCY** is the
center frequency of the access point's **primary** 20 MHz channel, in
megahertz, little-endian. A frequency rather than a channel number
because a channel number is ambiguous across bands and a frequency is
not, and the number follows from the frequency in one line wherever a
display wants it. The width of the operating channel is not reported:
the device negotiates it at association, and nothing about it is needed
to join. **RSSI** is a signed
dBm. **SSID** is the remainder of the item; empty means the network
hides its name, and its BSSID is what distinguishes it from the next
hidden one.

One item per access point, keyed by BSSID. The device reports what it
heard and nothing it inferred: which of several access points make up
one network is a question the host answers by grouping on SSID, and a
host that wants the list a phone shows coalesces, keeps the strongest
per name, and sorts. A host that wants to see every radio in the
building has that too. Hidden networks need no special case, since an
access point with no name still has an address.

The device reports each access point with `CMD_PROP_INSERTED` as it is
heard, and hearing one again is another `CMD_PROP_INSERTED` under the
same BSSID, which **replaces** the host's entry. Replacement by key is
what makes the inserts idempotent, and idempotence is what makes it safe
for a host to read the table mid-scan and follow the inserts from there:
an item that arrives in both the reply and a notification is the same
item twice.

The device retains a bounded table and reports an unbounded scan. Every
access point heard is inserted; the device keeps the strongest of them
up to its bound, evicting the weakest as stronger ones arrive, and
**never** reports an eviction. The bound **MUST** be chosen so the whole
retained value fits in one frame on every transport the device exposes:
on BLE that is the 512-octet reassembled frame, into which twenty or so
typical items fit. The inserts are one item each and never approach it.

This is the one place the sketch departs from the property model on
purpose. A host that followed the inserts holds a superset of what a
`CMD_PROP_GET` returns: everything the scan heard, against the strongest
twenty the device kept. The departure is harmless because nothing in the
host's copy is invented, every item in it was heard, and the two are
reconciled by the clear at the next scan. The alternative, a
`CMD_PROP_REMOVED` per eviction, would spend frames telling the host to
stop showing an access point it can see, in order to keep two views
identical that nobody needs to compare.

`CMD_PROP_GET` returns the retained table strongest first. Inserts
arrive in the order the access points were heard, which is the order the
host receives them in and has no other meaning.

Delivering results as they are found is a promise about delivery, not
about pace. Most stacks hand back a scan only when it finishes; a device
gets progressive results by scanning a channel at a time, which the
usual scan interfaces allow and which costs a little total duration for
first results in a fraction of a second. A device that cannot do that
emits every insert at the end and conforms.

The value is cleared, and the empty value published with `CMD_PROP_IS`,
when a scan starts and when the station is disabled. A list of what was
in the air somewhere the device may no longer be is worse than an empty
one.

### PROP 4885: `PROP_WIFI_LINK`

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_WIFI`
* Value Type: structure below
* Post-Reset Value: what the station is doing

~~~
+-------+--------+--------+-----------+
| STATE | REASON | BSSID  | FREQUENCY |
+-------+--------+--------+-----------+
  1 B     1 B      6 B      2 B, MHz
                  (present only when STATE is WIFI_LINK_UP)
~~~

**STATE**:

Value | Name                   | Meaning
------|------------------------|---------
0     | `WIFI_LINK_DOWN`       | Not trying: the station is off, or nothing is selected
1     | `WIFI_LINK_CONNECTING` | A network is selected and the device is not on it yet, or not any more
2     | `WIFI_LINK_UP`         | Associated

**REASON** says why the device is in `WIFI_LINK_CONNECTING` rather than
`WIFI_LINK_UP`, and is `0` in the other two states:

Value | Name                     | Meaning
------|--------------------------|---------
0     | `WIFI_REASON_NONE`       | No attempt has failed yet
1     | `WIFI_REASON_NOT_FOUND`  | The network was not heard and did not answer a probe
2     | `WIFI_REASON_AUTH`       | The network rejected the credential
3     | `WIFI_REASON_REJECTED`   | The network refused the association for another reason
4     | `WIFI_REASON_LOST`       | The association was up and dropped
5     | `WIFI_REASON_OTHER`      | Something the device has no name for

`WIFI_LINK_UP` is an 802.11 statement: the station is authenticated and
associated. Whether the device has an address on the link it is now on
is a different layer's fact, and belongs to
the [family state properties](#ip-connectivity), which report it.

`WIFI_LINK_CONNECTING` is the whole of "trying", including the waits
between attempts. While the station is enabled and a network is
selected, the device retries indefinitely with backoff and never gives
up: a wrong passphrase is a device that retries a few times an hour
until someone fixes it, which costs nothing and is what unattended
infrastructure should do. `WIFI_LINK_DOWN` is reserved for the two states
in which the device is not trying at all, so that a host reading `DOWN`
knows the fix is configuration and a host reading `CONNECTING` knows the
fix is in the reason.

The device publishes the property on every change of state and on every
change of reason, and on nothing else. Retrying and failing the same way
again is not a transition and is not published, so a device with a wrong
passphrase reports `WIFI_REASON_AUTH` once, not every attempt.

When `WIFI_LINK_UP`, the value carries the association: which access
point, and the center frequency of its primary channel in megahertz, as
in a scan result. A roam to another access point of the same network is
a change of value and is published.

Live transport state: not saved, and untouched by `CMD_RST` except as a
consequence of `CMD_RST` reverting the configuration it follows.

### PROP 4886: `PROP_WIFI_RSSI`

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_WIFI`
* Value Type: INT8 in dBm, or empty
* Post-Reset Value: the current measurement; empty when the link is not up

The received signal strength of the current association, measured when
the property is read. Empty when the link is not up.

Kept out of `PROP_WIFI_LINK` for the reason `PROP_GNSS_LOCATION` is kept
quiet: a measurement that changes on every beacon has no business in a
property that is published on every change. `PROP_PHY_RSSI` is the same
split on the LoRa side.

### PROP 4887: `PROP_WIFI_MAC`

* Type: Single-Value, Constant
* Asynchronous Updates: No
* Required: `CAP_WIFI`
* Value Type: 6 octets

The station's MAC address, as it appears to the access point. Constant
because a router's allow list is keyed on it; a device that randomized
it would be reporting an address nobody can use.

## Mechanics

The flows a host runs, in terms of the properties above. None of them
needs anything the property grammar does not already provide.

**Turn on.** Write `PROP_WIFI_ENABLED` to `1`. If a network is selected,
`PROP_WIFI_LINK` publishes `CONNECTING` and then `UP` or a reason.

**Scan.** Write `PROP_WIFI_SCANNING` to `1`; clear the list on the
`CMD_PROP_IS` that follows; add or replace an entry per
`CMD_PROP_INSERTED`, grouping by SSID for display; stop the spinner on
the unsolicited `0`. A host on a binding that carries no notifications
polls `PROP_WIFI_SCANNING` and reads `PROP_WIFI_SCAN_RESULTS` once it
reads `0`. A host presenting a picker can mark each network already in
`PROP_WIFI_NETWORKS` by matching SSIDs, since the reported table form
carries them.

**Join a new network.** Insert an entry in `PROP_WIFI_NETWORKS` with the
SSID from the scan result, the strongest mode in its offered set, and
the passphrase from the operator; on `STATUS_UNIMPLEMENTED`, insert
again with the next mode down. Then write the SSID to
`PROP_WIFI_NETWORK`. Two writes rather
than one because the credential has one home and the selection only
names it. There is no safe one-frame shortcut: a whole-table
`CMD_PROP_SET` replaces every entry, and since credentials cannot be
read back, a host can only write a whole table it holds every credential
for. That is the first host commissioning a fresh device, and nobody
after it.

**Fix a wrong passphrase.** `PROP_WIFI_LINK` reads `CONNECTING` with
`WIFI_REASON_AUTH`. Insert the entry again with the corrected credential;
the device tries it immediately and the link reports the outcome.

**Switch networks.** Write the other SSID to `PROP_WIFI_NETWORK`.

**Reconnect.** There is no such flow. The device is already retrying,
and a host that wants a fresh start with the same credentials has the
honest two-step: deselect, then select, each of which is a real state.

**Disconnect.** Write `PROP_WIFI_NETWORK` empty. The device leaves and
stays off the network with the station still up.

**Forget.** Remove the entry from `PROP_WIFI_NETWORKS`. If it was
selected the selection empties and the link drops, both published.

**Turn off.** Write `PROP_WIFI_ENABLED` to `0`. Nothing is forgotten.

**Commission for unattended use.** Do any of the above, then `CMD_SAVE`.
The station comes up and rejoins at every boot after that.

**Synchronize on attach.** Read `PROP_WIFI_ENABLED`, `PROP_WIFI_NETWORK`,
and `PROP_WIFI_LINK`, in one `CMD_PROP_MULTI_GET` where available. The
table is read only when the host needs to show it.

### What Survives What

Property                 | Saved | `CMD_RST` | Detach | Station off
-------------------------|-------|-----------|--------|-------------
`PROP_WIFI_ENABLED`      | yes   | reverts   | kept   | —
`PROP_WIFI_NETWORKS`     | yes   | reverts   | kept   | kept
`PROP_WIFI_NETWORK`      | yes   | reverts   | kept   | kept
`PROP_WIFI_SCANNING`     | no    | follows   | kept   | abandoned
`PROP_WIFI_SCAN_RESULTS` | no    | follows   | kept   | cleared
`PROP_WIFI_LINK`         | no    | follows   | kept   | `DOWN`
`PROP_WIFI_RSSI`         | no    | follows   | kept   | empty
`PROP_WIFI_MAC`          | —     | —         | —      | —

"Reverts" means to the post-reset value, which on a device with a
snapshot is the saved one. "Follows" means the live state ends up
wherever the reverted configuration puts it, and nowhere else. A
`CMD_RST` on a device whose live station configuration already matches
its snapshot leaves a running scan running and an association up; one
that reverts the selection or its credential drops the association and
joins the restored entry; and one on a device with no snapshot takes
the station down and everything live with it. `CMD_RESTORE` is the same
column: in either of its forms it reverts the three configuration
properties to the snapshot and the live state follows. Detach touches nothing: the
station is device-domain and runs unattended, and a scan that was in
progress when the host left completes and leaves its results for the
next one.

### Over the Node Management Binding

Every property here is device-domain, so a listed administrator over the
mesh may read and write all of them, under the same rule that lets
channel keys be provisioned remotely: the binding already delivers each
request authenticated and encrypted, so an administrator may provision
a credential. Reading is the redacted form and nothing else, here as on
the local link: the network table reads back without its credentials,
and no binding exists over which a credential can be read. Scan results
are the one large read, and the binding's cursors carry them. An
administrator who disables the station a bridge tunnel rides on has done
the same thing as one who writes `PROP_MAC_BACKHAUL`, and gets the same
warning in the same place.

### On BLE

The frame-size concerns are a `CMD_PROP_GET` of the scan results and of
the network table, and both are bounded above so they fit; the inserts
that deliver scanned access points live are one item each. The largest
credential write, a 32-octet SSID with a 128-octet SAE password, is
under two hundred octets with framing. Everything else is a few.

## IP Connectivity

The layer above the station, as capabilities of its own. Address
configuration is not a property of Wi-Fi: a wired link, should one ever
appear, would need exactly the same properties, and a device's IP stack
is one thing whichever link carries it. Everything here is therefore
named `IP`, not `WIFI`, and nothing in it knows what the link is.

What a host needs from this layer is small: whether the device can reach
anything, what it is reachable at, and a way to configure the cases the
network does not configure for it. Nothing about what the device reaches
belongs here; a bridge tunnel or a time source reports its own state
under its own capability.

This revision has one link and one interface. A device with two links
is a future revision, and the properties are shaped so an interface
selector could be added without renaming them.

### Capabilities

Code | Name       | Requires | Grants
-----|------------|----------|--------
54   | `CAP_IPV4` | —        | An IPv4 stack on the device's link: `PROP_IPV4_STATE`, `PROP_IPV4_CONFIG`, `PROP_IPV4_ADDRESS`, and the shared `PROP_IP_DNS` and `PROP_IP_RESOLVERS`
55   | `CAP_IPV6` | —        | An IPv6 stack on the device's link: `PROP_IPV6_STATE`, `PROP_IPV6_CONFIG`, `PROP_IPV6_ADDRESSES`, and the same two shared properties

One per family, because the families are peers. The BLE binding's
argument for a single capability is that a refusal is a complete answer
about an *extra*, and neither family is an extra to the other: a device
that speaks only IPv4 is ordinary today, and a device that speaks only
IPv6 is an ordinary device on a 6 GHz or IPv6-only-preferred network
tomorrow. Making either the floor would encode which one is normal,
which is a fact about the year, not the protocol. A device with both
advertises both; a host that sees either knows the shared properties
are there. The seam stops here: DHCP versus static, advertisements
versus DHCPv6, are methods within a family, and a device that lacks one
refuses the write with `STATUS_UNIMPLEMENTED` as the BLE argument
intends.

No formal requirement on either, on purpose. A capability's
requirements are concrete codes, and naming `CAP_WIFI` here would make
a wired device either lie about having Wi-Fi or invent a second pair
of IP capabilities. The precondition is stated instead: a device
advertising either has a stack on one link, and describes that link
through whatever link capability it also advertises, `CAP_WIFI` today.
A device that advertises an IP capability and no link capability has a
link it offers no control over, which is a legal shape for a device
with a fixed wired port; its family states simply never report
`IP_NO_LINK` for a reason the host can act on.

### Properties

Allocated in the block after the station's.

Id   | Mnemonic            | Commands                 | Class         | Description
-----|---------------------|--------------------------|---------------|-------------
4896 | `PROP_IPV4_STATE`     | Get, Is                  | Live          | IPv4 readiness
4897 | `PROP_IPV4_CONFIG`    | Get, Set                 | Configuration | How IPv4 is configured
4898 | `PROP_IPV4_ADDRESS`   | Get, Is                  | Live          | The IPv4 address, prefix, and gateway in effect
4899 | `PROP_IPV6_STATE`     | Get, Is                  | Live          | IPv6 readiness
4900 | `PROP_IPV6_CONFIG`    | Get, Set                 | Configuration | How IPv6 is configured
4901 | `PROP_IPV6_ADDRESSES` | Get, Is                  | Live          | The IPv6 addresses and default routers in effect
4902 | `PROP_IP_DNS`         | Get, Set, Insert, Remove | Configuration | Configured resolvers, or empty to use what the network provides
4903 | `PROP_IP_RESOLVERS`   | Get, Is                  | Live          | The resolvers in use

4904–4911 are reserved for this layer.

#### PROP 4896: `PROP_IPV4_STATE`

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_IPV4`
* Value Type: UINT8
* Post-Reset Value: what the family is doing

One octet, from the enumeration both family states share:

Value | Name          | Meaning
------|---------------|---------
0     | `IP_DISABLED` | The family is configured off
1     | `IP_NO_LINK`  | The link is down, so there is nothing to address
2     | `IP_WAITING`  | The link is up and the family has no usable address yet
3     | `IP_READY`    | The family holds a usable address
4     | `IP_CONFLICT` | The configured static address is held by something else

A **usable** address is a unicast host address that is not link-local:
for IPv4 anything outside `169.254/16` that is neither multicast,
broadcast, loopback, nor unspecified, and for IPv6 anything outside
`fe80::/10` under the same exclusions. A self-assigned `169.254` address
reaches only the link, exactly as `fe80::` does, and a device that fell
back to one is a device whose DHCP failed, which `IP_WAITING` says and
`IP_READY` would hide. A device with only
an IPv6 link-local address is `IP_WAITING`, because it is waiting for
exactly the advertisement that would give it one. This is the boundary
readiness is defined on, and the same boundary the static configuration
is validated against.

This is the property a host watches for its family: it changes when a
lease is obtained or lost, when a router starts or stops advertising,
when the link comes and goes, which is a few times in a session rather
than a few times a minute. The device publishes it on any change and on
nothing else. The address and resolver properties publish their own
changes, since those can move while the state stands still.

`IP_WAITING` is this layer's `WIFI_LINK_CONNECTING`: the device is doing
what its configuration says and the network has not answered. It carries
no reason, because the reasons are the network's, a DHCP server that
does not answer, a router that does not advertise, and the fix is on the
network. `IP_CONFLICT` is the exception that earns its own value: a
static address that duplicate-address detection or an ARP probe finds
already in use is a fault in the configuration this protocol wrote, the
fix is a different address, and a host that could not tell it from an
ordinary wait would tell the operator to check the router. The device
keeps probing while in `IP_CONFLICT` and moves to `IP_READY` if the
other holder goes away. Under `IP_METHOD_AUTO` a conflict is the
stack's to resolve, by declining the lease and asking again, and the
family stays `IP_WAITING`. `IP_NO_LINK` is separate so that a host can
tell "the station is not associated" from "the station is associated and
nobody is handing out addresses" without reading `PROP_WIFI_LINK` as
well.

`IP_READY` means an address, not a route. Whether the family also has a
default route is in the address property, the gateway field for IPv4
and the router items for IPv6, and a
device on an isolated network that hands out addresses and no gateway is
ready by this definition, which is the honest one.

#### PROP 4897: `PROP_IPV4_CONFIG`

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_IPV4`
* Value Type: structure below
* Post-Reset Value: `IP_METHOD_AUTO`, or restored from saved state

~~~
+--------+---------+--------+---------+
| METHOD | ADDRESS | PREFIX | GATEWAY |
+--------+---------+--------+---------+
  1 B      4 B       1 B      4 B
         (present only when METHOD is IP_METHOD_STATIC)
~~~

**METHOD**:

Value | Name                 | Meaning
------|----------------------|---------
0     | `IP_METHOD_DISABLED` | The family is not used on the link
1     | `IP_METHOD_AUTO`     | DHCP
2     | `IP_METHOD_STATIC`   | The address, prefix, and gateway that follow

The default is `IP_METHOD_AUTO` so that a device with nothing configured
is on the network the moment it is associated; this layer exists for the
cases where that is not enough. A **PREFIX** above 32, a static form of
the wrong length, or a static address that is not usable in the sense
`PROP_IPV4_STATE` defines, `169.254/16` included, is refused with
`STATUS_INVALID_ARGUMENT`. A **GATEWAY** is either all-zero or a unicast
address that is not multicast, broadcast, loopback, or link-local, and
anything else is refused the same way; the IPv6 form relaxes the last
exclusion, since a router names itself by its link-local address and a
static IPv6 gateway is usually exactly that. All-zero means
no default route, which is what a device on a network with no way out
should be told.

A write takes effect at once. On a device that is `IP_READY` under the
old configuration, the old address is released and the new one applied,
and `PROP_IPV4_STATE` reports the transitions like any other. A write
while the link is down is accepted and waits for it, so a static
configuration can be staged before the station is enabled.

#### PROP 4898: `PROP_IPV4_ADDRESS`

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_IPV4`
* Value Type: 4-octet address, 1-octet prefix, 4-octet gateway; or empty
* Post-Reset Value: the address in effect; empty when the family is not `IP_READY`

The IPv4 address the interface holds, its prefix length, and the default
gateway, all-zero when there is none. Whatever the method: under
`IP_METHOD_AUTO` this is what the lease said, under `IP_METHOD_STATIC`
it is what was written, once the device holds it.

Published whenever the reported value changes. Mostly that is when
`PROP_IPV4_STATE` moves, but not only then: a lease renewal can keep the
address and change the gateway, and a host that read the value once and
watched only the state would carry the old gateway forever. A renewal
that changes nothing publishes nothing.

#### PROP 4899: `PROP_IPV6_STATE`

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_IPV6`
* Value Type: UINT8
* Post-Reset Value: what the family is doing

IPv6 readiness, from the enumeration `PROP_IPV4_STATE` defines, with the
same publication rule and the same meaning for every value. The one
family-specific note is the link-local boundary: a device holding only
an `fe80::` address is `IP_WAITING`, because it is waiting for exactly
the advertisement that would give it a usable one.

Two properties rather than two octets in one, because the capabilities
are two: a device without `CAP_IPV6` would otherwise carry an octet
describing a family it does not have, and a property granted by "either
capability" is a property with two homes. One octet per family costs a
second notification when a link drop takes both families down, which
is one small frame at a moment the host is already being told things.

#### PROP 4900: `PROP_IPV6_CONFIG`

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_IPV6`
* Value Type: as `PROP_IPV4_CONFIG` with 16-octet addresses
* Post-Reset Value: `IP_METHOD_AUTO`, or restored from saved state

The same structure and the same methods, with 16-octet addresses and a
prefix of at most 128. A static address that is not usable in the sense
`PROP_IPV6_STATE` defines, link-local, multicast, loopback, or
unspecified, is refused with `STATUS_INVALID_ARGUMENT`; a static
address that is usable but already held on the link is accepted and
reported as `IP_CONFLICT`. `IP_METHOD_AUTO` means router
advertisements, and DHCPv6 where the router asks for it; which of those
produced an address is not reported, because a host has nothing to do
with the difference.

A device **MUST** hold a stable address and report only stable
addresses. It **MAY** additionally use temporary addresses for the
traffic it originates, which is the arrangement RFC 8981 describes for
a host that is reached at one address and reaches out from others, and
those are never reported: they exist to rotate, and a reported address
is one somebody wrote down.

#### PROP 4901: `PROP_IPV6_ADDRESSES`

* Type: Multiple-Value, Read-Only
* Has Item Length Prefix: Yes
* Asynchronous Updates: Yes
* Required: `CAP_IPV6`
* Post-Reset Value: what is in effect; empty when the family is not `IP_READY`

The usable IPv6 addresses the device holds, and the default router it
has selected. Each item is a kind octet and a kind-defined body:

Kind | Name             | Body
-----|------------------|------
0    | `IPV6_ADDRESS`   | 16-octet address, 1-octet prefix length
1    | `IPV6_ROUTER`    | 16-octet router address

A set rather than one address, because an IPv6 interface normally holds
several, a global one and a unique-local one from separate prefixes,
say, and which of them the device uses as a source depends on where the
packet is going; there is no one answer to "the device's address," only
"the addresses the device is reachable at," which is what a host
displaying or dialing it needs. Stable addresses only, per the
configuration above. The link-local address is not among them, for the
reason it does not make the family ready. The router items are the
stack's default router list, every router it currently retains from
those advertising, and none when there is none; a list rather than one,
because a stack keeps several and may send to different destinations
through different ones, so no single router describes the routing.

The prefix length is the one the address's assignment carried: the
advertised prefix an autoconfigured address was formed from, or the
prefix written for a static one. An address assigned by DHCPv6 reports
128, and 128 means the assignment carried none, not that the link is a
`/128`: DHCPv6 assigns addresses, not prefixes, and the on-link prefixes
a router advertises alongside are routing state that is not encoded
here.

A device bounds the set to what its stack holds, which for an embedded
stack is a few addresses and a few routers, and the bound **MUST** keep
the complete value inside one frame on every transport the device
exposes, as every multi-value property here is bounded. Which entries a
stack keeps once a network offers more than it can hold is the stack's
business.

Published whenever the reported set changes: a prefix renumbered, a
router replaced or expired, an address added or withdrawn. Router and
prefix lifetimes are independent of one another and of the state, so
this property moves while `PROP_IPV6_STATE` stands still, and a host that
only watched the state would not learn.

#### PROP 4902: `PROP_IP_DNS`

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: Yes
* Asynchronous Updates: No
* Required: `CAP_IPV4` or `CAP_IPV6`
* Item Form: a 4-octet IPv4 or 16-octet IPv6 resolver address
* Remove Selector: the address
* Post-Reset Value: Empty, or restored from saved state

The resolvers the device is to use. **Empty**, the default, means the
ones the network provided, by DHCP or router advertisement. Non-empty,
these **replace** the network's rather than join them, because a host
that configured resolvers meant those and a merged set would be neither
what it wrote nor what the network offered. An item of any other length,
or one that is not a unicast address, unspecified, multicast, broadcast,
loopback, is refused with `STATUS_INVALID_ARGUMENT`; an IPv6 resolver
**MAY** be link-local, as one advertised by a home router commonly is,
and an IPv4 one **MUST NOT** be. A device bounds the set,
**SHOULD** hold at least two, and refuses past its capacity with
`STATUS_NOMEM`.

The set is unordered, as every multi-value property is; a device asks
whichever it likes first.

Static addressing without this is a device that cannot resolve a name,
which is why the two are written together.

#### PROP 4903: `PROP_IP_RESOLVERS`

* Type: Multiple-Value, Read-Only
* Has Item Length Prefix: Yes
* Asynchronous Updates: Yes
* Required: `CAP_IPV4` or `CAP_IPV6`
* Item Form: as `PROP_IP_DNS`
* Post-Reset Value: the resolvers in use; empty when there are none

What the device is resolving with right now: the configured set when
`PROP_IP_DNS` is non-empty, otherwise what the network handed it, and
empty when neither has given it anything. Published whenever the set
changes, for the same reason the addresses are: a router advertisement
carries resolvers with lifetimes of their own and can add one, replace
one, or withdraw one with a zero lifetime, all without the family
leaving `IP_READY`. Bounded as `PROP_IPV6_ADDRESSES` is, to what the
stack holds and to one frame; a stack that keeps two or three resolvers
is the norm, and a network offering more than that is offering more
than the device will ask.

Chiefly a diagnostic, and the one that distinguishes "the device is on
the network and cannot resolve the server's name" from every other way a
tunnel fails to come up.

### Alongside the Station

In practice the two layers meet at exactly one property on each side:
`PROP_WIFI_LINK` says whether there is a link, and `PROP_IPV4_STATE` and
`PROP_IPV6_STATE` say what each family has made of it. The address and
resolver properties are
read after one of those two has moved and followed thereafter, since
each publishes its own changes.

**The stack follows the link.** While `PROP_WIFI_LINK` is anything but
`WIFI_LINK_UP`, every enabled family is `IP_NO_LINK` and both address
properties are empty. When the link comes up, each enabled family goes
to `IP_WAITING` and then, as the network answers, to `IP_READY`; a
static family skips the wait except for the duplicate-address check,
which ends in `IP_READY` or `IP_CONFLICT`.
When the link drops, everything goes back to `IP_NO_LINK` and the
addresses empty with it, learned resolvers included. A roam to another
access point of the same network is the same link and does not disturb
the stack; a device **MUST NOT** release its addresses over a roam.

**Publication order** is link first, then stack, in both directions: on
the way up, `PROP_WIFI_LINK` carrying `WIFI_LINK_UP`, then
each family's state for each transition as it happens; on the way down,
`PROP_WIFI_LINK` leaving `WIFI_LINK_UP`, then each family's state
carrying `IP_NO_LINK`. A host that sees `IP_READY` then reads the addresses it
wants and keeps them current from their own notifications; one that
sees `IP_WAITING` persist while the link is up knows the problem is the
network and not the radio, and one that sees `IP_CONFLICT` knows it is
the configuration.

**Disabling the station** reports `IP_NO_LINK`, not `IP_DISABLED`. The
second is the family's own switch, written in its configuration, and a
host that turned the radio off did not turn IPv6 off.

**Configuration is staged in any order.** The IP configuration properties
are writable while the link is down and while the station is disabled,
and they are ordinary `CMD_PROP_SET` targets, so a static commissioning
is one `CMD_PROP_MULTI_SET` where `CAP_CMD_MULTI` is present:
`PROP_IPV4_CONFIG`, `PROP_IP_DNS`, `PROP_WIFI_NETWORK`,
`PROP_WIFI_ENABLED`, in that order, then `CMD_SAVE`. The network insert
still stands apart, being an insert.

**Synchronizing on attach** adds the family states to the station's
read: `PROP_WIFI_ENABLED`, `PROP_WIFI_NETWORK`, `PROP_WIFI_LINK`,
`PROP_IPV4_STATE`, and `PROP_IPV6_STATE`, in one `CMD_PROP_MULTI_GET`,
where a family the device lacks comes back as the `STATUS_PROP_NOT_FOUND`
entry the multi-get already provides for. Between them a host knows
whether the device is configured, associated, and addressed without a
second round trip.

**Reconfiguring a live device** is a write and a watch: the device
applies the new configuration at once, the family leaves `IP_READY` and
arrives wherever the new configuration leads, `IP_READY` again by way of
`IP_WAITING`, `IP_CONFLICT` for a static address somebody else holds, or
`IP_DISABLED`, and a host that changed a static address learns the old
one is gone by the same notification everyone else does.

**The host name** the device presents to DHCP, and to DHCPv6 where it
runs, **SHOULD** be derived from `PROP_DEV_NAME`, folded to a valid
label, so the device can be found on a router's client list under the
name its operator gave it. That is a sentence, not a property, and this
is where the sentence lives.

**What survives what** extends the station's table by one rule: the
three configuration properties are saved and revert; the five live ones
follow. `CMD_RST` on a device whose snapshot matches its live IP
configuration leaves a lease in place; one that reverts a static address
releases and re-applies, with the transitions published.

**Over the node management binding,** all eight are device-domain: an
administrator may read every one and write the three configuration
properties, the other five being read-only for everybody. That binding
carries no unsolicited notifications, so the read-then-follow flow above
does not apply across the mesh: an administrator that wants a current
view of addresses or resolvers reads them again, and the family states
tell it when that is likely to be worth doing. An
administrator who writes a
static address that is wrong for the network has stranded a bridge just
as surely as one who disabled the station, and the same warning belongs
in the same place.

**Not here, and where it went:** a reachability test is command-shaped
and unnecessary, since a bridge client reports whether its tunnel is up
and that is the reachability anyone cares about; time from the network
belongs to the time capability, which would gain a trust switch shaped
like `PROP_GNSS_TIME_TRUST` if it takes SNTP; a second interface is a
selector for a later revision; and mDNS, which would let a phone find
the device by name, is a service the device offers rather than a
property of its stack, and waits for whatever first needs it.

## Security

* The passphrase crosses the link once, inbound, over a transport that
  meets the provisioning requirement, and is never reported. A later host
  on the same device cannot extract an earlier host's Wi-Fi credentials
  any more than its channel keys.
* The security mode is exact. A device joins with the mode the entry
  names and no other, whatever the network in front of it advertises, so
  a downgrade has to be written by the host, not offered by the air.
* Scan results are what the device heard, and an SSID is what its sender
  chose to call itself. A host displays them as untrusted strings.
* A device on Wi-Fi is a device on a LAN. This sketch gives it an
  address and nothing that listens on one. Any service the device later offers
  over the interface, a ULCP binding over TCP above all, carries the
  full authority of an attached host and needs an admission ceremony of
  its own before it exists; the serial transports' physical-possession
  argument does not extend to a network port.
* `PROP_WIFI_MAC` and the SSIDs in the table are identifying. They are
  no more so than `PROP_DEV_NAME`, and they are readable only by a party
  that has already been admitted.
* The IP stack trusts its network the way every client does: a rogue
  DHCP server or router advertisement on the LAN can hand the device a
  bad address, a bad route, or a resolver that lies. Nothing at this
  layer defends against that, and nothing needs to, because what rides
  on the address authenticates its far end itself: the bridge tunnel
  pins a key, and a redirected tunnel fails to open rather than opening
  to the wrong party.

## Not In This Sketch

Deliberately absent, with the reason:

* **Access-point mode** and any provisioning flow that depends on it. A
  different interface with different state; if it comes, it is its own
  capability in the reserved identifiers.
* **Enterprise authentication.** Certificates and identities are a
  provisioning surface an order of magnitude larger than a passphrase.
  The three enterprise modes have numbers so scan results can name them
  and a host can explain why a network is grayed out; the credential
  forms come with the capability that opens them.
* **Negotiation details.** Management frame protection, SAE
  hash-to-element, transition-disable: the device does what the mode
  requires and the host never sees them. WPS and Easy Connect are
  provisioning methods rather than modes, and a screenless device may
  want the latter one day.
* **Auto-join across the table.** See [Model](#model).
* **Regulatory country.** The station's channel set follows the
  platform's regulatory configuration, which may later be tied to the
  device's region; nothing here decides that.
* **Power-save mode, PHY rate, band preference.** The device's business.
  A property that exposes them is easy to add and hard to remove.
* **What the connection is for.** Bridge client configuration, a time
  source, a local binding: each is a capability of its own that
  requires `CAP_IPV4` or `CAP_IPV6` and is specified when built. IP addressing itself is
  no longer absent; see [IP Connectivity](#ip-connectivity).

## Index Additions

For [`ulcp-index.md`](protocol/src/ulcp-index.md) when this lands:

* Capabilities 53 `CAP_WIFI`, 54 `CAP_IPV4`, and 55 `CAP_IPV6`.
* Properties 4880–4887 as tabled above; 4888–4895 reserved.
  Properties 4896–4903 for IP connectivity; 4904–4911 reserved.
  `PROP_WIFI_SCAN_RESULTS` is the first property to publish
  `CMD_PROP_INSERTED` unsolicited, which the core chapter already
  provides for; its note on "Asynchronous Updates" is phrased around
  `Is` and should say `Inserted` too.
* Enumerations: security modes (`WIFI_SEC_*`), link states
  (`WIFI_LINK_*`), link reasons (`WIFI_REASON_*`), IP family states
  (`IP_*`), IP configuration methods (`IP_METHOD_*`), IPv6 address item kinds (`IPV6_*`).
* No commands and no new status codes. One existing status broadens:
  `STATUS_ITEM_NOT_FOUND` is defined for an unmatched `CMD_PROP_REMOVE`
  and gains the `CMD_PROP_SET` case where a written value names an item
  of another property that does not exist, as `PROP_WIFI_NETWORK` uses
  it.
