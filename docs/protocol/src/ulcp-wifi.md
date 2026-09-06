# ULCP: Wi-Fi

Wi-Fi control is the subsystem the host uses to configure and observe a
device's 802.11 hardware. It covers three functions, each its own
capability, because the hardware that has one does not always have the
others:

* **Scanning**, listening for access points and reporting what was
  heard. Every Wi-Fi receiver can do this, including ones that can do
  nothing else.
* **The station**, joining a network the device is given and staying on
  it.
* **The access point**, offering a network of the device's own for
  other stations to join.

This chapter specifies the interface, not what the connection carries.
Addressing is [IP Connectivity](ulcp-ip.md); a bridge tunnel, a time
source, or a binding a client could attach through is a capability of
its own.

Everything here is [device-domain](ulcp-core.md#device-domain) state.
The configuration properties, the two switches, the network table, the
selection, and the access point's network, are part of a [saved
snapshot](ulcp-saved-state.md#saved-state) and survive a change of
host. The rest is live: what a scan found, what the link is doing, who
is on the access point. Live state is never saved, and `CMD_RST`
reaches it only through the configuration it reverts, so each live
property's post-reset value is declared as whatever the fact is at the
time.

A device with a station and a network selected tries to be on that
network whenever it is enabled, with no host present and none ever
required. That is why nothing here is a command: a device on Wi-Fi is
infrastructure, and infrastructure that needs a phone to get back on
the network after a power cut is not.

## Capabilities {#capabilities}

Code | Name            | Requires        | Grants
-----|-----------------|-----------------|--------
53   | `CAP_WIFI_SCAN` | —               | A Wi-Fi receiver the device can scan with: `PROP_WIFI_SCANNING`, `PROP_WIFI_SCAN_RESULTS`
54   | `CAP_WIFI`      | `CAP_WIFI_SCAN` | A Wi-Fi station the device can enable and join networks with: `PROP_WIFI_ENABLED`, `PROP_WIFI_NETWORKS`, `PROP_WIFI_NETWORK`, `PROP_WIFI_LINK`
57   | `CAP_WIFI_AP`   | `CAP_WIFI_SCAN` | An access point the device can bring up: `PROP_WIFI_AP_ENABLED`, `PROP_WIFI_AP_CONFIG`, `PROP_WIFI_AP_STATE`, `PROP_WIFI_AP_CLIENTS`

Three capabilities on one base, and everything else discovered by
asking. The scan is the base because it is what every Wi-Fi radio can
do: a station that can join can always scan, and so can a radio that
can beacon, so both requiring `CAP_WIFI_SCAN` is a fact about hardware
rather than a policy, and the rule that a device
[advertises](ulcp-conformance.md#optional-subsystems) what its
capabilities require does the rest.

The station and the access point do not require each other. Nearly
every chip does both, but they are different functions with different
state, and a device that has one and not the other is describable. A
device advertising any of the three **MUST** serve every property it
grants.

The two remaining station properties, `PROP_WIFI_RSSI` and
`PROP_WIFI_MAC`, report things a stack may not expose, and a device
that only scans has neither. A device that cannot answer them answers
`STATUS_PROP_NOT_FOUND`, in the same exchange the host was already
making, for the reason the [BLE binding](ulcp-ble.md#capabilities)
gives: a refusal is a complete answer, and a second capability buys a
host nothing it cannot learn in the reply it is already waiting for.

None of the three requires `CAP_SAVE`. Without it the configuration is
volatile and the device knows no networks after a power cycle, which is
a worse device but a conforming one.

## Properties {#properties}

Allocated from the extended device and transport configuration range:
the station and its scan in a block of sixteen after the BLE
transport's, the access point in a block after
[IP Connectivity](ulcp-ip.md#properties), so that neither the station
nor the stack has to move to make room.

Id   | Mnemonic                 | Commands                   | Description
-----|--------------------------|----------------------------|-------------
4880 | `PROP_WIFI_ENABLED`      | Get, Set, Is               | Whether the station is up
4881 | `PROP_WIFI_NETWORKS`     | Get, Set, Insert, Remove   | Known networks and their credentials
4882 | `PROP_WIFI_NETWORK`      | Get, Set, Is               | The selected network, or empty
4883 | `PROP_WIFI_SCANNING`     | Get, Set, Is               | Whether a scan is in progress
4884 | `PROP_WIFI_SCAN_RESULTS` | Get, Is, Inserted          | What the current or last scan has found
4885 | `PROP_WIFI_LINK`         | Get, Is                    | Link state, failure reason, and association
4886 | `PROP_WIFI_RSSI`         | Get                        | Signal of the current association
4887 | `PROP_WIFI_MAC`          | Get                        | The station's MAC address
4912 | `PROP_WIFI_AP_ENABLED`   | Get, Set, Is               | Whether the access point is up
4913 | `PROP_WIFI_AP_CONFIG`    | Get, Set                   | The network the device offers
4914 | `PROP_WIFI_AP_STATE`     | Get, Is                    | Whether it is beaconing, and where
4915 | `PROP_WIFI_AP_CLIENTS`   | Get, Is, Inserted, Removed | Who is on it

4888 through 4895 are reserved for the station, and 4916 through 4927
for the access point.

### PROP 4880: `PROP_WIFI_ENABLED` {#prop-wifi-enabled}

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_WIFI`
* Value Type: BOOL
* Post-Reset Value: 0 (false), or restored from saved state

Whether the station is up. Cleared, the device **MUST** drop any
association, abandon any scan in progress, and put the station into the
lowest power state the platform offers. This is `PROP_GNSS_ENABLED`'s
promise rather than `PROP_BLE_ENABLED`'s: on a battery-powered node a
Wi-Fi radio that is merely idle is still the largest load on the board,
and a property that only stopped reporting would solve nothing.

Set again, the device comes back up and, if a network is selected,
starts joining it. The known-network table and the selection are
configuration and are not disturbed in either direction, so turning the
station off and on is not a way to forget anything.

Off by default, for the reason `PROP_GNSS_ENABLED` is: a device that
has never been given a network has nothing to spend the power on. Saved
state overrides the default, which is how a commissioned device comes
up connected.

Asynchronous because a device with a screen **MAY** offer the switch on
it, and a switch someone can flip is a value that moves without the
host asking.

A write of `1` answers `STATUS_INVALID_STATE` on a platform that cannot
run the station alongside another radio it currently has on, the
device's own access point included. The device **MUST NOT** take the
other radio down to honor the write; the host turns that one off first.
A platform that coexists, which is most of them, answers the write like
any other.

### PROP 4881: `PROP_WIFI_NETWORKS` {#prop-wifi-networks}

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
   1 B      1 B        1 B      1-32 B    security-defined
~~~
Figure: Known-network item format

**FLAGS** bit 0 set means the network hides its SSID and the device
probes for it by name rather than waiting to hear it. Bit 1 set means
the credential is a raw 32-octet pairwise master key rather than a
passphrase, which is valid only for the modes that derive one; a host
that holds the key need never hand the device the passphrase, and a
device never has to run the derivation. Bits 2 through 7 are reserved
and **MUST** be zero.

**SECURITY** is one mode:

Value | Name                    | Credential
------|-------------------------|------------
0     | `WIFI_SEC_OPEN`         | none
1     | `WIFI_SEC_OWE`          | none
2     | `WIFI_SEC_WPA2`         | passphrase of 8-63 octets, or a key
3     | `WIFI_SEC_WPA3`         | password of 1-128 octets
4     | `WIFI_SEC_WPA`          | passphrase of 8-63 octets, or a key
5     | `WIFI_SEC_WEP`          | none defined
6     | `WIFI_SEC_WPA2_ENT`     | none defined
7     | `WIFI_SEC_WPA3_ENT`     | none defined
8     | `WIFI_SEC_WPA3_ENT_192` | none defined

Values 9 through 15 are reserved. Sixteen is the ceiling because
[`PROP_WIFI_SCAN_RESULTS`](#prop-wifi-scan-results) reports these as a
16-bit set.

`WIFI_SEC_OPEN` is no security at all. `WIFI_SEC_OWE` is Enhanced Open:
encrypted against anyone listening, authenticated against nobody, with
no credential, and the only credential-free mode permitted on 6 GHz.
An OWE entry names the network as the operator sees it. Where that is a
plain OWE network the device joins it; where it is the visible half of
an OWE transition deployment, the device follows the transition element
to the hidden companion BSS and joins that. `PROP_WIFI_LINK` then
reports the companion's BSSID and frequency, which is all it ever
reports of any association, while `PROP_WIFI_NETWORK` goes on naming
the visible network the operator selected. The entry never names the
companion, because the operator never saw it.

`WIFI_SEC_WPA2` is WPA2-Personal and covers the WPA/WPA2 mixed networks
that negotiate CCMP; `WIFI_SEC_WPA` is the TKIP-only remainder, which a
device **MAY** decline to join. `WIFI_SEC_WPA3` is WPA3-Personal, SAE,
whose password is not a WPA2 passphrase: SAE puts no bounds on it, so
the 8 to 63 rule does not apply, and the table admits up to 128 octets,
which is where the more generous stacks stop. A device whose stack
holds a shorter limit refuses a longer password with
`STATUS_UNIMPLEMENTED`, since the entry is well-formed and the device
is what cannot hold it. A password shared with a transition network's
WPA2 side is 8 to 63 octets by that side's rule, which is the host's to
know.

The remaining four exist so that scan results can say what they heard.
WEP is not worth a credential form, and the three enterprise modes are
a provisioning surface this chapter does not open; they are numbered so
that opening it later renumbers nothing.

A passphrase or password is the UTF-8 encoding of what the operator
typed, with no terminator and no U+0000, and its length bounds count
octets. The device **MUST** derive keys from exactly those octets: the
PBKDF2 of 802.11 Annex J for `WIFI_SEC_WPA2` and `WIFI_SEC_WPA`, and
SAE over the octets directly. An ASCII passphrase therefore yields what
every router yields, and a non-ASCII one yields what a router that
accepted UTF-8 yielded. In both cases the host's job is to hand over
the same octets the router's operator entered, and the device's is not
to reinterpret them. A raw key, `FLAGS` bit 1, is exactly 32 octets and
skips the derivation.

An insert is refused with `STATUS_INVALID_ARGUMENT` when it is not
well-formed: an empty SSID, a mode with no credential form, a
credential of the wrong length or kind for its mode, a reserved mode, a
reserved flag bit set. The SSID is never empty because an empty
`PROP_WIFI_NETWORK` means no selection, so an entry with no name could
be stored and never chosen; a hidden network has a real name, and it is
only the advertisement that is blank. An insert is refused with
`STATUS_UNIMPLEMENTED` when it is well-formed and this device cannot do
it: a WPA3 entry on a chip without SAE, or a WPA entry on a device that
declines TKIP. The two are different answers because a host acts on
them differently. The first is a bug in the host, and the second is a
reason to pick the next mode the network offers.

The security mode is exact. It is the mode the device uses, not a
ceiling it negotiates down from. An entry marked `WIFI_SEC_WPA3` joins
a WPA2/WPA3 transition network with SAE and fails against a WPA2-only
one; an entry marked `WIFI_SEC_WPA2` joins either with PSK; an entry
marked `WIFI_SEC_OWE` never falls back to open. A device **MUST NOT**
negotiate a mode other than the one the entry names, so a host that
takes the mode out of a scan result gets exactly the network it saw,
and an evil twin advertising a weaker one gets nothing. Where the
passphrase is the same across a transition network's modes, which it
usually is, the host writes the strongest one the device accepts.

Items are keyed by SSID: the table holds at most one entry per network,
and an insert whose SSID matches an existing entry **replaces** it and
reports the item as inserted. That is the path for a wrong passphrase,
a changed one, or a mode upgrade, and it never needs a remove. The
SSID is octets, not text, and a device compares it bytewise. A
whole-table `CMD_PROP_SET` carrying two entries with the same SSID is
refused with `STATUS_INVALID_ARGUMENT` before anything changes, under
[Mutation Atomicity](ulcp-core.md#mutation-atomicity): the value is an
unordered set, so neither entry has standing to win, and a host that
wrote both did not mean either.

The credential is write-only, under the rules of [Provisioning
Security](ulcp-core.md#provisioning-security). The reported form is the
item through its SSID, and neither `CMD_PROP_GET` nor any notification
ever carries a passphrase. This is why replacing an entry is the only
way to change its credential: a host cannot read one back to compare
it. Writes that carry a credential are subject to the same transport
requirement as key material.

A device bounds the table and refuses an insert past its capacity with
`STATUS_NOMEM`. Four entries is enough for anything a device of this
class does, and a device **SHOULD** hold at least that many. The bound
**MUST** also keep the complete reported table, every entry in its
redacted form, inside one frame on every transport the device exposes,
so that a `CMD_PROP_GET` always answers in one piece. At under forty
octets per reported entry that constrains nothing a device would want.

Removing the selected network, whether by `CMD_PROP_REMOVE` or a
whole-table `CMD_PROP_SET` that omits it, clears the selection: the
device drops the association, publishes `PROP_WIFI_NETWORK` as empty,
and publishes the link going down. Replacing the selected network's
entry drops any association it holds and starts a fresh join with the
new entry at once, because a host that has just corrected a passphrase
should not wait out a backoff to learn whether it worked.

The table is part of the saved snapshot, credentials included, which is
what lets the device rejoin unattended. `CMD_CLEAR` erases the
persisted copy with everything else and, as with everything else,
leaves the live table alone: the device stays on its network until the
`CMD_RST` that completes a factory reset reverts the table to its
now-empty post-reset value. A device advertising `CAP_SAVE` stores it
as it stores key material.

### PROP 4882: `PROP_WIFI_NETWORK` {#prop-wifi-network}

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_WIFI`
* Value Type: 1 to 32 octets (an SSID), or empty
* Post-Reset Value: Empty, or restored from saved state

The network the device is on, or is to be on: the SSID of one entry in
[`PROP_WIFI_NETWORKS`](#prop-wifi-networks). This is "connect" and
"disconnect" both.

Writing an SSID selects that network. If the station is enabled, the
device drops any current association and starts joining the new one; if
it is not, the selection waits for it, so a whole configuration can be
staged and the station enabled last. Writing the SSID that is already
selected changes nothing and disturbs nothing, like any other property
written with its own value.

An SSID not in the table is refused with `STATUS_ITEM_NOT_FOUND`: the
credential lives in the table, and the selection only names it. A host
acts on that differently from `STATUS_INVALID_ARGUMENT`, one being
"insert it first" and the other a bug.

Writing the **empty** value deselects. The device leaves the network
and associates with nothing until something is selected again. This is
a stable state, not a moment: the station stays up, scans on request,
and joins nothing, which is what a phone with Wi-Fi on and no network
in range is doing. A device **MUST NOT** select a network on its own,
because a disconnect the device undoes by itself is not one.

The device **MUST** publish the property when it changes it: a removal
from the table that empties the selection, or a picker on the device's
own screen.

The selection is the network the device will spend its unattended life
trying to reach, so it is saved with the table. A device restored from
a snapshot comes up joining what it was joining.

### PROP 4883: `PROP_WIFI_SCANNING` {#prop-wifi-scanning}

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_WIFI_SCAN`
* Value Type: BOOL
* Post-Reset Value: whether a scan is running

Whether a scan is in progress. Writing `1` starts one; the device
answers with `1`, reports each access point as it is heard through
[`PROP_WIFI_SCAN_RESULTS`](#prop-wifi-scan-results), and publishes `0`
when the scan completes. Writing `0` abandons a scan in progress and
leaves in the results whatever had been found by then.

The frames of a scan **MUST** go out in this order, so that a host can
never misattribute one:

1. `CMD_PROP_IS` for `PROP_WIFI_SCAN_RESULTS` carrying the empty value:
   the previous results are gone.
2. `CMD_PROP_IS` for this property carrying `1`, as the reply to the
   host's write or unsolicited when the device started the scan itself.
3. One `CMD_PROP_INSERTED` per access point heard, in the order heard.
4. `CMD_PROP_IS` for this property carrying `0`, after the last of them.

The clear goes first so that every insert lands in a table the host
knows to be empty, and the completion goes last so that a host seeing
`0` holds the whole list without reading it.

This is a [pairing window](ulcp-ble.md#prop-ble-pairing)'s shape
exactly: a state the host can enter, that ends by itself, and that a
device with a screen can enter without the host. A device **MUST**
bound a scan's duration; a few seconds is what the hardware takes.

On a device with a station, a write of `1` answers
`STATUS_INVALID_STATE` while the station is disabled, and **MAY**
answer `STATUS_BUSY` while a join is in the middle of its handshake,
which resolves by itself. On a device without one there is nothing to
enable: the receiver is powered for the scan's duration and put back to
sleep after, which is the right power shape for a tracker that scans a
few times an hour. Writing `1` during a scan succeeds and answers `1`;
there is nothing to restart. A write of `0` always succeeds.

A device **MAY** scan while associated, at the cost of the
association's traffic while it is off-channel. Whether the scan is
active or passive, and on which channels, is the device's business,
except that a device with a station **MUST** probe by name for a hidden
network in its table so that it can appear.

A scan the device starts from its own menu is reported the same way,
inserts and all. An attached host pays twenty-odd small frames once per
scan, which is nothing against the scan itself, and a picker that
appears as networks are heard is the difference between a list that
fills in and a spinner.

### PROP 4884: `PROP_WIFI_SCAN_RESULTS` {#prop-wifi-scan-results}

* Type: Multiple-Value, Read-Only
* Has Item Length Prefix: Yes
* Asynchronous Updates: Yes (`Is`, `Inserted`)
* Required: `CAP_WIFI_SCAN`
* Post-Reset Value: what the receiver has found; empty after a power-on

What the scan in progress has found so far, or what the last one found.
Each item:

~~~
+-------+-----------+------+--------+-----------+
| MODES | FREQUENCY | RSSI | BSSID  |  SSID ... |
+-------+-----------+------+--------+-----------+
  2 B     2 B, MHz    1 B     6 B      0-32 B
~~~
Figure: Scan result item format

**MODES** is a 16-bit little-endian set of the security modes the
access point offers, bit *n* standing for mode *n* of the enumeration
above. **No bits at all** means the device did not determine them: a
receiver that reads beacon headers for their addresses has no reason to
parse the security elements, and no real access point offers nothing,
so the empty set is free to mean that.

A WPA2/WPA3 transition network sets both bits. An OWE transition
network is two BSSs, a visible open one and a hidden OWE companion that
the open one's transition element names by BSSID and SSID; the device
reads the element and reports the **visible** BSS with both the open
and the OWE bit set, so the host sees one network offering two modes
and picks between them like any other. The companion is reported as
itself, under the SSID the element gave it, and nothing depends on it.
A set rather than a single strongest value, because which of the
offered modes the host should write depends on what the device can do,
and the scan result is not the place to guess: the host writes the
strongest bit it likes and steps down on `STATUS_UNIMPLEMENTED`.

**FREQUENCY** is the center frequency of the access point's **primary**
20 MHz channel, in megahertz, little-endian. A frequency rather than a
channel number because a channel number is ambiguous across bands and a
frequency is not, and the number follows from the frequency in one line
wherever a display wants it. The width of the operating channel is not
reported: the device negotiates it at association, and nothing about it
is needed to join.

**RSSI** is a signed dBm. **SSID** is the remainder of the item, and
empty means no name was reported, because the network hides it or
because the scanner does not read names; the BSSID is what
distinguishes one nameless entry from the next. A device with a station
always reads names, so on such a device empty means hidden. A picker
treats the two alike in any case, since neither can be chosen by name.

One item per access point, keyed by BSSID, and never the device's own:
a device that is also an access point **MUST NOT** report itself. The
device reports what it heard and nothing it inferred. Which of several
access points make up one network is a question the host answers by
grouping on SSID, and a host that wants the list a phone shows
coalesces, keeps the strongest per name, and sorts. A host that wants
to see every radio in the building has that too. Hidden networks need
no special case, since an access point with no name still has an
address.

The device reports each access point with `CMD_PROP_INSERTED` as it is
heard, and hearing one again is another `CMD_PROP_INSERTED` under the
same BSSID, which **replaces** the host's entry. Replacement by key is
what makes the inserts idempotent, and idempotence is what makes it
safe for a host to read the table mid-scan and follow the inserts from
there: an item that arrives in both the reply and a notification is the
same item twice.

The device retains a bounded table and reports an unbounded scan. Every
access point heard is inserted; the device keeps the strongest of them
up to its bound, evicting the weakest as stronger ones arrive, and
**never** reports an eviction. The bound **MUST** be chosen so that the
whole retained value fits in one frame on every transport the device
exposes; on BLE that is the 512-octet reassembled frame, into which
twenty or so typical items fit. The inserts are one item each and never
approach it.

This is the one place the property model bends on purpose. A host that
followed the inserts holds a superset of what a `CMD_PROP_GET` returns:
everything the scan heard, against the strongest twenty the device
kept. It is harmless because nothing in the host's copy is invented,
every item in it was heard, and the two are reconciled by the clear at
the next scan. The alternative, a `CMD_PROP_REMOVED` per eviction,
would spend frames telling the host to stop showing an access point it
can see, in order to keep two views identical that nobody needs to
compare. Where removals do describe something a host wants, as they do
for [access point clients](#prop-wifi-ap-clients), they are sent.

`CMD_PROP_GET` returns the retained table strongest first. Inserts
arrive in the order the access points were heard, which is the order
the host receives them in and has no other meaning.

Delivering results as they are found is a promise about delivery, not
about pace. Most stacks hand back a scan only when it finishes; a
device gets progressive results by scanning a channel at a time, which
the usual scan interfaces allow and which costs a little total duration
for first results in a fraction of a second. A device that cannot do
that emits every insert at the end and conforms.

The value is cleared, and the empty value published with
`CMD_PROP_IS`, when a scan starts and when the station is disabled. A
list of what was in the air somewhere the device may no longer be is
worse than an empty one.

### PROP 4885: `PROP_WIFI_LINK` {#prop-wifi-link}

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
Figure: Link state format

**STATE**:

Value | Name                   | Meaning
------|------------------------|---------
0     | `WIFI_LINK_DOWN`       | Not trying: the station is off, or nothing is selected
1     | `WIFI_LINK_CONNECTING` | A network is selected and the device is not on it yet, or not any more
2     | `WIFI_LINK_UP`         | Associated

**REASON** says why the device is in `WIFI_LINK_CONNECTING` rather than
`WIFI_LINK_UP`, and is `0` in the other two states:

Value | Name                    | Meaning
------|-------------------------|---------
0     | `WIFI_REASON_NONE`      | No attempt has failed yet
1     | `WIFI_REASON_NOT_FOUND` | The network was not heard and did not answer a probe
2     | `WIFI_REASON_AUTH`      | The network rejected the credential
3     | `WIFI_REASON_REJECTED`  | The network refused the association for another reason
4     | `WIFI_REASON_LOST`      | The association was up and dropped
5     | `WIFI_REASON_OTHER`     | Something the device has no name for

`WIFI_LINK_UP` is an 802.11 statement: the station is authenticated and
associated. Whether the device has an address on the link it is now on
is a different layer's fact and belongs to the [family state
properties](ulcp-ip.md#prop-ipv4-state), which report it.

`WIFI_LINK_CONNECTING` is the whole of trying, including the waits
between attempts. While the station is enabled and a network is
selected, the device **MUST** retry indefinitely with backoff and
**MUST NOT** give up: a wrong passphrase is a device that retries a few
times an hour until someone fixes it, which costs nothing and is what
unattended infrastructure should do. `WIFI_LINK_DOWN` is reserved for
the two states in which the device is not trying at all, so that a host
reading `DOWN` knows the fix is configuration and a host reading
`CONNECTING` knows the fix is in the reason.

The device **MUST** publish the property on every change of state and
on every change of reason, and on nothing else. Retrying and failing
the same way again is not a transition and is not published, so a
device with a wrong passphrase reports `WIFI_REASON_AUTH` once, not
every attempt.

When `WIFI_LINK_UP`, the value carries the association: which access
point, and the center frequency of its primary channel in megahertz, as
in a scan result. A roam to another access point of the same network is
a change of value and is published.

Live state: **NOT** part of the saved snapshot, and `CMD_RST` reaches
it only as a consequence of reverting the configuration it follows.

### PROP 4886: `PROP_WIFI_RSSI` {#prop-wifi-rssi}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_WIFI`
* Value Type: INT8 in dBm, or empty
* Post-Reset Value: the current measurement; empty when the link is not up

The received signal strength of the current association, measured when
the property is read. Empty when the link is not up.

Kept out of `PROP_WIFI_LINK` for the reason `PROP_GNSS_LOCATION` is
kept quiet: a measurement that changes on every beacon has no business
in a property that is published on every change.
[`PROP_PHY_RSSI`](ulcp-radio.md#prop-phy-rssi) is the same split on the
LoRa side.

### PROP 4887: `PROP_WIFI_MAC` {#prop-wifi-mac}

* Type: Single-Value, Constant
* Asynchronous Updates: No
* Required: `CAP_WIFI`
* Value Type: 6 octets

The station's MAC address, as it appears to the access point. Constant
because a router's allow list is keyed on it, and a device that
randomized it would be reporting an address nobody can use.

### PROP 4912: `PROP_WIFI_AP_ENABLED` {#prop-wifi-ap-enabled}

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_WIFI_AP`
* Value Type: BOOL
* Post-Reset Value: 0 (false), or restored from saved state

Whether the access point is up. Set, the device beacons the configured
network, accepts stations onto it, and serves them addresses; cleared,
it **MUST** disassociate every client, stop beaconing, and release
whatever the access point held of the radio. The configuration is
untouched in both directions.

Off by default, and a write of `1` while
[`PROP_WIFI_AP_CONFIG`](#prop-wifi-ap-config) is empty answers
`STATUS_INVALID_STATE`. Together those two rules mean there is no
factory network: no default name a stranger can look up, no default
passphrase, and no open network a device falls back to because nobody
configured one. A device that has never been given a network to offer
offers nothing.

A write of `1` answers `STATUS_INVALID_STATE` on a platform that cannot
run the access point alongside a radio it currently has on, the station
included, and the device **MUST NOT** take the other down to honor the
write. A platform that runs both, which is most of them, answers the
write like any other.

Asynchronous for the reason every switch here is: a device with a
screen **MAY** offer it, and the device takes the access point down by
itself when its configuration is cleared.

### PROP 4913: `PROP_WIFI_AP_CONFIG` {#prop-wifi-ap-config}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_WIFI_AP`
* Value Type: structure below, or empty
* Reported Form: the structure with its credential omitted
* Post-Reset Value: Empty, or restored from saved state

~~~
+-------+----------+-------------+-----------+---------+--------+----------+--------+----------------+
| FLAGS | SECURITY | MAX_CLIENTS | FREQUENCY | ADDRESS | PREFIX | SSID_LEN |  SSID  | CREDENTIAL ... |
+-------+----------+-------------+-----------+---------+--------+----------+--------+----------------+
   1 B      1 B         1 B        2 B, MHz     4 B       1 B       1 B      1-32 B  security-defined
~~~
Figure: Access point configuration format

**FLAGS**, **SECURITY**, **SSID_LEN**, **SSID**, and **CREDENTIAL** are
as in a [`PROP_WIFI_NETWORKS`](#prop-wifi-networks) item, with the same
encodings, the same well-formedness rules, and `STATUS_INVALID_ARGUMENT`
for the same faults. The modes an access point may offer are
`WIFI_SEC_OPEN`, `WIFI_SEC_OWE`, `WIFI_SEC_WPA2`, and `WIFI_SEC_WPA3`;
any other is refused with `STATUS_INVALID_ARGUMENT`, because no
credential form for offering it is defined here, and a device without
SAE refuses `WIFI_SEC_WPA3` with `STATUS_UNIMPLEMENTED` as it does in
the table. A hidden network beacons without its name and answers probes
for it; the flag is a courtesy to neighbors' pickers and not a secret,
since the name is in every association.

**MAX_CLIENTS** is how many stations the device admits at once, or `0`
for the device's own limit. A device bounds it to what its stack can
hold and to what keeps
[`PROP_WIFI_AP_CLIENTS`](#prop-wifi-ap-clients) in one frame, and
clamps a larger write to that bound rather than refusing it, reporting
the clamped value: the host asked for "many", and the device's most is
the honest answer.

**FREQUENCY** is the center frequency of the primary channel the access
point is to use, in megahertz, or `0` for the device's choice. It is a
preference, not a promise. A frequency the device may not use under its
regulatory configuration is refused with `STATUS_INVALID_ARGUMENT`, and
one it may use is what the access point beacons on **while the station
is not associated**. On hardware where the access point and the station
share one radio, and therefore one channel, the access point sits on
the station's channel while the station is up, whatever this field
says, and moves when the station roams.
[`PROP_WIFI_AP_STATE`](#prop-wifi-ap-state) reports where the access
point actually is.

**ADDRESS** and **PREFIX** are the device's own IPv4 address on the
network it offers and the prefix of that network, or all-zero and `0`
for the device's default, which **SHOULD** be `192.168.4.1/24` since
that is what a phone joining an embedded device has come to expect. The
device serves DHCP on this subnet, handing out addresses within the
prefix other than its own, and answers as the gateway and resolver a
lease names, whether or not it can forward anything. The prefix is 8 to
30. An address that is not a usable unicast address in the sense
[`PROP_IPV4_STATE`](ulcp-ip.md#prop-ipv4-state) defines, or one that
lies within the subnet the station holds, is refused with
`STATUS_INVALID_ARGUMENT`. IPv6 on the offered network is link-local
only, which needs no configuration and is not reported.

This is where the access point's addressing lives, and not in the
[IP Connectivity](ulcp-ip.md) properties, which describe the interface
the device joins a network with and only that. Those properties
configure how a device gets onto someone else's network; the access
point's subnet is not a configuration the network hands the device but
one the device imposes, it never changes without a write here, and a
fixed address in the same structure as the network it belongs to is the
shape every embedded access point already has.

The credential is write-only under [Provisioning
Security](ulcp-core.md#provisioning-security), and the reported form
stops at the SSID. This is a passphrase the operator hands to other
people, which makes a case for reading it back, and the case loses. The
reader is a party that could write any passphrase it liked, so reading
one back leaks nothing but the ability to rotate it without disturbing
clients; a device with a screen **MAY** show it or a QR code for it;
and one rule for every credential on the device is worth more than that
convenience. It follows that every write of a secured configuration
carries its credential, since there is nothing to leave in place.

A write takes effect at once. While the access point is up, the device
disassociates every client, brings the network up again under the new
configuration, and publishes the client list going empty; a client that
knows the new credential rejoins on its own. Writing the **empty**
value clears the configuration and is refused with
`STATUS_INVALID_STATE` while the access point is enabled, so that no
write here ever takes the network down as a side effect. The host
disables it first.

Saved with the switch, credential included, so that a device
commissioned to offer a network offers it at every boot.

### PROP 4914: `PROP_WIFI_AP_STATE` {#prop-wifi-ap-state}

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_WIFI_AP`
* Value Type: structure below
* Post-Reset Value: what the access point is doing

~~~
+-------+-----------+
| STATE | FREQUENCY |
+-------+-----------+
  1 B     2 B, MHz
        (present only when STATE is WIFI_AP_UP)
~~~
Figure: Access point state format

**STATE**:

Value | Name           | Meaning
------|----------------|---------
0     | `WIFI_AP_DOWN` | Not beaconing: disabled, unconfigured, or refused the radio
1     | `WIFI_AP_UP`   | Beaconing and accepting stations

**FREQUENCY** is the center frequency of the primary channel the access
point is beaconing on, which is the configured one while the station is
not associated and the station's while it is. This is the field the
property exists for: the configuration says what was asked, and only
the state says where the network actually is, which a host that wants
to tell a person which channel to expect has no other way to learn.

The device **MUST** publish it on every change of state and every
change of frequency, so that a station roam which drags the access
point to a new channel is reported, and on nothing else. Two states and
no reason, because every way of being down is readable from the two
configuration properties and the station's link, and a reason octet
would only quote them.

### PROP 4915: `PROP_WIFI_AP_CLIENTS` {#prop-wifi-ap-clients}

* Type: Multiple-Value, Read-Only
* Has Item Length Prefix: Yes
* Asynchronous Updates: Yes (`Is`, `Inserted`, `Removed`)
* Required: `CAP_WIFI_AP`
* Remove Selector: the MAC
* Post-Reset Value: the stations currently associated; empty when the access point is down

The stations on the device's network. Each item:

~~~
+-------+------+---------+
|  MAC  | RSSI | ADDRESS |
+-------+------+---------+
   6 B    1 B     4 B
~~~
Figure: Access point client item format

**MAC** is the client's, and the key. **RSSI** is a signed dBm as the
device last heard the client. **ADDRESS** is the IPv4 address the
device's DHCP server leased it, or all-zero until it has one, which is
what lets a host reach a client it can see.

The device publishes `CMD_PROP_INSERTED` when a station associates and
again, under the same MAC, when its address is leased or changes, which
replaces the host's entry as a scan result does; `CMD_PROP_REMOVED`
with the MAC when a station leaves or is dropped; and `CMD_PROP_IS`
with the empty value when the access point goes down. RSSI is reported
as it stood at the last of those and is not published on its own, under
the rule that keeps a beacon-rate measurement out of every published
property here.

This is the one multi-value property in this chapter that emits
`CMD_PROP_REMOVED`, and the difference from
[`PROP_WIFI_SCAN_RESULTS`](#prop-wifi-scan-results) is not a matter of
taste. The scan table withholds removals because they would describe an
eviction from a bounded view of an unbounded list, telling the host to
stop showing something real. A client leaving is a fact about the world
that the host wants, the list is bounded by `MAX_CLIENTS` to something
small, and the device's view and the host's are meant to be the same
view, so the ordinary property model applies without amendment. The
bound **MUST** keep the whole list in one frame, which at eleven octets
an item constrains nothing.

## Sharing the Radio {#sharing-the-radio}

**One radio, one channel.** Where the access point and the station are
two interfaces on one transceiver, the transceiver is on one channel.
While the station is associated the access point is on the station's
channel; when the station roams, the access point moves with it and its
clients drop and rejoin, which is a few seconds of disruption the
device did not choose and cannot avoid, and which
[`PROP_WIFI_AP_STATE`](#prop-wifi-ap-state) reports as a frequency
change. A host that needs the access point to stay put keeps the
station off, or on a network with one access point.

**A scan is a gap.** Scanning takes the transceiver off channel. Every
client of the access point loses its beacons for the duration, which
most stations tolerate and some do not, and an association loses its
traffic. On a device whose Wi-Fi receiver is its LoRa transceiver, a
scan is also a gap in mesh reception lasting as long as the scan does,
during which nothing on the air is heard and nothing is forwarded. The
host asked for that, and it is not free: a repeater's operator scanning
on a schedule is spending the mesh's reliability. A device **MAY**
answer `STATUS_BUSY` to a scan request rather than abandon a
transmission in progress or drop the clients it is serving.

**Enable in either order.** The two switches are independent, and a
platform that cannot run both refuses the second `1` with
`STATUS_INVALID_STATE` and leaves the first alone. Nothing about the
station's table, selection, or link changes when the access point comes
up or goes down, and nothing about the access point's configuration
changes with the station's.

**Forwarding is not specified.** Whether a client of the access point
can reach the network the station is on, and how, is a policy about
what the device does with its two interfaces. A device that forwards
nothing is a conforming access point, and a useful one to a phone that
only wants to reach the device.

**Regulatory.** The channel set follows the platform's regulatory
configuration, with one asymmetry: a station on the wrong channel is a
receiver that hears nothing, and an access point on the wrong channel
is a transmitter beaconing where it may not. A device advertising
`CAP_WIFI_AP` therefore **MUST** refuse a `FREQUENCY` outside its
regulatory configuration, and **MUST** choose within it when the field
is `0`.

## Host Procedures {#host-procedures}

The flows a host runs, in terms of the properties above. None of them
needs anything the property grammar does not already provide.

**Turn on.** Write `PROP_WIFI_ENABLED` to `1`. If a network is
selected, `PROP_WIFI_LINK` publishes `CONNECTING` and then `UP` or a
reason.

**Scan.** Write `PROP_WIFI_SCANNING` to `1`; clear the list on the
`CMD_PROP_IS` that follows; add or replace an entry per
`CMD_PROP_INSERTED`, grouping by SSID for display; stop the spinner on
the unsolicited `0`. A host on a binding that carries no notifications
polls `PROP_WIFI_SCANNING` and reads `PROP_WIFI_SCAN_RESULTS` once it
reads `0`. A host presenting a picker marks each network already in
`PROP_WIFI_NETWORKS` by matching SSIDs, since the reported table form
carries them.

**Join a new network.** Insert an entry in `PROP_WIFI_NETWORKS` with
the SSID from the scan result, the strongest mode in its offered set,
and the passphrase from the operator; on `STATUS_UNIMPLEMENTED`, insert
again with the next mode down. Then write the SSID to
`PROP_WIFI_NETWORK`. Two writes rather than one because the credential
has one home and the selection only names it. There is no safe
one-frame shortcut: a whole-table `CMD_PROP_SET` replaces every entry,
and since credentials cannot be read back, a host can only write a
whole table it holds every credential for. That is the first host
commissioning a fresh device, and nobody after it.

**Fix a wrong passphrase.** `PROP_WIFI_LINK` reads `CONNECTING` with
`WIFI_REASON_AUTH`. Insert the entry again with the corrected
credential; the device tries it immediately and the link reports the
outcome.

**Switch networks.** Write the other SSID to `PROP_WIFI_NETWORK`.

**Reconnect.** There is no such flow. The device is already retrying,
and a host that wants a fresh start with the same credentials has the
honest two-step: deselect, then select, each of which is a real state.

**Disconnect.** Write `PROP_WIFI_NETWORK` empty. The device leaves and
stays off the network with the station still up.

**Forget.** Remove the entry from `PROP_WIFI_NETWORKS`. If it was
selected the selection empties and the link drops, both published.

**Turn off.** Write `PROP_WIFI_ENABLED` to `0`. Nothing is forgotten.

**Locate.** On a device with `CAP_WIFI_SCAN` and no station, run the
scan flow and hand the BSSIDs and signal levels to whatever resolves
them into a position. The item format is what a geolocation resolver
consumes, and a phone passes the list straight through. What the device
does with its own scan, resolving on board or sending access points
over the air, is application and is not here.

**Offer a network.** Write `PROP_WIFI_AP_CONFIG` with the SSID, mode,
and credential, then `PROP_WIFI_AP_ENABLED` to `1`. Watch
`PROP_WIFI_AP_STATE` for the channel it landed on and
`PROP_WIFI_AP_CLIENTS` for who arrives.

**Commission for unattended use.** Do any of the above, then
`CMD_SAVE`. The station comes up and rejoins, and the access point
comes up, at every boot after that.

**Synchronize on attach.** Read `PROP_WIFI_ENABLED`,
`PROP_WIFI_NETWORK`, `PROP_WIFI_LINK`, and, where the device has one,
`PROP_WIFI_AP_ENABLED` and `PROP_WIFI_AP_STATE`, in one
`CMD_PROP_MULTI_GET` where available. The tables are read only when the
host needs to show them.

### What Survives What {#what-survives-what}

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
`PROP_WIFI_AP_ENABLED`   | yes   | reverts   | kept   | —
`PROP_WIFI_AP_CONFIG`    | yes   | reverts   | kept   | —
`PROP_WIFI_AP_STATE`     | no    | follows   | kept   | —
`PROP_WIFI_AP_CLIENTS`   | no    | follows   | kept   | —

"Reverts" means to the post-reset value, which on a device with a
snapshot is the saved one. "Follows" means the live state ends up
wherever the reverted configuration puts it, and nowhere else. A
`CMD_RST` on a device whose live configuration already matches its
snapshot leaves a running scan running, an association up, and an
access point beaconing; one that reverts the selection or its
credential drops the association and joins the restored entry; and one
on a device with no snapshot takes the station and the access point
down and everything live with them.

`CMD_RESTORE` is the same column: in either of its forms it reverts the
configuration properties to the snapshot and the live state follows.
Detach touches nothing, because the station and the access point are
device-domain and run unattended, and a scan that was in progress when
the host left completes and leaves its results for the next one.

### Over the Node Management Binding {#over-node-management}

Every property here is device-domain, so a listed administrator over
the mesh may read all of them and write the configuration ones, under
the same rule that lets channel keys be provisioned remotely: the
[binding](app-node-management.md) already delivers each request
authenticated and encrypted, so an administrator may provision a
credential.

Reading is the redacted form and nothing else, here as on the local
link. The network table and the access point's configuration read back
without their credentials, and no binding exists over which a
credential can be read.

That binding carries no unsolicited notifications, so a scan is the
polled flow above, and an administrator that wants the client list
reads it while `PROP_WIFI_AP_STATE` says there is one to read. Scan
results are the one large read, and the binding's cursors carry them.

An administrator who disables the station a bridge tunnel rides on has
done the same thing as one who writes `PROP_MAC_BACKHAUL`, and warrants
the same warning in the same place.

### On BLE {#on-ble}

The frame-size concerns are a `CMD_PROP_GET` of the scan results, of
the network table, and of the client list, and all three are bounded
above so that they fit. The inserts that deliver scanned access points
live are one item each. The largest credential write, a 32-octet SSID
with a 128-octet SAE password, is under two hundred octets with
framing. Everything else is a few.

## Security Considerations {#wifi-security}

* A passphrase crosses the link once, inbound, over a transport that
  meets the provisioning requirement, and is never reported. A later
  host on the same device cannot extract an earlier host's Wi-Fi
  credentials any more than its channel keys.
* The security mode is exact. A device joins with the mode the entry
  names and no other, whatever the network in front of it advertises,
  so a downgrade has to be written by the host rather than offered by
  the air.
* Scan results are what the device heard, and an SSID is what its
  sender chose to call itself. A host displays them as untrusted
  strings.
* A scan result list is a location fingerprint of wherever the device
  is standing, precise to a building, which is exactly why a tracker
  wants one. It is readable only by an admitted party, like everything
  else here, and a device that resolves positions on board treats what
  it learned the way it treats a fix.
* An access point is the one thing here that announces the device to
  everyone in range. Its SSID and its MAC are in every beacon, a hidden
  network is hidden from pickers and not from anyone listening, and the
  name it beacons **MUST NOT** carry the device's mesh identity or any
  part of its address. There is no factory network: the access point
  offers nothing until a host configures it, and its passphrase is
  write-only like every other credential.
* `PROP_WIFI_MAC` and the SSIDs in the table are identifying. They are
  no more so than `PROP_DEV_NAME`, and they are readable only by a
  party that has already been admitted.
* A device on Wi-Fi is a device on a LAN, and a device with an access
  point is a device hosting one. This chapter gives it an address and
  nothing that listens on one. Any service the device later offers over
  the interface, a ULCP binding over TCP above all, carries the full
  authority of an attached host and needs an admission ceremony of its
  own before it exists; the serial transports' physical-possession
  argument does not extend to a network port, and it extends least of
  all to a network the device invited the client onto. Whether knowing
  the access point's passphrase is itself such a ceremony is a decision
  for the binding that would rely on it.

## Not Specified {#wifi-not-specified}

Deliberately absent, with the reason:

* **Anything on the access point's network.** Forwarding between the
  offered network and the station's, a captive portal, a provisioning
  flow, or a binding a client could attach through: each is a thing the
  device does with the network rather than the network itself, and the
  last needs the admission ceremony above before it can exist.
* **Enterprise authentication.** Certificates and identities are a
  provisioning surface an order of magnitude larger than a passphrase.
  The three enterprise modes have numbers so that scan results can name
  them and a host can explain why a network is unavailable; the
  credential forms come with the capability that opens them.
* **Negotiation details.** Management frame protection, SAE
  hash-to-element, transition-disable: the device does what the mode
  requires and the host never sees them. WPS and Easy Connect are
  provisioning methods rather than modes.
* **Auto-join across the table.** There is none. The device joins the
  network it was told to and no other, because a device that picks
  networks by itself is a device whose behavior depends on what is in
  the air around it, which is the wrong property for a repeater on a
  wall.
* **Regulatory country.** The channel set follows the platform's
  regulatory configuration, which may later be tied to the device's
  region; nothing here decides how that configuration is set. What is
  decided is that an access point stays inside it.
* **Power-save mode, PHY rate, band preference.** The device's
  business. A property that exposes them is easy to add and hard to
  remove.
* **A reconnect request.** The one genuinely command-shaped act in the
  vicinity is deliberately not disguised as a property: a property
  write with a side effect when written with the value it already holds
  is a command in a costume, and it breaks the moment a host replays
  its configuration. It is also unnecessary, since the device retries
  on its own and replacing the selected entry restarts the join at
  once.
