# ULCP: IP Connectivity

The layer above a link: whether the device can reach anything, what it
is reachable at, and how to configure the cases the network does not
configure for it.

Address configuration is not a property of Wi-Fi. A wired link, should
one ever appear, needs exactly these properties, and a device's IP
stack is one thing whichever link carries it. Everything here is
therefore named `IP` rather than after a link, and nothing in it knows
what the link is.

Nothing about what the device reaches belongs here. A bridge tunnel or
a time source reports its own state under its own capability.

These properties describe one interface: the one the device uses to
join a network, which is the station's on a device whose only link is
[Wi-Fi](ulcp-wifi.md). A device's own [access
point](ulcp-wifi.md#prop-wifi-ap-config) is a second interface and is
deliberately not described here, because its addressing is a subnet the
device imposes rather than one a network hands it, and it lives in that
access point's own configuration. A device with a second link of the
joining kind is a future revision, and these properties are shaped so
that an interface selector could be added without renaming them.

The two configuration properties and the configured resolver list are
[device-domain](ulcp-core.md#device-domain) state and part of a [saved
snapshot](ulcp-saved-state.md#saved-state). The five that report what
the stack currently holds are live: never saved, and reached by
`CMD_RST` only through the configuration they follow.

## Capabilities {#capabilities}

Code | Name       | Requires | Grants
-----|------------|----------|--------
55   | `CAP_IPV4` | —        | An IPv4 stack on the device's link: `PROP_IPV4_STATE`, `PROP_IPV4_CONFIG`, `PROP_IPV4_ADDRESS`, and the shared `PROP_IP_DNS` and `PROP_IP_RESOLVERS`
56   | `CAP_IPV6` | —        | An IPv6 stack on the device's link: `PROP_IPV6_STATE`, `PROP_IPV6_CONFIG`, `PROP_IPV6_ADDRESSES`, and the same two shared properties

One capability per family, because the families are peers. The [BLE
binding](ulcp-ble.md#capabilities) argues for a single capability on
the grounds that a refusal is a complete answer about an *extra*, and
neither family is an extra to the other: a device that speaks only IPv4
is ordinary today, and a device that speaks only IPv6 is an ordinary
device on an IPv6-only network tomorrow. Making either the floor would
encode which one is normal, which is a fact about the year rather than
about the protocol.

A device with both advertises both, and a host that sees either knows
the two shared properties are there. The seam stops at the family: DHCP
versus static, advertisements versus DHCPv6, are methods within a
family, and a device that lacks one refuses the write with
`STATUS_UNIMPLEMENTED` as that argument intends.

Neither capability formally requires a link capability, on purpose. A
capability's requirements are concrete codes, and naming `CAP_WIFI`
here would make a wired device either lie about having Wi-Fi or invent
a second pair of IP capabilities. The precondition is stated instead: a
device advertising either has a stack on one link, and describes that
link through whatever link capability it also advertises. A device that
advertises an IP capability and no link capability has a link it offers
no control over, which is a legal shape for a device with a fixed wired
port; its family states simply never report `IP_NO_LINK` for a reason
the host can act on.

## Properties {#properties}

Allocated in the block after the [Wi-Fi station's](ulcp-wifi.md#properties).

All IPv4 and IPv6 addresses, including gateways and resolvers, are
encoded as octets in network byte order (big-endian).

Id   | Mnemonic              | Commands                 | Description
-----|-----------------------|--------------------------|-------------
4896 | `PROP_IPV4_STATE`     | Get, Is                  | IPv4 readiness
4897 | `PROP_IPV4_CONFIG`    | Get, Set                 | How IPv4 is configured
4898 | `PROP_IPV4_ADDRESS`   | Get, Is                  | The IPv4 address, prefix, and gateway in effect
4899 | `PROP_IPV6_STATE`     | Get, Is                  | IPv6 readiness
4900 | `PROP_IPV6_CONFIG`    | Get, Set                 | How IPv6 is configured
4901 | `PROP_IPV6_ADDRESSES` | Get, Is                  | The IPv6 addresses and default routers in effect
4902 | `PROP_IP_DNS`         | Get, Set, Insert, Remove | Configured resolvers, or empty to use what the network provides
4903 | `PROP_IP_RESOLVERS`   | Get, Is                  | The resolvers in use

4904 through 4911 are reserved for this subsystem.

### PROP 4896: `PROP_IPV4_STATE` {#prop-ipv4-state}

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
`fe80::/10` under the same exclusions. A self-assigned `169.254`
address reaches only the link, exactly as `fe80::` does, and a device
that fell back to one is a device whose DHCP failed, which
`IP_WAITING` says and `IP_READY` would hide. A device with only an IPv6
link-local address is `IP_WAITING`, because it is waiting for exactly
the advertisement that would give it a usable one. This is the boundary
readiness is defined on, and the same boundary the static configuration
is validated against.

This is the property a host watches for its family. It changes when a
lease is obtained or lost, when a router starts or stops advertising,
and when the link comes and goes, which is a few times in a session
rather than a few times a minute. The device **MUST** publish it on any
change and on nothing else. The address and resolver properties publish
their own changes, since those can move while the state stands still.

`IP_WAITING` is this layer's
[`WIFI_LINK_CONNECTING`](ulcp-wifi.md#prop-wifi-link): the device is
doing what its configuration says and the network has not answered. It
carries no reason, because the reasons are the network's, a DHCP server
that does not answer or a router that does not advertise, and the fix
is on the network.

`IP_CONFLICT` is the exception that earns its own value. A static
address that duplicate-address detection or an ARP probe finds already
in use is a fault in the configuration this protocol wrote, the fix is
a different address, and a host that could not tell it from an ordinary
wait would tell the operator to check the router. The device keeps
probing while in `IP_CONFLICT` and moves to `IP_READY` if the other
holder goes away. Under `IP_METHOD_AUTO` a conflict is the stack's to
resolve, by declining the lease and asking again, and the family stays
`IP_WAITING`.

`IP_NO_LINK` is separate so that a host can tell "the station is not
associated" from "the station is associated and nobody is handing out
addresses" without reading `PROP_WIFI_LINK` as well.

`IP_READY` means an address, not a route. Whether the family also has a
default route is in the address property, the gateway field for IPv4
and the router items for IPv6, and a device on an isolated network that
hands out addresses and no gateway is ready by this definition, which
is the honest one.

### PROP 4897: `PROP_IPV4_CONFIG` {#prop-ipv4-config}

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
Figure: IPv4 configuration format

**METHOD**:

Value | Name                 | Meaning
------|----------------------|---------
0     | `IP_METHOD_DISABLED` | The family is not used on the link
1     | `IP_METHOD_AUTO`     | DHCP
2     | `IP_METHOD_STATIC`   | The address, prefix, and gateway that follow

The default is `IP_METHOD_AUTO`, so that a device with nothing
configured is on the network the moment it is associated; this
subsystem exists for the cases where that is not enough.

A **PREFIX** above 32, a static form of the wrong length, or a static
address that is not usable in the sense
[`PROP_IPV4_STATE`](#prop-ipv4-state) defines, `169.254/16` included,
is refused with `STATUS_INVALID_ARGUMENT`. A **GATEWAY** is either
all-zero or a unicast address that is not multicast, broadcast,
loopback, or link-local, and anything else is refused the same way; the
IPv6 form relaxes the last exclusion, since a router names itself by
its link-local address and a static IPv6 gateway is usually exactly
that. All-zero means no default route, which is what a device on a
network with no way out should be told.

A write takes effect at once. On a device that is `IP_READY` under the
old configuration, the old address is released and the new one applied,
and `PROP_IPV4_STATE` reports the transitions like any other. A write
while the link is down is accepted and waits for it, so that a static
configuration can be staged before the link is enabled.

### PROP 4898: `PROP_IPV4_ADDRESS` {#prop-ipv4-address}

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_IPV4`
* Value Type: 4-octet address, 1-octet prefix, 4-octet gateway; or empty
* Post-Reset Value: the address in effect; empty when the family is not `IP_READY`

The IPv4 address the interface holds, its prefix length, and the
default gateway, all-zero when there is none. Whatever the method:
under `IP_METHOD_AUTO` this is what the lease said, and under
`IP_METHOD_STATIC` it is what was written, once the device holds it.

The device **MUST** publish it whenever the reported value changes.
Mostly that is when `PROP_IPV4_STATE` moves, but not only then: a lease
renewal can keep the address and change the gateway, and a host that
read the value once and watched only the state would carry the old
gateway forever. A renewal that changes nothing publishes nothing.

### PROP 4899: `PROP_IPV6_STATE` {#prop-ipv6-state}

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_IPV6`
* Value Type: UINT8
* Post-Reset Value: what the family is doing

IPv6 readiness, from the enumeration
[`PROP_IPV4_STATE`](#prop-ipv4-state) defines, with the same
publication rule and the same meaning for every value. The one
family-specific note is the link-local boundary: a device holding only
an `fe80::` address is `IP_WAITING`, because it is waiting for exactly
the advertisement that would give it a usable one.

Two properties rather than two octets in one, because the capabilities
are two. A device without `CAP_IPV6` would otherwise carry an octet
describing a family it does not have, and a property granted by "either
capability" is a property with two homes. One octet per family costs a
second notification when a link drop takes both families down, which is
one small frame at a moment the host is already being told things.

### PROP 4900: `PROP_IPV6_CONFIG` {#prop-ipv6-config}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_IPV6`
* Value Type: as [`PROP_IPV4_CONFIG`](#prop-ipv4-config) with 16-octet addresses
* Post-Reset Value: `IP_METHOD_AUTO`, or restored from saved state

The same structure and the same methods, with 16-octet addresses and a
prefix of at most 128. A static address that is not usable in the sense
[`PROP_IPV6_STATE`](#prop-ipv6-state) defines, link-local, multicast,
loopback, or unspecified, is refused with `STATUS_INVALID_ARGUMENT`; a
static address that is usable but already held on the link is accepted
and reported as `IP_CONFLICT`.

`IP_METHOD_AUTO` means router advertisements, and DHCPv6 where the
router asks for it. Which of those produced an address is not reported,
because a host has nothing to do with the difference.

A device **MUST** hold a stable address and **MUST** report only stable
addresses. It **MAY** additionally use temporary addresses for the
traffic it originates, which is the arrangement RFC 8981 describes for
a host that is reached at one address and reaches out from others, and
those are never reported: they exist to rotate, and a reported address
is one somebody wrote down.

### PROP 4901: `PROP_IPV6_ADDRESSES` {#prop-ipv6-addresses}

* Type: Multiple-Value, Read-Only
* Has Item Length Prefix: Yes
* Asynchronous Updates: Yes
* Required: `CAP_IPV6`
* Post-Reset Value: what is in effect; empty when the family is not `IP_READY`

The usable IPv6 addresses the device holds, and the default routers it
has selected. Each item is a kind octet and a kind-defined body:

Kind | Name           | Body
-----|----------------|------
0    | `IPV6_ADDRESS` | 16-octet address, 1-octet prefix length
1    | `IPV6_ROUTER`  | 16-octet router address

A set rather than one address, because an IPv6 interface normally holds
several, a global one and a unique-local one from separate prefixes,
say, and which of them the device uses as a source depends on where the
packet is going. There is no one answer to "the device's address", only
"the addresses the device is reachable at", which is what a host
displaying or dialing it needs. Stable addresses only, per the
configuration above. The link-local address is not among them, for the
reason it does not make the family ready.

The router items are the stack's default router list, every router it
currently retains from those advertising, and none when there is none.
A list rather than one, because a stack keeps several and may send to
different destinations through different ones, so no single router
describes the routing.

The prefix length is the one the address's assignment carried: the
advertised prefix an autoconfigured address was formed from, or the
prefix written for a static one. An address assigned by DHCPv6 reports
128, and 128 means the assignment carried none rather than that the
link is a `/128`: DHCPv6 assigns addresses, not prefixes, and the
on-link prefixes a router advertises alongside are routing state that
is not encoded here.

A device bounds the set to what its stack holds, which for an embedded
stack is a few addresses and a few routers, and the bound **MUST** keep
the complete value inside one frame on every transport the device
exposes. Which entries a stack keeps once a network offers more than it
can hold is the stack's business.

The device **MUST** publish it whenever the reported set changes: a
prefix renumbered, a router replaced or expired, an address added or
withdrawn. Router and prefix lifetimes are independent of one another
and of the state, so this property moves while `PROP_IPV6_STATE` stands
still, and a host that only watched the state would not learn.

### PROP 4902: `PROP_IP_DNS` {#prop-ip-dns}

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
that configured resolvers meant those, and a merged set would be
neither what it wrote nor what the network offered.

An item of any other length, or one that is not a unicast address,
unspecified, multicast, broadcast, or loopback, is refused with
`STATUS_INVALID_ARGUMENT`. An IPv6 resolver **MAY** be link-local, as
one advertised by a home router commonly is, and an IPv4 one **MUST
NOT** be. A device bounds the set, **SHOULD** hold at least two, and
refuses past its capacity with `STATUS_NOMEM`.

The set is unordered, as every multi-value property is, and a device
asks whichever it likes first.

Static addressing without this is a device that cannot resolve a name,
which is why the two are written together.

### PROP 4903: `PROP_IP_RESOLVERS` {#prop-ip-resolvers}

* Type: Multiple-Value, Read-Only
* Has Item Length Prefix: Yes
* Asynchronous Updates: Yes
* Required: `CAP_IPV4` or `CAP_IPV6`
* Item Form: as [`PROP_IP_DNS`](#prop-ip-dns)
* Post-Reset Value: the resolvers in use; empty when there are none

What the device is resolving with right now: the configured set when
`PROP_IP_DNS` is non-empty, otherwise what the network handed it, and
empty when neither has given it anything.

The device **MUST** publish it whenever the set changes, for the same
reason the addresses are published: a router advertisement carries
resolvers with lifetimes of their own and can add one, replace one, or
withdraw one with a zero lifetime, all without the family leaving
`IP_READY`. Bounded as
[`PROP_IPV6_ADDRESSES`](#prop-ipv6-addresses) is, to what the stack
holds and to one frame; a stack that keeps two or three resolvers is
the norm, and a network offering more than that is offering more than
the device will ask.

Chiefly a diagnostic, and the one that distinguishes "the device is on
the network and cannot resolve the server's name" from every other way
a tunnel fails to come up.

## Alongside the Link {#alongside-the-link}

On a device whose link is Wi-Fi, the two subsystems meet at exactly one
property on each side: [`PROP_WIFI_LINK`](ulcp-wifi.md#prop-wifi-link)
says whether there is a link, and the two family states say what each
family has made of it. The address and resolver properties are read
after one of those has moved and followed thereafter, since each
publishes its own changes.

**The stack follows the link.** While the link is anything but up,
every enabled family is `IP_NO_LINK` and both address properties are
empty. When the link comes up, each enabled family goes to
`IP_WAITING` and then, as the network answers, to `IP_READY`; a static
family skips the wait except for the duplicate-address check, which
ends in `IP_READY` or `IP_CONFLICT`. When the link drops, everything
goes back to `IP_NO_LINK` and the addresses empty with it, learned
resolvers included. A roam to another access point of the same network
is the same link and does not disturb the stack: a device **MUST NOT**
release its addresses over a roam.

**Publication order** is link first, then stack, in both directions. On
the way up, `PROP_WIFI_LINK` carrying `WIFI_LINK_UP`, then each
family's state for each transition as it happens; on the way down,
`PROP_WIFI_LINK` leaving `WIFI_LINK_UP`, then each family's state
carrying `IP_NO_LINK`. A host that sees `IP_READY` reads the addresses
it wants and keeps them current from their own notifications; one that
sees `IP_WAITING` persist while the link is up knows the problem is the
network and not the radio; and one that sees `IP_CONFLICT` knows it is
the configuration.

**Disabling the link** reports `IP_NO_LINK`, not `IP_DISABLED`. The
second is the family's own switch, written in its configuration, and a
host that turned the radio off did not turn IPv6 off.

**Configuration is staged in any order.** These configuration
properties are writable while the link is down and while the radio is
disabled, and they are ordinary `CMD_PROP_SET` targets, so a static
commissioning is one `CMD_PROP_MULTI_SET` where `CAP_CMD_MULTI` is
present: `PROP_IPV4_CONFIG`, `PROP_IP_DNS`, `PROP_WIFI_NETWORK`,
`PROP_WIFI_ENABLED`, in that order, then `CMD_SAVE`. The network insert
still stands apart, being an insert.

**Synchronizing on attach** adds the family states to the link's read:
`PROP_WIFI_ENABLED`, `PROP_WIFI_NETWORK`, `PROP_WIFI_LINK`,
`PROP_IPV4_STATE`, and `PROP_IPV6_STATE`, in one
`CMD_PROP_MULTI_GET`, where a family the device lacks comes back as the
`STATUS_PROP_NOT_FOUND` entry the multi-get already provides for.
Between them a host knows whether the device is configured, associated,
and addressed without a second round trip.

**Reconfiguring a live device** is a write and a watch. The device
applies the new configuration at once, the family leaves `IP_READY` and
arrives wherever the new configuration leads, `IP_READY` again by way of
`IP_WAITING`, `IP_CONFLICT` for a static address somebody else holds, or
`IP_DISABLED`, and a host that changed a static address learns the old
one is gone by the same notification everyone else does.

**The host name** the device presents to DHCP, and to DHCPv6 where it
runs, **SHOULD** be derived from `PROP_DEV_NAME`, folded to a valid
label, so that the device can be found on a router's client list under
the name its operator gave it.

**What survives what.** The three configuration properties are saved
and revert with `CMD_RST`; the five live ones follow, in the sense the
Wi-Fi chapter's [table](ulcp-wifi.md#what-survives-what) defines.
`CMD_RST` on a device whose snapshot matches its live IP configuration
leaves a lease in place; one that reverts a static address releases and
re-applies, with the transitions published.

**Over the node management binding,** all eight are device-domain: an
administrator may read every one and write the three configuration
properties, the other five being read-only for everybody. That binding
carries no unsolicited notifications, so the read-then-follow flow does
not apply across the mesh: an administrator that wants a current view of
addresses or resolvers reads them again, and the family states tell it
when that is likely to be worth doing. An administrator who writes a
static address that is wrong for the network has stranded a bridge just
as surely as one who disabled the link, and the same warning belongs in
the same place.

## Security Considerations {#ip-security}

The IP stack trusts its network the way every client does. A rogue DHCP
server or router advertisement on the LAN can hand the device a bad
address, a bad route, or a resolver that lies. Nothing at this layer
defends against that, and nothing needs to, because what rides on the
address authenticates its far end itself: the bridge tunnel pins a key,
and a redirected tunnel fails to open rather than opening to the wrong
party.

## Not Specified {#ip-not-specified}

* **A reachability test.** Command-shaped, and unnecessary: a bridge
  client reports whether its tunnel is up, and that is the reachability
  anyone cares about.
* **A DHCP renew request.** The same argument. A lease is the stack's
  to manage, and a host that could force a renewal could not observe
  anything by it that the address property does not already publish.
* **Time from the network.** It belongs to the time capability, which
  would gain a trust switch shaped like `PROP_GNSS_TIME_TRUST` if it
  takes SNTP.
* **A second interface.** A selector for a later revision. The device's
  own access point is not one of these interfaces; see
  [`PROP_WIFI_AP_CONFIG`](ulcp-wifi.md#prop-wifi-ap-config).
* **mDNS.** Letting a phone find the device by name is a service the
  device offers rather than a property of its stack, and it waits for
  whatever first needs it.
