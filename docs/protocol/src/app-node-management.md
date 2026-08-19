# Node Management

> ![NOTE]
> This section is an early work in progress and this protocol may change significantly.

A node that supports node management can be configured and observed over the
mesh itself, using the same command grammar, property model, and numeric
registries that [ULCP](ulcp.md) defines for the local link. **Node
Management Request** (payload type 8) and **Node Management Response**
(payload type 9) payloads carry ordinary ULCP frames between an
**administrator** — a node listed in the device's
[administrator list](#prop-dev-admins) — and the **device**, in unicast
packets exchanged with the [device identity](ulcp-device.md#device-identity).
Support is optional and advertised through [`CAP_ADMIN`](#capabilities).

Administering a device over the mesh reaches the
[device domain](ulcp-core.md#device-domain) and nothing else. An
administrator is not a [tethered host](ulcp.md#attach-relationships): a
remote exchange is not an attach, touches no session state, and neither sees
nor disturbs the host domain or the assistance the device owes to whatever
host it serves. [Two Kinds of Attach](ulcp.md#attach-relationships) draws
the same boundary on the local link; over the mesh, only the administrative
kind exists.

## Transport Properties {#transport-properties}

The binding relies on exactly what the MAC layer guarantees for secure
unicast: the source of every accepted packet is authenticated, payloads are
confidential, and replay protection accepts a given frame at most once. It
assumes nothing more — not delivery, and not ordering. The payload format
adds what the ULCP grammar needs on such a transport:

- a **token** correlates responses with requests across long and variable
  round trips, in place of the TID of the local bindings;
- **retained responses** make retransmission safe: a repeated request is
  answered again, not executed again;
- **cursors** carry responses larger than one frame across as many
  exchanges as needed, without per-read state on the device.

Several operations per exchange need nothing from the envelope: the
[multi-property commands](ulcp-core.md#cmd-prop-multi-get) already carry
several reads, or several ordered writes, in a single frame.

Because wire-level duplicates are impossible, the binding has no
deduplication window of its own; the only duplicates that can exist are an
administrator's own retransmissions, which the token identifies.

## Payload Format {#payload-format}

Request and Response payloads share one format, consisting of, following
the payload type byte:

```text
+-------+---------+------+----------+
| TOKEN | OPTIONS | 0xFF |  FRAME   |
+-------+---------+------+----------+
  2 B    variable   1 B    variable
```

Direction lives entirely in the payload type. A device drops a Response
payload — it never solicits anything — and an administrator that receives
a Response matching no outstanding exchange of its own discards it, both
with accounting.

Node Management payloads travel only in unicast and blind unicast packets:
Requests are addressed to the device identity, and Responses return to the
requesting node on the carriage the Request arrived on (see
[Response Carriage](payload-format.md#response-carriage)), using whatever
routing state the exchange has supplied (see
[Route Learning](beacons.md#route-learning)). A device drops a Node
Management payload arriving by multicast or broadcast, with accounting.

### Token

Two opaque octets chosen by the administrator and echoed verbatim in the
response. The token correlates a response with its request and identifies
retransmissions (see
[Retries and At-Most-Once Processing](#at-most-once)). An administrator
MUST choose a token different from its previous exchange's when beginning
a new exchange, and MUST reuse the token when retransmitting a request
unchanged.

### Options

Options use the CoAP-style delta-length encoding defined in
[Packet Options](packet-options.md#attribute-encoding). As in
[MAC command options](mac-commands.md#identity-request-options),
odd-numbered options are **critical** and even-numbered options are
**elective**. A device that receives a request carrying an unrecognized
critical option answers with `PROP_LAST_STATUS` of `STATUS_UNIMPLEMENTED`
and does not process the request; unrecognized elective options are
ignored. An administrator that receives a response carrying an
unrecognized critical option treats the exchange as failed.

| Number | Critical | Name | Value |
|---:|---|---|---|
| 1 | Yes | CURSOR | 1–8 octets, see [Reading Large Values](#cursors) |
| 2 | No | REMAINING | PUI, see [Reading Large Values](#cursors) |

The `0xFF` end-of-options marker is always present, since the frame
follows.

### Frame

Exactly one ULCP frame, extending to the end of the payload — the payload
bounds it, so it carries no length prefix. The embedded frame uses the
exact [frame format](ulcp-core.md#frame-format) of the local bindings, so
a device dispatches it through the same machinery that serves its local
link. Senders MUST set its TID bits to zero, and receivers ignore them:
correlation is by token. A request whose frame is absent or cannot be
parsed is answered with a `CMD_PROP_IS` of `PROP_LAST_STATUS` reporting
`STATUS_PARSE_ERROR`.

The payload, envelope included, must fit a single UMSH frame; there is no
fragmentation. The unassigned option numbers are this format's growth
space: a future need — carrying a request larger than one frame, say — is
met by assigning a critical option, and existing devices already reject
what they do not recognize.

## Exchanges {#exchanges}

Every interaction is an **exchange**: one request payload from an
administrator, one response payload from the device. The device sends
nothing over this binding except in response to a request — `CMD_PROP_IS`
in its unsolicited role, and `CMD_PROP_INSERTED` and `CMD_PROP_REMOVED` as
spontaneous notifications, do not occur here. State an administrator cares
about is read, not pushed.

The Response echoes the token and carries one frame: exactly
the frame the device would emit in reply on a local binding — a
`CMD_PROP_IS`, `CMD_PROP_INSERTED`, `CMD_PROP_REMOVED`, or `CMD_PROP_ARE`
on success, or a `CMD_PROP_IS` of `PROP_LAST_STATUS` reporting the error.
A request frame carrying a Device→Host command is answered
`STATUS_INVALID_COMMAND`. Long-running operations report
`STATUS_IN_PROGRESS` as on any binding; the administrator observes
completion by reading state in a later exchange.

### Multi-Property Requests {#multi-property}

Several operations travel in one exchange through the multi-property
commands, whose semantics this binding leaves untouched:
[`CMD_PROP_MULTI_GET`](ulcp-core.md#cmd-prop-multi-get) reads several
properties, continuing past per-property failures, and
[`CMD_PROP_MULTI_SET`](ulcp-core.md#cmd-prop-multi-set) applies writes
strictly in order, stopping at the first failure — which is how an
administrator expresses writes whose effects depend on sequence.
`CAP_ADMIN` requires `CAP_CMD_MULTI`, so an administrator may rely on
both.

One rule is the binding's own: the device does not execute a
`CMD_PROP_MULTI_SET` entry whose reply entry would not fit the remaining
space in the response payload, and stops there exactly as an error would
stop it. An administrator that receives fewer reply entries than it sent
examines the last entry it did receive: an error means the sequence
stopped on that failure; a success means it stopped for space, and the
administrator reissues the remainder as a new exchange.

### Resets {#resets}

Commands that initiate a reset — `CMD_RST`, `CMD_RESTORE` in its reset
form, and `CMD_FACTORY_RESET` — are answered by **no** response payload.
Delivery of such a command is confirmed by requesting a MAC
acknowledgment, and its completion by a later exchange reading
`PROP_LAST_STATUS` for the reset code.

### Retries and At-Most-Once Processing {#at-most-once}

The MAC layer's replay protection means a device never receives the same
request frame twice; what it can receive twice is the same request *sent*
twice — an administrator retransmitting because no response arrived,
though the request may in fact have been executed. The device therefore
retains, per administrator, the token and the complete response of the
most recent exchange. A request whose token matches the retained token is
answered by retransmitting the retained response, without executing
anything. A device MAY bound how many administrators it retains an entry
for, evicting the least recently active, but retains at least the entry
for the most recently active administrator.

An administrator that receives no response retransmits the identical
request with the identical token, paced to the path's round-trip
behavior; the retained response makes this safe whether the request or
only its response was lost. An administrator MUST NOT have more than one
exchange outstanding with a given device.

Retained entries do not survive a reset. A reset command retransmitted
after it has already acted is therefore executed again — with the same
result.

## Reading Large Values {#cursors}

A read whose response does not fit one payload is completed across
several exchanges. This applies to both read requests: a `CMD_PROP_GET`
whose value does not fit, and a `CMD_PROP_MULTI_GET` whose entry list
does not fit. The response frame is well-formed but its trailing content
— the value of the `CMD_PROP_IS`, or the entry list of the
`CMD_PROP_ARE` — is a leading fragment, accompanied by a **CURSOR**
option: an opaque continuation handle, one to eight octets, chosen
entirely by the device. The administrator continues with a new exchange —
fresh token — whose request carries the returned cursor verbatim
alongside a repeat of the request being continued. Each response carries
the cursor to present in the *next* request; a response without one ends
the read, its fragment being the last. Fragment sizes are the device's
choice, made to fill each frame; there is no fixed block size and no
position numbering.

A request carrying a CURSOR option MUST be the read being continued — the
same `CMD_PROP_GET` or `CMD_PROP_MULTI_GET` that began it. A cursor on
any other request is answered `STATUS_INVALID_ARGUMENT`.

The contract:

- A cursor is meaningful only to the device that issued it, and only for
  the request it was issued for. The administrator returns it
  byte-for-byte and MUST NOT construct or modify one.
- Fragment boundaries are the device's choice and carry no meaning. The
  administrator reassembles the read by concatenating the fragments in
  order and parses the whole: a property value under the property's own
  rules, an entry list under `CMD_PROP_ARE`'s.
- Presenting the same cursor again SHOULD yield the same fragment or an
  equivalent one; a retransmitted continuation is in any case answered
  from the retained response (see
  [Retries and At-Most-Once Processing](#at-most-once)).
- Cursors are untrusted input. The device validates every cursor it
  receives and answers one it cannot honor — it does not parse, it was
  issued for a different request, or the underlying data has changed out
  from under the position — with
  `STATUS_CURSOR_INVALID` (see [Status Codes](ulcp-core.md#status-codes));
  the administrator restarts from a cursor-less request. A practical
  cursor encodes the position together with a generation of the
  underlying data — a table revision, a boot count — so that every change
  that invalidates positions is detected rather than served wrong.
- A response MAY carry an empty fragment with a cursor equal to the one
  presented, meaning nothing further is available yet; this suits data
  that accumulates over time.
- A response MAY carry a **REMAINING** option: the approximate number of
  octets not yet returned, as a packed unsigned integer. It is advisory,
  for progress reporting.
- The read holds no state on the device: between exchanges, the position
  lives entirely in the cursor the administrator holds.

## Authorization {#authorization}

A device executes a Node Management request only when the packet arrived
by unicast or blind unicast, its source is authenticated by the MAC layer,
and the source's public key is listed in
[`PROP_DEV_ADMINS`](#prop-dev-admins). Everything else it drops, with
accounting and without a response: an unlisted sender learns nothing about
whether the device is manageable.

Administrators reach the device domain and the device-scoped protocol
state — including `PROP_CAPS`, so capability discovery works exactly as on
the local link. Out of reach are:

- **session state** and the **host domain**
  (see [State Classes](ulcp-core.md#state-classes)): a request naming such
  a property is answered as an unrecognized property,
  `STATUS_PROP_NOT_FOUND`;
- `CMD_STR_SEND` and `CMD_QUEUE_DRAIN`, answered as unrecognized
  commands, `STATUS_INVALID_COMMAND`;
- [`PROP_DEV_PRIVATE_KEY`](ulcp-device.md#prop-dev-private-key), answered
  `STATUS_PROP_NOT_FOUND`: a device identity cannot be installed over the
  mesh.

For everything else this binding meets the transport requirement of
[Provisioning Security](ulcp-core.md#provisioning-security): every
executed request already arrives authenticated and encrypted from a listed
administrator, so device-domain key material — channel keys, peer entries
— may be provisioned remotely. The read-back rules are unchanged:
key-bearing properties report their digest forms, never secrets.

### PROP 4865: `PROP_DEV_ADMINS` {#prop-dev-admins}

* Type: Multiple-Value
* Has Item Length Prefix: No
* Asynchronous Updates: No
* Required: `CAP_ADMIN`
* Item Type: 32 octets
* Post-Reset Value: Empty

Each item is the Ed25519 public key of a node authorized as an
administrator of this device. Items are public keys: they carry no secret
material and are reported verbatim.

An empty list disables node management entirely and is the post-reset
default. The property is device-domain state: it participates in the
[saved snapshot](ulcp-saved-state.md#saved-state) like any other
device-domain property, which is how a commissioned repeater stays
manageable across a power cycle. It is writable over the local bindings
and over this one — a listed administrator may add or remove
administrators, itself included.

## Capabilities {#capabilities}

Code | Name        | Requires                            | Grants
-----|-------------|-------------------------------------|--------
43   | `CAP_ADMIN` | `CAP_DEV_IDENTITY`, `CAP_CMD_MULTI` | Node management: processing of Node Management Request payloads addressed to the device identity, and `PROP_DEV_ADMINS`

A device that does not advertise `CAP_ADMIN` drops Node Management
payloads, with accounting.
