# Importing, Discovery, and Sharing

UMSH does not have a central directory. Applications learn node public keys and
channel credentials from mesh traffic or from information exchanged outside
the mesh. The interface must make all of these routes understandable without
pretending that discovery establishes human identity.

## Ways information enters the application

| Source | What it can add | Required user treatment |
|---|---|---|
| Signed or identity-bearing mesh traffic | Known node, metadata, route evidence | May appear automatically under Nearby/Recent; do not silently make it a contact |
| First-contact packet | Sender public key and authenticated interaction | Show in the relevant inbox/conversation; let the user save or block |
| Camera scan | Node, channel, or CoAP resource URI | Parse locally, preview, then confirm |
| Paste or manual entry | URI or advanced public-key entry | Validate while preserving the original until confirmed |
| System link/open action | UMSH URI supplied by another app | Open the same preview flow; never commit on link activation alone |
| Share/import file | One or more future UMSH records | Preview each record and conflicts before commit |

## Known nodes and contacts

A **known node** is an address the application can use. It may have been
observed, imported, or contacted. A **contact** is a known node deliberately
saved by the user.

Observed nodes should be grouped by recency and role. Each row may show:

- display name, or **Unnamed node** plus the canonical complete address or
  rendered node hint when no name is known;
- role and useful capabilities, such as Text, Sensor, Repeater, or Room;
- how it was learned: Nearby, Received message, Scanned, or Imported;
- last observed time and coarse link information where available; and
- a warning when metadata is unsigned, stale, conflicting, or incomplete.

Do not rank nodes by RSSI as though it were physical distance. Multi-hop
traffic, antenna differences, and forwarded frames make that inference unsafe.

Saving a contact lets the user assign a local mnemonic alias and notes. Preserve the
node-advertised name separately so later advertisements cannot overwrite the
user's label.

## Peer discovery

**Discover peers** is an explicit, bounded mode in the mobile product. It is
not a promise that the mesh contains a global directory.

During a discovery session, the application:

1. ensures the radio is connected and able to receive;
2. listens for identity-bearing broadcast or multicast traffic and first-contact
   packets;
3. shows newly learned nodes as they arrive, deduplicated by public key;
4. identifies whether each result was heard directly or arrived through a
   forwarded packet when that evidence is available; and
5. lets the user inspect, message, or save a result without automatically
   turning it into a contact.

The user may choose **Announce my identity** during discovery. This sends the
user's signed public node identity with an explicit audience and flood scope.
The confirmation shows the metadata included, especially location, and the
airtime scope. Announcing must never include private key material.

The current protocol provides identity payloads over broadcast, multicast, or
unicast and provides an Identity Request for an already-addressable
destination. It does not define a broadcast discovery request that requires
unknown peers to answer. Therefore the first product can reliably implement
**listen for peers**, **announce myself**, and **refresh this known node**. A
button promising to query all unknown nearby peers requires a new, rate-limited
discovery convention or protocol definition.

Discovery sessions must be time-bounded and should use conservative flood
defaults. They may continue to populate Recent/Observed after the visible sheet
closes only as part of ordinary receive behavior; the UI must not imply that a
background scan is still running.

## URI import pipeline

All URI entry points use the same staged behavior:

1. **Acquire** — scan, paste, open a link, or type.
2. **Parse locally** — identify the URI kind and reject malformed or unsupported
   values without network access.
3. **Preview** — show the intended result, security meaning, metadata, and any
   conflict with local data.
4. **Confirm** — the user chooses an action appropriate to the URI kind.
5. **Verify when possible** — validate embedded signatures and show the result.
6. **Commit** — add or update local state without silently starting a
   transmission.

Unknown URI parameters should not cause rejection unless the protocol marks
them critical. If the application later re-shares an imported record, it should
preserve parameters it does not understand where practical.

### Node URI

A `umsh:n:` URI contains a public key and may contain an identity bundle. The
preview shows:

- advertised name and role, if present;
- the complete fixed-width Base58 node address, or a canonical node hint with
  `*` when the complete key is not present;
- signature status: **Valid signature**, **No standalone signature**, or
  **Invalid identity data**;
- location precision and identity timestamp, when present; and
- any conflict with an already-known address or name.

Primary actions are **Message** when text is supported, **View node**, or
**Save contact**. Importing a node must not imply that its human identity has
been independently verified.

### Direct-key channel URI

A `umsh:ck:` URI contains the channel membership secret. The preview must say
that anyone possessing this value can participate and impersonate a multicast
sender within the channel's symmetric authentication model.

Show the proposed display name, region, and maximum flood hops as
recommendations rather than authoritative policy. The user may edit the local
display name and accept or override safe routing defaults before choosing
**Join channel**.

### Named channel URI

A `umsh:cs:` URI derives a key from a canonical ASCII name. The preview must
label it **Public named channel**, explain that the name is not a password, and
show the canonical lowercase form when it differs from the input.

Joining `public` or `EMERGENCY` should apply the protocol's fixed behavior and
clearly identify those channels. The application must reject or hide messages
that violate each channel's source, encryption, or signature requirements.

### CoAP-over-UMSH URI

A `coap-umsh:` URI identifies a resource on a node. It opens a resource preview
or node-service detail, not a chat composer. Before the first request, show the
destination node, method implied by the action, and expected airtime impact when
known. Write or control actions require a separate confirmation.

## Generating and sharing URIs

### Share your identity

The Identity detail screen generates a `umsh:n:` URI from the user's public
key. The user chooses what metadata to include:

- display name;
- role and capabilities;
- location, with an explicit precision choice;
- generation timestamp; and
- standalone signature.

The default shared identity includes the public key, display name, role,
capabilities, current timestamp, and a signature, but no location. The preview
must state **Public information only** and must never include private key
material.

The application can present the result as a QR code, system share item, or
copied URI. The QR view keeps the complete 44-character Base58 address visible
so two people can compare it without decoding the QR code.

### Create a private channel

Creating a private channel generates a new random 32-byte channel key on the
phone. The creator supplies a local display name and optionally a region and
recommended hop count. The resulting `umsh:ck:` URI is a secret invitation.

The share sheet should be preceded by a disclosure: forwarding the invitation
grants full channel membership, and removing a participant later requires a new
channel key for everyone unless managed channels are defined and implemented.

### Create or join a named channel

The user enters an ASCII name. The application previews the canonical form and
explains that anyone knowing the name can join. A named channel can then be
shared as `umsh:cs:` without treating the URI as a secret.

## Conflicts and updates

Identity metadata is mutable while public keys are stable. When new metadata
conflicts with a saved record:

- never replace a user-assigned nickname;
- retain the newly observed advertised name as remote metadata;
- prefer a newer valid signed identity bundle over an older signed bundle;
- do not let unsigned metadata silently replace signed metadata; and
- provide a small history or diagnostic explanation when the conflict affects
  trust.

Importing a channel URI whose key already exists should offer **Update local
details**, not create a duplicate channel. Two channels with the same display
name but different keys must remain distinct and receive a visible conflict
warning.
