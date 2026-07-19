# iOS User Stories and Flows

These stories define observable product behavior. They intentionally avoid
implementation architecture.

## Identity and onboarding

### IOS-ID-01: Create an identity

**As a new user,** I want to create my UMSH identity before choosing a radio so
that my network identity belongs to me rather than to nearby hardware.

Acceptance criteria:

- The app creates the identity in platform secure storage.
- The app shows a display name and the exact 44-character Base58 public address.
- The app explains that the public identity is shareable and the private key is
  not.
- Leaving onboarding does not discard an already-created identity.
- The app does not claim the identity is backed up or synchronized unless that
  mechanism is active and verified.

### IOS-ID-02: Share public identity

**As a user meeting someone in person,** I want to show a QR code for my public
identity so they can message the correct node without typing a key.

Acceptance criteria:

- The default QR includes the public key, signed identity metadata, and no
  location.
- The screen labels the information **Public** and displays the complete
  fixed-width Base58 address.
- The user can change included metadata before regeneration.
- Copy and system Share produce the same logical URI as the QR code.
- No private key material is ever displayed or exported.

### IOS-ID-03: Protect an identity-changing action

**As a user,** I want identity deletion to describe its consequences so that I
do not mistake it for disconnecting a radio.

Acceptance criteria:

- The confirmation names the identity and exposes its complete Base58 address.
- It distinguishes phone identity, messages/contacts, BLE bonds, and radio
  settings.
- Cancel is the default action.
- Waiting outbound messages cannot silently move to a replacement identity.

### IOS-ID-04: Export an identity for recovery

**As a user,** I want to export a protected copy of my identity so that losing
this phone does not mean losing who I am on the mesh.

Acceptance criteria:

- Export is an explicit action inside Identity settings, available only when
  the protected export format (`docs/protocol/src/identity-export.md`) is
  implemented.
- Export requires choosing a passphrase, with guidance that the export is
  only as strong as the passphrase.
- The result is clearly labeled as containing the private key and is visually
  and verbally distinct from sharing the public identity.
- The export artifact is unusable without the passphrase.
- Public identity sharing (QR, Copy, Share) never includes exported private
  material.

### IOS-ID-05: Restore an exported identity

**As a returning user with a new phone,** I want to restore my previously
exported identity during onboarding so that the mesh continues to recognize
me.

Acceptance criteria:

- The restore entry appears in onboarding and Identity settings only when the
  protected export format is implemented; it is hidden, not disabled, before
  then.
- Restore requires the export artifact and its passphrase, and commits
  nothing before an explicit confirmation.
- The preview shows the display name and complete 44-character Base58 address
  before commit.
- A restored identity advances its frame counters past any value the previous
  installation could have used before sending authenticated traffic.
- Restore never merges with an identity already on the phone; replacing one
  is a separate, explicitly destructive action.
- The flow states that the exporting device must stop using this identity;
  simultaneous use is unsupported.

## Radio setup and recovery

### IOS-RAD-01: Pair a first radio

**As a new user,** I want the app to find compatible nearby radios and guide me
through physical-presence pairing.

Acceptance criteria:

- Bluetooth permission is requested in response to **Find a radio**.
- Only compatible service advertisements are shown by default.
- The app explains button/PIN/OOB requirements before invoking the system
  pairing step.
- Pairing progress distinguishes scanning, connecting, securing, and reading
  capabilities.
- Failure provides a specific retry or recovery suggestion.

### IOS-RAD-02: Reconnect a trusted radio

**As a returning user,** I want my trusted radio to reconnect without entering
pairing mode again.

Acceptance criteria:

- The app attempts reconnection to the selected trusted radio.
- A connection loss creates an actionable banner without deleting drafts and
  shows the last-known radio battery with its age.
- The app verifies the configured host identity after attachment.
- Queued inbound frames are drained only after session and identity checks.
- Every connected status control includes the current radio battery/power state
  or says that it is unavailable.
- In normal state, the companion-status control occupies the centered top
  toolbar group on every app screen and shows compact connection and battery
  symbols with a full accessible label.
- Its tap target remains at least 44 by 44 points even though the visible
  symbols are smaller.
- A connection problem expands in that slot rather than moving the radio state
  to a screen-specific location; the banner appears below the toolbar and above
  the page title/content.

### IOS-RAD-03: Take over a previously used radio

**As a user pairing a second-hand or shared radio,** I want to know what will be
erased before assigning it to my identity.

Acceptance criteria:

- The app stops before replacing a mismatched host identity.
- The sheet says old host-domain queue, filters, and delegated keys are erased.
- The sheet says radio identity, BLE pairing, and radio settings remain.
- Replace is deliberate and Cancel leaves the old host domain intact.

### IOS-RAD-04: Configure a radio safely

**As a non-expert user,** I want to select a regional preset instead of raw LoRa
parameters.

Acceptance criteria:

- Presets show region and a human-readable purpose.
- Regulatory and hardware constraints limit invalid combinations.
- Raw parameters are available in an Expert disclosure.
- Unsaved edits do not masquerade as active radio state.
- A failed apply leaves the last authoritative configuration visible.

### IOS-RAD-05: Understand offline assistance

**As a battery-conscious user,** I want to know what my radio can do when the
app is not connected.

Acceptance criteria:

- The summary separately describes filtering, inbound buffering, channel
  recognition, and delegated acknowledgements.
- The app names capability limitations of the current radio.
- Enabling key provisioning includes a concise security disclosure.
- The interface never claims the radio holds the user's private identity key.

## Import, discovery, and contacts

### IOS-DIS-01: Scan another person's node URI

**As a user,** I want to scan a person's code and inspect it before starting a
conversation.

Acceptance criteria:

- The scan parses locally and opens Node Identity Preview.
- The preview shows the complete Base58 address or canonical rendered node hint,
  advertised metadata, signature, freshness,
  and conflicts.
- The user can Message, Save Contact, or Cancel.
- Scanning alone does not save or transmit anything.

### IOS-DIS-02: Open a UMSH URI from another app

**As a user receiving a UMSH link,** I want it to open the same safe import
preview as a scanned code.

Acceptance criteria:

- Node, channel, and resource links route to type-specific previews.
- Malformed values remain visible enough to diagnose or copy, without partial
  import.
- Duplicate keys update/merge rather than create silent duplicates.
- Unknown supported-safe parameters are retained where practical.

### IOS-DIS-03: Review observed nodes

**As a user,** I want to see nodes learned from the mesh without having them all
become contacts.

Acceptance criteria:

- Network distinguishes Contacts from Recent/Observed nodes.
- Rows show source, role/capabilities, and last observation.
- RSSI is not labeled as distance.
- A node can be messaged when capable without first being saved.
- A local mnemonic alias is not overwritten by later advertisements.

### IOS-DIS-04: Inspect a location with honest precision

**As a user viewing a node on the map,** I want to understand how precise and
fresh its position is.

Acceptance criteria:

- Coarse location is rendered as an area, not an exact centered pin.
- Precision and timestamp/observation age are readable without color.
- Reported node location is distinguishable from the phone's location.
- No location is inferred when the node did not publish one.

### IOS-DIS-05: Run peer discovery

**As a user arriving in a new area,** I want a bounded discovery session so I
can see nodes that are currently announcing or communicating.

Acceptance criteria:

- The app says discovery listens for identity-bearing traffic and cannot find
  every silent node.
- Results stream in, deduplicate by public key, and remain known nodes rather
  than automatic contacts.
- The session has a visible end and can be stopped.
- Announce My Identity previews audience, flood scope, and included location.
- Refreshing a known node may use a unicast Identity Request; discovering an
  unknown node does not pretend that request is possible without its address.

### IOS-PEER-01: Recognize a peer consistently

**As a user,** I want the same peer to have the same compact identity marker
throughout the app.

Acceptance criteria:

- The fallback avatar uses the peer's raw three NodeHint bytes as RGB.
- Avatar text is exactly `NodeHint::to_string()`, laid out as two characters
  over two, or two over one for a three-character form.
- Avatar text uses the system monospaced typeface and scales proportionally
  with the circle rather than retaining one fixed glyph size.
- Black or white text is selected by the greater WCAG contrast ratio.
- The accessible label includes the canonical rendered NodeHint.
- The avatar appears consistently in conversation rows, direct-chat headers,
  channel sender labels, Network/discovery rows, and Peer Detail.
- The avatar is never treated as cryptographic verification or collision-free
  identity.

### IOS-PEER-02: Set a mnemonic alias

**As a user,** I want to assign a memorable local alias without changing what
the peer advertises.

Acceptance criteria:

- Peer Detail offers **Set alias** or **Edit alias**.
- The alias becomes the primary label throughout the app.
- The advertised name remains visible in Peer Detail and searchable.
- The alias is local-only unless the user explicitly includes it in shared
  metadata.
- Removing the alias restores the advertised-name or unnamed-node fallback.

### IOS-PEER-03: Inspect and share peer identity

**As a user,** I want one peer-detail screen for identity, communication, and
security actions.

Acceptance criteria:

- Tapping a direct-chat title/avatar or peer row opens the same Peer Detail.
- The screen shows the exact 44-character Base58 public key and canonical
  NodeHint.
- Copy, Show QR, and system Share expose public identity information only.
- Message, Ping, and PFS actions appear only when the peer is eligible.
- Returning to a direct chat preserves its draft and transcript position.

### IOS-PEER-04: Ping a peer

**As a user,** I want to test reachability without mistaking packet loss for an
offline verdict.

Acceptance criteria:

- Ping sends one Echo Request and shows **Sending ping…**.
- A matching Echo Response reports round-trip time and observation time.
- Timeout reports **No response before timeout**, not **Offline**.
- Opening Peer Detail does not automatically or repeatedly ping.

### IOS-PEER-05: Establish and inspect a PFS session

**As a user,** I want to establish forward secrecy and know when my direct chat
is using it.

Acceptance criteria:

- **Establish PFS session** confirms the requested duration before sending.
- Establishing, active with accepted lifetime, ending, and failed states have
  visible text in Peer Detail and the direct-chat header.
- A solid or broken outer ring surrounds the stable NodeHint avatar as a
  redundant cue; no security badge overlaps the avatar, and status is not
  communicated by color alone.
- Active traffic remains associated with the stable peer rather than creating
  a contact for an ephemeral address.
- **End PFS session**, expiration, or either device reboot returns the UI to
  standard encryption and explains the transition.
- Current PFS status does not retroactively label older messages as PFS
  protected.

## Direct and group messaging

### IOS-MSG-01: Send a direct message while connected

**As a user,** I want to send text and understand whether it reached the peer's
node.

Acceptance criteria:

- Pressing Send immediately creates one optimistic local message.
- Local radio acceptance and remote MAC acknowledgement are distinct states.
- **Delivered to node** appears only with valid end-to-end evidence.
- Failure offers Retry and Details without duplicating the logical message.

### IOS-MSG-02: Compose while disconnected

**As a user with a temporarily disconnected radio,** I want to keep writing and
choose to send when the radio returns.

Acceptance criteria:

- The draft survives navigation and app relaunch according to data settings.
- Send can create a **Waiting for radio** outbox item.
- The user can edit or cancel it before transmission.
- The backlog does not send under a different identity or materially changed
  channel context without confirmation.

### IOS-MSG-03: Send a fragmented message

**As a user writing a longer message,** I want to know it costs multiple frames
and whether every part completes.

Acceptance criteria:

- Before Send, the composer says **Will send as N parts**.
- Sending progress refers to the logical message, not N duplicate bubbles.
- Missing or failed fragments produce **Partially sent** or **Failed** details.
- Received incomplete messages display a missing-content marker.

### IOS-MSG-04: Reply or react

**As a user,** I want familiar reply and reaction actions without creating
invalid wire references.

Acceptance criteria:

- The action is offered only when the message can be referenced in context.
- Otherwise **Quote in new message** remains available.
- Replies show a compact source preview.
- Reactions/emotes remain accessible as text, not color or animation alone.

### IOS-MSG-05: Edit or delete my message

**As a sender,** I want to correct a recent message while retaining honest
history.

Acceptance criteria:

- Only locally eligible messages offer Edit/Delete.
- The transcript shows the latest version and an **Edited** marker.
- Delete sends the protocol's zero-length edit and renders a placeholder.
- Subsequent references use the original stable message reference.

### IOS-CHN-01: Join a private channel from a QR code

**As an invited user,** I want to understand that the scanned value is a shared
secret before joining.

Acceptance criteria:

- The preview labels it **Private channel invitation**.
- It explains possession grants membership and multicast sender authentication
  is shared-key based.
- Name, region, and hops are shown as editable/reviewable local details.
- Confirm adds one channel and opens its conversation; Cancel retains nothing.

### IOS-CHN-01A: Send a channel message

**As a channel participant,** I want a familiar chat transcript and composer so
I can talk to everyone listening on the channel.

Acceptance criteria:

- Before selection, the conversation row visibly says **Private channel** (or
  the applicable channel type) and does not rely on its icon alone.
- Selecting the channel in Conversations opens its transcript, not its settings
  or a recipient picker.
- The open header persistently identifies the destination as a channel and
  multicast; a private symmetric channel says **Everyone with the channel
  key**.
- The transcript identifies each incoming sender above the message bubble.
- Incoming speakers are separated by deterministic NodeHint avatar, name, bubble boundary, and
  group spacing; identification does not depend on unique colors.
- Consecutive messages from one sender form a tighter visual group.
- Outgoing messages align to the trailing edge and use the standard outgoing
  bubble treatment.
- The composer sends one multicast text message to the channel; it does not ask
  the user to choose individual recipients.
- The composer names the channel destination, such as **Message Trail Crew
  channel**.
- The optimistic outgoing message appears once in the transcript.
- Successful local transmission becomes **Sent over radio**, never
  **Delivered to everyone**.
- The channel title or Info button opens Channel Detail without losing the
  draft or transcript position.

### IOS-CHN-02: Create and share a private channel

**As a group organizer,** I want to create a random private channel and invite
others out of band.

Acceptance criteria:

- The app generates the key locally.
- The share disclosure explains forwarding grants membership and removal
  requires rekeying in the current protocol.
- QR, Copy, and Share represent the same invitation.
- Leaving and deleting the key are clearly distinguished from muting chat.

### IOS-CHN-03: Join a named channel

**As a user,** I want to join a public named channel without mistaking its name
for a password.

Acceptance criteria:

- Entry is restricted to the protocol's accepted ASCII form.
- The canonical lowercase value is previewed when different.
- The app labels the result public and derivable by anyone who knows the name.
- `public` and `EMERGENCY` receive their required validation behavior.

### IOS-CHN-04: Interpret channel send status

**As a channel participant,** I want status wording that does not claim group
delivery.

Acceptance criteria:

- Successful local transmission says **Sent over radio** in details.
- No Delivered check appears without recipient-specific evidence.
- Sender identity links to Peer Detail without auto-saving a contact.

### IOS-CHN-05: Inspect channel membership honestly

**As a channel participant,** I want to understand who has recently spoken
without mistaking that list for an authoritative roster.

Acceptance criteria:

- Channel Detail labels the key-based membership model.
- A private/named symmetric channel does not claim to know all members.
- Observed senders appear only as **Recently seen participants**.
- Sharing the invitation and leaving/deleting the key are clear first-class
  actions.
- Managed-member controls remain absent until the managed-channel protocol is
  defined.

## Chat rooms

### IOS-ROM-01: Preview and join a room

**As a user discovering a chat-room node,** I want to inspect its capacity and
description before logging in.

Acceptance criteria:

- Room info can be fetched without login.
- Preview shows name, description, user counts, history bounds, and password
  requirement when supplied.
- The user chooses a handle and password only when needed.
- Saving the room node and joining the room are separate decisions.

### IOS-ROM-02: Reconcile a room message

**As a room participant,** I want my optimistic bubble to become the room's
canonical message rather than appear twice.

Acceptance criteria:

- The outbound message carries a sender sequence.
- The matching room echo updates the existing bubble with canonical ID/time.
- Identical rapid messages remain distinguishable.
- No echo leaves the message **Waiting for room** or eventually Failed.

### IOS-ROM-03: Catch up on room history

**As a returning room participant,** I want recent history and an honest path to
older available messages.

Acceptance criteria:

- Login requests messages since the last room timestamp.
- At most the automatic room batch appears without a manual history request.
- **Load earlier messages** requests a bounded older batch.
- The UI stops offering more when the room reports or demonstrates exhaustion.

### IOS-ROM-04: Log out without erasing history

**As a user,** I want to stop room push membership while retaining my local
record.

Acceptance criteria:

- Logout changes membership state and preserves local messages.
- Delete Local History is a separate destructive action.
- Rejoin can request missed messages based on the last stored room timestamp.

## Sensors and infrastructure

### IOS-NOD-01: Read a sensor resource

**As a user,** I want to inspect an advertised sensor value with its provenance
and age.

Acceptance criteria:

- The app names the source node, resource, units, and observation time.
- Stale data is labeled in text.
- A request in progress distinguishes radio transmission from a resource
  response.
- Unsupported resource content can be inspected in an advanced raw view.

### IOS-NOD-02: Inspect a repeater

**As a mesh operator,** I want to view repeater identity, regions, and route
evidence without implying that I can administer it.

Acceptance criteria:

- Observation details and administrative actions are separated.
- Management appears only when supported and authorized.
- Signal measurements retain units and are not converted to a universal score.
- Bridge/flood limitations can be inspected in diagnostics.

## Failure and maintenance

### IOS-ERR-01: Recover from connection loss

**As a user in a conversation,** I want an obvious but non-destructive response
when Bluetooth disconnects.

Acceptance criteria:

- A banner says **Radio disconnected** and offers Connect/Details.
- The banner shows **Last battery N%, AGE** or **Battery unavailable**, never an
  unlabeled stale reading.
- The current draft remains intact.
- Incoming-queue uncertainty is reconciled after identity/session checks.
- Reconnection does not reopen pairing for a valid bond.

### IOS-ERR-02: Export useful diagnostics safely

**As a user seeking support,** I want to export logs after reviewing sensitive
content.

Acceptance criteria:

- The export preview lists messages, public addresses, locations, device IDs,
  and key material as separate data classes.
- Secrets and message bodies are excluded by default.
- The user can cancel before the system share sheet.
- The report includes app, protocol, radio firmware, and capability versions.
