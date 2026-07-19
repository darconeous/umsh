# Messaging and Delivery States

UMSH applications should feel like familiar messaging tools while remaining
honest about radio latency, packet loss, fragmentation, and the different kinds
of evidence available for direct messages, channels, and chat rooms.

## Conversation kinds

The conversation list combines three interaction types and labels them with an
icon and accessible text:

| Kind | Transport behavior | Meaning of success evidence |
|---|---|---|
| Direct | Unicast or blind unicast to one node | A valid MAC acknowledgement can show arrival at the destination node |
| Channel | Multicast to every holder of a shared channel key | Transmission does not prove that any member received it |
| Room | Unicast submission to a chat-room node, then room distribution | The room's correlated echo proves room acceptance and supplies the canonical message ID |

The conversation kind remains visible in both the list row and the open
conversation. Do not rely on a `#` glyph or other icon alone. A channel row,
for example, says **Private channel** or **Public named channel** alongside its
message preview. Its open transcript repeats that type and the multicast
audience near the title and composer.

Users should not have to choose the packet type for routine messages. A detail
view may show the selected privacy and routing behavior.

### Channel chat interaction

A joined channel is a normal conversation destination. Selecting it opens a
multi-sender transcript and composer. Pressing **Send** creates one multicast
text message addressed to the channel; the application does not ask the user to
select members or send separate direct copies. Every listening node that holds
the channel key is eligible to receive and display it.

Opening a channel therefore does not switch into a special setup mode. It uses
the familiar conversation screen, but persistently labels the destination as a
channel. The header identifies the channel type and multicast behavior, a brief
audience line says **Everyone with the channel key**, and the composer names the
destination, such as **Message Trail Crew channel**. Channel Detail remains a
separate Info destination.

Incoming bubbles identify their claimed/resolved sender. Recently observed
senders are useful transcript participants, not an authoritative roster and not
the target list for Send. Channel settings and invitation sharing live in a
secondary Channel Detail screen reached from the conversation title or Info
action.

Channel transcripts use chat bubbles to separate messages visually:

- incoming bubbles use one platform-adaptive neutral surface;
- the sender's deterministic NodeHint avatar and resolved name precede the first bubble in a
  consecutive group;
- consecutive messages from the same sender use tighter spacing, while a sender
  change creates a larger break;
- the user's bubbles use the platform's outgoing/accent treatment and align to
  the trailing edge;
- time, retry, and delivery evidence sit outside the bubble; and
- replies, reactions, missing fragments, and edited/deleted state remain
  readable without relying on bubble color.

Do not assign every participant a different bubble color. Sender name, avatar,
grouping, and alignment must be sufficient for identification in grayscale,
high-contrast modes, and with remote color suggestions disabled.

## Outbound lifecycle

Use text labels in message details and accessible descriptions; compact icons
may summarize them in the transcript.

| State | Meaning | Typical visible treatment |
|---|---|---|
| Draft | Stored locally and not committed | Text in composer or Draft label in list |
| Preparing | Application is encoding or fragmenting | Brief progress indication |
| Sending | One or more frames are being handed to the radio | Progress when fragmented |
| Transmitted | The radio reported local transmission success | **Sent over radio** in details; not **Delivered** |
| Delivered to node | A valid direct-message acknowledgement arrived | **Delivered to node** |
| Accepted by room | A correlated room echo arrived | Replace pending local identity with canonical room message identity |
| Delivery unconfirmed | The active send ended after local transmission without the expected direct acknowledgement or room echo | **Sent over radio · delivery unconfirmed**; effectively terminal, with no progress indicator or promised automatic resolution; valid late evidence may still upgrade it |
| Failed | The send attempt could not complete — the link dropped mid-send, the radio rejected it, or an error occurred | Specific reason and an explicit Retry action |
| Partially sent | Some fragments transmitted but the logical message is incomplete | Name missing/failed fragments; allow retry of the logical message |

There is no waiting-for-radio state: an eligible user send starts immediately,
while an ineligible send remains a draft. After it starts, the MAC may schedule
contention, fragmentation, acknowledgements, and retransmissions as part of
that active send. This is not a deferred application send. Waiting for a direct
acknowledgement or room echo after transmission is likewise not queueing.

Channel messages normally stop at **Transmitted**. They must not receive a
double-check or **Delivered** label merely because local transmission
succeeded.

The conversation row may use a short summary such as **Sending**, **Failed**,
or **Sent**. Tapping message details must reveal what the label means for that
conversation kind.

## No deferred application outbox

The application does not preserve an outbound operation to begin automatically
at some future connection or duty-limit window. Activating an eligible Send
starts one logical send immediately; activating a blocked Send explains why it
cannot start. Once active, ordinary MAC scheduling, backoff, fragmentation,
acknowledgement handling, and retransmission may continue until that send
reaches a terminal result. Consequences:

- when no usable radio is connected, Send looks blocked and its action explains
  why without transmitting; the draft is preserved;
- a failed message stays in the transcript with its reason and an explicit
  Retry action; no new application-level attempt begins automatically after a
  terminal result;
- retry re-validates the current identity, radio, and channel context — a
  failed message can never silently re-send under a replaced identity or
  changed configuration; and
- reconnection never triggers a backlog of automatic sends, because there is
  no backlog.

A message awaiting a direct acknowledgement or room echo is not queued: its
active send has already begun, and only confirmation is outstanding. If that
send ends without confirmation, including because the radio disconnects,
**Delivery unconfirmed** is effectively terminal. The app stops progress UI,
does not automatically begin another application-level attempt on reconnection,
and does not promise that later evidence will resolve the state. Valid late
evidence may still upgrade the recorded result without making it pending in the
meantime.

Every UMSH chat send includes the text protocol's Message Sequence option. A
manual Retry is a new transmission attempt for the same logical chat message:
it reuses that message's Message Sequence ID but creates new packets with fresh
packet counters. Receivers use sender identity, conversation context, and the
Message Sequence ID to reconcile an already-received resend rather than display
a duplicate bubble. All fragments of the resent logical message retain the same
Message Sequence ID and their defined fragment indices.

## Composer

The composer supports plain UTF-8 text first. Reply, reaction/emote, edit, and
delete appear through conventional message actions. Unsupported options from a
received message must not prevent its body from displaying.

Before sending:

- estimate whether the message fits one frame;
- for fragmentation, show a quiet **Will send as N parts** indication;
- block transmission from Send when the content cannot be represented, no
  valid destination exists, or the radio's current duty limit is known to
  reject the complete logical message;
- when duty-limited, preserve the draft, give Send a visibly blocked treatment,
  explain the reason when it is activated, and show the earliest reliable time
  or estimate at which sending can be tried again;
- apply the same blocked treatment when no connected, configured radio is
  available, with the action explaining the reason and the draft preserved; and
- warn before an unusually expensive flood or large fragmented send.

Duty-limit prevention is not an outbox or deferred-send feature. If the
radio rejects a send with `STATUS_DUTY_LIMIT` despite the preflight check, mark
that attempt **Failed**, retain the message for an explicit user retry, and
show the earliest reliable retry time or estimate. Do not start a new
application-level attempt automatically; this does not constrain MAC retries
within the original active attempt. If the available radio information cannot
support an exact time, say so rather than presenting a false timestamp.

The application should preserve unsent drafts per conversation.

## Replies, reactions, edits, and missing content

The protocol's message identifiers wrap and are not permanent global IDs.
Applications may maintain durable local identifiers, but must only offer a
reply or reaction when the required wire reference can still be represented.
If it cannot, offer **Quote in new message** rather than sending an invalid
Regarding reference.

Show the latest edit in the transcript with an **Edited** label. A detail view
may show edit history. A zero-length edit renders as a deleted-message
placeholder without erasing local audit information needed to interpret
replies.

When fragments are missing, render a localized missing-content marker in the
message rather than silently concatenating the remaining text. An automatic
resend request is transport behavior and should not appear as a chat message.

## Incoming requests and unknown senders

An authenticated direct message from a node that is not a contact belongs in a
Message Requests area. The user may **Accept**, **Block locally**, **Save
contact**, or **Delete**. Accepting moves the conversation into the normal list;
it does not claim real-world identity verification.

Channel traffic is visible only for joined channels. The `public` and
`EMERGENCY` channels must enforce their source-key, encryption, and signature
rules before a message reaches the transcript. Rejected traffic may be counted
in diagnostics but should not create alarming user-visible phantom messages.

## Room behavior

A room preview shows its name, description, active/max users, retrievable
history window, and password requirement when known. Joining is distinct from
saving the room node.

While logged in, show membership state and the room-provided handle. On
reconnect, the application requests recent history from the last room timestamp
and can expose **Load earlier messages** when more than the automatic batch is
available. Room timestamps are room-provided and may be inaccurate; the detail
view may identify their source.

Logging out stops room push membership but does not erase local history. A
separate delete action removes local conversation data.

## Notification behavior

Notifications should prioritize human messages and actionable sensor events.
Routine beacons, route changes, and radio diagnostics do not generate user
notifications by default. Channel and room notifications can be muted
independently. Urgent presentation is reserved for explicit user policy and
must not be inferred merely from the `EMERGENCY` channel name.
