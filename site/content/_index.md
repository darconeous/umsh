+++
title = "UMSH"
description = "Off-grid group text chat over long-range radio, with encryption and authentication designed in from the start."
template = "index.html"

[extra]
# Both halves are unbreakable, so the only place the tagline can wrap is
# between them: either one line, or "done right." on a line of its own.
tagline = '<span class="nowrap">Off-grid text chat</span> <span class="nowrap">done right.</span>'
lede = """
Long-range radio instead of cell towers. Group chats that cover a region, with \
replies, reactions, and edits. And encryption that was the starting point of \
the design, not an afterthought."""

# Hero imagery. Leave a filename empty to render a labelled placeholder
# instead of a broken image.
hero_device_image = "t1000e.jpg"
hero_device_caption = "SenseCAP T1000-E companion radio"
hero_app_image = "peers.png"
hero_app_caption = "The UMSH app for iPhone"

# The pillars are the evidence for "done right" in the tagline: differences a
# reader can judge for themselves, with a user-facing consequence. Anything
# that is architecture rather than consequence belongs in `understand` below.
[[extra.pillars]]
title = "Encryption came first"
body = """
Your messages are encrypted — a channel conversation as much as a private one \
— using a construction that stays safe even when a node reboots and loses \
track of its counters. A private message is authenticated against your \
contact's own key as well, so it cannot be forged or quietly altered on the \
way."""
link = "/docs/protocol/security.html"
link_text = "Security model"

[[extra.pillars]]
title = "A chat that behaves like a chat"
body = """
Replies, reactions, edits, and deletes — the things you stop noticing until \
they are missing. Messages run to 1,600 bytes, so you can say what you mean \
instead of compressing it into a telegram."""
link = "/docs/protocol/app-text-messages.html"
link_text = "Text messages"

[[extra.pillars]]
title = "Forward secrecy that costs nothing"
body = """
Two nodes can agree on a pair of ephemeral addresses and simply talk to those \
instead. At the link layer the result is indistinguishable from any other \
conversation, so it needs no special handling by repeaters, no changes to \
application protocols, and adds no per-packet overhead at all."""
link = "/docs/protocol/security.html"
link_text = "PFS sessions"

[[extra.pillars]]
title = "Private channels are like VPNs"
body = """
A private channel is more than encrypted group chat: the shared key protects \
everything inside it, not just the group thread. To anyone without it the \
traffic is unreadable, unalterable, and does not disclose which member is \
speaking. Sharing a key is a QR code away."""
planned = """
Planned: one-to-one messages carried under the channel key, so they look like \
ordinary group traffic — plus key rotation and member removal."""
link = "/docs/protocol/multicast-channels.html"
link_text = "Channels"

[[extra.pillars]]
title = "Sent means carried, not just transmitted"
body = """
After transmitting, your radio listens for the mesh to pick the message up, and \
tries again if it does not hear that happen. Along a known path each hop \
confirms the next one the same way, so a message that stalls partway through \
gets another chance instead of vanishing without trace."""
link = "/docs/protocol/repeater-operation.html"
link_text = "Forwarding confirmation"

[[extra.pillars]]
title = "Nothing depends on the time"
body = """
Replay protection counts frames rather than reading a clock, so nothing about \
the security of a message rests on knowing the time. A radio that has sat in a \
drawer for a year, or has never seen a GPS fix, can start talking securely the \
moment you switch it on — and there is no clock skew for an attacker to work \
with."""
link = "/docs/protocol/security.html"
link_text = "Replay protection"

# How it works underneath — the second, quieter section.
[[extra.understand]]
title = "Your key is your address"
body = """
A node is identified by its Ed25519 public key, and that key is the address \
other nodes send to — no node numbers to collide, no registration, no authority \
handing out identifiers. On air, most packets carry a three-byte hint instead of \
the full key, which keeps frames small. A hint is still a stable pseudonym that \
a patient listener could follow; only an encrypted channel conceals the sender \
outright."""

[[extra.understand]]
title = "Strict layers, tight frames"
body = """
The link layer moves opaque payloads and never inspects them, so it can carry \
UMSH's own chat protocols, CoAP, or something you invent. Typical authenticated \
overhead runs 16 to 28 bytes, and every packet fits in a single LoRa frame."""

[[extra.understand]]
title = "Designed for amateur radio"
body = """
Amateur rules bar encryption that obscures the meaning of a message, and UMSH \
keeps the two separable: a message can carry authentication without carrying \
encryption, so a licensed operator does not have to give up integrity to stay \
legal. Operator and station callsigns ride along as compact options, and a \
repeater rewrites the station callsign as it forwards."""

[[extra.understand]]
title = "Built to be debugged"
body = """
A Wireshark dissector, a capture tool, and published test vectors ship with \
the protocol. Being able to read a packet trace is treated as a requirement, \
not a nicety — a protocol nobody can troubleshoot does not survive contact \
with a real deployment."""
+++
