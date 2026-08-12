+++
title = "UMSH"
description = """
UMSH is a new mesh networking protocol enabling long-range text messaging \
without relying on cellular connectivity or internet access—designed from the ground up \
for strong security and ease of use.\
"""
template = "index.html"

# Every word on the home page lives in this file. `index.html` holds only
# markup: if you want to change copy, change it here. Prose fields are
# rendered as Markdown, so links, emphasis, and code spans all work.
[extra]
# Browser tab and search-result title, which is deliberately more descriptive
# than the `title` above.
page_title = "UMSH — an experimental LoRa mesh protocol"

hero_eyebrow = "Open mesh networking over LoRa"

# Both halves are unbreakable, so the only place the tagline can wrap is
# between them: either one line, or "done right." on a line of its own.
tagline = '<span class="tagline__part">Off-grid text chat</span>'
lede = """
UMSH is an experimental mesh networking protocol for long-range text messaging \
without relying on cellular connectivity or internet access—designed from the ground up \
for strong security and ease of use."""

# The first button points at TestFlight once `ios_beta_url` is set in
# config.toml, and at the app page until then — hence the two labels.
hero_cta_beta = "Join the iOS beta"
hero_cta_beta_pending = "Get the iOS beta"
hero_cta_spec = "Read the specification"
hero_note = "Open source, and open to anyone who wants to build on it."

# Hero imagery: one transparent composite, no frame and no caption. Leave the
# filename empty to render a labeled placeholder instead of a broken image.
hero_image = "hero.png"
hero_alt = "A SenseCAP T1000-E radio next to an iPhone showing a UMSH group conversation"

# The band under the hero. Two paragraphs, so mind the blank line.
[extra.status]
badge = "Technology preview"
body = """
While UMSH works today, it is not finalized. The protocol will continue to evolve
over the next several months. Expect breaking changes, and expect to reflash your
radios when they land.

You can take part right now: flash a supported board, and [join the iOS beta](/app/).

Much of this project was written with the help of LLMs (large language models).
You can learn more about this project's LLM use [here](https://github.com/darconeous/umsh/blob/main/docs/AI.md).
"""

[extra.pillars_head]
title = "What makes it different"
# intro = ""

# The pillars are the evidence for "done right" in the tagline: differences a
# reader can judge for themselves, with a user-facing consequence. Anything
# that is architecture rather than consequence belongs in `understand` below.
[[extra.pillars]]
title = "Strong Cryptography"
body = """
Cryptography is hard, and few LoRa-based text chat systems get it right. \
UMSH takes a conservative approach to message privacy using well-studied \
mechanisms that are straightforward to implement and don't fail catastrophically, \
like [AES-SIV](https://datatracker.ietf.org/doc/html/rfc5297)."""
link = "/docs/protocol/security.html"
link_text = "Security model"

[[extra.pillars]]
title = "Modern Text Chat"
body = """
UMSH supports modern text chat features like long messages, replies, reactions, edits, \
and deletes—the things you stop noticing until they are missing."""
link = "/docs/protocol/app-text-messages.html"
link_text = "Text messages"

[[extra.pillars]]
title = "Forward Secrecy"
body = """
Perfect Forward Secrecy (PFS) sessions allow you to communicate with a peer in a way \
that cannot be later decrypted even if the private key of one of the devices \
is later compromised. These sessions not only provide forward secrecy but also \
obfuscate the identity of the participants involved, helping to further improve privacy. \
"""
link = "/docs/protocol/security.html#perfect-forward-secrecy-sessions"
link_text = "PFS sessions"

[[extra.pillars]]
title = "Beyond Private Group Chat"
body = """
In UMSH, private channels enable more than just encrypted group chat—they can protect \
unicast chats as well while also obfuscating the sender and destination, kind of like a VPN.
UMSH calls this *blind unicast*. \
To anyone without the channel key the traffic is unreadable and unalterable. \
You can easily invite others to a private channel by sharing a QR code in person \
or with a simple UMSH text message."""
disclaimer = """
Blind unicast support is implemented in the stack and will be exposed in the iOS app soon."""
link = "/docs/protocol/multicast-channels.html"
link_text = "Channels"

[[extra.pillars]]
title = "Resilient Repeating"
body = """
UMSH has two forwarding modes: Flooding and Source Routing. Flooding is \
used for path discovery and group chats, whereas source routing is used for \
normal one-on-one text chats. Unlike some other source-routed protocols, UMSH \
repeaters will retry transmitting if they don't notice the next hop repeating the \
message. This dramatically improves the reliability of long-distance sessions. \
UMSH also allows composing both source routing and flooding, providing a degree \
of path-self-healing for mobile nodes. \
"""
link = "/docs/protocol/repeater-operation.html#forwarding-confirmation"
link_text = "Forwarding confirmation"

[[extra.pillars]]
title = "Replay Protection"
body = """
Other LoRa-based mesh protocols have struggled with replay protection, using \
timestamps that require accurate clocks or caching the signatures of previously-seen \
packets. UMSH uses frame counters and fast counter synchronization to prevent \
replay attacks. Additionally, no core UMSH functionality depends on the node \
knowing what time it is, removing another common source of annoyance. \
"""
link = "/docs/protocol/security.html"
link_text = "Replay protection"

[extra.understand_head]
title = "Understanding UMSH"
# intro = """
# How the thing works underneath, for anyone who wants to look. None of it is \
# required reading to use a radio."""
link_text = "Read the full specification"

# How it works underneath—the second, quieter section.
[[extra.understand]]
title = "Public Key Addressing"
body = """
A node is identified by its Ed25519 public key, which is also the address \
other nodes use to identify you. The only nodes that can communicate with you one-on-one \
are those you have shared your public key with, and who have shared their public \
key with you. Sharing your public key is easy: you can share your key in a URL, \
using a QR-Code, or send it privately to someone in a group chat. """
link = "/docs/protocol/addressing.html"
link_text = "Addressing"


[[extra.understand]]
title = "Strict layers, tight frames"
body = """
The link layer moves opaque payloads and never inspects them, so it can carry \
UMSH's own chat protocols, CoAP, or something you invent. Typical authenticated \
overhead runs 16 to 28 bytes, and every packet fits in a single LoRa frame. """
link = "/docs/protocol/introduction.html#design-principles"
link_text = "Design principles"

[[extra.understand]]
title = "Designed for amateur radio"
body = """
Amateur rules bar encryption that obscures the meaning of a message, and UMSH \
keeps the two separable: a message can carry authentication without carrying \
encryption, so a licensed operator can still benefit from strong authentication. \
Operator and station callsigns ride along as compact options, and a \
repeater rewrites the station callsign as it forwards, making it easy to identify \
who is responsible for a transmission when used in this way."""
link = "/docs/protocol/amateur-radio.html"
link_text = "Amateur radio"

[[extra.understand]]
title = "Built to be debugged"
body = """
A Wireshark dissector, a capture tool, and published test vectors ship with \
the protocol. """
link = "https://github.com/darconeous/umsh/blob/main/dissectors/README.md#umsh-wireshark-dissector"
link_text = "Wireshark support"

[extra.compare_head]
title = "How it compares"
intro = """
UMSH was largely inspired by [MeshCore](https://meshcore.io/), so it is natural to draw some comparisons to it. \
What follows are quick summaries of our much more detailed comparison documents, linked \
below. If you find anything inaccurate or out-of-date, please \
[file an issue](https://github.com/darconeous/umsh/issues/new) so we can correct it!"""

# Each table is `columns` plus `rows`, so a row is read left to right exactly
# as it appears on the page. `link` is relative to `protocol_url`.
[[extra.comparisons]]
heading = "MeshCore Comparison"
columns = ["Aspect", "UMSH", "MeshCore"]
rows = [
  ["Address on the wire", "3-byte hint, or the full public key when the receiver may not know it", "1-byte hash, with a dedicated packet type for first contact"],
  ["Encryption", "AES-256-CTR in a SIV construction (RFC 5297)", "AES-128-ECB"],
  ["Authentication", "S2V (AES-CMAC), 4 to 16 bytes", "HMAC-SHA256 truncated to 2 bytes"],
  ["Key derivation", "HKDF-SHA256, with separate encryption and authentication keys", "The ECDH secret used directly for both"],
  ["Replay protection", "Monotonic frame counters, no clock involved", "A 128-entry duplicate cache, with timestamps above"],
  ["Routing", "Independent options that combine freely", "A path field and route-mode bits"],
  ["Layering", "The link layer never inspects payloads", "Link, network, and application concerns combined"],
]
link = "meshcore-comparison.html"
link_text = "Read the full comparison"

[[extra.comparisons]]
heading = "Meshtastic Comparison" 
columns = ["Aspect", "UMSH", "Meshtastic"]
rows = [
  ["Identity", "An Ed25519 public key, which is also the address", "A 32-bit node number derived from the Bluetooth address"],
  ["Spoofing", "The address is a cryptographic credential", "Node numbers are not bound to any key"],
  ["Authentication", "Private messages bound to the sender's key; channel traffic carries an integrity tag", "None on channel traffic; direct messages only, since v2.5"],
  ["Header privacy", "Compact hints; Channel-based source/destination concealment", "16-byte cleartext header on every packet"],
  ["Typical overhead", "16 to 28 bytes, authentication included", "About 22 bytes for channel traffic, about 42 for direct messages"],
  ["Forward secrecy", "Available", "Not available"],
  ["Maturity", "Experimental, one app, six boards", "Mature, huge community, dozens of devices, a rich application layer"],
]
link = "meshtastic-comparison.html"
link_text = "Read the full comparison"

[extra.steps_head]
title = "Getting started"
intro = "You need one radio to listen, and two to have a conversation."

# `link` is a Zola internal path, so a renamed page breaks the build instead
# of shipping a dead link.
[[extra.steps]]
title = "Get a radio"
body = """
Six boards are supported, from a sealed pocket tracker to a solar-powered node \
you can bolt to a roof. The T1000-E is the one most of this was developed \
against."""
link = "@/hardware.md"
link_text = "Supported hardware"

[[extra.steps]]
title = "Flash it"
body = """
One command builds and installs the firmware for your board. A browser-based \
flasher that needs no toolchain at all is on the way."""
link = "@/flasher.md"
link_text = "Flashing instructions"

[[extra.steps]]
title = "Pair your phone"
body = """
The iPhone app connects to your radio over Bluetooth and gives you \
conversations, contacts, and a map. It is in beta."""
link = "@/app.md"
link_text = "About the app"
+++
