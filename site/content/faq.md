+++
title = "Questions"
description = "What UMSH is, what it is not, and what you should expect from it right now."
weight = 5
+++

<div class="faq-item">

### What is UMSH?

A mesh networking protocol for long-range, low-power radios — the kind of
hardware that can send a short text message several kilometres on a coin cell's
worth of energy. It is designed for group text chat and for reporting position
and sensor readings across an area with no cell coverage and no infrastructure
of any kind.

It is also a specification, a Rust implementation, firmware for half a dozen
boards, an iPhone app, and a Wireshark dissector. All of it is open source.

</div>
<div class="faq-item">

### Why another mesh protocol?

It started as a question about MeshCore: what would this look like if the
cryptography were done properly and the layers were kept separate? Several of
the answers turned out to require changes that would break compatibility, and
at that point it was a different protocol.

The honest framing is that few of the ideas here are new — cryptographic
addressing, source routing, and regions all come from MeshCore. What UMSH
contributes is putting them together with stronger cryptography, composable
routing, and a link layer that never looks inside a payload.

</div>
<div class="faq-item">

### Is it ready to use?

It is a technology preview. It works — nodes talk to each other, messages
arrive, the app is usable — but the protocol is still moving and will keep
moving for months. Expect changes that break compatibility, and expect to
reflash your radios when they happen.

If you want a mesh that works reliably today with a large community behind it,
use [Meshtastic](https://meshtastic.org). That is a genuine recommendation,
not a formality. Come back to UMSH when you want to see where a stricter
design goes.

</div>
<div class="faq-item">

### Can UMSH talk to Meshtastic or MeshCore?

No, and it never will. The packet formats, the cryptography, and the identity
models are all different at the lowest level. A radio runs one of these
protocols at a time.

Radios are not locked to anything, though. The boards UMSH supports are the
same boards those projects support, and you can flash back and forth as often
as you like.

</div>
<div class="faq-item">

### What hardware do I need?

At least one radio, and realistically two, since a mesh with one node in it is
just a radio. The [hardware page](/hardware/) lists everything supported.

If you are buying your first board and want the path most likely to work, get
a SenseCAP T1000-E. It is the board most of the development happened against,
and it is sealed, pocketable, and hard to damage.

</div>
<div class="faq-item">

### How far does it actually reach?

Between two radios with a clear line of sight, several kilometres, and much
more from a hilltop. Between two people standing in a city with buildings in
the way, sometimes only a few hundred metres.

Be sceptical of any specific number, including the ones on the boxes these
radios come in. Range depends on antennas, terrain, height, and how much
patience you have for slower settings. What a mesh adds is that nodes relay
for each other, so coverage is about where the nodes are rather than how far
any one of them shouts.

</div>
<div class="faq-item">

### Does it need the internet or a phone signal?

No. Radios talk directly to each other, and the app talks to your radio over
Bluetooth. A group of UMSH nodes works with every phone in aeroplane mode and
no network for a hundred kilometres.

Bridging two distant meshes over the internet is possible, and the
specification is deliberately grudging about it: a bridge cannot be relied on
in an emergency, and it can waste airtime on chatter from somewhere far away.

</div>
<div class="faq-item">

### Can I use it on amateur radio bands?

Yes, and the protocol was designed with that in mind. Traffic can be
authenticated without being encrypted, which is what regulations that forbid
obscuring the meaning of a transmission require. Operator and station
callsigns have their own compact encoding, and repeaters update the station
callsign as they pass a packet along.

You are responsible for operating within your own licence and your country's
rules.

</div>
<div class="faq-item">

### Is there an Android app?

Planned, not started. The [app page](/app/) has the detail. The protocol core
is shared and portable, which is a real head start, but there is no app and no
date.

</div>
<div class="faq-item">

### How much of this was written by an AI?

A great deal of it, and that is stated plainly rather than hidden. The
specification, the implementation, and this website were all written with
heavy help from large language models, under close human direction and review.

The project's [note about it](https://github.com/darconeous/umsh/blob/main/docs/AI.md)
is worth reading if that matters to you — and it is reasonable for it to
matter. Judge the result on whether the cryptography is sound and the packets
decode, which is why the specification, the test vectors, and the dissector
are all public.

</div>
<div class="faq-item">

### How do I help?

Use it and say what broke. Bug reports from someone with real hardware in
hand are the most valuable thing this project can receive right now.

Beyond that: port a board, read the specification and pick holes in it, or
write the Android app. The comparison chapters in particular ask to be
corrected if they are unfair to anyone.

If you would rather support the work financially, there is a
[sponsors page](https://github.com/sponsors/darconeous).

</div>
<div class="faq-item">

### What is the licence?

The code is dual licensed under Apache 2.0 and MIT, at your option. The
specification is published so that anyone can implement it, including in a
different language, on different hardware, or inside another project
entirely.

</div>
