+++
title = "Questions"
weight = 5
+++

<div class="faq-item">

### What is UMSH?

UMSH is a mesh networking protocol that enables long-range, low-power, secure text
messaging, without relying on cellular infrastructure or internet access.

UMSH devices contain LoRa radios and run firmware that implements the UMSH protocol.

The UMSH app allows you to use a UMSH device from your phone to send and receive
text messages, much how you would using any other messaging app; the difference
being that the messages are not sent across the internet but are instead routed
over the UMSH mesh network.

</div>
<div class="faq-item">

### Is it ready to use?

It is ready to use, test, and experiment with—but not yet to deploy
extensively. It's a technology preview. Nodes talk to each other, messages
arrive, encryption happens, and the app works, but the protocol is still moving
and will keep moving. Expect changes that break compatibility and expect to
reflash your radios when that happens.

There's no installed base to protect yet, so when a design decision and
backward compatibility are in conflict, the design wins.

If you need to deploy something today that is more mature, you should consider
Meshtastic or MeshCore.

</div>
<div class="faq-item">

### Can UMSH talk to Meshtastic or MeshCore?

Not today. The packet formats, the cryptography, and the identity models are
different at the lowest level, so this isn't a setting somewhere—a radio runs
one of these protocols at a time, and anything joining the two would have to be
a node that speaks both and translates.

The radios themselves aren't locked to anything. UMSH runs on the same boards
those projects run on, and you can flash back and forth as often as you like.

There is some possibility that MeshCore support may be added to the app and to
repeaters so that repeaters can forward both MeshCore and UMSH traffic, and the
app can communicate with contacts from either. But that's far from decided.

</div>
<div class="faq-item">

### What hardware do I need?

At least two radios (or a radio for yourself and someone else with a radio),
since a mesh with one node in it is just a radio. The [hardware page](/hardware/)
lists everything supported.

</div>
<div class="faq-item">

### Does it need internet access or a cell signal?

No, but you do need some [hardware](/hardware/) in addition to your phone.

</div>
<div class="faq-item">

### Can I use it on amateur radio bands?

Yes, [it was designed for that](/docs/protocol/amateur-radio.html).
Authentication is separable from encryption; it's only the encryption that
the amateur radio rules explicitly prohibit. UMSH can work in an
authentication-only mode.

Additionally, operator and station callsigns have their own compact encoding,
and repeaters update the station callsign as they pass a packet along.

Note, this mode isn't yet exposed in the iOS app but it will be soon.

</div>
<div class="faq-item">

### Is there an Android app?

Not yet, but hopefully there will be at some point.

</div>
<div class="faq-item">

### How much of this was written by an LLM?

Quite a bit of it. The protocol specification benefited from LLMs to improve
readability and for helping to research the comparison chapters.

The reference implementation, the dissector, and the app were largely written
by LLMs (under heavy human supervision).

There's a [longer note about it](https://github.com/darconeous/umsh/blob/main/docs/AI.md)
in the repository, including why I don't consider UMSH slop.

</div>
<div class="faq-item">

### What's the license?

The code is dual licensed under Apache 2.0 and MIT, at your option.

</div>
