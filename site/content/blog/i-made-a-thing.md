+++
title = "I made a thing..."
description = "A secure, off-grid LoRa mesh text protocol, a Rust reference implementation, six supported boards, and an iOS app—the story of an all-consuming side quest."
date = 2026-08-10

[extra]
# The social card for this post. Path is relative to static/, no leading
# slash. 1200x630; without it the post falls back to the site card.
image = "images/blog/i-made-a-thing.png"
+++

![A SenseCAP T1000-E next to an iPhone 17 running the UMSH app](/images/blog/i-made-a-thing.png)

So... I made a thing. And I'm not sure what to do about it.

I think it's cool, and I'd like to share it with you, but it's different than the [interactive light sculptures](https://lumanoi.com) I've been making.

First, I made my own [secure, off-grid LoRa-based mesh text chat protocol](/docs/protocol/). And then I made a [reference implementation for it in Rust](https://github.com/darconeous/umsh). And then I ported that reference implementation to [half a dozen different LoRa hardware platforms](/hardware/). And then I [wrote an iOS app](/app/) to control those hardware platforms and send/receive text messages.

I call it [UMSH](/).

Don't worry, I'm not stopping with the interactive light sculptures—this is a side quest. A bit all-consuming as of late, but still a side quest.

If you are curious how in the world I got to this point, well... read on.

Before I was making [interactive light sculptures](https://lumanoi.com), I was working at Google on what I described as low-power wireless mesh networking, [Thread](https://threadgroup.org) specifically. I had been doing it for over 10 years. I was tired of it, and needed to do something different that scratched my other creative itches. So I started [Voria Labs](https://voria.com) and started making interactive light sculptures.

But I guess there is still a part of me that really likes doing the low-power wireless mesh networking thing. Several months ago I started looking into LoRa-based mesh text chat protocols, like [Meshtastic](https://meshtastic.org) and [MeshCore](https://meshcore.io). These systems allow you to have long-range text communication with groups or individuals that doesn't rely on cellular infrastructure.

MeshCore, specifically, was interesting to me since the addresses were public keys and it was all source-routed. I started to use it myself, and it was decent enough. Then I went to go look under the hood to see how it was implemented... Well, let's just say that it was clear that MeshCore took a code-first approach to protocol design.

With a code-first approach, you write the code and get it working, and the source code ends up defining the protocol. This can be OK in certain contexts, but it is often a huge liability. In the case of MeshCore, that liability was a brittle, hard-to-extend protocol with [textbook-naive cryptography](https://github.com/meshcore-dev/MeshCore/issues/259). A proper fix would practically require compatibility-breaking changes to the protocol.

Which got me to thinking: Knowing what I now know, what would a protocol-first design for something like MeshCore look like? What would a "MeshCore 2.0" be if it was made with a professional-quality protocol-first design with proper cryptography and a flexible packet format?

And that was the start of me falling down the rabbit hole of protocol design again. I love designing protocols. I think I am fairly decent at it. So, on a lark, I started designing what I thought might be a good starting point for a "MeshCore 2.0".

Now, to be clear, I'm not affiliated with MeshCore in any way. It would be wildly presumptuous of me to actually call whatever-it-was that I was writing "MeshCore 2.0". But I also can't really work on something without a name, so I just came up with a random one: *UMSH*.

I strung together some of my ideas into a semi-coherent document and I brought it up on the MeshCore discord, half expecting to be burned at the stake. Instead, many people seemed fascinated and interested. I kept refining and improving, and eventually what I had was [comprehensive protocol documentation](/docs/protocol/).

Even with that, however, there seemed to be little motivation for any serious discussion about a future "MeshCore 2.0", especially an effort kicked off by an outsider who just came in and said that everything should be done differently. I get it.

At that point, I had a protocol but no implementation. Some time passed. Eventually I decided I should just go for it and see how far me (and Claude) could get with turning the protocol into a working reference implementation. With a full protocol specification in hand, the code would have something to be measured against, instead of becoming the definition itself.

Working with Claude to write code feels a bit like working with an enthusiastic junior software engineer with a short attention span and a habit of micro-dosing LSD. It's certainly interesting, and I got way more done than I would have otherwise, but I also had to be eagle-eyed about the decisions it was making. It's certainly not as easy as pointing the LLM at the protocol and saying "implement this"—keeping it on the rails required my full attention and it was a bit exhausting. But it's hard to argue with the results.

I worked like a madman, thinking "ok, after this feature I'll stop", but I kept finding more pain points and more features to implement. After several weeks of work, I now have a quite large chunk of the protocol completely implemented in Rust, as well as a reasonably functional iOS app to go with it. And six supported LoRa hardware platforms. And Wireshark support. And a command-line radio management tool. And a website, with a web-flashing tool.

And now, I must stop this breakneck development for at least a month or two. Maker Faire is coming up, and I just got a really big Lumanoi commission for a project in San Jose that I am extremely excited about.

So now that this is out there, what is next? I'm calling this a *technology preview* at this stage, so no one mistakes it for something to depend on just yet. I plan to continue to fix bugs and add features based on feedback, and I'm hoping that what I've written will resonate with a lot of people. Who knows? Maybe it will take off. Let's find out.

Check out the [protocol](/docs/protocol/), join the [iOS app beta](/app/), flash some [hardware](/hardware/), and [let me know what you think](https://github.com/darconeous/umsh/discussions).