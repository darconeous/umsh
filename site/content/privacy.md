+++
title = "Privacy"
description = "What this website and the UMSH software collect about you. The short answer is nothing."
weight = 8
+++

*Last updated 7 August 2026.*

## This website

This site collects nothing about you.

There are no analytics, no tracking pixels, no advertising, and no cookies. No
scripts from other companies run on these pages, and there are no forms to
submit anything to. Nothing you do here is recorded by us, because there is
nothing here to do the recording.

The site is a set of static files hosted by GitHub Pages. GitHub serves them
and, like any web server, sees the requests that reach it — your IP address,
the page you asked for, and your browser's user agent. That is between you and
GitHub, and it is covered by
[GitHub's privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).
We do not have access to those logs and do not receive any report derived from
them.

Pages that link outward — to Seeed Studio, to Heltec, to GitHub Sponsors —
take you to sites with their own practices, which are their own business and
not covered here.

## The firmware flasher

The flasher, once it exists, will run entirely inside your browser. It will
download firmware images from this site and from the project's GitHub
releases, and it will talk to the radio you plug in through your browser's
serial interface. Your browser will ask your permission before it can see any
device at all, and that permission covers only the one device you pick.

Nothing about your device is uploaded anywhere. There is no server side to
this — the page has nowhere to send anything even if it wanted to.

## The iPhone app

The app collects no analytics and contains no third-party software
development kits. It has no account system, so there is nothing to sign up
for and nothing to sign in to.

Your identity is an encryption key generated on your phone. It is stored in
the iOS keychain, marked as belonging to that device alone, which means it is
excluded from backups and never syncs to iCloud or to another device. Nobody
else — including us — ever holds a copy. If you lose the phone, that identity
is gone, and a new one takes its place.

Messages travel over radio, directly between devices, encrypted to the
recipient's key. They do not pass through any server we operate, because there
is no server we operate.

Location sharing is off until you switch it on. When you do turn it on, your
position goes out over the radio to the channel or contact you chose, exactly
like any other message.

## The protocol itself

Radio is a shared medium, and anyone nearby with a receiver can hear that
*something* was transmitted. UMSH is designed to give away as little as
possible beyond that: addresses travel as short hints rather than as
identities, encrypted multicast conceals who sent a packet, and blind unicast
can make a private message look like ordinary channel traffic.

None of this hides the fact that a radio transmitted, and none of it defeats
someone with direction-finding equipment. If that is part of your threat
model, read the
[security chapter](/docs/protocol/security.html) and the
[limitations chapter](/docs/protocol/limitations.html) before relying on
anything here.

## Changes

If this page changes in a way that matters, the date at the top changes with
it. The full history of this page is public in the project's git repository.

## Contact

Questions about any of this belong in
[an issue on GitHub](https://github.com/darconeous/umsh/issues).
