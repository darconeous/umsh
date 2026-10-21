# Communicators

Communicators are self-contained UMSH clients. A phone is never part of the
critical path for setup, reading, composing, sending, status, settings, or
recovery. Their default screen should answer:

- What conversation or activity needs attention?
- Is the radio/device connected and able to send?
- What is the battery state?
- What will the primary control do now?

## Proposed information architecture

1. **Home / Inbox**—conversations, unread state, delivery summary
2. **Conversation**—message history and compose entry
3. **Nodes / Contacts**—reachable identities and details
4. **Channels**—membership and channel activity
5. **Device status**—radio, location, battery, storage, companion state
6. **Settings**—notifications, display, input, radio policy
7. **Maintenance**—pairing, diagnostics, firmware update, destructive resets

Maintenance actions should not compete visually with messaging.

## Composition

- Preserve drafts when leaving a conversation accidentally.
- Make recipient/channel and Send state visible while composing.
- Distinguish queued, transmitted, acknowledged, delivered (if the protocol
  can prove it), and failed. Never invent a stronger delivery claim.
- Provide an explicit cancel path for queued work when technically possible.

## Adding peers

Every communicator adds peers without anyone typing an address. A board
without a feature, such as NFC, leaves out the parts that use it and nothing
else changes. The screens are in the
[T-LoRa Pager mockups](../hardware/mockups/tlora-pager-messenger.svg),
Peers section.

**Add peer** heads the Peers list. It opens on **Nearby**, followed by
**Enter an address** and **Show my code**.

| | |
|---|---|
| ![Add peer](../hardware/mockups/tlora-pager-native/34-add-peer.png) | ![Asked to exchange](../hardware/mockups/tlora-pager-native/35-asked-to-exchange.png) |

- **Nearby** lists the devices that also have Add peer open, nearest first.
  A device is discoverable only while this screen is open.
- **Nothing identifying is sent before both people agree.** Each row shows
  only the device's model and a color, never a name, address, hint or
  avatar. The color comes from a session key made fresh each time Add peer
  opens, so it identifies nothing afterward. The header shows this device's
  own color beside **You**, so two people holding the same model can tell
  which row is whose.
- The person is the identification. Pressing a row asks that device to
  exchange; its holder sees **Exchange contacts?** and knows who asked by
  who is standing there.

| | |
|---|---|
| ![Compare](../hardware/mockups/tlora-pager-native/36-compare.png) | ![Waiting](../hardware/mockups/tlora-pager-native/37-waiting.png) |

- After **Exchange**, both screens show a six-digit code. The codes match
  only if nobody is in the middle, and both people must press **Same**.
- Only after both press Same do the devices send their addresses and
  names. Each then shows the other on the ordinary sheet for a peer who is
  not saved: it opens on Message, and Save peer is one turn down. Nothing
  is saved until Save peer is pressed.
- **Different** on either side ends it for both: nothing has been sent and
  nothing is saved. Leaving the code screen cancels the same way.

| | |
|---|---|
| ![Codes differ](../hardware/mockups/tlora-pager-native/38-codes-differ.png) | ![Exchanged](../hardware/mockups/tlora-pager-native/39-exchanged.png) |

**Tap.** On boards with NFC, holding two devices back to back while both
have Add peer open exchanges contacts with no code: the touch is the
agreement. Both land on the same unsaved-peer sheet. A tag carrying a
channel invitation opens Join channel, naming the card in its warning. A
phone tapping the device reads its link only while Show my code is open;
Add peer never serves it.

![Channel card](../hardware/mockups/tlora-pager-native/30-channel-card.png)

**Introductions.** A message whose whole body is a `umsh:n:` link is a
contact card, as an invitation is for a channel. Pressing it opens the same
unsaved-peer sheet. A saved peer's page has **Share contact**, which sends
that contact to a chosen chat.

| | |
|---|---|
| ![Contact in a chat](../hardware/mockups/tlora-pager-native/43-contact-in-a-chat.png) | ![Contact opened](../hardware/mockups/tlora-pager-native/44-contact-opened.png) |

**Enter an address** still takes a 44-character address or a `umsh:n:`
invitation, for when nobody is nearby.

## Keyboard and auxiliary controls

Use hardware navigation controls for focus and scrolling; use the keyboard for
text. Rotary encoders, trackballs, or touch can accelerate navigation but must
not be the only path when the keyboard contains usable navigation keys.

A press acts when the wheel comes back up. Holding it down instead opens
what is focused's menu where it has one: a direct chat's offers Show peer
and Delete, which asks to confirm.

Haptic or key-click feedback should be short, optional, and rate-limited. A
speaker is for notifications and media-quality tones, not confirmation for
every keystroke by default.

Modifiers, typing aids, the character picker, and the keyboard light are in
[Communicator Keyboard](communicator-keyboard.md).

## Locking

A communicator locks when its screen times out and a second passes without
input, or at once on a short press of the lock button, which shows the lock
screen. A dark screen is always a locked one. On the lock screen, the lock
button darkens it; while dark, it wakes to the lock screen. Holding it still
shuts down.

- **The lock screen** shows the device name, the time and date when the clock
  is known, the unread count, and one card per chat heard from since locking.
- **Unlocking** is five wheel steps down, which fill a bar, then a press within
  2 s. Turning up empties the bar; keys do nothing. Unlocking returns to
  where the user was.
- **While locked**, the screen stays lit 15 s, then fades and goes dark. Every
  message that would alert lights it again, with its tick, and restarts the
  15 s.

## Clock

**No time or date is shown anywhere until the clock is known.** Ages measured
since power-on are not read off the clock and may still show.

- **Time zones** are POSIX TZ rules the device keeps, so daylight saving needs
  no host. The list names zones ("Pacific Time"), not cities, west to east,
  with today's offset.
- **First run** asks for the zone after the radio profile, even with a GNSS
  fix: GNSS gives the time, not the zone.
- **Device › Clock** holds whether GNSS sets the time, the date and time set by
  hand, the zone, 12- or 24-hour time, and where the time last came from.
- **Every time shown** is in the offset its zone kept at that instant, so a
  message from before a daylight-saving change keeps its own hour.

## Optional phone integration

A communicator may optionally pair with a phone for synchronization, backup,
maps, bulk configuration, or accessibility. That connection is an enhancement,
not the communicator's primary UI and not a prerequisite for UMSH messaging.

If phone integration exists, pairing and bond management are visible
Maintenance actions. A communicator with a screen must not require users to
memorize click counts to clear trust or enter pairing. Loss of the phone or its
bond must not impair standalone communicator operation.
