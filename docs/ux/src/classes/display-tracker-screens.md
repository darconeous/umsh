# Display Tracker Screens

A display tracker's screen exists so that the small set of things a user must
be able to do without a phone are visible while they do them. This page defines
the screens a display tracker presents, what each one shows, and where each
setting lives.

The navigation intents used here are defined in
[Actions and Navigation](../interaction-model/actions-and-navigation.md#display-tracker-navigation).
Display lapse, input gating, and power-off are in
[Power and Attention](../interaction-model/power-and-attention.md#display-attention).

## What the device owns locally

With no phone present, a display tracker should let its user:

- read the device's own node address, and show it as a QR code when the panel
  can carry one;
- turn Bluetooth on and off, and open a pairing window with its PIN visible;
- turn the GNSS receiver on and off, and choose whether position is shared;
- turn frame forwarding on and off;
- check in on demand;
- read the current position and altitude;
- read what the radio has been doing; and
- read recent channel text.

Everything else—maps, history, contacts, composing text, bulk
configuration—stays on the phone, per
[Put the richest available interface in charge](../principles.md#put-the-richest-available-interface-in-charge).

## Screen hierarchy

```text
Status              reads in place; Select checks in
Identity            reads in place; Select alternates QR code and address text
Messages            reads in place; Select enters the message list
Settings            Select enters
    Back
    Bluetooth       Select enters
        Back
        Bluetooth       toggle
        Start pairing   action
        Clear bonds     action, confirmed
    GNSS            Select enters
        Back
        GNSS            toggle
        Share location  toggle
    Radio           Select enters
        Back
        Forwarding      toggle
        Statistics      reads in place
```

Each level is a wrapping list. Next and Previous walk it, and Select does
whatever the highlighted entry defines.

**Highlighting an entry is how you read it.** An entry that has content shows
it right there rather than behind a Select; the top three entries and
Statistics are all read by walking to them. Walking the list therefore never
changes anything, which is what makes it safe to explore a device whose entire
input vocabulary is three gestures.

**Status is home.** It is where boot lands, where a completed action returns,
and where a display lapse sends the user back to. It is always enabled.

**Back is the first entry of every submenu.** Entering a submenu highlights the
entry *after* Back, so one Previous reaches the way out and Next walks the
list; highlighting the exit of a screen the user just asked to enter would
waste the press that got them there. On a board with a Back control, the
gesture does exactly what selecting the entry does—the entry is what makes
the way out discoverable, and the control is what makes it quick.

**Gesture hints name the controls the board has.** The rows at the foot of a
page say how to move and what Select would do from the entry under the cursor,
in the vocabulary of that hardware: a one-button board counts clicks, a board
with a pad names its directions, and neither ever shows the other's wording. A
hint that names a gesture the device does not have is worse than no hint, which
is also why the second row is built from the highlighted entry rather than
picked from a fixed pair—it says *open*, *toggle*, or *check in*, not *select*,
wherever the entry knows better.

**A board enables the subset it can perform**, and navigation skips the rest. A
board with no GNSS does not show a GNSS submenu; a board with no bond storage
does not show Clear bonds. A submenu whose entries are all disabled is not
shown at all, rather than opening onto a list containing only Back.

### Showing the highlight

The highlighted entry is drawn inverted: the panel's foreground and background
swap across the whole width of the row, including the space either side of the
label, so the highlight reads as a solid bar rather than as emphasized text.
Exactly one entry is inverted at any moment, and the two choices on a
confirmation page use the same inversion.

Inversion is chosen because it survives everything these panels do badly. It
needs no color, no second font, and no glyph column stolen from a row that is
already narrow; it is legible on a monochrome OLED at a glance and on a
bistable panel with no backlight. A caret or a leading marker asks the user to
find a small mark, and on a board showing one entry at a time it asks them to
find it with nothing to compare it against.

The highlight is also the contract for Select. It must be on the panel, and on
e-paper it must have finished refreshing, before a Select is accepted; see
[Respect latency and persistence](../principles.md#respect-latency-and-persistence).

### Showing that the list continues

A board that draws several entries at once must show when there are more than
fit. Either rendering is acceptable:

- **Clip the overflowing row.** Draw the row past the last complete one cut off
  by the panel edge, so a half-height row of text hangs over the bottom.
- **Draw a scroll bar.** A track down the right edge with a thumb sized to the
  visible fraction and placed at the current position.

Pick one per board and use it on every list, including the message history.
Two overflow idioms in one product teach the user to read neither.

The clipped row costs nothing horizontally, which is what recommends it on a
panel already short of characters per line; a scroll bar takes a column away
from every row on the screen to say something about the list as a whole. What
the bar buys is extent: it says how much list there is and how far through it
you are, which a clipped row cannot. Prefer the bar where the panel can spare
the width, and the clip where it cannot.

Whichever is used, the highlight never lands on a partly drawn row. Moving onto
an entry scrolls the list far enough to draw that entry complete, because
[the displayed state must be the state the next input operates on](../principles.md#respect-latency-and-persistence)
and a Select against a row the user can only half read is a guess.

A board that shows one entry at a time has no list on screen to overflow, and
adds nothing: the wrapping list is the whole affordance, and a permanent marker
saying "there is more" on a screen that is always showing exactly one of
several entries is a row that never changes.

### What Select does

| Entry kind | On Select |
|---|---|
| Reading entry | Nothing, or the one extra action that entry defines |
| Submenu | Enter it |
| Toggle | Flip it and stay on the entry, showing the new state |
| Action | Perform it, return home, and report the outcome |
| Destructive action | Open a confirmation that defaults to Cancel |
| Back | Leave this level |

A toggle stays put deliberately. Its whole result is a state the user is
looking at, and returning home would hide the evidence that the press worked.
An action has no such state, so it returns to the home screen and reports what
happened there as a transient notice.

## The header

Every frame—menu, message, confirmation, and transient notice alike—carries
the same header: the device name, and glyphs for the states the user needs at a
glance.

| Glyph | Shown when |
|---|---|
| Battery body | A charge level is known; see [battery rules](../interaction-model/status-and-feedback.md#battery-indication) |
| Bolt or plug | The pack is on external power |
| Bluetooth | The Bluetooth radio is enabled |
| Position | The GNSS receiver is enabled |

The Bluetooth and position glyphs are present when the subsystem is on and
absent when it is off. This looks like a contradiction of
[show only what departs from nominal](../principles.md#show-only-what-departs-from-nominal),
and is not: these are modes the user switches from this menu, and their off
states are precisely what explains a phone that cannot find the device or a
check-in with no coordinates in it. A glyph the user can turn off is not
chrome.

Where the panel can distinguish two forms of the position glyph, use them for
searching versus holding a fix. That is an honest distinction and the one a
user waiting on a position actually wants. A board that cannot draw two forms
shows the one glyph for enabled and says the rest on the Status screen.

Connection state is not a header glyph. Whether a host is attached is a line on
Status, because it is a fact about a session rather than a mode the user set.

## Status

Home. It says which device this is, answers what it is doing right now, and
stays quiet when the answer is "the usual".

- The device name and the four-character rendering of its node hint, together.
  The name is what the user calls it and the hint is what the mesh calls it,
  and the pairing is what lets someone confirm that the device in their hand is
  the one on their phone screen. Render the hint canonically, `*` and all; see
  [Render addresses and hints canonically](../apps/mobile-guidelines.md#render-addresses-and-hints-canonically).
  The header already carries the name on every frame, so a panel short of rows
  may let the header's name stand and give Status the hint alone rather than
  printing the name twice.
- The current time, when the device knows it. A device with no clock shows no
  clock row at all rather than a placeholder.
- Position and altitude in standard coordinates, when there is a fix. No fix
  means no rows—never the last known position presented as the current one.
- The number of repeaters heard in the last hour.
- The pairing PIN, for as long as a pairing window is open.
- Anything else that departs from nominal: a connected host, suppressed
  advertising, a low pack, an error.

Select checks in: it sends an advertisement immediately and returns a notice
saying the request was accepted. It does not claim the advertisement was heard.
Giving the home screen's Select the device's frequent, non-destructive action
is [make the primary action easy and safe](../principles.md#make-the-primary-action-easy-and-safe)
applied directly. The cost of firing it by accident is one frame of airtime,
and a gesture begun against a lapsed display is consumed by the display anyway.

## Identity

A QR code of the device's `umsh:n:` URI, filling as much of the panel as it
can. The QR code is the point of the screen: it exists so another device can
take the address off it, and a phone camera is the only thing that needs to
read the address in full.

The device name belongs here too, so that the person holding the phone knows
whose code they just scanned. On a panel where the symbol takes everything
below the header, the header's name is that answer and nothing is repeated; a
panel with rows to spare names the device again beside or beneath the symbol.
A name that would have to shrink or truncate to fit is not worth the
space—the header still has it.

So the complete 44-character Base58 address is not shown alongside the symbol.
It is what the screen falls back to when there is no room for a QR code the
camera could resolve, and Select alternates the two on a panel that can render
both but not at once. Where the address is displaced by the symbol, the
four-character node hint may stay visible as the part a person can compare by
eye; the full 44 characters are for machines, and a machine is already reading
them.

A `umsh:n:` URI carrying a bare address is around 51 characters, which fits a
29-module QR symbol; with its four-module quiet zone that is 37 modules across.
A phone camera wants roughly three device pixels per module, so offering the QR
code takes about 110 px square below the header. A 200×200 panel clears this
comfortably, with room left for the name. A 128×64 panel does not, and those
boards fall back to the address as text.

## Messages

The most recent text received on the device's channels, with its sender. That
is what the entry reads in place, because the newest message is the one a
glance is usually looking for.

Select enters the history, a list of the messages the device has kept, newest
first. It is a submenu like any other: Back is its first entry, Next and
Previous walk from newer to older, and each message has the screen to itself
for as long as it is highlighted.

A display tracker does not compose. It has no text entry, and the phone owns
replying. Do not offer a canned-reply ladder as a substitute unless the product
has a reason for one, and never present a read message as acknowledged to the
sender.

## Bluetooth

**Bluetooth** turns the radio on and off. Turning it off drops any attached
host, and needs no confirmation for that: nothing is destroyed, bonds survive,
and the host reconnects when the radio comes back on.

**Start pairing** opens a time-limited window and puts the PIN on the Status
screen for the whole of it. The pairing window holds the display awake for its
duration, because an emissive panel that lapses mid-window takes the PIN with
it. See [Pairing, Privacy, and Recovery](../interaction-model/pairing-and-recovery.md).

**Clear bonds** is destructive and confirms. The confirmation names the count
it would destroy—"Clear 3 bonds?"—which is where that number changes a
decision, and it defaults to Cancel. It clears companion trust and nothing
else: not the UMSH identity, not messages.

## GNSS

**GNSS** turns the receiver on and off. It is the largest power decision the
user can make from this menu on most tracker hardware, and the header glyph is
what tells them which way it is set.

**Share location** governs whether position goes out in what the device
advertises. It is a separate decision from whether the device knows where it
is, and the two must not be collapsed into one switch: a user who wants a
position on their own screen without broadcasting it is asking for something
reasonable. Turning GNSS off makes Share location moot but does not silently
change it.

## Radio

**Forwarding** turns relaying of other nodes' frames on and off. A device with
forwarding on is acting as a repeater; the menu says what the device does, not
what to call it.

**Statistics** is a page reporting what the radio has done since boot: frames
transmitted and received, frames repeated onward, receptions that went nowhere,
the configured transmit power, and duty-cycle usage. Sample it when a frame is
drawn rather than pushing updates at it, so watching the page costs no extra
panel refreshes.
