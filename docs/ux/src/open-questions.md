# Open Design Questions

The first implementation pass should resolve these questions with prototypes
and hardware testing.

## Cross-device vocabulary

- Should the tracker primary action be named **Check in**, **Beacon**, or be a
  user-configurable action with a stable default?
- Which states deserve standard LED/haptic/audio shapes across vendors, and
  which should remain board-specific?
- Should attention preferences be stored on the device, phone, or both, and how
  are conflicts resolved?

## T1000-E migration

- What role-neutral result should single-click have in autonomous and
  tethered operation?
- What unambiguous local feedback should distinguish request accepted,
  transmitted, and failed?

## Full pager conventions

- Which keys form the minimum portable pager navigation set?
- How should drafts, queued messages, acknowledgments, and delivery evidence
  be named and displayed?
- What status information belongs in the always-visible strip on small screens?
- Which shortcuts can be shared by T-LoRa Pager and T-Deck without hiding
  functionality from visible navigation?

## Display tracker screens

The screen hierarchy is settled; see
[Display Tracker Screens](classes/display-tracker-screens.md). These remain
open.

- Radio statistics sit inside Settings under Radio, which costs three presses
  to reach. They are also a read-only glanceable page, and on the boards that
  implement them today they are one press from home. Does a diagnostic page
  belong beside the settings for the subsystem it describes, or beside the
  other pages a user reads at a glance?
- Select on the home screen checks in, and on a one-button board Select is a
  double click. Is that frequent enough to be worth the occasional accidental
  advertisement, and does the display-lapse gate absorb enough of them?
- Silence and locate-alert state have no place in the header yet. Do they earn
  a glyph, or does an alert own the whole screen while it runs?

Two screens in that hierarchy are deferred rather than open:

- **Identity's QR code.** Only the T-Echo's 200×200 panel can carry a scannable
  `umsh:n:` symbol, and no QR encoder exists in either workspace. Adding one is
  a new dependency that four of the five nRF images would carry and none but the
  T-Echo could use. Every board falls back to address text meanwhile, which is
  what a person compares by eye anyway.
- **Messages.** The device node logs a received payload and returns; there is no
  device-side text store for the page to read. The page is a consequence of
  building that store, not a screen that could be added on its own. Whether it
  should then offer any reply path on a board with no text entry, or stay
  read-only until a canned-reply set has a product reason to exist, is the
  question to settle at that point.

The toggles are settled: Bluetooth, GNSS, Share location, and Forwarding all
flip through the ULCP session rather than at the subsystem, so a local change
is the same event as a host write—it persists in the saved snapshot, and an
attached host is told about it asynchronously. There is no disagreement to
resolve because there is only one writer.

## E-paper trackers

Refresh scheduling is settled for display trackers: screens refresh on events,
never on a timer, and display attention lapses back to the home page after
thirty seconds. See
[Power and Attention](interaction-model/power-and-attention.md#display-attention).

The clock row is the one sanctioned exception, and is bounded to the case that
requires it. A minute-boundary timer is armed only while the panel is already
awake **and** the device knows what time it is; a sleeping panel is never woken
by it, a device with no clock never arms it, and a panel that was asleep catches
up on its next event-driven redraw. A clock that does not advance while you are
looking at it is a broken clock, which is the whole reason the exception
exists—and a device that does not know the time shows no clock at all, so
there is nothing to advance.

Minute-rate partial refresh does not visibly ghost the T-Echo's panel, so the
tick runs at its natural rate. Quantizing to five minutes stays available as a
knob if a slower or older panel disagrees.

- When the displayed radio state can become stale during sleep, what wording or
  timestamp makes that limitation clear?
