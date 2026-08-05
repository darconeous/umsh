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
- How should drafts, queued messages, acknowledgements, and delivery evidence
  be named and displayed?
- What status information belongs in the always-visible strip on small screens?
- Which shortcuts can be shared by T-LoRa Pager and T-Deck without hiding
  functionality from visible navigation?

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
looking at it is a broken clock, which is the whole reason the exception exists
— and a device that does not know the time shows no clock at all, so there is
nothing to advance.

Minute-rate partial refresh does not visibly ghost the T-Echo's panel, so the
tick runs at its natural rate. Quantizing to five minutes stays available as a
knob if a slower or older panel disagrees.

- When the displayed radio state can become stale during sleep, what wording or
  timestamp makes that limitation clear?
