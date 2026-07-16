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

- What role-neutral result should single-click have in autonomous and NCP
  firmware?
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

- Should status screens refresh on events, on a bounded schedule, or only on
  user input to balance truthfulness, latency, ghosting, and battery use?
- When the displayed radio state can become stale during sleep, what wording or
  timestamp makes that limitation clear?
