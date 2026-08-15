# Power and Attention

## User model

Use **Sleep** or **Power off** according to what the user experiences, not the
MCU primitive. If a button wakes the board into the same state, “Sleep” is often
more accurate. Documentation should explain the physical wake action.

## Power transitions

- A hold used for sleep must fire while held or give progressive feedback; it
  must not be confused with a short click.
- Release the wake button before arming a level-sensitive wake source, so the
  device does not immediately wake again.
- Finish or safely cancel persistent writes before sleep.
- Render a truthful final screen on persistent displays.
- Critical low-battery shutdown overrides ordinary UI state and explains the
  reason on the next capable interface.

## Display attention

A device with a display should stop assuming the user is looking at it after a
short period without input. Both panel technologies lapse; what lapsing does
differs because their costs differ.

| Panel | On lapse |
|---|---|
| Emissive (OLED, LCD) | Dim as a warning, then switch the panel off |
| Persistent (e-paper) | Stay readable; return the menu to its home page |

The user-visible rule is the same on both: after a while away, the device
forgets what you were in the middle of, so the next press starts from a page
whose meaning is on screen. A persistent panel must not be blanked to imitate an
emissive one—a screen that is readable at no cost should stay readable.

### What restarts the timeout

Wake on anything that means the user is present or wants to be: a button or
navigation press, a connection-state change, an opening pairing window, an
alert, a low-battery notice, entering a maintenance flow.

Do **not** wake on content the device produced on its own—a battery sample, a
bond count, a periodic refresh. Redraw those only while the panel is already
showing something. A device that samples on a timer and treats each sample as
attention will never let its display sleep.

Some conditions must hold the display awake for as long as they last rather than
merely restarting the timeout. A pairing window is the clearest case: its PIN
has to stay readable for the whole window. An ordinary connected or attached
state is not such a condition—a device that holds its display awake whenever a
companion is connected has no display timeout at all.

### Input against a lapsed display

A gesture that begins while the display is dark only brings it back. The user
cannot have meant to act on something they could not see, so the whole gesture
is consumed, not just its first press. Decide this at the press that starts the
gesture rather than at the event that ends it: a double-click begun in the dark
resolves after the panel is already lit, and judging it late would both wake the
display and activate something.

Wake on the press rather than the release, so the panel is legible while the
user is still deciding what the press will become.

The power-off hold is the one gesture that always passes through. It is
deliberate enough to mean it, and a device that has gone dark still has to be
switchable off.

The same consumption rule covers two related cases: input during an alert
cancels the alert instead of navigating, and input against a panel that has not
finished refreshing is discarded rather than acted on.

### Timings

Ten seconds suits an emissive panel, with the last three of them dimmed. A
persistent panel can afford longer—thirty seconds is comfortable—because
only stale context is at stake, and because a visible refresh makes an
aggressive fallback an annoyance of its own.

Devices in one product class should share a single set of numbers, and a shared
implementation, so that learning one teaches the others.

## Attention budget

Trackers are ambient devices. Routine operation should be quiet and visually
subtle. Reserve repeating sound, haptics, or bright patterns for events that
need action. A user-selected silence or low-attention preference should persist
when feasible and be inspectable from the companion.

Full pagers may provide richer notifications, but should still offer per-source
or global quiet modes and preserve critical system feedback through a
non-audible channel.
