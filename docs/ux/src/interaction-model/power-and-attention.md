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
| Emissive (OLED, LCD) | Fall to a dim warning, then switch the panel off |
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

Thirty seconds suits an emissive panel, with the last ten of them dimmed. Time
the panel at what a person actually does with it: walk to an entry, read it,
and think about the answer. Ten seconds is barely the first of those, and a
dimmed period short enough to be a countdown is a threat rather than a warning.
A persistent panel wants the same thirty for a different reason—only stale
context is at stake, and a visible refresh makes an aggressive fallback an
annoyance of its own.

Fall into the dim rather than dropping into it. About a second, stepped often
enough to read as a fade, turns "the screen is going" into something the user
notices in peripheral vision and can answer before it finishes. The rise is not
gradual: a panel coming back is a panel someone is waiting on.

A fade is affordable because it is not a redraw. Brightness on these
controllers is a register, so a step costs a few bytes on the bus and leaves the
framebuffer alone—which is what lets a panel that redraws only on events still
dim smoothly.

Express the fall as a position between the panel's own dim and full levels
rather than as a brightness. Full is not the same number across a class—an
SH1106 and an SSD1306 disagree about it—so a policy that named a brightness
would be naming the wrong one on half the boards. Where the dim end sits is a
judgment about the warning rather than about the panel: far enough down to be
unmistakable in peripheral vision, still lit enough to read and answer.

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
