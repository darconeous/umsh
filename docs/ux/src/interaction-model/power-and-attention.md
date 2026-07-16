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

## Attention budget

Trackers are ambient devices. Routine operation should be quiet and visually
subtle. Reserve repeating sound, haptics, or bright patterns for events that
need action. A user-selected silence or low-attention preference should persist
when feasible and be inspectable from the companion.

Full pagers may provide richer notifications, but should still offer per-source
or global quiet modes and preserve critical system feedback through a
non-audible channel.
