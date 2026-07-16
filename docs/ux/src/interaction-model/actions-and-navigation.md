# Actions and Navigation

## Common action vocabulary

UMSH interfaces should use these user-facing concepts consistently:

| Action | Meaning |
|---|---|
| Check in | Advertise the device or user's current status/location |
| Send | Commit an outgoing message or check-in |
| Select | Open or activate the visible item |
| Back | Return one level without discarding more than the current edit |
| Home | Return to the primary status or conversation surface |
| Pair | Temporarily allow a new companion to establish trust |
| Disconnect | End the current connection without forgetting trust |
| Forget / Clear bonds | Remove stored companion trust |
| Silence | Suppress optional audible feedback and alerts |
| Sleep / Power off | Enter the board's lowest intended user-wakeable state |
| Update firmware | Enter a guided maintenance flow |

Use verbs that describe the user outcome. Avoid exposing protocol or radio
terms unless the UI is explicitly an expert/debug surface.

## Control precedence

Map an action to the first suitable option:

1. A labeled dedicated control
2. A visible menu item
3. A conventional navigation gesture
4. A short, documented button gesture
5. A boot-held physical-presence ceremony

Routine actions should be near the top; recovery actions may be near the
bottom. Never hide destructive data actions behind an undocumented gesture.

## One-button vocabulary

For a headless tracker, prefer this hierarchy:

- **Single press:** primary safe action
- **Double press:** reversible secondary action
- **Hold:** power or a clearly acknowledged mode transition
- **Triple/quadruple press:** no generic cross-device meaning; a device profile
  may reserve a slot for a hardware-specific action, otherwise leave it
  unassigned
- **Boot-held press:** physical presence for pairing or recovery, with
  unmistakable feedback and a timeout

Click and hold thresholds belong to a shared, tested recognizer. Board code
must debounce input and must not infer multi-click events independently.

## Keyboard and pager navigation

Full pagers should provide predictable focus and visible selection. A user must
be able to operate every screen without guessing whether typing edits text or
triggers commands.

- Typing goes to the focused text field.
- Select opens the highlighted item or sends only when Send is visibly focused.
- Back closes overlays, exits a screen, or offers to discard an edited draft.
- Home returns to the stable top level without deleting state.
- Modifier shortcuts may accelerate common actions, but visible navigation
  remains complete.

Non-touch hardware must not render controls that imply tapping.
