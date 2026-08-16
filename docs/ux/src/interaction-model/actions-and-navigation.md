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
| Share location | Include position in what the device advertises |
| Forwarding | Relay other nodes' frames onward |
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

## Display tracker navigation

A display tracker navigates a list. Three intents are required of every board
in the class, whatever controls it has:

| Intent | Meaning |
|---|---|
| Next | Move forward to the next item, wrapping at the end |
| Select | Open, activate, or toggle the visible item |
| Previous | Move backward to the previous item, wrapping at the start |

A board with richer input may add these, and must not require them:

| Intent | Meaning |
|---|---|
| Up, Down | Aliases for Previous and Next within a list |
| Back | Leave the current level, as if its Back entry had been selected |

The optional intents are shortcuts to results the required three already
reach. That is what keeps one interaction model across boards with very
different controls: a user who learns a one-button device can operate a D-pad
device, and a user who learns the D-pad has learned nothing that fails on the
button. A board must not give an optional control a meaning the required three
cannot produce.

On a single-button board the mapping is single click for Next, double click for
Select, and release after a one-to-four-second hold for Previous. Continuing to
hold past four seconds always powers the device off, from any screen and
regardless of display state. There is no Back gesture on such a board; the Back
entry in each submenu is how the user gets out.

On a board with a four-way pad and a Back button the mapping is one control per
intent and no control with two meanings: the center press for Select, the Back
button for Back, and the pad for moving through the list. All four directions
move—down and right for Next, up and left for Previous—because the pad is one
control for walking a list, not a map of where the tree sits on screen. Nothing
on the pad leaves a screen; that is the Back button's job and nothing else's.
The power-off hold also stays on the Back button, which is the one control such
a board still has when nothing is on the panel. The Back entry remains in every
submenu—a user who has not found the button is not stuck—and the gesture hints
name the controls the board actually has, so a pad device never says "2x".

The screens these intents drive, and what each one shows, are in
[Display Tracker Screens](../classes/display-tracker-screens.md).

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
