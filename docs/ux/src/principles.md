# Design Principles

## Preserve meanings, adapt mechanics

UMSH standardizes user intentions such as **Send**, **Pair**, **Back**,
**Silence**, and **Sleep**. It does not require every board to use the same
physical gesture. A pager can show a Pair command; a screenless tracker can
offer it in the phone application and require physical presence at the device.

Changing hardware should require learning where an action lives, not what the
action means.

## Put the richest available interface in charge

Use the most expressive surface available for a task:

1. A pager handles messaging and ordinary settings on the device. A phone is
   optional and must not be required for normal operation.
2. A tracker with a display shows status and makes sensitive local actions
   visible, while the phone remains the primary interface.
3. A screenless tracker reserves its button for a very small set of frequent or
   safety-critical actions. Configuration lives on the paired phone.

Do not turn a screen-equipped device into a memorized gesture ladder merely to
match a screenless device.

## Preserve self-contained operation

A pager must provide its complete core experience without a phone: setup,
messaging, status, settings, and recovery. A tracker may use a phone for its
interactive experience, but its tracking function should continue
autonomously whenever the use case and hardware allow it. It must also remain
safe and legible enough to wake, identify its basic state, request help or check
in, and recover pairing without already having a working phone connection.

## Make the primary action easy and safe

The shortest gesture or most prominent control should perform the device's
frequent, non-destructive action. On a tracker this will usually be a check-in,
location advertisement, or status acknowledgement. On a pager it will usually
be opening or sending a message.

Rare, destructive, or maintenance actions must never displace the primary
action.

## Acknowledge input before completing work

Give immediate feedback that an input was recognized, then distinguish success
from failure when the operation completes. A chirp that means "button accepted"
must not be presented as proof that a packet was delivered.

If the hardware cannot report completion locally, the local response should
mean **accepted** and the companion interface should show the eventual result.

## Never require sound

Every essential audible signal must have a visual, haptic, or companion-app
equivalent. Silence mode suppresses optional sound, never safety indications or
the only confirmation of a destructive action.

## Make dangerous actions deliberate and recoverable

Clearing identity, bonds, messages, or configuration requires explicit
confirmation. On a screen, show the object and consequence and default to
Cancel. Without a screen, prefer a phone confirmation plus a physical-presence
gesture. Firmware update and bootloader entry are maintenance functions, not
ordinary runtime shortcuts.

## Expose state; do not make users infer it

When possible, show whether the device is powered, connected, pairing,
acquiring a location, transmitting, silenced, low on battery, or in an error
state. Do not overload one pattern with multiple meanings in the same context.

## Never state a value the device cannot stand behind

A reading that is known to be wrong, or that the hardware cannot currently
substantiate, must not be presented as fact. Withdraw it and show that it is
unknown.

The temptation is always to keep displaying the last good value, because a
blank looks like a defect. It is the worse option: a stale number carries the
same authority as a fresh one, so the user cannot tell the difference, and
they will act on it. A charge estimate derived from resting terminal voltage
means nothing while the pack is charging, and on a charger that reports no
completion there is no later moment to correct it against — so for that whole
period the device has no state of charge, and says so. What it does know, that
the pack is on external power, it still shows.

This applies equally to what leaves the device. A protocol field that cannot
be substantiated is omitted rather than filled with the last value or a
plausible guess; an absent field and a wrong one are not equally recoverable,
because a peer can reason about the first and not the second.

Distinguish this from a value that is merely coarse. An estimate that is
approximate, quantized, or slow to converge is still worth showing, provided
its presentation does not imply more precision than it has. The rule is
against asserting what is false, not against admitting what is rough.

## Show only what departs from nominal

A row that is present on almost every frame teaches the user to stop reading
that row, and takes the space from something that would have been worth
reading. State whose normal value is uninteresting — a closed pairing window,
ordinary advertising with nobody connected — earns its place on screen only
when it changes.

Reserve the persistent indicators for what a user checks at a glance and acts
on: power, and whether anything is currently wrong. A small screen that is
quiet when nothing is happening is one whose contents mean something when they
appear.

## Respect latency and persistence

The displayed state must be the state on which the next input operates. This is
especially important on e-paper: input must be serialized with refresh so a
Select action cannot activate an item the user has not seen. Persistent screens
must not be left showing a misleading live state after shutdown.

## Keep the device profile stable across firmware roles

Every firmware for a board must use the same input recognizer, mandated actions,
reserved action slots, state transitions, and feedback rules defined by its
device profile. Configurable slots may perform different documented actions
according to firmware capability. An unsupported mandatory or reserved action
must remain inert unless the device profile defines a fallback; it must not be
silently reassigned to an unrelated action.
