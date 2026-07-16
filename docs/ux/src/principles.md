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
