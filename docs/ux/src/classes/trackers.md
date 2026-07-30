# Trackers

The phone is typically the primary interactive tracker interface. It owns maps,
history, detailed status, text, configuration, and explanations. The physical
tracker owns the small set of actions that must remain available without a
phone.

Companion-operated is not the same as phone-dependent. Once provisioned, a
tracker should continue its configured tracking, logging, advertising, or
transmitting behavior without a live phone whenever its product use case allows.
The phone is required to *interact richly* with the tracker, not necessarily for
the tracker to perform its job.

## Required companion surfaces

- Device identity and connection state
- Battery, charging, and last-seen time
- Last location and location-acquisition state, when applicable
- Check-in/transmit state with honest delivery terminology
- Sound/light preferences
- Pairing and bond management
- Firmware version, update, diagnostics, and recovery instructions
- A device-specific gesture reference

## Local action budget

Every local gesture consumes memory and increases ambiguity. Start with only:

- wake/sleep;
- one primary check-in or alert action;
- an accessible feedback/silence control if the board makes sound; and
- a physical-presence pairing/recovery path.

Add another gesture only when the task must work without a phone, happens often
enough to remember, and can be confirmed unambiguously.

## Display trackers

Use the display to make local state and sensitive actions explicit.

Display trackers share one interaction model regardless of panel technology or
input richness, because a user who learns one should already know the others.
One-button navigation uses single = next, double = select, and hold-release =
back, with the mapping printed on every relevant screen; a longer, continuing
hold always powers the device off. A board with a D-pad maps its own controls
onto the same three actions rather than inventing a second vocabulary.

The menu is a wrapping list with a home page, and each board enables the subset
of entries it can actually perform. Destructive entries open a confirmation
that defaults to Cancel — the confirmation is what makes them safe to expose on
the menu at all, so a board should not hide such an action behind an
undocumented gesture instead.

Display attention, including what a lapse does on each panel technology and how
input against a lapsed panel is treated, is specified in
[Power and Attention](../interaction-model/power-and-attention.md#display-attention).
Do not accept input against a screen that has not finished refreshing.

## Headless trackers

The LED, buzzer, and haptic channels form a compact language. Keep it small and
teach it in the companion. The device should acknowledge the button immediately
and let the phone explain detailed outcomes. Silence must never suppress the
only visible indication.
