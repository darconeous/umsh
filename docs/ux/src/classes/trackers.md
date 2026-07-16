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

Use the display to make local state and sensitive actions explicit. One-button
navigation may use single = next, double = select, and hold-release = back if
the mapping is printed on every relevant screen. A separate, longer hold can
remain available for sleep. Do not accept input against a screen that has not
finished refreshing.

## Headless trackers

The LED, buzzer, and haptic channels form a compact language. Keep it small and
teach it in the companion. The device should acknowledge the button immediately
and let the phone explain detailed outcomes. Silence must never suppress the
only visible indication.
