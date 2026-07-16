# Device Classes

UMSH has two product classes and three useful interaction profiles. Classify by
whether the product provides its complete core experience on the device, not
simply by screen size or peripheral count.

| Product class | Interaction profile | Primary interface | Typical hardware |
|---|---|---|---|
| Pager | Full pager | Device; phone optional | Screen, text keyboard, navigation controls; often sound or haptics |
| Tracker | Display tracker | Phone, with local status/configuration | Small or e-paper screen, one or a few controls, limited indicators |
| Tracker | Headless tracker | Phone | One button, LED, buzzer or haptic; no screen |

The class is determined by the intended user experience, not by the number of
peripherals. A T-Echo has a screen, but no text keyboard and is normally used
with a phone, so it is a **display tracker**, not a pager. Conversely, a pager
does not become companion-dependent merely because it can optionally connect to
a phone.

## Full pagers

Pagers support the core UMSH experience directly: reading conversations,
composing and sending text, inspecting delivery state, managing contacts or
channels, and changing ordinary settings. A phone connection may improve the
experience or provide backup/synchronization, but cannot be required for setup,
routine use, or recovery.

Examples include the T-LoRa Pager and T-Deck class of hardware.

## Trackers

Trackers are usually companion-operated devices. The phone owns rich
configuration, history, maps, text entry, and explanations. This does not mean
the tracking function itself requires a live phone: a tracker may acquire
position, log data, advertise, or transmit autonomously. The tracker retains
local controls for actions that must work when the phone is absent or
disconnected.

A display tracker should use its display for glanceable status, pairing and
recovery, confirmations, and progress. A headless tracker encodes only a small,
documented vocabulary into its controls and feedback channels.

## Class boundaries are intentional

Do not implement the pager navigation model on a one-button tracker, and do not
copy a headless tracker's click counts onto a pager. Share semantic models and
pure state machines where they fit; use class-specific interaction mechanisms
where the hardware changes the nature of the task.
