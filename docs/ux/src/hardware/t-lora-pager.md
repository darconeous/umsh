# LilyGO T-LoRa Pager

The T-LoRa Pager is a proposed full-pager target and therefore a self-contained
UMSH client. Repository hardware research
identifies a 480×222 landscape non-touch display, a 31-key keyboard, rotary
encoder with push, keyboard backlight, haptic driver, speaker/audio codec, and
GNSS. No UMSH pager UI is implemented yet; this chapter is a proposed mapping.

See `docs/lilygo-t-lora-pager-hardware.md` before writing board code. In
particular, treat the display as non-touch and do not inherit T-Deck Pro pins.

## Proposed control mapping

| Hardware | Proposed use |
|---|---|
| Keyboard | Text composition, search, and documented shortcuts |
| Rotary turn | Move focus, scroll lists/history, change a selected value |
| Rotary press | Select/open; never Send unless Send is visibly focused |
| Back/escape key, if confirmed | Back or cancel |
| Boot/user button | Power and recovery only; not routine navigation |
| Haptic motor | Optional short focus/action confirmation and silent alerts |
| Speaker | Message/urgent notifications; optional and silenced by profile |
| Keyboard backlight | Follows activity and user brightness/timeout settings |

## Proposed layout

Use the wide display for a stable top status strip, a main list or conversation
region, and a bottom context/action strip. The focused item and available
rotary/keyboard action must always be visible. Do not draw touch-style buttons.

The first implementation should cover on-device setup, Inbox,
Conversation/Compose, Nodes or
Contacts, Device status, Settings, and Maintenance. Audio, NFC, sensors, and SD
features should not distort the core messaging navigation before they have a
clear UMSH user story. None of these core paths may depend on a phone.
