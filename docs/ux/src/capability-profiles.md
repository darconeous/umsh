# Capability Profiles

Before designing a board's UI, record what it can sense and express. This is a
capability inventory, not a feature wish list.

## Input capabilities

- Text keyboard or keypad
- Directional navigation, rotary encoder, trackball, or joystick
- Dedicated Select, Back, Home, power, or programmable keys
- Touchscreen or non-touch display
- One or more general-purpose buttons
- Short press, multi-click, hold, and boot-held detection
- Phone, USB, or serial control

## Output capabilities

- Refreshable color or monochrome display
- E-paper or other persistent, slow-refresh display
- Single-color or RGB LED
- Buzzer or speaker with controllable pitch and volume
- Haptic motor
- Keyboard or display backlight
- Companion-phone notifications

## Operational capabilities

- Battery and charging state
- Deep sleep and hardware wake sources
- BLE pairing and bond storage
- GNSS or other sensors
- Autonomous UMSH identity and transmission
- Companion-radio-only operation
- Safe bootloader and factory-recovery paths

## Mapping rule

For every required action and state, choose:

1. a primary input or output;
2. a redundant accessible channel where practical;
3. behavior when the phone is disconnected;
4. behavior when the operation is pending, succeeds, or fails; and
5. a recovery path.

If the board cannot express a state unambiguously, the companion must explain
it. If the board cannot safely accept an action, the companion must own it.
