# Porting Checklist

Use this checklist when assigning a UMSH experience to a new board.

## 1. Classify

- Does the complete core experience live on the device? If yes, it is a pager;
  if rich interaction normally requires a phone, it is a tracker.
- For a pager, can setup, messaging, status, settings, and recovery all work
  without a phone?
- For a tracker, which tracking functions continue without a live phone?
- Is this a full pager, display tracker, or headless tracker?
- Which firmware roles will run, and can the physical vocabulary remain stable
  across them?

## 2. Inventory

- Record every reliable input, output, wake source, and companion link.
- Record display refresh and persistence constraints.
- Record which feedback survives silence, darkness, gloves, pockets, and a
  disconnected phone.
- Verify hardware behavior; do not infer controls from a nearby board model.

## 3. Map required actions

- Primary safe action
- Select, Back, Home, and text composition where applicable
- Pair and reconnect
- Silence/attention preference
- Sleep and wake
- Bond clearing, identity reset, firmware update, and recovery

Prefer dedicated controls and visible menus before gestures.

## 4. Map states and outcomes

For boot, pairing, connection, location acquisition, transmit, success, failure,
low battery, silence, update, and shutdown, define:

- immediate recognition feedback;
- pending feedback;
- success and failure feedback;
- screenless and silenced alternatives; and
- what the phone reports.

## 5. Apply safety rules

- Destructive actions name their scope and default to Cancel.
- Pairing is explicit and time-limited.
- Maintenance is separated from routine input.
- Displayed selection and acted-on selection cannot diverge.
- Sleep cannot immediately wake from the still-held control.
- Delivery claims do not exceed protocol evidence.

## 6. Test the user model

- Can a new user discover the primary action?
- Can an occasional user operate it after a month without consulting a click
  codebook?
- Can a user recover after losing the phone?
- Can a deaf, color-blind, or sound-sensitive user perceive essential state?
- Can the device be used in bright light, darkness, and with its sound off?
- Do firmware roles and upgrades preserve familiar meanings?

## 7. Document and verify

- Add an “implemented behavior” table to this book.
- Link the hardware reference and exact firmware source.
- Mark proposed behavior as proposed.
- Unit-test pure input/state policy and verify timings and outputs on hardware.
