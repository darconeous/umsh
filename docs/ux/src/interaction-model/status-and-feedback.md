# Status and Feedback

## Feedback phases

An asynchronous action can have four states:

1. **Recognized**—the input was accepted.
2. **Working**—the device is acquiring, transmitting, pairing, or saving.
3. **Succeeded**—the requested local operation completed.
4. **Failed**—it did not complete, with a recovery hint where space permits.

Do not collapse Recognized and Succeeded. In particular, a transmit-start chirp
does not mean a peer received a message.

## Semantic families

Use a consistent shape across output channels:

| Meaning | Screen | LED/haptic | Sound |
|---|---|---|---|
| Positive transition | Plain success text or icon | One short positive pulse | Short rising interval |
| Negative transition | Error text with next step | Repeated or contrasting pulse | Short falling interval |
| Working | Progress/status label | Slow periodic pulse | Normally silent |
| Urgent alarm | Specific alert | Distinct repeating pattern | Repeating alert, if not silenced |

Exact colors and pitches depend on hardware. Shape and cadence carry the
meaning so the UI remains legible to users who cannot distinguish color or
have disabled sound.

## Battery indication

A battery indicator answers these questions, to the best of the hardware's
ability:

- What is the charge level of the pack?
- Is the device connected to external power? If so:
  - Is it still charging, or is it fully charged?

They are answered independently. Either may be known without the other, and
neither may be inferred from the other's absence—charging while the level is
unknown is an ordinary state, not a contradiction.

### Charge level

Where the hardware permits it, the level is drawn as a body divided into
segments. Bands are chosen so that each segment count sits *centered* on the
level it depicts rather than starting at it—a body drawn half full should
mean a pack that is roughly half full. With four segments:

| Level | Segments lit |
|---|---|
| 0–14 % | 0 |
| 15–36 % | 1 |
| 37–62 % | 2 |
| 63–84 % | 3 |
| 85–100 % | 4 |

The two end bands are deliberately narrower than the middle ones. Full and
empty are absolute claims, and a body should not look full at 80 % nor empty at
20 %.

Coarse quantization is intended. A bistable panel diffs frames to decide how
small a partial refresh it can get away with, so an indicator that moved on
every sample would keep re-inking the display. Four segments change four times
across a discharge.

### No level to show

When there is no level, no body is drawn. An empty body is a reading—it means
a pack down to its last sixth—and the absence of a reading must not borrow
it. This is the [honesty principle](../principles.md) applied to the one
indicator users check most often: a device that has not yet established a level,
or that has withdrawn one it can no longer substantiate, shows nothing rather
than a shape that can be read as a number.

A device reports the same way over the wire: it omits the level from its
battery property rather than sending a value it knows to be unreliable, and
keeps reporting what it can still measure. A host treats the omission as
unknown at that instant and does not carry forward an earlier value in its
place.

Where a device has a diagnostic line as well as an icon, the same rule governs
it: the line drops the percentage and says the pack is charging, rather than
printing a figure that would look like a fresh measurement.

### External power

Answering the power questions fully takes two glyphs alongside the body:

| Glyph | Meaning |
|---|---|
| Bolt | On external power, still charging |
| Plug | On external power, charging complete |

Each combines with the body rather than replacing it, because the level and
the power state are separate answers. A bolt beside a nearly full body means
charging and close to done; a plug beside a full body means finished. A glyph
with no body means the power state is known and the level is not.

Whichever glyph is showing holds the same position, and the same position it
would hold if the other were showing—an indicator that slides sideways when
the charger goes in reads as two changes rather than one.

### Degrading to what the hardware can tell

Most hardware cannot answer all of this, and the indicator says less rather
than guessing:

| The device can see | It draws |
|---|---|
| Level, external power, and completion | Body, plus bolt or plug |
| Level and external power only | Body, plus bolt whenever powered |
| Level only | Body alone |
| Neither | Nothing |

A board that sees external power but cannot distinguish charging from complete
shows the bolt the whole time it is plugged in. It never shows a plug, because
it never learns the thing a plug would assert.

A board that cannot see external power at all draws neither glyph. That is
distinct from knowing the pack is discharging, and it has a second cost: such a
board cannot withdraw its level while charging, so its reading runs high
whenever it is plugged in. Prefer hardware that at least exposes VBUS presence,
and prefer hardware that exposes the charger's completion line over hardware
that does not.

## App-level infrastructure precedes content

In companion applications, endpoint-wide infrastructure state must sit outside
the hierarchy of the current conversation, peer, map, or settings screen. The
companion-radio status therefore belongs in stable app-level chrome at the top
of the app surface, not in screen content. A platform may integrate normal
connected state into its top toolbar rather than dedicating a full-width row.
An expanded attention/error banner occupies a reserved app-level position
between that toolbar and the screen's title/content.

Do not place radio state beneath a chat title, because that visually implies
that the radio belongs to that conversation. Platform safe areas and operating
system status chrome remain above the application-owned toolbar/status area.

## LEDs

Keep the codebook small. A single LED should normally express power/liveness,
one pending state, and immediate event acknowledgments—not the entire device
state. Event patterns may temporarily preempt a heartbeat, then return to the
original cadence.

Avoid bright, frequent heartbeats on battery devices. Offer a way to reduce or
disable non-essential light while preserving critical feedback through another
channel.

### User-attention indication

Firmware may request a persistent **user attention** indication when it has
received a message or another actionable event that requires the user to act.
This is a semantic request, not a separate LED code for each event type.

On a device with a heartbeat LED, user attention should preserve the heartbeat
cadence but replace each ordinary heartbeat flash with a short, smooth
brightness ramp up and down. A complete attention pulse should take roughly
300 ms. The pattern repeats at heartbeat moments until the actionable condition
is acknowledged, dismissed, or otherwise cleared.

User attention is distinct from:

- a one-shot action confirmation;
- a working/progress indication;
- an urgent repeating alarm; and
- an unread-count display on devices capable of showing one.

The firmware owns the reason for the request and the condition that clears it;
the device profile owns its physical presentation. Silence does not suppress
the visual attention indication.

## E-paper

- Prefer stable status over animation.
- Show a visible selection before accepting Select.
- Serialize input with refresh or queue it without changing its meaning.
- Use partial refresh only when its artifacts remain understandable.
- Before sleep, render a truthful persistent state such as “Sleeping,” then put
  the panel into its low-power mode.

## Silence and accessibility

Silence mode applies to optional audible output, not visual status, haptics the
user has enabled, or critical safety behavior. The current silence state must
be visible in the companion UI and on any capable local display.

Do not rely on color alone, pitch alone, or precise timing alone. Text labels
and companion explanations are preferred whenever available.
