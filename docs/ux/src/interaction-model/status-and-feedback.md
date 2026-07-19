# Status and Feedback

## Feedback phases

An asynchronous action can have four states:

1. **Recognized** — the input was accepted.
2. **Working** — the device is acquiring, transmitting, pairing, or saving.
3. **Succeeded** — the requested local operation completed.
4. **Failed** — it did not complete, with a recovery hint where space permits.

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
one pending state, and immediate event acknowledgements—not the entire device
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
