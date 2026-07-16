# Full Pagers

Pagers are self-contained UMSH clients. A phone is never part of the critical
path for setup, reading, composing, sending, status, settings, or recovery.
Their default screen should answer:

- What conversation or activity needs attention?
- Is the radio/device connected and able to send?
- What is the battery state?
- What will the primary control do now?

## Proposed information architecture

1. **Home / Inbox** — conversations, unread state, delivery summary
2. **Conversation** — message history and compose entry
3. **Nodes / Contacts** — reachable identities and details
4. **Channels** — membership and channel activity
5. **Device status** — radio, location, battery, storage, companion state
6. **Settings** — notifications, display, input, radio policy
7. **Maintenance** — pairing, diagnostics, firmware update, destructive resets

Maintenance actions should not compete visually with messaging.

## Composition

- Preserve drafts when leaving a conversation accidentally.
- Make recipient/channel and Send state visible while composing.
- Distinguish queued, transmitted, acknowledged, delivered (if the protocol
  can prove it), and failed. Never invent a stronger delivery claim.
- Provide an explicit cancel path for queued work when technically possible.

## Keyboard and auxiliary controls

Use hardware navigation controls for focus and scrolling; use the keyboard for
text. Rotary encoders, trackballs, or touch can accelerate navigation but must
not be the only path when the keyboard contains usable navigation keys.

Haptic or key-click feedback should be short, optional, and rate-limited. A
speaker is for notifications and media-quality tones, not confirmation for
every keystroke by default.

## Optional phone integration

A pager may optionally pair with a phone for synchronization, backup, maps,
bulk configuration, or accessibility. That connection is an enhancement, not
the pager's primary UI and not a prerequisite for UMSH messaging.

If phone integration exists, pairing and bond management are visible
Maintenance actions. A pager with a screen must not require users to memorize
click counts to clear trust or enter pairing. Loss of the phone or its bond must
not impair standalone pager operation.
