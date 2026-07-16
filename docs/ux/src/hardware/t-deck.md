# LilyGO T-Deck

The T-Deck represents keyboard-equipped, screen-based hardware and therefore
belongs to the full-pager class. The repository currently contains no audited
T-Deck hardware reference and no UMSH T-Deck interface implementation. This
chapter intentionally records only the class mapping, not unverified control or
pin details.

## Proposed mapping

- The device must provide the full pager information architecture and remain
  usable without a phone.
- Text entry belongs to the keyboard; navigation belongs to the board's
  confirmed navigation controls.
- Touch, trackball, speaker, microphone, haptic, or other model-specific
  capabilities may enhance the interface only after a hardware audit.
- Pairing, bond clearing, firmware update, and resets live in visible
  Maintenance screens.
- A phone companion may synchronize, back up, or provide a larger map, but it
  must not become a prerequisite for setup, configuration, recovery, reading,
  or sending messages.

Before implementation, add a source-derived hardware reference comparable to
the T-LoRa Pager and T-Echo references, then replace this outline with a concrete
control table and hardware-verified behavior.
