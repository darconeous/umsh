# Bosch BHI260AP RAM firmware

This is Bosch's unchanged, non-turbo `firmware/bhi260ap/BHI260AP.fw` from
[`BHI2xy_SensorAPI` revision `177681d120ac42760c9f19505697ccd5c7103e87`](https://github.com/boschsensortec/BHI2xy_SensorAPI/tree/177681d120ac42760c9f19505697ccd5c7103e87).

- Size: 103,676 bytes.
- SHA-256: `318def511fd8eb762bf1e61cf02cfd6ecac70f8627d3bacfa7d24a1641f9e915`.
- Upstream license: BSD-3-Clause; the accompanying `LICENSE` is copied unchanged.
- No runtime or build-time download is required.

The Pager includes this image in ESP32 flash and streams it into sensor RAM
when a motion consumer needs it. It does not write sensor flash. The opt-in
`motion-qualification` build uses the same image for diagnostics. See the
[qualification record](../../../docs/tlora-pager-motion-qualification.md) for
observed capabilities, timing limitations, and remaining hardware acceptance.
