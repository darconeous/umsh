# Splash logos

The UMSH logo, finished for each color panel's width. `generate.py` beside
them makes both from `docs/logo/umsh-logo-orange-noshadow.png`. It needs
Pillow and is a host-only step; firmware builds include the files as they
are.

| Asset | For | Bytes |
|---|---|---|
| `umsh-432x101.rle` | 480-wide panels (T-LoRa Pager) | 4405 |
| `umsh-288x67.rle` | 320-wide panels (T-Deck) | 2525 |

The version under the logo has no asset here. It is set in the face the
communicator draws body text in, which is already in flash.

## Format (`.rle`)

Width and height as big-endian `u16`, then coverage levels row by row, 0
clear to 15 solid. The levels are run-length coded: each token byte carries
the level in its high nibble and a run of 1 to 15 in its low nibble. A low
nibble of 0 means the run is 16 more than the next byte, up to 271.

The levels are the source's alpha resampled to a width that leaves about
2.7 mm clear at either side of the panel. The renderer turns each level into
one of sixteen shades of the logo's orange over black, so the frame is
composed on black and nothing is blended at draw time.
