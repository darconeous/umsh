# Display logos

These row-major, MSB-first 1-bit images use 1 for foreground and 0 for
background. Each row is byte-aligned. All logos fill the display width;
their heights preserve the source proportions rounded to the nearest pixel.

| Asset | Dimensions | Bytes |
|---|---|---|
| `umsh-128x30.raw` | 128×30 | 480 |
| `umsh-200x47.raw` | 200×47 | 1175 |
| `umsh-480x112.raw` | 480×112 | 6720 |

Regenerate from the repository root using Python with Pillow (generated with
Pillow 11.0.0). This is a host-only operation; firmware builds include the
finished bytes and require no image tools.

```sh
python3 - <<'PY'
from pathlib import Path
from PIL import Image

source = Image.open("docs/logo/umsh-logo-orange-noshadow.png").convert("RGBA")
alpha = source.getchannel("A")
destination = Path("crates/umsh-ux-display-tracker/assets")
for width in (128, 200, 480):
    height = round(source.height * width / source.width)
    scaled = alpha.resize((width, height), Image.Resampling.LANCZOS)
    mask = scaled.point(lambda coverage: 255 if coverage >= 128 else 0, mode="1")
    (destination / f"umsh-{width}x{height}.raw").write_bytes(mask.tobytes())
PY
```

Use alpha coverage rather than orange luminance, and threshold only after
resizing. Dithering is intentionally absent so the small logo has solid strokes.
