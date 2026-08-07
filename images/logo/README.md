# Website logo assets

`umsh-logo-white.svg` and `umsh-logo-orange.svg` are generated from
`docs/logo/umsh-logo-bw.svg` — the same single path with the fill baked in
and Inkscape's editor metadata stripped. Regenerate them if the master
changes; do not hand-edit the path data.

The white lockup is for the orange header and hero; the orange lockup is for
white backgrounds. The stacked UM/SH lockup (`docs/logo/umsh-app-icon.png`)
is for app icons and favicons only, never for page headers.

Brand colors are International Orange `#FA5000` and white `#FFFFFF`
(`docs/logo/GUIDELINES.md`).

`og-card.svg` is the source for the social preview image. Rasterize it after
editing:

```bash
magick -density 96 site/static/images/logo/og-card.svg -resize 1200x630 \
  -depth 8 -define png:color-type=2 site/static/og-card.png
```

The favicons come from the stacked app icon:

```bash
magick docs/logo/umsh-app-icon.png -define icon:auto-resize=48,32,16 site/static/favicon.ico
sips -s format png -Z 32 docs/logo/umsh-app-icon.png --out site/static/favicon-32.png
sips -s format png -Z 180 docs/logo/umsh-app-icon.png --out site/static/apple-touch-icon.png
```
