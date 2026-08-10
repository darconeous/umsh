# Firmware releases

How a UMSH firmware release is cut, what it contains, and where the pieces
end up. The web flasher on umsh.dev is the main consumer; everything here is
shaped by what a browser can and cannot do.

## Versioning

Releases are currently tagged `fw-YYYY.MM.NN` — annotated, with a zero-padded sequence
number within the month:

```bash
git tag -a fw-2026.08.01 -m "UMSH firmware 2026.08.01"
```

Crate versions are all `0.1.0` and mean nothing, so a date-based scheme is
the honest one for a technology preview. The padding is not cosmetic: it
makes tags and filenames sort correctly, so `2026.08.09` comes before
`2026.08.10`. The scheme moves to semver (`fw-1.0.0`) at first stable, and
`scripts/release.py` already sorts either.

The `fw-` prefix namespaces the tag so that a future crate or app tag cannot
be mistaken for a firmware version — each `build.rs` runs
`git describe --tags --match 'fw-*' --always --dirty`, which sees only these.

Every board reports the result as `PROP_DEV_VERSION`:

| Build | `PROP_DEV_VERSION` |
|---|---|
| At the tag | `umsh/fw-2026.08.01` |
| Three commits past it | `umsh/fw-2026.08.01-3-g4afef27b` |
| Uncommitted changes | `umsh/fw-2026.08.01-3-g4afef27b-dirty` |
| Never tagged | `umsh/4afef27b` |

Which board it is running on is `PROP_DEV_MODEL`, a separate property, whose
string matches the `model` field in the release manifest.

### The tag does not invalidate the build cache

Creating a tag touches neither `HEAD` nor any branch ref, so `git describe`
alone would let `make build-t1000e && git tag … && make release-artifacts`
package the *pre-tag* binary without a word of complaint.

Each `build.rs` therefore prefers a `UMSH_FW_VERSION` environment variable
and declares `cargo:rerun-if-env-changed=UMSH_FW_VERSION`, which cargo does
watch. `release-artifacts` sets it to the tag. Ordinary builds leave it unset
and fall back to `git describe` as before.

## Cutting a release

```bash
git tag -a fw-2026.08.01 -m "UMSH firmware 2026.08.01"
make release-artifacts
#   ... verify on hardware, see below ...
git push origin main --follow-tags
make release-publish
make release-mirror
git push origin gh-pages
```

No step takes a version argument. `VERSION` defaults to the tag on `HEAD`, so
the tag you just created is the one that gets built — it cannot disagree with
itself. To work on a release other than the one `HEAD` is on, pass the **tag**:
`make release-artifacts VERSION=fw-2026.08.01`. The bare `2026.08.01` is
rejected rather than quietly missing the tag by one prefix.

`release-artifacts` refuses to run unless the working tree is clean, the
annotated tag exists, and `HEAD` is exactly at it — `git describe` has no way
to warn you about any of those on its own. It builds all six shipping images,
converts them, and writes `manifest.json` and `SHA256SUMS` into
`target/firmware-release/<version>/`, where `<version>` is the tag without its
`fw-` prefix.

`release-publish` drafts the GitHub Release. Review the asset list, then
`gh release edit fw-2026.08.01 --draft=false`.

Releases are cut **locally, not in CI**: this is where the Xtensa toolchain
for the merged ESP32 image lives, and CI does not build `xiao-nrf52`. Moving
it into a `workflow_dispatch` job is a reasonable follow-on.

Only shipping images are released. The `*-console` builds are per-board
bringup harnesses, not products.

## Artifacts

| Board | Chip | Artifacts |
|---|---|---|
| `techo` | nRF52840 | `.uf2`, `-dfu.zip` |
| `t1000e` | nRF52840 | `.uf2`, `-dfu.zip` |
| `sensecap-solar` | nRF52840 | `.uf2`, `-dfu.zip` |
| `wio-tracker-l1` | nRF52840 | `.uf2`, `-dfu.zip` |
| `xiao-nrf52` | nRF52840 | `.uf2`, `-dfu.zip` |
| `heltec-v3` | ESP32-S3 | `.bin` (merged, written at `0x0`) |

Named `umsh-<board>-<version>.<ext>`. Board ids match the `BOARDS` presets in
`scripts/firmware_image.py`, the `make` target suffixes, and
`site/data/hardware.toml` — keep the four in step.

The UF2 is not converted by the release; `make build-<board>` already writes
it, and the release ships that exact file.

### SoftDevice requirement

DFU packages are built with `--sd-req`, so a package refuses to install on a
board running a different SoftDevice:

| SoftDevice | Boards | `--sd-req` | Confirmed |
|---|---|---|---|
| S140 6.1.1 | `techo` (app base `0x26000`) | `0x00B6` | `flash-techo-serial`, 2026-08-09 |
| S140 7.3.0 | everything else (app base `0x27000`) | `0x0123` | `flash-t1000e-serial`, 2026-08-09 |

Both were confirmed by installing a strict package on the real board. The
other three nRF52840 boards inherit `0x0123` from having the same SoftDevice,
and have not been individually checked.

adafruit-nrfutil's default is `0xFFFE`, "any SoftDevice", which is fine for a
zip you built thirty seconds ago and wrong for one published on the internet:
the app base differs with the SoftDevice, so the wrong image lands at the
wrong offset. This is the check that stops it — and it matters more once a
web page can push a package to whatever board is plugged in.

`scripts/release.py` reads the value back out of each package's own manifest
rather than repeating the Makefile's, so the release manifest describes the
artifact that exists rather than the one that was intended.

### The merged ESP32 image

```bash
espflash save-image --chip esp32s3 --merge --skip-padding -s 4mb \
    --partition-table firmware-esp32/partitions-umsh.csv <ELF> <OUT.bin>
```

`--skip-padding` is load-bearing. Without it espflash pads the image out to
the full flash size with `0xFF`, and writing that at `0x0` runs straight over
the `umsh` data partition at `0x300000` — every device would lose its
identity and saved state on update. With it the image stops after the
application, around `0x13E000`, and `0x300000` is never touched.

## Where the artifacts live

### GitHub Releases — the archive

`https://github.com/darconeous/umsh/releases/tag/fw-<version>` holds every
artifact, permanently. Direct links work in an `<a href>`: GitHub serves
assets with `Content-Disposition: attachment`, so a click downloads.

### umsh.dev/firmware/ — what the flasher reads

GitHub's release assets send **no CORS headers**, so a page on umsh.dev
cannot `fetch()` them. Anything the flasher must read is therefore mirrored
same-origin into the `gh-pages` tree, whose ownership map reserves
`/firmware` for this.

| URL | Changes |
|---|---|
| `/firmware/manifest.json` | every release — a copy of the current version's manifest |
| `/firmware/releases.json` | every release — the mirrored versions, newest first |
| `/firmware/<version>/manifest.json` | never, once written |
| `/firmware/<version>/umsh-<board>-<version>-dfu.zip` | never |
| `/firmware/<version>/umsh-heltec-v3-<version>.bin` | never |

`MIRROR_KEEP` (default 3) versions are kept so a bad release can be backed
out from the flasher itself; older ones are pruned from the tree and remain
on GitHub Releases forever. Version directories are immutable — every URL
under one is cacheable indefinitely, and `release-mirror` refuses to
overwrite one.

There is no `latest` symlink: GitHub Pages serves repository contents without
resolving git symlinks, so one would 404 or serve its target's path as text.
The manifest is the pointer instead.

**UF2 files are published but not mirrored.** Mirroring exists to satisfy
`fetch()`, and nothing fetches a UF2 — a browser cannot write to a
mass-storage volume, so that flow is a download the user drags onto the
drive, which works from the GitHub URL. Add `"uf2"` to `MIRRORED_ROLES` in
`scripts/release.py` if a File System Access flow ever makes the bytes worth
having in the page.

## manifest.json

`schema_version` is `1`. Per board: the id, display name, the `model` string
its firmware reports as `PROP_DEV_MODEL`, the chip, the flash methods, the
UF2 family id and app base or the ESP32 write offset, and for each file a
size, a SHA-256, a `url`, and a `path`.

`path` is the same-origin mirror location, and is `null` for anything not
mirrored. A flasher reads that as "offer this as a download, do not try to
fetch it".

The manifest carries only what is needed to put bytes on a board. Photos,
specs, and prose about entering DFU live in `site/data/hardware.toml`, keyed
by the same board ids, so the two join without duplicating each other.

## Verification

Before promoting a draft release:

- [ ] `shasum -a 256 -c SHA256SUMS` in the staging directory
- [ ] `cmp` each staged UF2 against `target/thumbv7em-none-eabihf/release/firmware-<board>.uf2` — the release renames, it must not re-convert
- [ ] Flash one nRF52 board from the staged UF2; confirm `PROP_DEV_VERSION` reads `umsh/fw-<version>` and `PROP_DEV_MODEL` names the board. This also proves `UMSH_FW_VERSION` reached the compiler.
- [ ] Install a DFU package over serial DFU on a T1000-E (S140 7.3.0) and a T-Echo (S140 6.1.1). A wrong FWID is a clean init-packet rejection, not a damaged board. If either is refused, drop `--sd-req` back to the `0xFFFE` default and note it here. *(Both passed 2026-08-09; only re-check if the SoftDevice table above changes.)*
- [ ] Confirm the negative: a T-Echo package must be **refused** by a T1000-E. Still unchecked — it proves the guard guards, rather than that a correct package installs. If it were ever to *succeed*, the wrong-base image is recoverable with a normal UF2 flash, since the bootloader is untouched.
- [ ] Write the merged ESP32 image at offset zero with a plain flasher — `espflash write-bin 0x0 <bin>`, and again with `esptool.py --chip esp32s3 write_flash 0x0 <bin>`, since that is the path esptool-js mirrors. Set and save a device name first, and confirm it **survives** the reflash: that is what proves `--skip-padding` kept the image clear of `0x300000`.
- [ ] After `release-mirror` and a push, fetch `https://umsh.dev/firmware/manifest.json` from a browser console on another origin, and spot-check one mirrored file's SHA-256 against it.
