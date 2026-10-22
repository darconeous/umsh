# Emoji on Communicators—Plan

Communicators (T-LoRa Pager, T-Deck) draw emoji wherever they draw user text:
message bubbles, chat previews, reaction chips, device, peer, and channel
names, avatars, lock-screen cards, and the status strip. They also send
emoji, which the user inserts from the character picker. The art is
Twemoji, pre-rendered at build time, palette-quantized, and compressed. The
set is a curated subset of about 800 emoji, chosen by actual usage and
listed in a committed manifest, so supporting more emoji means adding lines
to that manifest, not changing code.

Steps 1–3 of the [work order](#work-order) are implemented, apart from
Device › About and retiring the reaction art. Input (step 4) and the spec
edits and mockups (step 5) are not. The protocol-facing changes are
collected in [Protocol changes](#protocol-changes).

## Where things stand

- **Fonts.** `crates/umsh-ux-communicator/build.rs` rasterizes M PLUS 1 and
  M PLUS Code (Latin subsets, OFL) with `swash` into 4-bit coverage maps:
  42 faces, about 745 KB of coverage plus about 250 KB of glyph entries. The
  Buoyant fork's `PrerenderedFont` looks glyphs up per `char` and blends
  coverage into the layer's background hint.
- **Missing characters.** Every unmapped code point draws the face's U+FFFD
  diamond. An emoji like 👍🏽 or 🇫🇷 draws two diamonds, and 👨‍👩‍👧 draws
  five, because ZWJ, VS16, and skin-tone modifiers each get one.
- **Text handling is per `char` everywhere.** Wrapping, ellipsis truncation,
  the text field's cursor and backspace, preview cutting (`push_cut`), and
  name clipping (`record.rs`, `settings.rs`) all respect UTF-8 but none
  respect grapheme clusters. Backspace after 👍🏽 leaves 👍.
  `set_device_name` (`umsh-ulcp-runtime/src/device_node.rs:432`) cuts raw
  bytes; a cut inside a code point makes `profile_name` return `None`, and
  the node advertises no name at all.
- **Avatars.** `avatar.rs` builds initials from the first `char` of each
  word, and `two_lines` pushes into a 2-byte `String<2>`, which silently
  drops any 4-byte character. iOS takes the first `Character` (a grapheme
  cluster) of each word, so a channel named "🔥 Crew" is badged 🔥C on iOS
  and C on the device. Avatar lettering is canonical across surfaces, so
  this is a bug.
- **Reactions.** The six canonical reactions are hand-drawn vector paths in
  `build.rs`, composited onto five fixed backgrounds (about 26 KB). Any
  other reaction falls back to the body's first `char`.
- **Input.** The keyboard spec already defines the character picker
  (`docs/ux/src/classes/communicator-keyboard.md`, "Character picker"):
  categories, recents, filter by name, and "only characters the panel's
  fonts can draw." Only a 16-symbol ASCII stand-in is implemented. The
  T-Deck keyboard sends ASCII only, so the picker is the only emoji entry on
  either board.
- **Flash.** The communicator partition table gives the app 7.94 MB
  (`factory` at 0x10000); the Pager's current image is about 6.25 MB of
  `.text` and `.rodata`. 0x800000–0xDF0000 is unused. No compression crate
  is built for the target today.

## Choosing the art

| Set | Art license | Coverage | Fit at 16–40 px | Verdict |
|---|---|---|---|---|
| **Twemoji** (`jdecked/twemoji`, v17.0) | CC BY 4.0 (code MIT) | Emoji 17.0, actively maintained | Flat, bold shapes that fill the cell; best at small sizes | **Chosen** |
| Fluent Emoji Flat (Microsoft) | MIT | 1,595 emoji; stops partway through Emoji 15.1; no new art since January 2025; no country flags | Good, but drawn smaller within its cell | Falls further behind phones every Unicode release |
| Noto Color Emoji | Apache 2.0 (images); OFL (font) | Current | More fine detail and gradients; muddier at 16–20 px | Fallback if Twemoji stalls; the pipeline does not depend on the set |
| OpenMoji | CC BY-SA 4.0 | Current | Thin outlines | Share-alike attaches to our derived rasters; avoid |
| Apple, Samsung, Segoe | Proprietary | — | — | Not licensable |

**Decision: Twemoji**, pinned to a release tag. It tracks the current
Unicode version, so emoji from up-to-date phones keep rendering, and its art
was designed to read at 16–20 px. Fluent was compared at device sizes and
was close on size (about 10% smaller, mostly because its art is drawn
smaller) but has nothing from Emoji 16 or 17. CC BY 4.0 obliges us to:

1. **Credit it.** A Device › About › Credits screen (new; there is none
   today) lists "Emoji art: Twemoji, CC BY 4.0", with the copyright line
   exactly as the pinned release's `LICENSE` gives it (`LICENSE-GRAPHICS`
   is the bare CC BY 4.0 text). The same
   text goes in a `THIRD-PARTY-NOTICES` file shipped
   with each firmware release and on the site's firmware page. Twemoji names
   an About screen as an acceptable place for attribution. The M PLUS fonts
   (OFL) and the CLDR name data (Unicode License v3) belong on the same
   screen.
2. **Link the license.** The credits entry and the notices file carry the
   CC BY 4.0 URL.
3. **Say that we changed it.** "Rasterized, color-reduced, and compressed"
   goes next to the credit.

Nothing ShareAlike or NonCommercial is involved, so the firmware's own
MIT/Apache licensing is unaffected. The art is licensed separately from the
code; `crates/umsh-emoji/twemoji/LICENSE-GRAPHICS` holds the CC BY 4.0 text,
next to the vendored SVGs of Twemoji v17.0.3.

Two more licensing points:

- **Build-time tools.** The quantizer must be permissively licensed; the
  build's own k-means quantizer is. **Not `imagequant`**: libimagequant is
  GPL-3.0. Nothing from the rasterizer (`resvg`) or the encoder ships in the
  image, but keep the build tree clean anyway.
- **The UX mockups.** `docs/ux/src/hardware/mockups/tlora-pager-src/generate.py`
  draws emoji with `'Apple Color Emoji', 'Noto Color Emoji'`, so the
  published mockup PNGs contain Apple artwork, which is not licensed for
  redistribution. Switch the generator to the same Twemoji rasters the
  firmware uses. The mockups then show what the device draws, and no Apple
  art gets published.

## Choosing the set

### The default set

Both communicators ship one set, about 800 base emoji:

1. **Every face, heart, and hand**, whatever its rank: all of Smileys &
   Emotion, and the `hand-*`, `hands`, and `hand-prop` subgroups of People &
   Body. The usage ranking predates newer favorites (🫠 🥹 🫶 🫡) and
   undercounts them, so these subgroups go in whole, including what Emoji
   15.1–17 add to them.
2. **The 719 most-used emoji** in Unicode's [emoji frequency
   ranking](https://www.unicode.org/emoji/frequency.html): rows 0–10, each
   item used at least 1/2048 as often as 😂. The ranking folds gender
   variants into one item, so an included item brings its gendered forms
   (🤦 brings 🤦‍♀️ and 🤦‍♂️).
3. **Completeness rules**, so families are never half present: all keycaps
   (the ranking keeps 4️⃣ but not 8️⃣ or 🔟), the colored circles and
   squares, and the eight non-country flags (🏁 🚩 🎌 🏳️ 🏴 🏳️‍🌈 🏳️‍⚧️ 🏴‍☠️).
4. **No skin tones.** Everything is default yellow; 👍🏽 draws as 👍.
5. **No country or subdivision flags.** They draw as lettered badges (see
   [Fallback](#fallback-for-what-the-set-lacks)).

Rules 1, 2, 4, and 5, measured on Twemoji 15, give 792 emoji. Rule 3 and
the Emoji 15.1–17 additions to rule 1 add a few dozen more. The set draws
**98.0% of emoji use** exactly. Country flags (0.7%) draw as badges, and the
remaining 1.2% falls back as described below. 🫃 is not in the ranking at
all and is out; 💅 ranks in the top 250 and 💇 in the last band, so both
are in.

### Why there

The ranking puts each emoji in a band by how often it is used, so it gives
a usage-weighted coverage for any candidate set. Measured on the Pager:

| Set | Emoji | Use drawn exactly | Pager flash |
|---|---|---|---|
| Faces, hearts, hands only | 209 | 71.8% | 77 KB |
| + top 242 by use | 332 | 91.4% | 114 KB |
| + top 504 by use | 571 | 96.3% | 182 KB |
| **+ top 719 by use (default)** | **792** | **98.0%** | **248 KB** |
| + top 953 by use | 1,017 | 98.8% | 311 KB |
| Everything except country flags | 1,609 | 99.3% | 478 KB |
| Everything | 1,870 | 100% | 523 KB |

Coverage climbs steeply to the default, then flattens: the last two
percentage points cost twice the flash. The T-Deck needs about 20% less than
the Pager for every row, because its smaller text gets smaller emoji (see
[Sizes](#sizes)). Skin tones would change no row's coverage, since the
ranking counts 👍🏽 as 👍.

### The manifest

`crates/umsh-emoji/manifest.txt` lists the set explicitly, one sequence per
line in `emoji-test.txt` syntax and CLDR order. A stdlib script in `scripts/`
generated the first version from the ranking and `emoji-test.txt` (both
vendored as inputs to that script only). From then on the manifest is
maintained by hand, and the build reads only the manifest.

Every table on the device (lookup, picker categories and order, name filter)
is generated from the manifest, so "enable more" means adding lines and
rebuilding. A change shows up as a manifest diff.

## The glyph store

### Sizes

Every glyph is pre-rendered at 16, 20, and 24 px, the sizes both boards'
text styles call for (`board.rs`). One build runs on either board, as the
fonts do, so both boards carry all three. An emoji is drawn at the size
nearest 1.2× the em of the text around it:

| Text | Pager | T-Deck | Emoji |
|---|---|---|---|
| Small and secondary | 16–17 px | 12–14 px | 20 px / 16 px |
| Body | 20 px | 16 px | 24 px / 20 px |

Emoji may stand a little above and below their line. Anything drawn around
text that they might reach, such as a field's outline, is drawn over the
text rather than under it.

A message that is only emoji draws at body size, like any other. Large
emoji-only messages, as iOS shows them, are left out; adding them later is a
fourth size (40 px / 32 px) costing about 150 KB of indices.

Rendering one large master and downscaling at runtime was measured and
rejected: against an ideal render, the derived glyphs had 2–3× the error of
directly rendered ones (RMSE 7.6 at an exact 2:1 ratio, 11.8 at 2.5:1,
against 3.7 for a direct render with the same palette). Small sizes need the
rasterizer's own anti-aliasing.

### Encoding

Each glyph is a square of indices into a palette, and all three sizes of a
glyph share one palette:

- **Palette.** Up to 32 entries, each RGB565 plus 8-bit alpha, drawn from
  all three renders together. When any pixel is fully clear, the first
  entry is exactly clear, so nothing is drawn around the art. A palette a
  size measured RMSE 2.0–2.2; the shared one measures 2.8–3.3, and stores
  palettes once instead of three times (they are a third of the bytes).
- **Indices.** One byte per pixel before compression.
- **Compression.** Palettes, and each size's indices, are grouped into
  blocks of 16 glyphs in manifest order, and each block is one raw DEFLATE
  stream. Blocks of 16 came out 27–44% smaller than per-glyph streams; a
  shared preset dictionary gave nothing.
- **Decoder.** A small purpose-built raw-DEFLATE decoder in `umsh-emoji`,
  after Mark Adler's `puff`: its whole state is about 1 KB, where
  `miniz_oxide`'s table-driven inflater keeps about 11 KB that cannot be
  built in place without assuming its layout. A block inflates in well
  under a millisecond.
- **A codec byte per block**, so a better coder can replace DEFLATE later
  without changing the rest of the format.

**Drawing.** This works the way the fonts already do. The draw blends the
glyph's ≤32 palette entries into the layer's background hint once, the way
`PrerenderedFont` blends its 16 coverage shades, and then each pixel is a
table lookup. Without a hint, a pixel is drawn when its alpha is at least
half, which is the font's rule too. The six reaction images, pre-composited
onto five backgrounds, go away. Chips draw the same glyphs as the bubbles.

**Cache.** Decoded glyphs (palette plus indices: about 670 B at 24 px) live
in an LRU cache of 48 slots, with the last palette block and index block
inflated beside them: about 45 KB in all, in PSRAM on the device. The cache
is plain data with no atomics, since the ESP32-S3 cannot do atomic
operations in PSRAM; the interface locks it by taking its pointer out of an
atomic in internal RAM while it draws.

### Skin tones, if added later

The set has none; a toned emoji draws its base (fallback rule 2). If tones
are added later, most cost less than a full glyph: in Twemoji, 1,342 of the
1,690 tone variants (79%) are the base drawing with only the fill colors
changed, and the build can store such a variant as a palette over its base's
indices. The saving is modest. Anti-aliased edges blend skin into its
outline, so a variant changes about 18 of ~31 palette entries, and a tone
palette costs about 64 B per size compressed, roughly 60% of a whole glyph
at 20 px. Hands alone (235 variants) would add about 30 KB on the Pager.

### Lookup

The table holds the manifest's sequences, keyed with U+FE0F removed. The
device removes FE0F from a cluster before looking it up, so minimally
qualified and unqualified forms from other senders (`❤` as well as `❤️`)
find the same glyph. The keys are sorted, as UTF-8, in one string, with
each key's start and glyph beside it, and a cluster is found by binary
search: about 8 KB for the default set.

A single code point that defaults to text presentation (™, ©, ↔), with no
FE0F after it, is drawn from the text font when the font has it. Otherwise
it is an emoji.

### Measured cost

Measured from the build, for the 815 emoji of the default set:

| Part | Bytes |
|---|---|
| Palettes | 65 KB |
| Indices at 16 px | 76 KB |
| Indices at 20 px | 102 KB |
| Indices at 24 px | 128 KB |
| **Store** | **371 KB** |

The planning estimate was 248 KB a board. It stored each palette as zero
bytes and quantized with an octree, which leaves fewer colors in use, so it
undercounted; with a palette a size, the store was 555 KB.

The store goes in the app image, like the fonts and art (the partition
table's comment says that's where they belong). With it, the Pager image's
text is 7.03 MB, leaving about 1.29 MB in `factory`. If a later, larger set
outgrows that, the store moves to its own partition in the unused
0x800000–0xDF0000 without a format change, since lookups already go through
an offset table. Building the store takes about a minute.

## Text: clusters, not characters

### Segmentation

Every text path segments by **extended grapheme cluster** (UAX #29), with
the `unicode-segmentation` crate (`no_std`, MIT/Apache). Its tables add
26.9 KB to the T1000-E image, the same as on host builds, so no
purpose-built subset was written. It lives in a small `no_std` crate,
`umsh-grapheme`, which provides:

- `clusters(&str)`, the iterator.
- `cut(&str, max_bytes)`, which shortens at a cluster boundary, and
  `cut_len` for bytes that may not be UTF-8. They replace
  `truncate_utf8`, `record.rs`'s `clip`, `push_cut`, `utf8_prefix_len`,
  and the raw byte cut in `set_device_name`.
- `first_cluster(&str)`, used by reaction parsing and avatar initials.

### Buoyant (the fork)

Buoyant's text was per `char`. The fork (`02aa2d5` on its `umsh` branch)
lays out by cluster, behind a `unicode-segmentation` feature:

- `FontMetrics::cluster_advance` and `cluster_rendered_size`, and
  `FontRender::draw_cluster`, take a cluster (`&str`). They default to the
  cluster's characters one after another, so a `char`-only font is
  unchanged and the change upstreams cleanly. `FontRender` is no longer
  sealed.
- Word wrap, character wrap, and ellipsis truncation step by cluster; an
  emoji is never broken across a line or cut in half by `…`.
- `TextField` inserts, deletes, and moves the cursor by cluster. Backspace
  removes 👍🏽 whole. A splice that doesn't fit is refused whole, as it is
  now, so an emoji the 24-byte name field cannot hold simply doesn't go in.

The communicator's fonts are a `Typeface` (`umsh-ux-communicator`): a
`PrerenderedFont` for text, with emoji beside it. For each cluster it tries
the text face, then the emoji store, then the fallbacks below.

### Fallback for what the set lacks

From the best result to the last resort, with one cell per cluster and
never one per code point:

1. **Exact match** (after removing FE0F).
2. **A skin-toned emoji:** its base glyph, in default yellow.
3. **ZWJ sequence not in the set:** its parts that *are* in the set, side by
   side. 🧑‍🚀 becomes 🧑🚀, as UTS #51 recommends.
4. **Flag not in the set:** its region code in a small rounded badge drawn
   with the text font (`FR`, `GB-SCT`). It is readable and costs no art.
5. **Anything else pictographic:** the placeholder (below). ZWJ, variation
   selectors, and tag characters on their own draw nothing.

With the default set, 1.2% of emoji use reaches rule 5.

**The placeholder** is a gray disc with a question mark:

- The disc fills the emoji cell edge to edge (a half-pixel inset), the same
  footprint as a Twemoji glyph, in `#6B7480`. That shade reads as a disc on
  both the received (`INBOUND`) and sent (`OUTBOUND`) bubble colors at both
  boards' sizes.
- The "?" is M PLUS 1 at weight 800, about two-thirds of the cell tall, in
  `TEXT` (`#EEF1F5`), centered on its ink bounds rather than the font's
  line box.
- The communicator's build renders it at each emoji size with the same
  font, and it blends like any emoji, including in reaction chips. The
  disc's `#6B7480` is `theme::PLACEHOLDER`, which also fills a flag's badge.
- Gray and neutral, it cannot be mistaken for Twemoji's red ❓, which is
  also the `?` reaction.

The non-communicator boards (OLED and e-paper trackers) show names too. They
get the segmentation and rule 5 alone, so a peer named "Bob 🚀" shows one
placeholder there instead of a run of diamonds, at almost no flash cost.
On a one-bit panel the placeholder is a filled disc with a "?" knocked
out, drawn by hand at each panel font's size (5×7 and 9×11): a disc that
held the font's own "?" would not fit a 6- or 10-pixel cell.

## Sending

- **The character picker** is built as the keyboard spec describes it.
  Categories come from the manifest's CLDR groups, recents come first, and
  the grid shows only what the board's set draws. The name filter matches
  CLDR short names plus a few aliases (`+1`, `lol`). Names are English for
  now; CLDR annotations make other languages a data change.
- **No skin-tone choice.** The set has no tones, so the picker offers none.
- **Recents** are stored in the chat store, not as a setting: they are
  frequent, local, and not configuration. Writes are debounced.
- **Reactions.** The six canonical reactions still send their tokens (`<3`,
  `+1`, …). A **More** cell at the end of the reaction palette opens the
  picker, and the reaction body is that emoji. A reaction received with any
  emoji the set has is drawn as that emoji. Parsing takes the first
  *cluster* rather than the first `char`.
- **Names.** Device, peer, and private-channel display names take emoji
  through the same picker. Byte limits do not change; a name is cut only at
  cluster boundaries. 24 bytes holds six single-code-point emoji. Public
  named channels stay ASCII-only, as the spec requires
  (`multicast-channels.md`).
- **Avatars** take the first cluster of each word, matching iOS, and draw an
  emoji initial from the store at the avatar's size class. `two_lines` stores
  clusters, not 2 bytes.

## Device › About

A new **About** screen under Device, the communicators' first. It shows,
one row each:

- **Name**: the device name.
- **Model**: the board, e.g. LILYGO T-LoRa Pager.
- **Firmware**: the release tag (`fw-YYYY.MM.NN`), or the commit for a
  development build, and the build date.
- **Address**: the node's address in its fixed 44-character base58 form,
  and its hint.
- **Storage**: chat store used of total.
- **Credits**: opens the credits screen.

The credits screen lists, one entry each, with its license and URL:

- UMSH firmware: MIT or Apache 2.0.
- Twemoji: CC BY 4.0, its copyright line from the pinned release's
  `LICENSE-GRAPHICS`, and "rasterized, color-reduced, and compressed".
- M PLUS 1 and M PLUS Code: SIL OFL 1.1.
- Unicode emoji data and CLDR names: Unicode License v3.
- Open-source components: the Rust crates in the image by name and SPDX
  license ID, generated from `cargo metadata` and committed (a Makefile
  target regenerates it; CI checks it is current). The full license texts
  ship in `THIRD-PARTY-NOTICES` with each release, and the entry gives its
  URL.

Rows follow the terse UI copy rule: labels and values, no explanations.
The screen gets a section and mockup in
`docs/ux/src/classes/communicators.md`.

## Protocol changes

No wire format changes and no new identifiers: all text is already UTF-8,
and nothing new is carried. These are spec clarifications so that every
implementation treats an emoji sequence as one unit where it shortens or
picks from text:

1. **`common-patterns.md`, UTF-8 Strings.** Add: a sender that shortens a
   string to fit a byte limit (a node name, a sender handle, a region name)
   cuts at an extended grapheme cluster boundary (UAX #29). A receiver given
   a string that ends mid-cluster renders what it can, per receiver
   tolerance; it does not reject the string. Message fragmentation is
   unaffected: it splits bodies at byte boundaries, as
   `app-text-messages.md` already specifies.
2. **`app-text-messages.md`, reactions.** "Render a reaction as a single
   glyph, taking the first one" becomes "the first extended grapheme
   cluster", so 👍🏽 and 🇫🇷 stay whole. Also fix the count: the text says
   "five canonical reactions" and the table lists six.
3. **`ulcp-ble.md`, pairing advertisement.** The device name is shortened
   "without splitting a UTF-8 code point" becomes "without splitting a
   grapheme cluster".

## Components

| Component | Where | What it does |
|---|---|---|
| `umsh-emoji` (new, `no_std`) | `crates/umsh-emoji` | Manifest, vendored Twemoji SVGs and the Unicode inputs to the generator, `build.rs` (resvg → shared-palette quantize → block DEFLATE → tables), lookup with the fallback chain, block decoder, glyph cache |
| Manifest generator | `scripts/` (stdlib Python) | One-off: the ranking plus `emoji-test.txt` → the first `manifest.txt` |
| Grapheme support | `umsh-grapheme` (new) | `clusters`, `cut`, `first_cluster`; replaces every byte or `char` cutter |
| Buoyant fork | `buoyant` | Cluster-based metrics, draw, wrap, truncation, and `TextField` editing |
| Communicator UI | `umsh-ux-communicator` | `Typeface` (text with emoji beside it), the placeholder, field outlines drawn over text, picker, reaction **More**, avatar clusters, Device › About and Credits; retires the hand-drawn reaction art |
| Crate notices | `Makefile`, CI | Generates and checks the committed crate list for Credits |
| Trackers' UX | `umsh-ux-display-tracker` | Segmentation plus one hand-drawn one-bit placeholder per cluster, at each panel font's size |
| Mockups | `docs/ux/.../generate.py` | Draw Twemoji rasters from `umsh-emoji` instead of Apple Color Emoji |

Building firmware still needs only a Rust toolchain. `resvg` and
`miniz_oxide`'s encoder are build dependencies, the way `swash` is for
the fonts. The SVGs are vendored, so the build is offline.

## Flows

**Receiving "Nice 👍🏽🇫🇷" in a bubble**

1. The bubble's text view splits the text into clusters: `N`, `i`, `c`,
   `e`, ` `, `👍🏽`, `🇫🇷`.
2. The text face draws the letters. `👍🏽` misses the text face and has no
   entry of its own; with its tone removed (fallback rule 2) it matches 👍
   in the regular-size store.
3. The cache misses, so the draw inflates 👍's block into PSRAM.
4. The draw blends the glyph's palette entries against the bubble color and
   copies indices to pixels.
5. `🇫🇷` has no entry (rule 4), so it draws as an `FR` badge. Wrapping
   would have moved either cluster whole to the next line.

**Sending a reaction that isn't one of the six**

1. Hold a bubble → reaction palette → **More** → the picker opens on
   recents.
2. The user types `fi`; the filter narrows to 🔥 and the other matches.
3. Press inserts 🔥 as the reaction body, which goes out as a Status message
   with Regarding, as today. The recents record is updated after a debounce.

## Work order

1. **Clusters first.** The grapheme crate and the replacement cutters,
   including the `device_node.rs` fix. Then cluster-based Buoyant. With the
   generic placeholder alone, this already turns every sequence into one
   cell on every board.
2. **The store.** The manifest, and `umsh-emoji` with faces only at
   regular size on the Pager. Check rendering on the panel, then fix the
   size classes against real hardware rather than the table above.
3. **Rendering everywhere.** Both sizes, both boards, the full default set,
   the placeholder, chips (retire the reaction art), avatars, and Device ›
   About with Credits.
4. **Input.** The picker, recents, the name filter, and reaction **More**.
5. **Spec edits and mockups.** The protocol clarifications above, the
   About screen in the UX docs, and the `generate.py` switch.

## Decisions

- **Art:** Twemoji, pinned to a release. All of its SVGs are vendored
  (about 3,800 files), so enabling more emoji is a manifest edit only.
- **Set:** the default set above, with no skin tones and no country flags.
- **Sizes:** small and regular only; no large emoji-only messages for now.
- **Missing emoji:** the gray-disc placeholder, with no name lookup.
- **Credits:** on a new Device › About screen.
- **Reactions:** a **More** cell opens the picker.
- **Twemoji updates:** on each bump, regenerate rule 1's subgroup
  additions and review the manifest diff.
- **Spec:** clarifications 1–3; byte-boundary fragmentation is unchanged.
