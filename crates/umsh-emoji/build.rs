//! Renders the manifest's emoji into compressed glyph stores.
//!
//! Each emoji is drawn from its Twemoji SVG at every size in [`SIZES`],
//! rasterized at four times the size and box filtered down. Its sizes
//! share one palette of at most 32 colors, and each size is an index a
//! pixel into it. Palettes, and each size's indices, are grouped in
//! manifest order into blocks of [`BLOCK`] glyphs, and each block is one
//! raw DEFLATE stream after a codec byte.
//!
//! The format is read by `src/store.rs`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The sizes, in pixels, glyphs are rendered at: emoji set beside the
/// T-Deck's small text, beside the Pager's small text and the T-Deck's
/// body, and beside the Pager's body.
const SIZES: &[u32] = &[16, 20, 24];
/// Glyphs to a compressed block.
const BLOCK: usize = 16;
/// The most colors a glyph's palette holds.
const COLORS: usize = 32;
/// Rendered at this many times the size, then averaged down.
const SUPERSAMPLE: u32 = 4;
/// The codec byte of a block compressed with raw DEFLATE.
const CODEC_DEFLATE: u8 = 1;

const TONES: std::ops::RangeInclusive<u32> = 0x1F3FB..=0x1F3FF;
const VS16: u32 = 0xFE0F;

struct Entry {
    sequence: Vec<u32>,
}

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=manifest.txt");
    println!("cargo:rerun-if-changed=twemoji/svg");

    let entries = manifest(&std::fs::read_to_string(dir.join("manifest.txt")).unwrap());
    assert!(
        entries.len() <= usize::from(u16::MAX),
        "glyph ids are 16 bits"
    );
    let trees: Vec<resvg::usvg::Tree> = entries
        .iter()
        .map(|entry| {
            let path = svg_path(&dir.join("twemoji/svg"), &entry.sequence);
            let data = std::fs::read(&path).unwrap();
            resvg::usvg::Tree::from_data(&data, &resvg::usvg::Options::default())
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        })
        .collect();

    // Every size of a glyph shares one palette, drawn from all of them:
    // stored once, it costs a third of what one a size would.
    let renders: Vec<Vec<Vec<[f32; 4]>>> = trees
        .iter()
        .map(|tree| SIZES.iter().map(|&size| render(tree, size)).collect())
        .collect();
    let palettes: Vec<Vec<[f32; 4]>> = renders
        .iter()
        .map(|sizes| quantize(&sizes.concat()))
        .collect();
    if std::env::var_os("UMSH_EMOJI_STATS").is_some() {
        stats(&renders, &palettes);
    }

    let mut tables = String::new();
    writeln!(tables, "/// Glyphs in each store.").unwrap();
    writeln!(tables, "pub const COUNT: u16 = {};", entries.len()).unwrap();
    let records: Vec<Vec<u8>> = palettes.iter().map(|p| palette_record(p)).collect();
    let (data, starts, largest_palettes) = blocks(&records);
    std::fs::write(out.join("palettes.bin"), &data).unwrap();
    writeln!(
        tables,
        "/// Every glyph's palette: {} bytes compressed.\n\
         static PALETTES: Blocks = Blocks {{\n    \
         starts: &{starts:?},\n    \
         data: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/palettes.bin\")),\n\
         }};",
        data.len(),
    )
    .unwrap();
    let mut largest_indices = 0;
    for (s, &size) in SIZES.iter().enumerate() {
        let maps: Vec<Vec<u8>> = renders
            .iter()
            .zip(&palettes)
            .map(|(sizes, palette)| {
                sizes[s]
                    .iter()
                    .map(|p| nearest(palette, p).0 as u8)
                    .collect()
            })
            .collect();
        let (data, starts, largest) = blocks(&maps);
        largest_indices = largest_indices.max(largest);
        let file = format!("emoji-{size}.bin");
        std::fs::write(out.join(&file), &data).unwrap();
        writeln!(
            tables,
            "/// Emoji {size} pixels square: {} bytes compressed.\n\
             pub static STORE_{size}: Store = Store {{\n    \
             size: {size},\n    \
             indices: Blocks {{\n        \
             starts: &{starts:?},\n        \
             data: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{file}\")),\n    \
             }},\n\
             }};",
            data.len(),
        )
        .unwrap();
    }
    writeln!(
        tables,
        "/// Every store, smallest first.\npub static STORES: [&Store; {}] = [{}];",
        SIZES.len(),
        SIZES
            .iter()
            .map(|s| format!("&STORE_{s}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
    .unwrap();
    writeln!(
        tables,
        "/// The longest a block of palettes is inflated, in bytes.\n\
         const LARGEST_PALETTES: usize = {largest_palettes};\n\
         /// The longest a block of indices is inflated, in bytes.\n\
         const LARGEST_INDICES: usize = {largest_indices};\n\
         /// The most pixels a glyph has.\n\
         const PIXELS_MAX: usize = {};",
        SIZES.last().unwrap().pow(2)
    )
    .unwrap();
    lookup(&mut tables, &entries);
    std::fs::write(out.join("emoji.rs"), tables).unwrap();
}

/// The manifest's sequences, in order.
fn manifest(text: &str) -> Vec<Entry> {
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let codes = line.split(';').next().unwrap();
            let sequence: Vec<u32> = codes
                .split_whitespace()
                .map(|c| u32::from_str_radix(c, 16).expect("hex code point"))
                .collect();
            assert!(
                !sequence.iter().any(|c| TONES.contains(c)),
                "skin tones are drawn as their base: {line}"
            );
            Entry { sequence }
        })
        .collect()
}

/// Where Twemoji keeps a sequence's art. It names most files without
/// U+FE0F, but keeps it in some.
fn svg_path(dir: &Path, sequence: &[u32]) -> PathBuf {
    let name = |cps: &[u32]| {
        cps.iter()
            .map(|c| format!("{c:x}"))
            .collect::<Vec<_>>()
            .join("-")
    };
    let bare: Vec<u32> = sequence.iter().copied().filter(|&c| c != VS16).collect();
    let mut candidates = vec![name(sequence), name(&bare)];
    if bare.len() > 1 {
        let mut kept = vec![bare[0], VS16];
        kept.extend(&bare[1..]);
        candidates.push(name(&kept));
    }
    candidates
        .iter()
        .map(|n| dir.join(format!("{n}.svg")))
        .find(|p| p.exists())
        .unwrap_or_else(|| panic!("no Twemoji art for {sequence:x?}"))
}

/// A palette's record: its length, and then each color as RGB565 (big
/// endian) and an alpha.
fn palette_record(palette: &[[f32; 4]]) -> Vec<u8> {
    let mut record = vec![palette.len() as u8];
    for &[r, g, b, a] in palette {
        // Stored unpremultiplied: the device blends each entry into the
        // background once.
        let unpremultiply = |c: f32| {
            if a > 0.0 {
                (c / a).clamp(0.0, 1.0)
            } else {
                0.0
            }
        };
        let rgb565 = (u16::from(to_bits(unpremultiply(r), 5)) << 11)
            | (u16::from(to_bits(unpremultiply(g), 6)) << 5)
            | u16::from(to_bits(unpremultiply(b), 5));
        record.extend(rgb565.to_be_bytes());
        record.push((a * 255.0).round() as u8);
    }
    record
}

/// `records` compressed [`BLOCK`] at a time: the data, where each block
/// starts in it and then where the last ends, and the longest a block is
/// inflated.
fn blocks(records: &[Vec<u8>]) -> (Vec<u8>, Vec<usize>, usize) {
    let mut data = Vec::new();
    let mut starts = Vec::new();
    let mut largest = 0;
    for block in records.chunks(BLOCK) {
        let raw: Vec<u8> = block.concat();
        largest = largest.max(raw.len());
        starts.push(data.len());
        data.push(CODEC_DEFLATE);
        data.extend(miniz_oxide::deflate::compress_to_vec(&raw, 10));
    }
    starts.push(data.len());
    (data, starts, largest)
}

/// Prints how far each glyph's colors are from its render: with the shared
/// palette, and with one of its own a size.
fn stats(renders: &[Vec<Vec<[f32; 4]>>], palettes: &[Vec<[f32; 4]>]) {
    for (s, size) in SIZES.iter().enumerate() {
        let (mut shared, mut own, mut n) = (0.0f64, 0.0f64, 0.0f64);
        for (sizes, palette) in renders.iter().zip(palettes) {
            let pixels = &sizes[s];
            let alone = quantize(pixels);
            for p in pixels {
                shared += f64::from(nearest(palette, p).1);
                own += f64::from(nearest(&alone, p).1);
                n += 1.0;
            }
        }
        let rmse = |e: f64| (e / n / 4.0).sqrt() * 255.0;
        println!(
            "cargo:warning={size} px: RMSE {:.2} shared, {:.2} a size",
            rmse(shared),
            rmse(own)
        );
    }
}

fn to_bits(value: f32, bits: u32) -> u8 {
    (value * ((1 << bits) - 1) as f32).round() as u8
}

/// The glyph at `size`, as premultiplied RGBA from 0 to 1.
fn render(tree: &resvg::usvg::Tree, size: u32) -> Vec<[f32; 4]> {
    let big = size * SUPERSAMPLE;
    let mut pixmap = resvg::tiny_skia::Pixmap::new(big, big).unwrap();
    let scale = big as f32 / tree.size().width().max(tree.size().height());
    resvg::render(
        tree,
        resvg::tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    let samples = (SUPERSAMPLE * SUPERSAMPLE) as f32;
    let mut out = Vec::with_capacity((size * size) as usize);
    for y in 0..size {
        for x in 0..size {
            let mut sum = [0.0f32; 4];
            for dy in 0..SUPERSAMPLE {
                for dx in 0..SUPERSAMPLE {
                    let p = pixmap
                        .pixel(x * SUPERSAMPLE + dx, y * SUPERSAMPLE + dy)
                        .unwrap();
                    sum[0] += f32::from(p.red());
                    sum[1] += f32::from(p.green());
                    sum[2] += f32::from(p.blue());
                    sum[3] += f32::from(p.alpha());
                }
            }
            out.push(sum.map(|s| s / samples / 255.0));
        }
    }
    out
}

/// At most [`COLORS`] premultiplied colors for `pixels`.
///
/// k-means from a deterministic start: the most common color, then
/// repeatedly the pixel farthest from every chosen color, so the same
/// art always gives the same glyph.
fn quantize(pixels: &[[f32; 4]]) -> Vec<[f32; 4]> {
    // Distinct colors, by count, at the precision stored.
    let key = |p: &[f32; 4]| p.map(|c| (c * 255.0).round() as u8);
    let mut counts: HashMap<[u8; 4], (usize, [f32; 4])> = HashMap::new();
    for p in pixels {
        let entry = counts.entry(key(p)).or_insert((0, *p));
        entry.0 += 1;
    }
    let mut distinct: Vec<([u8; 4], usize, [f32; 4])> =
        counts.into_iter().map(|(k, (n, p))| (k, n, p)).collect();
    distinct.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    if distinct.len() <= COLORS {
        return distinct.iter().map(|d| d.2).collect();
    }
    // Clear stays exactly clear, so nothing is drawn around the art: when
    // any pixel is clear, the first color is, and stays so.
    let clear = distinct.iter().any(|d| d.0[3] == 0);
    let mut centers = vec![if clear { [0.0; 4] } else { distinct[0].2 }];
    while centers.len() < COLORS {
        let farthest = distinct
            .iter()
            .max_by(|a, b| {
                nearest(&centers, &a.2)
                    .1
                    .total_cmp(&nearest(&centers, &b.2).1)
            })
            .unwrap();
        centers.push(farthest.2);
    }
    for _ in 0..16 {
        let mut sums = vec![([0.0f32; 4], 0.0f32); centers.len()];
        for (_, n, p) in &distinct {
            let (i, _) = nearest(&centers, p);
            for (sum, channel) in sums[i].0.iter_mut().zip(p) {
                *sum += channel * *n as f32;
            }
            sums[i].1 += *n as f32;
        }
        let pinned = usize::from(clear);
        for (center, (sum, n)) in centers.iter_mut().zip(sums).skip(pinned) {
            if n > 0.0 {
                *center = sum.map(|s| s / n);
            }
        }
    }
    centers
}

/// The nearest of `centers` to `p`, and its squared distance.
fn nearest(centers: &[[f32; 4]], p: &[f32; 4]) -> (usize, f32) {
    centers
        .iter()
        .map(|c| (0..4).map(|i| (c[i] - p[i]).powi(2)).sum::<f32>())
        .enumerate()
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .unwrap()
}

/// The lookup table: each sequence without U+FE0F, as UTF-8, sorted, in
/// one string, and beside each its start in that string and its glyph.
fn lookup(tables: &mut String, entries: &[Entry]) {
    let mut keys: Vec<(String, usize)> = entries
        .iter()
        .enumerate()
        .map(|(id, entry)| {
            let key: String = entry
                .sequence
                .iter()
                .filter(|&&c| c != VS16)
                .map(|&c| char::from_u32(c).unwrap())
                .collect();
            (key, id)
        })
        .collect();
    keys.sort();
    for pair in keys.windows(2) {
        assert_ne!(pair[0].0, pair[1].0, "two sequences differ only by U+FE0F");
    }
    let mut pool = String::new();
    let mut index = Vec::new();
    for (key, id) in &keys {
        index.push((pool.len(), *id));
        pool.push_str(key);
    }
    assert!(pool.len() <= usize::from(u16::MAX));
    writeln!(
        tables,
        "/// Every sequence without U+FE0F, sorted, one after another.\n\
         static KEYS: &str = {pool:?};\n\
         /// Each sequence's start in [`KEYS`], and its glyph.\n\
         static INDEX: [(u16, u16); {}] = {index:?};",
        index.len()
    )
    .unwrap();
}
