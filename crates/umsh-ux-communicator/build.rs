//! Rasterizes the bundled fonts into Buoyant `PrerenderedFont` tables.
//!
//! Every character the font maps is rendered at each listed size, as 4-bit
//! coverage. Weights come from the variable fonts' `wght` axis.

use std::fmt::Write as _;
use std::path::PathBuf;

use swash::scale::{Render, ScaleContext, Source};
use swash::zeno::Format;
use swash::{FontRef, Setting};

struct Spec {
    /// The Rust name of the generated static.
    name: &'static str,
    file: &'static str,
    weight: f32,
    /// The sizes the Pager draws, then the T-Deck's.
    pager: &'static [u16],
    tdeck: &'static [u16],
    /// The characters rendered, when not every one the font maps.
    only: Option<&'static str>,
}

const SANS: &str = "fonts/MPLUS1[wght]-latin.ttf";
const MONO: &str = "fonts/MPLUSCodeLatin[wdth,wght]-latin.ttf";

// A board carries only the faces its sizes resolve to: each `Metrics` text
// size (small, secondary, body, title), and the avatar lettering, the flag
// badges, the clock, and the exchange code below. A size with no face of
// its own is drawn in the nearest, so a face missing here shows as text a
// size off, not as an error. `font::tests::faces_cover_requests` checks
// the metric sizes and the badges.

/// The Pager's text sizes: 16, 17, 20, and its 26 title drawn at 20.
const PAGER_UI: &[u16] = &[16, 17, 20];
/// The T-Deck's: 12, 14, 16, and 20, on its coarser panel.
const TDECK_UI: &[u16] = &[12, 14, 16, 20];

const SPECS: &[Spec] = &[
    Spec {
        name: "REGULAR",
        file: SANS,
        weight: 400.0,
        pager: PAGER_UI,
        tdeck: TDECK_UI,
        only: None,
    },
    Spec {
        name: "MEDIUM",
        file: SANS,
        weight: 500.0,
        pager: PAGER_UI,
        tdeck: TDECK_UI,
        only: None,
    },
    Spec {
        name: "SEMIBOLD",
        file: SANS,
        weight: 600.0,
        pager: PAGER_UI,
        tdeck: TDECK_UI,
        only: None,
    },
    // Beside the text sizes: 10, 12, 13, and 26 for avatar lettering on
    // both boards, and 10, 12, and 13 for every flag's region badge.
    Spec {
        name: "BOLD",
        file: SANS,
        weight: 700.0,
        pager: &[10, 12, 13, 16, 17, 20, 26],
        tdeck: &[10, 12, 13, 14, 16, 17, 20, 26],
        only: None,
    },
    Spec {
        name: "EXTRABOLD",
        file: SANS,
        weight: 800.0,
        pager: PAGER_UI,
        tdeck: TDECK_UI,
        only: None,
    },
    Spec {
        name: "MONO",
        file: MONO,
        weight: 400.0,
        pager: &[16, 20],
        tdeck: &[12, 14, 16, 20],
        only: None,
    },
    // Peer avatars' hints, on both boards.
    Spec {
        name: "MONO_BOLD",
        file: MONO,
        weight: 700.0,
        pager: &[10, 13, 14, 16, 20],
        tdeck: &[10, 13, 14, 16, 20],
        only: None,
    },
    // The lock screen's time: digits alone, large, beside the date and
    // unread chats, and larger in the middle when nothing else is shown.
    Spec {
        name: "CLOCK",
        file: SANS,
        weight: 700.0,
        pager: &[46, 56, 72],
        tdeck: &[46, 56, 72],
        only: Some("0123456789:"),
    },
    // A contact exchange's code, for both holders to compare.
    Spec {
        name: "CODE",
        file: MONO,
        weight: 700.0,
        pager: &[42],
        tdeck: &[32],
        only: Some("0123456789 "),
    },
];

/// Drawn for characters a face lacks. The fonts lack it too, so it is drawn
/// here: see [`replacement`].
const REPLACEMENT: char = '\u{FFFD}';

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let mut out = String::new();
    let mut context = ScaleContext::new();
    // A build that names no board draws for every one.
    let (pager, tdeck) = match (
        std::env::var_os("CARGO_FEATURE_PAGER").is_some(),
        std::env::var_os("CARGO_FEATURE_TDECK").is_some(),
    ) {
        (false, false) => (true, true),
        named => named,
    };
    let mut families = Vec::new();
    for spec in SPECS {
        println!("cargo:rerun-if-changed={}", spec.file);
        let data = std::fs::read(dir.join(spec.file)).expect("font file");
        let font = FontRef::from_index(&data, 0).expect("parsable font");
        let mut sizes = Vec::new();
        if pager {
            sizes.extend(spec.pager);
        }
        if tdeck {
            sizes.extend(spec.tdeck);
        }
        sizes.sort_unstable();
        sizes.dedup();
        let rasters: Vec<Raster> = sizes
            .iter()
            .map(|&size| face(&mut context, font, spec, size))
            .collect();
        for raster in &rasters {
            assert_eq!(
                raster.characters, rasters[0].characters,
                "{}: one character set",
                spec.name
            );
        }
        families.push((spec, rasters));
    }
    // One code for every face this build keeps.
    let code = Code::train(
        families
            .iter()
            .flat_map(|(_, rasters)| rasters)
            .flat_map(|raster| &raster.glyphs),
    );
    let table = code.table();
    writeln!(
        out,
        "/// Every face's decoding table.\nstatic CODES: [u8; {}] = {table:?};",
        table.len()
    )
    .unwrap();
    writeln!(
        out,
        "const _: () = {{\n    use buoyant::font::prerendered::coding;\n    \
         assert!(coding::EDGE == {EDGE} && coding::LEVELS == {LEVELS} && coding::PEEK == {PEEK});\n    \
         let bands = {:?};\n    let mut level = 0;\n    while level <= coding::EDGE {{\n        \
         assert!(coding::band(level) == bands[level as usize]);\n        level += 1;\n    }}\n}};",
        (0..=EDGE).map(band).collect::<Vec<_>>()
    )
    .unwrap();
    for (spec, rasters) in &families {
        let characters = &rasters[0].characters;
        writeln!(
            out,
            "static {}_RUNS: [CharRun; {}] = [{}];",
            spec.name,
            runs(characters).matches("CharRun").count(),
            runs(characters)
        )
        .unwrap();
        let faces: Vec<String> = rasters.iter().map(|r| emit(&mut out, r, &code)).collect();
        writeln!(
            out,
            "pub static {}: Typeface = Typeface::new(PrerenderedFont {{ faces: &[{}] }});",
            spec.name,
            faces.join(", ")
        )
        .unwrap();
    }
    writeln!(
        out,
        "/// Each typeface's sizes on the Pager, then on the T-Deck.\n\
         #[cfg(test)]\n\
         pub(crate) const BOARD_SIZES: &[(&Typeface, &[u16], &[u16])] = &["
    )
    .unwrap();
    for spec in SPECS {
        writeln!(
            out,
            "    (&{}, &{:?}, &{:?}),",
            spec.name, spec.pager, spec.tdeck
        )
        .unwrap();
    }
    writeln!(out, "];").unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out_dir.join("fonts.rs"), out).unwrap();
    std::fs::write(out_dir.join("shapes.rs"), shapes()).unwrap();
    std::fs::write(out_dir.join("icons.rs"), icons()).unwrap();
    let sans = std::fs::read(dir.join(SANS)).expect("font file");
    let sans = FontRef::from_index(&sans, 0).expect("parsable font");
    std::fs::write(
        out_dir.join("placeholder.rs"),
        placeholders(&mut context, sans),
    )
    .unwrap();
}

/// The sizes emoji are drawn at, as `umsh-emoji` renders them.
const EMOJI_SIZES: &[u32] = &[16, 20, 24];

/// The placeholder for an emoji the set lacks, at each emoji size: a gray
/// disc filling the cell, with a heavy question mark in the text color,
/// about two-thirds of the cell tall and centered on its ink. Each pixel
/// is RGB565 and an alpha, as an emoji's palette entries are.
fn placeholders(context: &mut ScaleContext, font: FontRef) -> String {
    const DISC: [f32; 3] = [0x6B as f32, 0x74 as f32, 0x80 as f32];
    const MARK: [f32; 3] = [0xEE as f32, 0xF1 as f32, 0xF5 as f32];
    const SS: u32 = 4;
    let mut out = String::new();
    let mut names = Vec::new();
    for &size in EMOJI_SIZES {
        let big = size * SS;
        let settings = [Setting {
            tag: swash::tag_from_bytes(b"wght"),
            value: 800.0,
        }];
        let mut scaler = context
            .builder(font)
            .size(big as f32 * 0.66)
            .hint(false)
            .variations(settings.iter().copied())
            .build();
        let mut renderer = Render::new(&[Source::Outline]);
        renderer.format(Format::Alpha);
        let mark = renderer
            .render(&mut scaler, font.charmap().map('?'))
            .expect("a question mark");
        let (mark_width, mark_height) = (mark.placement.width, mark.placement.height);
        let mark_x = (big as i32 - mark_width as i32) / 2;
        let mark_y = (big as i32 - mark_height as i32) / 2;
        // A half-pixel inset, so the disc fills the cell as Twemoji's art
        // does.
        let center = big as f32 / 2.0;
        let radius = center - SS as f32 / 2.0;
        let mut pixels = Vec::new();
        for y in 0..size {
            for x in 0..size {
                let (mut rgb, mut alpha) = ([0.0f32; 3], 0.0f32);
                for j in 0..SS {
                    for i in 0..SS {
                        let (sx, sy) = (x * SS + i, y * SS + j);
                        let (dx, dy) = (sx as f32 + 0.5 - center, sy as f32 + 0.5 - center);
                        if dx * dx + dy * dy > radius * radius {
                            continue;
                        }
                        let (mx, my) = (sx as i32 - mark_x, sy as i32 - mark_y);
                        let q = if (0..mark_width as i32).contains(&mx)
                            && (0..mark_height as i32).contains(&my)
                        {
                            f32::from(mark.data[(my as u32 * mark_width + mx as u32) as usize])
                                / 255.0
                        } else {
                            0.0
                        };
                        for c in 0..3 {
                            rgb[c] += DISC[c] * (1.0 - q) + MARK[c] * q;
                        }
                        alpha += 1.0;
                    }
                }
                let rgb565 = if alpha > 0.0 {
                    let c = rgb.map(|v| v / alpha / 255.0);
                    ((c[0] * 31.0).round() as u16) << 11
                        | ((c[1] * 63.0).round() as u16) << 5
                        | (c[2] * 31.0).round() as u16
                } else {
                    0
                };
                let alpha = (alpha / (SS * SS) as f32 * 255.0).round() as u8;
                pixels.push(format!("({rgb565:#06x}, {alpha})"));
            }
        }
        writeln!(
            out,
            "static PLACEHOLDER_{size}: [(u16, u8); {}] = [{}];",
            pixels.len(),
            pixels.join(", ")
        )
        .unwrap();
        names.push(format!("({size}, &PLACEHOLDER_{size})"));
    }
    writeln!(
        out,
        "/// The placeholder at each emoji size: each pixel's RGB565 and alpha.\n\
         static PLACEHOLDERS: [(u16, &[(u16, u8)]); {}] = [{}];",
        names.len(),
        names.join(", ")
    )
    .unwrap();
    out
}

/// One layer of an icon: SVG path data, filled or stroked, added to the
/// mask or cut out of it.
struct Layer {
    path: &'static str,
    stroke: Option<f32>,
    cut: bool,
}

const fn stroke(path: &'static str, width: f32) -> Layer {
    Layer {
        path,
        stroke: Some(width),
        cut: false,
    }
}

const fn fill(path: &'static str) -> Layer {
    Layer {
        path,
        stroke: None,
        cut: false,
    }
}

const fn cut(path: &'static str) -> Layer {
    Layer {
        path,
        stroke: None,
        cut: true,
    }
}

/// Icons drawn centered on the origin, each with the square size in pixels
/// it is rasterized at and its scale in pixels per unit. These are the
/// mockup's glyphs at the mockup's scales.
const ICONS: &[(&str, u32, f32, &[Layer])] = &[
    (
        "CHATS",
        28,
        1.5,
        &[
            stroke(
                "M-4.5 -7 H4.5 Q8 -7 8 -3.5 V1 Q8 4.5 4.5 4.5 H-4.5 Q-8 4.5 -8 1 V-3.5 Q-8 -7 -4.5 -7 Z",
                1.4,
            ),
            stroke("M-4 4.5 L-5.5 8 L0 4.5", 1.4),
        ],
    ),
    (
        "PEERS",
        28,
        1.5,
        // Clear of the square's edges on every side, the circles' strokes
        // included.
        &[
            stroke("M0 -5.5 L-5.5 5.5 L5.5 5.5 Z", 1.2),
            cut("M-2.6 -5.5 A2.6 2.6 0 1 0 2.6 -5.5 A2.6 2.6 0 1 0 -2.6 -5.5 Z"),
            cut("M-8.1 5.5 A2.6 2.6 0 1 0 -2.9 5.5 A2.6 2.6 0 1 0 -8.1 5.5 Z"),
            cut("M2.9 5.5 A2.6 2.6 0 1 0 8.1 5.5 A2.6 2.6 0 1 0 2.9 5.5 Z"),
            stroke(
                "M-2.6 -5.5 A2.6 2.6 0 1 0 2.6 -5.5 A2.6 2.6 0 1 0 -2.6 -5.5 Z",
                1.4,
            ),
            stroke(
                "M-8.1 5.5 A2.6 2.6 0 1 0 -2.9 5.5 A2.6 2.6 0 1 0 -8.1 5.5 Z",
                1.4,
            ),
            stroke(
                "M2.9 5.5 A2.6 2.6 0 1 0 8.1 5.5 A2.6 2.6 0 1 0 2.9 5.5 Z",
                1.4,
            ),
        ],
    ),
    (
        "DEVICE",
        28,
        1.5,
        &[
            stroke("M-4.6 0 A4.6 4.6 0 1 0 4.6 0 A4.6 4.6 0 1 0 -4.6 0 Z", 1.6),
            fill("M-1.4 0 A1.4 1.4 0 1 0 1.4 0 A1.4 1.4 0 1 0 -1.4 0 Z"),
            stroke(
                "M6 0 L8.2 0 M4.24 4.24 L5.8 5.8 M0 6 L0 8.2 M-4.24 4.24 L-5.8 5.8 \
                 M-6 0 L-8.2 0 M-4.24 -4.24 L-5.8 -5.8 M0 -6 L0 -8.2 M4.24 -4.24 L5.8 -5.8",
                2.2,
            ),
        ],
    ),
    // The strip's links: Bluetooth's rune, flanked while a phone is
    // connected; GNSS's crosshairs, closed on a center once there is a
    // fix; and Wi-Fi's fan, full when joined, its inner arcs while
    // joining, and its outer arcs over a cross while no network is.
    ("BLUETOOTH", 18, 1.3, &[stroke(BLUETOOTH, 1.1)]),
    (
        "BLUETOOTH_LINKED",
        18,
        1.3,
        &[
            stroke(BLUETOOTH, 1.1),
            fill("M-6.6 0 A1 1 0 1 0 -4.6 0 A1 1 0 1 0 -6.6 0 Z"),
            fill("M4.6 0 A1 1 0 1 0 6.6 0 A1 1 0 1 0 4.6 0 Z"),
        ],
    ),
    (
        "GNSS",
        18,
        1.3,
        &[
            stroke(GNSS_RING, 1.1),
            fill("M-1.1 0 A1.1 1.1 0 1 0 1.1 0 A1.1 1.1 0 1 0 -1.1 0 Z"),
            stroke(GNSS_TICKS, 1.1),
        ],
    ),
    (
        "GNSS_SEARCHING",
        18,
        1.3,
        &[stroke(GNSS_RING, 1.1), stroke(GNSS_TICKS, 1.1)],
    ),
    (
        "WIFI",
        18,
        1.3,
        &[
            fill(WIFI_DOT),
            stroke(WIFI_INNER, 1.1),
            stroke(WIFI_MIDDLE, 1.1),
            stroke(WIFI_OUTER, 1.1),
        ],
    ),
    (
        "WIFI_JOINING",
        18,
        1.3,
        &[
            fill(WIFI_DOT),
            stroke(WIFI_INNER, 1.1),
            stroke(WIFI_MIDDLE, 1.1),
        ],
    ),
    // A "C", while the device is a phone's companion radio.
    (
        "COMPANION",
        18,
        1.3,
        &[stroke("M2.97 -2.97 A4.2 4.2 0 1 0 2.97 2.97", 2.0)],
    ),
    // A network's row: its fan, drawn whole and dim with its lit arcs over
    // it, so a weaker signal lights fewer; and a padlock on those that take
    // a password.
    (
        "FAN",
        16,
        1.15,
        &[
            fill(WIFI_DOT),
            stroke(WIFI_INNER, 1.2),
            stroke(WIFI_MIDDLE, 1.2),
            stroke(WIFI_OUTER, 1.2),
        ],
    ),
    (
        "FAN_2",
        16,
        1.15,
        &[
            fill(WIFI_DOT),
            stroke(WIFI_INNER, 1.2),
            stroke(WIFI_MIDDLE, 1.2),
        ],
    ),
    (
        "FAN_1",
        16,
        1.15,
        &[fill(WIFI_DOT), stroke(WIFI_INNER, 1.2)],
    ),
    (
        "LOCK_SMALL",
        12,
        0.75,
        &[
            stroke(
                "M-3.5 0.05 V-2.95 Q-3.5 -6.95 0 -6.95 Q3.5 -6.95 3.5 -2.95 V0.05",
                1.8,
            ),
            fill(
                "M-4 0.05 H4 Q5.5 0.05 5.5 1.55 V7.05 Q5.5 8.55 4 8.55 H-4 Q-5.5 8.55 -5.5 7.05 V1.55 Q-5.5 0.05 -4 0.05 Z",
            ),
        ],
    ),
    (
        "WIFI_LOST",
        18,
        1.3,
        &[
            stroke(WIFI_MIDDLE, 1.1),
            stroke(WIFI_OUTER, 1.1),
            stroke("M-1.5 2.2 L1.5 5.2 M1.5 2.2 L-1.5 5.2", 1.1),
        ],
    ),
    (
        "BELL_SLASH",
        18,
        1.3,
        &[
            stroke(
                "M-4 3 Q-3.5 1 -3.5 -1 Q-3.5 -5 0 -5 Q3.5 -5 3.5 -1 Q3.5 1 4 3 Z M-1.3 4.5 H1.3",
                1.1,
            ),
            stroke("M-5 -5 L5 5", 1.2),
        ],
    ),
    (
        "PENCIL",
        18,
        1.2,
        &[stroke("M-5 5 L-4 1 L3 -6 L6 -3 L-1 4 Z M1 -4 L4 -1", 1.4)],
    ),
    ("BACK", 14, 1.0, &[stroke("M3 -6 L-3 0 L3 6", 2.0)]),
    ("CHEVRON", 14, 1.0, &[stroke("M-3 -6 L3 0 L-3 6", 2.0)]),
    ("CHECK", 16, 1.0, &[stroke("M-5 0 L-1.5 4 L5 -4", 2.2)]),
    (
        "SEARCH",
        18,
        1.4,
        &[
            stroke("M-5 -1 A4 4 0 1 0 3 -1 A4 4 0 1 0 -5 -1 Z", 1.3),
            stroke("M2 2 L5 5", 1.4),
        ],
    ),
    // The character picker's recently used characters.
    (
        "CLOCK",
        18,
        1.0,
        &[
            stroke("M-7 0 A7 7 0 1 0 7 0 A7 7 0 1 0 -7 0 Z", 1.5),
            stroke("M0 -4 L0 0 L3 2", 1.5),
        ],
    ),
    // Shift and Alt in the strip: outlined while armed for one key,
    // filled with a bar beneath while locked. Alt is drawn as its key.
    ("SHIFT_ONCE", 20, 1.15, &[stroke(SHIFT, 1.5)]),
    (
        "SHIFT_LOCK",
        20,
        1.15,
        &[fill(SHIFT), stroke(SHIFT, 1.2), fill(LOCK_BAR)],
    ),
    (
        "ALT_ONCE",
        20,
        1.15,
        &[stroke(
            "M-3.25 -6.25 H3.25 A3.5 3.5 0 0 1 6.75 -2.75 V-1.25 A3.5 3.5 0 0 1 3.25 2.25 H-3.25 A3.5 3.5 0 0 1 -6.75 -1.25 V-2.75 A3.5 3.5 0 0 1 -3.25 -6.25 Z",
            1.5,
        )],
    ),
    (
        "ALT_LOCK",
        20,
        1.15,
        &[
            fill(
                "M-3.5 -7 H3.5 A4 4 0 0 1 7.5 -3 V-1 A4 4 0 0 1 3.5 3 H-3.5 A4 4 0 0 1 -7.5 -1 V-3 A4 4 0 0 1 -3.5 -7 Z",
            ),
            fill(LOCK_BAR),
        ],
    ),
    // The keyboard light's glance: the keyboard, with rays while lit.
    (
        "KEYBOARD_LIT",
        48,
        1.5,
        &[
            stroke(KEYBOARD_BODY, 1.8),
            fill(KEYBOARD_KEYS),
            stroke("M-11.5 -6 L-13.5 -11 M0 -6 L0 -11 M11.5 -6 L13.5 -11", 1.8),
        ],
    ),
    (
        "KEYBOARD_UNLIT",
        48,
        1.5,
        &[stroke(KEYBOARD_BODY, 1.8), fill(KEYBOARD_KEYS)],
    ),
    // Brightness's glance.
    (
        "SUN",
        24,
        1.0,
        &[
            fill("M-5 0 A5 5 0 1 0 5 0 A5 5 0 1 0 -5 0 Z"),
            stroke(
                "M8 0 L11 0 M5.66 5.66 L7.78 7.78 M0 8 L0 11 M-5.66 5.66 L-7.78 7.78 M-8 0 L-11 0 M-5.66 -5.66 L-7.78 -7.78 M0 -8 L0 -11 M5.66 -5.66 L7.78 -7.78",
                2.0,
            ),
        ],
    ),
    // Beside the strip's battery while it charges.
    (
        "BOLT",
        14,
        1.3,
        &[fill(
            "M0.25 -5.5 L-2.75 0.5 H-0.25 L-1.75 5.5 L2.75 -1 H0.25 Z",
        )],
    ),
    // Shutting down's.
    (
        "POWER",
        40,
        2.0,
        &[
            stroke("M-4.6 -5.2 A7 7 0 1 0 4.6 -5.2", 1.6),
            stroke("M0 -8.5 V-1.5", 1.6),
        ],
    ),
    // The lock screen's: the padlock before its hint, shut until the wheel
    // has turned far enough and open while a press unlocks.
    (
        "PADLOCK",
        20,
        1.1,
        &[
            stroke(
                "M-3.5 0.05 V-2.95 Q-3.5 -6.95 0 -6.95 Q3.5 -6.95 3.5 -2.95 V0.05",
                1.4,
            ),
            fill(
                "M-4 0.05 H4 Q5.5 0.05 5.5 1.55 V7.05 Q5.5 8.55 4 8.55 H-4 Q-5.5 8.55 -5.5 7.05 V1.55 Q-5.5 0.05 -4 0.05 Z",
            ),
        ],
    ),
    (
        "PADLOCK_OPEN",
        20,
        1.1,
        &[
            stroke(
                "M-3.5 0.05 V-3.95 Q-3.5 -7.95 0 -7.95 Q3.5 -7.95 3.5 -3.95 V-2.45",
                1.4,
            ),
            fill(
                "M-4 0.05 H4 Q5.5 0.05 5.5 1.55 V7.05 Q5.5 8.55 4 8.55 H-4 Q-5.5 8.55 -5.5 7.05 V1.55 Q-5.5 0.05 -4 0.05 Z",
            ),
        ],
    ),
    // Under the unlock bar: which way to turn.
    ("DOWN", 12, 1.0, &[stroke("M-4 -2 L0 2 L4 -2", 1.6)]),
    // Over and under a part of the date and time being changed.
    ("UP", 12, 1.0, &[stroke("M-4 2 L0 -2 L4 2", 1.6)]),
    // A hop of a route being edited, which can be moved.
    (
        "GRIP",
        16,
        1.0,
        &[stroke("M-7 -4 H7 M-7 0 H7 M-7 4 H7", 1.6)],
    ),
    // A battery with only its last cell left: the banner's at 22, and the
    // screen's when it is empty at five times that.
    ("BATTERY_LOW", 22, 1.0, BATTERY),
    ("BATTERY_EMPTY", 104, 5.0, BATTERY),
    (
        "ADD",
        32,
        1.0,
        &[
            stroke("M-14 0 A14 14 0 1 0 14 0 A14 14 0 1 0 -14 0 Z", 1.8),
            stroke("M-6 0 H6 M0 -6 V6", 2.2),
        ],
    ),
    // The route editor's Add hop, on the rail where a hop's avatar sits.
    (
        "ADD_HOP",
        24,
        0.78,
        &[
            stroke("M-14 0 A14 14 0 1 0 14 0 A14 14 0 1 0 -14 0 Z", 2.2),
            stroke("M-6 0 H6 M0 -6 V6", 2.6),
        ],
    ),
    (
        "WARNING",
        18,
        0.9,
        &[
            stroke("M0 -8 L9 7 H-9 Z", 1.8),
            stroke("M0 -2.5 V2", 2.0),
            fill("M-1.2 4.6 A1.2 1.2 0 1 0 1.2 4.6 A1.2 1.2 0 1 0 -1.2 4.6 Z"),
        ],
    ),
    // The same, over an exchange whose codes differ.
    (
        "WARNING_LARGE",
        36,
        1.8,
        &[
            stroke("M0 -8 L9 7 H-9 Z", 1.8),
            stroke("M0 -2.5 V2", 2.0),
            fill("M-1.2 4.6 A1.2 1.2 0 1 0 1.2 4.6 A1.2 1.2 0 1 0 -1.2 4.6 Z"),
        ],
    ),
    // A device on Add peer before anything is exchanged: the outline of
    // its kind of hardware, drawn over its session color. At the size of
    // a row's avatar and of a header's.
    ("HANDHELD_34", 34, 1.0, HANDHELD),
    ("HANDHELD_26", 26, 0.765, HANDHELD),
    // How near a device on Add peer seems: the dot, and the arcs lit from
    // the inside out.
    (
        "NEAR_DOT",
        30,
        1.0,
        &[fill(
            "M-9.6 0 A2.6 2.6 0 1 0 -4.4 0 A2.6 2.6 0 1 0 -9.6 0 Z",
        )],
    ),
    (
        "NEAR_1",
        30,
        1.0,
        &[stroke("M-3.4 -4.8 A6 6 0 0 1 -3.4 4.8", 2.0)],
    ),
    (
        "NEAR_2",
        30,
        1.0,
        &[stroke("M-0.4 -8.8 A11 11 0 0 1 -0.4 8.8", 2.0)],
    ),
    (
        "NEAR_3",
        30,
        1.0,
        &[stroke("M2.6 -12.8 A16 16 0 0 1 2.6 12.8", 2.0)],
    ),
];

/// A handheld with a screen over a row of keys, landscape.
const HANDHELD: &[Layer] = &[
    stroke(
        "M-7.5 -7 H7.5 A2.5 2.5 0 0 1 10 -4.5 V4.5 A2.5 2.5 0 0 1 7.5 7 H-7.5 \
         A2.5 2.5 0 0 1 -10 4.5 V-4.5 A2.5 2.5 0 0 1 -7.5 -7 Z",
        1.8,
    ),
    fill(
        "M-5.5 -4 H5.5 A1 1 0 0 1 6.5 -3 V-0.5 A1 1 0 0 1 5.5 0.5 H-5.5 \
         A1 1 0 0 1 -6.5 -0.5 V-3 A1 1 0 0 1 -5.5 -4 Z",
    ),
    fill(
        "M-6.3 3.5 A0.9 0.9 0 1 0 -4.5 3.5 A0.9 0.9 0 1 0 -6.3 3.5 Z \
         M-2.7 3.5 A0.9 0.9 0 1 0 -0.9 3.5 A0.9 0.9 0 1 0 -2.7 3.5 Z \
         M0.9 3.5 A0.9 0.9 0 1 0 2.7 3.5 A0.9 0.9 0 1 0 0.9 3.5 Z \
         M4.5 3.5 A0.9 0.9 0 1 0 6.3 3.5 A0.9 0.9 0 1 0 4.5 3.5 Z",
    ),
];

/// The strip's link glyphs, in parts. Wi-Fi's arcs span 45 degrees either
/// side of upright, about the dot.
const BLUETOOTH: &str = "M-3 -3 L3 3 L0 6 V-6 L3 -3 L-3 3";
const GNSS_RING: &str = "M-3.6 0 A3.6 3.6 0 1 0 3.6 0 A3.6 3.6 0 1 0 -3.6 0 Z";
const GNSS_TICKS: &str = "M0 -6 V-4 M0 4 V6 M-6 0 H-4 M4 0 H6";
const WIFI_DOT: &str = "M-1.1 3.7 A1.1 1.1 0 1 0 1.1 3.7 A1.1 1.1 0 1 0 -1.1 3.7 Z";
const WIFI_INNER: &str = "M-1.98 1.72 A2.8 2.8 0 0 1 1.98 1.72";
const WIFI_MIDDLE: &str = "M-3.96 -0.26 A5.6 5.6 0 0 1 3.96 -0.26";
const WIFI_OUTER: &str = "M-5.94 -2.24 A8.4 8.4 0 0 1 5.94 -2.24";

/// Shift's arrow, and the bar under a locked modifier.
const SHIFT: &str = "M0 -7.5 L7 -0.5 H3.2 V3.5 H-3.2 V-0.5 H-7 Z";
const LOCK_BAR: &str = "M-4.5 5.5 H4.5 V7.7 H-4.5 Z";

/// The keyboard's outline, and its keys and space bar.
const KEYBOARD_BODY: &str = "M-11 -2 H11 A3 3 0 0 1 14 1 V11 A3 3 0 0 1 11 14 H-11 A3 3 0 0 1 -14 11 V1 A3 3 0 0 1 -11 -2 Z";
const KEYBOARD_KEYS: &str = "M-10.5 1.5 H-7.9 V3.9 H-10.5 Z M-5.9 1.5 H-3.3 V3.9 H-5.9 Z M-1.3 1.5 H1.3 V3.9 H-1.3 Z M3.3 1.5 H5.9 V3.9 H3.3 Z M7.9 1.5 H10.5 V3.9 H7.9 Z M-10.5 5.7 H-7.9 V8.1 H-10.5 Z M-5.9 5.7 H-3.3 V8.1 H-5.9 Z M-1.3 5.7 H1.3 V8.1 H-1.3 Z M3.3 5.7 H5.9 V8.1 H3.3 Z M7.9 5.7 H10.5 V8.1 H7.9 Z M-6 9.6 H6 V11.6 H-6 Z";

const BATTERY: &[Layer] = &[
    stroke(
        "M-7 -5 H5 A2 2 0 0 1 7 -3 V3 A2 2 0 0 1 5 5 H-7 A2 2 0 0 1 -9 3 V-3 A2 2 0 0 1 -7 -5 Z",
        1.5,
    ),
    fill("M7.5 -2 H9.5 V2 H7.5 Z"),
    fill("M-7 -3 H-4.5 V3 H-7 Z"),
];

/// The icons as Gray4 masks.
fn icons() -> String {
    use swash::zeno::{Cap, Join, Mask, Stroke, Transform};
    let mut out = String::new();
    // Each icon's inked columns, for rows that pack icons by what shows.
    let mut inks = String::new();
    for &(name, size, k, layers) in ICONS {
        let n = (size * size) as usize;
        let mut acc = vec![0f32; n];
        for layer in layers {
            let transform =
                Transform::scale(k, k).then_translate(size as f32 / 2.0, size as f32 / 2.0);
            let mut mask = Mask::new(layer.path);
            mask.size(size, size)
                .transform(Some(transform))
                .format(Format::Alpha);
            if let Some(width) = layer.stroke {
                let mut style = Stroke::new(width);
                style.cap(Cap::Round).join(Join::Round);
                mask.style(style);
            }
            let (alpha, placement) = mask.render();
            assert_eq!((placement.width, placement.height), (size, size));
            for (a, &v) in acc.iter_mut().zip(alpha.iter()) {
                let v = f32::from(v) / 255.0;
                *a = if layer.cut { *a * (1.0 - v) } else { a.max(v) };
            }
        }
        let row_bytes = size.div_ceil(2) as usize;
        let mut packed = vec![0u8; row_bytes * size as usize];
        for y in 0..size as usize {
            for x in 0..size as usize {
                let nibble = (acc[y * size as usize + x] * 15.0).round() as u8;
                packed[y * row_bytes + x / 2] |= if x % 2 == 0 { nibble << 4 } else { nibble };
            }
        }
        writeln!(
            out,
            "pub static {name}: ImageRaw<'static, Gray4> = ImageRaw::new(&{packed:?}, {size});"
        )
        .unwrap();
        // A column counts once something in it shows: antialiasing's faint
        // fringe would otherwise hold every icon at its square's width.
        let inked = |x: usize| (0..size as usize).any(|y| acc[y * size as usize + x] >= 0.35);
        let left = (0..size as usize).find(|&x| inked(x)).unwrap_or(0);
        let right = (0..size as usize)
            .rfind(|&x| inked(x))
            .map_or(left, |x| x + 1);
        writeln!(
            inks,
            "    pub const {name}: super::Ink = super::Ink {{ left: {left}, width: {} }};",
            right - left
        )
        .unwrap();
    }
    writeln!(out, "pub mod ink {{\n{inks}}}").unwrap();
    out
}

/// Avatar diameters, in pixels, that the screens draw.
const AVATAR_SIZES: &[u32] = &[26, 28, 30, 34, 44];

/// The avatar outlines as Gray4 masks: one static per shape and size, named
/// like `HEXAGON_34`, each row padded to a whole byte.
fn shapes() -> String {
    let mut out = String::new();
    for &size in AVATAR_SIZES {
        let s = size as f32;
        let c = s / 2.0;
        let triangle_height = s * 1.16;
        let half_base = triangle_height / 3f32.sqrt();
        let triangle_corner = s * 0.16;
        // A base corner rounded at 60° reaches (√3 - 1) times its radius
        // short of its vertex across.
        let triangle_half_width = half_base - triangle_corner * (3f32.sqrt() - 1.0);
        let half_width = s / 3f32.sqrt();
        let outlines = [
            ("CIRCLE", rounded_polygon(&circle_points(c, c, c), 0.0)),
            (
                "TRIANGLE",
                rounded_polygon(
                    &[
                        (c, s - triangle_height),
                        (c + half_base, s),
                        (c - half_base, s),
                    ],
                    triangle_corner,
                ),
            ),
            (
                "HEXAGON",
                rounded_polygon(
                    &[
                        (c - half_width, c),
                        (c - half_width / 2.0, 0.0),
                        (c + half_width / 2.0, 0.0),
                        (c + half_width, c),
                        (c + half_width / 2.0, s),
                        (c - half_width / 2.0, s),
                    ],
                    s * 0.2,
                ),
            ),
            (
                "SQUARE",
                rounded_polygon(&[(0.0, 0.0), (s, 0.0), (s, s), (0.0, s)], s * 0.25),
            ),
        ];
        for (name, path) in outlines {
            // The triangle and the hexagon are wider than tall; every mask
            // is centered in a frame wide enough for it.
            let width = match name {
                "TRIANGLE" => (2.0 * triangle_half_width).ceil() as u32,
                "HEXAGON" => (2.0 * half_width).ceil() as u32,
                _ => size,
            };
            let dx = (width as f32 - s) / 2.0;
            let (alpha, placement) = swash::zeno::Mask::new(path.as_str())
                .size(width, size)
                .offset(swash::zeno::Vector::new(dx, 0.0))
                .format(Format::Alpha)
                .render();
            assert_eq!((placement.width, placement.height), (width, size));
            let row_bytes = width.div_ceil(2) as usize;
            let mut packed = vec![0u8; row_bytes * size as usize];
            for y in 0..size as usize {
                for x in 0..width as usize {
                    let a = alpha[y * width as usize + x];
                    let nibble = ((u16::from(a) * 15 + 127) / 255) as u8;
                    packed[y * row_bytes + x / 2] |= if x % 2 == 0 { nibble << 4 } else { nibble };
                }
            }
            writeln!(
                out,
                "pub static {name}_{size}: ImageRaw<'static, Gray4> = ImageRaw::new(&{packed:?}, {width});"
            )
            .unwrap();
        }
    }
    out
}

/// A circle, as a polygon so it shares the path code: enough sides that no
/// facet survives rasterization at these sizes.
fn circle_points(cx: f32, cy: f32, r: f32) -> Vec<(f32, f32)> {
    (0..96)
        .map(|i| {
            let a = i as f32 / 96.0 * std::f32::consts::TAU;
            (cx + r * a.cos(), cy + r * a.sin())
        })
        .collect()
}

/// SVG path data for a closed polygon whose corners are arcs of `radius`
/// tangent to both adjoining edges, matching the iOS `PeerAvatarOutline`.
fn rounded_polygon(points: &[(f32, f32)], radius: f32) -> String {
    let n = points.len();
    let mut d = String::new();
    for i in 0..n {
        let p0 = points[(i + n - 1) % n];
        let p1 = points[i];
        let p2 = points[(i + 1) % n];
        let v1 = (p0.0 - p1.0, p0.1 - p1.1);
        let v2 = (p2.0 - p1.0, p2.1 - p1.1);
        let l1 = v1.0.hypot(v1.1);
        let l2 = v2.0.hypot(v2.1);
        let angle = ((v1.0 * v2.0 + v1.1 * v2.1) / (l1 * l2))
            .clamp(-1.0, 1.0)
            .acos();
        let t = if radius > 0.0 {
            radius / (angle / 2.0).tan()
        } else {
            0.0
        };
        let a = (p1.0 + v1.0 / l1 * t, p1.1 + v1.1 / l1 * t);
        let b = (p1.0 + v2.0 / l2 * t, p1.1 + v2.1 / l2 * t);
        write!(d, "{}{:.3} {:.3}", if i == 0 { "M" } else { "L" }, a.0, a.1).unwrap();
        if radius > 0.0 {
            write!(d, "A{radius:.3} {radius:.3} 0 0 1 {:.3} {:.3}", b.0, b.1).unwrap();
        }
    }
    d.push('Z');
    d
}

/// The replacement character at `size`: a diamond centered on the capitals,
/// `cap` tall, with a bold question mark knocked out of it. Returns the
/// diamond's side, how far its top stands above the baseline, and its 4-bit
/// coverage.
fn replacement(
    context: &mut ScaleContext,
    font: FontRef,
    spec: &Spec,
    size: u16,
    cap: i32,
    ascent: i32,
    descent: i32,
) -> (u32, i32, Vec<u8>) {
    // As tall as the line box allows, up to 1.4 capitals.
    let side = ((cap as f32 * 1.4).round() as i32)
        .min(2 * ascent - cap)
        .min(cap - 2 * descent)
        .max(1);
    let rise = ((cap + side) as f32 / 2.0).round() as i32;
    let mark = {
        let settings = [Setting {
            tag: swash::tag_from_bytes(b"wght"),
            value: spec.weight.max(700.0),
        }];
        let mut scaler = context
            .builder(font)
            .size(f32::from(size) * 0.55 * side as f32 / cap.max(1) as f32)
            .hint(false)
            .variations(settings.iter().copied())
            .build();
        let mut renderer = Render::new(&[Source::Outline]);
        renderer.format(Format::Alpha);
        renderer
            .render(&mut scaler, font.charmap().map('?'))
            .expect("a question mark")
    };
    let (mark_width, mark_height) = (mark.placement.width as i32, mark.placement.height as i32);
    let (mark_x, mark_y) = ((side - mark_width) / 2, (side - mark_height) / 2);
    let half = side as f32 / 2.0;
    let mut coverage = Vec::with_capacity((side * side) as usize);
    for y in 0..side {
        for x in 0..side {
            // Four by four samples of the diamond.
            let mut inside = 0;
            for j in 0..4 {
                for i in 0..4 {
                    let dx = (x as f32 + (i as f32 + 0.5) / 4.0 - half).abs();
                    let dy = (y as f32 + (j as f32 + 0.5) / 4.0 - half).abs();
                    inside += u32::from(dx + dy <= half);
                }
            }
            let (mx, my) = (x - mark_x, y - mark_y);
            let knocked = if (0..mark_width).contains(&mx) && (0..mark_height).contains(&my) {
                u32::from(mark.data[(my * mark_width + mx) as usize])
            } else {
                0
            };
            let alpha = inside * 255 / 16 * (255 - knocked) / 255;
            coverage.push(((alpha * 15 + 127) / 255) as u8);
        }
    }
    (side as u32, rise, coverage)
}

/// Writes one face's tables and returns its `Face` expression.
/// One face, rasterized: its line metrics, and each glyph in character
/// order, the replacement glyph last, which is also the fallback.
struct Raster {
    id: String,
    family: &'static str,
    size: u16,
    ascent: i32,
    descent: i32,
    line_gap: i32,
    glyphs: Vec<Glyph>,
    characters: Vec<char>,
}

struct Glyph {
    advance: i32,
    left: i32,
    top: i32,
    width: u32,
    height: u32,
    /// 4-bit coverage, row by row.
    pixels: Vec<u8>,
}

fn face(context: &mut ScaleContext, font: FontRef, spec: &Spec, size: u16) -> Raster {
    let settings = [Setting {
        tag: swash::tag_from_bytes(b"wght"),
        value: spec.weight,
    }];
    let coords: Vec<_> = font
        .variations()
        .normalized_coords(settings.iter().copied())
        .collect();
    let glyph_metrics = font.glyph_metrics(&coords).scale(f32::from(size));

    let mut scaler = context
        .builder(font)
        .size(f32::from(size))
        .hint(false)
        .variations(settings.iter().copied())
        .build();
    let mut renderer = Render::new(&[Source::Outline]);
    renderer.format(Format::Alpha);

    let mut chars = Vec::new();
    font.charmap().enumerate(|code, id| {
        if let Some(c) = char::from_u32(code)
            && id != 0
            && spec.only.is_none_or(|only| only.contains(c))
        {
            chars.push((c, id));
        }
    });
    chars.sort_unstable();
    let images: Vec<_> = chars
        .iter()
        .map(|&(c, id)| {
            let image = renderer
                .render(&mut scaler, id)
                .filter(|i| i.placement.width > 0 && i.placement.height > 0);
            (c, glyph_metrics.advance_width(id).round() as i32, image)
        })
        .collect();

    // The font's own line metrics make room for Japanese, about 1.45 em.
    // The line box here fits ASCII instead, and lines are 1.2 em apart:
    // 24 px for 20 px text, as in the mockup.
    let ascii = || {
        images
            .iter()
            .filter(|(c, ..)| c.is_ascii_graphic())
            .filter_map(|(_, _, i)| i.as_ref())
    };
    let ascent = ascii().map(|i| i.placement.top).max().unwrap_or(0);
    let descent = -ascii()
        .map(|i| i.placement.height as i32 - i.placement.top)
        .max()
        .unwrap_or(0);
    let line_gap = ((f32::from(size) * 1.2).round() as i32 - (ascent - descent)).max(0);
    let cap = images
        .iter()
        .find(|(c, ..)| *c == 'H')
        .and_then(|(_, _, i)| i.as_ref())
        .map_or(ascent, |i| i.placement.top);
    assert!(
        images.last().is_none_or(|(c, ..)| *c < REPLACEMENT),
        "the replacement character goes last"
    );

    let mut glyphs = Vec::new();
    let mut characters = Vec::new();
    for (c, advance, image) in images {
        glyphs.push(match image {
            Some(image) => {
                let p = image.placement;
                Glyph {
                    advance,
                    left: p.left,
                    top: ascent - p.top,
                    width: p.width,
                    height: p.height,
                    // Round 8-bit alpha to 4 bits.
                    pixels: image
                        .data
                        .iter()
                        .map(|&a| ((u16::from(a) * 15 + 127) / 255) as u8)
                        .collect(),
                }
            }
            None => Glyph {
                advance,
                left: 0,
                top: 0,
                width: 0,
                height: 0,
                pixels: Vec::new(),
            },
        });
        characters.push(c);
    }
    let (side, rise, coverage) = replacement(context, font, spec, size, cap, ascent, descent);
    let left = (f32::from(size) * 0.06).round() as i32;
    glyphs.push(Glyph {
        advance: side as i32 + 2 * left,
        left,
        top: ascent - rise,
        width: side,
        height: side,
        pixels: coverage,
    });
    characters.push(REPLACEMENT);
    Raster {
        id: format!("{}_{}", spec.name, size),
        family: spec.name,
        size,
        ascent,
        descent,
        line_gap,
        glyphs,
        characters,
    }
}

/// Writes `raster`'s glyph table and coded coverage, returning the `Face`.
fn emit(out: &mut String, raster: &Raster, code: &Code) -> String {
    let mut bits = Bits::default();
    let entries: Vec<String> = raster
        .glyphs
        .iter()
        .map(|g| {
            let start = bits.len;
            code.encode(&mut bits, g);
            glyph_entry(g.advance, g.left, g.top, g.width, g.height, start)
        })
        .collect();
    let Raster {
        id,
        family,
        size,
        ascent,
        descent,
        line_gap,
        ..
    } = raster;
    writeln!(
        out,
        "static {id}_GLYPHS: [GlyphEntry; {}] = [{}];",
        entries.len(),
        entries.join(", ")
    )
    .unwrap();
    writeln!(
        out,
        "static {id}_COVERAGE: [u8; {}] = {:?};",
        bits.bytes.len(),
        bits.bytes
    )
    .unwrap();
    format!(
        "Face {{ size: {size}, ascent: {ascent}, descent: {descent}, line_gap: {line_gap}, \
         runs: &{family}_RUNS, glyphs: &{id}_GLYPHS, coverage: &{id}_COVERAGE, codes: &CODES, \
         fallback: Some({}) }}",
        entries.last().expect("the replacement glyph")
    )
}

// ─── Coverage coding ────────────────────────────────────────────────────────
//
// As `buoyant::font::prerendered::coding` reads it: a prefix code for each
// pixel's context, its left and upper neighbors' bands, no code longer than
// PEEK bits. fonts.rs checks these constants against Buoyant's at compile
// time.

const EDGE: u8 = 16;
const LEVELS: usize = 6;
const PEEK: usize = 6;
const CONTEXTS: usize = LEVELS * LEVELS;

const fn band(level: u8) -> usize {
    match level {
        0 => 0,
        1..=4 => 1,
        5..=10 => 2,
        11..=14 => 3,
        15 => 4,
        _ => 5,
    }
}

/// Each pixel of `glyph` with its context, row by row.
fn contexts(glyph: &Glyph) -> impl Iterator<Item = (usize, u8)> + '_ {
    let width = glyph.width as usize;
    glyph.pixels.iter().enumerate().map(move |(i, &level)| {
        let left = if i % width == 0 {
            EDGE
        } else {
            glyph.pixels[i - 1]
        };
        let above = if i < width {
            EDGE
        } else {
            glyph.pixels[i - width]
        };
        (band(left) * LEVELS + band(above), level)
    })
}

#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    len: usize,
}

impl Bits {
    /// Appends the low `len` bits of `code`, the most significant first.
    fn push(&mut self, code: u32, len: u8) {
        for i in (0..len).rev() {
            if self.len.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if code >> i & 1 != 0 {
                *self.bytes.last_mut().unwrap() |= 0x80 >> (self.len % 8);
            }
            self.len += 1;
        }
    }
}

/// A prefix code for each context: each level's code and its length.
struct Code {
    codes: Vec<[(u32, u8); 16]>,
}

impl Code {
    /// The code that makes `glyphs` shortest, no code over PEEK bits.
    fn train<'a>(glyphs: impl Iterator<Item = &'a Glyph>) -> Self {
        let mut counts = vec![[0u64; 16]; CONTEXTS];
        for glyph in glyphs {
            for (context, level) in contexts(glyph) {
                counts[context][usize::from(level)] += 1;
            }
        }
        let codes = counts
            .iter()
            .map(|counts| canonical(&limited_lengths(counts, PEEK)))
            .collect();
        Self { codes }
    }

    fn encode(&self, bits: &mut Bits, glyph: &Glyph) {
        for (context, level) in contexts(glyph) {
            let (code, len) = self.codes[context][usize::from(level)];
            assert!(len > 0, "a level the code was trained on");
            bits.push(code, len);
        }
    }

    /// Buoyant's decoding table: for each context, every PEEK-bit window,
    /// as the level its code begins and the code's length.
    fn table(&self) -> Vec<u8> {
        let mut table = vec![0u8; CONTEXTS << PEEK];
        for (context, codes) in self.codes.iter().enumerate() {
            for (level, &(code, len)) in codes.iter().enumerate() {
                if len == 0 {
                    continue;
                }
                let first = (code as usize) << (PEEK - usize::from(len));
                for window in first..first + (1 << (PEEK - usize::from(len))) {
                    table[context << PEEK | window] = level as u8 | len << 4;
                }
            }
        }
        table
    }
}

/// Code lengths for symbols seen `counts` times, none over `limit`
/// (package-merge). A symbol never seen gets none.
fn limited_lengths(counts: &[u64; 16], limit: usize) -> [u8; 16] {
    let mut lengths = [0u8; 16];
    let seen: Vec<usize> = (0..16).filter(|&s| counts[s] > 0).collect();
    match seen.len() {
        0 => return lengths,
        1 => {
            lengths[seen[0]] = 1;
            return lengths;
        }
        _ => {}
    }
    let mut leaves: Vec<(u64, Vec<usize>)> = seen.iter().map(|&s| (counts[s], vec![s])).collect();
    leaves.sort();
    let mut packages = leaves.clone();
    for _ in 1..limit {
        let mut merged: Vec<(u64, Vec<usize>)> = packages
            .chunks_exact(2)
            .map(|pair| {
                let mut symbols = pair[0].1.clone();
                symbols.extend(&pair[1].1);
                (pair[0].0 + pair[1].0, symbols)
            })
            .collect();
        merged.extend(leaves.iter().cloned());
        merged.sort();
        packages = merged;
    }
    for (_, symbols) in &packages[..2 * seen.len() - 2] {
        for &s in symbols {
            lengths[s] += 1;
        }
    }
    lengths
}

/// Canonical codes for `lengths`: shorter codes first, then lower levels.
fn canonical(lengths: &[u8; 16]) -> [(u32, u8); 16] {
    let mut order: Vec<usize> = (0..16).filter(|&s| lengths[s] > 0).collect();
    order.sort_by_key(|&s| (lengths[s], s));
    let mut codes = [(0, 0); 16];
    let (mut code, mut len) = (0u32, 0u8);
    for s in order {
        code <<= lengths[s] - len;
        len = lengths[s];
        codes[s] = (code, len);
        code += 1;
    }
    assert!(
        len == 0 || u64::from(code) <= 1 << len,
        "a prefix code fits its lengths"
    );
    codes
}

/// A glyph's table entry. Every field is a byte, and the start three.
fn glyph_entry(
    advance: impl TryInto<u8> + Copy + std::fmt::Display,
    left: impl TryInto<i8> + Copy + std::fmt::Display,
    top: impl TryInto<i8> + Copy + std::fmt::Display,
    width: impl TryInto<u8> + Copy + std::fmt::Display,
    height: impl TryInto<u8> + Copy + std::fmt::Display,
    start: usize,
) -> String {
    fn byte<T: TryInto<B> + Copy + std::fmt::Display, B>(value: T, what: &str) -> B {
        value
            .try_into()
            .unwrap_or_else(|_| panic!("a glyph's {what} of {value} does not fit a byte"))
    }
    let (advance, left, top) = (
        byte::<_, u8>(advance, "advance"),
        byte::<_, i8>(left, "left"),
        byte::<_, i8>(top, "top"),
    );
    let (width, height) = (
        byte::<_, u8>(width, "width"),
        byte::<_, u8>(height, "height"),
    );
    let start = u32::try_from(start)
        .ok()
        .filter(|&s| s < 1 << 24)
        .expect("a face's coverage within 2^24 bits")
        .to_le_bytes();
    format!(
        "GlyphEntry {{ advance: {advance}, left: {left}, top: {top}, width: {width}, \
         height: {height}, start: [{}, {}, {}] }}",
        start[0], start[1], start[2]
    )
}

/// `characters`, sorted, as runs of consecutive code points.
fn runs(characters: &[char]) -> String {
    let mut runs: Vec<(char, u16, u16)> = Vec::new();
    for (index, &c) in characters.iter().enumerate() {
        match runs.last_mut() {
            Some((first, len, _)) if u32::from(*first) + u32::from(*len) == u32::from(c) => {
                *len += 1;
            }
            _ => {
                assert!(
                    runs.last().is_none_or(
                        |&(first, len, _)| u32::from(first) + u32::from(len) < u32::from(c)
                    ),
                    "characters in order"
                );
                runs.push((c, 1, u16::try_from(index).unwrap()));
            }
        }
    }
    runs.iter()
        .map(|(first, len, index)| {
            format!("CharRun {{ first: {first:?}, len: {len}, index: {index} }}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}
