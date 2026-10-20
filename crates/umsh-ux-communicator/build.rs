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
    sizes: &'static [u16],
    /// The characters rendered, when not every one the font maps.
    only: Option<&'static str>,
}

const SANS: &str = "fonts/MPLUS1[wght]-latin.ttf";
const MONO: &str = "fonts/MPLUSCodeLatin[wdth,wght]-latin.ttf";
const UI_SIZES: &[u16] = &[16, 17, 20];

const SPECS: &[Spec] = &[
    Spec {
        name: "REGULAR",
        file: SANS,
        weight: 400.0,
        sizes: UI_SIZES,
        only: None,
    },
    Spec {
        name: "MEDIUM",
        file: SANS,
        weight: 500.0,
        sizes: UI_SIZES,
        only: None,
    },
    Spec {
        name: "SEMIBOLD",
        file: SANS,
        weight: 600.0,
        sizes: UI_SIZES,
        only: None,
    },
    // The small and large sizes are for avatar lettering.
    Spec {
        name: "BOLD",
        file: SANS,
        weight: 700.0,
        sizes: &[10, 13, 16, 17, 20, 26],
        only: None,
    },
    Spec {
        name: "EXTRABOLD",
        file: SANS,
        weight: 800.0,
        sizes: UI_SIZES,
        only: None,
    },
    Spec {
        name: "MONO",
        file: MONO,
        weight: 400.0,
        sizes: &[16, 20],
        only: None,
    },
    Spec {
        name: "MONO_BOLD",
        file: MONO,
        weight: 700.0,
        sizes: &[10, 13, 16, 20],
        only: None,
    },
    // The lock screen's time: digits alone, large, beside the date and
    // unread chats, and larger in the middle when nothing else is shown.
    Spec {
        name: "CLOCK",
        file: SANS,
        weight: 700.0,
        sizes: &[46, 56, 72],
        only: Some("0123456789:"),
    },
];

/// Drawn for characters a face lacks. The fonts lack it too, so it is drawn
/// here: see [`replacement`].
const REPLACEMENT: char = '\u{FFFD}';

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let mut out = String::new();
    let mut context = ScaleContext::new();
    for spec in SPECS {
        println!("cargo:rerun-if-changed={}", spec.file);
        let data = std::fs::read(dir.join(spec.file)).expect("font file");
        let font = FontRef::from_index(&data, 0).expect("parsable font");
        let mut faces = Vec::new();
        for &size in spec.sizes {
            faces.push(face(&mut out, &mut context, font, spec, size));
        }
        writeln!(
            out,
            "pub static {}: PrerenderedFont = PrerenderedFont {{ faces: &[{}] }};",
            spec.name,
            faces.join(", ")
        )
        .unwrap();
    }
    println!("cargo:rerun-if-changed=build.rs");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out_dir.join("fonts.rs"), out).unwrap();
    std::fs::write(out_dir.join("shapes.rs"), shapes()).unwrap();
    std::fs::write(out_dir.join("icons.rs"), icons()).unwrap();
    std::fs::write(out_dir.join("reactions.rs"), reactions()).unwrap();
}

/// One painted part of a reaction glyph, in the mockup's units centered on
/// the glyph, turned by `degrees`.
struct Paint {
    path: String,
    stroke: Option<f32>,
    color: u32,
    degrees: f32,
}

const PINK: u32 = 0xFF8FC4;
const YELLOW: u32 = 0xFFC83D;
const SHADE: u32 = 0xB87A0E;
const INK: u32 = 0x4A2E08;
const TEAR: u32 = 0x5AB8FF;
const RED: u32 = 0xF0453A;
const WHITE: u32 = 0xFFFFFF;

/// A circle's path.
fn disc(cx: f32, cy: f32, r: f32) -> String {
    format!(
        "M{} {cy} A{r} {r} 0 1 0 {} {cy} A{r} {r} 0 1 0 {} {cy} Z",
        cx - r,
        cx + r,
        cx - r
    )
}

fn filled(path: impl Into<String>, color: u32, degrees: f32) -> Paint {
    Paint {
        path: path.into(),
        stroke: None,
        color,
        degrees,
    }
}

fn stroked(path: impl Into<String>, width: f32, color: u32, degrees: f32) -> Paint {
    Paint {
        path: path.into(),
        stroke: Some(width),
        color,
        degrees,
    }
}

/// The reaction glyphs, in `model::Reaction` order: the mockup's drawings of
/// 🩷 👍 👎 🤣 ‼️ ❓.
fn reaction_glyphs() -> [Vec<Paint>; 6] {
    let k = 1.35;
    let y = 0.5;
    let heart = format!(
        "M0 {} C{} {} {} {} {} {} C{} {} 0 {} 0 {} C0 {} {} {} {} {} C{} {} {} {} 0 {} Z",
        y + 5.5 * k,
        -8.0 * k,
        y + 0.5 * k,
        -6.5 * k,
        y - 6.0 * k,
        -3.2 * k,
        y - 6.0 * k,
        -1.4 * k,
        y - 6.0 * k,
        y - 4.6 * k,
        y - 3.4 * k,
        y - 4.6 * k,
        1.4 * k,
        y - 6.0 * k,
        3.2 * k,
        y - 6.0 * k,
        6.5 * k,
        y - 6.0 * k,
        8.0 * k,
        y + 0.5 * k,
        y + 5.5 * k,
    );
    let hand = "M-8 -0.3 L-4 -0.3 L-2 -6.3 Q-1 -9.3 1.5 -8.3 Q3 -7.3 2.5 -4.3 \
                L1.5 -0.8 L6 -0.8 Q8 -0.8 8 1.2 Q8 2.7 7 3.2 Q8.2 4 7.6 5.4 \
                Q8 6.6 7 7.4 Q7.6 8.6 6 9.2 L-5 9.2 Q-8 9.2 -8 6.7 Z";
    let creases = "M3 3.2 H7 M3 5.4 H7.4 M3 7.4 H6.8";
    let thumb = |degrees| {
        vec![
            filled(hand, YELLOW, degrees),
            stroked(hand, 0.9, SHADE, degrees),
            stroked(creases, 0.9, SHADE, degrees),
        ]
    };
    let tilt = -20.0;
    let laugh = vec![
        filled(disc(0.0, 0.0, 8.6), YELLOW, tilt),
        stroked(
            "M-6 -4.8 L-2.6 -3.2 L-6 -1.6 M6 -4.8 L2.6 -3.2 L6 -1.6",
            1.5,
            INK,
            tilt,
        ),
        filled("M-5.6 0.6 H5.6 Q5.6 7 0 7 Q-5.6 7 -5.6 0.6 Z", INK, tilt),
        filled("M-4.9 0.6 H4.9 L4.7 2.2 H-4.7 Z", WHITE, tilt),
        filled(
            "M-8.4 -2.4 Q-12.2 1.4 -10 3.2 Q-7.8 4 -8.4 -2.4 Z",
            TEAR,
            tilt,
        ),
        filled("M8.4 -2.4 Q12.2 1.4 10 3.2 Q7.8 4 8.4 -2.4 Z", TEAR, tilt),
    ];
    let mut bangs = Vec::new();
    for x in [-3.6f32, 3.6] {
        let bar = format!(
            "M{} -8.6 H{} L{} 3 H{} Z",
            x - 2.0,
            x + 2.0,
            x + 1.1,
            x - 1.1
        );
        bangs.push(filled(bar.clone(), RED, 0.0));
        bangs.push(stroked(bar, 1.0, RED, 0.0));
        bangs.push(filled(disc(x, 7.0, 1.9), RED, 0.0));
    }
    let question = vec![
        stroked(
            "M-4.6 -4.2 C-4.6 -10.2 5 -10.2 5 -4.6 C5 -1.2 0 -1.2 0 2.8",
            3.2,
            RED,
            0.0,
        ),
        filled(disc(0.0, 7.2, 2.0), RED, 0.0),
    ];
    [
        vec![filled(heart, PINK, 0.0)],
        thumb(0.0),
        thumb(180.0),
        laugh,
        bangs,
        question,
    ]
}

/// What a reaction glyph is drawn on, and at what size and scale: the
/// palette in the actions menu; the chips over a bubble: mine, someone
/// else's, and mine in an open channel; and the screen itself. The colors
/// are `theme::REACTION_PAD`, `theme::OUTBOUND`, `theme::CHIP_THEIRS`,
/// `theme::OUTBOUND_OPEN` and `theme::BACKGROUND`, in `icon::Pad` order;
/// each image is composited onto its own, since the panel is drawn without
/// reading it back.
const REACTION_PADS: &[(u32, u32, f32)] = &[
    (0x2A313B, 23, 1.0),
    (0x2A62C9, 19, 0.78),
    (0x323A45, 19, 0.78),
    (0x1E7B45, 19, 0.78),
    (0x0B0D10, 23, 1.0),
];

/// The reaction glyphs as RGB565 images, `REACTIONS[reaction][pad]`.
fn reactions() -> String {
    use swash::zeno::{Angle, Cap, Join, Mask, Stroke, Transform};
    let channels =
        |rgb: u32| [16, 8, 0].map(|shift| f32::from(((rgb >> shift) & 0xFF) as u8) / 255.0);
    let mut rows = Vec::new();
    for glyph in reaction_glyphs() {
        let mut pads = Vec::new();
        for &(background, size, k) in REACTION_PADS {
            let n = (size * size) as usize;
            let mut pixels = vec![channels(background); n];
            for paint in &glyph {
                let transform = Transform::rotation(Angle::from_degrees(paint.degrees))
                    .then(&Transform::scale(k, k))
                    .then_translate(size as f32 / 2.0, size as f32 / 2.0);
                let mut mask = Mask::new(paint.path.as_str());
                mask.size(size, size)
                    .transform(Some(transform))
                    .format(Format::Alpha);
                if let Some(width) = paint.stroke {
                    let mut style = Stroke::new(width);
                    style.cap(Cap::Round).join(Join::Round);
                    mask.style(style);
                }
                let (alpha, _) = mask.render();
                let color = channels(paint.color);
                for (pixel, &a) in pixels.iter_mut().zip(alpha.iter()) {
                    let a = f32::from(a) / 255.0;
                    for (c, &p) in pixel.iter_mut().zip(color.iter()) {
                        *c = *c * (1.0 - a) + p * a;
                    }
                }
            }
            let mut bytes = Vec::with_capacity(n * 2);
            for [r, g, b] in pixels {
                let r = (r * 31.0).round() as u16;
                let g = (g * 63.0).round() as u16;
                let b = (b * 31.0).round() as u16;
                bytes.extend(((r << 11) | (g << 5) | b).to_be_bytes());
            }
            pads.push(format!("ImageRaw::new(&{bytes:?}, {size})"));
        }
        rows.push(format!("[{}]", pads.join(", ")));
    }
    format!(
        "pub static REACTIONS: [[ImageRaw<'static, Rgb565>; {}]; {}] = [{}];\n",
        REACTION_PADS.len(),
        rows.len(),
        rows.join(", ")
    )
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
        &[
            stroke("M0 -6 L-7 5 L7 5 Z", 1.2),
            cut("M-2.6 -6 A2.6 2.6 0 1 0 2.6 -6 A2.6 2.6 0 1 0 -2.6 -6 Z"),
            cut("M-9.6 5 A2.6 2.6 0 1 0 -4.4 5 A2.6 2.6 0 1 0 -9.6 5 Z"),
            cut("M4.4 5 A2.6 2.6 0 1 0 9.6 5 A2.6 2.6 0 1 0 4.4 5 Z"),
            stroke(
                "M-2.6 -6 A2.6 2.6 0 1 0 2.6 -6 A2.6 2.6 0 1 0 -2.6 -6 Z",
                1.4,
            ),
            stroke("M-9.6 5 A2.6 2.6 0 1 0 -4.4 5 A2.6 2.6 0 1 0 -9.6 5 Z", 1.4),
            stroke("M4.4 5 A2.6 2.6 0 1 0 9.6 5 A2.6 2.6 0 1 0 4.4 5 Z", 1.4),
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
    // has turned far enough and open while a press unlocks; and the clock
    // in place of the time while the time is not known.
    (
        "PADLOCK",
        18,
        1.1,
        &[
            stroke(
                "M-3.5 -0.75 V-3.75 Q-3.5 -7.75 0 -7.75 Q3.5 -7.75 3.5 -3.75 V-0.75",
                1.4,
            ),
            fill(
                "M-4 -0.75 H4 Q5.5 -0.75 5.5 0.75 V6.25 Q5.5 7.75 4 7.75 H-4 \
                 Q-5.5 7.75 -5.5 6.25 V0.75 Q-5.5 -0.75 -4 -0.75 Z",
            ),
        ],
    ),
    (
        "PADLOCK_OPEN",
        18,
        1.1,
        &[
            stroke(
                "M-3.5 -0.75 V-4.75 Q-3.5 -8.75 0 -8.75 Q3.5 -8.75 3.5 -4.75 V-3.25",
                1.4,
            ),
            fill(
                "M-4 -0.75 H4 Q5.5 -0.75 5.5 0.75 V6.25 Q5.5 7.75 4 7.75 H-4 \
                 Q-5.5 7.75 -5.5 6.25 V0.75 Q-5.5 -0.75 -4 -0.75 Z",
            ),
        ],
    ),
    // Under the unlock bar: which way to turn.
    ("DOWN", 12, 1.0, &[stroke("M-4 -2 L0 2 L4 -2", 1.6)]),
    // Over and under a part of the date and time being changed.
    ("UP", 12, 1.0, &[stroke("M-4 2 L0 -2 L4 2", 1.6)]),
    (
        "CLOCK",
        40,
        2.4,
        &[
            stroke("M-7 0 A7 7 0 1 0 7 0 A7 7 0 1 0 -7 0 Z", 1.3),
            stroke("M0 -4 V0 L3 2", 1.3),
        ],
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
    }
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
                    s * 0.16,
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
            // The hexagon is wider than tall; every mask is centered in a
            // frame wide enough for it.
            let width = if name == "HEXAGON" {
                (2.0 * half_width).ceil() as u32
            } else {
                size
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
fn face(
    out: &mut String,
    context: &mut ScaleContext,
    font: FontRef,
    spec: &Spec,
    size: u16,
) -> String {
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

    let mut pixels: Vec<u8> = Vec::new();
    let mut entries = Vec::new();
    for (c, advance, image) in images {
        let start = pixels.len();
        let (left, top, width, height) = match image {
            Some(image) => {
                let p = image.placement;
                // Round 8-bit alpha to 4 bits.
                pixels.extend(
                    image
                        .data
                        .iter()
                        .map(|&a| ((u16::from(a) * 15 + 127) / 255) as u8),
                );
                (p.left, ascent - p.top, p.width, p.height)
            }
            None => (0, 0, 0, 0),
        };
        let entry = format!(
            "GlyphEntry {{ character: {c:?}, advance: {advance}, left: {left}, top: {top}, \
             width: {width}, height: {height}, start: {start} }}"
        );
        entries.push(entry);
    }
    let fallback = {
        let (side, rise, coverage) = replacement(context, font, spec, size, cap, ascent, descent);
        let start = pixels.len();
        pixels.extend(coverage);
        let left = (f32::from(size) * 0.06).round() as i32;
        let entry = format!(
            "GlyphEntry {{ character: {REPLACEMENT:?}, advance: {}, left: {left}, top: {}, \
             width: {side}, height: {side}, start: {start} }}",
            side as i32 + 2 * left,
            ascent - rise,
        );
        entries.push(entry.clone());
        entry
    };

    let id = format!("{}_{}", spec.name, size);
    let mut packed = Vec::with_capacity(pixels.len().div_ceil(2));
    for pair in pixels.chunks(2) {
        packed.push((pair[0] << 4) | pair.get(1).copied().unwrap_or(0));
    }
    writeln!(
        out,
        "static {id}_GLYPHS: [GlyphEntry; {}] = [{}];",
        entries.len(),
        entries.join(", ")
    )
    .unwrap();
    writeln!(
        out,
        "static {id}_COVERAGE: [u8; {}] = {packed:?};",
        packed.len()
    )
    .unwrap();
    format!(
        "Face {{ size: {size}, ascent: {ascent}, descent: {descent}, line_gap: {line_gap}, \
         glyphs: &{id}_GLYPHS, coverage: &{id}_COVERAGE, fallback: Some({fallback}) }}"
    )
}
