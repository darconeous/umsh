//! The front of the board around its screen: the keyboard, and the Pager's
//! wheel and lock button or the T-Deck's trackball, drawn with their hit
//! boxes, so that they can be clicked.
//!
//! The keys are laid out as the boards' are, row for row. Where on the
//! T-Deck its modifier keys sit has not been recorded from a unit
//! (`docs/hardware/lilygo-t-deck-hardware.md` §8.6), so its bottom row is
//! approximate.

use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::ascii::{FONT_6X10, FONT_7X13_BOLD, FONT_9X15_BOLD};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{
    Arc, Circle, Line, Polyline, PrimitiveStyle, Rectangle, RoundedRectangle, Triangle,
};
use embedded_graphics::text::{Alignment, Text};
use umsh_pager_peripherals::input::alt_legend;
use umsh_ux_communicator::board::Board;
use umsh_ux_communicator::input::{Arrow, Input};
use umsh_ux_communicator::keyboard::Modifier;

/// The space around the screen and the controls.
const MARGIN: i32 = 14;

/// What a part of the face does when clicked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// A key that types its letter, with what it types with the Pager's
    /// orange key or the T-Deck's Sym.
    Letter(char, Option<char>),
    Enter,
    Backspace,
    Space,
    /// The Pager's CAP and orange keys, which the interface latches.
    Modifier(Modifier),
    /// The T-Deck's Shift, Sym, and Alt, which its keyboard applies to the
    /// next key: clicked, each holds for one key.
    Chord(Chord),
    /// A T-Deck key that is not a letter: Mic, which types `0` under Sym,
    /// and `$`, which types nothing under Sym.
    Symbol {
        label: &'static str,
        plain: Option<char>,
        sym: Option<char>,
    },
    /// The Pager's wheel, turned a detent, or pressed.
    Turn(i8),
    WheelPress,
    /// The T-Deck's trackball, rolled, or pressed.
    Roll(Arrow),
    BallPress,
    /// The Pager's lock button.
    Lock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chord {
    Shift,
    Sym,
    Alt,
}

#[derive(Clone, Copy, Debug)]
pub struct Part {
    pub area: Rectangle,
    pub control: Control,
}

/// The board's front: its size, where the screen is on it, and the parts
/// around the screen.
pub struct Face {
    pub size: Size,
    pub screen: Rectangle,
    pub parts: Vec<Part>,
    tdeck: bool,
}

impl Face {
    pub fn of(board: &Board) -> Self {
        if board == &Board::TDECK {
            Self::tdeck(board)
        } else {
            Self::pager(board)
        }
    }

    /// The Pager: the wheel and the lock button beside the screen, and
    /// three rows of ten keys and the space bar under it.
    fn pager(board: &Board) -> Self {
        let panel = board.metrics.size();
        let screen = Rectangle::new(Point::new(MARGIN, MARGIN), panel);
        let mut parts = Vec::new();
        let side = MARGIN + panel.width as i32 + MARGIN;
        let column = |y, h| Rectangle::new(Point::new(side, y), Size::new(48, h));
        parts.push(Part {
            area: column(MARGIN + 6, 30),
            control: Control::Lock,
        });
        let wheel = MARGIN + panel.height as i32 / 2 - 24;
        parts.push(Part {
            area: column(wheel - 40, 36),
            control: Control::Turn(-1),
        });
        parts.push(Part {
            area: column(wheel, 48),
            control: Control::WheelPress,
        });
        parts.push(Part {
            area: column(wheel + 52, 36),
            control: Control::Turn(1),
        });
        let letter = |c| Control::Letter(c, alt_legend(c));
        let rows: [Vec<Control>; 3] = [
            "qwertyuiop".chars().map(letter).collect(),
            "asdfghjkl"
                .chars()
                .map(letter)
                .chain([Control::Enter])
                .collect(),
            [Control::Modifier(Modifier::Alt)]
                .into_iter()
                .chain("zxcvbnm".chars().map(letter))
                .chain([Control::Modifier(Modifier::Shift), Control::Backspace])
                .collect(),
        ];
        let grid = Grid {
            left: MARGIN + 2,
            top: MARGIN + panel.height as i32 + 12,
            key: Size::new(44, 36),
            gap: 4,
        };
        grid.rows(&rows, &mut parts);
        parts.push(Part {
            area: grid.span(3, 2, 6),
            control: Control::Space,
        });
        Self {
            size: Size::new(
                side as u32 + 48 + MARGIN as u32,
                grid.bottom(4) as u32 + MARGIN as u32,
            ),
            screen,
            parts,
            tdeck: false,
        }
    }

    /// The T-Deck: the trackball under the screen, and the keyboard under
    /// it, BlackBerry-style.
    fn tdeck(board: &Board) -> Self {
        let panel = board.metrics.size();
        let screen = Rectangle::new(Point::new(MARGIN, MARGIN), panel);
        let mut parts = Vec::new();
        let middle = MARGIN + panel.width as i32 / 2;
        let ball = MARGIN + panel.height as i32 + 40;
        let cell = |dx: i32, dy: i32, w: u32, h: u32| {
            Rectangle::with_center(Point::new(middle + dx, ball + dy), Size::new(w, h))
        };
        for (area, control) in [
            (cell(0, -27, 26, 20), Control::Roll(Arrow::Up)),
            (cell(-29, 0, 24, 26), Control::Roll(Arrow::Left)),
            (cell(0, 0, 30, 30), Control::BallPress),
            (cell(29, 0, 24, 26), Control::Roll(Arrow::Right)),
            (cell(0, 27, 26, 20), Control::Roll(Arrow::Down)),
        ] {
            parts.push(Part { area, control });
        }
        let letter = |c| Control::Letter(c, tdeck_sym(c));
        let rows: [Vec<Control>; 3] = [
            "qwertyuiop".chars().map(letter).collect(),
            "asdfghjkl"
                .chars()
                .map(letter)
                .chain([Control::Backspace])
                .collect(),
            [Control::Chord(Chord::Shift)]
                .into_iter()
                .chain("zxcvbnm".chars().map(letter))
                .chain([
                    Control::Symbol {
                        label: "$",
                        plain: Some('$'),
                        sym: None,
                    },
                    Control::Enter,
                ])
                .collect(),
        ];
        let grid = Grid {
            left: MARGIN + 2,
            top: ball + 50,
            key: Size::new(29, 32),
            gap: 3,
        };
        grid.rows(&rows, &mut parts);
        for (column, width, control) in [
            (0, 1, Control::Chord(Chord::Alt)),
            (
                1,
                1,
                Control::Symbol {
                    label: "mic",
                    plain: None,
                    sym: Some('0'),
                },
            ),
            (2, 5, Control::Space),
            (7, 1, Control::Chord(Chord::Sym)),
            (8, 2, Control::Chord(Chord::Shift)),
        ] {
            parts.push(Part {
                area: grid.span(3, column, width),
                control,
            });
        }
        Self {
            size: Size::new(
                panel.width + 2 * MARGIN as u32,
                grid.bottom(4) as u32 + MARGIN as u32,
            ),
            screen,
            parts,
            tdeck: true,
        }
    }

    /// The part at `point`, if any.
    pub fn hit(&self, point: Point) -> Option<usize> {
        self.parts.iter().position(|part| part.area.contains(point))
    }

    /// Draws the face, with the part `held` down and the T-Deck's chord
    /// keys in `keys` latched. The screen is left for the panel.
    pub fn draw<D>(&self, target: &mut D, held: Option<usize>, keys: &Keys)
    where
        D: DrawTarget<Color = Rgb565>,
    {
        let _ = target.clear(BODY);
        let _ = RoundedRectangle::with_equal_corners(self.screen.offset(3), Size::new(6, 6))
            .into_styled(PrimitiveStyle::with_fill(BEZEL))
            .draw(target);
        for (index, part) in self.parts.iter().enumerate() {
            let down = held == Some(index)
                || matches!(part.control, Control::Chord(chord) if keys.latched(chord));
            let _ = draw_part(target, part, down, self.tdeck);
        }
    }
}

/// Rows of keys of one size, on a grid.
struct Grid {
    left: i32,
    top: i32,
    key: Size,
    gap: i32,
}

impl Grid {
    fn rows(&self, rows: &[Vec<Control>], parts: &mut Vec<Part>) {
        for (row, controls) in rows.iter().enumerate() {
            for (column, &control) in controls.iter().enumerate() {
                parts.push(Part {
                    area: self.span(row, column, 1),
                    control,
                });
            }
        }
    }

    /// The key at `row` and `column`, `width` columns wide.
    fn span(&self, row: usize, column: usize, width: usize) -> Rectangle {
        let step = |size: u32, n: usize| n as i32 * (size as i32 + self.gap);
        let wide = step(self.key.width, width) - self.gap;
        Rectangle::new(
            Point::new(
                self.left + step(self.key.width, column),
                self.top + step(self.key.height, row),
            ),
            Size::new(wide as u32, self.key.height),
        )
    }

    /// Where the keys end, after `rows` rows.
    fn bottom(&self, rows: usize) -> i32 {
        self.top + rows as i32 * (self.key.height as i32 + self.gap) - self.gap
    }
}

/// What a T-Deck letter key types under Sym, as its keyboard's firmware
/// has it (`docs/hardware/lilygo-t-deck-hardware.md` §8.6).
fn tdeck_sym(letter: char) -> Option<char> {
    const LETTERS: &str = "qwertyuiopasdfghjklzxcvbnm";
    const SYMBOLS: &str = "#123()_-+@*456/:;'\"789?!,.";
    let index = LETTERS.find(letter)?;
    SYMBOLS[index..].chars().next()
}

/// What the T-Deck's keyboard holds for its next key: the chord keys
/// clicked since the last key. The Pager's modifiers are the interface's
/// to latch, and pass through.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Keys {
    shift: bool,
    sym: bool,
    alt: bool,
}

impl Keys {
    fn latched(&self, chord: Chord) -> bool {
        match chord {
            Chord::Shift => self.shift,
            Chord::Sym => self.sym,
            Chord::Alt => self.alt,
        }
    }

    /// What `control` going down sends, on the T-Deck when `tdeck`.
    pub fn down(&mut self, control: Control, tdeck: bool) -> Vec<Input> {
        match control {
            Control::Letter(c, alt) if !tdeck => vec![Input::Key { plain: c, alt }],
            Control::Letter(c, sym) => {
                let keys = core::mem::take(self);
                if keys.sym {
                    sym.map(Input::Character).into_iter().collect()
                } else if keys.alt && c == 'c' {
                    // The picker's chord, as the board makes of Alt+C.
                    let alt = |down| Input::Modifier {
                        modifier: Modifier::Alt,
                        down,
                    };
                    vec![alt(true), Input::Space, alt(false)]
                } else if keys.alt && c == 'b' {
                    // The keyboard's light, which the keyboard keeps.
                    vec![]
                } else if keys.shift {
                    vec![Input::Character(c.to_ascii_uppercase())]
                } else {
                    vec![Input::Character(c)]
                }
            }
            Control::Symbol { plain, sym, .. } => {
                let keys = core::mem::take(self);
                if keys.sym { sym } else { plain }
                    .map(Input::Character)
                    .into_iter()
                    .collect()
            }
            Control::Chord(chord) => {
                let latch = match chord {
                    Chord::Shift => &mut self.shift,
                    Chord::Sym => &mut self.sym,
                    Chord::Alt => &mut self.alt,
                };
                *latch = !*latch;
                vec![]
            }
            Control::Enter | Control::Backspace | Control::Space => {
                *self = Self::default();
                vec![match control {
                    Control::Enter => Input::Enter,
                    Control::Backspace => Input::Backspace,
                    _ => Input::Space,
                }]
            }
            Control::Modifier(modifier) => vec![Input::Modifier {
                modifier,
                down: true,
            }],
            Control::Turn(detents) => vec![Input::Turn(detents)],
            Control::Roll(arrow) => vec![Input::Move(arrow)],
            Control::WheelPress | Control::BallPress => vec![Input::Press],
            Control::Lock => vec![],
        }
    }

    /// What `control` coming back up sends.
    pub fn up(control: Control) -> Vec<Input> {
        match control {
            Control::Modifier(modifier) => vec![Input::Modifier {
                modifier,
                down: false,
            }],
            Control::WheelPress | Control::BallPress => vec![Input::Release],
            _ => vec![],
        }
    }
}

// ─── Drawing ──────────────────────────────────────────────────────────

/// `#rrggbb` as the panel's color, in a const.
const fn color(r: u8, g: u8, b: u8) -> Rgb565 {
    Rgb565::new(r >> 3, g >> 2, b >> 3)
}

const BODY: Rgb565 = color(0x26, 0x27, 0x2b);
const BEZEL: Rgb565 = color(0x0c, 0x0c, 0x0e);
const CAP: Rgb565 = color(0x3c, 0x3e, 0x44);
const CAP_DOWN: Rgb565 = color(0x86, 0x89, 0x92);
const LEGEND: Rgb565 = color(0xec, 0xec, 0xee);
const SECOND: Rgb565 = color(0x9c, 0x9f, 0xa8);
const ORANGE: Rgb565 = color(0xf2, 0x8c, 0x28);

fn draw_part<D>(target: &mut D, part: &Part, down: bool, tdeck: bool) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let area = part.area;
    let center = area.center();
    let orange = part.control == Control::Modifier(Modifier::Alt);
    let fill = match (down, orange) {
        (true, _) => CAP_DOWN,
        (false, true) => ORANGE,
        (false, false) => CAP,
    };
    let round = matches!(part.control, Control::WheelPress | Control::BallPress);
    if round {
        Circle::with_center(center, area.size.width.min(area.size.height))
            .into_styled(PrimitiveStyle::with_fill(fill))
            .draw(target)?;
    } else {
        RoundedRectangle::with_equal_corners(area, Size::new(5, 5))
            .into_styled(PrimitiveStyle::with_fill(fill))
            .draw(target)?;
    }
    let ink = PrimitiveStyle::with_stroke(LEGEND, 2);
    let solid = PrimitiveStyle::with_fill(LEGEND);
    let label = |text: &str, target: &mut D| {
        Text::with_alignment(
            text,
            center + Point::new(0, 4),
            MonoTextStyle::new(&FONT_7X13_BOLD, LEGEND),
            Alignment::Center,
        )
        .draw(target)
        .map(|_| ())
    };
    match part.control {
        Control::Letter(c, second) => {
            let mut buffer = [0; 4];
            let upper = c.to_ascii_uppercase().encode_utf8(&mut buffer);
            Text::with_alignment(
                upper,
                center + Point::new(if second.is_some() { -3 } else { 0 }, 6),
                MonoTextStyle::new(&FONT_9X15_BOLD, LEGEND),
                Alignment::Center,
            )
            .draw(target)?;
            if let Some(second) = second {
                let mut buffer = [0; 4];
                let text = second.encode_utf8(&mut buffer);
                let legend = if tdeck { SECOND } else { ORANGE };
                Text::with_alignment(
                    text,
                    area.top_left + Point::new(area.size.width as i32 - 4, 10),
                    MonoTextStyle::new(&FONT_6X10, legend),
                    Alignment::Right,
                )
                .draw(target)?;
            }
        }
        Control::Symbol {
            label: text, sym, ..
        } => {
            label(text, target)?;
            if let Some(sym) = sym {
                let mut buffer = [0; 4];
                Text::with_alignment(
                    sym.encode_utf8(&mut buffer),
                    area.top_left + Point::new(area.size.width as i32 - 4, 10),
                    MonoTextStyle::new(&FONT_6X10, SECOND),
                    Alignment::Right,
                )
                .draw(target)?;
            }
        }
        Control::Enter => {
            // ↵
            let (x, y) = (center.x, center.y);
            Polyline::new(&[
                Point::new(x + 7, y - 6),
                Point::new(x + 7, y + 2),
                Point::new(x - 4, y + 2),
            ])
            .into_styled(ink)
            .draw(target)?;
            Triangle::new(
                Point::new(x - 9, y + 2),
                Point::new(x - 3, y - 3),
                Point::new(x - 3, y + 7),
            )
            .into_styled(solid)
            .draw(target)?;
        }
        Control::Backspace => {
            // ⌫
            let (x, y) = (center.x, center.y);
            Polyline::new(&[
                Point::new(x - 4, y - 6),
                Point::new(x + 9, y - 6),
                Point::new(x + 9, y + 6),
                Point::new(x - 4, y + 6),
                Point::new(x - 10, y),
                Point::new(x - 4, y - 6),
            ])
            .into_styled(PrimitiveStyle::with_stroke(LEGEND, 1))
            .draw(target)?;
            for (a, b) in [((-1, -3), (5, 3)), ((-1, 3), (5, -3))] {
                Line::new(Point::new(x + a.0, y + a.1), Point::new(x + b.0, y + b.1))
                    .into_styled(PrimitiveStyle::with_stroke(LEGEND, 1))
                    .draw(target)?;
            }
        }
        Control::Space => {
            Line::new(center + Point::new(-14, 5), center + Point::new(14, 5))
                .into_styled(ink)
                .draw(target)?;
        }
        Control::Modifier(Modifier::Shift) => label("CAP", target)?,
        Control::Modifier(Modifier::Alt) => {}
        Control::Chord(Chord::Shift) => {
            // ⇧
            let (x, y) = (center.x, center.y);
            Polyline::new(&[
                Point::new(x, y - 7),
                Point::new(x + 7, y),
                Point::new(x + 3, y),
                Point::new(x + 3, y + 6),
                Point::new(x - 3, y + 6),
                Point::new(x - 3, y),
                Point::new(x - 7, y),
                Point::new(x, y - 7),
            ])
            .into_styled(PrimitiveStyle::with_stroke(LEGEND, 1))
            .draw(target)?;
        }
        Control::Chord(Chord::Sym) => label("sym", target)?,
        Control::Chord(Chord::Alt) => label("alt", target)?,
        Control::Turn(detents) => arrow(
            target,
            center,
            if detents < 0 { Arrow::Up } else { Arrow::Down },
        )?,
        Control::Roll(direction) => arrow(target, center, direction)?,
        Control::WheelPress | Control::BallPress => {
            Circle::with_center(center, 10)
                .into_styled(PrimitiveStyle::with_stroke(SECOND, 2))
                .draw(target)?;
        }
        Control::Lock => {
            // A padlock.
            Arc::with_center(center + Point::new(0, -2), 11, 180.0.deg(), 180.0.deg())
                .into_styled(PrimitiveStyle::with_stroke(LEGEND, 2))
                .draw(target)?;
            Rectangle::with_center(center + Point::new(0, 4), Size::new(14, 10))
                .into_styled(solid)
                .draw(target)?;
        }
    }
    Ok(())
}

/// A small solid arrow at `center`, pointing `direction`.
fn arrow<D>(target: &mut D, center: Point, direction: Arrow) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let (tip, a, b) = match direction {
        Arrow::Up => ((0, -5), (-6, 4), (6, 4)),
        Arrow::Down => ((0, 5), (-6, -4), (6, -4)),
        Arrow::Left => ((-5, 0), (4, -6), (4, 6)),
        Arrow::Right => ((5, 0), (-4, -6), (-4, 6)),
    };
    let at = |(x, y): (i32, i32)| center + Point::new(x, y);
    Triangle::new(at(tip), at(a), at(b))
        .into_styled(PrimitiveStyle::with_fill(LEGEND))
        .draw(target)
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn faces() -> [Face; 2] {
        [Face::of(&Board::PAGER), Face::of(&Board::TDECK)]
    }

    #[test]
    fn every_part_is_on_the_face_apart_from_the_screen_and_the_others() {
        for face in faces() {
            let whole = Rectangle::new(Point::zero(), face.size);
            for (i, part) in face.parts.iter().enumerate() {
                assert!(whole.contains(part.area.top_left), "{part:?}");
                assert!(
                    whole.contains(part.area.bottom_right().unwrap()),
                    "{part:?}"
                );
                assert!(
                    face.screen.intersection(&part.area).is_zero_sized(),
                    "{part:?}"
                );
                for other in &face.parts[i + 1..] {
                    assert!(
                        part.area.intersection(&other.area).is_zero_sized(),
                        "{part:?} {other:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_pager_has_every_key_of_its_matrix() {
        let face = Face::of(&Board::PAGER);
        let letters = face
            .parts
            .iter()
            .filter(|p| matches!(p.control, Control::Letter(..)))
            .count();
        assert_eq!(letters, 26);
        for control in [
            Control::Enter,
            Control::Backspace,
            Control::Space,
            Control::Modifier(Modifier::Shift),
            Control::Modifier(Modifier::Alt),
            Control::Lock,
        ] {
            assert!(
                face.parts.iter().any(|p| p.control == control),
                "{control:?}"
            );
        }
    }

    #[test]
    fn the_t_deck_has_its_thirty_five_keys() {
        let face = Face::of(&Board::TDECK);
        let keys = face
            .parts
            .iter()
            .filter(|p| !matches!(p.control, Control::Roll(_) | Control::BallPress))
            .count();
        assert_eq!(keys, 35);
    }

    #[test]
    fn a_t_deck_chord_key_holds_for_the_next_key() {
        let w = Control::Letter('w', tdeck_sym('w'));
        let mut keys = Keys::default();
        assert_eq!(keys.down(w, true), [Input::Character('w')]);
        keys.down(Control::Chord(Chord::Sym), true);
        assert_eq!(keys.down(w, true), [Input::Character('1')]);
        assert_eq!(keys.down(w, true), [Input::Character('w')]);
        keys.down(Control::Chord(Chord::Shift), true);
        assert_eq!(keys.down(w, true), [Input::Character('W')]);
        // Clicked again, it lets go.
        keys.down(Control::Chord(Chord::Shift), true);
        keys.down(Control::Chord(Chord::Shift), true);
        assert_eq!(keys.down(w, true), [Input::Character('w')]);
        // Alt+C is the picker's chord.
        keys.down(Control::Chord(Chord::Alt), true);
        let c = Control::Letter('c', tdeck_sym('c'));
        assert_eq!(keys.down(c, true).len(), 3);
        assert_eq!(tdeck_sym('m'), Some('.'));
        assert_eq!(tdeck_sym('l'), Some('"'));
    }

    #[test]
    fn a_pager_key_carries_its_orange_legend() {
        let mut keys = Keys::default();
        let q = Control::Letter('q', alt_legend('q'));
        assert_eq!(
            keys.down(q, false),
            [Input::Key {
                plain: 'q',
                alt: Some('1')
            }]
        );
    }

    /// Writes each face to `$FACE_PNG_DIR`, when it is set, to look at.
    #[test]
    fn faces_draw() {
        use embedded_graphics_simulator::{OutputSettings, SimulatorDisplay};
        for (face, name) in faces().into_iter().zip(["pager", "tdeck"]) {
            let mut display: SimulatorDisplay<Rgb565> = SimulatorDisplay::new(face.size);
            let keys = Keys {
                sym: true,
                ..Keys::default()
            };
            face.draw(&mut display, Some(0), &keys);
            if let Some(dir) = std::env::var_os("FACE_PNG_DIR") {
                let path = std::path::Path::new(&dir).join(format!("{name}.png"));
                display
                    .to_rgb_output_image(&OutputSettings::default())
                    .save_png(path)
                    .unwrap();
            }
        }
    }
}
