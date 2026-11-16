//! Gamma test: a gray square on a field of alternating black and lit rows.
//! Seen from far enough away that its rows blur, the field is half its
//! lit rows' light; turned until the square disappears into it, the
//! square is too. The first field's rows are white. Pressing lights the
//! next field's rows at the square's level, so each field is half the one
//! before: 50%, 25%, and so on down to 0.8% of white, the square naming
//! the panel's gamma at each.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;
use heapless::String;

use super::conversation::header;
use crate::model::State;
use crate::nav::keys;
use crate::qr::Owned;
use crate::{font, theme};

/// Fields, each half the one before.
const FIELDS: u8 = 7;
/// The gamma a field's square starts at.
const START: f32 = 2.2;
/// The brightest a square can be, in six-bit levels.
const TOP: u8 = 63;
/// Around the field, and between it and its caption.
const MARGIN: u32 = 6;

/// Which field is shown, its lit rows' level, and the square's.
///
/// Levels are six bits: green's level, red's and blue's the five-bit
/// level below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GammaTest {
    /// From 0, whose field is half of white.
    field: u8,
    /// The square matched on the field before; white on the first.
    rows: u8,
    level: u8,
}

impl GammaTest {
    /// The first field, its square at [`START`].
    #[must_use]
    pub fn new() -> Self {
        Self::on(0, TOP)
    }

    fn on(field: u8, rows: u8) -> Self {
        let level = libm::roundf(f32::from(TOP) * libm::powf(share(field), 1.0 / START));
        Self {
            field,
            rows,
            level: level as u8,
        }
    }

    /// The next field, its rows lit at the square's level and its square
    /// at [`START`]; after the last, the first again.
    #[must_use]
    pub fn next_field(self) -> Self {
        if self.field + 1 < FIELDS {
            Self::on(self.field + 1, self.level)
        } else {
            Self::new()
        }
    }

    /// The square `steps` levels lighter, or darker when negative.
    #[must_use]
    pub fn step(self, steps: i8) -> Self {
        let level = i16::from(self.level) + i16::from(steps);
        Self {
            level: level.clamp(1, i16::from(TOP) - 1) as u8,
            ..self
        }
    }

    fn color(self) -> Rgb565 {
        gray(self.level)
    }

    /// The gamma under which the square is the field's share of white.
    /// Red and blue, a step behind green half the time, count for what
    /// they add to the square's light.
    fn gamma(self) -> f32 {
        let five = self.level >> 1;
        let red = f32::from((five << 1) | (five >> 4)) / f32::from(TOP);
        let green = f32::from(self.level) / f32::from(TOP);
        let light = 0.2848 * red + 0.7152 * green;
        libm::logf(share(self.field)) / libm::logf(light)
    }

    /// The field's share of white and the square's gamma, as the caption
    /// reads.
    fn caption(self) -> String<16> {
        let mut text = String::new();
        let share = match self.field {
            0 => "50%",
            1 => "25%",
            2 => "12.5%",
            3 => "6.25%",
            4 => "3.1%",
            5 => "1.6%",
            _ => "0.8%",
        };
        _ = core::fmt::write(&mut text, format_args!("{share}  {:.2}", self.gamma()));
        text
    }
}

/// Field `field`'s share of white.
fn share(field: u8) -> f32 {
    libm::powf(0.5, f32::from(field) + 1.0)
}

/// Six-bit `level` as a gray.
fn gray(level: u8) -> Rgb565 {
    Rgb565::new(level >> 1, level, level >> 1)
}

impl Default for GammaTest {
    fn default() -> Self {
        Self::new()
    }
}

/// The field, its square, and what the square's level is in gamma.
pub fn view(state: &State, test: GammaTest) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let height = m.below_strip() - m.header - m.body - 3 * MARGIN;
    let chart = Chart {
        test,
        width: (m.width - 2 * MARGIN) as u16,
        height: height as u16,
    };
    VStack::new((
        header(m, "Gamma", None, None),
        Button::new(State::next_gamma_field, move |_| {
            VStack::new((
                Image::new(Owned(chart.clone())),
                super::line(test.caption(), &font::REGULAR, m.body, theme::TEXT),
            ))
            .with_spacing(MARGIN)
            .padding(Edges::All, MARGIN)
            .flex_infinite_width(HorizontalAlignment::Center)
            .content_shape(Rectangle)
        })
        .focus_key(keys::GAMMA_CHART),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
}

/// The field, with the square in its middle.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Chart {
    test: GammaTest,
    width: u16,
    height: u16,
}

impl OriginDimensions for Chart {
    fn size(&self) -> Size {
        Size::new(u32::from(self.width), u32::from(self.height))
    }
}

impl ImageDrawable for Chart {
    type Color = Rgb565;

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, target: &mut D) -> Result<(), D::Error> {
        let width = u32::from(self.width);
        let height = u32::from(self.height);
        target.fill_solid(&Rectangle::new(Point::zero(), self.size()), Rgb565::BLACK)?;
        let lit = gray(self.test.rows);
        for y in (0..height).step_by(2) {
            target.fill_solid(
                &Rectangle::new(Point::new(0, y as i32), Size::new(width, 1)),
                lit,
            )?;
        }
        let square = Size::new(width / 3, height / 2);
        let origin = Point::new(
            ((width - square.width) / 2) as i32,
            ((height - square.height) / 2) as i32,
        );
        target.fill_solid(&Rectangle::new(origin, square), self.test.color())
    }

    fn draw_sub_image<D: DrawTarget<Color = Rgb565>>(
        &self,
        target: &mut D,
        area: &Rectangle,
    ) -> Result<(), D::Error> {
        self.draw(
            &mut target
                .translated(-area.top_left)
                .clipped(&Rectangle::new(area.top_left, area.size)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{FIELDS, GammaTest, TOP};

    #[test]
    fn each_field_starts_near_two_point_two() {
        let mut test = GammaTest::new();
        for _ in 0..FIELDS {
            assert!(
                (test.gamma() - 2.2).abs() < 0.1,
                "{test:?}: {}",
                test.gamma()
            );
            test = test.next_field();
        }
        assert_eq!(test, GammaTest::new());
    }

    #[test]
    fn each_field_is_lit_by_the_square_matched_before() {
        let first = GammaTest::new();
        assert_eq!(first.rows, TOP);
        let matched = first.step(3);
        assert_eq!(matched.next_field().rows, matched.level);
    }

    #[test]
    fn lighter_squares_stand_for_steeper_gammas() {
        let test = GammaTest::new();
        assert!(test.step(1).gamma() > test.gamma());
        assert!(test.step(-1).gamma() < test.gamma());
    }

    #[test]
    fn a_square_stays_short_of_black_and_white() {
        assert_eq!(GammaTest::new().step(i8::MAX).level, 62);
        assert_eq!(GammaTest::new().step(i8::MIN).level, 1);
    }
}
