//! The status strip's indicators as one view: a row of icons, each in its
//! own color, that is exactly as wide as the icons it holds.
//!
//! One leaf rather than a stack of optional images. A stack lays each child
//! out several times to learn how flexible it is, and every child it could
//! hold is part of its type and its render tree whether it is shown or not.
//! These have nothing to flex, so the row is measured once, and an
//! indicator added later is an entry in the list rather than a slot in the
//! tree.

use buoyant::event::{Event, EventContext, EventResult, TouchResult};
use buoyant::focus::{Seek, SeekResult};
use buoyant::layout::ResolvedLayout;
use buoyant::primitives::geometry::Rectangle;
use buoyant::primitives::{Interpolate as _, Point, ProposedDimensions, Size};
use buoyant::render::{
    AnimatedJoin, AnimationDomain, ContentShape, IntrinsicShape, Rect, Render, RoundedRect,
    StrokedShape,
};
use buoyant::render_target::RenderTarget;
use buoyant::transition::Opacity;
use buoyant::view::{ViewLayout, ViewMarker};
use embedded_graphics::image::ImageRaw;
use embedded_graphics::pixelcolor::{Gray4, Rgb565};
use embedded_graphics::prelude::OriginDimensions as _;
use embedded_touch::Touch;
use heapless::Vec;

use crate::icon::Ink;
use crate::theme;

/// An icon mask, drawn in the indicator's color.
pub type Mask = ImageRaw<'static, Gray4>;

/// Between neighboring indicators' ink: icons are packed by what they
/// draw, not by their square masks, so each is as wide as its state's
/// drawing.
const SPACING: u32 = 3;

/// The most the strip shows at once: both keyboard modifiers, the bell,
/// Wi-Fi, Bluetooth, the companion mark, GNSS, the bolt, and the battery.
const CAPACITY: usize = 9;

/// One indicator.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Indicator {
    Icon(&'static Mask, Ink, Rgb565),
    /// Filled to its charge, in percent; amber while the charge is `low`.
    Battery {
        percent: u8,
        low: bool,
    },
}

impl Indicator {
    /// The space it takes in the row: its ink's width, and its mask's
    /// height, so that icons stay centered as they were drawn.
    fn size(&self) -> Size {
        match self {
            Self::Icon(mask, ink, _) => Size::new(ink.width, mask.size().height),
            Self::Battery { .. } => Size::new(BATTERY_WIDTH + 3, BATTERY_HEIGHT),
        }
    }
}

/// The row, in the order it is drawn, left to right.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Indicators(Vec<Indicator, CAPACITY>);

impl Indicators {
    /// Adds `indicator` at the right of the row.
    pub fn push(&mut self, indicator: Indicator) {
        // The capacity is every indicator there is.
        let _ = self.0.push(indicator);
    }

    pub fn icon(&mut self, (mask, ink): (&'static Mask, Ink), color: Rgb565) {
        self.push(Indicator::Icon(mask, ink, color));
    }

    /// How wide the row is.
    pub fn width(&self) -> u32 {
        self.size().width
    }

    fn size(&self) -> Size {
        let width = self.0.iter().map(|i| i.size().width).sum::<u32>()
            + SPACING * (self.0.len() as u32).saturating_sub(1);
        let height = self.0.iter().map(|i| i.size().height).max().unwrap_or(0);
        Size::new(width, height)
    }
}

impl ViewMarker for Indicators {
    type Renderables = Row;
    type Transition = Opacity;
}

impl<Captures: ?Sized> ViewLayout<Captures> for Indicators {
    type Sublayout = ();
    type State = ();
    type FocusTree = ();

    fn transition(&self) -> Self::Transition {
        Opacity
    }

    fn build_state(&self, _captures: &mut Captures) -> Self::State {}

    fn layout(
        &self,
        _offer: &ProposedDimensions,
        _env: &impl buoyant::environment::LayoutEnvironment,
        _captures: &mut Captures,
        _state: &mut Self::State,
    ) -> ResolvedLayout<Self::Sublayout> {
        ResolvedLayout {
            resolved_size: self.size().into(),
            sublayouts: (),
        }
    }

    fn render_tree(
        &self,
        _layout: &Self::Sublayout,
        origin: Point,
        _env: &impl buoyant::environment::LayoutEnvironment,
        _captures: &mut Captures,
        _state: &mut Self::State,
    ) -> Self::Renderables {
        Row {
            origin,
            indicators: self.clone(),
        }
    }

    fn handle_event(
        &self,
        _event: &Event,
        _context: &EventContext,
        _render_tree: &mut Self::Renderables,
        _captures: &mut Captures,
        _state: &mut Self::State,
        _focus: &mut Self::FocusTree,
    ) -> EventResult {
        EventResult::default()
    }

    fn seek(
        &self,
        _seek: &Seek,
        _render_tree: &Self::Renderables,
        _state: &Self::State,
        _focus: Option<&Self::FocusTree>,
    ) -> SeekResult<Self::FocusTree> {
        SeekResult::Absent
    }

    fn handle_touch(
        &self,
        _touch: &Touch,
        _context: &EventContext,
        _render_tree: &mut Self::Renderables,
        _captures: &mut Captures,
        _state: &mut Self::State,
    ) -> TouchResult<Self::FocusTree> {
        TouchResult::Deferred
    }
}

/// The row as laid out: where it starts, and what it holds.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    origin: Point,
    indicators: Indicators,
}

impl Row {
    fn draw(&self, target: &mut impl RenderTarget<ColorFormat = Rgb565>, origin: Point) {
        let height = self.indicators.size().height;
        let mut x = origin.x;
        for indicator in &self.indicators.0 {
            let size = indicator.size();
            // Each centered on the row, as a stack would place it.
            let at = Point::new(x, origin.y + (height - size.height) as i32 / 2);
            match *indicator {
                Indicator::Icon(mask, ink, color) => {
                    // The mask's blank columns fall over its neighbors'
                    // space, where a template draws nothing.
                    let at = Point::new(at.x - ink.left as i32, at.y);
                    buoyant::render::Image::<_, buoyant::render::image::Template>::new(at, mask)
                        .render(target, &color);
                }
                Indicator::Battery { percent, low } => battery(target, at, percent, low),
            }
            x += (size.width + SPACING) as i32;
        }
    }
}

impl AnimatedJoin for Row {
    fn join_from(&mut self, source: &Self, domain: &AnimationDomain) {
        // The icons jump; only the row's place moves.
        self.origin = Point::interpolate(source.origin, self.origin, domain.factor);
    }
}

impl IntrinsicShape for Row {
    fn content_shape(&self) -> ContentShape {
        Rectangle::new(self.origin, self.indicators.size()).into()
    }
}

impl Render<Rgb565> for Row {
    fn render(&self, target: &mut impl RenderTarget<ColorFormat = Rgb565>, _style: &Rgb565) {
        self.draw(target, self.origin);
    }

    fn render_animated(
        target: &mut impl RenderTarget<ColorFormat = Rgb565>,
        source: &Self,
        to: &Self,
        _style: &Rgb565,
        domain: &AnimationDomain,
    ) {
        to.draw(
            target,
            Point::interpolate(source.origin, to.origin, domain.factor),
        );
    }
}

/// A battery outline filled to `percent`, and its terminal, amber while
/// the charge is `low`. The fill keeps [`FILL_GAP`] from the outline's
/// inside on every side; the terminal stands level with it.
fn battery(
    target: &mut impl RenderTarget<ColorFormat = Rgb565>,
    at: Point,
    percent: u8,
    low: bool,
) {
    let outline = if low {
        theme::AMBER
    } else {
        theme::TEXT_SECONDARY
    };
    StrokedShape::new(
        RoundedRect::new(at, Size::new(BATTERY_WIDTH, BATTERY_HEIGHT), 3),
        1,
    )
    .render(target, &outline);
    let inside = Point::new(at.x + (1 + FILL_GAP) as i32, at.y + (1 + FILL_GAP) as i32);
    let width = fill(percent, FILL_WIDTH);
    if width > 0 {
        Rect::new(inside, Size::new(width, FILL_HEIGHT)).render(target, &theme::TEXT);
    }
    Rect::new(
        Point::new(at.x + BATTERY_WIDTH as i32 + 1, inside.y),
        Size::new(2, FILL_HEIGHT),
    )
    .render(target, &outline);
}

/// How many of `width` columns a charge of `percent` fills, to the
/// nearest.
const fn fill(percent: u8, width: u32) -> u32 {
    let percent = if percent > 100 { 100 } else { percent as u32 };
    (width * percent + 50) / 100
}

/// The battery's outline, its stroke included.
const BATTERY_WIDTH: u32 = 1 + FILL_GAP + FILL_WIDTH + FILL_GAP + 1;
const BATTERY_HEIGHT: u32 = 1 + FILL_GAP + FILL_HEIGHT + FILL_GAP + 1;
const FILL_WIDTH: u32 = 19;
const FILL_HEIGHT: u32 = 6;
/// Between the fill and the outline's inside.
const FILL_GAP: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fill_follows_the_charge() {
        assert_eq!(fill(0, FILL_WIDTH), 0);
        assert_eq!(fill(2, FILL_WIDTH), 0);
        assert_eq!(fill(3, FILL_WIDTH), 1);
        assert_eq!(fill(50, FILL_WIDTH), 10);
        assert_eq!(fill(100, FILL_WIDTH), FILL_WIDTH);
        assert_eq!(fill(255, FILL_WIDTH), FILL_WIDTH);
    }
}
