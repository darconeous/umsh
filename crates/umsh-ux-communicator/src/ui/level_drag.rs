//! A level's steps under a finger: a finger slid across them sets the
//! level under it as it goes, and a tap sets the one tapped.
//!
//! Laid over a row's steps, it draws nothing. It covers them and some reach
//! either side, the full height of the row, so a finger need not land on a
//! step to take them; whatever lies past them is clamped to the nearest.
//!
//! The level is set only once the finger has moved [`SLOP`] across, or
//! lifts: a touch that goes on to scroll the list it is in changes nothing.
//! A touch that changed the level is followed through when it ends, once:
//! the volume chimes then, not at every level a finger slides over.

use buoyant::environment::LayoutEnvironment;
use buoyant::event::{Event, EventContext, EventResult, TouchResult};
use buoyant::focus::{Seek, SeekResult};
use buoyant::layout::ResolvedLayout;
use buoyant::place::{Built, Place};
use buoyant::primitives::geometry::Rectangle;
use buoyant::primitives::{Point, ProposedDimension, ProposedDimensions, Size};
use buoyant::render::{AnimatedJoin, AnimationDomain, ContentShape, IntrinsicShape, Render};
use buoyant::render_target::RenderTarget;
use buoyant::transition::Opacity;
use buoyant::view::{ViewLayout, ViewMarker};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_touch::{Phase, Touch};

use crate::model::{LEVELS, State};

/// How far a finger moves across before it sets the level: as far as a
/// list moves it before it gives the touch to what lies in it to take,
/// rather than scrolling. Any less, and a touch the list goes on to scroll
/// would already have set the level, and any more, a touch the list has
/// given up would not. The Volume tests in `chat_loop_tdeck` fail if the
/// two part.
const SLOP: i32 = 8;

/// The steps of a level, each `step` wide and `gap` apart, taken as touched
/// as far as `reach` either side; the level each sets with `set`, which
/// says whether that changed it; and `done`, for when a touch that changed
/// it ends.
#[derive(Clone, Copy)]
pub(super) struct LevelDrag {
    step: u32,
    gap: u32,
    reach: u32,
    set: fn(&mut State, u8) -> bool,
    done: fn(&mut State),
}

impl LevelDrag {
    pub(super) const fn new(
        step: u32,
        gap: u32,
        reach: u32,
        set: fn(&mut State, u8) -> bool,
        done: fn(&mut State),
    ) -> Self {
        Self {
            step,
            gap,
            reach,
            set,
            done,
        }
    }

    /// How wide the steps are, with their reach either side.
    const fn width(&self) -> u32 {
        self.step * LEVELS as u32 + self.gap * (LEVELS as u32 - 1) + 2 * self.reach
    }

    /// The level whose step, or the gap after it, lies under `x`, for an
    /// area at `area`.
    fn level_at(&self, area: &Rectangle, x: i32) -> u8 {
        let along = x - area.origin.x - self.reach as i32;
        if along < 0 {
            return 1;
        }
        (along as u32 / (self.step + self.gap) + 1).min(u32::from(LEVELS)) as u8
    }

    /// Sets the level under `x`, for an area at `area`, and has the view
    /// built again if that changed it. Returns whether it did.
    fn set_at(&self, area: &Rectangle, x: i32, state: &mut State, context: &EventContext) -> bool {
        let changed = (self.set)(state, self.level_at(area, x));
        if changed {
            context.request_view_rebuild();
        }
        changed
    }

    /// Follows `held` through as its touch ends.
    fn end(&self, held: Held, state: &mut State) {
        if held.changed {
            (self.done)(state);
        }
    }
}

/// A touch on the steps: where it started, whether it has moved far
/// enough across to be setting the level, and whether it has changed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Held {
    id: u8,
    start_x: i32,
    sliding: bool,
    changed: bool,
}

impl ViewMarker for LevelDrag {
    type Renderables = Area;
    type Transition = Opacity;
}

impl ViewLayout<State> for LevelDrag {
    type Sublayout = Size;
    type State = Option<Held>;
    type FocusTree = ();

    fn transition(&self) -> Self::Transition {
        Opacity
    }

    fn build_state(&self, _captures: &mut State) -> Self::State {
        None
    }

    fn layout(
        &self,
        offer: &ProposedDimensions,
        _env: &impl LayoutEnvironment,
        _captures: &mut State,
        _state: &mut Self::State,
    ) -> ResolvedLayout<Self::Sublayout> {
        let height = match offer.height {
            ProposedDimension::Exact(height) => height,
            ProposedDimension::Compact | ProposedDimension::Infinite => 0,
        };
        let size = Size::new(self.width(), height);
        ResolvedLayout {
            resolved_size: size.into(),
            sublayouts: size,
        }
    }

    fn render_tree_in<'p>(
        &self,
        layout: &Self::Sublayout,
        origin: Point,
        _env: &impl LayoutEnvironment,
        _captures: &mut State,
        _state: &mut Self::State,
        place: Place<'p, Self::Renderables>,
    ) -> Built<'p> {
        place.write(Area(Rectangle::new(origin, *layout)))
    }

    fn handle_event(
        &self,
        _event: &Event,
        _context: &EventContext,
        _render_tree: &mut Self::Renderables,
        _captures: &mut State,
        _state: &mut Self::State,
        _focus: &mut Self::FocusTree,
    ) -> EventResult {
        EventResult::Deferred
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
        touch: &Touch,
        context: &EventContext,
        render_tree: &mut Self::Renderables,
        captures: &mut State,
        state: &mut Self::State,
    ) -> TouchResult<Self::FocusTree> {
        let point: Point = touch.location.into();
        let area = render_tree.0;
        if let Some(held) = state
            && held.id != touch.id
        {
            return TouchResult::Deferred;
        }
        match touch.phase {
            Phase::Started => {
                if context.touch_starts_on(&area.into(), point) {
                    *state = Some(Held {
                        id: touch.id,
                        start_x: point.x,
                        sliding: false,
                        changed: false,
                    });
                    return TouchResult::Handled;
                }
                // A touch whose end went missing is over: one that starts
                // elsewhere must not slide the level.
                if !context.is_touch_probe() {
                    *state = None;
                }
                TouchResult::Deferred
            }
            Phase::Moved => {
                let Some(held) = state else {
                    return TouchResult::Deferred;
                };
                held.sliding |= (point.x - held.start_x).abs() >= SLOP;
                if held.sliding {
                    held.changed |= self.set_at(&area, point.x, captures, context);
                }
                TouchResult::Handled
            }
            Phase::Ended => {
                let Some(mut held) = state.take() else {
                    return TouchResult::Deferred;
                };
                held.changed |= self.set_at(&area, point.x, captures, context);
                self.end(held, captures);
                TouchResult::Handled
            }
            Phase::Cancelled => {
                let Some(held) = state.take() else {
                    return TouchResult::Deferred;
                };
                self.end(held, captures);
                TouchResult::Handled
            }
            Phase::Hovering(_) => TouchResult::Deferred,
        }
    }
}

/// Where the steps take a touch. Nothing is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Area(Rectangle);

impl AnimatedJoin for Area {
    fn join_from(&mut self, _source: &Self, _domain: &AnimationDomain) {}
}

impl IntrinsicShape for Area {
    fn content_shape(&self) -> ContentShape {
        self.0.into()
    }
}

impl Render<Rgb565> for Area {
    fn render(&self, _target: &mut impl RenderTarget<ColorFormat = Rgb565>, _style: &Rgb565) {}

    fn render_animated(
        _target: &mut impl RenderTarget<ColorFormat = Rgb565>,
        _source: &Self,
        _target_tree: &Self,
        _style: &Rgb565,
        _domain: &AnimationDomain,
    ) {
    }
}
