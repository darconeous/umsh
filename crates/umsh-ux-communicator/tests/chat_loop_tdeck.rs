//! The chat loop on the T-Deck.

const BOARD: &umsh_ux_communicator::board::Board = &umsh_ux_communicator::board::Board::TDECK;

include!("chat_loop/cases.rs");

/// The middle of what `key` names on screen, with focus left where it was.
fn middle_of<V, F>(app: &mut App<V, State, F>, key: FocusKey) -> (i16, i16)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    let was = focus(app.state());
    app.focus(key);
    let area = app
        .focus_shape()
        .bounding_box()
        .expect("the element is on screen");
    if let Some(was) = was {
        app.focus(was);
    }
    let x = area.origin.x + area.size.width as i32 / 2;
    let y = area.origin.y + area.size.height as i32 / 2;
    (x as i16, y as i16)
}

/// A tap anywhere on a code goes back: here, at the screen's far corner,
/// away from the code and its words.
#[test]
fn a_tap_anywhere_on_a_code_goes_back() {
    use input::TouchPhase::{Ended, Started};
    let mut app = app!();
    open_category(&mut app, keys::IDENTITY);
    turn_to(&mut app, keys::IDENTITY_CODE);
    run(&mut app, &[Input::Press]);
    assert!(matches!(
        app.state().screen(),
        Screen::Device {
            page: DevicePage::Share { .. },
            ..
        }
    ));
    let size = BOARD.metrics.size();
    let corner = (size.width as i16 - 4, size.height as i16 - 4);
    input::apply(&mut app, touch(Started, corner, tick(100)), tick(0));
    input::apply(&mut app, touch(Ended, corner, tick(50)), tick(0));
    assert_eq!(focus(app.state()), Some(keys::IDENTITY_CODE));
}

/// A touch the panel reported at `at`.
fn touch(phase: input::TouchPhase, (x, y): (i16, i16), at: u64) -> Input {
    Input::Touch { phase, x, y, at }
}

/// A touch reported at `now`, and taken in at once.
fn apply_touch<V, F>(app: &mut App<V, State, F>, phase: input::TouchPhase, at: (i16, i16), now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    input::apply(app, touch(phase, at, now), now);
}

/// A downward stroke through a long history, as the panel reports it: 8 px
/// every 20 ms from `start`, then lifted `lift` ms after the last move.
fn stroke(start: u64, lift: u64) -> Vec<Input> {
    use input::TouchPhase::{Ended, Moved, Started};
    let (x, y) = (160, 60);
    let mut stroke = vec![touch(Started, (x, y), start)];
    for step in 1..=5 {
        stroke.push(touch(Moved, (x, y + 8 * step), start + 20 * step as u64));
    }
    stroke.push(touch(Ended, (x, y + 40), start + 100 + lift));
    stroke
}

/// Takes in each of `inputs` as the panel reports it, returning the time.
fn at_once<V, F>(app: &mut App<V, State, F>, inputs: Vec<Input>) -> u64
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    let mut now = 0;
    for input in inputs {
        let Input::Touch { at, .. } = input else {
            unreachable!("a stroke is touches")
        };
        now = at;
        app.set_time(std::time::Duration::from_millis(now));
        input::apply(app, input, now);
    }
    now
}

/// Takes in all of `inputs` together at `now`, as after a slow frame.
fn all_at<V, F>(app: &mut App<V, State, F>, inputs: Vec<Input>, now: u64) -> u64
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    app.set_time(std::time::Duration::from_millis(now));
    let mut queue = inputs.into_iter().peekable();
    while let Some(input) = queue.next() {
        input::apply_before(app, input, queue.peek(), now);
    }
    now
}

/// The message a tap lands on in a long history at `start`, once what
/// `take` takes in has come to rest.
fn landing<V, F>(
    mut app: App<V, State, F>,
    start: u64,
    take: impl FnOnce(&mut App<V, State, F>) -> u64,
) -> Option<FocusKey>
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    use input::TouchPhase::{Ended, Started};
    app.state_mut().open_chat(7);
    app.set_time(std::time::Duration::from_millis(start));
    app.finalize_view();
    let mut now = take(&mut app);
    for _ in 0..100 {
        now += 20;
        app.set_time(std::time::Duration::from_millis(now));
        input::expire(&mut app, now);
        app.finalize_view();
    }
    apply_touch(&mut app, Started, (160, 100), now + 20);
    apply_touch(&mut app, Ended, (160, 100), now + 40);
    focus(app.state())
}

#[test]
fn a_flick_taken_in_late_coasts_as_far_as_one_taken_in_at_once() {
    let start = 10_000;
    // Held still before lifting, it stops where the finger left it.
    let held = landing(app!(), start, |app| at_once(app, stroke(start, 200)));
    let flung = landing(app!(), start, |app| at_once(app, stroke(start, 0)));
    assert_ne!(flung, held, "a flick coasts on");
    // The whole flick queued behind a slow frame, and taken in together.
    let late = landing(app!(), start, |app| {
        all_at(app, stroke(start, 0), start + 250)
    });
    assert_eq!(late, flung);
}

#[test]
fn tapping_a_chat_opens_it() {
    use input::TouchPhase::{Ended, Started};
    let mut app = app!();
    let at = middle_of(&mut app, keys::chat(PAT));
    apply_touch(&mut app, Started, at, tick(1000));
    apply_touch(&mut app, Ended, at, tick(100));
    assert_in_conversation(app.state(), PAT);
}

#[test]
fn holding_a_finger_on_a_chat_opens_its_menu_and_lifting_it_does_not_open_it() {
    use input::TouchPhase::{Ended, Started};
    let mut app = app!();
    let at = middle_of(&mut app, keys::chat(PAT));
    apply_touch(&mut app, Started, at, tick(1000));
    let due = app
        .state()
        .next_deadline()
        .expect("a touch held has a deadline");
    input::expire(&mut app, tick(due - tick(0)));
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::Open(PAT)));
    apply_touch(&mut app, Ended, at, tick(100));
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::Open(PAT)));
}

#[test]
fn a_finger_that_moves_away_is_not_held() {
    use input::TouchPhase::{Moved, Started};
    let mut app = app!();
    let (x, y) = middle_of(&mut app, keys::chat(PAT));
    apply_touch(&mut app, Started, (x, y), tick(1000));
    apply_touch(&mut app, Moved, (x, y - 20), tick(50));
    assert_eq!(app.state().next_deadline(), None);
}

#[test]
fn the_lock_screen_takes_no_touch() {
    use input::TouchPhase::{Ended, Started};
    let mut app = app!();
    let at = middle_of(&mut app, keys::chat(PAT));
    lock(&mut app);
    apply_touch(&mut app, Started, at, tick(1000));
    apply_touch(&mut app, Ended, at, tick(100));
    assert!(app.state().lock.locked);
    assert_eq!(app.state().touch, None);
}

#[test]
fn tapping_the_back_arrow_goes_back_and_the_trackball_never_lands_on_it() {
    use input::TouchPhase::{Ended, Started};
    let mut app = app!();
    run(&mut app, &[Input::Turn(2), Input::Press]);
    assert_in_conversation(app.state(), PAT);
    // Up from the composer walks the history and stops at its top.
    for _ in 0..40 {
        click(&mut app, Input::Move(Arrow::Up), tick(100));
    }
    assert!(matches!(app.state().screen(), Screen::Conversation { .. }));
    // Off the arrow itself, toward the far corner of the place a finger
    // is taken to cover.
    let m = &BOARD.metrics;
    let reach = m.touch_target.expect("the T-Deck has touch") as i16 / 2;
    let at = (reach + 6, (m.strip + m.header) as i16 - 3);
    apply_touch(&mut app, Started, at, tick(1000));
    apply_touch(&mut app, Ended, at, tick(100));
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(focus(app.state()), Some(keys::chat(PAT)));
}

#[test]
fn a_tap_on_a_message_selects_it_and_holding_it_opens_its_actions() {
    use input::TouchPhase::{Ended, Started};
    let mut app = app!();
    run(&mut app, &[Input::Press]);
    // Measured with the composer focused, as it is for the tap: focus
    // changes the layout.
    let at = middle_of(&mut app, keys::message(SEE_YOU));
    let composer = middle_of(&mut app, keys::COMPOSER);
    app.focus(keys::COMPOSER);
    let area = app
        .focus_shape()
        .bounding_box()
        .expect("the composer is on screen");
    let at = (at.0, at.1.min(area.origin.y as i16 - 30));
    assert_ne!(at, composer);
    apply_touch(&mut app, Started, at, tick(1000));
    apply_touch(&mut app, Ended, at, tick(100));
    assert_eq!(actions(app.state()), None);
    assert_eq!(focus(app.state()), Some(keys::message(SEE_YOU)));
    // Focused, it has moved again.
    let at = middle_of(&mut app, keys::message(SEE_YOU));
    apply_touch(&mut app, Started, at, tick(1000));
    let due = app
        .state()
        .next_deadline()
        .expect("a touch held has a deadline");
    input::expire(&mut app, tick(due - tick(0)));
    assert_eq!(actions(app.state()), Some(SEE_YOU));
    // Lifting the finger chooses nothing in the menu.
    apply_touch(&mut app, Ended, at, tick(100));
    assert_eq!(actions(app.state()), Some(SEE_YOU));
}

#[test]
fn a_tap_outside_a_menu_closes_it_and_chooses_nothing() {
    use input::TouchPhase::{Ended, Started};
    let mut app = app!();
    run(&mut app, &[Input::Turn(2)]);
    hold(&mut app);
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::Open(PAT)));
    // The bottom-left corner, clear of the menu.
    let at = (4, BOARD.metrics.height as i16 - 4);
    apply_touch(&mut app, Started, at, tick(1000));
    apply_touch(&mut app, Ended, at, tick(100));
    assert_eq!(chat_menu(app.state()), None);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(focus(app.state()), Some(keys::chat(PAT)));
}

/// A drag moves the history, never focus, through its coast too.
#[test]
fn a_flick_through_the_history_selects_nothing() {
    use input::TouchPhase::{Ended, Moved, Started};
    use std::time::Duration;
    let mut app = app!();
    run(&mut app, &[Input::Turn(2), Input::Press]);
    assert_in_conversation(app.state(), PAT);
    let was = focus(app.state());
    let mut ms = 10_000u64;
    let mut at = |app: &mut App<_, State, _>, step: u64| {
        ms += step;
        app.set_time(Duration::from_millis(ms));
        ms
    };
    let (x, y) = (100, 60);
    let now = at(&mut app, 0);
    apply_touch(&mut app, Started, (x, y), now);
    for step in 1..=5 {
        let now = at(&mut app, 20);
        apply_touch(&mut app, Moved, (x, y + 25 * step), now);
    }
    let now = at(&mut app, 20);
    apply_touch(&mut app, Ended, (x, y + 125), now);
    let mut seen = vec![focus(app.state())];
    for _ in 0..100 {
        let now = at(&mut app, 20);
        input::expire(&mut app, now);
        app.finalize_view();
        if seen.last() != Some(&focus(app.state())) {
            seen.push(focus(app.state()));
        }
    }
    assert_eq!(seen, [was]);
}

/// A screen that keeps nothing drawn to it.
struct Blank(embedded_graphics::geometry::Size);

impl embedded_graphics::geometry::OriginDimensions for Blank {
    fn size(&self) -> embedded_graphics::geometry::Size {
        self.0
    }
}

impl embedded_graphics::draw_target::DrawTarget for Blank {
    type Color = embedded_graphics::pixelcolor::Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = embedded_graphics::Pixel<Self::Color>>,
    {
        pixels.into_iter().for_each(drop);
        Ok(())
    }
}

/// Paints a frame, as the board does whenever the app asks, which is where
/// a long list builds the rows the frame shows.
fn paint<V, F>(app: &mut App<V, State, F>)
where
    V: buoyant::view::View<embedded_graphics::pixelcolor::Rgb565, State>,
    V::FocusTree: DefaultFocus,
    F: Fn(&State) -> V,
{
    use embedded_graphics::pixelcolor::{Rgb565, RgbColor as _};
    let mut screen = Blank(BOARD.metrics.size());
    let mut target = buoyant::render_target::EmbeddedGraphicsRenderTarget::new(&mut screen);
    app.render_animated(&mut target, &Rgb565::WHITE);
}

/// Flicks the content up from `y`, 25 px every 20 ms from `ms`, and paints
/// each frame until it comes to rest. Returns when it did.
fn flick_up<V, F>(app: &mut App<V, State, F>, mut ms: u64, y: i16) -> u64
where
    V: buoyant::view::View<embedded_graphics::pixelcolor::Rgb565, State>,
    V::FocusTree: DefaultFocus,
    F: Fn(&State) -> V,
{
    use input::TouchPhase::{Ended, Moved, Started};
    use std::time::Duration;
    let x = 160;
    app.set_time(Duration::from_millis(ms));
    apply_touch(app, Started, (x, y), ms);
    for step in 1..=6 {
        ms += 20;
        app.set_time(Duration::from_millis(ms));
        apply_touch(app, Moved, (x, y - 25 * step), ms);
        paint(app);
    }
    ms += 20;
    app.set_time(Duration::from_millis(ms));
    apply_touch(app, Ended, (x, y - 150), ms);
    for _ in 0..150 {
        ms += 20;
        app.set_time(Duration::from_millis(ms));
        input::expire(app, ms);
        app.finalize_view();
        paint(app);
    }
    ms
}

/// The time zones, past the dozen built around the one set, are all there
/// to flick through, and a tap on one far down sets it.
#[test]
fn a_flick_through_the_time_zones_reaches_far_down_and_a_tap_sets_one() {
    use input::TouchPhase::{Ended, Started};
    use std::time::Duration;
    let mut app = app!();
    open_clock(&mut app);
    turn_to(&mut app, keys::CLOCK_ZONE);
    run(&mut app, &[Input::Press]);
    let was = focus(app.state()).and_then(keys::zone_of).unwrap();
    let mut ms = tick(1000);
    paint(&mut app);
    for _ in 0..3 {
        ms = flick_up(&mut app, ms, 210);
    }
    // The zone in the middle of the screen, by touch.
    let (x, y) = (160, 130);
    ms += 1000;
    app.set_time(Duration::from_millis(ms));
    apply_touch(&mut app, Started, (x, y), ms);
    ms += 50;
    app.set_time(Duration::from_millis(ms));
    apply_touch(&mut app, Ended, (x, y), ms);
    app.finalize_view();
    let set = zones::find(&app.state().clock.zone).unwrap();
    assert!(set > was + 12, "set {set}, from {was}");
}

/// Flung, with nothing more from the panel, the list asks for frames that
/// build the rows to come, and a board that paints when asked builds them.
#[test]
fn a_fling_through_the_time_zones_asks_for_the_rows_to_come() {
    use input::TouchPhase::{Ended, Moved, Started};
    use std::time::Duration;
    let mut app = app!();
    open_clock(&mut app);
    turn_to(&mut app, keys::CLOCK_ZONE);
    run(&mut app, &[Input::Press]);
    let mut ms = tick(1000);
    paint(&mut app);
    let (x, y) = (160, 210);
    app.set_time(Duration::from_millis(ms));
    apply_touch(&mut app, Started, (x, y), ms);
    for step in 1..=6 {
        ms += 20;
        app.set_time(Duration::from_millis(ms));
        apply_touch(&mut app, Moved, (x, y - 25 * step), ms);
    }
    ms += 20;
    app.set_time(Duration::from_millis(ms));
    apply_touch(&mut app, Ended, (x, y - 150), ms);
    paint(&mut app);
    let mut asked = 0;
    for _ in 0..150 {
        ms += 20;
        app.set_time(Duration::from_millis(ms));
        paint(&mut app);
        // A frame near the end of the rows built asks for another...
        if app.should_redraw() {
            asked += 1;
            // ...which builds them, and asks for nothing more.
            paint(&mut app);
            assert!(!app.should_redraw());
        }
    }
    assert!(asked > 0);
}
