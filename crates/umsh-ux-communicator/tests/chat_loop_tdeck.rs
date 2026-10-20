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

fn touch(phase: input::TouchPhase, (x, y): (i16, i16)) -> Input {
    Input::Touch { phase, x, y }
}

#[test]
fn tapping_a_chat_opens_it() {
    use input::TouchPhase::{Ended, Started};
    let mut app = app!();
    let at = middle_of(&mut app, keys::chat(PAT));
    input::apply(&mut app, touch(Started, at), tick(1000));
    input::apply(&mut app, touch(Ended, at), tick(100));
    assert_in_conversation(app.state(), PAT);
}

#[test]
fn holding_a_finger_on_a_chat_opens_its_menu_and_lifting_it_does_not_open_it() {
    use input::TouchPhase::{Ended, Started};
    let mut app = app!();
    let at = middle_of(&mut app, keys::chat(PAT));
    input::apply(&mut app, touch(Started, at), tick(1000));
    let due = app
        .state()
        .next_deadline()
        .expect("a touch held has a deadline");
    input::expire(&mut app, tick(due - tick(0)));
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::Open(PAT)));
    input::apply(&mut app, touch(Ended, at), tick(100));
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::Open(PAT)));
}

#[test]
fn a_finger_that_moves_away_is_not_held() {
    use input::TouchPhase::{Moved, Started};
    let mut app = app!();
    let (x, y) = middle_of(&mut app, keys::chat(PAT));
    input::apply(&mut app, touch(Started, (x, y)), tick(1000));
    input::apply(&mut app, touch(Moved, (x, y - 20)), tick(50));
    assert_eq!(app.state().next_deadline(), None);
}

#[test]
fn the_lock_screen_takes_no_touch() {
    use input::TouchPhase::{Ended, Started};
    let mut app = app!();
    let at = middle_of(&mut app, keys::chat(PAT));
    lock(&mut app);
    input::apply(&mut app, touch(Started, at), tick(1000));
    input::apply(&mut app, touch(Ended, at), tick(100));
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
    // Near the far corner of its place, well off the arrow itself.
    let m = &BOARD.metrics;
    let at = (
        m.back.expect("the T-Deck has touch") as i16 - 3,
        (m.strip + m.header) as i16 - 3,
    );
    input::apply(&mut app, touch(Started, at), tick(1000));
    input::apply(&mut app, touch(Ended, at), tick(100));
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
    input::apply(&mut app, touch(Started, at), tick(1000));
    input::apply(&mut app, touch(Ended, at), tick(100));
    assert_eq!(actions(app.state()), None);
    assert_eq!(focus(app.state()), Some(keys::message(SEE_YOU)));
    // Focused, it has moved again.
    let at = middle_of(&mut app, keys::message(SEE_YOU));
    input::apply(&mut app, touch(Started, at), tick(1000));
    let due = app
        .state()
        .next_deadline()
        .expect("a touch held has a deadline");
    input::expire(&mut app, tick(due - tick(0)));
    assert_eq!(actions(app.state()), Some(SEE_YOU));
    // Lifting the finger chooses nothing in the menu.
    input::apply(&mut app, touch(Ended, at), tick(100));
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
    input::apply(&mut app, touch(Started, at), tick(1000));
    input::apply(&mut app, touch(Ended, at), tick(100));
    assert_eq!(chat_menu(app.state()), None);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(focus(app.state()), Some(keys::chat(PAT)));
}
