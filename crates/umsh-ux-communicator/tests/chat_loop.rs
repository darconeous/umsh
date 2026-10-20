//! The chat loop driven the way a board drives it: inputs through
//! `input::apply`, with no frame drawn between them.

use buoyant::app::App;
use buoyant::focus::{DefaultFocus, FocusKey};
use buoyant::render::AnimatedJoin;
use buoyant::view::ViewLayout;
use embedded_graphics::prelude::Size;
use umsh_ux_communicator::buoyant;
use umsh_ux_communicator::clock_settings::DateParts;
use umsh_ux_communicator::input::{self, Input};
use umsh_ux_communicator::keyboard::{Latch, Modifier, PICKER};
use umsh_ux_communicator::model::{
    ChannelAccess, ChannelEntry, ChatKind, ClockSource, Delivery, Direction, Ending, FoundKind,
    Glance, Node as _, NodeEvent, Notice, Profile, Reaction, Rule, Section, Shareable, State,
    brightness_level,
};
use umsh_ux_communicator::nav::{ChatMenu, DevicePage, MemberFrom, Screen, Unsent, keys};
use umsh_ux_communicator::{fixture, theme, ui, zones};

/// The fixture's chats, in list order.
const RIDGE: u32 = 1;
const PAT: u32 = 3;
const RIDGE_DRAFT: &str = "On my way, save me some hot coffee";

/// Where the fixture's chats keep their messages, for the life of a test.
fn store() -> &'static fixture::Store {
    Box::leak(Box::new(fixture::Store::new(&std::alloc::System)))
}

macro_rules! app {
    () => {
        app!(store())
    };
    ($store:expr) => {{
        let mut app = App::new(
            fixture::state($store),
            Size::new(theme::WIDTH, theme::HEIGHT).into(),
            ui::root_view,
        );
        ui::bind(&mut app);
        app
    }};
}

/// Each input, then what the node says of it, as a board takes them. A
/// press is let go at once, which makes it a click.
fn run<V, F>(app: &mut App<V, State, F>, inputs: &[Input])
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    // A second apart: never quick enough to be a double tap.
    for &input in inputs {
        let now = tick(1000);
        click(app, input, now);
    }
}

/// `input` at `now`, then what the node says of it; a press is let go at
/// once.
fn click<V, F>(app: &mut App<V, State, F>, input: Input, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    input::apply(app, input, now);
    if input == Input::Press {
        input::apply(app, Input::Release, now);
    }
    input::events(app, now);
}

/// Holds the wheel down until its hold has had its time, as a board's loop
/// wakes for it, then lets go.
fn hold<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    input::apply(app, Input::Press, tick(1000));
    let due = app.state().next_deadline().expect("a hold has a deadline");
    let now = tick(due.saturating_sub(tick(0)));
    app.state_mut().expire(now);
    app.finalize_view();
    input::apply(app, Input::Release, tick(100));
    input::events(app, tick(0));
}

/// Inputs in quick succession, a tenth of a second apart.
fn quick<V, F>(app: &mut App<V, State, F>, inputs: &[Input])
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    for &input in inputs {
        let now = tick(100);
        click(app, input, now);
    }
}

/// Moves the test's clock on by `ms`, and returns it.
fn tick(ms: u64) -> u64 {
    thread_local!(static CLOCK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) });
    CLOCK.with(|clock| {
        clock.set(clock.get() + ms);
        clock.get()
    })
}

fn typed(text: &str) -> Vec<Input> {
    text.chars().map(Input::Character).collect()
}

fn focus(state: &State) -> Option<FocusKey> {
    state.screen().focus().current()
}

fn draft(state: &State, chat: u32) -> &str {
    state.chat(chat).expect("chat exists").draft.text()
}

fn assert_in_conversation(state: &State, chat: u32) {
    assert!(
        matches!(state.screen(), Screen::Conversation { chat: c, .. } if *c == chat),
        "expected chat {chat}, got {:?}",
        state.screen()
    );
    assert_eq!(focus(state), Some(keys::COMPOSER));
}

#[test]
fn the_list_opens_on_its_first_chat() {
    let app = app!();
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(focus(app.state()), Some(keys::chat(RIDGE)));
}

#[test]
fn press_and_enter_both_open_the_focused_chat() {
    let mut pressed = app!();
    run(&mut pressed, &[Input::Press]);
    assert_in_conversation(pressed.state(), RIDGE);

    let mut entered = app!();
    run(&mut entered, &[Input::Enter]);
    assert_in_conversation(entered.state(), RIDGE);
}

#[test]
fn typing_edits_at_the_cursor_and_back_keeps_the_draft() {
    let mut app = app!();
    run(&mut app, &[Input::Press]);
    // The first letter wakes the field and is typed.
    run(&mut app, &typed("!"));
    assert_eq!(
        draft(app.state(), RIDGE),
        "On my way, save me some hot coffee!"
    );
    // In an active field the wheel moves the cursor, not focus.
    run(&mut app, &[Input::Turn(-7)]);
    run(&mut app, &typed("cup of "));
    assert_eq!(
        draft(app.state(), RIDGE),
        "On my way, save me some hot cup of coffee!"
    );
    assert_eq!(focus(app.state()), Some(keys::COMPOSER));

    // Press is Done; then Backspace is Back.
    run(&mut app, &[Input::Press, Input::Backspace]);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(focus(app.state()), Some(keys::chat(RIDGE)));
    assert_eq!(
        draft(app.state(), RIDGE),
        "On my way, save me some hot cup of coffee!"
    );
}

#[test]
fn backspace_erases_while_typing() {
    let mut app = app!();
    run(&mut app, &[Input::Press, Input::Enter, Input::Backspace]);
    assert_in_conversation(app.state(), RIDGE);
    assert_eq!(
        draft(app.state(), RIDGE),
        "On my way, save me some hot coffe"
    );
}

#[test]
fn backspace_with_nothing_to_erase_ends_the_edit_then_goes_back() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2), Input::Press, Input::Enter]);
    assert_in_conversation(app.state(), PAT);
    run(&mut app, &[Input::Backspace]);
    assert_in_conversation(app.state(), PAT);
    run(&mut app, &[Input::Backspace]);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
}

#[test]
fn enter_sends_the_draft() {
    let mut app = app!();
    // Enter wakes the field, then sends.
    run(&mut app, &[Input::Press, Input::Enter, Input::Enter]);
    let conversation = app.state().conversation(RIDGE).expect("chat exists");
    let sent = conversation.messages.last().expect("a message");
    assert_eq!(sent.direction, Direction::Outbound);
    assert_eq!(sent.text.as_str(), RIDGE_DRAFT);
    assert_eq!(sent.delivery, Delivery::Sending);
    assert_eq!(draft(app.state(), RIDGE), "");
    assert_eq!(focus(app.state()), Some(keys::COMPOSER));

    // Sending ends the edit, so the wheel reaches the history again.
    let sent = sent.id;
    run(&mut app, &[Input::Turn(-1)]);
    assert_eq!(focus(app.state()), Some(keys::message(sent)));
}

#[test]
fn a_draft_longer_than_a_fragment_is_sent_whole() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2), Input::Press]);
    let long = "Trail is washed out past the second creek crossing. ".repeat(6);
    assert!(long.len() > 160);
    run(&mut app, &typed(&long));
    assert_eq!(draft(app.state(), PAT), long);
    run(&mut app, &[Input::Enter]);
    let conversation = app.state().conversation(PAT).expect("chat is open");
    let sent = conversation.messages.last().expect("a message");
    assert_eq!(sent.text.as_str(), long);
}

#[test]
fn a_sent_message_is_there_when_the_chat_opens_again() {
    let mut app = app!();
    run(&mut app, &[Input::Press, Input::Enter, Input::Enter]);
    run(&mut app, &[Input::Backspace]);
    assert!(app.state().conversation.is_none());
    let summary = app.state().chat(RIDGE).expect("chat exists");
    assert_eq!(
        summary.preview.as_str(),
        "You: On my way, save me some hot coffee"
    );

    run(&mut app, &[Input::Press]);
    assert_in_conversation(app.state(), RIDGE);
    let conversation = app.state().conversation(RIDGE).expect("chat is open");
    let texts: Vec<&str> = conversation
        .messages
        .iter()
        .map(|m| m.text.as_str())
        .collect();
    assert_eq!(texts.len(), 4);
    assert_eq!(texts[3], RIDGE_DRAFT);
}

#[test]
fn a_chat_that_moves_to_the_top_keeps_focus() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2), Input::Press]);
    assert_in_conversation(app.state(), PAT);
    run(&mut app, &typed("ok"));
    run(&mut app, &[Input::Enter, Input::Backspace]);
    assert_eq!(app.state().chats[0].id, PAT);
    assert_eq!(focus(app.state()), Some(keys::chat(PAT)));
}

#[test]
fn backspace_on_the_list_goes_to_the_rail_and_press_returns() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(1), Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::rail(Section::Chats)));
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::chat(2)));
}

#[test]
fn open_back_and_open_again_with_no_frame_between() {
    let mut app = app!();
    run(&mut app, &[Input::Press, Input::Backspace, Input::Press]);
    assert_in_conversation(app.state(), RIDGE);
}

#[test]
fn typing_from_the_history_goes_to_the_composer() {
    let mut app = app!();
    run(&mut app, &[Input::Press, Input::Turn(-1)]);
    let reading = focus(app.state()).expect("a message is focused");
    assert!(keys::is_message(reading));
    // The composer is folded to a bar here; the letter unfolds it and lands.
    run(&mut app, &typed("k"));
    assert_in_conversation(app.state(), RIDGE);
    assert_eq!(
        draft(app.state(), RIDGE),
        "On my way, save me some hot coffeek"
    );
}

#[test]
fn backspace_in_the_history_is_back() {
    let mut app = app!();
    run(&mut app, &[Input::Press, Input::Turn(-2), Input::Backspace]);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(focus(app.state()), Some(keys::chat(RIDGE)));
}

/// Ridge Medic's messages: the question, my answer, and "See you at the hut".
const QUESTION: u32 = 0x100;
const ANSWER: u32 = 0x101;
const SEE_YOU: u32 = 0x102;

fn chat_menu(state: &State) -> Option<ChatMenu> {
    match state.screen() {
        Screen::Chats { menu, .. } => *menu,
        _ => None,
    }
}

#[test]
fn holding_the_wheel_on_a_chat_opens_its_menu_and_letting_go_does_not_open_it() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2)]);
    assert_eq!(focus(app.state()), Some(keys::chat(PAT)));
    hold(&mut app);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::Open(PAT)));
    assert_eq!(focus(app.state()), Some(keys::CHAT_SHOW_PEER));
    // Backspace closes it, back to the row.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(chat_menu(app.state()), None);
    assert_eq!(focus(app.state()), Some(keys::chat(PAT)));
}

#[test]
fn a_press_opens_a_chat_when_the_wheel_comes_back_up() {
    let mut app = app!();
    input::apply(&mut app, Input::Press, tick(1000));
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    input::apply(&mut app, Input::Release, tick(100));
    assert_in_conversation(app.state(), RIDGE);
}

#[test]
fn turning_while_the_wheel_is_down_lets_go_of_the_press() {
    let mut app = app!();
    input::apply(&mut app, Input::Press, tick(1000));
    input::apply(&mut app, Input::Turn(1), tick(100));
    input::apply(&mut app, Input::Release, tick(100));
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(app.state().next_deadline(), None);
}

#[test]
fn show_peer_opens_the_chats_saved_peer() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2)]);
    hold(&mut app);
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Peer { .. }));
    assert_eq!(focus(app.state()), Some(keys::PEER_MESSAGE));
}

#[test]
fn show_peer_offers_to_save_a_chats_unsaved_peer() {
    let mut app = app!();
    assert_eq!(focus(app.state()), Some(keys::chat(RIDGE)));
    hold(&mut app);
    assert_eq!(focus(app.state()), Some(keys::CHAT_SHOW_PEER));
    run(&mut app, &[Input::Press]);
    let (member, _) = shown_member(app.state());
    assert_eq!(member.sender.name.as_str(), "Ridge Medic");
    assert!(member.address.is_some());
    assert!(!member.saved);
    assert_eq!(focus(app.state()), Some(keys::SAVE_PEER));
    run(&mut app, &[Input::Press]);
    assert!(shown_member(app.state()).0.saved);
    assert_eq!(focus(app.state()), Some(keys::MESSAGE_MEMBER));
    // Message goes back to the chat it came from.
    run(&mut app, &[Input::Press]);
    assert_in_conversation(app.state(), RIDGE);
}

#[test]
fn deleting_a_chat_asks_first_and_then_removes_it() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2)]);
    hold(&mut app);
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::ConfirmDelete(PAT)));
    assert_eq!(focus(app.state()), Some(keys::DELETE_CANCEL));
    // Cancel keeps it.
    run(&mut app, &[Input::Press]);
    assert_eq!(chat_menu(app.state()), None);
    assert!(app.state().chat(PAT).is_some());

    hold(&mut app);
    run(
        &mut app,
        &[Input::Turn(1), Input::Press, Input::Turn(-1), Input::Press],
    );
    assert_eq!(chat_menu(app.state()), None);
    assert!(app.state().chat(PAT).is_none());
    // The row that took its place is focused.
    let next = app.state().chats[2].id;
    assert_eq!(focus(app.state()), Some(keys::chat(next)));
}

#[test]
fn holding_the_wheel_on_a_channel_opens_it_on_letting_go() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(1)]);
    assert!(matches!(
        app.state().chats[1].kind,
        ChatKind::Channel { .. }
    ));
    let channel = app.state().chats[1].id;
    hold(&mut app);
    assert_eq!(chat_menu(app.state()), None);
    assert!(matches!(app.state().screen(), Screen::Conversation { chat, .. } if *chat == channel));
}

fn actions(state: &State) -> Option<u32> {
    match state.screen() {
        Screen::Conversation { actions, .. } => *actions,
        _ => None,
    }
}

fn reply(state: &State) -> Option<u32> {
    match state.screen() {
        Screen::Conversation { reply, .. } => *reply,
        _ => None,
    }
}

fn reactions(state: &State, message: u32) -> Vec<(Reaction, u8, bool)> {
    let conversation = state.conversation.as_ref().expect("a chat is open");
    let message = conversation
        .messages
        .iter()
        .find(|m| m.id == message)
        .expect("the message");
    message
        .reactions
        .iter()
        .map(|r| (r.reaction, r.count, r.mine))
        .collect()
}

#[test]
fn pressing_a_message_opens_its_actions_and_backspace_closes_them() {
    let mut app = app!();
    run(&mut app, &[Input::Press, Input::Turn(-1), Input::Press]);
    assert_eq!(actions(app.state()), Some(SEE_YOU));
    assert_eq!(focus(app.state()), Some(keys::REPLY));
    // The palette is above Reply.
    run(&mut app, &[Input::Turn(-1)]);
    assert_eq!(focus(app.state()), Some(keys::reaction(Reaction::Question)));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(actions(app.state()), None);
    assert_eq!(focus(app.state()), Some(keys::message(SEE_YOU)));
}

#[test]
fn a_reaction_is_mine_until_chosen_again_and_kept_across_opening_the_chat() {
    let mut app = app!();
    let open_on_answer = [Input::Press, Input::Turn(-2), Input::Press, Input::Turn(-6)];
    run(&mut app, &open_on_answer);
    // Ridge Medic's heart is there already; mine joins it.
    assert_eq!(focus(app.state()), Some(keys::reaction(Reaction::Heart)));
    run(&mut app, &[Input::Press]);
    assert_eq!(actions(app.state()), None);
    assert_eq!(reactions(app.state(), ANSWER), [(Reaction::Heart, 2, true)]);

    run(&mut app, &[Input::Backspace, Input::Press]);
    assert_eq!(reactions(app.state(), ANSWER), [(Reaction::Heart, 2, true)]);

    // Choosing it again withdraws it.
    run(&mut app, &open_on_answer[1..]);
    run(&mut app, &[Input::Press]);
    assert_eq!(
        reactions(app.state(), ANSWER),
        [(Reaction::Heart, 1, false)]
    );
}

#[test]
fn typing_with_the_actions_open_goes_to_the_composer() {
    let mut app = app!();
    run(&mut app, &[Input::Press, Input::Turn(-1), Input::Press]);
    run(&mut app, &typed("!"));
    assert_eq!(actions(app.state()), None);
    assert_in_conversation(app.state(), RIDGE);
    assert_eq!(draft(app.state(), RIDGE), format!("{RIDGE_DRAFT}!"));
}

#[test]
fn a_reply_is_dropped_by_backspace_before_backspace_leaves() {
    let mut app = app!();
    run(
        &mut app,
        &[Input::Press, Input::Turn(-3), Input::Press, Input::Press],
    );
    assert_eq!(reply(app.state()), Some(QUESTION));
    assert_in_conversation(app.state(), RIDGE);
    // The field is not being edited: the first Backspace drops the reply
    // and keeps the text, the next leaves.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(reply(app.state()), None);
    assert_in_conversation(app.state(), RIDGE);
    assert_eq!(draft(app.state(), RIDGE), RIDGE_DRAFT);
    run(&mut app, &[Input::Backspace]);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
}

#[test]
fn sending_a_reply_ends_it() {
    let mut app = app!();
    run(
        &mut app,
        &[Input::Press, Input::Turn(-3), Input::Press, Input::Press],
    );
    run(&mut app, &[Input::Enter, Input::Enter]);
    assert_eq!(reply(app.state()), None);
    assert_eq!(draft(app.state(), RIDGE), "");
}

#[test]
fn details_open_from_the_actions_and_back_returns_to_the_message() {
    let mut app = app!();
    run(
        &mut app,
        &[
            Input::Press,
            Input::Turn(-3),
            Input::Press,
            Input::Turn(1),
            Input::Press,
        ],
    );
    let Screen::Details {
        message, details, ..
    } = app.state().screen()
    else {
        panic!("expected details, got {:?}", app.state().screen());
    };
    assert_eq!(*message, QUESTION);
    assert_eq!(details.rssi, Some(-97));
    assert_eq!(focus(app.state()), Some(keys::DETAIL_LIST));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::message(QUESTION)));
    assert_eq!(actions(app.state()), None);
}

/// Pat Okafor's last message, which went unconfirmed.
const ANTENNA: u32 = (PAT << 8) | 2;

fn message(state: &State, message: u32) -> umsh_ux_communicator::model::Message {
    let conversation = state.conversation.as_ref().expect("a chat is open");
    conversation
        .messages
        .iter()
        .find(|m| m.id == message)
        .expect("the message")
        .clone()
}

fn delivery(state: &State, message: u32) -> Delivery {
    let conversation = state.conversation.as_ref().expect("a chat is open");
    conversation
        .messages
        .iter()
        .find(|m| m.id == message)
        .expect("the message")
        .delivery
}

fn spend_airtime<V, F>(app: &mut App<V, State, F>, wait: Option<u16>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    app.state_mut().apply(NodeEvent::Airtime { wait }, 0);
    app.finalize_view();
}

#[test]
fn an_unconfirmed_message_offers_retry_first() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2), Input::Press]);
    assert_in_conversation(app.state(), PAT);
    run(&mut app, &[Input::Turn(-1)]);
    assert_eq!(focus(app.state()), Some(keys::message(ANTENNA)));
    assert_eq!(delivery(app.state(), ANTENNA), Delivery::Unconfirmed);
    // A press opens its actions, and sends nothing.
    run(&mut app, &[Input::Press]);
    assert_eq!(actions(app.state()), Some(ANTENNA));
    assert_eq!(focus(app.state()), Some(keys::RETRY));
    assert_eq!(delivery(app.state(), ANTENNA), Delivery::Unconfirmed);
    // Backspace closes them; Retry sends it again.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(actions(app.state()), None);
    assert_eq!(delivery(app.state(), ANTENNA), Delivery::Unconfirmed);
    run(&mut app, &[Input::Press, Input::Press]);
    assert_eq!(delivery(app.state(), ANTENNA), Delivery::Sending);
    assert_eq!(actions(app.state()), None);
    // On its way again, it is a message like any other.
    run(&mut app, &[Input::Press]);
    assert_eq!(actions(app.state()), Some(ANTENNA));
    // And it stays on its way when the chat opens again.
    run(
        &mut app,
        &[Input::Backspace, Input::Backspace, Input::Press],
    );
    assert_eq!(delivery(app.state(), ANTENNA), Delivery::Sending);
}

#[test]
fn deleting_an_unconfirmed_message_asks_first() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2), Input::Press, Input::Turn(-1)]);
    assert_eq!(focus(app.state()), Some(keys::message(ANTENNA)));
    run(&mut app, &[Input::Press, Input::Turn(2)]);
    assert_eq!(focus(app.state()), Some(keys::DELETE_MESSAGE));
    run(&mut app, &[Input::Press]);
    assert_eq!(actions(app.state()), None);
    assert_eq!(unsent(app.state()), Some(ANTENNA));
    assert_eq!(focus(app.state()), Some(keys::DELETE_MESSAGE_CANCEL));
    // Cancel keeps it.
    run(&mut app, &[Input::Press]);
    assert_eq!(unsent(app.state()), None);
    assert_eq!(focus(app.state()), Some(keys::message(ANTENNA)));
    assert!(!message(app.state(), ANTENNA).deleted);

    run(
        &mut app,
        &[
            Input::Press,
            Input::Turn(2),
            Input::Press,
            Input::Turn(-1),
            Input::Press,
        ],
    );
    assert_eq!(unsent(app.state()), None);
    assert!(message(app.state(), ANTENNA).deleted);
    // What stands in for it takes no focus.
    assert_eq!(focus(app.state()), Some(keys::COMPOSER));
}

/// The fixture's chat of message states, which holds a session with
/// forward secrecy, and my message in it that went unconfirmed under one.
const STATES: u32 = 7;
const SECRET: u32 = (STATES << 8) | 7;

fn unsent(state: &State) -> Option<u32> {
    match state.screen() {
        Screen::Conversation { unsent, .. } => unsent.map(Unsent::message),
        _ => None,
    }
}

fn forward_secret(state: &State, message: u32) -> bool {
    let conversation = state.conversation.as_ref().expect("a chat is open");
    let message = conversation.messages.iter().find(|m| m.id == message);
    message.expect("the message").forward_secret
}

#[test]
fn an_unconfirmed_message_under_forward_secrecy_asks_before_going_without() {
    let mut app = app!();
    app.state_mut().open_chat(STATES);
    app.finalize_view();
    assert!(app.state().chat(STATES).unwrap().forward_secret);
    assert!(forward_secret(app.state(), SECRET));
    app.state_mut().retry(SECRET);
    app.finalize_view();
    assert_eq!(unsent(app.state()), Some(SECRET));
    assert_eq!(focus(app.state()), Some(keys::RESEND));
    assert_eq!(delivery(app.state(), SECRET), Delivery::Unconfirmed);

    // Back leaves it as it was.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(unsent(app.state()), None);
    assert_eq!(focus(app.state()), Some(keys::message(SECRET)));
    assert_eq!(delivery(app.state(), SECRET), Delivery::Unconfirmed);

    // Going without, it is mine like any other.
    run(&mut app, &[Input::Press, Input::Press]);
    assert_eq!(unsent(app.state()), Some(SECRET));
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(unsent(app.state()), None);
    assert_eq!(delivery(app.state(), SECRET), Delivery::Sending);
    assert!(!forward_secret(app.state(), SECRET));
}

#[test]
fn trying_again_keeps_forward_secrecy() {
    let mut app = app!();
    app.state_mut().open_chat(STATES);
    app.finalize_view();
    app.state_mut().retry(SECRET);
    app.finalize_view();
    run(&mut app, &[Input::Press]);
    assert_eq!(unsent(app.state()), None);
    assert_eq!(delivery(app.state(), SECRET), Delivery::Sending);
    assert!(forward_secret(app.state(), SECRET));
}

#[test]
fn spent_airtime_keeps_the_draft_and_holds_a_retry() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2), Input::Press]);
    spend_airtime(&mut app, Some(100));
    run(&mut app, &typed("Also the 18650s"));
    run(&mut app, &[Input::Enter]);
    assert_eq!(draft(app.state(), PAT), "Also the 18650s");
    assert_eq!(app.state().conversation.as_ref().unwrap().messages.len(), 3);
    run(&mut app, &[Input::Turn(-1), Input::Press]);
    assert_eq!(delivery(app.state(), ANTENNA), Delivery::Unconfirmed);

    spend_airtime(&mut app, None);
    run(&mut app, &[Input::Press]);
    assert_eq!(delivery(app.state(), ANTENNA), Delivery::Sending);
    // The first Enter takes up the draft again; the second sends it.
    run(&mut app, &[Input::Turn(1), Input::Enter, Input::Enter]);
    assert_eq!(draft(app.state(), PAT), "");
}

/// Trail Crew, the chat the fixture's first arrival comes in.
const TRAIL_CREW: u32 = 2;

/// Takes in the fixture's next message to arrive, at `now`, as a board
/// would. Returns whether it calls for attention.
fn arrive<V, F>(app: &mut App<V, State, F>, store: &fixture::Store, now: u64) -> bool
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    assert!(store.arrive(), "an arrival left");
    input::events(app, now)
}

/// Takes in a message saying `text` that arrives in `chat` at `now`.
/// Returns whether it calls for attention.
fn arrive_in<V, F>(
    app: &mut App<V, State, F>,
    store: &fixture::Store,
    chat: u32,
    text: &str,
    now: u64,
) -> bool
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    store.arrive_in(chat, text);
    input::events(app, now)
}

#[test]
fn a_message_from_elsewhere_shows_a_banner_that_takes_no_key() {
    let store = store();
    let mut app = app!(store);
    // Typing in Ridge Medic, between "hot" and " coffee".
    run(&mut app, &[Input::Press, Input::Enter, Input::Turn(-7)]);
    assert!(arrive(&mut app, store, 1000));
    let banner = app.state().banner.expect("a banner");
    assert_eq!(banner.notice, Notice::Message(TRAIL_CREW));
    assert_eq!(app.state().chats[0].id, TRAIL_CREW);
    assert!(app.state().chats[0].unread);
    // Typing goes on where it was.
    run(&mut app, &typed("ed"));
    assert_eq!(
        draft(app.state(), RIDGE),
        "On my way, save me some hoted coffee"
    );
    // And it goes by itself.
    app.state_mut().expire(banner.until - 1);
    assert!(app.state().banner.is_some());
    app.state_mut().expire(banner.until);
    assert_eq!(app.state().banner, None);
    // Enter still sends the draft it interrupted.
    run(&mut app, &[Input::Enter]);
    assert_eq!(draft(app.state(), RIDGE), "");
}

#[test]
fn a_message_in_the_open_chat_joins_it_without_a_banner() {
    let store = store();
    let mut app = app!(store);
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_in_conversation(app.state(), TRAIL_CREW);
    let before = app.state().conversation.as_ref().unwrap().messages.len();
    assert!(!arrive(&mut app, store, 0));
    assert_eq!(app.state().banner, None);
    assert!(!app.state().chats[0].unread);
    let conversation = app.state().conversation.as_ref().unwrap();
    assert_eq!(conversation.messages.len(), before + 1);
    assert_eq!(
        conversation.messages.last().unwrap().direction,
        Direction::Inbound
    );
}

#[test]
fn the_list_shows_a_message_arrive_without_a_banner() {
    let store = store();
    let mut app = app!(store);
    assert!(arrive(&mut app, store, 0));
    assert_eq!(app.state().banner, None);
    assert_eq!(app.state().chats[0].id, TRAIL_CREW);
    // Focus stays on the chat it was on.
    assert_eq!(focus(app.state()), Some(keys::chat(RIDGE)));
}

#[test]
fn a_muted_chat_does_not_call_for_attention() {
    let store = store();
    let mut app = app!(store);
    run(&mut app, &[Input::Press]);
    // The public channel is muted.
    assert!(!arrive_in(&mut app, store, 4, "Mill Creek is clear", 0));
    assert_eq!(app.state().banner, None);
    assert_eq!(app.state().chats[0].id, 4);
}

/// Jo Reyes, the chat of the fixture's last arrival.
const JO: u32 = 5;

/// Locks the interface, as the lock button does, and lets it settle.
fn lock<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    app.state_mut().lock();
    app.finalize_view();
}

fn arrived(state: &State) -> Vec<(u32, String)> {
    state
        .arrived
        .iter()
        .map(|a| (a.chat, a.text.as_str().to_owned()))
        .collect()
}

#[test]
fn a_dark_panel_locks_after_a_moment_unless_it_lights_first() {
    let mut app = app!();
    app.state_mut().screen_off(10_000);
    app.state_mut().expire(10_999);
    assert!(!app.state().lock.locked);
    // Lit again in time: still unlocked.
    app.state_mut().screen_on(10_500);
    app.state_mut().expire(12_000);
    assert!(!app.state().lock.locked);
    app.state_mut().screen_off(20_000);
    assert_eq!(app.state().next_deadline(), Some(21_000));
    app.state_mut().expire(21_000);
    assert!(app.state().lock.locked);
}

#[test]
fn five_steps_down_and_a_press_unlock_to_where_it_was() {
    let store = store();
    let mut app = app!(store);
    // Reading Ridge Medic's last message.
    run(&mut app, &[Input::Press, Input::Turn(-1)]);
    let held = focus(app.state());
    assert_eq!(held, Some(keys::message(SEE_YOU)));
    lock(&mut app);
    assert!(app.state().lock.locked);
    quick(&mut app, &[Input::Turn(4)]);
    assert!(!app.state().lock.ready());
    quick(&mut app, &[Input::Turn(1)]);
    assert!(app.state().lock.ready());
    quick(&mut app, &[Input::Press]);
    assert!(!app.state().lock.locked);
    assert!(matches!(
        app.state().screen(),
        Screen::Conversation { chat: RIDGE, .. }
    ));
    assert_eq!(focus(app.state()), held);
}

#[test]
fn a_press_before_the_steps_or_after_the_window_does_nothing() {
    let mut app = app!();
    lock(&mut app);
    quick(&mut app, &[Input::Press, Input::Turn(3), Input::Press]);
    assert!(app.state().lock.locked);
    quick(&mut app, &[Input::Turn(2)]);
    assert!(app.state().lock.ready());
    // Once the window has passed, the bar starts over.
    tick(umsh_ux_communicator::lock::UNLOCK_WINDOW_MS);
    quick(&mut app, &[Input::Press]);
    assert!(app.state().lock.locked);
    assert_eq!(app.state().lock.steps, 0);
    assert!(!app.state().lock.ready());
}

#[test]
fn turning_up_takes_steps_back() {
    let mut app = app!();
    lock(&mut app);
    quick(&mut app, &[Input::Turn(5), Input::Turn(-2)]);
    assert_eq!(app.state().lock.steps, 3);
    assert!(!app.state().lock.ready());
    quick(&mut app, &[Input::Turn(-9)]);
    assert_eq!(app.state().lock.steps, 0);
}

#[test]
fn keys_do_nothing_while_locked() {
    let mut app = app!();
    // Ridge Medic, its draft being written.
    run(&mut app, &[Input::Press, Input::Enter]);
    lock(&mut app);
    run(&mut app, &typed("hi"));
    run(&mut app, &[Input::Enter, Input::Backspace, Input::Space]);
    assert!(app.state().lock.locked);
    assert_eq!(draft(app.state(), RIDGE), RIDGE_DRAFT);
}

#[test]
fn messages_while_locked_are_listed_newest_first_and_call_for_attention() {
    let store = store();
    let mut app = app!(store);
    lock(&mut app);
    assert!(arrive(&mut app, store, 1000));
    assert!(arrive(&mut app, store, 2000));
    assert!(arrive(&mut app, store, 3000));
    assert_eq!(app.state().banner, None);
    assert_eq!(
        arrived(app.state()),
        [
            (JO, "Are you on the ridge yet?".to_owned()),
            (PAT, "Got the antenna. Bringing two.".to_owned()),
            (
                TRAIL_CREW,
                "Sam: Will wait 10 min at the saddle, then we head down".to_owned()
            ),
        ]
    );
    // A muted chat is listed, and calls for nothing.
    assert!(!arrive_in(&mut app, store, 4, "Mill Creek is clear", 4000));
    assert_eq!(app.state().arrived[0].chat, 4);
    // Unlocking lets them go; the chats wait at the top of the list.
    quick(&mut app, &[Input::Turn(5), Input::Press]);
    assert!(!app.state().lock.locked);
    assert!(app.state().arrived.is_empty());
    assert_eq!(app.state().chats[0].id, 4);
}

#[test]
fn a_message_just_after_going_dark_locks_at_once() {
    let store = store();
    let mut app = app!(store);
    // Reading Ridge Medic when the panel goes dark: a message there is
    // not being read.
    run(&mut app, &[Input::Press]);
    app.state_mut().screen_off(5000);
    assert!(arrive_in(&mut app, store, RIDGE, "Coffee's on", 5100));
    assert!(app.state().lock.locked);
    assert!(app.state().chats[0].unread);
    assert_eq!(arrived(app.state()), [(RIDGE, "Coffee's on".to_owned())]);
}

#[test]
fn turning_with_alt_held_while_locked_sets_brightness_not_the_bar() {
    let mut app = app!();
    let level = |app: &App<_, State, _>| brightness_level(app.state().node.brightness());
    let before = level(&app);
    lock(&mut app);
    quick(
        &mut app,
        &[
            Input::Modifier {
                modifier: Modifier::Alt,
                down: true,
            },
            Input::Turn(-2),
            Input::Modifier {
                modifier: Modifier::Alt,
                down: false,
            },
        ],
    );
    assert_eq!(app.state().lock.steps, 0);
    assert_eq!(level(&app), before + 2);
}

#[test]
fn a_channel_send_ends_at_sent() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_in_conversation(app.state(), TRAIL_CREW);
    run(&mut app, &[Input::Enter]);
    run(&mut app, &typed("Switchbacks, 15 min out"));
    run(&mut app, &[Input::Enter]);
    let conversation = app.state().conversation.as_ref().expect("a chat is open");
    let sent = conversation.messages.last().expect("the message sent");
    assert_eq!(sent.text.as_str(), "Switchbacks, 15 min out");
    // Multicast has no acknowledgment to wait for.
    assert_eq!(sent.delivery, Delivery::Sent);
}

/// Opens the actions of the Trail Crew message `back` from its newest, and
/// presses View member.
fn view_member<V, F>(app: &mut App<V, State, F>, back: i8)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    run(app, &[Input::Turn(1), Input::Press]);
    assert_in_conversation(app.state(), TRAIL_CREW);
    run(app, &[Input::Turn(-back), Input::Press, Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::VIEW_MEMBER));
    run(app, &[Input::Press]);
}

#[test]
fn a_member_not_yet_known_offers_to_request_their_identity() {
    let mut app = app!();
    view_member(&mut app, 2);
    let Screen::Member {
        from: MemberFrom::Message(message),
        member,
        ..
    } = app.state().screen()
    else {
        panic!("expected a member, got {:?}", app.state().screen());
    };
    let message = *message;
    assert_eq!(member.hint.as_str(), "4Fz*");
    assert_eq!(member.address, None);
    assert_eq!(focus(app.state()), Some(keys::REQUEST_IDENTITY));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::message(message)));
    assert_eq!(actions(app.state()), None);
}

#[test]
fn a_known_member_shows_their_address() {
    let mut app = app!();
    view_member(&mut app, 1);
    let Screen::Member { member, .. } = app.state().screen() else {
        panic!("expected a member, got {:?}", app.state().screen());
    };
    assert_eq!(member.sender.name.as_str(), "Sam");
    assert!(member.address.is_some());
    assert_eq!(focus(app.state()), Some(keys::MESSAGE_MEMBER));
}

#[test]
fn a_peer_message_has_no_member_to_view() {
    let mut app = app!();
    run(&mut app, &[Input::Press, Input::Turn(-3), Input::Press]);
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::DETAILS));
}

/// Member 4Fz*'s message, which others have reacted to with 👍 and ‼.
const BEHIND_YOU: u32 = (TRAIL_CREW << 8) | 1;

#[test]
fn changing_my_reaction_moves_it_between_shared_chips() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(1), Input::Press, Input::Turn(-2)]);
    assert_eq!(focus(app.state()), Some(keys::message(BEHIND_YOU)));
    let on = |reaction: Reaction| {
        let step = Reaction::ALL
            .iter()
            .position(|&r| r == reaction)
            .expect("in the palette");
        [
            Input::Press,
            Input::Turn(-(Reaction::ALL.len() as i8 - step as i8)),
            Input::Press,
        ]
    };
    run(&mut app, &on(Reaction::ThumbsUp));
    assert_eq!(
        reactions(app.state(), BEHIND_YOU),
        [(Reaction::ThumbsUp, 2, true), (Reaction::Exclaim, 1, false)]
    );
    run(&mut app, &on(Reaction::Exclaim));
    assert_eq!(
        reactions(app.state(), BEHIND_YOU),
        [(Reaction::ThumbsUp, 1, false), (Reaction::Exclaim, 2, true)]
    );
}

fn shown_member(state: &State) -> (&umsh_ux_communicator::model::Member, bool) {
    match state.screen() {
        Screen::Member {
            member, requested, ..
        } => (member, *requested),
        other => panic!("expected a member, got {other:?}"),
    }
}

#[test]
fn an_identity_that_arrives_names_the_member_everywhere() {
    let store = store();
    let mut app = app!(store);
    view_member(&mut app, 2);
    assert!(!store.answer_identity(), "nothing asked yet");
    run(&mut app, &[Input::Press]);
    assert!(shown_member(app.state()).1, "requested");
    assert!(store.answer_identity());
    input::events(&mut app, 0);

    let (member, _) = shown_member(app.state());
    assert_eq!(member.sender.name.as_str(), "Robin Hale");
    assert_eq!(member.hint.as_str(), "4FzR");
    assert!(member.address.is_some());
    assert_eq!(focus(app.state()), Some(keys::MESSAGE_MEMBER));
    let conversation = app.state().conversation.as_ref().expect("a chat is open");
    let sender = conversation.messages.iter().find(|m| m.id == BEHIND_YOU);
    assert_eq!(
        sender
            .and_then(|m| m.sender.as_ref())
            .map(|s| s.name.as_str()),
        Some("Robin Hale")
    );
}

#[test]
fn save_peer_goes_once_saved_and_message_opens_a_direct_chat() {
    let mut app = app!();
    view_member(&mut app, 1);
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::SAVE_PEER));
    run(&mut app, &[Input::Press]);
    assert!(shown_member(app.state()).0.saved);
    assert_eq!(
        app.state().peers.first().map(|p| p.name.as_str()),
        Some("Sam")
    );
    assert_eq!(focus(app.state()), Some(keys::MESSAGE_MEMBER));

    run(&mut app, &[Input::Press]);
    let chat = match app.state().screen() {
        Screen::Conversation { chat, .. } => *chat,
        other => panic!("expected a conversation, got {other:?}"),
    };
    assert_eq!(app.state().chat(chat).map(|c| c.name.as_str()), Some("Sam"));
    assert_eq!(app.state().chats.first().map(|c| c.id), Some(chat));
    assert_in_conversation(app.state(), chat);
    // Back goes to the list, at the new chat's row.
    run(&mut app, &[Input::Backspace]);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(focus(app.state()), Some(keys::chat(chat)));
}

/// Jo's invitation to Base Camp.
const INVITE: u32 = (JO << 8) | 2;

/// Opens Jo's chat, `row` down the list, and turns up to the invitation, through the tall
/// message, which the wheel scrolls through first.
fn to_invite<V, F>(app: &mut App<V, State, F>, row: i8)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    run(app, &[Input::Turn(row), Input::Press]);
    assert_in_conversation(app.state(), JO);
    for _ in 0..20 {
        if focus(app.state()) == Some(keys::message(INVITE)) {
            return;
        }
        run(app, &[Input::Turn(-1)]);
    }
    panic!("never reached the invitation: {:?}", focus(app.state()));
}

fn joined_chat(state: &State) -> u32 {
    match state.screen() {
        Screen::Conversation { chat, .. } => *chat,
        other => panic!("expected a conversation, got {other:?}"),
    }
}

#[test]
fn an_invitation_offers_joining_first_and_join_opens_the_channel() {
    let mut app = app!();
    to_invite(&mut app, 4);
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::JOIN));
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Join { .. }));
    assert_eq!(focus(app.state()), Some(keys::JOIN_CHANNEL));
    // Nothing is joined until Join channel.
    let before = app.state().chats.len();
    run(&mut app, &[Input::Backspace]);
    assert_eq!(app.state().chats.len(), before);
    assert_eq!(focus(app.state()), Some(keys::message(INVITE)));

    run(&mut app, &[Input::Press, Input::Press, Input::Press]);
    let chat = joined_chat(app.state());
    assert_in_conversation(app.state(), chat);
    let summary = app.state().chat(chat).expect("joined");
    assert_eq!(summary.name.as_str(), "Base Camp");
    assert_eq!(
        summary.kind,
        ChatKind::Channel {
            access: ChannelAccess::Private
        }
    );
    assert_eq!(app.state().chats.first().map(|c| c.id), Some(chat));

    // Joining again opens the same channel.
    run(&mut app, &[Input::Backspace]);
    // The channel heads the list now, above Jo.
    run(&mut app, &[Input::Turn(-20)]);
    to_invite(&mut app, 5);
    run(&mut app, &[Input::Press, Input::Press, Input::Press]);
    assert_eq!(joined_chat(app.state()), chat);
    assert_eq!(app.state().chats.len(), before + 1);
}

#[test]
fn a_channel_joined_can_be_called_something_else_here() {
    let mut app = app!();
    to_invite(&mut app, 4);
    run(&mut app, &[Input::Press, Input::Press, Input::Turn(-1)]);
    assert_eq!(focus(app.state()), Some(keys::JOIN_NAME));
    run(&mut app, &[Input::Press]);
    run(&mut app, &[Input::Backspace; 4]);
    run(&mut app, &typed("Hut"));
    run(&mut app, &[Input::Enter, Input::Turn(1), Input::Press]);
    let chat = joined_chat(app.state());
    assert_eq!(
        app.state().chat(chat).map(|c| c.name.as_str()),
        Some("Base Hut")
    );
}

const EMERGENCY: u32 = 6;

#[test]
fn emergency_is_open_and_its_sends_end_at_sent() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(5), Input::Press]);
    assert_in_conversation(app.state(), EMERGENCY);
    let kind = app
        .state()
        .chat(EMERGENCY)
        .expect("joined from the start")
        .kind;
    assert_eq!(
        kind,
        ChatKind::Channel {
            access: ChannelAccess::Clear
        }
    );
    assert!(kind.is_open());
    run(&mut app, &[Input::Enter]);
    run(&mut app, &typed("Heading down"));
    run(&mut app, &[Input::Enter]);
    let conversation = app.state().conversation.as_ref().expect("a chat is open");
    assert_eq!(
        conversation.messages.last().map(|m| m.delivery),
        Some(Delivery::Sent)
    );
}

#[test]
fn the_rail_switches_to_peers_which_open_on_add_peer() {
    let mut app = app!();
    run(&mut app, &[Input::Backspace, Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::rail(Section::Peers)));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().section, Section::Peers);
    assert_eq!(focus(app.state()), Some(keys::ADD_PEER));
    run(&mut app, &[Input::Turn(1)]);
    let first = app.state().peers.first().map(|p| keys::peer(p.id));
    assert_eq!(focus(app.state()), first);
    // Back on the rail, and into Chats, at its first chat.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::rail(Section::Peers)));
    run(&mut app, &[Input::Turn(-1), Input::Press]);
    assert_eq!(app.state().section, Section::Chats);
    assert_eq!(focus(app.state()), Some(keys::chat(RIDGE)));
}

#[test]
fn add_peer_unlocks_message_once_the_address_is_whole() {
    use umsh_ux_communicator::model::PeerEntry;
    let mut app = app!();
    run(
        &mut app,
        &[Input::Backspace, Input::Turn(1), Input::Press, Input::Press],
    );
    assert!(matches!(app.state().screen(), Screen::AddPeer { .. }));
    assert_eq!(focus(app.state()), Some(keys::PEER_FIELD));
    run(&mut app, &typed("7cQRwjEyMJRDQCrtkgvaKiXfJ2CrUi"));
    assert!(matches!(
        app.state().peer_entry(),
        PeerEntry::Partial {
            avatar: Some(_),
            missing: 14,
            ..
        }
    ));
    // Not whole: Enter only ends the edit, and Message cannot be reached.
    run(&mut app, &[Input::Enter, Input::Turn(1)]);
    assert!(matches!(app.state().screen(), Screen::AddPeer { .. }));
    assert_ne!(focus(app.state()), Some(keys::MESSAGE_PEER));

    run(&mut app, &[Input::Turn(-1)]);
    run(&mut app, &typed("8pTn4kWsYbHd9e"));
    assert!(matches!(
        app.state().peer_entry(),
        PeerEntry::Complete { .. }
    ));
    run(&mut app, &[Input::Enter]);
    let chat = joined_chat(app.state());
    assert_in_conversation(app.state(), chat);
    assert_eq!(
        app.state().chat(chat).map(|c| c.name.as_str()),
        Some("7cQR")
    );
    assert_eq!(app.state().section, Section::Chats);
}

#[test]
fn add_peer_reads_an_invitation_and_refuses_what_is_not_an_address() {
    use umsh_ux_communicator::model::PeerEntry;
    let mut app = app!();
    run(
        &mut app,
        &[Input::Backspace, Input::Turn(1), Input::Press, Input::Press],
    );
    run(
        &mut app,
        &typed("umsh:n:7cQRwjEyMJRDQCrtkgvaKiXfJ2CrUi8pTn4kWsYbHd9e"),
    );
    assert!(matches!(
        app.state().peer_entry(),
        PeerEntry::Complete { .. }
    ));
    run(&mut app, &[Input::Backspace; 51]);
    run(&mut app, &typed("0O"));
    assert_eq!(app.state().peer_entry(), PeerEntry::Invalid);
}

fn peer_detail(state: &State) -> &umsh_ux_communicator::model::PeerDetail {
    match state.screen() {
        Screen::Peer { detail, .. } => detail,
        other => panic!("expected a peer, got {other:?}"),
    }
}

/// Opens the first saved peer, Pat Okafor, from the Peers list.
fn open_pat<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    run(
        app,
        &[
            Input::Backspace,
            Input::Turn(1),
            Input::Press,
            Input::Turn(1),
            Input::Press,
        ],
    );
    assert_eq!(focus(app.state()), Some(keys::PEER_MESSAGE));
}

#[test]
fn a_saved_peer_shows_its_detail_and_messages_in_its_own_chat() {
    let mut app = app!();
    open_pat(&mut app);
    assert!(peer_detail(app.state()).address.starts_with("YmRG"));
    run(&mut app, &[Input::Press]);
    assert_in_conversation(app.state(), PAT);
}

#[test]
fn forward_secrecy_switches_and_a_ping_is_answered() {
    let mut app = app!();
    open_pat(&mut app);
    run(&mut app, &[Input::Turn(3)]);
    assert_eq!(focus(app.state()), Some(keys::PEER_SECRECY));
    run(&mut app, &[Input::Press]);
    assert!(peer_detail(app.state()).forward_secrecy);
    run(&mut app, &[Input::Press]);
    assert!(!peer_detail(app.state()).forward_secrecy);
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(peer_detail(app.state()).ping.as_deref(), Some("1.4 s"));
}

#[test]
fn a_saved_peer_is_asked_for_their_identity() {
    let mut app = app!();
    open_pat(&mut app);
    run(&mut app, &[Input::Turn(5)]);
    assert_eq!(focus(app.state()), Some(keys::PEER_IDENTITY));
    assert!(matches!(
        app.state().screen(),
        Screen::Peer {
            requested: false,
            ..
        }
    ));
    run(&mut app, &[Input::Press]);
    assert!(matches!(
        app.state().screen(),
        Screen::Peer {
            requested: true,
            ..
        }
    ));
    assert_eq!(focus(app.state()), Some(keys::PEER_IDENTITY));
}

#[test]
fn forget_asks_first_and_cancel_keeps_the_peer() {
    let mut app = app!();
    open_pat(&mut app);
    let peers = app.state().peers.len();
    run(&mut app, &[Input::Turn(6)]);
    assert_eq!(focus(app.state()), Some(keys::PEER_FORGET));
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::FORGET_CANCEL));
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::PEER_FORGET));
    assert_eq!(app.state().peers.len(), peers);

    run(&mut app, &[Input::Press, Input::Turn(-1), Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(app.state().peers.len(), peers - 1);
    // The row that took its place is focused.
    let next = app.state().peers.first().map(|p| keys::peer(p.id));
    assert_eq!(focus(app.state()), next);
}

fn radio(state: &State) -> &umsh_ux_communicator::model::RadioSettings {
    match state.screen() {
        Screen::Device {
            page: DevicePage::Radio { settings },
            ..
        } => settings,
        other => panic!("expected Radio, got {other:?}"),
    }
}

/// Opens Device › Radio from the Chats list.
fn open_radio<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    run(app, &[Input::Backspace, Input::Turn(2), Input::Press]);
    assert_eq!(app.state().section, Section::Device);
    assert_eq!(focus(app.state()), Some(keys::IDENTITY));
    run(app, &[Input::Turn(2), Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::PROFILE));
}

fn on_profiles(state: &State) -> bool {
    matches!(
        state.screen(),
        Screen::Device {
            page: DevicePage::Profiles,
            ..
        }
    )
}

#[test]
fn a_profile_is_chosen_from_the_list_and_backspace_cancels() {
    let mut app = app!();
    open_radio(&mut app);
    assert_eq!(radio(app.state()).profile, Profile::Vetted(0));
    run(&mut app, &[Input::Press]);
    assert!(on_profiles(app.state()));
    assert_eq!(focus(app.state()), Some(keys::profile(0)));
    run(&mut app, &[Input::Turn(1), Input::Backspace]);
    assert_eq!(radio(app.state()).profile, Profile::Vetted(0));
    assert_eq!(focus(app.state()), Some(keys::PROFILE));

    run(&mut app, &[Input::Press, Input::Turn(2), Input::Press]);
    assert_eq!(radio(app.state()).profile, Profile::Vetted(2));
    assert_eq!(focus(app.state()), Some(keys::PROFILE));
    // Opened again, the list starts at the profile chosen.
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::profile(2)));
    run(&mut app, &[Input::Backspace]);

    // Back returns to Radio's category, and again to the rail.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::RADIO));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::rail(Section::Device)));
}

#[test]
fn every_profile_of_a_long_list_can_be_reached() {
    let mut app = app!();
    let count = app.state().node.profile_count();
    assert!(count > 12, "the list is longer than its window");
    open_radio(&mut app);
    run(&mut app, &[Input::Press]);
    // One detent at a time down the whole list, and past its end.
    for _ in 0..count {
        run(&mut app, &[Input::Turn(1)]);
    }
    assert_eq!(focus(app.state()), Some(keys::profile(count - 1)));
    run(&mut app, &[Input::Press]);
    assert_eq!(radio(app.state()).profile, Profile::Vetted(count - 1));
    // And from there back to the top, opened at the last.
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::profile(count - 1)));
    for _ in 0..count {
        run(&mut app, &[Input::Turn(-1)]);
    }
    assert_eq!(focus(app.state()), Some(keys::profile(0)));
}

#[test]
fn settings_no_profile_has_read_as_custom() {
    let store = store();
    let mut app = app!(store);
    open_radio(&mut app);
    store.set_custom_radio();
    input::events(&mut app, 0);
    assert_eq!(radio(app.state()).profile, Profile::Custom);
    assert_eq!(app.state().profile_name(radio(app.state())), "Custom");
    // The list has no Custom to choose: it opens at its first.
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::profile(0)));
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(radio(app.state()).profile, Profile::Vetted(1));
}

#[test]
fn a_switch_flips_on_press() {
    let mut app = app!();
    open_radio(&mut app);
    run(&mut app, &[Input::Turn(3)]);
    assert_eq!(focus(app.state()), Some(keys::SHARE_LOCATION));
    assert!(!radio(app.state()).share_location);
    run(&mut app, &[Input::Press]);
    assert!(radio(app.state()).share_location);
    run(&mut app, &[Input::Turn(-1), Input::Press]);
    assert!(!radio(app.state()).forwarding);
}

#[test]
fn turning_on_share_moves_between_this_node_and_its_channels() {
    let mut app = app!();
    run(
        &mut app,
        &[Input::Backspace, Input::Turn(2), Input::Press, Input::Press],
    );
    assert!(matches!(
        app.state().screen(),
        Screen::Device {
            page: DevicePage::Share,
            ..
        }
    ));
    assert_eq!(app.state().shared(), Shareable::Identity);
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(app.state().shared(), Shareable::Channel(2));
    run(&mut app, &[Input::Turn(2)]);
    assert_eq!(app.state().shared(), Shareable::Channel(6));
    // The last stays put.
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(app.state().shared(), Shareable::Channel(6));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::IDENTITY));
}

/// Opens Device › Channels › Add channel from the Chats list.
fn open_add_channel<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    run(
        app,
        &[
            Input::Backspace,
            Input::Turn(2),
            Input::Press,
            Input::Turn(1),
            Input::Press,
        ],
    );
    assert_eq!(focus(app.state()), Some(keys::ADD_CHANNEL));
    run(app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CHANNEL_FIELD));
}

#[test]
fn a_channel_name_joins_a_named_channel() {
    let mut app = app!();
    open_add_channel(&mut app);
    assert_eq!(app.state().channel_entry(), ChannelEntry::Empty);
    run(&mut app, &typed("Ridge Runners"));
    assert_eq!(app.state().channel_entry(), ChannelEntry::Named);
    run(&mut app, &[Input::Enter]);
    let chat = app.state().chats[0].id;
    assert_eq!(app.state().chats[0].name.as_str(), "Ridge Runners");
    assert_eq!(
        app.state().chats[0].kind,
        ChatKind::Channel {
            access: ChannelAccess::Named
        }
    );
    assert_in_conversation(app.state(), chat);
}

#[test]
fn an_invitation_counts_down_and_joins_a_private_channel() {
    let mut app = app!();
    open_add_channel(&mut app);
    run(
        &mut app,
        &typed("umsh:ck:5BFn8YGKJ6pZR4qV3tW7mNhDrXsCxEaL9kUv2wAjT"),
    );
    assert_eq!(
        app.state().channel_entry(),
        ChannelEntry::Partial { missing: 3 }
    );
    // Join is not there to press yet.
    run(&mut app, &[Input::Enter, Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::CHANNEL_FIELD));
    run(&mut app, &[Input::Press]);
    run(&mut app, &typed("8bP?n=Base%20Camp"));
    assert_eq!(app.state().channel_entry(), ChannelEntry::Private);
    run(&mut app, &[Input::Enter]);
    assert_eq!(app.state().chats[0].name.as_str(), "Base Camp");
    assert_in_conversation(app.state(), app.state().chats[0].id);
}

#[test]
fn a_joined_channel_opens_from_the_channels_list() {
    let mut app = app!();
    open_add_channel(&mut app);
    run(&mut app, &[Input::Backspace, Input::Turn(1), Input::Press]);
    // Trail Crew, the first channel in the list.
    assert_in_conversation(app.state(), 2);
}

#[test]
fn low_battery_says_so_once_without_taking_a_key() {
    let mut app = app!();
    // Typing in Ridge Medic.
    run(&mut app, &[Input::Press, Input::Enter]);
    app.state_mut().battery(Some(11), false, 0);
    assert!(!app.state().status.battery_low);
    app.state_mut().battery(Some(9), false, 1000);
    app.finalize_view();
    assert!(app.state().status.battery_low);
    assert_eq!(app.state().status.battery_segments, 0);
    let banner = app.state().banner.expect("a banner");
    assert_eq!(banner.notice, Notice::BatteryLow { percent: 9 });
    run(&mut app, &typed("!"));
    assert!(draft(app.state(), RIDGE).ends_with('!'));
    app.state_mut().expire(banner.until);
    assert_eq!(app.state().banner, None);
    // The strip keeps saying it, and wavering does not say it again.
    app.state_mut().battery(Some(11), false, 6000);
    app.state_mut().battery(Some(9), false, 7000);
    assert!(app.state().status.battery_low);
    assert_eq!(app.state().banner, None);
    // Charging ends it.
    app.state_mut().battery(Some(9), true, 8000);
    assert!(!app.state().status.battery_low);
    assert!(app.state().status.charging);
}

#[test]
fn low_battery_while_dark_marks_only_the_strip() {
    let mut app = app!();
    app.state_mut().dark = true;
    app.state_mut().battery(Some(9), false, 1000);
    assert!(app.state().status.battery_low);
    assert_eq!(app.state().banner, None);
}

#[test]
fn first_run_takes_a_name_a_profile_and_a_zone_and_ends_on_the_chats() {
    let mut app = app!();
    app.state_mut().start_setup();
    app.finalize_view();
    assert!(app.state().in_setup());
    assert_eq!(focus(app.state()), Some(keys::NAME_FIELD));
    // Backspace has nothing to go back to.
    run(&mut app, &[Input::Backspace]);
    assert!(app.state().in_setup());
    run(&mut app, &typed("Wren"));
    run(&mut app, &[Input::Enter]);
    assert_eq!(app.state().status.device_name.as_str(), "Wren");
    assert_eq!(app.state().node.device_name().as_str(), "Wren");
    assert_eq!(focus(app.state()), Some(keys::profile(0)));
    // Back to the name, and on again.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::NAME_FIELD));
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::profile(0)));
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(app.state().node.radio().profile, Profile::Vetted(1));
    // The zone, starting on the one set.
    assert!(app.state().in_setup());
    let utc = zones::find(&Rule::UTC).unwrap();
    assert_eq!(focus(app.state()), Some(keys::zone(utc)));
    run(&mut app, &typed("pac"));
    let pacific = zones::ZONES
        .iter()
        .position(|z| z.name == "Pacific Time")
        .unwrap();
    assert_eq!(focus(app.state()), Some(keys::zone(pacific)));
    run(&mut app, &[Input::Press]);
    assert!(!app.state().in_setup());
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(app.state().clock.zone.std_offset_min(), -480);
}

#[test]
fn typing_on_the_list_finds_and_enter_opens_the_top_result() {
    let mut app = app!();
    run(&mut app, &typed("ri"));
    assert_eq!(focus(app.state()), Some(keys::FIND_FIELD));
    assert_eq!(app.state().find_query(), Some("ri"));
    let (found, count) = app.state().found();
    // Ridge Medic; Rick Alvarez; Riverbend Camp and Ridge Runner, heard.
    assert_eq!(count, 4);
    assert_eq!(found[0].kind, FoundKind::Chat(RIDGE));
    assert_eq!(found[1].kind, FoundKind::Peer(app.state().peers[2].id));
    assert_eq!(found[2].name.as_str(), "Riverbend Camp");
    run(&mut app, &[Input::Enter]);
    assert_in_conversation(app.state(), RIDGE);
    // Find closed behind it.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(app.state().find_query(), None);
    assert_eq!(focus(app.state()), Some(keys::chat(RIDGE)));
}

#[test]
fn backspace_ends_find_and_turning_moves_into_the_results() {
    let mut app = app!();
    run(&mut app, &typed("cr"));
    // Trail Crew matches at its second word.
    assert_eq!(app.state().found().0[0].kind, FoundKind::Chat(2));
    // Press ends the edit; turning then moves into the results.
    run(&mut app, &[Input::Press, Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::found(0)));
    run(&mut app, &[Input::Press]);
    assert_in_conversation(app.state(), 2);
    run(&mut app, &[Input::Backspace]);
    // Typing again and erasing it all, then Backspace closes Find.
    run(&mut app, &typed("x"));
    assert_eq!(app.state().found().1, 0);
    run(&mut app, &[Input::Backspace, Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::FIND_FIELD));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(app.state().find_query(), None);
    assert_eq!(focus(app.state()), Some(keys::chat(RIDGE)));
}

#[test]
fn the_strip_counts_thirds_centered_on_their_levels() {
    use umsh_ux_communicator::model::battery_segments;
    assert_eq!(battery_segments(16), 0);
    assert_eq!(battery_segments(17), 1);
    assert_eq!(battery_segments(49), 1);
    assert_eq!(battery_segments(50), 2);
    assert_eq!(battery_segments(82), 2);
    assert_eq!(battery_segments(83), 3);
    assert_eq!(battery_segments(100), 3);
}

#[test]
fn shut_down_asks_first_and_then_ends_input() {
    let mut app = app!();
    run(&mut app, &[Input::Backspace, Input::Turn(2), Input::Press]);
    run(&mut app, &[Input::Turn(9)]);
    assert_eq!(focus(app.state()), Some(keys::SHUT_DOWN));
    // Cancel is focused, and Backspace cancels too.
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::SHUT_DOWN_CANCEL));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::SHUT_DOWN));
    assert_eq!(app.state().ending, None);

    run(&mut app, &[Input::Press, Input::Turn(-1), Input::Press]);
    assert_eq!(app.state().ending, Some(Ending::ShuttingDown));
    // Nothing moves under the card.
    run(&mut app, &[Input::Turn(-3), Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::SHUT_DOWN));
}

/// A key of the Pager's keyboard: its letter, and its top-row digit under
/// Alt where it has one.
fn key(plain: char) -> Input {
    let alt = "qwertyuiop"
        .find(plain)
        .map(|i| char::from(b"1234567890"[i]));
    Input::Key { plain, alt }
}

fn keys_for(text: &str) -> Vec<Input> {
    text.chars()
        .map(|c| if c == ' ' { Input::Space } else { key(c) })
        .collect()
}

fn tap(modifier: Modifier) -> [Input; 2] {
    [
        Input::Modifier {
            modifier,
            down: true,
        },
        Input::Modifier {
            modifier,
            down: false,
        },
    ]
}

/// Opens Trail Crew, whose draft is empty, its composer focused.
fn open_trail_crew<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    run(app, &[Input::Turn(1), Input::Press]);
    assert_in_conversation(app.state(), TRAIL_CREW);
    assert_eq!(draft(app.state(), TRAIL_CREW), "");
}

#[test]
fn a_message_starts_with_a_capital_and_two_quick_spaces_end_a_sentence() {
    let mut app = app!();
    open_trail_crew(&mut app);
    run(&mut app, &keys_for("on my way"));
    quick(&mut app, &[Input::Space, Input::Space]);
    assert_eq!(draft(app.state(), TRAIL_CREW), "On my way. ");
    // The period starts a sentence, so Shift is armed again.
    assert_eq!(app.state().keyboard.latches(), (Latch::Once, Latch::Off));
    run(&mut app, &keys_for("ok"));
    assert_eq!(draft(app.state(), TRAIL_CREW), "On my way. Ok");
}

#[test]
fn the_aids_stay_off_when_switched_off() {
    let mut app = app!();
    // Device › Keyboard, Capitalize sentences and Period on double space.
    run(&mut app, &[Input::Backspace, Input::Turn(2), Input::Press]);
    run(&mut app, &[Input::Turn(5), Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CAPITALIZE));
    run(&mut app, &[Input::Press, Input::Turn(1), Input::Press]);
    let settings = app.state().node.keyboard();
    assert!(!settings.capitalize && !settings.period && settings.light);
    run(&mut app, &[Input::Backspace, Input::Backspace]);
    run(&mut app, &[Input::Turn(-2), Input::Press]);

    open_trail_crew(&mut app);
    run(&mut app, &keys_for("on"));
    quick(&mut app, &[Input::Space, Input::Space]);
    assert_eq!(draft(app.state(), TRAIL_CREW), "on  ");
}

#[test]
fn caps_lock_and_alt_type_capitals_and_symbols() {
    let mut app = app!();
    open_trail_crew(&mut app);
    // Alt then Shift is caps lock.
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &tap(Modifier::Shift));
    assert_eq!(app.state().keyboard.latches(), (Latch::Locked, Latch::Off));
    run(&mut app, &keys_for("hut"));
    run(&mut app, &tap(Modifier::Shift));
    // Alt, once: the next key types its digit.
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &keys_for("qq"));
    assert_eq!(draft(app.state(), TRAIL_CREW), "HUT1q");
}

#[test]
fn alt_then_space_opens_the_picker_and_a_press_types_from_it() {
    let mut app = app!();
    open_trail_crew(&mut app);
    run(&mut app, &keys_for("a"));
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &[Input::Space]);
    assert_eq!(app.state().picker, Some(0));
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(app.state().picker, None);
    assert_eq!(draft(app.state(), TRAIL_CREW), format!("A{}", PICKER[1]));
    // The field is still being edited.
    run(&mut app, &keys_for("b"));
    assert_eq!(draft(app.state(), TRAIL_CREW), format!("A{}b", PICKER[1]));

    // Space in the picker switches the keyboard light instead.
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &[Input::Space, Input::Space]);
    assert_eq!(app.state().picker, None);
    assert!(!app.state().node.keyboard().light);
    assert!(matches!(
        app.state().glance,
        Some(Glance::KeyboardLight { on: false, .. })
    ));
}

#[test]
fn alt_and_two_quick_spaces_switch_the_keyboard_light_anywhere() {
    let mut app = app!();
    // On the Chats list, with no field: Alt+Space alone does nothing.
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &[Input::Space]);
    assert_eq!(app.state().picker, None);
    assert!(app.state().node.keyboard().light);
    // Held Alt, then one-shot Alt, each with two quick spaces.
    quick(
        &mut app,
        &[
            Input::Modifier {
                modifier: Modifier::Alt,
                down: true,
            },
            Input::Space,
            Input::Space,
            Input::Modifier {
                modifier: Modifier::Alt,
                down: false,
            },
        ],
    );
    assert!(!app.state().node.keyboard().light);
    assert!(matches!(
        app.state().glance,
        Some(Glance::KeyboardLight { on: false, .. })
    ));
    run(&mut app, &tap(Modifier::Alt));
    quick(&mut app, &[Input::Space, Input::Space]);
    assert!(app.state().node.keyboard().light);
    assert_eq!(focus(app.state()), Some(keys::chat(RIDGE)));
}

#[test]
fn turning_with_alt_held_sets_brightness() {
    let mut app = app!();
    let level = || brightness_level(app.state().node.brightness());
    let before = level();
    run(
        &mut app,
        &[
            Input::Modifier {
                modifier: Modifier::Alt,
                down: true,
            },
            Input::Turn(-2),
            Input::Modifier {
                modifier: Modifier::Alt,
                down: false,
            },
        ],
    );
    assert_eq!(brightness_level(app.state().node.brightness()), before + 2);
    assert!(
        matches!(app.state().glance, Some(Glance::Brightness { level, .. }) if level == before + 2)
    );
    // Focus did not move, and letting go of Alt armed nothing.
    assert_eq!(focus(app.state()), Some(keys::chat(RIDGE)));
    assert_eq!(app.state().keyboard.latches(), (Latch::Off, Latch::Off));
}

#[test]
fn transmit_power_is_typed_in_symbol_lock() {
    let mut app = app!();
    open_radio(&mut app);
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::POWER_FIELD));
    assert_eq!(app.state().keyboard.latches(), (Latch::Off, Latch::Locked));
    // The field holds 22; a key types its digit.
    run(&mut app, &[key('q')]);
    assert!(matches!(
        app.state().screen(),
        Screen::Device { page: DevicePage::TransmitPower { text }, .. } if text.text() == "221"
    ));
    // Too much for the radio: the field stays to be corrected.
    run(&mut app, &[Input::Enter]);
    assert_eq!(focus(app.state()), Some(keys::POWER_FIELD));
    assert_eq!(app.state().keyboard.latches(), (Latch::Off, Latch::Locked));
    run(
        &mut app,
        &[
            key('q'),
            Input::Backspace,
            Input::Backspace,
            Input::Backspace,
            Input::Backspace,
        ],
    );
    run(&mut app, &[key('r'), Input::Enter]);
    assert_eq!(radio(app.state()).transmit_power, 4);
    assert_eq!(focus(app.state()), Some(keys::TRANSMIT_POWER));
}

#[test]
fn transmit_power_takes_only_a_number() {
    let mut app = app!();
    open_radio(&mut app);
    run(&mut app, &[Input::Turn(1), Input::Press]);
    let tap = |modifier| {
        [
            Input::Modifier {
                modifier,
                down: true,
            },
            Input::Modifier {
                modifier,
                down: false,
            },
        ]
    };
    // Alt and Shift leave symbol lock on; what is not part of a number,
    // from a key without one, Space, or a host's keyboard, types nothing.
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &tap(Modifier::Shift));
    assert_eq!(app.state().keyboard.latches(), (Latch::Off, Latch::Locked));
    run(
        &mut app,
        &[
            Input::Key {
                plain: 'a',
                alt: Some('*'),
            },
            Input::Space,
            Input::Character('x'),
            Input::Key {
                plain: 'f',
                alt: Some('-'),
            },
            key('w'),
        ],
    );
    assert!(matches!(
        app.state().screen(),
        Screen::Device { page: DevicePage::TransmitPower { text }, .. } if text.text() == "22-2"
    ));
}

#[test]
fn ages_count_to_the_wall_clock() {
    use umsh_ux_communicator::model::age;
    let at = Some(1_000_000);
    assert_eq!(age(at, Some(1_000_059)).as_str(), "now");
    assert_eq!(age(at, Some(1_000_060)).as_str(), "1m");
    assert_eq!(age(at, Some(1_000_000 + 3 * 3600 + 5)).as_str(), "3h");
    assert_eq!(age(at, Some(1_000_000 + 2 * 86_400)).as_str(), "2d");
    assert_eq!(age(at, Some(1_000_000 + 21 * 86_400)).as_str(), "3w");
    assert_eq!(age(at, Some(1_000_000 + 800 * 86_400)).as_str(), "2y");
    // A clock set back is not a time to come.
    assert_eq!(age(at, Some(999_000)).as_str(), "now");
    assert_eq!(age(None, Some(1_000_000)).as_str(), "");
    assert_eq!(age(at, None).as_str(), "");

    // The list's ages move on with the clock.
    let mut app = app!();
    let ridge = app.state().chat(RIDGE).expect("listed").clone();
    assert_eq!(app.state().age(&ridge).as_str(), "2m");
    let later = app.state().wall_time.map(|t| t + 60);
    app.state_mut().set_wall_time(later);
    assert_eq!(app.state().age(&ridge).as_str(), "3m");
}

#[test]
fn brightness_levels_cover_the_whole_range() {
    use umsh_ux_communicator::model::{BRIGHTNESS_LEVELS, brightness_at};
    assert_eq!(brightness_at(1), 0);
    assert_eq!(brightness_at(BRIGHTNESS_LEVELS), 255);
    for level in 1..=BRIGHTNESS_LEVELS {
        assert_eq!(brightness_level(brightness_at(level)), level);
    }
    assert_eq!(brightness_level(0), 1);
    assert_eq!(brightness_level(255), BRIGHTNESS_LEVELS);
}

#[test]
fn events_keep_one_of_each_and_overflow_to_a_resync() {
    use umsh_ux_communicator::model::EventQueue;
    let mut queue: EventQueue<4> = EventQueue::new();
    queue.push(NodeEvent::ChatChanged(1));
    queue.push(NodeEvent::Airtime { wait: Some(30) });
    queue.push(NodeEvent::ChatChanged(2));
    // The same again moves to the back, carrying what it says now.
    queue.push(NodeEvent::ChatChanged(1));
    queue.push(NodeEvent::Airtime { wait: None });
    assert_eq!(queue.pop(), Some(NodeEvent::ChatChanged(2)));
    assert_eq!(queue.pop(), Some(NodeEvent::ChatChanged(1)));
    assert_eq!(queue.pop(), Some(NodeEvent::Airtime { wait: None }));
    assert_eq!(queue.pop(), None);

    for chat in 0..5 {
        queue.push(NodeEvent::ChatChanged(chat));
    }
    assert_eq!(queue.pop(), Some(NodeEvent::Resync));
    assert!(queue.is_empty());
}

#[test]
fn a_resync_reads_everything_again_and_keeps_the_draft_being_written() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2), Input::Press]);
    // Typing, the cursor two back from the end.
    run(&mut app, &typed("Bring"));
    run(&mut app, &[Input::Turn(-2)]);
    let before = app.state().conversation.as_ref().map(|c| c.messages.len());
    let chats = app.state().chats.len();
    app.state_mut().apply(NodeEvent::Resync, 0);
    app.finalize_view();
    assert_in_conversation(app.state(), PAT);
    assert_eq!(draft(app.state(), PAT), "Bring");
    assert_eq!(
        app.state().conversation.as_ref().map(|c| c.messages.len()),
        before
    );
    assert_eq!(app.state().chats.len(), chats);
    assert_eq!(draft(app.state(), RIDGE), RIDGE_DRAFT);
    // Typing goes on where it was.
    run(&mut app, &typed("i"));
    assert_eq!(draft(app.state(), PAT), "Briing");
}

#[test]
fn a_draft_left_unsent_is_kept_by_the_node() {
    let mut app = app!();
    run(&mut app, &[Input::Turn(2), Input::Press]);
    run(&mut app, &typed("Back by six"));
    run(&mut app, &[Input::Press, Input::Backspace]);
    let kept = app.state().node.chat(PAT).expect("the chat");
    assert_eq!(kept.draft.text(), "Back by six");

    // Erased to nothing but a space, it is no draft.
    run(&mut app, &[Input::Press, Input::Enter]);
    run(&mut app, &[Input::Backspace; 11]);
    run(&mut app, &typed(" "));
    run(&mut app, &[Input::Press, Input::Backspace]);
    let kept = app.state().node.chat(PAT).expect("the chat");
    assert_eq!(kept.draft.text(), "");
}

#[test]
fn opening_a_chat_marks_it_read_in_the_node() {
    let mut app = app!();
    assert!(app.state().node.chat(TRAIL_CREW).expect("the chat").unread);
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert!(!app.state().node.chat(TRAIL_CREW).expect("the chat").unread);
}

#[test]
fn a_message_arriving_in_the_chat_being_read_is_read() {
    let store = store();
    let mut app = app!(store);
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert!(!arrive(&mut app, store, 0));
    assert!(!store.chat(TRAIL_CREW).expect("the chat").unread);
    // Taken in twice, it is shown once.
    let conversation = app.state().conversation.as_ref().expect("a chat is open");
    let (count, newest) = (
        conversation.messages.len(),
        conversation.messages.last().unwrap().id,
    );
    app.state_mut().apply(
        NodeEvent::Arrived {
            chat: TRAIL_CREW,
            message: newest,
        },
        0,
    );
    assert_eq!(
        app.state().conversation.as_ref().map(|c| c.messages.len()),
        Some(count)
    );
}

#[test]
fn a_chat_gone_from_the_node_closes_and_its_row_gives_way() {
    let mut app = app!();
    run(&mut app, &[Input::Press, Input::Turn(-1)]);
    app.state_mut().apply(NodeEvent::ChatRemoved(RIDGE), 0);
    app.finalize_view();
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert!(app.state().conversation.is_none());
    assert!(app.state().chat(RIDGE).is_none());
    assert_eq!(focus(app.state()), Some(keys::chat(TRAIL_CREW)));
}

#[test]
fn a_peer_forgotten_elsewhere_leaves_its_screen() {
    let store = store();
    let mut app = app!(store);
    open_pat(&mut app);
    let pat = app.state().peers[0].id;
    store.forget_peer(pat);
    input::events(&mut app, 0);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert!(app.state().peer(pat).is_none());
    let next = app.state().peers.first().map(|p| keys::peer(p.id));
    assert_eq!(focus(app.state()), next);
}

#[test]
fn a_setting_refused_reads_back_as_it_stands() {
    let store = store();
    let mut app = app!(store);
    open_radio(&mut app);
    store.set_transmit_power(99);
    assert_eq!(
        store.next_event(),
        Some(NodeEvent::SettingRefused(
            umsh_ux_communicator::model::Setting::TransmitPower
        ))
    );
    assert_eq!(radio(app.state()).transmit_power, 22);
    // A setting applied elsewhere shows as it is applied.
    store.set_forwarding(false);
    input::events(&mut app, 0);
    assert!(!radio(app.state()).forwarding);
}

#[test]
fn an_invitation_is_its_channel_link_alone() {
    let store = store();
    let invite = store.message(JO, INVITE).expect("the invitation");
    assert!(invite.text.as_str().starts_with("umsh:ck:"));
    let mut summary = store.chat(JO).expect("the chat");
    summary.preview(&invite);
    assert_eq!(summary.preview.as_str(), "Channel invite: Base Camp");
}

#[test]
fn the_fixture_brings_arrivals_and_identities_on_its_own_clock() {
    let store = store();
    let mut app = app!(store);
    store.pace_arrivals(5000);
    store.advance(4999);
    assert!(!input::events(&mut app, 4999));
    store.advance(5000);
    assert!(input::events(&mut app, 5000));
    assert_eq!(app.state().chats[0].id, TRAIL_CREW);
    // The next comes a while after, by itself.
    assert!(store.next_deadline().is_some_and(|at| at > 5000));

    // An identity asked for arrives a moment after it is asked.
    let store = self::store();
    let mut app = app!(store);
    view_member(&mut app, 2);
    run(&mut app, &[Input::Press]);
    assert!(store.identity_asked());
    store.advance(6000);
    let at = store.next_deadline().expect("the identity is due");
    store.advance(at);
    input::events(&mut app, at);
    assert_eq!(
        shown_member(app.state()).0.sender.name.as_str(),
        "Robin Hale"
    );
}

/// Device › Clock, from the Chats list.
fn open_clock<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    run(app, &[Input::Backspace, Input::Turn(2), Input::Press]);
    run(app, &[Input::Turn(6)]);
    assert_eq!(focus(app.state()), Some(keys::CLOCK));
    run(app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CLOCK_AUTOMATIC));
}

#[test]
fn the_clock_is_set_by_hand_a_part_at_a_time() {
    let mut app = app!();
    open_clock(&mut app);
    // Automatic, Date and time is a readout and opens nothing.
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CLOCK_TIME));
    run(&mut app, &[Input::Turn(-1), Input::Press]);
    assert_eq!(app.state().clock.automatic, Some(false));
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(
        focus(app.state()),
        Some(keys::time_part(umsh_ux_communicator::nav::Part::Month))
    );
    let before = DateParts::at(app.state().local(app.state().wall_time.unwrap()));
    // Pressed, turning changes the month; pressed again, it moves on.
    run(
        &mut app,
        &[Input::Press, Input::Turn(1), Input::Press, Input::Turn(4)],
    );
    run(&mut app, &typed("05"));
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CLOCK_TIME));
    let after = DateParts::at(app.state().local(app.state().wall_time.unwrap()));
    assert_eq!(after.month, before.month % 12 + 1);
    assert_eq!(
        (after.day, after.hour, after.minute),
        (before.day, before.hour, 5)
    );
    assert_eq!(
        app.state().node.clock_source().map(|(source, _)| source),
        Some(ClockSource::Manual)
    );
}

#[test]
fn hours_are_written_as_the_clock_is_set_to() {
    let mut app = app!();
    open_clock(&mut app);
    run(&mut app, &[Input::Turn(3), Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CLOCK_24H));
    assert!(!app.state().hour24());
    let local = app.state().local(app.state().wall_time.unwrap());
    assert!(local.time(app.state().hour24()).ends_with('M'));
}

#[test]
fn letters_narrow_the_time_zones_and_a_press_sets_one() {
    let mut app = app!();
    open_clock(&mut app);
    run(&mut app, &[Input::Turn(2), Input::Press]);
    // No zone is called that, so the x is refused.
    run(&mut app, &typed("jx"));
    let japan = zones::ZONES
        .iter()
        .position(|z| z.name == "Japan Time")
        .unwrap();
    assert_eq!(focus(app.state()), Some(keys::zone(japan)));
    // Backspace takes back a letter before it goes back.
    run(&mut app, &[Input::Backspace]);
    assert!(matches!(app.state().screen(), Screen::Device { .. }));
    run(&mut app, &typed("jap"));
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CLOCK_ZONE));
    assert_eq!(app.state().clock.zone, Rule::parse("JST-9").unwrap());
}

#[test]
fn a_time_is_written_in_the_offset_its_zone_kept_then() {
    let app = app!();
    app.state().node.set_zone("PST8PDT,M3.2.0,M11.1.0");
    let mut app = app;
    input::events(&mut app, 0);
    // 2026-07-01 and 2026-12-01, 20:00 UTC.
    let summer = app.state().local(1_782_936_000);
    let winter = app.state().local(1_796_155_200);
    assert_eq!(summer.time(true).as_str(), "13:00");
    assert_eq!(winter.time(true).as_str(), "12:00");
}
