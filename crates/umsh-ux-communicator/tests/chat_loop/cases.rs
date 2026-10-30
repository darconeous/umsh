// The chat loop driven the way a board drives it: inputs through
// `input::apply`, with no frame drawn between them. Each board's test
// target includes this with its `BOARD`.

use buoyant::app::App;
use buoyant::focus::{DefaultFocus, FocusKey};
use buoyant::render::AnimatedJoin;
use buoyant::view::ViewLayout;
use umsh_ux_communicator::board::{KeyboardKind, Unlock};
use umsh_ux_communicator::buoyant;
use umsh_ux_communicator::clock_settings::DateParts;
use umsh_ux_communicator::input::{self, Arrow, Input};
use umsh_ux_communicator::keyboard::{Latch, Modifier};
use umsh_ux_communicator::picker::Pick;
use umsh_ux_communicator::model::{
    BatteryReading, ChannelAccess, Charge, ChannelEntry, ChatKind, ClockSource, Delivery, Details, Direction, Ending, Exchange,
    ExchangeEnd, FoundKind,
    Glance, Node as _, NodeEvent, Notice, Presence, Profile, Reaction, Rule, Section, Shareable, State,
    brightness_level,
};
use umsh_ux_communicator::nav::{ChatMenu, DevicePage, MemberFrom, Screen, Unsent, keys};
use umsh_ux_communicator::model::Cue;
use umsh_ux_communicator::model::WifiStatus;
use umsh_ux_communicator::model::{Leg, PeerRoute, PingView, RouteKind};
use umsh_ux_communicator::{fixture, ui, zones};

/// The fixture's chats, in list order.
const RIDGE: u32 = 1;
const PAT: u32 = 3;
const RIDGE_DRAFT: &str = "On my way, save me some hot coffee";

/// The open chat's messages, oldest first, as its rows show them: a run
/// on its way again as the first of it.
fn messages(state: &State) -> Vec<umsh_ux_communicator::model::Message> {
    let chat = state.conversation.as_ref().expect("a chat is open").chat;
    (0..state.node.rows(chat))
        .filter_map(|row| state.node.row_message(chat, row))
        .collect()
}

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
            fixture::state($store, BOARD),
            BOARD.metrics.size().into(),
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

/// Turns the wheel a notch at a time until `key` has focus: down first,
/// then back up. A test names the row it wants, not how far down it sits.
fn turn_to<V, F>(app: &mut App<V, State, F>, key: FocusKey)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    for step in [1, -1] {
        let mut passed = Vec::new();
        while !passed.contains(&focus(app.state())) {
            if focus(app.state()) == Some(key) {
                return;
            }
            passed.push(focus(app.state()));
            run(app, &[Input::Turn(step)]);
        }
    }
    panic!("never reached {key:?}: {:?}", focus(app.state()));
}

/// Opens `chat` from the Chats list.
fn open_chat<V, F>(app: &mut App<V, State, F>, chat: u32)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    turn_to(app, keys::chat(chat));
    run(app, &[Input::Press]);
    assert_in_conversation(app.state(), chat);
}

/// Device, from the Chats list, on its first category.
fn open_device<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    run(app, &[Input::Backspace]);
    turn_to(app, keys::rail(Section::Device));
    run(app, &[Input::Press]);
    assert_eq!(app.state().section, Section::Device);
    assert_eq!(focus(app.state()), Some(keys::IDENTITY));
}

/// Opens the Device category at `key`, from the Chats list.
fn open_category<V, F>(app: &mut App<V, State, F>, key: FocusKey)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    open_device(app);
    turn_to(app, key);
    run(app, &[Input::Press]);
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
fn enter_opens_a_focused_row_as_a_press_does() {
    // A rail entry, then a settings row: neither takes Enter of its own.
    let opened = |input: Input| {
        let mut app = app!();
        run(&mut app, &[Input::Backspace]);
        turn_to(&mut app, keys::rail(Section::Device));
        run(&mut app, &[input]);
        assert_eq!(app.state().section, Section::Device);
        assert_eq!(focus(app.state()), Some(keys::IDENTITY));
        turn_to(&mut app, keys::DISPLAY);
        run(&mut app, &[input]);
        (format!("{:?}", app.state().screen()), focus(app.state()))
    };
    let pressed = opened(Input::Press);
    assert_ne!(pressed.1, Some(keys::DISPLAY), "the press opened the row");
    assert_eq!(opened(Input::Enter), pressed);
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
    open_chat(&mut app, PAT);
    run(&mut app, &[Input::Enter]);
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
    assert!(app.state().conversation(RIDGE).is_some(), "chat exists");
    let sent = messages(app.state()).pop().expect("a message");
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
    open_chat(&mut app, PAT);
    let long ="Trail is washed out past the second creek crossing. ".repeat(6);
    assert!(long.len() > 160);
    run(&mut app, &typed(&long));
    assert_eq!(draft(app.state(), PAT), long);
    run(&mut app, &[Input::Enter]);
    assert!(app.state().conversation(PAT).is_some(), "chat is open");
    let sent = messages(app.state()).pop().expect("a message");
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
    assert!(app.state().conversation(RIDGE).is_some(), "chat is open");
    let shown = messages(app.state());
    let texts: Vec<&str> = shown.iter().map(|m| m.text.as_str()).collect();
    assert_eq!(texts.len(), 4);
    assert_eq!(texts[3], RIDGE_DRAFT);
}

#[test]
fn a_chat_that_moves_to_the_top_keeps_focus() {
    let mut app = app!();
    open_chat(&mut app, PAT);
    run(&mut app, &typed("ok"));
    run(&mut app, &[Input::Enter, Input::Backspace]);
    assert_eq!(app.state().chats[0].id, PAT);
    assert_eq!(focus(app.state()), Some(keys::chat(PAT)));
}

#[test]
fn backspace_on_the_list_goes_to_the_rail_and_press_returns() {
    let mut app = app!();
    turn_to(&mut app, keys::chat(TRAIL_CREW));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::rail(Section::Chats)));
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::chat(TRAIL_CREW)));
}

#[test]
fn the_lock_control_locks_then_darkens_then_lights() {
    use umsh_ux_communicator::lock::attention_config;
    use umsh_ux_display_tracker::attention::{Attention, DisplayKind, Transition};
    let mut app = app!();
    let mut attention = Attention::new(DisplayKind::Emissive, attention_config(false, None), 0);
    // Lit and unlocked, it locks and stays lit.
    assert_eq!(app.state_mut().lock_control(&mut attention, 10), None);
    assert!(app.state().lock.locked);
    assert!(attention.accepts_redraw());
    // Lit and locked, it goes dark.
    assert_eq!(
        app.state_mut().lock_control(&mut attention, 20),
        Some(Transition::Lapsed)
    );
    assert!(!attention.accepts_redraw());
    // Dark, it lights, still locked.
    assert_eq!(
        app.state_mut().lock_control(&mut attention, 30),
        Some(Transition::Woke)
    );
    assert!(app.state().lock.locked);
}

#[test]
fn auto_lock_sets_how_long_the_panel_stays_lit() {
    use core::time::Duration;
    use umsh_ux_communicator::lock::attention_config;
    use umsh_ux_display_tracker::attention::AttentionConfig;
    let secs = |s| Some(Duration::from_secs(s));
    assert_eq!(attention_config(false, Some(60)).timeout, secs(60));
    assert_eq!(attention_config(false, None).timeout, secs(30));
    // Never, unless locked: a locked screen is only glanced at.
    assert_eq!(attention_config(false, Some(0)).timeout, None);
    assert_eq!(attention_config(true, Some(0)), AttentionConfig::LOCKED);
    assert_eq!(attention_config(true, Some(60)), AttentionConfig::LOCKED);
    // Locked, no longer than Auto-Lock says.
    assert_eq!(attention_config(true, Some(10)).timeout, secs(10));
}

#[test]
fn backspace_on_the_rail_locks_a_board_without_a_lock_button() {
    let mut app = app!();
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::rail(Section::Chats)));
    assert!(!app.state().lock.locked);
    run(&mut app, &[Input::Backspace]);
    let locks = !BOARD.controls.lock_button;
    assert_eq!(app.state().lock.locked, locks);
    if !locks {
        assert_eq!(focus(app.state()), Some(keys::rail(Section::Chats)));
    }
    // Again, it stays locked, and on the lock screen asks for the dark.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(app.state().lock.locked, locks);
    assert_eq!(app.state().lock.wants_dark(), locks);
}

#[test]
fn backspace_on_the_lock_screen_darkens_it_as_the_lock_control_does() {
    use umsh_ux_communicator::lock::attention_config;
    use umsh_ux_display_tracker::attention::{Attention, DisplayKind, Transition};
    let mut app = app!();
    let mut attention = Attention::new(DisplayKind::Emissive, attention_config(false, None), 0);
    // Unlocked, it is Back, and asks nothing of the panel.
    run(&mut app, &[Input::Backspace]);
    assert!(!app.state().lock.wants_dark());
    lock(&mut app);
    run(&mut app, &[Input::Backspace]);
    assert!(app.state().lock.locked);
    assert!(app.state().lock.wants_dark());
    // The board takes it as its lock control: lit and locked, it goes dark.
    assert_eq!(
        app.state_mut().lock_control(&mut attention, 10),
        Some(Transition::Lapsed)
    );
    assert!(!app.state().lock.wants_dark());
    assert!(app.state().lock.locked);
    // Unlocked after it, the ask is gone.
    run(&mut app, &[Input::Backspace]);
    unlock(&mut app);
    assert!(!app.state().lock.locked);
    assert!(!app.state().lock.wants_dark());
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
    turn_to(&mut app, keys::chat(PAT));
    hold(&mut app);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::Open(PAT)));
    assert_eq!(focus(app.state()), Some(keys::CHAT_SHOW));
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
    turn_to(&mut app, keys::chat(PAT));
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
    assert_eq!(focus(app.state()), Some(keys::CHAT_SHOW));
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
    turn_to(&mut app, keys::chat(PAT));
    hold(&mut app);
    turn_to(&mut app, keys::CHAT_DELETE);
    run(&mut app, &[Input::Press]);
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::ConfirmDelete(PAT)));
    assert_eq!(focus(app.state()), Some(keys::DELETE_CANCEL));
    // Cancel keeps it.
    run(&mut app, &[Input::Press]);
    assert_eq!(chat_menu(app.state()), None);
    assert!(app.state().chat(PAT).is_some());

    hold(&mut app);
    turn_to(&mut app, keys::CHAT_DELETE);
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::DELETE_CONFIRM);
    run(&mut app, &[Input::Press]);
    assert_eq!(chat_menu(app.state()), None);
    assert!(app.state().chat(PAT).is_none());
    // The row that took its place is focused.
    let next = app.state().chats[2].id;
    assert_eq!(focus(app.state()), Some(keys::chat(next)));
}

#[test]
fn holding_the_wheel_on_a_channel_opens_its_menu_to_show_it() {
    let mut app = app!();
    turn_to(&mut app, keys::chat(TRAIL_CREW));
    assert!(matches!(
        app.state().chat(TRAIL_CREW).expect("chat exists").kind,
        ChatKind::Channel { .. }
    ));
    hold(&mut app);
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::Open(TRAIL_CREW)));
    assert_eq!(focus(app.state()), Some(keys::CHAT_SHOW));
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Channel { chat, .. } if *chat == TRAIL_CREW));
}

#[test]
fn leaving_a_channel_from_its_menu_asks_first() {
    let mut app = app!();
    turn_to(&mut app, keys::chat(TRAIL_CREW));
    hold(&mut app);
    turn_to(&mut app, keys::CHAT_DELETE);
    run(&mut app, &[Input::Press]);
    assert_eq!(chat_menu(app.state()), Some(ChatMenu::ConfirmDelete(TRAIL_CREW)));
    turn_to(&mut app, keys::DELETE_CONFIRM);
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().chat(TRAIL_CREW), None);
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
    let message = state.open_message(message).expect("the message");
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
    assert_eq!(focus(app.state()), Some(keys::MORE_REACTIONS));
    run(&mut app, &[Input::Turn(-1)]);
    assert_eq!(focus(app.state()), Some(keys::reaction(Reaction::Question)));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(actions(app.state()), None);
    assert_eq!(focus(app.state()), Some(keys::message(SEE_YOU)));
}

#[test]
fn more_reacts_with_any_emoji_from_the_picker() {
    let mut app = app!();
    let open_on_answer = [Input::Press, Input::Turn(-2), Input::Press];
    run(&mut app, &open_on_answer);
    turn_to(&mut app, keys::MORE_REACTIONS);
    run(&mut app, &[Input::Press]);
    assert_eq!(actions(app.state()), None);
    let picker = app.state().picker.as_ref().expect("the picker is open");
    assert!(picker.reacting().is_some());
    run(&mut app, &typed("fire"));
    run(&mut app, &[Input::Enter]);
    assert!(app.state().picker.is_none());
    let fire = Reaction::of("\u{1F525}");
    assert!(matches!(fire, Reaction::Emoji(_)));
    assert_eq!(
        reactions(app.state(), ANSWER),
        [(Reaction::Heart, 1, false), (fire, 1, true)]
    );

    // An emote picked there is the emote.
    run(&mut app, &[Input::Backspace, Input::Press]);
    run(&mut app, &open_on_answer[1..]);
    turn_to(&mut app, keys::MORE_REACTIONS);
    run(&mut app, &[Input::Press]);
    run(&mut app, &typed("<3"));
    run(&mut app, &[Input::Enter]);
    assert_eq!(reactions(app.state(), ANSWER), [(Reaction::Heart, 2, true)]);
}

#[test]
fn a_reaction_is_mine_until_chosen_again_and_kept_across_opening_the_chat() {
    let mut app = app!();
    let open_on_answer = [Input::Press, Input::Turn(-2), Input::Press];
    run(&mut app, &open_on_answer);
    // Ridge Medic's heart is there already; mine joins it.
    turn_to(&mut app, keys::reaction(Reaction::Heart));
    run(&mut app, &[Input::Press]);
    assert_eq!(actions(app.state()), None);
    assert_eq!(reactions(app.state(), ANSWER), [(Reaction::Heart, 2, true)]);

    run(&mut app, &[Input::Backspace, Input::Press]);
    assert_eq!(reactions(app.state(), ANSWER), [(Reaction::Heart, 2, true)]);

    // Choosing it again withdraws it.
    run(&mut app, &open_on_answer[1..]);
    turn_to(&mut app, keys::reaction(Reaction::Heart));
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
    run(&mut app, &[Input::Press, Input::Turn(-3), Input::Press]);
    turn_to(&mut app, keys::DETAILS);
    run(&mut app, &[Input::Press]);
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

/// Turns the wheel down until `key` has focus, through rows the wheel
/// scrolls a step at a time.
fn scroll_to<V, F>(app: &mut App<V, State, F>, key: FocusKey)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    for _ in 0..32 {
        if focus(app.state()) == Some(key) {
            return;
        }
        run(app, &[Input::Turn(1)]);
    }
    panic!("never reached {key:?}: {:?}", focus(app.state()));
}

/// The details of my answer to Ridge Medic, which list the repeaters that
/// carried it.
fn answer_details<V, F>(app: &mut App<V, State, F>) -> Details
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    if !matches!(app.state().screen(), Screen::Details { .. }) {
        run(app, &[Input::Press, Input::Turn(-2), Input::Press]);
        turn_to(app, keys::DETAILS);
        run(app, &[Input::Press]);
    }
    let Screen::Details {
        message, details, ..
    } = app.state().screen()
    else {
        panic!("expected details, got {:?}", app.state().screen());
    };
    assert_eq!(*message, ANSWER);
    details.clone()
}

#[test]
fn my_messages_details_list_the_repeaters_that_carried_it() {
    let mut app = app!();
    let details = answer_details(&mut app);
    let names: Vec<&str> = details.repeaters.iter().map(|r| &*r.name).collect();
    assert_eq!(names, ["Riverbend Camp", "3w*"]);
    assert!(details.repeaters[0].address.is_some());
    assert_eq!(details.repeaters[1].address, None);
    assert_eq!(details.anonymous, 1);
    // Its caption names the first of them.
    let via = message(app.state(), ANSWER).via.expect("repeaters were heard");
    assert_eq!(via.lead.as_deref(), Some("Riverbend Camp"));
    assert_eq!(via.count, 3);

    // A known one opens as the node it is.
    scroll_to(&mut app, keys::repeater(0));
    run(&mut app, &[Input::Press]);
    assert_eq!(
        shown_member(app.state()).0.sender.name.as_str(),
        "Riverbend Camp"
    );
}

#[test]
fn a_repeater_known_by_its_hint_is_asked_who_it_is_and_named_once_it_answers() {
    let store = store();
    let mut app = app!(store);
    let details = answer_details(&mut app);
    let hint = details.repeaters[1].hint;
    scroll_to(&mut app, keys::repeater(1));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().identifying().as_slice(), [hint]);
    // The spinner keeps the screen coming back while it waits.
    assert!(app.state().next_deadline().is_some());

    let at = store.next_deadline().expect("the answer is due");
    store.advance(at);
    input::events(&mut app, at);
    let details = answer_details(&mut app);
    assert_eq!(&*details.repeaters[1].name, "Bald Knob");
    assert!(details.repeaters[1].address.is_some());
    assert_eq!(
        message(app.state(), ANSWER).via.unwrap().lead.as_deref(),
        Some("Riverbend Camp")
    );
}

#[test]
fn a_message_to_a_peer_names_its_repeaters_then_waits_then_is_delivered() {
    let store = store();
    let mut app = app!(store);
    open_chat(&mut app, RIDGE);
    let sent = app
        .state()
        .node
        .send(RIDGE, "At the hut", None, false)
        .expect("sent");
    let mut seen = Vec::new();
    let mut now = 0;
    while let Some(at) = store.next_deadline() {
        now = at;
        store.advance(now);
        input::events(&mut app, now);
        let shown = message(app.state(), sent.id);
        let step = (shown.delivery, shown.via.map(|via| via.count));
        if seen.last() != Some(&step) {
            seen.push(step);
        }
    }
    assert!(now > 0);
    assert_eq!(
        seen,
        [
            (Delivery::Sent, None),
            (Delivery::Sent, Some(1)),
            (Delivery::Sent, Some(2)),
            (Delivery::Confirming, Some(2)),
            (Delivery::Delivered, Some(2)),
        ]
    );
}

/// Pat Okafor's last message, which went unconfirmed.
const ANTENNA: u32 = (PAT << 8) | 2;

fn message(state: &State, message: u32) -> umsh_ux_communicator::model::Message {
    state.open_message(message).expect("the message")
}

fn delivery(state: &State, message: u32) -> Delivery {
    self::message(state, message).delivery
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
    open_chat(&mut app, PAT);
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
    open_chat(&mut app, PAT);
    run(&mut app, &[Input::Turn(-1)]);
    assert_eq!(focus(app.state()), Some(keys::message(ANTENNA)));
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::DELETE_MESSAGE);
    run(&mut app, &[Input::Press]);
    assert_eq!(actions(app.state()), None);
    assert_eq!(unsent(app.state()), Some(ANTENNA));
    assert_eq!(focus(app.state()), Some(keys::DELETE_MESSAGE_CANCEL));
    // Cancel keeps it.
    run(&mut app, &[Input::Press]);
    assert_eq!(unsent(app.state()), None);
    assert_eq!(focus(app.state()), Some(keys::message(ANTENNA)));
    assert!(!message(app.state(), ANTENNA).deleted);

    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::DELETE_MESSAGE);
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::DELETE_MESSAGE_CONFIRM);
    run(&mut app, &[Input::Press]);
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
    self::message(state, message).forward_secret
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
    turn_to(&mut app, keys::RESEND_WITHOUT_SECRECY);
    run(&mut app, &[Input::Press]);
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
    open_chat(&mut app, PAT);
    spend_airtime(&mut app, Some(100));
    run(&mut app, &typed("Also the 18650s"));
    run(&mut app, &[Input::Enter]);
    assert_eq!(draft(app.state(), PAT), "Also the 18650s");
    assert_eq!(messages(app.state()).len(), 3);
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
    open_chat(&mut app, TRAIL_CREW);
    let before = messages(app.state()).len();
    assert!(!arrive(&mut app, store, 0));
    assert_eq!(app.state().banner, None);
    assert!(!app.state().chats[0].unread);
    let shown = messages(app.state());
    assert_eq!(shown.len(), before + 1);
    assert_eq!(shown.last().unwrap().direction, Direction::Inbound);
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

// ─── Sounds ──────────────────────────────────────────────────────────

#[test]
fn a_direct_message_and_a_channel_message_each_sound_their_own() {
    let store = store();
    let mut app = app!(store);
    assert_eq!(app.state_mut().take_cue(), None);
    assert!(arrive_in(&mut app, store, PAT, "Got it", tick(1000)));
    assert_eq!(app.state_mut().take_cue(), Some(Cue::Direct));
    assert!(arrive_in(&mut app, store, TRAIL_CREW, "Heading up", tick(1000)));
    assert_eq!(app.state_mut().take_cue(), Some(Cue::Channel));
    assert_eq!(app.state_mut().take_cue(), None);
}

#[test]
fn a_muted_chat_makes_no_sound() {
    let store = store();
    let mut app = app!(store);
    // The public channel is muted.
    arrive_in(&mut app, store, 4, "Mill Creek is clear", tick(1000));
    assert_eq!(app.state_mut().take_cue(), None);
}

#[test]
fn a_message_in_the_open_chat_sounds_quietly() {
    let store = store();
    let mut app = app!(store);
    open_chat(&mut app, TRAIL_CREW);
    assert!(!arrive(&mut app, store, tick(1000)));
    assert_eq!(app.state_mut().take_cue(), Some(Cue::InChat));
}

#[test]
fn a_burst_of_messages_sounds_once_for_the_one_that_matters_most() {
    let store = store();
    let mut app = app!(store);
    store.arrive_in(TRAIL_CREW, "One");
    store.arrive_in(PAT, "Two");
    store.arrive_in(TRAIL_CREW, "Three");
    assert!(input::events(&mut app, tick(1000)));
    assert_eq!(app.state_mut().take_cue(), Some(Cue::Direct));
    assert_eq!(app.state_mut().take_cue(), None);
}

#[test]
fn a_message_sounds_as_it_is_sent_and_again_as_it_comes_out() {
    let store = store();
    let mut app = app!(store);
    app.state_mut().send(RIDGE);
    assert_eq!(app.state_mut().take_cue(), Some(Cue::Sent));
    let mut cues = Vec::new();
    while let Some(at) = store.next_deadline() {
        store.advance(at);
        input::events(&mut app, at);
        cues.extend(app.state_mut().take_cue());
    }
    assert_eq!(cues, [Cue::Delivered]);
    // One that went unconfirmed sounds unlike one delivered.
    store.settle(PAT, ANTENNA);
    input::events(&mut app, tick(1000));
    assert_eq!(app.state_mut().take_cue(), Some(Cue::Unconfirmed));
}

#[test]
fn the_mute_key_switches_sounds_anywhere() {
    let mut app = app!();
    run(&mut app, &[Input::Mute]);
    assert_eq!(app.state().node.sound_enabled(), Some(false));
    assert!(app.state().status.silent);
    // Locked too.
    app.state_mut().lock();
    app.finalize_view();
    assert!(app.state().lock.locked);
    run(&mut app, &[Input::Mute]);
    assert_eq!(app.state().node.sound_enabled(), Some(true));
    assert!(!app.state().status.silent);
}

#[test]
fn with_sounds_off_nothing_sounds_and_the_strip_says_so() {
    let store = store();
    let mut app = app!(store);
    assert!(!app.state().status.silent);
    app.state_mut().open_sounds();
    app.finalize_view();
    assert_eq!(focus(app.state()), Some(keys::SOUNDS_ENABLED));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().node.sound_enabled(), Some(false));
    assert!(app.state().status.silent);
    // Still called to attention, in silence.
    assert!(arrive_in(&mut app, store, PAT, "Got it", tick(1000)));
    assert_eq!(app.state_mut().take_cue(), None);
    app.state_mut().send(RIDGE);
    assert_eq!(app.state_mut().take_cue(), None);

    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().node.sound_enabled(), Some(true));
    assert!(!app.state().status.silent);
    assert!(arrive_in(&mut app, store, PAT, "Again", tick(1000)));
    assert_eq!(app.state_mut().take_cue(), Some(Cue::Direct));
}

#[test]
fn pressing_volume_lets_turning_change_it_and_plays_it_at_each_level() {
    let store = store();
    let mut app = app!(store);
    app.state_mut().open_sounds();
    app.finalize_view();
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::VOLUME));
    let before = app.state().node.sound_volume();
    run(&mut app, &[Input::Press]);
    assert!(app.state().adjusting_volume());
    // Turned up, louder, and heard at the new level.
    run(&mut app, &[Input::Turn(-1)]);
    assert!(app.state().node.sound_volume() > before);
    assert_eq!(app.state_mut().take_cue(), Some(Cue::Direct));
    assert_eq!(focus(app.state()), Some(keys::VOLUME));
    run(&mut app, &[Input::Turn(3)]);
    assert!(app.state().node.sound_volume() < before);
    // Pressed again, turning moves on.
    run(&mut app, &[Input::Press, Input::Turn(-1)]);
    assert!(!app.state().adjusting_volume());
    assert_eq!(focus(app.state()), Some(keys::SOUNDS_ENABLED));
}

#[test]
fn a_level_rows_arrows_change_its_own_setting_and_no_other() {
    let store = store();
    let mut app = app!(store);
    let levels = |app: &App<_, State, _>| {
        let node = app.state().node;
        (node.brightness(), node.sound_volume())
    };
    // Brightness focused, not pressed: across, the trackball sets the
    // brightness.
    open_category(&mut app, keys::DISPLAY);
    assert_eq!(focus(app.state()), Some(keys::BRIGHTNESS));
    let (brightness, volume) = levels(&app);
    run(&mut app, &[Input::Move(Arrow::Left)]);
    assert!(levels(&app).0 < brightness);
    assert_eq!(levels(&app).1, volume);
    // And Volume's sets the volume.
    app.state_mut().open_sounds();
    app.finalize_view();
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::VOLUME));
    let (brightness, volume) = levels(&app);
    run(&mut app, &[Input::Move(Arrow::Left)]);
    assert_eq!(levels(&app).0, brightness);
    assert!(levels(&app).1 < volume);
    run(&mut app, &[Input::Move(Arrow::Right), Input::Move(Arrow::Right)]);
    assert_eq!(levels(&app).0, brightness);
    assert!(levels(&app).1 > volume);
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

/// Whether turning is part of unlocking, as it is with a wheel.
fn turning_unlocks() -> bool {
    BOARD.controls.unlock == Unlock::TurnThenPress
}

#[test]
fn five_steps_down_and_a_press_unlock_to_where_it_was() {
    if !turning_unlocks() {
        return;
    }
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
    if !turning_unlocks() {
        return;
    }
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
    if !turning_unlocks() {
        return;
    }
    let mut app = app!();
    lock(&mut app);
    quick(&mut app, &[Input::Turn(5), Input::Turn(-2)]);
    assert_eq!(app.state().lock.steps, 3);
    assert!(!app.state().lock.ready());
    quick(&mut app, &[Input::Turn(-9)]);
    assert_eq!(app.state().lock.steps, 0);
}

#[test]
fn a_press_alone_unlocks_to_where_it_was_where_turning_is_no_part() {
    if turning_unlocks() {
        return;
    }
    let mut app = app!();
    run(&mut app, &[Input::Press, Input::Turn(-1)]);
    let held = focus(app.state());
    lock(&mut app);
    // Turning neither unlocks nor counts toward it.
    quick(&mut app, &[Input::Turn(5)]);
    assert!(app.state().lock.locked);
    assert_eq!(app.state().lock.steps, 0);
    quick(&mut app, &[Input::Press]);
    assert!(!app.state().lock.locked);
    assert_eq!(focus(app.state()), held);
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
    open_chat(&mut app, TRAIL_CREW);
    run(&mut app, &[Input::Enter]);
    run(&mut app, &typed("Switchbacks, 15 min out"));
    run(&mut app, &[Input::Enter]);
    let sent = messages(app.state()).pop().expect("the message sent");
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
    open_chat(app, TRAIL_CREW);
    run(app, &[Input::Turn(-back), Input::Press]);
    turn_to(app, keys::VIEW_MEMBER);
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
    open_chat(&mut app, TRAIL_CREW);
    run(&mut app, &[Input::Turn(-2)]);
    assert_eq!(focus(app.state()), Some(keys::message(BEHIND_YOU)));
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::reaction(Reaction::ThumbsUp));
    run(&mut app, &[Input::Press]);
    assert_eq!(
        reactions(app.state(), BEHIND_YOU),
        [(Reaction::ThumbsUp, 2, true), (Reaction::Exclaim, 1, false)]
    );
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::reaction(Reaction::Exclaim));
    run(&mut app, &[Input::Press]);
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
    let sender = app.state().open_message(BEHIND_YOU);
    assert_eq!(
        sender
            .as_ref()
            .and_then(|m| m.sender.as_ref())
            .map(|s| s.name.as_str()),
        Some("Robin Hale")
    );
}

#[test]
fn save_peer_goes_once_saved_and_message_opens_a_direct_chat() {
    let mut app = app!();
    view_member(&mut app, 1);
    turn_to(&mut app, keys::SAVE_PEER);
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

/// Opens Jo's chat and turns up to the invitation, through the tall
/// message, which the wheel scrolls through first.
fn to_invite<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    open_chat(app, JO);
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
    to_invite(&mut app);
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
    to_invite(&mut app);
    run(&mut app, &[Input::Press, Input::Press, Input::Press]);
    assert_eq!(joined_chat(app.state()), chat);
    assert_eq!(app.state().chats.len(), before + 1);
}

#[test]
fn a_channel_joined_can_be_called_something_else_here() {
    let mut app = app!();
    to_invite(&mut app);
    run(&mut app, &[Input::Press, Input::Press]);
    turn_to(&mut app, keys::JOIN_NAME);
    run(&mut app, &[Input::Press]);
    run(&mut app, &[Input::Backspace; 4]);
    run(&mut app, &typed("Hut"));
    run(&mut app, &[Input::Enter]);
    turn_to(&mut app, keys::JOIN_CHANNEL);
    run(&mut app, &[Input::Press]);
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
    open_chat(&mut app, EMERGENCY);
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
    assert_eq!(
        messages(app.state()).last().map(|m| m.delivery),
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
fn enter_an_address_unlocks_message_once_the_address_is_whole() {
    use umsh_ux_communicator::model::PeerEntry;
    let mut app = app!();
    open_nearby(&mut app);
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::EnterAddress { .. }));
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
    assert!(matches!(app.state().screen(), Screen::EnterAddress { .. }));
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
fn enter_an_address_reads_an_invitation_and_refuses_what_is_not_an_address() {
    use umsh_ux_communicator::model::PeerEntry;
    let mut app = app!();
    open_nearby(&mut app);
    run(&mut app, &[Input::Press]);
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

/// Opens Add peer from the Peers list, on Nearby.
fn open_nearby<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    run(app, &[Input::Backspace]);
    turn_to(app, keys::rail(Section::Peers));
    run(app, &[Input::Press]);
    turn_to(app, keys::ADD_PEER);
    run(app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Nearby { .. }));
}

/// What the fixture's other holder does, and what the node then says.
fn other_holder<V, F>(app: &mut App<V, State, F>, store: &fixture::Store, step: fixture::MeetStep)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    store.meet_peer(step);
    input::events(app, tick(100));
}

#[test]
fn nearby_lists_devices_by_model_and_color_alone() {
    let mut app = app!();
    open_nearby(&mut app);
    let meet = &app.state().meet;
    assert!(meet.own_color.is_some());
    assert_eq!(meet.exchange, Exchange::Idle);
    assert_eq!(meet.devices.len(), 2);
    assert_eq!(focus(app.state()), Some(keys::ENTER_ADDRESS));
    turn_to(&mut app, keys::nearby(1));
    // Leaving Add peer closes its session.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(app.state().meet.exchange, Exchange::Closed);
}

#[test]
fn an_exchange_asked_for_opens_on_its_card_and_goes_on_to_the_code() {
    let store = store();
    let mut app = app!(store);
    open_nearby(&mut app);
    other_holder(&mut app, store, fixture::MeetStep::Asks);
    assert!(matches!(app.state().meet.exchange, Exchange::Asked(_)));
    assert_eq!(focus(app.state()), Some(keys::EXCHANGE_ACCEPT));
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Exchange { .. }));
    assert!(matches!(
        app.state().meet.exchange,
        Exchange::Comparing { sent: false, .. }
    ));
    assert_eq!(focus(app.state()), Some(keys::SAME));
}

#[test]
fn not_now_stays_on_nearby_under_a_new_color() {
    let store = store();
    let mut app = app!(store);
    open_nearby(&mut app);
    let before = app.state().meet.own_color;
    other_holder(&mut app, store, fixture::MeetStep::Asks);
    turn_to(&mut app, keys::EXCHANGE_DECLINE);
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Nearby { .. }));
    assert_eq!(app.state().meet.exchange, Exchange::Idle);
    assert_ne!(app.state().meet.own_color, before);
    assert_eq!(focus(app.state()), Some(keys::ENTER_ADDRESS));
}

#[test]
fn same_on_both_sides_opens_the_unsaved_peer_on_message() {
    let store = store();
    let mut app = app!(store);
    let saved = app.state().peers.len();
    open_nearby(&mut app);
    turn_to(&mut app, keys::nearby(1));
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Exchange { .. }));
    assert!(matches!(app.state().meet.exchange, Exchange::Asking(_)));
    other_holder(&mut app, store, fixture::MeetStep::Answers(true));
    assert_eq!(focus(app.state()), Some(keys::SAME));
    run(&mut app, &[Input::Press]);
    assert!(matches!(
        app.state().meet.exchange,
        Exchange::Comparing { sent: true, .. }
    ));
    other_holder(&mut app, store, fixture::MeetStep::Same);
    match app.state().screen() {
        Screen::Member {
            from: MemberFrom::Known,
            member,
            ..
        } => {
            assert_eq!(member.sender.name.as_str(), "Kit Moreno");
            assert!(!member.saved);
        }
        other => panic!("expected the unsaved peer, got {other:?}"),
    }
    assert_eq!(focus(app.state()), Some(keys::MESSAGE_MEMBER));
    assert_eq!(app.state().meet.exchange, Exchange::Closed);
    assert_eq!(app.state().peers.len(), saved);
    // Back goes to the Peers list, not to Add peer.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(app.state().screens.len(), 1);
    assert_eq!(app.state().section, Section::Peers);
}

#[test]
fn different_ends_the_exchange_and_try_again_draws_a_new_color() {
    let store = store();
    let mut app = app!(store);
    open_nearby(&mut app);
    let before = app.state().meet.own_color;
    other_holder(&mut app, store, fixture::MeetStep::Asks);
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::DIFFERENT);
    run(&mut app, &[Input::Press]);
    assert_eq!(
        app.state().meet.exchange,
        Exchange::Ended(ExchangeEnd::Different)
    );
    assert_eq!(focus(app.state()), Some(keys::TRY_AGAIN));
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Nearby { .. }));
    assert_eq!(app.state().meet.exchange, Exchange::Idle);
    assert_ne!(app.state().meet.own_color, before);
}

#[test]
fn backing_out_of_an_exchange_closes_add_peer() {
    let store = store();
    let mut app = app!(store);
    open_nearby(&mut app);
    other_holder(&mut app, store, fixture::MeetStep::Asks);
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Exchange { .. }));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(app.state().screens.len(), 1);
    assert_eq!(app.state().meet.exchange, Exchange::Closed);
}

#[test]
fn the_other_holder_backing_out_ends_it_here() {
    let store = store();
    let mut app = app!(store);
    open_nearby(&mut app);
    other_holder(&mut app, store, fixture::MeetStep::Asks);
    run(&mut app, &[Input::Press]);
    other_holder(&mut app, store, fixture::MeetStep::Leaves);
    assert_eq!(app.state().meet.exchange, Exchange::Ended(ExchangeEnd::Left));
    assert_eq!(focus(app.state()), Some(keys::TRY_AGAIN));
    turn_to(&mut app, keys::DONE);
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().screens.len(), 1);
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
    run(app, &[Input::Backspace]);
    turn_to(app, keys::rail(Section::Peers));
    run(app, &[Input::Press]);
    let pat = app
        .state()
        .peers
        .iter()
        .find(|p| p.name.as_str() == "Pat Okafor")
        .map(|p| p.id)
        .expect("Pat is saved");
    turn_to(app, keys::peer(pat));
    run(app, &[Input::Press]);
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
fn forward_secrecy_switches_and_a_ping_opens_its_screen() {
    let mut app = app!();
    open_pat(&mut app);
    turn_to(&mut app, keys::PEER_SECRECY);
    run(&mut app, &[Input::Press]);
    assert!(peer_detail(app.state()).forward_secrecy);
    run(&mut app, &[Input::Press]);
    assert!(!peer_detail(app.state()).forward_secrecy);
    turn_to(&mut app, keys::PEER_PING);
    run(&mut app, &[Input::Press]);
    assert_eq!(shown_ping(app.state()), Some(PingView::Waiting));
}

#[test]
fn a_saved_peer_is_given_an_alias_where_it_stands() {
    let mut app = app!();
    open_pat(&mut app);
    let Screen::Peer { peer, .. } = *app.state().screen() else {
        panic!("not on a peer");
    };
    let name = |app: &App<_, State, _>| app.state().peer(peer).unwrap().name.clone();
    turn_to(&mut app, keys::PEER_ALIAS);
    run(&mut app, &[Input::Press]);
    run(&mut app, &typed("Pat"));
    run(&mut app, &[Input::Enter]);
    assert_eq!(name(&app).as_str(), "Pat");
    let detail = peer_detail(app.state());
    assert_eq!(detail.alias.as_deref(), Some("Pat"));
    assert_eq!(detail.advertised.as_deref(), Some("Pat Okafor"));
    // Emptied, they go by their own name again.
    run(&mut app, &[Input::Press]);
    run(&mut app, &[Input::Backspace; 3]);
    run(&mut app, &[Input::Enter]);
    assert_eq!(name(&app).as_str(), "Pat Okafor");
    assert_eq!(peer_detail(app.state()).alias, None);
}

#[test]
fn a_saved_peer_is_asked_for_their_identity() {
    let mut app = app!();
    open_pat(&mut app);
    turn_to(&mut app, keys::PEER_IDENTITY);
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
    turn_to(&mut app, keys::PEER_FORGET);
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::FORGET_CANCEL));
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::PEER_FORGET));
    assert_eq!(app.state().peers.len(), peers);

    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::FORGET_CONFIRM);
    run(&mut app, &[Input::Press]);
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
    open_category(app, keys::RADIO);
    assert_eq!(focus(app.state()), Some(keys::RADIO_ENABLED));
    turn_to(app, keys::PROFILE);
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
    turn_to(&mut app, keys::SHARE_LOCATION);
    assert!(!radio(app.state()).share_location);
    run(&mut app, &[Input::Press]);
    assert!(radio(app.state()).share_location);
    turn_to(&mut app, keys::FORWARDING);
    run(&mut app, &[Input::Press]);
    assert!(!radio(app.state()).forwarding);
}

#[test]
fn identity_is_renamed_in_place_and_shows_its_code() {
    let mut app = app!();
    open_category(&mut app, keys::IDENTITY);
    assert!(matches!(
        app.state().screen(),
        Screen::Device {
            page: DevicePage::Identity { .. },
            ..
        }
    ));
    assert_eq!(focus(app.state()), Some(keys::IDENTITY_NAME));
    let before = app.state().status.device_name.chars().count();
    run(&mut app, &[Input::Press]);
    run(&mut app, &vec![Input::Backspace; before]);
    run(&mut app, &typed("Robin"));
    run(&mut app, &[Input::Enter]);
    assert_eq!(app.state().status.device_name.as_str(), "Robin");
    // A press ends an edit as Enter does.
    run(&mut app, &[Input::Press]);
    run(&mut app, &typed("!"));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().status.device_name.as_str(), "Robin!");

    turn_to(&mut app, keys::IDENTITY_CODE);
    run(&mut app, &[Input::Press]);
    assert!(matches!(
        app.state().screen(),
        Screen::Device {
            page: DevicePage::Share {
                what: Shareable::Identity
            },
            ..
        }
    ));
    // A press goes back, as Backspace does.
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::IDENTITY_CODE));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::IDENTITY));
}

/// Opens Device › Channels › Trail Crew's screen from the Chats list.
fn show_trail_crew<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    open_category(app, keys::CHANNELS);
    turn_to(app, keys::chat(TRAIL_CREW));
    run(app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Channel { chat, .. } if *chat == TRAIL_CREW));
    assert_eq!(focus(app.state()), Some(keys::CHANNEL_MESSAGE));
}

#[test]
fn a_channel_is_renamed_muted_and_shared_from_its_screen() {
    let mut app = app!();
    show_trail_crew(&mut app);
    turn_to(&mut app, keys::CHANNEL_CODE);
    run(&mut app, &[Input::Press]);
    assert!(matches!(
        app.state().screen(),
        Screen::Device {
            page: DevicePage::Share {
                what: Shareable::Channel(TRAIL_CREW)
            },
            ..
        }
    ));
    run(&mut app, &[Input::Backspace]);

    turn_to(&mut app, keys::CHANNEL_NAME);
    run(&mut app, &[Input::Press]);
    run(&mut app, &[Input::Backspace; 10]);
    run(&mut app, &typed("Crew"));
    run(&mut app, &[Input::Enter]);
    let name = |app: &App<_, State, _>| app.state().chat(TRAIL_CREW).unwrap().name.clone();
    assert_eq!(name(&app).as_str(), "Crew");
    // Emptied, it goes by its own name again.
    run(&mut app, &[Input::Press]);
    run(&mut app, &[Input::Backspace; 4]);
    run(&mut app, &[Input::Enter]);
    assert_eq!(name(&app).as_str(), "Trail Crew");

    assert!(!app.state().chat(TRAIL_CREW).unwrap().muted);
    turn_to(&mut app, keys::CHANNEL_NOTIFICATIONS);
    run(&mut app, &[Input::Press]);
    assert!(app.state().chat(TRAIL_CREW).unwrap().muted);

    turn_to(&mut app, keys::CHANNEL_MESSAGE);
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Conversation { chat, .. } if *chat == TRAIL_CREW));
}

#[test]
fn leaving_a_channel_asks_first_and_returns_to_channels() {
    let mut app = app!();
    show_trail_crew(&mut app);
    turn_to(&mut app, keys::CHANNEL_LEAVE);
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::LEAVE_CANCEL));
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CHANNEL_LEAVE));
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::LEAVE_CONFIRM);
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().chat(TRAIL_CREW), None);
    assert!(matches!(
        app.state().screen(),
        Screen::Device {
            page: DevicePage::Channels,
            ..
        }
    ));
    let focused = focus(app.state()).and_then(keys::chat_of);
    assert!(focused.is_some_and(|chat| app.state().is_channel(chat)), "{focused:?}");
}

/// Opens Device › Channels › Add channel from the Chats list.
fn open_add_channel<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    open_category(app, keys::CHANNELS);
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
fn a_channel_row_leaves_out_the_emoji_its_badge_shows() {
    let invitation = "umsh:ck:5BFn8YGKJ6pZR4qV3tW7mNhDrXsCxEaL9kUv2wAjT8bP?n=";
    for (encoded, name, title) in [
        ("%F0%9F%94%A5%20Hot%20Topic", "🔥 Hot Topic", "Hot Topic"),
        ("%F0%9F%94%A5", "🔥", "Fire"),
    ] {
        let mut app = app!();
        open_add_channel(&mut app);
        run(&mut app, &typed(invitation));
        run(&mut app, &typed(encoded));
        run(&mut app, &[Input::Enter]);
        let chat = app.state().chats[0].clone();
        assert_eq!(chat.name.as_str(), name);
        assert_eq!(chat.title().as_ref(), title);
        // Find knows it by what its row calls it, and lights that.
        run(&mut app, &[Input::Backspace]);
        run(&mut app, &typed(&title[..3]));
        let (found, _) = app.state().found();
        let found = found
            .iter()
            .find(|f| f.kind == FoundKind::Chat(chat.id))
            .expect("found");
        assert_eq!(found.title.as_ref(), title);
    }
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
    show_trail_crew(&mut app);
    run(&mut app, &[Input::Press]);
    assert_in_conversation(app.state(), TRAIL_CREW);
}

/// A battery at `percent`, charging or running the board.
fn reading(percent: u8, charging: bool) -> BatteryReading {
    BatteryReading {
        percent: Some(percent),
        charge: Some(if charging {
            Charge::Charging
        } else {
            Charge::Discharging
        }),
        millivolts: None,
    }
}

#[test]
fn low_battery_says_so_once_without_taking_a_key() {
    let mut app = app!();
    // Typing in Ridge Medic.
    run(&mut app, &[Input::Press, Input::Enter]);
    app.state_mut().battery(reading(11, false), 0);
    assert!(!app.state().status.battery_low);
    app.state_mut().battery(reading(9, false), 1000);
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
    app.state_mut().battery(reading(11, false), 6000);
    app.state_mut().battery(reading(9, false), 7000);
    assert!(app.state().status.battery_low);
    assert_eq!(app.state().banner, None);
    // Charging ends it.
    app.state_mut().battery(reading(9, true), 8000);
    assert!(!app.state().status.battery_low);
    assert!(app.state().status.charging);
}

#[test]
fn low_battery_while_dark_marks_only_the_strip() {
    let mut app = app!();
    app.state_mut().dark = true;
    app.state_mut().battery(reading(9, false), 1000);
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
    assert_eq!(app.state().clock.zone.std_offset_min(), -480);
    // Set up, it says so, and goes on to the Chats list.
    assert!(app.state().in_setup());
    run(&mut app, &[Input::Backspace]);
    assert!(!app.state().in_setup());
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
}

/// Unlocks the way the board's control does.
fn unlock<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    if turning_unlocks() {
        quick(app, &[Input::Turn(5)]);
    }
    quick(app, &[Input::Press]);
}

#[test]
fn unlocking_a_device_not_set_up_opens_first_run_until_it_finishes() {
    let mut app = app!();
    app.state().node.set_setup_complete(false);
    lock(&mut app);
    unlock(&mut app);
    assert!(!app.state().lock.locked);
    assert!(app.state().in_setup());
    assert_eq!(focus(app.state()), Some(keys::NAME_FIELD));
    run(&mut app, &typed("Wren"));
    run(&mut app, &[Input::Enter]);
    let profile = focus(app.state());
    assert!(app.state().in_setup());
    assert_ne!(profile, Some(keys::NAME_FIELD));
    // Locked partway, it unlocks back to first run as it was left.
    lock(&mut app);
    unlock(&mut app);
    assert!(app.state().in_setup());
    assert_eq!(focus(app.state()), profile);
    // The profile as it is, and the zone as it is: set up, it says so.
    run(&mut app, &[Input::Press, Input::Press]);
    assert!(app.state().in_setup());
    assert!(app.state().node.setup_complete());
    assert_eq!(focus(app.state()), Some(keys::CONTINUE));
    // Back from there is the Chats list.
    run(&mut app, &[Input::Backspace]);
    assert!(!app.state().in_setup());
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    // Set up, it unlocks to where it was.
    let held = focus(app.state());
    lock(&mut app);
    unlock(&mut app);
    assert!(!app.state().in_setup());
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(focus(app.state()), held);
}

#[test]
fn first_run_ends_on_add_peer() {
    let mut app = app!();
    app.state().node.set_setup_complete(false);
    lock(&mut app);
    unlock(&mut app);
    run(&mut app, &typed("Wren"));
    run(&mut app, &[Input::Enter, Input::Press, Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CONTINUE));
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Nearby { .. }));
    // Back from Add peer is the Peers list, on Add peer.
    run(&mut app, &[Input::Backspace]);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert_eq!(app.state().section, Section::Peers);
    assert_eq!(focus(app.state()), Some(keys::ADD_PEER));
}

#[test]
fn unlocking_a_device_set_up_skips_first_run() {
    let mut app = app!();
    assert!(app.state().node.setup_complete());
    lock(&mut app);
    unlock(&mut app);
    assert!(!app.state().lock.locked);
    assert!(!app.state().in_setup());
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
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
    assert_eq!(found[2].title.as_ref(), "Riverbend Camp");
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
    open_device(&mut app);
    turn_to(&mut app, keys::SHUT_DOWN);
    // Cancel is focused, and Backspace cancels too.
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::SHUT_DOWN_CANCEL));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::SHUT_DOWN));
    assert_eq!(app.state().ending, None);

    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::SHUT_DOWN_CONFIRM);
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().ending, Some(Ending::ShuttingDown));
    // Nothing moves under the card.
    run(&mut app, &[Input::Turn(-3), Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::SHUT_DOWN));
}

#[test]
fn restart_asks_first() {
    let store = store();
    let mut app = app!(store);
    open_device(&mut app);
    turn_to(&mut app, keys::RESTART);
    // Cancel is focused, and Backspace cancels too.
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::RESTART_CANCEL));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::RESTART));
    assert_eq!(store.restarts(), 0);

    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::RESTART_CONFIRM);
    run(&mut app, &[Input::Press]);
    assert_eq!(store.restarts(), 1);
    assert_eq!(focus(app.state()), Some(keys::RESTART));
}

#[test]
fn factory_reset_asks_twice_with_its_choices_swapped() {
    let store = store();
    let mut app = app!(store);
    open_device(&mut app);
    turn_to(&mut app, keys::FACTORY_RESET);
    // Cancel is focused, under Factory reset, and Backspace cancels too.
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::FACTORY_RESET_CANCEL));
    run(&mut app, &[Input::Turn(-1)]);
    assert_eq!(focus(app.state()), Some(keys::FACTORY_RESET_CONFIRM));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::FACTORY_RESET));

    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::FACTORY_RESET_CONFIRM);
    run(&mut app, &[Input::Press]);
    // Asked again, Cancel is where Factory reset was, and focused.
    assert_eq!(focus(app.state()), Some(keys::ERASE_CANCEL));
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::ERASE_CONFIRM));
    run(&mut app, &[Input::Turn(-1), Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::FACTORY_RESET));
    assert_eq!(store.factory_resets(), 0);

    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::FACTORY_RESET_CONFIRM);
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::ERASE_CONFIRM);
    run(&mut app, &[Input::Press]);
    assert_eq!(store.factory_resets(), 1);
    assert_eq!(focus(app.state()), Some(keys::FACTORY_RESET));
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
    open_chat(app, TRAIL_CREW);
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
fn typed_characters_take_the_capital_and_the_period_too() {
    let mut app = app!();
    open_trail_crew(&mut app);
    for word in ["on", "my"] {
        run(&mut app, &typed(word));
        run(&mut app, &[Input::Space]);
    }
    run(&mut app, &typed("way"));
    quick(&mut app, &[Input::Space, Input::Space]);
    assert_eq!(draft(app.state(), TRAIL_CREW), "On my way. ");
    // A capital typed as one takes the armed capital's place.
    run(&mut app, &typed("Ok"));
    assert_eq!(draft(app.state(), TRAIL_CREW), "On my way. Ok");
}

#[test]
fn the_aids_stay_off_when_switched_off() {
    let mut app = app!();
    // Device › Keyboard, Capitalize sentences and Period on double space.
    open_category(&mut app, keys::KEYBOARD);
    assert_eq!(focus(app.state()), Some(keys::CAPITALIZE));
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::PERIOD);
    run(&mut app, &[Input::Press]);
    let settings = app.state().node.keyboard();
    assert!(!settings.capitalize && !settings.period && settings.light);
    run(&mut app, &[Input::Backspace, Input::Backspace]);
    turn_to(&mut app, keys::rail(Section::Chats));
    run(&mut app, &[Input::Press]);

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

/// The pick the open picker has focused.
fn picked(state: &State) -> Option<Pick> {
    state.picker.as_ref()?.focused(state.recents.picks())
}

#[test]
fn alt_then_space_opens_the_picker_and_a_press_types_from_it() {
    let mut app = app!();
    open_trail_crew(&mut app);
    run(&mut app, &keys_for("a"));
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &[Input::Space]);
    // With nothing picked yet, it opens on the first emoji.
    assert_eq!(picked(app.state()), Some(Pick::Emoji(0)));
    run(&mut app, &[Input::Turn(1), Input::Press]);
    assert!(app.state().picker.is_none());
    let pick = Pick::Emoji(1).text();
    assert_eq!(draft(app.state(), TRAIL_CREW), format!("A{pick}"));
    // The field is still being edited.
    run(&mut app, &keys_for("b"));
    assert_eq!(draft(app.state(), TRAIL_CREW), format!("A{pick}b"));

    // It opens next on what was picked, which the node keeps a little
    // later.
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &[Input::Space]);
    assert_eq!(picked(app.state()), Some(Pick::Emoji(1)));
    let now = tick(5000);
    app.state_mut().expire(now);
    assert_eq!(app.state().node.recent_picks().as_str(), format!("{pick}\n"));
    run(&mut app, &[Input::Backspace]);
    assert!(app.state().picker.is_none());

    // Space in the picker switches the keyboard light instead.
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &[Input::Space, Input::Space]);
    assert!(app.state().picker.is_none());
    assert!(!app.state().node.keyboard().light);
    assert!(matches!(
        app.state().glance,
        Some(Glance::KeyboardLight { on: false, .. })
    ));
}

#[test]
fn the_picker_key_opens_and_closes_the_picker_and_only_while_typing() {
    let mut app = app!();
    // Nothing to type into.
    run(&mut app, &[Input::Picker]);
    assert!(app.state().picker.is_none());

    open_trail_crew(&mut app);
    run(&mut app, &keys_for("a"));
    run(&mut app, &[Input::Picker]);
    assert_eq!(picked(app.state()), Some(Pick::Emoji(0)));
    run(&mut app, &[Input::Picker]);
    assert!(app.state().picker.is_none());
    assert_eq!(app.state().keyboard.latches(), (Latch::Off, Latch::Off));
    run(&mut app, &keys_for("b"));
    assert_eq!(draft(app.state(), TRAIL_CREW), "Ab");

    // Locked, it does nothing, and leaves nothing behind.
    app.state_mut().lock();
    app.finalize_view();
    run(&mut app, &[Input::Picker]);
    assert!(app.state().lock.locked);
    assert!(app.state().picker.is_none());
    assert_eq!(app.state().keyboard.latches(), (Latch::Off, Latch::Off));
}

#[test]
fn letters_in_the_picker_find_by_name_and_backspace_takes_them_off() {
    let mut app = app!();
    open_trail_crew(&mut app);
    run(&mut app, &keys_for("a"));
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &[Input::Space]);
    run(&mut app, &typed("<3"));
    assert_eq!(app.state().picker.as_ref().unwrap().filter(), "<3");
    let heart = Pick::of("\u{2764}").unwrap();
    assert_eq!(picked(app.state()), Some(heart));
    run(&mut app, &[Input::Enter]);
    // Two code points, typed whole.
    assert_eq!(draft(app.state(), TRAIL_CREW), "A\u{2764}\u{FE0F}");

    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &[Input::Space]);
    run(&mut app, &typed("zq"));
    assert_eq!(picked(app.state()), None);
    run(&mut app, &[Input::Backspace, Input::Backspace]);
    assert_eq!(app.state().picker.as_ref().unwrap().filter(), "");
    // Back on the recent picks.
    assert_eq!(picked(app.state()), Some(heart));
    run(&mut app, &[Input::Backspace]);
    assert!(app.state().picker.is_none());
}

#[test]
fn alt_and_two_quick_spaces_switch_the_keyboard_light_anywhere() {
    let mut app = app!();
    // On the Chats list, with no field: Alt+Space alone does nothing.
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &[Input::Space]);
    assert!(app.state().picker.is_none());
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
    if BOARD.controls.keyboard != KeyboardKind::Legends {
        return;
    }
    let mut app = app!();
    open_radio(&mut app);
    turn_to(&mut app, keys::TRANSMIT_POWER);
    run(&mut app, &[Input::Press]);
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
fn a_keyboard_with_its_own_symbols_types_transmit_power_as_it_is() {
    if BOARD.controls.keyboard != KeyboardKind::Characters {
        return;
    }
    let mut app = app!();
    open_radio(&mut app);
    turn_to(&mut app, keys::TRANSMIT_POWER);
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::POWER_FIELD));
    // No symbol lock to show: the keyboard's own Sym layer types digits.
    assert_eq!(app.state().keyboard.latches(), (Latch::Off, Latch::Off));
    // What is not part of a number types nothing.
    run(&mut app, &typed("1x "));
    assert!(matches!(
        app.state().screen(),
        Screen::Device { page: DevicePage::TransmitPower { text }, .. } if text.text() == "221"
    ));
}

#[test]
fn a_keyboard_that_reports_its_latches_shows_them() {
    let mut app = app!();
    let report = |shift, symbol| Input::Latches { shift, symbol };
    run(&mut app, &[report(Latch::Once, Latch::Off)]);
    assert_eq!(app.state().keyboard.latches(), (Latch::Once, Latch::Off));
    run(&mut app, &[report(Latch::Off, Latch::Locked)]);
    assert_eq!(app.state().keyboard.latches(), (Latch::Off, Latch::Locked));
    // With none reported, the interface's own show again.
    run(&mut app, &[report(Latch::Off, Latch::Off)]);
    assert_eq!(app.state().keyboard.latches(), (Latch::Off, Latch::Off));
}

#[test]
fn transmit_power_takes_only_a_number() {
    // Symbol lock is the legends keyboard's: the other is just above.
    if BOARD.controls.keyboard != KeyboardKind::Legends {
        return;
    }
    let mut app = app!();
    open_radio(&mut app);
    turn_to(&mut app, keys::TRANSMIT_POWER);
    run(&mut app, &[Input::Press]);
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
    use umsh_ux_communicator::model::{LEVELS, brightness_at};
    assert_eq!(brightness_at(1), 0);
    assert_eq!(brightness_at(LEVELS), 255);
    for level in 1..=LEVELS {
        assert_eq!(brightness_level(brightness_at(level)), level);
    }
    assert_eq!(brightness_level(0), 1);
    assert_eq!(brightness_level(255), LEVELS);
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
    open_chat(&mut app, PAT);
    // Typing, the cursor two back from the end.
    run(&mut app, &typed("Bring"));
    run(&mut app, &[Input::Turn(-2)]);
    let before = messages(app.state()).len();
    let chats = app.state().chats.len();
    app.state_mut().apply(NodeEvent::Resync, 0);
    app.finalize_view();
    assert_in_conversation(app.state(), PAT);
    assert_eq!(draft(app.state(), PAT), "Bring");
    assert_eq!(messages(app.state()).len(), before);
    assert_eq!(app.state().chats.len(), chats);
    assert_eq!(draft(app.state(), RIDGE), RIDGE_DRAFT);
    // Typing goes on where it was.
    run(&mut app, &typed("i"));
    assert_eq!(draft(app.state(), PAT), "Briing");
}

#[test]
fn a_draft_left_unsent_is_kept_by_the_node() {
    let mut app = app!();
    open_chat(&mut app, PAT);
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
    open_chat(&mut app, TRAIL_CREW);
    assert!(!app.state().node.chat(TRAIL_CREW).expect("the chat").unread);
}

#[test]
fn a_message_arriving_in_the_chat_being_read_is_read() {
    let store = store();
    let mut app = app!(store);
    open_chat(&mut app, TRAIL_CREW);
    assert!(!arrive(&mut app, store, 0));
    assert!(!store.chat(TRAIL_CREW).expect("the chat").unread);
    // Taken in twice, it is shown once.
    let shown = messages(app.state());
    let (count, newest) = (shown.len(), shown.last().unwrap().id);
    app.state_mut().apply(
        NodeEvent::Arrived {
            chat: TRAIL_CREW,
            message: newest,
        },
        0,
    );
    assert_eq!(messages(app.state()).len(), count);
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
    open_category(app, keys::CLOCK);
    assert_eq!(focus(app.state()), Some(keys::CLOCK_AUTOMATIC));
}

#[test]
fn the_clock_is_set_by_hand_a_part_at_a_time() {
    let mut app = app!();
    open_clock(&mut app);
    // Automatic, Date and time is a readout and opens nothing.
    turn_to(&mut app, keys::CLOCK_TIME);
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CLOCK_TIME));
    turn_to(&mut app, keys::CLOCK_AUTOMATIC);
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().clock.automatic, Some(false));
    turn_to(&mut app, keys::CLOCK_TIME);
    run(&mut app, &[Input::Press]);
    assert_eq!(
        focus(app.state()),
        Some(keys::time_part(umsh_ux_communicator::nav::Part::Month))
    );
    let before = DateParts::at(app.state().local(app.state().wall_time.unwrap()));
    // Pressed, turning changes the month; pressed again, it moves on.
    run(&mut app, &[Input::Press, Input::Turn(1), Input::Press]);
    turn_to(
        &mut app,
        keys::time_part(umsh_ux_communicator::nav::Part::Minute),
    );
    run(&mut app, &typed("05"));
    turn_to(&mut app, keys::SET_TIME);
    run(&mut app, &[Input::Press]);
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
    turn_to(&mut app, keys::CLOCK_24H);
    run(&mut app, &[Input::Press]);
    assert!(!app.state().hour24());
    let local = app.state().local(app.state().wall_time.unwrap());
    assert!(local.time(app.state().hour24()).ends_with('M'));
}

#[test]
fn letters_narrow_the_time_zones_and_a_press_sets_one() {
    let mut app = app!();
    open_clock(&mut app);
    turn_to(&mut app, keys::CLOCK_ZONE);
    run(&mut app, &[Input::Press]);
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

#[test]
fn rolling_down_and_up_the_list_moves_as_the_wheel_does() {
    let mut app = app!();
    let (first, second) = (app.state().chats[0].id, app.state().chats[1].id);
    run(&mut app, &[Input::Move(Arrow::Down)]);
    assert_eq!(focus(app.state()), Some(keys::chat(second)));
    run(&mut app, &[Input::Move(Arrow::Up)]);
    assert_eq!(focus(app.state()), Some(keys::chat(first)));
}

#[test]
fn rolling_left_from_a_list_reaches_the_rail_and_right_enters_a_section() {
    let mut app = app!();
    run(&mut app, &[Input::Move(Arrow::Left)]);
    assert_eq!(focus(app.state()), Some(keys::rail(Section::Chats)));
    run(&mut app, &[Input::Move(Arrow::Down), Input::Move(Arrow::Right)]);
    assert_eq!(app.state().section, Section::Peers);
    assert_eq!(focus(app.state()), Some(keys::ADD_PEER));
}

#[test]
fn rolling_across_a_switch_sets_it() {
    let mut app = app!();
    open_radio(&mut app);
    turn_to(&mut app, keys::SHARE_LOCATION);
    run(&mut app, &[Input::Move(Arrow::Left)]);
    assert!(!radio(app.state()).share_location);
    run(&mut app, &[Input::Move(Arrow::Right)]);
    assert!(radio(app.state()).share_location);
    run(&mut app, &[Input::Move(Arrow::Right)]);
    assert!(radio(app.state()).share_location);
    run(&mut app, &[Input::Move(Arrow::Left)]);
    assert!(!radio(app.state()).share_location);
}

#[test]
fn rolling_up_a_part_of_the_date_adds_and_across_is_done_with_it() {
    let mut app = app!();
    open_clock(&mut app);
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::CLOCK_TIME);
    run(&mut app, &[Input::Press]);
    let month =keys::time_part(umsh_ux_communicator::nav::Part::Month);
    assert_eq!(focus(app.state()), Some(month));
    let shown = |state: &State| match state.screen() {
        Screen::Device {
            page:
                DevicePage::Clock {
                    page: umsh_ux_communicator::nav::ClockPage::SetTime { parts, .. },
                },
            ..
        } => parts.month,
        other => panic!("expected the date and time, got {other:?}"),
    };
    let before = shown(app.state());
    run(
        &mut app,
        &[
            Input::Press,
            Input::Move(Arrow::Up),
            Input::Move(Arrow::Up),
            Input::Move(Arrow::Down),
        ],
    );
    assert_eq!(shown(app.state()), before % 12 + 1);
    // Across, the month is done with: rolling up no longer changes it.
    run(&mut app, &[Input::Move(Arrow::Right), Input::Move(Arrow::Up)]);
    assert_eq!(shown(app.state()), before % 12 + 1);
}

#[test]
fn the_picker_rolls_a_row_up_and_down_and_a_character_across() {
    let columns = ui::picker_columns(&BOARD.metrics) as u16;
    let mut app = app!();
    open_trail_crew(&mut app);
    run(&mut app, &typed("a"));
    run(&mut app, &tap(Modifier::Alt));
    run(&mut app, &[Input::Space]);
    assert_eq!(picked(app.state()), Some(Pick::Emoji(0)));
    run(&mut app, &[Input::Move(Arrow::Right)]);
    assert_eq!(picked(app.state()), Some(Pick::Emoji(1)));
    run(&mut app, &[Input::Move(Arrow::Down)]);
    assert_eq!(picked(app.state()), Some(Pick::Emoji(1 + columns)));
    run(&mut app, &[Input::Move(Arrow::Left), Input::Move(Arrow::Up)]);
    assert_eq!(picked(app.state()), Some(Pick::Emoji(0)));
    // At an edge, it stays.
    run(&mut app, &[Input::Move(Arrow::Up), Input::Move(Arrow::Left)]);
    assert_eq!(picked(app.state()), Some(Pick::Emoji(0)));
}

#[test]
fn rolling_does_nothing_while_locked() {
    let mut app = app!();
    lock(&mut app);
    run(
        &mut app,
        &[
            Input::Move(Arrow::Down),
            Input::Move(Arrow::Down),
            Input::Move(Arrow::Right),
        ],
    );
    assert!(app.state().lock.locked);
    assert_eq!(app.state().lock.steps, 0);
}

#[test]
fn the_radio_turns_off_and_on_from_its_page() {
    let mut app = app!();
    open_category(&mut app, keys::RADIO);
    assert_eq!(focus(app.state()), Some(keys::RADIO_ENABLED));
    assert!(radio(app.state()).enabled);
    run(&mut app, &[Input::Press]);
    assert!(!radio(app.state()).enabled);
    assert!(!app.state().node.radio().enabled);
    run(&mut app, &[Input::Press]);
    assert!(radio(app.state()).enabled);
}

/// Device's Bluetooth, open.
fn open_bluetooth<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    open_category(app, keys::BLUETOOTH);
    assert_eq!(focus(app.state()), Some(keys::BLUETOOTH_ENABLED));
}

#[test]
fn bluetooth_turns_off_and_its_rows_go_with_it() {
    let mut app = app!();
    open_bluetooth(&mut app);
    // The readouts take no focus: the next turn passes them by.
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::PAIRING));
    turn_to(&mut app, keys::BLUETOOTH_ENABLED);
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().node.bluetooth_enabled(), Some(false));
    // Nothing below the switch is left to land on.
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::BLUETOOTH_ENABLED));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().node.bluetooth_enabled(), Some(true));
}

#[test]
fn pairing_opens_shows_its_pin_and_pairings_clear_once_confirmed() {
    let mut app = app!();
    open_bluetooth(&mut app);
    turn_to(&mut app, keys::PAIRING);
    run(&mut app, &[Input::Press]);
    assert!(app.state().links.bluetooth.pairing);
    // The board reads the window open, and the PIN to give.
    app.state_mut().links.bluetooth.pin = Some(4_321);
    app.finalize_view();
    turn_to(&mut app, keys::CLEAR_PAIRINGS);
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CLEAR_PAIRINGS_CANCEL));
    // Backspace cancels, and nothing is forgotten.
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::CLEAR_PAIRINGS));
    assert_eq!(app.state().links.bluetooth.paired, Some(1));
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::CLEAR_PAIRINGS_CONFIRM);
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::CLEAR_PAIRINGS));
    assert_eq!(app.state().links.bluetooth.paired, Some(0));
}

#[test]
fn gnss_shows_its_fix_while_on() {
    let mut app = app!();
    open_category(&mut app, keys::GNSS);
    // Its readouts take no focus, so turning stays on the switch.
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::GNSS_ENABLED));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().node.gnss_enabled(), Some(false));
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::GNSS_ENABLED));
}

#[test]
fn brightness_turns_while_pressed_and_auto_lock_picks_from_its_choices() {
    let mut app = app!();
    open_category(&mut app, keys::DISPLAY);
    assert_eq!(focus(app.state()), Some(keys::BRIGHTNESS));
    let level = |app: &App<_, State, _>| brightness_level(app.state().node.brightness());
    let before = level(&app);
    // Turning moves focus until Brightness is pressed; then it brightens,
    // turned up, until pressed again.
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::AUTO_LOCK));
    run(&mut app, &[Input::Turn(-1), Input::Press, Input::Turn(-2)]);
    assert_eq!(focus(app.state()), Some(keys::BRIGHTNESS));
    assert_eq!(level(&app), before + 2);
    run(&mut app, &[Input::Press, Input::Turn(1)]);
    assert_eq!(level(&app), before + 2);
    assert_eq!(focus(app.state()), Some(keys::AUTO_LOCK));
    // Auto-Lock opens on the choice in force, and a choice goes back.
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::auto_lock_choice(1)));
    turn_to(&mut app, keys::auto_lock_choice(0));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().node.auto_lock(), Some(0));
    assert_eq!(focus(app.state()), Some(keys::AUTO_LOCK));
}

#[test]
fn battery_is_listed_once_the_board_reads_it() {
    let mut app = app!();
    app.state_mut().battery(BatteryReading::default(), 0);
    open_device(&mut app);
    let listed = |app: &mut App<_, State, _>| {
        turn_to(app, keys::IDENTITY);
        let mut passed = Vec::new();
        while !passed.contains(&focus(app.state())) {
            passed.push(focus(app.state()));
            run(app, &[Input::Turn(1)]);
        }
        passed.contains(&Some(keys::BATTERY))
    };
    assert!(!listed(&mut app));
    app.state_mut().battery(
        BatteryReading {
            percent: None,
            charge: Some(Charge::Charged),
            millivolts: Some(4_180),
        },
        0,
    );
    app.finalize_view();
    assert!(listed(&mut app));
    turn_to(&mut app, keys::BATTERY);
    run(&mut app, &[Input::Press]);
    // Nothing on it to focus: the screen takes focus as a whole.
    assert_eq!(focus(app.state()), Some(keys::READING));
    // The voltage is news only while it is shown.
    let wavered = BatteryReading {
        millivolts: Some(4_170),
        ..app.state().battery
    };
    assert!(app.state().battery_changes(&wavered));
    run(&mut app, &[Input::Backspace]);
    assert!(!app.state().battery_changes(&wavered));
}

#[test]
fn statistics_are_read_while_shown() {
    let mut app = app!();
    open_category(&mut app, keys::STATISTICS);
    assert_eq!(focus(app.state()), Some(keys::READING));
    // The fixture counts more traffic with each read.
    let sent = |app: &App<_, State, _>| app.state().node.statistics().sent;
    let opened = sent(&app);
    // Turning scrolls, and focus stays with the screen.
    for _ in 0..20 {
        run(&mut app, &[Input::Turn(1)]);
    }
    assert_eq!(focus(app.state()), Some(keys::READING));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::STATISTICS));
    assert_eq!(sent(&app), opened);
    run(&mut app, &[Input::Press]);
    assert!(sent(&app) > opened);
}

#[test]
fn about_opens_credits_and_backs_out() {
    let mut app = app!();
    open_category(&mut app, keys::ABOUT);
    // Credits is all there is to focus.
    assert_eq!(focus(app.state()), Some(keys::CREDITS));
    run(&mut app, &[Input::Turn(-1)]);
    assert_eq!(focus(app.state()), Some(keys::CREDITS));
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::READING));
    for _ in 0..40 {
        run(&mut app, &[Input::Turn(1)]);
    }
    assert_eq!(focus(app.state()), Some(keys::READING));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::CREDITS));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::ABOUT));
}

/// Turns to the newest message of the conversation shown: up from the
/// composer, or down from an older message.
fn to_newest<V, F>(app: &mut App<V, State, F>) -> u32
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    let newest = messages(app.state()).last().map(|m| m.id).expect("a message");
    for _ in 0..40 {
        let at = focus(app.state());
        if at == Some(keys::message(newest)) {
            return newest;
        }
        let turn = if at == Some(keys::COMPOSER) { -1 } else { 1 };
        run(app, &[Input::Turn(turn)]);
    }
    panic!("never reached the newest message: {:?}", focus(app.state()));
}

/// Share contact sends a saved peer's link to the chat picked, where it
/// shows as their card. Show opens their page while they are saved, and
/// their unsaved sheet, on Message, once they are not: nothing is saved
/// until Save peer.
#[test]
fn a_contact_is_shared_as_a_card_that_saves_nothing_by_itself() {
    let mut app = app!();
    open_pat(&mut app);
    turn_to(&mut app, keys::PEER_SHARE);
    run(&mut app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::ShareContact { .. }));
    let first = app.state().chats.first().map(|c| c.id).unwrap();
    assert_eq!(focus(app.state()), Some(keys::chat(first)));
    run(&mut app, &[Input::Press]);
    assert_in_conversation(app.state(), first);
    let card = to_newest(&mut app);
    let message = app.state().open_message(card).unwrap();
    assert!(message.text.as_str().starts_with("umsh:n:YmRG"));
    assert_eq!(message.contact().map(|c| c.name.as_str()), Some("Pat Okafor"));
    let preview = app.state().chat(first).unwrap().preview.as_str();
    assert_eq!(preview, "You: Contact: Pat Okafor");

    // A card offers Show first; Pat is saved, so it opens their page.
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::VIEW_CONTACT));
    run(&mut app, &[Input::Press]);
    assert!(peer_detail(app.state()).address.starts_with("YmRG"));

    // Forgotten, Pat's card opens what is known of them, unsaved.
    let peers = app.state().peers.len();
    turn_to(&mut app, keys::PEER_FORGET);
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::FORGET_CONFIRM);
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().peers.len(), peers - 1);
    // Forget goes back to where the page was opened from.
    assert!(matches!(app.state().screen(), Screen::Conversation { .. }));
    to_newest(&mut app);
    run(&mut app, &[Input::Press, Input::Press]);
    let Screen::Member { member, .. } = app.state().screen() else {
        panic!("expected the member sheet, got {:?}", app.state().screen());
    };
    assert!(!member.saved);
    assert_eq!(member.sender.name.as_str(), "Pat Okafor");
    assert_eq!(focus(app.state()), Some(keys::MESSAGE_MEMBER));
    assert_eq!(app.state().peers.len(), peers - 1);
    turn_to(&mut app, keys::SAVE_PEER);
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().peers.len(), peers);
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

// ─── A long chat ─────────────────────────────────────────────────────────

/// The public channel, which holds the fixture's long history when asked.
const PUBLIC: u32 = 4;

fn long_store() -> &'static fixture::Store {
    Box::leak(Box::new(
        fixture::Store::new(&std::alloc::System).with_long_history(),
    ))
}

/// The keys of the long chat's rows that focus lands on, oldest first:
/// every row but those standing in for messages on their way again.
fn focusable_rows(state: &State) -> Vec<FocusKey> {
    let node = state.node;
    (0..node.rows(PUBLIC))
        .filter(|&row| {
            node.neighbor(PUBLIC, row)
                .is_some_and(|n| n.presence != Presence::PendingRepair)
        })
        .filter_map(|row| node.row_id(PUBLIC, row))
        .map(keys::message)
        .collect()
}

/// Paints the screen as it is once what the last input set moving has come
/// to rest, and once more, as a board does when a frame asks for another.
fn settle<V, F>(app: &mut App<V, State, F>)
where
    V: buoyant::view::View<embedded_graphics::pixelcolor::Rgb565, State>,
    V::FocusTree: DefaultFocus,
    F: Fn(&State) -> V,
{
    app.set_time(std::time::Duration::from_millis(tick(1000)));
    paint(app);
    paint(app);
}

/// Where the focused element is on screen.
fn focus_box<V, F>(app: &mut App<V, State, F>) -> buoyant::primitives::geometry::Rectangle
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    app.focus_shape()
        .bounding_box()
        .expect("the focused element is on screen")
}

/// Turns the wheel back through the long chat's messages from the composer
/// until `count` have had focus, painting each. Returns the last.
fn read_back<V, F>(app: &mut App<V, State, F>, count: usize) -> FocusKey
where
    V: buoyant::view::View<embedded_graphics::pixelcolor::Rgb565, State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    let mut seen = 0;
    let mut at = focus(app.state());
    while seen < count {
        run(app, &[Input::Turn(-1)]);
        settle(app);
        let now = focus(app.state());
        if now != at && now.is_some_and(keys::is_message) {
            seen += 1;
        }
        at = now;
    }
    at.expect("a message has focus")
}

/// The wheel reaches every message of a long chat, newest to oldest and
/// back, each in view as it has focus, a run on its way again with them.
#[test]
fn the_wheel_walks_a_long_chat_to_its_oldest_message_and_back() {
    let store = long_store();
    // Still far more than the history builds at once, and both runs on
    // their way again with it, in half the steps.
    store.evict_oldest(250);
    let mut app = app!(store);
    open_chat(&mut app, PUBLIC);
    settle(&mut app);
    let rows = focusable_rows(app.state());
    assert!(rows.len() > 250, "{} rows", rows.len());
    let height = BOARD.metrics.size().height as i32;
    let walk = |app: &mut App<_, State, _>, step: i8, to: FocusKey| {
        let mut seen: Vec<FocusKey> = Vec::new();
        for _ in 0..rows.len() * 3 {
            run(app, &[Input::Turn(step)]);
            app.set_time(std::time::Duration::from_millis(tick(1000)));
            paint(app);
            let Some(at) = focus(app.state()).filter(|&key| keys::is_message(key)) else {
                continue;
            };
            if seen.last() != Some(&at) {
                let area = focus_box(app);
                let bottom = area.origin.y + area.size.height as i32;
                assert!(area.origin.y < height && bottom > 0, "{at:?} at {area:?}");
                seen.push(at);
            }
            if at == to {
                break;
            }
        }
        seen
    };
    let mut back = walk(&mut app, -1, rows[0]);
    back.reverse();
    assert_eq!(back, rows);
    let ahead = walk(&mut app, 1, *rows.last().unwrap());
    assert_eq!(ahead, rows[1..]);
}

/// A message arriving while the chat is read far back leaves the message
/// being read where it is on screen, as does the store letting go of the
/// oldest to make room.
#[test]
fn what_is_read_far_back_stays_put_as_messages_come_and_go() {
    let store = long_store();
    let mut app = app!(store);
    open_chat(&mut app, PUBLIC);
    settle(&mut app);
    let reading = read_back(&mut app, 40);
    let was = focus_box(&mut app);

    arrive_in(&mut app, store, PUBLIC, "Checking in from the hut", tick(1000));
    settle(&mut app);
    assert_eq!(focus(app.state()), Some(reading));
    assert_eq!(focus_box(&mut app), was);

    // Most of the history goes, the message being read with it in view.
    store.evict_oldest(450);
    input::events(&mut app, tick(1000));
    settle(&mut app);
    assert_eq!(focus(app.state()), Some(reading));
    assert_eq!(focus_box(&mut app), was);
}

/// A message arriving while the newest is read comes into view below it.
#[test]
fn a_message_arriving_at_the_end_of_a_long_chat_shows() {
    let store = long_store();
    let mut app = app!(store);
    open_chat(&mut app, PUBLIC);
    settle(&mut app);
    let newest = read_back(&mut app, 1);
    assert_eq!(Some(&newest), focusable_rows(app.state()).last());
    let was = focus_box(&mut app);
    arrive_in(&mut app, store, PUBLIC, "Checking in from the hut", tick(1000));
    settle(&mut app);
    let now = focus_box(&mut app);
    assert!(now.origin.y < was.origin.y, "{now:?} from {was:?}");
}

/// A message far back in a long chat opens its actions.
#[test]
fn a_message_far_back_opens_its_actions() {
    let mut app = app!(long_store());
    open_chat(&mut app, PUBLIC);
    settle(&mut app);
    let reading = read_back(&mut app, 60);
    let id = app
        .state()
        .node
        .row_id(
            PUBLIC,
            (0..app.state().node.rows(PUBLIC))
                .find(|&row| {
                    app.state().node.row_id(PUBLIC, row).map(keys::message) == Some(reading)
                })
                .expect("the row read"),
        )
        .unwrap();
    run(&mut app, &[Input::Press]);
    assert_eq!(actions(app.state()), Some(id));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(actions(app.state()), None);
    assert_eq!(focus(app.state()), Some(reading));
}

/// The route on the screen shown, once it has been read.
fn shown_route(state: &State) -> Option<PeerRoute> {
    match state.screen() {
        Screen::Route { peer, .. } => state.node.peer_route(*peer),
        other => panic!("expected a route, got {other:?}"),
    }
}

/// How the latest ping on the screen shown went.
fn shown_ping(state: &State) -> Option<PingView> {
    match state.screen() {
        Screen::Ping { peer, .. } => state.node.ping_view(*peer),
        other => panic!("expected a ping, got {other:?}"),
    }
}

/// Opens the saved peer `name` from the Peers list.
fn open_peer<V, F>(app: &mut App<V, State, F>, name: &str)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    run(app, &[Input::Backspace]);
    turn_to(app, keys::rail(Section::Peers));
    run(app, &[Input::Press]);
    let peer = app
        .state()
        .peers
        .iter()
        .find(|p| p.name.as_str() == name)
        .map(|p| p.id)
        .expect("saved");
    turn_to(app, keys::peer(peer));
    run(app, &[Input::Press]);
    assert!(matches!(app.state().screen(), Screen::Peer { .. }));
}

/// Opens the route to the saved peer `name`.
fn open_route_to<V, F>(app: &mut App<V, State, F>, name: &str)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    open_peer(app, name);
    turn_to(app, keys::PEER_ROUTE);
    run(app, &[Input::Press]);
    assert!(shown_route(app.state()).is_some());
}

#[test]
fn a_route_lists_its_repeaters_and_backspace_returns_to_the_peer() {
    let mut app = app!();
    open_peer(&mut app, "Jo Reyes");
    assert_eq!(peer_detail(app.state()).route.as_deref(), Some("3 hops"));
    turn_to(&mut app, keys::PEER_ROUTE);
    run(&mut app, &[Input::Press]);
    let route = shown_route(app.state()).unwrap();
    assert_eq!(route.kind, RouteKind::Source);
    assert_eq!(route.repeaters.len(), 2);
    // The wheel stops on the repeaters and Reset route, never on this
    // device or the peer.
    let mut stops: Vec<_> = focus(app.state()).into_iter().collect();
    for _ in 0..6 {
        run(&mut app, &[Input::Turn(1)]);
        if let Some(key) = focus(app.state())
            && !stops.contains(&key)
        {
            stops.push(key);
        }
    }
    for key in &stops {
        assert!(
            [keys::path(0), keys::path(1), keys::ROUTE_RESET, keys::READING].contains(key),
            "stopped on {key:?}"
        );
    }
    assert!(stops.contains(&keys::path(0)));
    assert!(stops.contains(&keys::path(1)));
    assert!(stops.contains(&keys::ROUTE_RESET));
    run(&mut app, &[Input::Backspace]);
    assert!(matches!(app.state().screen(), Screen::Peer { .. }));
    assert_eq!(focus(app.state()), Some(keys::PEER_ROUTE));
}

#[test]
fn an_unknown_repeater_on_a_route_is_asked_by_way_of_those_before_it() {
    let store = store();
    let mut app = app!(store);
    open_route_to(&mut app, "Jo Reyes");
    let route = shown_route(app.state()).unwrap();
    let (nearby, unknown) = (route.repeaters[0].hint, route.repeaters[1].hint);
    assert!(route.repeaters[1].address.is_none());
    turn_to(&mut app, keys::path(1));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().identifying().as_slice(), [unknown]);
    assert_eq!(store.repeater_route().as_slice(), [nearby]);
    assert!(app.state().next_deadline().is_some());

    let at = store.next_deadline().expect("the answer is due");
    store.advance(at);
    input::events(&mut app, at);
    let route = shown_route(app.state()).unwrap();
    assert_eq!(&*route.repeaters[1].name, "Bald Knob");
    assert!(route.repeaters[1].address.is_some());
}

#[test]
fn a_known_repeater_on_a_route_opens_and_backspace_returns() {
    let mut app = app!();
    open_route_to(&mut app, "Jo Reyes");
    turn_to(&mut app, keys::path(0));
    run(&mut app, &[Input::Press]);
    assert_eq!(&*shown_member(app.state()).0.sender.name, "Riverbend Camp");
    run(&mut app, &[Input::Backspace]);
    assert!(shown_route(app.state()).is_some());
    assert_eq!(focus(app.state()), Some(keys::path(0)));
}

#[test]
fn a_route_reset_is_not_learned_and_offers_a_ping() {
    let mut app = app!();
    open_route_to(&mut app, "Pat Okafor");
    assert_eq!(shown_route(app.state()).unwrap().kind, RouteKind::Direct);
    turn_to(&mut app, keys::ROUTE_RESET);
    run(&mut app, &[Input::Press]);
    let route = shown_route(app.state()).unwrap();
    assert_eq!(route.kind, RouteKind::Unknown);
    assert_eq!(route.confirmed, None);
    turn_to(&mut app, keys::ROUTE_PING);
    run(&mut app, &[Input::Press]);
    assert_eq!(shown_ping(app.state()), Some(PingView::Waiting));
    run(&mut app, &[Input::Backspace, Input::Backspace]);
    assert_eq!(peer_detail(app.state()).route.as_deref(), Some("Not learned"));
}

#[test]
fn a_ping_waits_then_shows_the_path_its_answer_took() {
    let store = store();
    let mut app = app!(store);
    open_peer(&mut app, "Jo Reyes");
    turn_to(&mut app, keys::PEER_PING);
    run(&mut app, &[Input::Press]);
    assert_eq!(shown_ping(app.state()), Some(PingView::Waiting));
    assert!(app.state().ping_elapsed().is_some());
    // The count and the spinner keep the screen coming back.
    assert!(app.state().next_deadline().is_some());

    let at = store.next_deadline().expect("the answer is due");
    store.advance(at);
    input::events(&mut app, at);
    let Some(PingView::Reply(reply)) = shown_ping(app.state()) else {
        panic!("no reply: {:?}", shown_ping(app.state()));
    };
    assert_eq!(reply.round_trip_ms, 1_400);
    assert_eq!(reply.hops, Some(3));
    assert_eq!(reply.repeaters.len(), 2);
    assert_eq!(reply.legs.len(), 3);
    assert!(matches!(reply.legs[0], Leg::Heard(_)));
    assert_eq!(app.state().ping_elapsed(), None);
    assert_eq!(focus(app.state()), Some(keys::PING_AGAIN));

    run(&mut app, &[Input::Press]);
    assert_eq!(shown_ping(app.state()), Some(PingView::Waiting));
    let Screen::Ping { earlier, .. } = app.state().screen() else {
        panic!("not on a ping");
    };
    assert_eq!(earlier.len(), 1);
    assert_eq!(earlier[0].round_trip_ms, Some(1_400));
    assert_eq!(earlier[0].hops, Some(3));
}

#[test]
fn a_ping_nobody_answers_ends_as_no_reply() {
    let store = store();
    let mut app = app!(store);
    open_peer(&mut app, "Dana Cho");
    turn_to(&mut app, keys::PEER_PING);
    run(&mut app, &[Input::Press]);
    let at = store.next_deadline().expect("the wait ends");
    store.advance(at);
    input::events(&mut app, at);
    assert_eq!(shown_ping(app.state()), Some(PingView::NoReply));
    assert_eq!(focus(app.state()), Some(keys::PING_AGAIN));
}

#[test]
fn a_peer_forgotten_while_its_ping_is_open_backs_out() {
    let store = store();
    let mut app = app!(store);
    open_route_to(&mut app, "Pat Okafor");
    turn_to(&mut app, keys::ROUTE_RESET);
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::ROUTE_PING);
    run(&mut app, &[Input::Press]);
    let Screen::Ping { peer, .. } = *app.state().screen() else {
        panic!("not on a ping");
    };
    store.forget_peer(peer);
    input::events(&mut app, 0);
    assert!(matches!(app.state().screen(), Screen::Chats { .. }));
    assert!(app.state().peer(peer).is_none());
}

/// Device › Wi-Fi, its switch focused.
fn open_wifi<V, F>(app: &mut App<V, State, F>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    open_category(app, keys::WIFI);
    assert_eq!(focus(app.state()), Some(keys::WIFI_ENABLED));
}

/// Where Nearby lists `ssid`.
fn nearby(state: &State, ssid: &[u8]) -> usize {
    state
        .wifi
        .nearby
        .iter()
        .position(|network| network.ssid == ssid)
        .expect("heard")
}

/// Where Saved lists `ssid`.
fn saved(state: &State, ssid: &[u8]) -> usize {
    state
        .wifi
        .saved
        .iter()
        .position(|network| network.ssid == ssid)
        .expect("saved")
}

#[test]
fn wifi_lists_the_network_in_use_then_saved_and_nearby() {
    let mut app = app!();
    open_wifi(&mut app);
    let wifi = &app.state().wifi;
    assert_eq!(wifi.current, b"Okafor-5G");
    assert_eq!(wifi.status, WifiStatus::Connected);
    // Opening it scanned; what is saved is not listed again as nearby.
    assert!(wifi.nearby.iter().any(|network| network.ssid == b"NETGEAR47"));
    assert!(!wifi.nearby.iter().any(|network| network.ssid == b"Home"));
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_CURRENT));
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::wifi_saved(saved(app.state(), b"Home"))));
}

#[test]
fn ip_multicast_is_the_last_row_and_a_switch() {
    let mut app = app!();
    open_wifi(&mut app);
    assert_eq!(app.state().wifi.address, Some([192, 168, 1, 23]));
    assert_eq!(app.state().wifi.ip_multicast, Some(false));
    turn_to(&mut app, keys::WIFI_IP_MULTICAST);
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_IP_MULTICAST));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().wifi.ip_multicast, Some(true));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().wifi.ip_multicast, Some(false));
}

#[test]
fn a_nearby_network_joins_once_its_password_is_typed() {
    let mut app = app!();
    open_wifi(&mut app);
    let index = nearby(app.state(), b"NETGEAR47");
    turn_to(&mut app, keys::wifi_nearby(index));
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_PASSWORD_FIELD));
    // Too short to be a password: Enter does nothing.
    run(&mut app, &typed("router"));
    run(&mut app, &[Input::Enter]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_PASSWORD_FIELD));
    run(&mut app, &typed("-47"));
    run(&mut app, &[Input::Enter]);
    let wifi = &app.state().wifi;
    assert_eq!(wifi.current, b"NETGEAR47");
    assert_eq!(wifi.status, WifiStatus::Connected);
    assert!(wifi.saved.iter().any(|network| network.ssid == b"NETGEAR47" && network.auto_join));
}

#[test]
fn an_open_network_joins_on_the_press() {
    let mut app = app!();
    open_wifi(&mut app);
    let index = nearby(app.state(), "Trailhead Café".as_bytes());
    turn_to(&mut app, keys::wifi_nearby(index));
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().wifi.current, "Trailhead Café".as_bytes());
}

#[test]
fn a_wrong_password_is_named_and_its_sheet_offers_a_new_one_first() {
    let mut app = app!();
    open_wifi(&mut app);
    let index = nearby(app.state(), b"NETGEAR47");
    turn_to(&mut app, keys::wifi_nearby(index));
    run(&mut app, &[Input::Press]);
    run(&mut app, &typed("not-the-one"));
    run(&mut app, &[Input::Enter]);
    assert_eq!(app.state().wifi.status, WifiStatus::WrongPassword);
    turn_to(&mut app, keys::WIFI_CURRENT);
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_CHANGE_PASSWORD));
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_PASSWORD_FIELD));
    run(&mut app, &typed("router-47"));
    run(&mut app, &[Input::Enter]);
    // Back on the list, joined.
    assert!(matches!(
        app.state().screen(),
        Screen::Device {
            page: DevicePage::Wifi { .. },
            ..
        }
    ));
    assert_eq!(app.state().wifi.status, WifiStatus::Connected);
}

#[test]
fn disconnect_leaves_and_a_saved_network_joins_from_its_sheet() {
    let mut app = app!();
    open_wifi(&mut app);
    turn_to(&mut app, keys::WIFI_CURRENT);
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_ACT));
    run(&mut app, &[Input::Press]);
    let wifi = &app.state().wifi;
    assert!(wifi.current.is_empty());
    assert!(!wifi.searching, "Disconnect joins nothing by itself");
    let index = saved(app.state(), b"Home");
    turn_to(&mut app, keys::wifi_saved(index));
    run(&mut app, &[Input::Press]);
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().wifi.current, b"Home");
}

#[test]
fn join_automatically_turns_off_without_a_password() {
    let mut app = app!();
    open_wifi(&mut app);
    turn_to(&mut app, keys::WIFI_CURRENT);
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::WIFI_AUTO_JOIN);
    run(&mut app, &[Input::Press]);
    let index = saved(app.state(), b"Okafor-5G");
    assert!(!app.state().wifi.saved[index].auto_join);
}

#[test]
fn forgetting_a_network_asks_first() {
    let mut app = app!();
    open_wifi(&mut app);
    let index = saved(app.state(), b"Home");
    turn_to(&mut app, keys::wifi_saved(index));
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::WIFI_FORGET);
    run(&mut app, &[Input::Press]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_FORGET_CANCEL));
    run(&mut app, &[Input::Backspace]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_FORGET));
    assert!(app.state().wifi.saved(b"Home").is_some());
    run(&mut app, &[Input::Press]);
    turn_to(&mut app, keys::WIFI_FORGET_CONFIRM);
    run(&mut app, &[Input::Press]);
    assert!(app.state().wifi.saved(b"Home").is_none());
}

#[test]
fn wifi_turned_off_is_only_its_switches() {
    let mut app = app!();
    open_wifi(&mut app);
    run(&mut app, &[Input::Press]);
    assert_eq!(app.state().wifi.enabled, Some(false));
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_IP_MULTICAST));
    run(&mut app, &[Input::Turn(1)]);
    assert_eq!(focus(app.state()), Some(keys::WIFI_IP_MULTICAST));
    run(&mut app, &[Input::Turn(-1), Input::Press]);
    assert_eq!(app.state().wifi.current, b"Okafor-5G");
}
