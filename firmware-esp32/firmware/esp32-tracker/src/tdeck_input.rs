//! The T-Deck's controls: the trackball, its press, the keyboard, and the
//! touch panel.
//! The trackball is captured by interrupt while the panel is lit and not
//! at all while it is dark, so a roll never wakes it; the press and the
//! keys do. What a gesture means is the input gate's.
use super::*;
use crate::input_gate::{
    self, CHANGED, control, finish_gesture, hold, note_activity, send, start_gesture, wake_display,
};
use core::cell::RefCell;
use esp_hal::gpio::Io;
use esp_hal::peripherals;
use esp_hal::ram;
use esp_hal::rtc_cntl::WakeLock;
use umsh_tdeck_peripherals::gt911::{Gt911, Report};
use umsh_tdeck_peripherals::keyboard::{self as keys, Key};
use umsh_tdeck_peripherals::trackball::{Direction, Trackball};
use umsh_ux_communicator::input::{Arrow, Input as UiItem, TouchPhase};
use umsh_ux_communicator::keyboard::Modifier;
use umsh_ux_display_tracker::input_power::{Gesture, Mode};
use umsh_ux_tracker::debounce::{Debounce, PressLatch};

/// The T-Deck's controls produce the communicator's inputs directly.
pub(crate) type Item = UiItem;

pub(crate) fn to_input(input: UiItem) -> UiItem {
    input
}

static KEYBOARD_RETRY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOP_PRESS: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOP_KEYBOARD: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOP_TOUCH: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// The capture tasks [`stop`] ends: the press, the keyboard, and touch.
pub(crate) const STOPPERS: u32 = 3;

pub(crate) fn stop() {
    STOP_PRESS.signal(());
    STOP_KEYBOARD.signal(());
    STOP_TOUCH.signal(());
}

/// The panel lit: a keyboard that failed is tried again at once.
pub(crate) fn shown() {
    KEYBOARD_RETRY.signal(());
}

pub(crate) fn lit(_lit: bool) {}

/// There is no locate alert on this board.
pub(crate) fn alert_active() -> bool {
    false
}

pub(crate) fn cancel_alert() {}

struct Ball {
    /// Up, Right, Down, Left.
    pins: [Input<'static>; 4],
    decoder: Trackball,
}
const DIRECTIONS: [Direction; 4] = [
    Direction::Up,
    Direction::Right,
    Direction::Down,
    Direction::Left,
];
static BALL: critical_section::Mutex<RefCell<Option<Ball>>> =
    critical_section::Mutex::new(RefCell::new(None));

pub fn init_trackball(
    io: peripherals::IO_MUX<'static>,
    up: peripherals::GPIO3<'static>,
    right: peripherals::GPIO2<'static>,
    down: peripherals::GPIO15<'static>,
    left: peripherals::GPIO1<'static>,
) {
    control(hold);
    let mut io = Io::new(io);
    io.set_interrupt_handler(trackball_interrupt);
    let config = InputConfig::default().with_pull(Pull::Up);
    let ball = Ball {
        pins: [
            Input::new(up, config),
            Input::new(right, config),
            Input::new(down, config),
            Input::new(left, config),
        ],
        decoder: Trackball::default(),
    };
    critical_section::with(|cs| BALL.borrow_ref_mut(cs).replace(ball));
    listen(true);
}

/// Captures rolls, or stops, starting the count over either way.
fn listen(on: bool) {
    critical_section::with(|cs| {
        let mut slot = BALL.borrow_ref_mut(cs);
        let Some(ball) = slot.as_mut() else { return };
        ball.decoder = Trackball::default();
        for pin in &mut ball.pins {
            if on {
                pin.clear_interrupt();
                pin.listen(Event::AnyEdge);
            } else {
                pin.unlisten();
            }
        }
    });
}

#[esp_hal::handler]
#[ram]
fn trackball_interrupt() {
    critical_section::with(|cs| {
        let mut slot = BALL.borrow_ref_mut(cs);
        let Some(ball) = slot.as_mut() else { return };
        let now = Instant::now().as_millis();
        for (pin, direction) in ball.pins.iter_mut().zip(DIRECTIONS) {
            if !pin.is_interrupt_set() {
                continue;
            }
            pin.clear_interrupt();
            note_activity();
            if let Some(step) = ball.decoder.edge(direction, now) {
                finish_gesture(UiItem::Move(arrow(step)), start_gesture());
            }
        }
    });
}

fn arrow(direction: Direction) -> Arrow {
    match direction {
        Direction::Up => Arrow::Up,
        Direction::Down => Arrow::Down,
        Direction::Left => Arrow::Left,
        Direction::Right => Arrow::Right,
    }
}

/// Lit, the trackball is captured; dark, nothing here holds the chip
/// awake, and the press or a key brings the panel back.
#[embassy_executor::task]
pub async fn coordinator() {
    loop {
        CHANGED.reset();
        let (mode, epoch) = control(|c| (c.policy.mode, c.policy.epoch));
        match mode {
            Mode::Interactive => {
                listen(true);
                input_gate::captured(epoch);
            }
            Mode::Shutdown => {
                listen(false);
                input_gate::coordinator_stopped(epoch);
                return;
            }
            Mode::Dark => {
                listen(false);
                let raced = control(|c| {
                    if c.policy.arm(epoch) {
                        c.guard.take();
                        return false;
                    }
                    c.policy.mode == Mode::Dark
                        && (c.policy.activity_since_dark() || input_gate::navigation_pending())
                });
                // An input between going dark and here brings it back.
                if raced {
                    wake_display();
                    continue;
                }
            }
        }
        CHANGED.wait().await;
    }
}

#[embassy_executor::task]
pub async fn press_task(mut pin: Input<'static>) {
    select(run_press(&mut pin), STOP_PRESS.wait()).await;
    drop(pin);
    input_gate::stopped();
}

async fn run_press(pin: &mut Input<'static>) {
    let mut debounce = Debounce::new(false);
    let mut press_cycle = PressLatch::default();
    // The press going down reached the interface, so its coming up does
    // too, and only its: a release must never wake the panel.
    let mut delivered = false;
    let mut debounce_guard = None;
    loop {
        let now = Instant::now();
        let raw = pin.is_low();
        if raw != debounce.observed() {
            note_activity();
        }
        if press_cycle.observe(raw, now.as_millis()) {
            let gate = start_gesture();
            control(|c| c.policy.begin_press(gate));
        }
        if let Some(pressed) = debounce.sample(raw, now.as_millis()) {
            if pressed {
                let disposition = control(|c| c.policy.press_disposition());
                delivered = disposition == Gesture::Navigate;
                finish_gesture(UiItem::Press, disposition);
            } else {
                control(|c| c.policy.release_press());
                if core::mem::take(&mut delivered) {
                    send(UiItem::Release);
                }
            }
        }
        let deadline = match (debounce.deadline(), press_cycle.deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
        .map(Instant::from_millis);
        if deadline.is_some() {
            debounce_guard.get_or_insert_with(WakeLock::new);
        } else {
            debounce_guard.take();
        }
        let timer = async {
            match deadline {
                Some(at) => Timer::at(at).await,
                None => core::future::pending().await,
            }
        };
        let level = if debounce.observed() {
            Event::HighLevel
        } else {
            Event::LowLevel
        };
        select(pin.wait_for(level), timer).await;
    }
}

#[embassy_executor::task]
pub async fn keyboard_task(bus: &'static board::I2cBus) {
    select(run_keyboard(bus), STOP_KEYBOARD.wait()).await;
    input_gate::stopped();
}

/// When the keyboard's controller first answers: about half a second
/// after the rail it shares rises, which is at boot.
const KEYBOARD_START: Instant = Instant::from_millis(500);
/// How often the keyboard is read: often enough while lit that two keys
/// in quick succession are both seen (it holds only the last), and
/// rarely while dark, when a key only wakes the panel.
const KEYBOARD_LIT: Duration = Duration::from_millis(30);
const KEYBOARD_DARK: Duration = Duration::from_millis(250);
/// The wait before the controller is tried again after a failure: it
/// doubles while failures repeat, and a display wake cuts it short.
const KEYBOARD_RETRY_FIRST: Duration = Duration::from_millis(250);
const KEYBOARD_RETRY_MOST: Duration = Duration::from_secs(8);
/// The key light's duty when lit, the keyboard's own default.
const KEYBOARD_LIGHT_DUTY: u8 = 127;
/// How long after the controller first answers before the light is set:
/// it answers before it has set up the light, which it then turns off.
const KEYBOARD_LIGHT_SETTLE: Duration = Duration::from_millis(500);

async fn run_keyboard(bus: &'static board::I2cBus) {
    let mut keyboard = I2cDevice::new(bus);
    Timer::at(KEYBOARD_START).await;
    let mut retry = KEYBOARD_RETRY_FIRST;
    // The light wanted, and the light last set.
    let mut light = true;
    let mut set = None;
    // When the controller can take the light, once it is answering. A
    // controller that stopped answering may have restarted, with its
    // light off.
    let mut light_from = None;
    loop {
        use embedded_hal_async::i2c::I2c as _;
        if set != Some(light) && light_from.is_some_and(|from| Instant::now() >= from) {
            let duty = if light { KEYBOARD_LIGHT_DUTY } else { 0 };
            // Firmware older than the light command ignores it.
            if let Ok(Ok(())) = with_timeout(
                Duration::from_millis(50),
                keyboard.write(keys::ADDRESS, &keys::backlight(duty)),
            )
            .await
            {
                set = Some(light);
            }
        }
        let mut byte = [0];
        match with_timeout(
            Duration::from_millis(50),
            keyboard.read(keys::ADDRESS, &mut byte),
        )
        .await
        {
            Ok(Ok(())) => {
                retry = KEYBOARD_RETRY_FIRST;
                light_from.get_or_insert_with(|| Instant::now() + KEYBOARD_LIGHT_SETTLE);
                if let Some(key) = keys::key(byte[0]) {
                    deliver(key);
                }
            }
            _ => {
                light_from = None;
                set = None;
                debug_log(format_args!(
                    "tdeck: keyboard not answering; retry in {} ms",
                    retry.as_millis()
                ));
                KEYBOARD_RETRY.reset();
                select(Timer::after(retry), KEYBOARD_RETRY.wait()).await;
                retry = (retry * 2).min(KEYBOARD_RETRY_MOST);
                continue;
            }
        }
        let period = if control(|c| c.policy.mode == Mode::Interactive) {
            KEYBOARD_LIT
        } else {
            KEYBOARD_DARK
        };
        if let Either::Second(lit) =
            select(Timer::after(period), board::display::KEYBOARD_LIGHT.wait()).await
        {
            light = lit;
        }
    }
}

fn deliver(key: Key) {
    let input = match key {
        Key::Character(c) => UiItem::Character(c),
        Key::Space => UiItem::Space,
        Key::Enter => UiItem::Enter,
        Key::Backspace => UiItem::Backspace,
        // The picker's chord, Alt and Space, which is all Alt+C is for.
        Key::AltC => {
            let alt = |down| UiItem::Modifier {
                modifier: Modifier::Alt,
                down,
            };
            let gesture = start_gesture();
            let delivered = gesture == Gesture::Navigate;
            finish_gesture(alt(true), gesture);
            if delivered {
                send(UiItem::Space);
                send(alt(false));
            }
            return;
        }
    };
    finish_gesture(input, start_gesture());
}

/// How often the touch panel is read while lit: about its own report rate.
const TOUCH_LIT: Duration = Duration::from_millis(20);
/// How often the panel's mode is looked at while it is dark, when nothing
/// is read: a touch never wakes it.
const TOUCH_DARK: Duration = Duration::from_millis(250);
/// The tries at finding the controller, a little apart, before the board
/// is taken to have no touch panel.
const TOUCH_PROBES: u32 = 4;
const TOUCH_PROBE_GAP: Duration = Duration::from_millis(250);

type TouchPanel = Gt911<board::I2cHandle>;

#[embassy_executor::task]
pub async fn touch_task(bus: &'static board::I2cBus) {
    let mut panel = None;
    select(run_touch(bus, &mut panel), STOP_TOUCH.wait()).await;
    // The controller keeps power through deep sleep.
    if let Some(panel) = panel.as_mut() {
        let _ = with_timeout(Duration::from_millis(50), panel.sleep()).await;
    }
    input_gate::stopped();
}

async fn run_touch(bus: &'static board::I2cBus, slot: &mut Option<TouchPanel>) {
    let mut device = I2cDevice::new(bus);
    let mut tries = 0;
    let panel = loop {
        match Gt911::probe(device).await {
            Ok(panel) => break slot.insert(panel),
            Err(back) => device = back,
        }
        tries += 1;
        if tries == TOUCH_PROBES {
            debug_log(format_args!("tdeck: no touch panel"));
            return core::future::pending().await;
        }
        Timer::after(TOUCH_PROBE_GAP).await;
    };
    debug_log(format_args!(
        "tdeck: touch panel at {:#04x}",
        panel.address()
    ));
    // The point last sent of a touch whose start reached the interface, and
    // whether one is on the panel at all: one whose start woke the panel or
    // was otherwise taken goes no further.
    let mut contact: Option<Option<(i16, i16)>> = None;
    loop {
        if control(|c| c.policy.mode != Mode::Interactive) {
            if let Some(Some((x, y))) = contact.take() {
                send(touch(TouchPhase::Cancelled, x, y));
            }
            Timer::after(TOUCH_DARK).await;
            continue;
        }
        match with_timeout(Duration::from_millis(50), panel.read()).await {
            Ok(Ok(Report::Pending)) => {}
            Ok(Ok(Report::Touched(point))) => {
                note_activity();
                let at = (point.x as i16, point.y as i16);
                match contact {
                    None => {
                        let gesture = start_gesture();
                        let delivered = gesture == Gesture::Navigate;
                        finish_gesture(touch(TouchPhase::Started, at.0, at.1), gesture);
                        contact = Some(delivered.then_some(at));
                    }
                    Some(Some(last)) if last != at => {
                        send(touch(TouchPhase::Moved, at.0, at.1));
                        contact = Some(Some(at));
                    }
                    Some(_) => {}
                }
            }
            Ok(Ok(Report::Released)) => {
                note_activity();
                if let Some(Some((x, y))) = contact.take() {
                    send(touch(TouchPhase::Ended, x, y));
                }
            }
            // A failed read is dropped; the next one tries again.
            _ => {}
        }
        Timer::after(TOUCH_LIT).await;
    }
}

fn touch(phase: TouchPhase, x: i16, y: i16) -> UiItem {
    UiItem::Touch { phase, x, y }
}
