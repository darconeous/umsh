//! The T-Deck's controls: the trackball, its press, the keyboard, and the
//! touch panel.
//! The trackball and the touch panel's INT are captured by interrupt while
//! the panel is lit and not at all while it is dark, and the keyboard is
//! not read while it is dark, so only the press wakes it. Dark, the touch
//! controller sleeps, and so, after it, does a keyboard whose controller
//! runs UMSH's firmware. The microphone ADC is powered down at boot. What a
//! gesture means is the input gate's.
//! The keyboard and the touch panel are read on an executor of their own,
//! above thread mode, so a frame being laid out and painted never holds a
//! read back.
use super::*;
use crate::input_gate::{
    self, CHANGED, control, finish_gesture, hold, note_activity, send, start_gesture, wake_display,
};
use core::cell::RefCell;
use embassy_sync::watch::Watch;
use embassy_time::TimeoutError;
use esp_hal::gpio::{Flex, Io};
use esp_hal::interrupt::Priority;
use esp_hal::peripherals;
use esp_hal::ram;
use esp_hal::rtc_cntl::WakeLock;
use esp_rtos::embassy::InterruptExecutor;
use umsh_tdeck_peripherals::es7210;
use umsh_tdeck_peripherals::gt911::{Gt911, Polarity, Report};
use umsh_tdeck_peripherals::keyboard::{self as keys, Key};
use umsh_tdeck_peripherals::trackball::{Direction, Trackball};
use umsh_ux_communicator::input::{Arrow, Input as UiItem, TouchPhase};
use umsh_ux_communicator::keyboard::Modifier;
use umsh_ux_communicator::model::KeyboardFirmware;
use umsh_ux_display_tracker::input_power::{Gesture, Mode};
use umsh_ux_tracker::debounce::{Debounce, PressLatch};

/// The T-Deck's controls produce the communicator's inputs directly.
pub(crate) type Item = UiItem;

pub(crate) fn to_input(input: UiItem) -> UiItem {
    input
}

static KEYBOARD_SHOWN: Signal<CriticalSectionRawMutex, ()> = Signal::new();
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

/// The panel lit: the keyboard is read again, and one that failed is
/// tried again at once.
pub(crate) fn shown() {
    KEYBOARD_SHOWN.signal(());
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
    io.set_interrupt_handler(gpio_interrupt);
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

/// Captures rolls and touch reports, or stops, starting the roll count
/// over either way.
fn listen(on: bool) {
    critical_section::with(|cs| {
        if let Some(line) = TOUCH_LINE.borrow_ref_mut(cs).as_mut() {
            line.listen(on);
        }
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
    // Lit, whatever the controller holds is read at once; dark, the
    // controller is put to sleep.
    TOUCH_READY.signal(());
}

#[esp_hal::handler]
#[ram]
fn gpio_interrupt() {
    critical_section::with(|cs| {
        if let Some(line) = TOUCH_LINE.borrow_ref_mut(cs).as_mut()
            && line.pin.is_interrupt_set()
        {
            line.pin.clear_interrupt();
            TOUCH_EDGE.store(Instant::now().as_millis() as u32, Ordering::Relaxed);
            TOUCH_READY.signal(());
        }
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
/// awake, and the press brings the panel back.
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
async fn keyboard_task(bus: &'static board::I2cBus) {
    select(run_keyboard(bus), STOP_KEYBOARD.wait()).await;
    input_gate::stopped();
}

/// When the keyboard's controller first answers: about half a second
/// after the rail it shares rises, which is at boot.
const KEYBOARD_START: Instant = Instant::from_millis(500);
/// How often the keyboard is read while lit: often enough that two keys
/// in quick succession are both seen (it holds only the last).
const KEYBOARD_PERIOD: Duration = Duration::from_millis(30);
/// The wait before the controller is tried again after a failure: it
/// doubles while failures repeat, and a display wake cuts it short.
const KEYBOARD_RETRY_FIRST: Duration = Duration::from_millis(250);
const KEYBOARD_RETRY_MOST: Duration = Duration::from_secs(8);
/// The key light's duty when lit, the keyboard's own default.
const KEYBOARD_LIGHT_DUTY: u8 = 127;
/// How long after the controller first answers before the light is set:
/// it answers before it has set up the light, which it then turns off.
const KEYBOARD_LIGHT_SETTLE: Duration = Duration::from_millis(500);
/// The longest a keyboard transfer may take.
const KEYBOARD_TRANSFER: Duration = Duration::from_millis(50);
/// A sleeping keyboard leaves the read that wakes it unanswered, so it is
/// tried again this often, this many times.
const KEYBOARD_WAKE_RETRY: Duration = Duration::from_millis(2);
const KEYBOARD_WAKE_TRIES: u32 = 15;

async fn run_keyboard(bus: &'static board::I2cBus) {
    let mut keyboard = I2cDevice::new(bus);
    Timer::at(KEYBOARD_START).await;
    let mut retry = KEYBOARD_RETRY_FIRST;
    // The light wanted while lit, and the light last set.
    let mut wanted = true;
    let mut set = None;
    // When the controller can take the light, once it is answering. A
    // controller that stopped answering may have restarted, with its
    // light off.
    let mut light_from = None;
    // A key pressed while dark is still held by the controller; the first
    // read once lit takes it, and it goes no further.
    let mut stale = false;
    // What the controller says it is (`Some(None)` for stock firmware),
    // asked when it first answers, and again after it stops answering,
    // since it may have restarted.
    let mut identity: Option<Option<keys::Identity>> = None;
    // Its only receiver: there is one keyboard task, run once.
    let mut touch_quiet = TOUCH_QUIET.receiver().unwrap();
    loop {
        use embedded_hal_async::i2c::I2c as _;
        let lit = control(|c| c.policy.mode == Mode::Interactive);
        let light = wanted && lit;
        if set != Some(light) && light_from.is_some_and(|from| Instant::now() >= from) {
            let duty = if light { KEYBOARD_LIGHT_DUTY } else { 0 };
            // Firmware older than the light command ignores it.
            if answered(
                with_timeout(
                    KEYBOARD_TRANSFER,
                    keyboard.write(keys::ADDRESS, &keys::backlight(duty)),
                )
                .await,
            ) {
                set = Some(light);
            }
        }
        // Dark, the keyboard is left alone until the panel lights again,
        // asleep if it can sleep. Sleep goes after the light, in a write of
        // its own, and after touch has done with the bus.
        if !lit {
            KEYBOARD_SHOWN.reset();
            let sleeps = identity.flatten().is_some_and(|it| it.sleeps());
            if sleeps {
                let _ = with_timeout(TOUCH_QUIET_WAIT, touch_quiet.get_and(|&quiet| quiet)).await;
            }
            let asleep = sleeps
                && answered(
                    with_timeout(
                        KEYBOARD_TRANSFER,
                        keyboard.write(keys::ADDRESS, &keys::SLEEP),
                    )
                    .await,
                );
            if control(|c| c.policy.mode != Mode::Interactive) {
                KEYBOARD_SHOWN.wait().await;
            }
            // Waking takes a read, which takes the stale key with it.
            stale = !(asleep && wake_keyboard(&mut keyboard).await);
            continue;
        }
        let answer = match identity {
            Some(_) => read_key(&mut keyboard).await,
            None => identify_keyboard(&mut keyboard).await.map(|(found, byte)| {
                match found {
                    Some(it) => debug_log(format_args!(
                        "tdeck: keyboard runs UMSH firmware {}.{}",
                        it.major, it.minor
                    )),
                    None => debug_log(format_args!("tdeck: keyboard runs stock firmware")),
                }
                identity = Some(found);
                publish_identity(identity);
                byte
            }),
        };
        match answer {
            Ok(byte) => {
                retry = KEYBOARD_RETRY_FIRST;
                light_from.get_or_insert_with(|| Instant::now() + KEYBOARD_LIGHT_SETTLE);
                if !core::mem::take(&mut stale)
                    && let Some(key) = keys::key(byte)
                {
                    deliver(key);
                }
            }
            Err(()) => {
                light_from = None;
                set = None;
                identity = None;
                publish_identity(identity);
                debug_log(format_args!(
                    "tdeck: keyboard not answering; retry in {} ms",
                    retry.as_millis()
                ));
                KEYBOARD_SHOWN.reset();
                select(Timer::after(retry), KEYBOARD_SHOWN.wait()).await;
                retry = (retry * 2).min(KEYBOARD_RETRY_MOST);
                continue;
            }
        }
        if let Either::Second(light) = select(
            Timer::after(KEYBOARD_PERIOD),
            board::display::KEYBOARD_LIGHT.wait(),
        )
        .await
        {
            wanted = light;
        }
    }
}

/// What the keyboard's controller says it runs, for the keyboard screen.
static KEYBOARD_FIRMWARE: critical_section::Mutex<core::cell::Cell<Option<KeyboardFirmware>>> =
    critical_section::Mutex::new(core::cell::Cell::new(None));

pub(crate) fn keyboard_firmware() -> Option<KeyboardFirmware> {
    critical_section::with(|cs| KEYBOARD_FIRMWARE.borrow(cs).get())
}

/// Publishes what is known of the controller: nothing until it answers.
fn publish_identity(identity: Option<Option<keys::Identity>>) {
    let firmware = identity.map(|found| match found {
        Some(it) => KeyboardFirmware::Umsh {
            major: it.major,
            minor: it.minor,
        },
        None => KeyboardFirmware::Stock,
    });
    critical_section::with(|cs| KEYBOARD_FIRMWARE.borrow(cs).set(firmware));
}

/// Whether a keyboard transfer went through in time.
fn answered<E>(transfer: Result<Result<(), E>, TimeoutError>) -> bool {
    matches!(transfer, Ok(Ok(())))
}

/// One key-mode read.
async fn read_key(keyboard: &mut impl embedded_hal_async::i2c::I2c) -> Result<u8, ()> {
    let mut byte = [0];
    answered(with_timeout(KEYBOARD_TRANSFER, keyboard.read(keys::ADDRESS, &mut byte)).await)
        .then_some(byte[0])
        .ok_or(())
}

/// Asks the controller what it is. Stock firmware ignores the question and
/// answers the read with the key it was holding, which comes back with no
/// identity; UMSH's firmware gives no key.
async fn identify_keyboard(
    keyboard: &mut impl embedded_hal_async::i2c::I2c,
) -> Result<(Option<keys::Identity>, u8), ()> {
    let mut reply = [0; keys::IDENTIFY_LEN];
    if !answered(
        with_timeout(
            KEYBOARD_TRANSFER,
            keyboard.write(keys::ADDRESS, &keys::IDENTIFY),
        )
        .await,
    ) || !answered(
        with_timeout(KEYBOARD_TRANSFER, keyboard.read(keys::ADDRESS, &mut reply)).await,
    ) {
        return Err(());
    }
    Ok(match keys::identity(&reply) {
        Some(found) => (Some(found), 0),
        None => (None, reply[0]),
    })
}

/// Wakes a keyboard sent to sleep, and says whether it answered. The read
/// that wakes it goes unanswered, so it is tried again for a little while;
/// the key it reads is from before the sleep, and goes no further.
async fn wake_keyboard(keyboard: &mut impl embedded_hal_async::i2c::I2c) -> bool {
    for _ in 0..KEYBOARD_WAKE_TRIES {
        if read_key(keyboard).await.is_ok() {
            return true;
        }
        Timer::after(KEYBOARD_WAKE_RETRY).await;
    }
    false
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

/// How long a read of the touch panel may take before it is given up on.
const TOUCH_READ: Duration = Duration::from_millis(50);
/// How often the panel is read while INT stays raised: a panel that holds
/// it through a drag raises no further edges, so its reports are read at
/// about its own rate.
const TOUCH_REPORT: Duration = Duration::from_millis(10);
/// How long a touch may go unreported before the panel is read anyway, so
/// a lost edge cannot leave a finger down.
const TOUCH_STALL: Duration = Duration::from_millis(50);
/// The wait after a failed read: a report left unacknowledged may keep
/// the controller from raising INT again.
const TOUCH_RETRY: Duration = Duration::from_millis(20);
/// The wait before INT's idle level is sampled: over two report periods,
/// so a finger on the panel has reported again by then.
const TOUCH_SETTLE: Duration = Duration::from_millis(30);
/// The tries at finding the controller, a little apart, before the board
/// is taken to have no touch panel.
const TOUCH_PROBES: u32 = 4;
const TOUCH_PROBE_GAP: Duration = Duration::from_millis(250);

type TouchPanel = Gt911<board::I2cHandle>;

/// How long INT is driven high to wake a sleeping controller (§7.5).
const TOUCH_WAKE: Duration = Duration::from_millis(8);

/// The touch panel's INT, once its sense is known. Driven only to wake
/// the controller.
struct TouchLine {
    pin: Flex<'static>,
    polarity: Polarity,
}

impl TouchLine {
    /// Captures the edge that raises the line, or stops.
    fn listen(&mut self, on: bool) {
        if on {
            self.pin.clear_interrupt();
            self.pin.listen(match self.polarity {
                Polarity::ActiveLow => Event::FallingEdge,
                Polarity::ActiveHigh => Event::RisingEdge,
            });
        } else {
            self.pin.unlisten();
        }
    }
}

static TOUCH_LINE: critical_section::Mutex<RefCell<Option<TouchLine>>> =
    critical_section::Mutex::new(RefCell::new(None));
/// Whether the touch panel will say nothing more on the bus until the
/// panel lights: its controller is asleep, or there is none. Any traffic
/// wakes a sleeping keyboard, so the keyboard is sent to sleep after this.
static TOUCH_QUIET: Watch<CriticalSectionRawMutex, bool, 1> = Watch::new();
/// The longest the keyboard waits for [`TOUCH_QUIET`]: touch still
/// looking for its controller says nothing of it.
const TOUCH_QUIET_WAIT: Duration = Duration::from_millis(200);
/// INT was raised, or the panel lit, since the touch task last looked.
static TOUCH_READY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// When INT was last raised, in ms, until a read takes it.
static TOUCH_EDGE: AtomicU32 = AtomicU32::new(NO_EDGE);
const NO_EDGE: u32 = u32::MAX;

/// Whether INT is raised now.
fn touch_asserted() -> bool {
    critical_section::with(|cs| {
        TOUCH_LINE
            .borrow_ref(cs)
            .as_ref()
            .is_some_and(|line| line.polarity.asserted(line.pin.is_high()))
    })
}

static BUS_EXECUTOR: StaticCell<InterruptExecutor<2>> = StaticCell::new();

/// The I²C bus on its way to the bus executor.
struct BusHandoff(&'static board::I2cBus);
// SAFETY: the board runs on core 0 alone, so both executors and the bus's
// interrupt share one core, and the bus's own async mutex keeps their
// transfers apart.
unsafe impl Send for BusHandoff {}

/// Starts the keyboard and touch tasks on an executor above thread mode.
/// The keyboard goes too: it holds the bus from a transfer until it is
/// polled again, so left behind a paint it would hold touch back with it.
pub fn spawn_bus_tasks(
    interrupt: peripherals::FROM_CPU_INTR2<'static>,
    bus: &'static board::I2cBus,
    int: peripherals::GPIO16<'static>,
) {
    let executor = BUS_EXECUTOR.init(InterruptExecutor::new(interrupt));
    executor
        .start(Priority::Priority1)
        .spawn(bus_tasks(BusHandoff(bus), int).unwrap());
}

#[embassy_executor::task]
async fn bus_tasks(bus: BusHandoff, int: peripherals::GPIO16<'static>) {
    // SAFETY: this task is polled by the bus executor, an Embassy one.
    let spawner = unsafe { Spawner::for_current_executor() }.await;
    spawner.spawn(touch_task(bus.0, int).unwrap());
    // Nothing records. Before the keyboard starts, which may sleep, since
    // any traffic would wake it again.
    let _ = with_timeout(
        Duration::from_millis(50),
        es7210::power_down(&mut I2cDevice::new(bus.0)),
    )
    .await;
    spawner.spawn(keyboard_task(bus.0).unwrap());
}

#[embassy_executor::task]
async fn touch_task(bus: &'static board::I2cBus, int: peripherals::GPIO16<'static>) {
    // The controller is reset only by its own power-on, so one put to
    // sleep at shutdown still sleeps after the S3 boots again, and answers
    // no probe until INT wakes it.
    let mut int = Flex::new(int);
    int.apply_input_config(&InputConfig::default());
    int.set_input_enable(true);
    drive_touch_wake(&mut int, true);
    Timer::after(TOUCH_WAKE).await;
    drive_touch_wake(&mut int, false);
    let mut panel = None;
    select(run_touch(bus, int, &mut panel), STOP_TOUCH.wait()).await;
    // The controller keeps power through deep sleep.
    if let Some(panel) = panel.as_mut() {
        let _ = with_timeout(Duration::from_millis(50), panel.sleep()).await;
    }
    input_gate::stopped();
}

async fn run_touch(bus: &'static board::I2cBus, int: Flex<'static>, slot: &mut Option<TouchPanel>) {
    let quiet = TOUCH_QUIET.sender();
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
            quiet.send(true);
            return core::future::pending().await;
        }
        Timer::after(TOUCH_PROBE_GAP).await;
    };
    debug_log(format_args!(
        "tdeck: touch panel at {:#04x}",
        panel.address()
    ));
    let polarity = idle_polarity(panel, &int).await;
    debug_log(format_args!("tdeck: touch INT active-{}", sense(polarity)));
    critical_section::with(|cs| {
        let mut line = TouchLine { pin: int, polarity };
        // The coordinator listens from here on; until now there was no line.
        line.listen(control(|c| c.policy.mode == Mode::Interactive));
        TOUCH_LINE.borrow_ref_mut(cs).replace(line);
    });
    // The point last sent of a touch whose start reached the interface, and
    // whether one is on the panel at all: one whose start woke the panel or
    // was otherwise taken goes no further.
    let mut contact: Option<Option<(i16, i16)>> = None;
    let mut lag = TouchLag::new(polarity);
    loop {
        if control(|c| c.policy.mode != Mode::Interactive) {
            if let Some(Some((x, y))) = contact.take() {
                send(touch(TouchPhase::Cancelled, x, y, Instant::now()));
                lag.end(true);
            }
            // Dark, nothing reads the controller, so it sleeps. One that
            // missed the command keeps scanning, and says nothing unread.
            let _ = with_timeout(TOUCH_READ, panel.sleep()).await;
            quiet.send(true);
            // Lighting the panel raises the signal.
            while control(|c| c.policy.mode != Mode::Interactive) {
                TOUCH_READY.wait().await;
            }
            quiet.send(false);
            wake_touch().await;
            continue;
        }
        let edge = TOUCH_EDGE.swap(NO_EDGE, Ordering::Relaxed);
        let began = Instant::now();
        let wait = match with_timeout(TOUCH_READ, panel.read()).await {
            Ok(Ok(report)) => {
                if report != Report::Pending {
                    lag.report(edge, began);
                }
                match report {
                    Report::Pending => {}
                    Report::Touched(point) => {
                        note_activity();
                        let at = (point.x as i16, point.y as i16);
                        match contact {
                            None => {
                                let gesture = start_gesture();
                                let delivered = gesture == Gesture::Navigate;
                                finish_gesture(
                                    touch(TouchPhase::Started, at.0, at.1, began),
                                    gesture,
                                );
                                contact = Some(delivered.then_some(at));
                            }
                            Some(Some(last)) if last != at => {
                                send(touch(TouchPhase::Moved, at.0, at.1, began));
                                contact = Some(Some(at));
                            }
                            Some(_) => {}
                        }
                    }
                    Report::Released => {
                        note_activity();
                        let last = contact.take().flatten();
                        if let Some((x, y)) = last {
                            send(touch(TouchPhase::Ended, x, y, began));
                        }
                        lag.end(last.is_some());
                    }
                }
                if touch_asserted() {
                    Some(TOUCH_REPORT)
                } else if contact.is_some() {
                    Some(TOUCH_STALL)
                } else {
                    None
                }
            }
            // A failed read is dropped, and tried again shortly.
            _ => Some(TOUCH_RETRY),
        };
        match wait {
            Some(wait) => {
                select(TOUCH_READY.wait(), Timer::after(wait)).await;
            }
            None => TOUCH_READY.wait().await,
        }
    }
}

/// Drives INT high to wake the controller (§7.5), or lets it go.
fn drive_touch_wake(int: &mut Flex<'static>, high: bool) {
    if high {
        int.set_high();
    }
    int.set_output_enable(high);
}

/// Wakes the controller from sleep, with INT's edges unheard while it is
/// driven.
async fn wake_touch() {
    critical_section::with(|cs| {
        if let Some(line) = TOUCH_LINE.borrow_ref_mut(cs).as_mut() {
            line.pin.unlisten();
            drive_touch_wake(&mut line.pin, true);
        }
    });
    Timer::after(TOUCH_WAKE).await;
    critical_section::with(|cs| {
        if let Some(line) = TOUCH_LINE.borrow_ref_mut(cs).as_mut() {
            drive_touch_wake(&mut line.pin, false);
            line.listen(control(|c| c.policy.mode == Mode::Interactive));
        }
    });
}

/// INT's sense, from its level while the controller reports nothing. A
/// finger on the panel at boot puts it off until the finger lifts.
async fn idle_polarity(panel: &mut TouchPanel, int: &Flex<'static>) -> Polarity {
    loop {
        // Whatever is waiting is acknowledged, then a finger on the panel
        // is given the time to report again.
        let _ = with_timeout(TOUCH_READ, panel.read()).await;
        Timer::after(TOUCH_SETTLE).await;
        if let Ok(Ok(Some(polarity))) =
            with_timeout(TOUCH_READ * 2, panel.idle_polarity(|| int.is_high())).await
        {
            return polarity;
        }
        Timer::after(TOUCH_PROBE_GAP).await;
    }
}

fn sense(polarity: Polarity) -> &'static str {
    match polarity {
        Polarity::ActiveLow => "low",
        Polarity::ActiveHigh => "high",
    }
}

/// The reports one touch took, how many of them INT rose for, and the
/// longest any waited after it rose: logged as the touch ends, which is
/// how a flick is checked, and whether the panel raises INT per report or
/// holds it through a drag.
struct TouchLag {
    polarity: Polarity,
    reports: u32,
    edges: u32,
    worst_ms: u32,
}

impl TouchLag {
    const fn new(polarity: Polarity) -> Self {
        Self {
            polarity,
            reports: 0,
            edges: 0,
            worst_ms: 0,
        }
    }

    fn report(&mut self, edge: u32, began: Instant) {
        self.reports += 1;
        if edge != NO_EDGE {
            self.edges += 1;
            let waited = (began.as_millis() as u32).wrapping_sub(edge);
            self.worst_ms = self.worst_ms.max(waited);
        }
    }

    fn end(&mut self, delivered: bool) {
        if delivered {
            debug_log(format_args!(
                "tdeck: touch n={} e={} lag={} ms int={}",
                self.reports,
                self.edges,
                self.worst_ms,
                sense(self.polarity)
            ));
        }
        *self = Self::new(self.polarity);
    }
}

fn touch(phase: TouchPhase, x: i16, y: i16, at: Instant) -> UiItem {
    UiItem::Touch {
        phase,
        x,
        y,
        at: at.as_millis(),
    }
}
