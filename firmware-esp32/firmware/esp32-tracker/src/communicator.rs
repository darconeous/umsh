//! The communicator interface on a keyboard board's panel, in place of
//! the tracker's menus, over the communicator's node. The node reaches the
//! device's settings through the session's device link, and its chats are
//! fed what the device node receives. The interface task reports what each
//! frame costs: layout, painting, the panel transfer, and the least stack
//! left free.
//!
//! Both of the node's tasks keep what they allocate in PSRAM.
use super::*;
use board::display::{Brightness, Display};
use heap::InPsram;
use umsh_communicator::task::Inbox;
use umsh_communicator::{Clock, CommunicatorNode};
use umsh_ulcp_admin::local::driver::DriverPort;
use umsh_ux_communicator::board::Board;
use umsh_ux_communicator::buoyant::app::App;
use umsh_ux_communicator::buoyant::render_target::{
    EmbeddedGraphicsRenderTarget, RenderTarget as _,
};
use umsh_ux_communicator::buoyant::view::View;
use umsh_ux_communicator::input::{self, Input};
use umsh_ux_communicator::model::{
    BatteryReading, Bluetooth, BluetoothReading, Charge, ClockSource, DEFAULT_AUTO_LOCK_S, Fix,
    Gnss, GnssReading, Links, Node as _, State, Wifi, brightness_level,
};
use umsh_ux_communicator::{theme, typeface, ui};
use umsh_ux_display_tracker::attention::{Attention, AttentionConfig, DisplayKind, Transition};

/// The board the interface runs on. The boot splash sets its version in
/// this board's body face too.
#[cfg(feature = "board-tlora-pager")]
pub(crate) const BOARD: &Board = &Board::PAGER;
#[cfg(feature = "board-tdeck")]
pub(crate) const BOARD: &Board = &Board::TDECK;

/// How often an animation advances.
const FRAME: Duration = Duration::from_millis(16);
/// How often the costs are reported.
const REPORT: Duration = Duration::from_secs(1);
/// How long the settings are waited for before anything is shown, and how
/// often the node asks again while the driver's input is full.
const PRIME_WAIT: Duration = Duration::from_secs(1);
const PRIME_RETRY: Duration = Duration::from_millis(20);
/// How long Shutting down shows before the panel goes dark.
const SHUTTING_DOWN: Duration = Duration::from_millis(1500);
/// The empty battery's blink before the power path opens: how many times,
/// and how long it is lit and dark each time. Inside the two seconds
/// [`ui::end_farewell`](crate::ui::end_farewell) waits.
#[cfg(feature = "battery-cutoff")]
const EMPTY_BLINKS: u8 = 3;
#[cfg(feature = "battery-cutoff")]
const EMPTY_LIT: Duration = Duration::from_millis(300);
#[cfg(feature = "battery-cutoff")]
const EMPTY_DARK: Duration = Duration::from_millis(200);

/// The communicator's node, over the session's device link, with its
/// chats kept in the [`PARTITION`].
pub(crate) type Node = CommunicatorNode<
    DriverPort<CriticalSectionRawMutex>,
    umsh_communicator::FlashMapStore<umsh_bsp_esp32::flash_store::Bounced>,
>;

/// The label of the partition the chats are kept in.
pub(crate) const PARTITION: &str = "chat";

/// The port into the session for [`Node`].
pub(crate) const fn port() -> DriverPort<CriticalSectionRawMutex> {
    DriverPort::new(&INPUT_CH, &DEVICE_LINK)
}

/// The board's clocks, as the node reads them.
pub(crate) struct Clocks;

impl Clock for Clocks {
    fn now_ms(&self) -> u64 {
        Instant::now().as_millis()
    }

    fn wall(&self) -> Option<u32> {
        umsh_hal::wall_clock::now()
    }

    fn source(&self) -> Option<(ClockSource, u64)> {
        use umsh_hal::wall_clock::TimeSource;
        let clock = umsh_hal::wall_clock::snapshot();
        let source = match clock.source()? {
            TimeSource::Manual => ClockSource::Manual,
            TimeSource::GnssFix | TimeSource::GnssRtc => ClockSource::Gnss,
            TimeSource::ExternalRtc => ClockSource::Rtc,
        };
        Some((source, clock.set_at()?))
    }
}

pub(crate) static CLOCK: Clocks = Clocks;

/// What the device node received for the chats.
pub(crate) static INBOX: Inbox<CriticalSectionRawMutex> = Inbox::new();

/// The board's controls, past the input gate.
pub(crate) static INPUT: Channel<CriticalSectionRawMutex, Input, 16> = Channel::new();

/// The chats have changed, and the node holds events for the interface.
static CHATS_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// The chats: what reaches [`INBOX`], fed to the node, the node's timers,
/// and what it sends through the device node.
#[embassy_executor::task]
pub(crate) async fn chats(node: &'static Node, mesh: crate::device_node::DeviceNode) {
    InPsram(umsh_communicator::task::run(
        node,
        &mesh,
        &INBOX,
        |at| Timer::at(Instant::from_millis(at)),
        || CHATS_CHANGED.signal(()),
    ))
    .await
}

#[embassy_executor::task]
pub(crate) async fn task(
    display: Display,
    splash: umsh_ux_display_tracker::boot::BootSplash,
    node: &'static Node,
) {
    InPsram(interface(display, splash, node)).await
}

async fn interface(
    mut display: Display,
    mut splash: umsh_ux_display_tracker::boot::BootSplash,
    node: &'static Node,
) {
    let epoch = input_gate::interactive().await;
    if let Some(deadline) = splash.next_deadline() {
        Timer::at(Instant::from_millis(deadline)).await;
    }
    splash.dismiss();
    BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);

    let start = Instant::now();
    prime(node).await;
    // Inflated emoji, kept beside the app: plain data, touched only here.
    typeface::install(external::communicator(typeface::EmojiCache::new_in));
    // The interface's state and both of its render trees are plain data
    // that only this task touches, and they are the largest thing it
    // holds: kept in the task, they would come out of the main stack.
    let app = external::communicator(|slot| {
        App::new_in(
            slot,
            state(node),
            BOARD.metrics.size().into(),
            ui::root_view,
        )
    });
    // Binding lays the interface out again: outside the constructor, so
    // that its frame, which holds the state and a render tree on their
    // way into place, is not under that layout too.
    ui::bind(app);
    // The least stack left free so far: bring-up, and building the app.
    #[cfg(feature = "debug-log")]
    debug_log(format_args!(
        "communicator: app={} bytes free={}",
        core::mem::size_of_val(app),
        memory_probe::stack().margin
    ));
    #[cfg(not(feature = "debug-log"))]
    debug_log(format_args!(
        "communicator: app={} bytes",
        core::mem::size_of_val(app)
    ));
    app.state_mut().battery(battery_reading(), 0);
    let mut costs = Costs::default();
    // The panel's brightness level and the keyboard light, as last set.
    let mut lights = (brightness_level(node.brightness()), node.keyboard().light);
    let _ = display.set_brightness(Brightness::level(lights.0)).await;
    display.set_keyboard_light(lights.1);
    let mut animating = draw(&mut display, app, start, &mut costs).await;
    let _ = display.set_display_on(true).await;
    input_gate::shown(epoch);
    // The panel dims, then goes dark, after a while without input, as the
    // tracker's does. An input against a fading or dark panel only wakes
    // it: the input layer reads `SCREEN_FADED` and consumes the gesture.
    let mut attention = Attention::new(
        DisplayKind::Emissive,
        attention_config(app.state().lock.locked, node.auto_lock()),
        Instant::now().as_millis(),
    );

    // When the clock next turns to a new minute, for the strip's time and
    // the ages counted to it. Setting the clock is waited on apart.
    let mut minute = next_minute();

    loop {
        let config = attention_config(app.state().lock.locked, node.auto_lock());
        if attention.config() != config {
            attention.set_config(config);
        }
        SCREEN_FADED.store(attention.is_faded(), Ordering::Release);
        let lit = attention.accepts_redraw();
        let tick = Instant::now() + if animating && lit { FRAME } else { REPORT };
        let wake_at = [
            attention.next_deadline(),
            app.state().next_deadline(),
            node.next_deadline(),
            minute.map(|minute| minute.as_millis()),
        ]
        .into_iter()
        .flatten()
        .fold(tick, |at, deadline| at.min(Instant::from_millis(deadline)));
        let now = || Instant::now().as_millis();
        let woken = select4(
            INPUT.receive(),
            select3(
                UI_WAKE.wait(),
                input_gate::LOCK.wait(),
                umsh_hal::wall_clock::changed(),
            ),
            Timer::at(wake_at),
            select4(
                BATTERY_UI_CHANGED.wait(),
                DISPLAY_SHUTDOWN.wait(),
                DEVICE_LINK.ready(),
                CHATS_CHANGED.wait(),
            ),
        )
        .await;
        mark(app.state(), Phase::Idle);
        // Whatever this changes animates from now, not from the last frame.
        app.set_time((Instant::now() - start).into());
        let mut transition = match woken {
            Either4::First(first) => {
                // An input leaves the interface laid out and settled, so its
                // layout is counted here rather than in the frame. Everything
                // queued is taken before drawing, so typing outpacing the
                // frames only skips frames.
                let began = Instant::now();
                let mut next = Some(first);
                while let Some(input) = next {
                    input::apply(app, input, now());
                    next = INPUT.try_receive().ok();
                }
                costs.layout = costs.layout.max(Instant::now() - began);
                mark(app.state(), Phase::Input);
                // Shut down, confirmed.
                if app.state().ending.is_some() {
                    SHUTDOWN_REQUEST.signal(ShutdownCause::Asked);
                }
                attention.wake(now())
            }
            Either4::Second(Either3::First(())) => attention.wake(now()),
            // The lock control locks a lit screen to the lock screen,
            // darkens the lock screen, and lights a dark one to it.
            Either4::Second(Either3::Second(()))
                if attention.accepts_redraw() && !app.state().lock.locked =>
            {
                app.state_mut().lock();
                attention.wake(now())
            }
            Either4::Second(Either3::Second(())) if attention.accepts_redraw() => {
                attention.sleep(now())
            }
            Either4::Second(Either3::Second(())) => attention.wake(now()),
            // The clock was set, or moved: it is read again below.
            Either4::Second(Either3::Third(())) => {
                minute = Some(Instant::now());
                None
            }
            Either4::Third(()) => attention.poll(now()),
            // A reading is taken in below, and never lights the panel.
            Either4::Fourth(Either4::First(())) => None,
            Either4::Fourth(Either4::Second(cause)) => farewell(&mut display, app, cause).await,
            // The session answered, or published: the node takes it in
            // below.
            Either4::Fourth(Either4::Third(())) => None,
            // The chats changed: their events are taken below.
            Either4::Fourth(Either4::Fourth(())) => None,
        };
        if app.state().next_deadline().is_some_and(|at| at <= now()) {
            input::expire(app, now());
        }
        // What an input changed goes out, and what the session sent comes
        // in as events, taken just below.
        node.pump();
        mark(app.state(), Phase::Pump);
        if minute.is_some_and(|minute| minute <= Instant::now()) {
            app.state_mut().set_wall_time(umsh_hal::wall_clock::now());
            minute = next_minute();
        }
        // The links are read on every pass, which is at least once a
        // second, and redraw the strip only when one has changed.
        let read = links();
        let status = &app.state().status;
        if (status.bluetooth, status.wifi, status.gnss) != read {
            let mut state = app.state_mut();
            (state.status.bluetooth, state.status.wifi, state.status.gnss) = read;
        }
        let readings = link_readings();
        if app.state().links != readings {
            app.state_mut().links = readings;
        }
        let battery = battery_reading();
        if app.state().battery_changes(&battery) {
            app.state_mut().battery(battery, now());
        }
        // Taken in while the panel is still dark, so that a message
        // arriving then is listed for the screen it wakes to.
        if input::events(app, now()) {
            #[cfg(feature = "board-tlora-pager")]
            pager::alert::tick();
            if let Some(woke) = attention.wake(now()) {
                transition = Some(woke);
            }
        }
        mark(app.state(), Phase::Events);
        // A key, or the node, may have changed the lights.
        let set = (brightness_level(node.brightness()), node.keyboard().light);
        if set != lights {
            lights = set;
            let _ = display.set_brightness(Brightness::level(lights.0)).await;
            display.set_keyboard_light(lights.1);
        }
        match transition {
            Some(Transition::Woke) => {
                if app.state().dark {
                    app.state_mut().screen_on(now());
                }
                // A fresh frame goes in before the panel lights, so a stale
                // one is never seen.
                let epoch = input_gate::interactive().await;
                animating = draw(&mut display, app, start, &mut costs).await;
                let _ = display.set_brightness(Brightness::level(lights.0)).await;
                if display.set_display_on(true).await.is_ok() {
                    input_gate::shown(epoch);
                }
                continue;
            }
            Some(Transition::Dimming) => {
                let dimmed = Brightness::level(lights.0).dimmed(attention.brightness_permille());
                let _ = display.set_brightness(dimmed).await;
            }
            Some(Transition::Lapsed) => {
                let before = input_gate::activity();
                if display.set_display_on(false).await.is_ok() {
                    input_gate::dark(before);
                }
                app.state_mut().screen_off(now());
            }
            None => {}
        }
        if attention.accepts_redraw() && (animating || app.should_redraw()) {
            animating = draw(&mut display, app, start, &mut costs).await;
        }
        costs.report(animating);
    }
}

/// Waits for the node's first read of the settings, so the first frame
/// shows the device's name and brightness rather than defaults. A session
/// not serving within [`PRIME_WAIT`] is shown with defaults, which its
/// answers replace as they come.
async fn prime(node: &Node) {
    let deadline = Instant::now() + PRIME_WAIT;
    while !node.primed() && Instant::now() < deadline {
        node.pump();
        // The driver's input may have been full: try again shortly.
        let _ = select(DEVICE_LINK.ready(), Timer::after(PRIME_RETRY)).await;
    }
    node.pump();
    // The settings the interface reads in building its state.
    while node.next_event().is_some() {}
}

/// The interface's state over `node`: locked, over the Chats screen.
fn state(node: &'static Node) -> State {
    let mut state = State::new(node, BOARD);
    state.firmware = env!("GIT_DESCRIBE");
    state.status.device_name = node.device_name();
    (state.status.bluetooth, state.status.wifi, state.status.gnss) = links();
    state.set_wall_time(umsh_hal::wall_clock::now());
    state.reload();
    state.focus_list();
    state.lock();
    state
}

/// Bluetooth, Wi-Fi, and GNSS, as the strip shows them: each only while it
/// is on, as the tracker's header shows them. Bluetooth is hidden while a
/// wired host has it off.
fn links() -> (Option<Bluetooth>, Option<Wifi>, Option<Gnss>) {
    use umsh_ux_display_tracker::screen::{LinkState, PairingState};
    let ble = ble::panel();
    let bluetooth = (ble.enabled == Some(true)
        && !matches!(ble.link, LinkState::Disabled | LinkState::OffWired))
    .then(|| match (ble.pairing, ble.link) {
        (PairingState::Open { .. }, _) => Bluetooth::Pairing,
        (_, LinkState::Connected | LinkState::Attached) => Bluetooth::Connected,
        _ => Bluetooth::Waiting,
    });
    #[cfg(feature = "wifi")]
    let wifi = {
        use umsh_ux_display_tracker::wifi::WifiState;
        let menu = wifi::ui_snapshot();
        match menu.state {
            _ if !menu.enabled => None,
            WifiState::Off => None,
            WifiState::Disconnected => Some(Wifi::Disconnected),
            WifiState::Connecting => Some(Wifi::Joining),
            WifiState::Connected => Some(Wifi::Connected),
        }
    };
    #[cfg(not(feature = "wifi"))]
    let wifi = None;
    #[cfg(feature = "gnss")]
    let gnss = umsh_ulcp_runtime::gnss::enabled().then(|| {
        if umsh_ulcp_runtime::gnss::has_fix() {
            Gnss::Fixed
        } else {
            Gnss::Searching
        }
    });
    #[cfg(not(feature = "gnss"))]
    let gnss = None;
    (bluetooth, wifi, gnss)
}

/// What Bluetooth and the GNSS receiver are doing, for the screens that
/// show more than the strip does.
fn link_readings() -> Links {
    use umsh_ux_display_tracker::screen::{LinkState, PairingState};
    let ble = ble::panel();
    let bluetooth = BluetoothReading {
        connected: matches!(ble.link, LinkState::Connected | LinkState::Attached),
        paired: Some(ble.bonds),
        pairing: matches!(ble.pairing, PairingState::Open { .. }),
        pin: match ble.pairing {
            PairingState::Open { pin } => pin,
            _ => None,
        },
    };
    #[cfg(feature = "gnss")]
    let gnss = {
        use umsh_ulcp::gnss::FixKind;
        let snapshot = umsh_ulcp_runtime::gnss::snapshot();
        let location = snapshot.location();
        GnssReading {
            fix: match snapshot.fix {
                FixKind::TwoD => Fix::TwoD,
                FixKind::ThreeD => Fix::ThreeD,
                _ => Fix::None,
            },
            position: (!location.is_empty()).then(|| {
                let (latitude, longitude) =
                    umsh_node::location::NodeLocation::from_bytes(location).center();
                ((latitude * 1e6) as i32, (longitude * 1e6) as i32)
            }),
            altitude: snapshot.altitude_m,
            used: snapshot.sats_used,
            in_view: snapshot.sats_in_view,
        }
    };
    #[cfg(not(feature = "gnss"))]
    let gnss = GnssReading::default();
    Links { bluetooth, gnss }
}

/// When the clock next turns to a new minute, while it is known.
fn next_minute() -> Option<Instant> {
    umsh_hal::wall_clock::millis_to_next_minute()
        .map(|ms| Instant::now() + Duration::from_millis(u64::from(ms)))
}

/// How long the panel stays lit without input: as Auto-Lock says while
/// unlocked, and while locked no longer than that, as a locked screen is
/// lit only to glance at.
fn attention_config(locked: bool, auto_lock: Option<u16>) -> AttentionConfig {
    let timeout = match auto_lock.unwrap_or(DEFAULT_AUTO_LOCK_S) {
        0 => None,
        seconds => Some(core::time::Duration::from_secs(u64::from(seconds))),
    };
    let unlocked = AttentionConfig::emissive_for(timeout);
    let shorter = |timeout| {
        AttentionConfig::LOCKED
            .timeout
            .is_some_and(|locked| timeout < locked)
    };
    match timeout {
        Some(timeout) if locked && shorter(timeout) => unlocked,
        _ if locked => AttentionConfig::LOCKED,
        _ => unlocked,
    }
}

/// The battery as the board last read it.
fn battery_reading() -> BatteryReading {
    BatteryReading {
        percent: Some(BATTERY_LEVEL.load(Ordering::Acquire)).filter(|&level| level != 0xFF),
        charge: match BATTERY_CHARGE.load(Ordering::Acquire) {
            1 => Some(Charge::Discharging),
            2 => Some(Charge::Charging),
            3 => Some(Charge::Charged),
            4 => Some(Charge::NotCharging),
            _ => None,
        },
        millivolts: battery_millivolts(),
    }
}

/// The cell's voltage as last read. Where the divider reads the supply
/// rail, a reading is the cell's only while the cell runs the board.
fn battery_millivolts() -> Option<u16> {
    let mv = BATTERY_MV.load(Ordering::Acquire);
    #[cfg(feature = "battery-adc-rail")]
    return match board::battery::Rail::classify(mv) {
        board::battery::Rail::Battery(mv) => Some(mv),
        _ => None,
    };
    #[cfg(not(feature = "battery-adc-rail"))]
    (mv != 0).then_some(mv)
}

/// The board is turning off, and the panel says so: Shutting down, or with
/// the battery empty its icon blinking a few times. Then the panel goes
/// dark, and nothing more is drawn.
async fn farewell<V, F>(
    display: &mut Display,
    app: &mut App<V, State, F>,
    cause: ShutdownCause,
) -> !
where
    V: View<embedded_graphics::pixelcolor::Rgb565, State>,
    F: Fn(&State) -> V,
{
    let start = Instant::now();
    let mut costs = Costs::default();
    // Each frame shown lit at full brightness, whatever the panel was doing.
    match cause {
        ShutdownCause::Asked => {
            app.state_mut().shutting_down();
            draw(display, app, start, &mut costs).await;
            let _ = display.set_brightness(Brightness::NORMAL).await;
            let _ = display.set_display_on(true).await;
            Timer::after(SHUTTING_DOWN).await;
        }
        #[cfg(feature = "battery-cutoff")]
        ShutdownCause::BatteryEmpty => {
            for _ in 0..EMPTY_BLINKS {
                for (lit, hold) in [(true, EMPTY_LIT), (false, EMPTY_DARK)] {
                    app.state_mut().battery_empty(lit);
                    draw(display, app, start, &mut costs).await;
                    if lit {
                        let _ = display.set_brightness(Brightness::NORMAL).await;
                        let _ = display.set_display_on(true).await;
                    }
                    Timer::after(hold).await;
                }
            }
        }
    }
    let _ = display.sleep().await;
    DISPLAY_SHUTDOWN_DONE.signal(());
    core::future::pending().await
}

/// The frames since the last report, and the worst of each stage. Reported
/// at most once per [`REPORT`], on one short line: the Pager's debug stream
/// holds one 64-byte line at a time.
#[derive(Default)]
struct Costs {
    frames: u32,
    layout: Duration,
    paint: Duration,
    flush: Duration,
    since: Option<Instant>,
}

impl Costs {
    fn report(&mut self, animating: bool) {
        let since = *self.since.get_or_insert_with(Instant::now);
        if self.frames == 0 || Instant::now() - since < REPORT {
            return;
        }
        // Frames, animating, the worst layout, paint, and flush in
        // ms, the least stack left free so far, and the CPU clock. A
        // screen's stack, when it has changed, takes every other line.
        #[cfg(feature = "debug-log")]
        if !report_stack() {
            debug_log(format_args!(
                "ui f={} a={} l={} p={} s={} free={} mhz={}",
                self.frames,
                u8::from(animating),
                self.layout.as_millis(),
                self.paint.as_millis(),
                self.flush.as_millis(),
                memory_probe::stack().margin,
                esp_hal::clock::cpu_clock().as_mhz(),
            ));
        }
        #[cfg(not(feature = "debug-log"))]
        let _ = animating;
        *self = Self {
            since: Some(Instant::now()),
            ..Self::default()
        };
    }
}

/// The parts of a pass whose stack is measured.
#[derive(Clone, Copy)]
enum Phase {
    /// Inputs applied.
    Input,
    /// The node pumped.
    Pump,
    /// Its events taken, and the strip brought up to date.
    Events,
    /// The view built and laid out.
    Layout,
    /// The frame painted.
    Paint,
    /// Waiting: the other tasks, and interrupts.
    Idle,
}

/// The stack left free since the last mark, counted to `phase` on the
/// screen `state` shows.
#[cfg_attr(not(feature = "debug-log"), allow(unused_variables))]
fn mark(state: &State, phase: Phase) {
    #[cfg(feature = "debug-log")]
    {
        // Painted again outside the lock: it is most of the stack.
        let free = memory_probe::take();
        let screen = screen(state);
        DEPTHS.lock(|depths| depths.borrow_mut().record(screen, phase, free));
    }
}

/// Reports the least stack each phase has left free on the screen shown,
/// or on another whose least has fallen, unless the last report was this
/// one. Returns whether it reported.
#[cfg(feature = "debug-log")]
fn report_stack() -> bool {
    let Some((screen, least)) = DEPTHS.lock(|depths| depths.borrow_mut().due()) else {
        return false;
    };
    // Input, pump, events, layout, paint, idle.
    debug_log(format_args!(
        "stk {} {} {} {} {} {} {}",
        SCREENS[screen], least[0], least[1], least[2], least[3], least[4], least[5],
    ));
    true
}

#[cfg(feature = "debug-log")]
const PHASES: usize = 6;

/// What the stack's report calls each screen.
#[cfg(feature = "debug-log")]
const SCREENS: [&str; 18] = [
    "chats", "find", "peers", "device", "conv", "menu", "resend", "details", "member", "peer",
    "page", "setup", "address", "join", "lock", "share", "nearby", "exchange",
];

/// The screen `state` shows, as an index into [`SCREENS`].
#[cfg(feature = "debug-log")]
fn screen(state: &State) -> usize {
    use umsh_ux_communicator::model::Section;
    use umsh_ux_communicator::nav::{Screen, keys};
    if state.lock.locked {
        return 14;
    }
    match state.screen() {
        Screen::Chats { find, focus, .. } => {
            match focus
                .current()
                .and_then(keys::section)
                .unwrap_or(state.section)
            {
                Section::Chats if find.is_some() => 1,
                Section::Chats => 0,
                Section::Peers => 2,
                Section::Device => 3,
            }
        }
        Screen::Conversation {
            actions, unsent, ..
        } => match (actions, unsent) {
            (Some(_), _) => 5,
            (_, Some(_)) => 6,
            _ => 4,
        },
        Screen::Details { .. } => 7,
        Screen::Member { .. } => 8,
        Screen::Peer { .. } => 9,
        Screen::Device { .. } => 10,
        Screen::Setup { .. } => 11,
        Screen::EnterAddress { .. } => 12,
        Screen::Join { .. } => 13,
        Screen::ShareContact { .. } => 15,
        Screen::Nearby { .. } => 16,
        Screen::Exchange { .. } => 17,
    }
}

/// The least stack each phase has left free on each screen. Kept apart
/// from the interface's task, whose future holds two sets of costs.
#[cfg(feature = "debug-log")]
static DEPTHS: embassy_sync::blocking_mutex::Mutex<
    CriticalSectionRawMutex,
    core::cell::RefCell<Depths>,
> = embassy_sync::blocking_mutex::Mutex::new(core::cell::RefCell::new(Depths::new()));

#[cfg(feature = "debug-log")]
struct Depths {
    /// Bytes, or `NONE` for a phase not seen on a screen.
    least: [[u16; PHASES]; SCREENS.len()],
    /// The screens whose least has fallen since they were reported.
    fallen: u16,
    /// The screen last measured.
    shown: usize,
    /// The last report was of the stack.
    reported: bool,
}

#[cfg(feature = "debug-log")]
impl Depths {
    const NONE: u16 = u16::MAX;
    /// Less than this below a screen's least is not news.
    const STEP: u16 = 128;

    const fn new() -> Self {
        Self {
            least: [[Self::NONE; PHASES]; SCREENS.len()],
            fallen: 0,
            shown: 0,
            reported: false,
        }
    }

    fn record(&mut self, screen: usize, phase: Phase, free: usize) {
        let free = u16::try_from(free).unwrap_or(Self::NONE - 1);
        let least = &mut self.least[screen][phase as usize];
        if *least == Self::NONE || free < least.saturating_sub(Self::STEP) {
            self.fallen |= 1 << screen;
        }
        *least = (*least).min(free);
        self.shown = screen;
    }

    /// The screen to report, and its least for each phase: the one shown,
    /// or another whose least has fallen, never twice running.
    fn due(&mut self) -> Option<(usize, [u16; PHASES])> {
        if core::mem::take(&mut self.reported) || self.fallen == 0 {
            return None;
        }
        let screen = if self.fallen & 1 << self.shown != 0 {
            self.shown
        } else {
            self.fallen.trailing_zeros() as usize
        };
        self.fallen &= !(1 << screen);
        self.reported = true;
        Some((
            screen,
            self.least[screen].map(|free| if free == Self::NONE { 0 } else { free }),
        ))
    }
}

/// Lays out, draws, and sends one frame. Returns whether an animation is
/// still running.
async fn draw<V, F>(
    display: &mut Display,
    app: &mut App<V, State, F>,
    start: Instant,
    costs: &mut Costs,
) -> bool
where
    V: View<embedded_graphics::pixelcolor::Rgb565, State>,
    F: Fn(&State) -> V,
{
    mark(app.state(), Phase::Idle);
    let began = Instant::now();
    app.set_time((began - start).into());
    app.finalize_view();
    let laid_out = Instant::now();
    mark(app.state(), Phase::Layout);
    let animating = {
        let mut target =
            EmbeddedGraphicsRenderTarget::new_hinted(display.color(), theme::BACKGROUND);
        // A new target reports an animation until told otherwise, so that
        // a first frame always draws; this one is made fresh every frame.
        target.clear_animation_status();
        // No clear: the root view paints the whole screen.
        app.render_animated(&mut target, &theme::TEXT);
        target.clear_animation_status()
    };
    let painted = Instant::now();
    mark(app.state(), Phase::Paint);
    // A failed transfer leaves the panel's history invalid, so the next
    // frame resends everything; there is nothing more to do here.
    let _ = display.flush().await;
    let sent = Instant::now();
    mark(app.state(), Phase::Idle);
    costs.frames += 1;
    costs.layout = costs.layout.max(laid_out - began);
    costs.paint = costs.paint.max(painted - laid_out);
    costs.flush = costs.flush.max(sent - painted);
    animating
}
