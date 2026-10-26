//! A communicator on the host: the T-LoRa Pager's or the T-Deck's
//! interface in a window, over the Pager's own ULCP session and device
//! node, with an IP multicast group (UMSH over IP Multicast) for its
//! radio. See `README.md` beside this crate for how to run it, its
//! controls, its instances, and the script language its headless runs
//! take.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, ValueEnum};

mod board;
mod flash;
mod node;

use umsh_ux_communicator::buoyant;

use buoyant::app::App;
use buoyant::focus::DefaultFocus;
use buoyant::render::AnimatedJoin;
use buoyant::render_target::{EmbeddedGraphicsRenderTarget, RenderTarget as _};
use buoyant::view::ViewLayout;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics_simulator::{OutputSettings, SimulatorDisplay};
use umsh::tokio_support::LanConfig;
use umsh_pager_peripherals::input::alt_legend;
use umsh_ux_communicator::board::Board;
use umsh_ux_communicator::input::{self, Arrow, Input, TouchPhase};
use umsh_ux_communicator::keyboard::Modifier;
use umsh_ux_communicator::model::{BatteryReading, Charge, HOLD_MS, NodeEvent, State};
use umsh_ux_communicator::{fixture, theme, typeface, ui};

/// A communicator on this computer, on the network as a UMSH node.
#[derive(Parser)]
#[command(name = "host-communicator", version)]
struct Args {
    /// The instance to run, `default` if none is named. Each instance is
    /// its own device, with its own identity, settings, and chats.
    #[arg(conflicts_with_all = ["data_dir", "demo"], value_parser = instance_name)]
    name: Option<String>,

    /// Keep the device here instead of the instance's own folder.
    #[arg(long, value_name = "DIR", conflicts_with = "demo")]
    data_dir: Option<PathBuf>,

    /// The board whose screen and controls to show.
    #[arg(long, value_enum, default_value_t = BoardName::Tdeck)]
    board: BoardName,

    /// Join the group on this interface's address, not the one the
    /// routing table picks.
    #[arg(long, value_name = "ADDRESS", conflicts_with_all = ["host_local", "demo"])]
    interface: Option<Ipv4Addr>,

    /// Join the group on the loopback interface: reach only the other
    /// devices on this computer.
    #[arg(long, conflicts_with = "demo")]
    host_local: bool,

    /// Print the device's debug log on standard error.
    #[arg(long, short, conflicts_with = "demo")]
    verbose: bool,

    /// Show the demo's made-up chats instead of running a device.
    #[arg(long)]
    demo: bool,

    /// With --demo, a public channel several hundred messages long.
    #[arg(long, requires = "demo")]
    long_history: bool,

    /// Run headless: the steps in FILE, with screenshots written to --out.
    /// Runs the demo unless an instance or --data-dir is named.
    #[arg(long, value_name = "FILE", requires = "out", conflicts_with = "bench")]
    script: Option<PathBuf>,

    /// Where a script's screenshots go.
    #[arg(long, value_name = "DIR", requires = "script")]
    out: Option<PathBuf>,

    /// Turn the wheel N times over the demo and report the time a frame takes.
    #[arg(long, value_name = "N")]
    bench: Option<u32>,
}

/// An instance's name: a folder's name, and the device's until it is given
/// one of its own.
fn instance_name(name: &str) -> Result<String, String> {
    let folder =
        !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0']);
    if folder && name.len() <= umsh_ulcp_device::MAX_DEVICE_NAME_LEN {
        Ok(name.to_string())
    } else {
        Err("an instance is named like a folder, in at most 64 bytes".to_string())
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum BoardName {
    /// The LILYGO T-Deck: 320x240, a touchscreen and a trackball.
    Tdeck,
    /// The LILYGO T-LoRa Pager: 480x222, a wheel.
    Pager,
}

impl BoardName {
    fn board(self) -> &'static Board {
        match self {
            Self::Pager => &Board::PAGER,
            Self::Tdeck => &Board::TDECK,
        }
    }
}

/// Where the demo's chats keep their messages, for the life of the run,
/// with a long history when asked.
fn store(long: bool) -> &'static fixture::Store {
    let store = fixture::Store::new(&std::alloc::System);
    Box::leak(Box::new(if long {
        store.with_long_history()
    } else {
        store
    }))
}

/// Moves the demo on to `now` on the board's clock, in milliseconds, and
/// takes in what that brings as a board would: the minute turning over,
/// and what the demo has to say.
fn advance<V, F>(app: &mut App<V, State, F>, store: &fixture::Store, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    store.advance(now);
    set_wall_time(app, Some(store.time()));
    input::events(app, now);
}

/// Takes in the wall clock's minute when it turns over.
fn set_wall_time<V, F>(app: &mut App<V, State, F>, time: Option<u32>)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    if app.state().wall_time.map(|t| t / 60) != time.map(|t| t / 60) {
        app.state_mut().set_wall_time(time);
        app.finalize_view();
    }
}

/// Lets go of whatever on screen has had its time by `now`.
fn expire<V, F>(app: &mut App<V, State, F>, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    if app.state().next_deadline().is_some_and(|at| at <= now) {
        umsh_ux_communicator::input::expire(app, now);
    }
}

/// What the window shows: the demo's chats, or a device.
#[derive(Clone, Copy)]
enum Backend {
    Demo(&'static fixture::Store),
    Device(&'static board::Board),
}

impl Backend {
    fn state(self, board: &'static Board) -> State {
        match self {
            Self::Demo(store) => fixture::state(store, board),
            Self::Device(device) => node::state(device.node, board),
        }
    }

    /// Moves the backend on to `now` and takes in what it has to say.
    fn advance<V, F>(self, app: &mut App<V, State, F>, now: u64)
    where
        V: ViewLayout<State>,
        V::FocusTree: DefaultFocus,
        V::Renderables: AnimatedJoin,
        F: Fn(&State) -> V,
    {
        match self {
            Self::Demo(store) => advance(app, store, now),
            Self::Device(device) => {
                device.node.pump();
                set_wall_time(app, umsh_hal::wall_clock::now());
                input::events(app, now);
            }
        }
        // There is nothing to play it on: what would sound is said.
        if app.state().has_cue()
            && let Some(cue) = app.state_mut().take_cue()
        {
            eprintln!("sound: {cue:?}");
        }
    }

    /// Lets the device run for `span`, or waits it out over the demo.
    fn run_for(self, span: Duration) {
        match self {
            Self::Demo(_) => std::thread::sleep(span),
            Self::Device(device) => device.run_for(span),
        }
    }

    /// Tab: the demo's next message arrives. A device has none to give.
    fn tab(self) {
        if let Self::Demo(store) = self {
            store.arrive();
        }
    }
}

fn main() -> ExitCode {
    typeface::install(Box::leak(Box::new(typeface::EmojiCache::new())));
    let args = Args::parse();
    let board = args.board.board();
    if let Some(count) = args.bench {
        bench(board, count);
        return ExitCode::SUCCESS;
    }
    // A script runs the demo unless it names a device, and a device it
    // runs never joins its group, so that what it shows is only what it
    // did.
    let named = args.name.is_some() || args.data_dir.is_some();
    let demo = args.demo || (args.script.is_some() && !named);
    let (backend, name) = if demo {
        (Backend::Demo(store(args.long_history)), "demo".to_string())
    } else {
        // A device kept elsewhere is named for its folder until it is
        // given a name of its own.
        let name = match (&args.name, &args.data_dir) {
            (Some(name), _) => name.clone(),
            (None, Some(dir)) => dir
                .file_name()
                .and_then(|name| instance_name(&name.to_string_lossy()).ok())
                .unwrap_or_else(|| "default".into()),
            (None, None) => "default".into(),
        };
        let Some(dir) = args.data_dir.clone().or_else(|| board::instance_dir(&name)) else {
            eprintln!("host-communicator: no home folder to keep instances in; use --data-dir");
            return ExitCode::FAILURE;
        };
        let network = if args.script.is_some() {
            board::Network::Offline
        } else {
            let mut base = LanConfig::lan();
            if args.host_local {
                base.interface = Ipv4Addr::LOCALHOST;
            } else if let Some(interface) = args.interface {
                base.interface = interface;
            }
            board::Network::Lan(base)
        };
        if args.verbose {
            umsh_ulcp_runtime::log::set_debug_log(|line| eprintln!("{line}"));
        }
        match board::Board::start(&dir, name.clone().leak(), network) {
            Ok(device) => {
                device.node.set_model(board.model);
                (Backend::Device(Box::leak(Box::new(device))), name)
            }
            Err(board::BootError::Running) => {
                eprintln!(
                    "host-communicator: {} is already running; start another instance with `host-communicator NAME`",
                    dir.display()
                );
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("host-communicator: {}: {error}", dir.display());
                return ExitCode::FAILURE;
            }
        }
    };
    match (&args.script, &args.out) {
        (Some(script), Some(out)) => match headless(board, script, out, backend) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("host-communicator: {e}");
                ExitCode::FAILURE
            }
        },
        _ => window(board, backend, &format!("UMSH communicator — {name}")),
    }
}

fn bench(board: &'static Board, count: u32) {
    use std::time::{Duration, Instant};

    let size = board.metrics.size();
    let mut display: SimulatorDisplay<Rgb565> = SimulatorDisplay::new(size);
    let mut app = App::new(
        fixture::state(store(false), board),
        size.into(),
        ui::root_view,
    );
    ui::bind(&mut app);
    let (mut layout, mut paint) = (Duration::ZERO, Duration::ZERO);
    for turn in 0..count {
        // Four steps down, four back, so the focus keeps moving.
        let step = if turn / 4 % 2 == 0 { 1 } else { -1 };
        input::apply(&mut app, Input::Turn(step), 0);
        let began = Instant::now();
        app.finalize_view();
        let laid_out = Instant::now();
        let mut target = EmbeddedGraphicsRenderTarget::new_hinted(&mut display, theme::BACKGROUND);
        app.render_animated(&mut target, &theme::TEXT);
        paint += laid_out.elapsed();
        layout += laid_out - began;
    }
    let count = count.max(1);
    println!(
        "{count} frames: layout {:?}, paint {:?} per frame",
        layout / count,
        paint / count
    );
}

fn headless(
    board: &'static Board,
    script: &Path,
    out: &Path,
    backend: Backend,
) -> Result<(), String> {
    let steps =
        std::fs::read_to_string(script).map_err(|e| format!("{}: {e}", script.display()))?;
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let size = board.metrics.size();
    let mut display: SimulatorDisplay<Rgb565> = SimulatorDisplay::new(size);
    let mut app = App::new(backend.state(board), size.into(), ui::root_view);
    ui::bind(&mut app);
    // The board's clock: each input takes a moment, and `wait` moves it on.
    let mut clock = 0;
    for (number, line) in steps.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
        let rest = rest.trim();
        let inputs = match word {
            "turn" => {
                vec![Input::Turn(rest.parse().map_err(|_| {
                    format!("line {}: turn needs a count", number + 1)
                })?)]
            }
            "move" => {
                let mut words = rest.split_whitespace();
                let arrow = match words.next() {
                    Some("up") => Arrow::Up,
                    Some("down") => Arrow::Down,
                    Some("left") => Arrow::Left,
                    Some("right") => Arrow::Right,
                    _ => {
                        return Err(format!(
                            "line {}: move needs up, down, left, or right",
                            number + 1
                        ));
                    }
                };
                let count: usize = match words.next() {
                    Some(count) => count
                        .parse()
                        .map_err(|_| format!("line {}: move takes a count", number + 1))?,
                    None => 1,
                };
                vec![Input::Move(arrow); count]
            }
            "press" => vec![Input::Press, Input::Release],
            // A finger down and up again at a point on a touchscreen.
            "tap" => {
                let point: Vec<i16> = rest
                    .split_whitespace()
                    .map(str::parse)
                    .collect::<Result<_, _>>()
                    .map_err(|_| format!("line {}: tap needs x and y", number + 1))?;
                let [x, y] = point[..] else {
                    return Err(format!("line {}: tap needs x and y", number + 1));
                };
                [TouchPhase::Started, TouchPhase::Ended]
                    .map(|phase| Input::Touch {
                        phase,
                        x,
                        y,
                        at: clock + INPUT_MS,
                    })
                    .to_vec()
            }
            // Down long enough to open a menu, then up.
            "hold" => {
                input::apply(&mut app, Input::Press, clock);
                clock += HOLD_MS;
                expire(&mut app, clock);
                vec![Input::Release]
            }
            "enter" => vec![Input::Enter],
            "backspace" => vec![Input::Backspace],
            "type" => rest.chars().map(Input::Character).collect(),
            "keys" => rest.chars().map(pager_key).collect(),
            "space" => vec![Input::Space],
            "shift" => tap(Modifier::Shift).to_vec(),
            "alt" => tap(Modifier::Alt).to_vec(),
            "alt-down" | "alt-up" => vec![Input::Modifier {
                modifier: Modifier::Alt,
                down: word == "alt-down",
            }],
            "dark" | "lit" => {
                if word == "dark" {
                    app.state_mut().screen_off(clock);
                } else {
                    app.state_mut().screen_on(clock);
                }
                app.finalize_view();
                vec![]
            }
            "lock" => {
                app.state_mut().lock();
                app.finalize_view();
                vec![]
            }
            "arrive" | "identify" => {
                let Backend::Demo(store) = backend else {
                    return Err(format!("line {}: {word} needs the demo", number + 1));
                };
                if word == "arrive" {
                    store.arrive();
                } else {
                    store.answer_identity();
                }
                vec![]
            }
            "meet" => {
                use umsh_ux_communicator::fixture::MeetStep;
                let Backend::Demo(store) = backend else {
                    return Err(format!("line {}: meet needs the demo", number + 1));
                };
                store.meet_peer(match rest {
                    "asks" => MeetStep::Asks,
                    "accepts" => MeetStep::Answers(true),
                    "declines" => MeetStep::Answers(false),
                    "same" => MeetStep::Same,
                    "different" => MeetStep::Different,
                    "leaves" => MeetStep::Leaves,
                    _ => {
                        return Err(format!(
                            "line {}: meet asks, accepts, declines, same, different, or leaves",
                            number + 1
                        ));
                    }
                });
                vec![]
            }
            "wait" => {
                let seconds: u64 = rest
                    .parse()
                    .map_err(|_| format!("line {}: wait needs seconds", number + 1))?;
                clock += seconds * 1000;
                expire(&mut app, clock);
                vec![]
            }
            "battery" => {
                // `battery PERCENT`, with `charging` after it while plugged in.
                let mut words = rest.split_whitespace();
                let percent: u8 = words
                    .next()
                    .and_then(|w| w.parse().ok())
                    .ok_or_else(|| format!("line {}: battery needs a percent", number + 1))?;
                let charge = if words.next() == Some("charging") {
                    Charge::Charging
                } else {
                    Charge::Discharging
                };
                let reading = BatteryReading {
                    percent: Some(percent),
                    charge: Some(charge),
                    millivolts: None,
                };
                app.state_mut().battery(reading, clock);
                app.finalize_view();
                vec![]
            }
            "first-run" => {
                app.state_mut().start_setup();
                app.finalize_view();
                vec![]
            }
            "battery-empty" => {
                // `battery-empty off` draws the blink's dark half.
                app.state_mut().battery_empty(rest != "off");
                app.finalize_view();
                vec![]
            }
            "airtime" => {
                let wait: u16 = rest
                    .parse()
                    .map_err(|_| format!("line {}: airtime needs seconds", number + 1))?;
                let wait = (wait > 0).then_some(wait);
                app.state_mut().apply(NodeEvent::Airtime { wait }, clock);
                app.finalize_view();
                vec![]
            }
            "shot" | "peek" => {
                // Headless runs are not animated: a shot draws where things
                // settle, well after what the last steps started, and a peek
                // that many milliseconds into it.
                let (after, name) = if word == "shot" {
                    (60_000, rest)
                } else {
                    let (ms, name) = rest.split_once(' ').unwrap_or((rest, ""));
                    let ms = ms.parse().map_err(|_| {
                        format!("line {}: peek needs milliseconds and a name", number + 1)
                    })?;
                    (ms, name.trim())
                };
                let mut target =
                    EmbeddedGraphicsRenderTarget::new_hinted(&mut display, theme::BACKGROUND);
                target.clear(theme::BACKGROUND);
                app.advance_time(std::time::Duration::from_millis(after));
                app.render_animated(&mut target, &theme::TEXT);
                let path = out.join(format!("{name}.png"));
                display
                    .to_rgb_output_image(&OutputSettings::default())
                    .save_png(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                vec![]
            }
            other => return Err(format!("line {}: unknown step {other:?}", number + 1)),
        };
        for input in inputs {
            clock += INPUT_MS;
            input::apply(&mut app, input, clock);
            backend.advance(&mut app, clock);
        }
        // A device takes what the step started in on its own clock.
        if let Backend::Device(device) = backend {
            device.run_for(Duration::from_millis(INPUT_MS));
        }
        backend.advance(&mut app, clock);
    }
    Ok(())
}

/// How long one input takes in a script.
const INPUT_MS: u64 = 50;

/// The Pager key that types `c`, with its Alt legend.
fn pager_key(c: char) -> Input {
    if c == ' ' {
        Input::Space
    } else {
        Input::Key {
            plain: c.to_ascii_lowercase(),
            alt: alt_legend(c),
        }
    }
}

/// A modifier pressed and let go.
fn tap(modifier: Modifier) -> [Input; 2] {
    [true, false].map(|down| Input::Modifier { modifier, down })
}

#[cfg(feature = "window")]
fn window(board: &'static Board, backend: Backend, title: &str) -> ExitCode {
    use embedded_graphics_simulator::sdl2::{Keycode, MouseButton};
    use embedded_graphics_simulator::{SimulatorEvent, Window};

    /// The Pager modifier a host key stands for.
    fn modifier(key: Keycode) -> Option<Modifier> {
        match key {
            Keycode::LShift | Keycode::RShift => Some(Modifier::Shift),
            Keycode::LAlt | Keycode::RAlt => Some(Modifier::Alt),
            _ => None,
        }
    }

    let mut window = Window::new(
        title,
        &OutputSettings {
            scale: 2,
            ..OutputSettings::default()
        },
    );
    // The T-Deck's trackball and keyboard, or the Pager's wheel and keys.
    let tdeck = board == &Board::TDECK;
    let size = board.metrics.size();
    let mut display: SimulatorDisplay<Rgb565> = SimulatorDisplay::new(size);
    let mut target = EmbeddedGraphicsRenderTarget::new_hinted(&mut display, theme::BACKGROUND);
    window.update(target.display());
    let start = std::time::Instant::now();
    let mut app = App::new(backend.state(board), size.into(), ui::root_view);
    ui::bind(&mut app);
    // Whether the left button is down on the T-Deck's touchscreen.
    let mut touching = false;
    /// A finger at `point` on the touchscreen, at `now`.
    fn touch(phase: TouchPhase, point: embedded_graphics::prelude::Point, now: u64) -> Input {
        let clamp = |v: i32| v.clamp(0, i32::from(i16::MAX)) as i16;
        Input::Touch {
            phase,
            x: clamp(point.x),
            y: clamp(point.y),
            at: now,
        }
    }
    loop {
        app.set_time(start.elapsed());
        let now = start.elapsed().as_millis() as u64;
        expire(&mut app, now);
        for event in window.events() {
            let input = match event {
                SimulatorEvent::Quit => return ExitCode::SUCCESS,
                SimulatorEvent::KeyDown {
                    keycode,
                    keymod,
                    repeat,
                } if tdeck => tdeck_key(keycode, keymod, repeat).or_else(|| {
                    match keycode {
                        Keycode::Tab => backend.tab(),
                        Keycode::Escape => {
                            app.state_mut().lock();
                            app.finalize_view();
                        }
                        _ => {}
                    }
                    None
                }),
                SimulatorEvent::KeyUp {
                    keycode: Keycode::LCtrl | Keycode::RCtrl,
                    ..
                } if tdeck => Some(Input::Release),
                SimulatorEvent::KeyUp { .. } if tdeck => None,
                SimulatorEvent::KeyDown {
                    keycode, repeat, ..
                } => match keycode {
                    Keycode::Up => Some(Input::Turn(-1)),
                    Keycode::Down => Some(Input::Turn(1)),
                    Keycode::Right if !repeat => Some(Input::Press),
                    // Back, as the Pager's Backspace goes back; never into
                    // text being edited, which it would delete from.
                    Keycode::Left => (!app.state().keyboard.active()).then_some(Input::Backspace),
                    Keycode::Return => Some(Input::Enter),
                    Keycode::Backspace => Some(Input::Backspace),
                    Keycode::Space => Some(Input::Space),
                    Keycode::Tab => {
                        backend.tab();
                        None
                    }
                    Keycode::Escape => {
                        app.state_mut().lock();
                        app.finalize_view();
                        None
                    }
                    // The Pager's keyboard does not repeat.
                    _ if repeat => None,
                    other => modifier(other)
                        .map(|modifier| Input::Modifier {
                            modifier,
                            down: true,
                        })
                        .or_else(|| {
                            // Letters, by their key names.
                            let name = other.name();
                            let mut chars = name.chars();
                            match (chars.next(), chars.next()) {
                                (Some(c), None) if c.is_ascii_alphabetic() => Some(pager_key(c)),
                                _ => None,
                            }
                        }),
                },
                SimulatorEvent::KeyUp {
                    keycode: Keycode::Right,
                    ..
                } => Some(Input::Release),
                SimulatorEvent::KeyUp { keycode, .. } => {
                    modifier(keycode).map(|modifier| Input::Modifier {
                        modifier,
                        down: false,
                    })
                }
                // On the T-Deck the mouse is a finger on its touchscreen,
                // and the right button and the wheel are its trackball.
                SimulatorEvent::MouseButtonDown {
                    mouse_btn: MouseButton::Left,
                    point,
                } if tdeck => {
                    touching = true;
                    Some(touch(TouchPhase::Started, point, now))
                }
                SimulatorEvent::MouseMove { point } if tdeck && touching => {
                    Some(touch(TouchPhase::Moved, point, now))
                }
                SimulatorEvent::MouseButtonUp {
                    mouse_btn: MouseButton::Left,
                    point,
                } if tdeck && touching => {
                    touching = false;
                    Some(touch(TouchPhase::Ended, point, now))
                }
                SimulatorEvent::MouseButtonDown {
                    mouse_btn: MouseButton::Right,
                    ..
                } if tdeck => Some(Input::Press),
                SimulatorEvent::MouseButtonUp {
                    mouse_btn: MouseButton::Right,
                    ..
                } if tdeck => Some(Input::Release),
                SimulatorEvent::MouseWheel { scroll_delta, .. } if tdeck => {
                    Some(Input::Move(if scroll_delta.y > 0 {
                        Arrow::Up
                    } else {
                        Arrow::Down
                    }))
                }
                SimulatorEvent::MouseButtonDown { .. }
                | SimulatorEvent::MouseButtonUp { .. }
                | SimulatorEvent::MouseMove { .. }
                    if tdeck =>
                {
                    None
                }
                SimulatorEvent::MouseWheel { scroll_delta, .. } => {
                    Some(Input::Turn(if scroll_delta.y > 0 { -1 } else { 1 }))
                }
                SimulatorEvent::MouseButtonDown {
                    mouse_btn: MouseButton::Left,
                    ..
                } => Some(Input::Press),
                SimulatorEvent::MouseButtonUp {
                    mouse_btn: MouseButton::Left,
                    ..
                } => Some(Input::Release),
                _ => None,
            };
            if let Some(input) = input {
                input::apply(&mut app, input, now);
            }
        }
        backend.advance(&mut app, now);
        if app.should_redraw() || target.clear_animation_status() {
            target.clear(theme::BACKGROUND);
            app.render_animated(&mut target, &theme::TEXT);
            window.update(target.display());
        }
        let frame = std::time::Duration::from_millis(8);
        backend.run_for(frame);
    }
}

/// What a host key does on the T-Deck: the arrows roll the trackball,
/// Control presses it, and the rest type as its keyboard does.
#[cfg(feature = "window")]
fn tdeck_key(
    key: embedded_graphics_simulator::sdl2::Keycode,
    keymod: embedded_graphics_simulator::sdl2::Mod,
    repeat: bool,
) -> Option<Input> {
    use embedded_graphics_simulator::sdl2::{Keycode, Mod};
    let input = match key {
        Keycode::Up => Input::Move(Arrow::Up),
        Keycode::Down => Input::Move(Arrow::Down),
        Keycode::Left => Input::Move(Arrow::Left),
        Keycode::Right => Input::Move(Arrow::Right),
        // Its keyboard does not repeat, and the ball's press is one press.
        _ if repeat => return None,
        Keycode::LCtrl | Keycode::RCtrl => Input::Press,
        Keycode::Return => Input::Enter,
        Keycode::Backspace => Input::Backspace,
        Keycode::Space => Input::Space,
        other => {
            let name = other.name();
            let mut chars = name.chars();
            let (Some(c), None) = (chars.next(), chars.next()) else {
                return None;
            };
            if !c.is_ascii_alphanumeric() {
                return None;
            }
            let shift = keymod.intersects(Mod::LSHIFTMOD | Mod::RSHIFTMOD);
            Input::Character(if shift {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            })
        }
    };
    Some(input)
}

#[cfg(not(feature = "window"))]
fn window(_board: &'static Board, _backend: Backend, _title: &str) -> ExitCode {
    eprintln!("host-communicator: built without the window feature; use --script");
    ExitCode::from(2)
}
