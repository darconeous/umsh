//! A communicator on the host. The screen is a window the size of a
//! board's: the T-LoRa Pager's 480x222, or with `--board tdeck` the
//! T-Deck's 320x240. The keyboard is the Pager's keyboard.
//!
//! Interactive (needs the `window` feature):
//!
//!     host-communicator [--board pager|tdeck]
//!     host-communicator [--board pager|tdeck] --node DIR
//!
//! The first shows the fixture's chats. The second runs the communicator's
//! node, as the Pager does, with its settings served by a soft device that
//! keeps its saved state and identity under DIR, and a device node on the
//! LAN bearer.
//!
//! On the Pager, Up and Down arrows or the mouse wheel turn the wheel; the
//! Right arrow or a click presses it. Escape is the lock button. Return,
//! Backspace, Space, and the letters are the Pager's; Shift is CAP, and Alt
//! the orange key.
//!
//! On the T-Deck, the arrows roll the trackball and Control presses it.
//! Escape locks, as the screen going dark would. The keyboard types
//! characters, with Shift applied as the T-Deck's keyboard applies its own.
//! With the fixture, Tab brings its next message in, as if it arrived. An
//! identity asked for arrives two seconds later, as the fixture's own
//! clock has it.
//!
//! Headless, for scripted runs and comparisons with the mockup:
//!
//!     host-communicator [--board B] [--node DIR] --script steps.txt --out shots/
//!
//! Each script line is one step: `turn N` (negative is up), `move up`,
//! `move down`, `move left`, or `move right` with a count after it if more
//! than one (the trackball), `press`,
//! `enter`, `backspace`, `type TEXT` (typed as it is), `keys TEXT` (pressed
//! as Pager keys, so the modifiers and typing aids act on them), `space`,
//! `shift` and `alt` (tapped), `alt-down` and `alt-up`, `airtime SECONDS`
//! (spent airtime that returns in that long; 0 for none), `arrive` (the
//! fixture's next message arrives), `identify` (the identity asked for
//! arrives at once), `meet STEP` (the fixture's other holder of a contact
//! exchange `asks`, `accepts`, `declines`, presses `same` or `different`,
//! or `leaves`), `wait SECONDS` (the board's clock moves on, and the
//! fixture's with it), `dark` and `lit`
//! (the panel goes dark, which locks it a second later, and lights again),
//! `lock` (the lock button), `battery PERCENT [charging]`,
//! `battery-empty` (with `off` for the blink's dark half), `first-run`,
//! `shot NAME`, which writes `NAME.png` into the output directory once
//! everything has settled, or `peek MS NAME`, which writes it MS
//! milliseconds into what the last steps started. `#` starts a comment.
//! Each input takes 50 ms of the board's clock.
//!
//! Timing, and something for a profiler to watch:
//!
//!     host-communicator [--board B] --bench N
//!
//! Turns the wheel N times, down the list and back, and reports the mean
//! layout and paint time of a frame.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod flash;
mod mesh;
mod node;

use umsh_ux_communicator::buoyant;

use buoyant::app::App;
use buoyant::focus::DefaultFocus;
use buoyant::render::AnimatedJoin;
use buoyant::render_target::{EmbeddedGraphicsRenderTarget, RenderTarget as _};
use buoyant::view::ViewLayout;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics_simulator::{OutputSettings, SimulatorDisplay};
use umsh_pager_peripherals::input::alt_legend;
use umsh_ux_communicator::board::Board;
use umsh_ux_communicator::input::{self, Arrow, Input};
use umsh_ux_communicator::keyboard::Modifier;
use umsh_ux_communicator::model::{BatteryReading, Charge, HOLD_MS, NodeEvent, State};
use umsh_ux_communicator::{fixture, theme, typeface, ui};

/// Where the fixture's chats keep their messages, for the life of the run.
fn store() -> &'static fixture::Store {
    Box::leak(Box::new(fixture::Store::new(&std::alloc::System)))
}

/// Moves the fixture on to `now` on the board's clock, in milliseconds, and
/// takes in what that brings as a board would: the minute turning over,
/// and what the fixture has to say.
fn advance<V, F>(app: &mut App<V, State, F>, store: &fixture::Store, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    store.advance(now);
    let time = store.time();
    if app.state().wall_time.map(|t| t / 60) != Some(time / 60) {
        app.state_mut().set_wall_time(Some(time));
        app.finalize_view();
    }
    input::events(app, now);
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

/// What the window shows: the fixture's chats, or the communicator's node.
#[derive(Clone, Copy)]
enum Backend {
    Fixture(&'static fixture::Store),
    Node(&'static node::Node),
}

impl Backend {
    fn state(self, board: &'static Board) -> State {
        match self {
            Self::Fixture(store) => fixture::state(store, board),
            Self::Node(node) => node::state(node, board),
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
            Self::Fixture(store) => advance(app, store, now),
            Self::Node(node) => {
                node.pump();
                input::events(app, now);
            }
        }
    }

    /// Tab: the fixture's next message arrives. The node has none to give.
    fn tab(self) {
        if let Self::Fixture(store) = self {
            store.arrive();
        }
    }
}

fn main() -> ExitCode {
    typeface::install(Box::leak(Box::new(typeface::EmojiCache::new())));
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let board = match args.iter().position(|a| a == "--board") {
        Some(at) if at + 1 < args.len() => {
            let name = args.remove(at + 1);
            args.remove(at);
            match name.as_str() {
                "pager" => &Board::PAGER,
                "tdeck" => &Board::TDECK,
                other => {
                    eprintln!("host-communicator: no board {other:?}; pager or tdeck");
                    return ExitCode::from(2);
                }
            }
        }
        Some(_) => {
            eprintln!("host-communicator: --board needs a name");
            return ExitCode::from(2);
        }
        None => &Board::PAGER,
    };
    let (backend, dir, args) = match args.as_slice() {
        [node_flag, dir, rest @ ..] if node_flag == "--node" => {
            match node::open(Path::new(dir), std::time::Instant::now()) {
                Ok(node) => {
                    node.set_model(board.model);
                    (Backend::Node(node), Some(dir), rest)
                }
                Err(e) => {
                    eprintln!("host-communicator: {dir}: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        rest => (Backend::Fixture(store()), None, rest),
    };
    match args {
        [] => {
            // Interactive, the node has a radio. A script runs without one,
            // so that what it shows is only what it did.
            let mesh = match (backend, dir) {
                (Backend::Node(node), Some(dir)) => match mesh::Mesh::start(Path::new(dir), node) {
                    Ok(mesh) => Some(mesh),
                    Err(e) => {
                        eprintln!("host-communicator: the device node: {e}");
                        return ExitCode::FAILURE;
                    }
                },
                _ => None,
            };
            window(board, backend, mesh)
        }
        [script_flag, script, out_flag, out]
            if script_flag == "--script" && out_flag == "--out" =>
        {
            match headless(board, Path::new(script), &PathBuf::from(out), backend) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("host-communicator: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        [bench_flag, count] if bench_flag == "--bench" => match count.parse() {
            Ok(count) => {
                bench(board, count);
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("host-communicator: --bench needs a count");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!(
                "usage: host-communicator [--board pager|tdeck] [--node DIR] [--script FILE --out DIR | --bench N]"
            );
            ExitCode::from(2)
        }
    }
}

fn bench(board: &'static Board, count: u32) {
    use std::time::{Duration, Instant};

    let size = board.metrics.size();
    let mut display: SimulatorDisplay<Rgb565> = SimulatorDisplay::new(size);
    let mut app = App::new(fixture::state(store(), board), size.into(), ui::root_view);
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
                let Backend::Fixture(store) = backend else {
                    return Err(format!("line {}: {word} needs the fixture", number + 1));
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
                let Backend::Fixture(store) = backend else {
                    return Err(format!("line {}: meet needs the fixture", number + 1));
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
fn window(board: &'static Board, backend: Backend, mesh: Option<mesh::Mesh>) -> ExitCode {
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
        "UMSH communicator",
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
        match &mesh {
            Some(mesh) => mesh.run_for(frame),
            None => std::thread::sleep(frame),
        }
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
fn window(_board: &'static Board, _backend: Backend, _mesh: Option<mesh::Mesh>) -> ExitCode {
    eprintln!("host-communicator: built without the window feature; use --script");
    ExitCode::from(2)
}
