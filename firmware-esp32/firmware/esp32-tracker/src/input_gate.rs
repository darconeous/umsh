//! Between a board's controls and the interface: what a gesture means
//! while the panel is dark, fading, or showing the splash, and the handoff
//! from interrupt-driven capture while lit to wake-enabled level waits
//! while dark. The board's own capture lives in `board_input`, which
//! supplies the hooks this calls: the item it captures, how its capture
//! resyncs and stops, and its alert.
use super::*;
use core::cell::RefCell;
use esp_hal::rtc_cntl::WakeLock;
use umsh_ux_display_tracker::input_power::{Gesture, InputPower, Mode};

/// What the board's capture produces.
pub(crate) type Item = board_input::Item;

pub(crate) struct Control {
    pub(crate) policy: InputPower,
    pub(crate) guard: Option<WakeLock>,
}
static CONTROL: critical_section::Mutex<RefCell<Control>> =
    critical_section::Mutex::new(RefCell::new(Control {
        policy: InputPower::new(),
        guard: None,
    }));
/// The policy's mode or epoch changed: the board's coordinator looks again.
pub(crate) static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static CAPTURE_READY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static CAPTURE_EPOCH: AtomicU32 = AtomicU32::new(0);
static DISPLAY_READY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOPPED: AtomicU32 = AtomicU32::new(0);
static STOP_PROGRESS: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static NAVIGATION: Channel<CriticalSectionRawMutex, Item, 64> = Channel::new();
static NAVIGATION_PENDING: AtomicBool = AtomicBool::new(false);
static INPUT_OVERFLOW: AtomicBool = AtomicBool::new(false);
/// The user asked for the lock screen: on the Pager, the lock button
/// pressed and let go before its hold shuts the board down. A press that
/// silenced an alert does not count. A board with no such control never
/// raises it, and locks on timeout alone.
pub(crate) static LOCK: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Where navigation goes once the display is ready for it.
fn forward(item: Item) -> bool {
    #[cfg(feature = "communicator")]
    let sent = communicator::INPUT
        .try_send(board_input::to_input(item))
        .is_ok();
    #[cfg(not(feature = "communicator"))]
    let sent = UI_INPUT_CH.try_send(item).is_ok();
    sent
}

fn clear_forwarded() {
    #[cfg(feature = "communicator")]
    communicator::INPUT.clear();
    #[cfg(not(feature = "communicator"))]
    UI_INPUT_CH.clear();
}

/// A locate alert began or ended: what was queued is dropped. Only the
/// Pager has an alert.
#[cfg(feature = "board-tlora-pager")]
pub fn discard_navigation() {
    critical_section::with(|_| {
        NAVIGATION_PENDING.store(false, Ordering::Release);
        NAVIGATION.clear();
        clear_forwarded();
        // A gesture spanning an alert boundary is consumed in its entirety.
        board_input::resync();
    });
}
#[cfg(feature = "board-tlora-pager")]
pub fn alert_started() {
    control(|c| c.policy.alert_started());
}

pub(crate) fn control<R>(f: impl FnOnce(&mut Control) -> R) -> R {
    critical_section::with(|cs| f(&mut CONTROL.borrow_ref_mut(cs)))
}

pub(crate) fn hold(c: &mut Control) {
    if c.guard.is_none() {
        c.guard = Some(WakeLock::new());
    }
}

pub fn activity() -> u32 {
    control(|c| c.policy.activity())
}

pub(crate) fn note_activity() {
    control(|c| c.policy.note_activity());
}

pub fn dark(before_display_off: u32) {
    let accepted = control(|c| c.policy.dark(before_display_off));
    if accepted {
        display_lit(false);
        CHANGED.signal(());
    } else {
        wake_display();
    }
}

pub(crate) fn wake_display() {
    if control(|c| {
        if !c.policy.wake() {
            return false;
        }
        hold(c);
        true
    }) {
        CHANGED.signal(());
        UI_WAKE.signal(());
    }
}

/// Called before wake rendering, including wakes originating outside input.
pub async fn interactive() -> u32 {
    let epoch = control(|c| {
        c.policy.wake();
        hold(c);
        c.policy.epoch
    });
    CHANGED.signal(());
    loop {
        CAPTURE_READY.reset();
        if CAPTURE_EPOCH.load(Ordering::Acquire) == epoch {
            return epoch;
        }
        CAPTURE_READY.wait().await;
    }
}

/// The board's coordinator has capture in the shape `epoch` calls for.
pub(crate) fn captured(epoch: u32) {
    CAPTURE_EPOCH.store(epoch, Ordering::Release);
    CAPTURE_READY.signal(());
}

pub fn shown(epoch: u32) {
    // Publish before allowing queued post-wake gestures through the display.
    SCREEN_FADED.store(false, Ordering::Release);
    control(|c| c.policy.shown(epoch));
    display_lit(true);
    DISPLAY_READY.signal(());
    board_input::shown();
}

pub(crate) fn start_gesture() -> Gesture {
    let disposition = control(|c| {
        let disposition = c.policy.gesture(
            BOOT_SPLASH_ACTIVE.load(Ordering::Acquire),
            SCREEN_FADED.load(Ordering::Acquire),
            board_input::alert_active(),
        );
        if disposition == Gesture::Wake {
            hold(c);
        }
        disposition
    });
    if disposition == Gesture::Wake {
        CHANGED.signal(());
        UI_WAKE.signal(());
    }
    disposition
}

pub(crate) fn finish_gesture(input: Item, disposition: Gesture) {
    if disposition == Gesture::CancelAlert {
        board_input::cancel_alert();
        return;
    }
    if board_input::alert_active() {
        // The alert arrived after this gesture began. Consume it too.
        board_input::cancel_alert();
        return;
    }
    match disposition {
        Gesture::CancelAlert => unreachable!(),
        Gesture::Navigate => send(input),
        Gesture::Splash => {
            UI_SPLASH_DISMISS.signal(());
            UI_WAKE.signal(());
        }
        Gesture::Wake | Gesture::Ignore => {}
    }
}

/// Queues `input` without a gesture: the release of a press or modifier
/// whose going down reached the interface.
pub(crate) fn send(input: Item) {
    if NAVIGATION.try_send(input).is_err() {
        INPUT_OVERFLOW.store(true, Ordering::Release);
    }
}

/// Whether gestures are queued that the dark handoff has not seen.
pub(crate) fn navigation_pending() -> bool {
    !NAVIGATION.is_empty()
}

#[embassy_executor::task]
pub async fn navigation_task() {
    loop {
        let input = NAVIGATION.receive().await;
        NAVIGATION_PENDING.store(true, Ordering::Release);
        if board_input::alert_active() {
            continue;
        }
        loop {
            DISPLAY_READY.reset();
            if control(|c| c.policy.display_ready || c.policy.mode == Mode::Shutdown) {
                break;
            }
            DISPLAY_READY.wait().await;
        }
        if control(|c| c.policy.mode == Mode::Shutdown) {
            return;
        }
        if INPUT_OVERFLOW.swap(false, Ordering::AcqRel) {
            NAVIGATION.clear();
            clear_forwarded();
            debug_log(format_args!(
                "input: overflow; pending navigation discarded"
            ));
            continue;
        }
        if board_input::alert_active() || !NAVIGATION_PENDING.swap(false, Ordering::AcqRel) {
            continue;
        }
        UI_WAKE.signal(());
        // Do not suspend with an already-dequeued input across an alert edge.
        if !forward(input) {
            INPUT_OVERFLOW.store(true, Ordering::Release);
        }
    }
}

/// One of the board's capture tasks has let go of its pins.
pub(crate) fn stopped() {
    STOPPED.fetch_add(1, Ordering::AcqRel);
    STOP_PROGRESS.signal(());
}

/// The coordinator has given up capture for shutdown, at `epoch`.
pub(crate) fn coordinator_stopped(epoch: u32) {
    captured(epoch);
    STOP_PROGRESS.signal(());
}

pub async fn shutdown() {
    let epoch = control(|c| {
        c.policy.shutdown();
        hold(c);
        c.policy.epoch
    });
    CHANGED.signal(());
    DISPLAY_READY.signal(());
    board_input::stop();
    loop {
        STOP_PROGRESS.reset();
        if STOPPED.load(Ordering::Acquire) == board_input::STOPPERS
            && CAPTURE_EPOCH.load(Ordering::Acquire) == epoch
        {
            break;
        }
        STOP_PROGRESS.wait().await;
    }
}

/// The panel has lit or gone dark. Lit, the CPU runs at full speed, so
/// that drawing is quick; dark, it returns to [`CPU_CLOCK`]. Either way
/// the battery estimator hears of it, where the board has one.
fn display_lit(lit: bool) {
    set_cpu_clock(if lit { CpuClock::max() } else { CPU_CLOCK });
    board_input::lit(lit);
    #[cfg(feature = "battery-adc-rail")]
    crate::note_screen_lit(lit);
}

/// Moves the CPU to `clock` while running. The PLL stays at 480 MHz, so APB
/// and every peripheral on it keep their timing; the clock tree raises the
/// core voltage before a faster clock and lowers it after a slower one.
fn set_cpu_clock(clock: CpuClock) {
    use esp_hal::clock::ll::{
        ClockTree, CpuClkConfig, CpuPllDivOutConfig, configure_cpu_clk, configure_cpu_pll_div_out,
    };
    let divided = match clock {
        CpuClock::_80MHz => CpuPllDivOutConfig::_80,
        CpuClock::_160MHz => CpuPllDivOutConfig::_160,
        _ => CpuPllDivOutConfig::_240,
    };
    let changed = ClockTree::with(|clocks| {
        let changed = clocks.cpu_pll_div_out() != Some(divided);
        if changed {
            configure_cpu_pll_div_out(clocks, divided);
            configure_cpu_clk(clocks, CpuClkConfig::Pll);
        }
        changed
    });
    if changed {
        debug_log(format_args!(
            "input: CPU {} MHz",
            esp_hal::clock::cpu_clock().as_mhz()
        ));
    }
}

/// Fed by the Pager's fuel gauge, the only current reading there is.
#[cfg(feature = "board-tlora-pager")]
pub fn locks_active() -> bool {
    #[cfg(feature = "input-qualification")]
    {
        WakeLock::is_active()
    }
    #[cfg(not(feature = "input-qualification"))]
    {
        false
    }
}

#[cfg(feature = "board-tlora-pager")]
pub fn power_sample(current: Option<i32>, usb: bool, locks: bool) {
    #[cfg(feature = "input-qualification")]
    qualification::sample(current, usb, locks);
    #[cfg(not(feature = "input-qualification"))]
    let _ = (current, usb, locks);
}

pub fn power_report() -> Option<heapless::String<256>> {
    #[cfg(feature = "input-qualification")]
    {
        qualification::report()
    }
    #[cfg(not(feature = "input-qualification"))]
    {
        None
    }
}

pub fn power_report_sent() {
    #[cfg(feature = "input-qualification")]
    qualification::sent();
}

#[cfg(feature = "input-qualification")]
mod qualification {
    use super::*;
    use umsh_ux_display_tracker::input_power::PowerWindow;

    struct Monitor {
        epoch: u32,
        dark_since: Option<u64>,
        window: PowerWindow,
        pending: bool,
    }
    static MONITOR: critical_section::Mutex<RefCell<Monitor>> =
        critical_section::Mutex::new(RefCell::new(Monitor {
            epoch: 0,
            dark_since: None,
            window: PowerWindow::new(),
            pending: false,
        }));

    pub fn sample(current: Option<i32>, usb: bool, locks: bool) {
        let (dark, epoch) = control(|c| {
            (
                c.policy.mode == Mode::Dark && c.policy.armed,
                c.policy.epoch,
            )
        });
        let now = Instant::now().as_millis();
        critical_section::with(|cs| {
            let mut m = MONITOR.borrow_ref_mut(cs);
            if usb {
                m.pending |= m.window.count != 0;
                m.dark_since = None;
                return;
            }
            if m.pending || m.window.complete() {
                return;
            }
            if !dark {
                m.dark_since = None;
                return;
            }
            if m.dark_since.is_none() || m.epoch != epoch {
                m.epoch = epoch;
                m.dark_since = Some(now);
                m.window = PowerWindow::new();
            }
            // Avoid the display-off transient and the fuel gauge's old average.
            if now.saturating_sub(m.dark_since.unwrap()) < 30_000 {
                return;
            }
            if let Some(current) = current {
                m.window.sample(now, current, !locks);
            }
        });
    }

    pub fn report() -> Option<heapless::String<256>> {
        critical_section::with(|cs| {
            let m = MONITOR.borrow_ref(cs);
            if !m.pending {
                return None;
            }
            let w = &m.window;
            let mut line = heapless::String::new();
            write!(line, "pager input-power: n={} span_ms={} mean_ma={} min_ma={} max_ma={} unlocked={} complete={} (eligibility, not sleep residency)\r\n",
                w.count, w.span_ms(), w.mean_ma(), w.min_ma, w.max_ma, w.unlocked, w.complete()).ok()?;
            Some(line)
        })
    }

    pub fn sent() {
        critical_section::with(|cs| {
            let mut m = MONITOR.borrow_ref_mut(cs);
            m.pending = false;
            m.window = PowerWindow::new();
            m.dark_since = None;
        });
    }
}
