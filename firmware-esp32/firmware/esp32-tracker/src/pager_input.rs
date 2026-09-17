//! ISR capture while interactive; wake-enabled level waits while dark.
use super::*;
use core::{future::Future, pin::pin, task::Poll};
use esp_hal::rtc_cntl::WakeLock;
use umsh_pager_peripherals::input::PressLatch;
use umsh_pager_peripherals::input_power::{Gesture, InputPower, Mode};

struct Control {
    policy: InputPower,
    guard: Option<WakeLock>,
}
static CONTROL: critical_section::Mutex<RefCell<Control>> =
    critical_section::Mutex::new(RefCell::new(Control {
        policy: InputPower::new(),
        guard: None,
    }));
static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static CAPTURE_READY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static CAPTURE_EPOCH: AtomicU32 = AtomicU32::new(0);
static DISPLAY_READY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static KEYBOARD_RETRY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOP_PRESS: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOP_BOOT: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOP_KEYBOARD: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOPPED: AtomicU32 = AtomicU32::new(0);
static STOP_PROGRESS: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static NAVIGATION: Channel<CriticalSectionRawMutex, UiInput, 64> = Channel::new();
static INPUT_OVERFLOW: AtomicBool = AtomicBool::new(false);

fn control<R>(f: impl FnOnce(&mut Control) -> R) -> R {
    critical_section::with(|cs| f(&mut CONTROL.borrow_ref_mut(cs)))
}

fn hold(c: &mut Control) {
    if c.guard.is_none() {
        c.guard = Some(WakeLock::new());
    }
}

pub fn activity() -> u32 {
    control(|c| c.policy.activity())
}

pub fn dark(before_display_off: u32) {
    let accepted = control(|c| c.policy.dark(before_display_off));
    if accepted {
        CHANGED.signal(());
    } else {
        wake_display();
    }
}

fn wake_display() {
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

pub fn shown(epoch: u32) {
    // Publish before allowing queued post-wake gestures through the display.
    SCREEN_FADED.store(false, Ordering::Release);
    control(|c| c.policy.shown(epoch));
    DISPLAY_READY.signal(());
    KEYBOARD_RETRY.signal(());
}

fn start_gesture() -> Gesture {
    let disposition = control(|c| {
        let disposition = c.policy.gesture(
            BOOT_SPLASH_ACTIVE.load(Ordering::Acquire),
            SCREEN_FADED.load(Ordering::Acquire),
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

fn finish_gesture(input: UiInput, disposition: Gesture) {
    match disposition {
        Gesture::Navigate => {
            if NAVIGATION.try_send(input).is_err() {
                INPUT_OVERFLOW.store(true, Ordering::Release);
            }
        }
        Gesture::Splash => {
            UI_SPLASH_DISMISS.signal(());
            UI_WAKE.signal(());
        }
        Gesture::Wake | Gesture::Ignore => {}
    }
}

struct Encoder {
    a: Input<'static>,
    b: Input<'static>,
    decoder: Quadrature,
    ab: u8,
}
impl Encoder {
    fn levels(&self) -> u8 {
        (u8::from(self.a.is_high()) << 1) | u8::from(self.b.is_high())
    }
}
static ENCODER: critical_section::Mutex<RefCell<Option<Encoder>>> =
    critical_section::Mutex::new(RefCell::new(None));

pub fn init_encoder(
    io: peripherals::IO_MUX<'static>,
    a: peripherals::GPIO40<'static>,
    b: peripherals::GPIO41<'static>,
) {
    control(hold);
    let mut io = Io::new(io);
    io.set_interrupt_handler(encoder_interrupt);
    let config = InputConfig::default().with_pull(Pull::Up);
    let a = Input::new(a, config);
    let b = Input::new(b, config);
    let ab = (u8::from(a.is_high()) << 1) | u8::from(b.is_high());
    restore(
        Encoder {
            a,
            b,
            decoder: Quadrature::new(ab),
            ab,
        },
        true,
    );
}

fn restore(mut encoder: Encoder, listen: bool) {
    critical_section::with(|cs| {
        // Mode transitions may have missed edges. Never infer their direction.
        encoder.ab = encoder.levels();
        encoder.decoder = Quadrature::new(encoder.ab);
        if listen {
            encoder.a.listen(Event::AnyEdge);
            encoder.b.listen(Event::AnyEdge);
        }
        ENCODER.borrow_ref_mut(cs).replace(encoder);
    });
}

#[esp_hal::handler]
#[ram]
fn encoder_interrupt() {
    critical_section::with(|cs| {
        let mut slot = ENCODER.borrow_ref_mut(cs);
        let Some(e) = slot.as_mut() else { return };
        if !(e.a.is_interrupt_set() || e.b.is_interrupt_set()) {
            return;
        }
        e.a.clear_interrupt();
        e.b.clear_interrupt();
        CONTROL.borrow_ref_mut(cs).policy.note_activity();
        e.ab = e.levels();
        let input = match e.decoder.transition(e.ab) {
            1 => UiInput::Backward,
            -1 => UiInput::Forward,
            _ => return,
        };
        finish_gesture(input, start_gesture());
    });
}

#[embassy_executor::task]
pub async fn coordinator() {
    loop {
        CHANGED.reset();
        let (mode, epoch) = control(|c| (c.policy.mode, c.policy.epoch));
        if mode == Mode::Interactive {
            CAPTURE_EPOCH.store(epoch, Ordering::Release);
            CAPTURE_READY.signal(());
            CHANGED.wait().await;
            continue;
        }
        // The interactive guard is still held during the ownership transfer.
        let (mut encoder, raced) = critical_section::with(|cs| {
            let mut e = ENCODER.borrow_ref_mut(cs).take().unwrap();
            let raced = e.a.is_interrupt_set()
                || e.b.is_interrupt_set()
                || e.levels() != e.ab
                || !NAVIGATION.is_empty()
                || CONTROL.borrow_ref_mut(cs).policy.activity_since_dark();
            e.a.unlisten();
            e.b.unlisten();
            (e, raced)
        });
        if mode == Mode::Shutdown {
            restore(encoder, false);
            CAPTURE_EPOCH.store(epoch, Ordering::Release);
            CAPTURE_READY.signal(());
            STOP_PROGRESS.signal(());
            return;
        }
        if raced {
            wake_display();
            restore(encoder, true);
            continue;
        }
        // Use the phase checked under the ownership-transfer critical section.
        // A contact changing afterward must satisfy the opposite-level wait,
        // rather than becoming a new baseline that silently swallows the wake.
        let ab = encoder.ab;
        let event = |high| {
            if high {
                Event::LowLevel
            } else {
                Event::HighLevel
            }
        };
        let outcome = {
            let mut waits = pin!(select(
                select(
                    encoder.a.wait_for(event(ab & 2 != 0)),
                    encoder.b.wait_for(event(ab & 1 != 0)),
                ),
                CHANGED.wait(),
            ));
            core::future::poll_fn(|cx| match waits.as_mut().poll(cx) {
                Poll::Pending => {
                    // Both level waits have been polled. A control change
                    // racing this check retains its guard and invalidates epoch.
                    let raced = control(|c| {
                        if c.policy.arm(epoch) {
                            c.guard.take();
                        }
                        c.policy.mode == Mode::Dark && c.policy.activity_since_dark()
                    });
                    if raced {
                        wake_display();
                    }
                    Poll::Pending
                }
                Poll::Ready(outcome) => {
                    // Acquire before dropping/canceling either GPIO future.
                    control(hold);
                    Poll::Ready(outcome)
                }
            })
            .await
        };
        match outcome {
            Either::First(_) => wake_display(),
            Either::Second(()) => {}
        }
        restore(encoder, control(|c| c.policy.mode != Mode::Shutdown));
    }
}

#[embassy_executor::task]
pub async fn navigation_task() {
    loop {
        let input = NAVIGATION.receive().await;
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
            UI_INPUT_CH.clear();
            debug_log(format_args!(
                "pager: input overflow; pending navigation discarded"
            ));
            continue;
        }
        UI_WAKE.signal(());
        UI_INPUT_CH.send(input).await;
    }
}

#[embassy_executor::task(pool_size = 2)]
pub async fn button_task(mut pin: Input<'static>, boot: bool) {
    let stop = if boot { &STOP_BOOT } else { &STOP_PRESS };
    select(run_button(&mut pin, boot), stop.wait()).await;
    drop(pin);
    STOPPED.fetch_add(1, Ordering::AcqRel);
    STOP_PROGRESS.signal(());
}

async fn run_button(pin: &mut Input<'static>, boot: bool) {
    let mut debounce = Debounce::new(false);
    let mut gate = Gesture::Ignore;
    let mut press_cycle = PressLatch::default();
    let mut shutdown_at = None;
    let mut debounce_guard = None;
    loop {
        let now = Instant::now();
        let raw = pin.is_low();
        if !boot && raw != debounce.observed() {
            control(|c| c.policy.note_activity());
        }
        if press_cycle.observe(raw, now.as_millis()) && !boot {
            gate = start_gesture();
        }
        if let Some(pressed) = debounce.sample(raw, now.as_millis()) {
            if boot {
                shutdown_at = pressed.then_some(now + Duration::from_secs(4));
            } else if pressed {
                finish_gesture(UiInput::Select, gate);
            }
        }
        if shutdown_at.is_some_and(|at| now >= at) {
            SHUTDOWN_REQUEST.signal(());
            shutdown_at = None;
        }
        let debouncing = match (debounce.deadline(), press_cycle.deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
        .map(Instant::from_millis);
        if debouncing.is_some() {
            debounce_guard.get_or_insert_with(WakeLock::new);
        } else {
            debounce_guard.take();
        }
        let deadline = match (debouncing, shutdown_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
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
pub async fn keyboard_task(mut irq: Input<'static>, bus: &'static board::I2cBus) {
    select(run_keyboard(&mut irq, bus), STOP_KEYBOARD.wait()).await;
    drop(irq);
    STOPPED.fetch_add(1, Ordering::AcqRel);
    STOP_PROGRESS.signal(());
}

async fn run_keyboard(irq: &mut Input<'static>, bus: &'static board::I2cBus) {
    let mut keyboard = Keyboard::new(I2cDevice::new(bus));
    loop {
        let mut attempts = 0;
        let mut initialized = false;
        while attempts < 3 {
            // Idle waits have no timer. Only controller transactions and
            // asserted-IRQ drains are bounded by the acquisition timeout.
            if initialized && irq.is_high() {
                irq.wait_for(Event::LowLevel).await;
            }
            let result = with_timeout(Duration::from_millis(500), async {
                if !initialized {
                    keyboard.init().await.map_err(|_| ())?;
                    initialized = true;
                }
                if irq.is_high() {
                    return Ok(());
                }
                for _ in 0..16 {
                    match keyboard.next().await.map_err(|_| ())? {
                        Some(KeyEvent::BackPress) => finish_gesture(UiInput::Back, start_gesture()),
                        Some(KeyEvent::Overflow) => debug_log(format_args!(
                            "pager: keyboard FIFO overflow; keyboard gestures discarded"
                        )),
                        Some(_) => {}
                        None if irq.is_high() => return Ok(()),
                        None => {}
                    }
                }
                Err(())
            })
            .await;
            match result {
                Ok(Ok(())) => attempts = 0,
                _ => {
                    attempts += 1;
                    initialized = false;
                    if attempts < 3 {
                        Timer::after_millis(250).await;
                    }
                }
            }
        }
        // Only a wake after entering quarantine may restart recovery.
        KEYBOARD_RETRY.reset();
        debug_log(format_args!(
            "pager: keyboard IRQ/bus failed; retry on next display wake"
        ));
        KEYBOARD_RETRY.wait().await;
    }
}

pub async fn shutdown() {
    let epoch = control(|c| {
        c.policy.shutdown();
        hold(c);
        c.policy.epoch
    });
    CHANGED.signal(());
    DISPLAY_READY.signal(());
    STOP_PRESS.signal(());
    STOP_BOOT.signal(());
    STOP_KEYBOARD.signal(());
    loop {
        STOP_PROGRESS.reset();
        if STOPPED.load(Ordering::Acquire) == 3 && CAPTURE_EPOCH.load(Ordering::Acquire) == epoch {
            break;
        }
        STOP_PROGRESS.wait().await;
    }
}

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
    use umsh_pager_peripherals::input_power::PowerWindow;

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
