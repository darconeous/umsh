//! The Pager's controls: the wheel, its press, the lock button, and the
//! keyboard. ISR capture while interactive; wake-enabled level waits while
//! dark. What a gesture means is the input gate's.
use super::*;
use crate::input_gate::{
    self, CHANGED, control, finish_gesture, hold, note_activity, send, start_gesture, wake_display,
};
use core::{future::Future, pin::pin, task::Poll};
use esp_hal::rtc_cntl::WakeLock;
use umsh_ux_display_tracker::input_power::{Gesture, Mode};
use umsh_ux_display_tracker::menu::KeyModifier;
use umsh_ux_tracker::debounce::PressLatch;

/// The Pager's controls produce the tracker menus' inputs, which the
/// communicator takes through [`to_input`].
pub(crate) type Item = UiInput;

static KEYBOARD_RETRY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOP_PRESS: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOP_BOOT: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static STOP_KEYBOARD: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// The capture tasks [`stop`] ends: the wheel press, the lock button, and
/// the keyboard.
pub(crate) const STOPPERS: u32 = 3;

pub(crate) fn stop() {
    STOP_PRESS.signal(());
    STOP_BOOT.signal(());
    STOP_KEYBOARD.signal(());
}

/// A turn spanning an alert boundary is consumed in its entirety.
pub(crate) fn resync() {
    critical_section::with(|cs| {
        if let Some(e) = ENCODER.borrow_ref_mut(cs).as_mut() {
            e.ab = e.levels();
            e.decoder = Quadrature::new(e.ab);
        }
    });
}

/// The panel lit: a keyboard that failed is tried again at once.
pub(crate) fn shown() {
    KEYBOARD_RETRY.signal(());
}

pub(crate) fn lit(lit: bool) {
    super::battery_lit(lit);
}

pub(crate) fn alert_active() -> bool {
    super::alert::active()
}

pub(crate) fn cancel_alert() {
    super::alert::cancel();
}

#[cfg(feature = "communicator")]
pub(crate) fn to_input(input: UiInput) -> umsh_ux_communicator::input::Input {
    use umsh_ux_communicator::input::Input;
    use umsh_ux_communicator::keyboard::Modifier;
    match input {
        UiInput::Forward => Input::Turn(1),
        UiInput::Backward => Input::Turn(-1),
        UiInput::Select => Input::Press,
        UiInput::Released => Input::Release,
        UiInput::Back => Input::Backspace,
        UiInput::Enter => Input::Enter,
        UiInput::Key { plain, alt } => Input::Key { plain, alt },
        UiInput::Space => Input::Space,
        UiInput::Modifier { modifier, down } => Input::Modifier {
            modifier: match modifier {
                KeyModifier::Shift => Modifier::Shift,
                KeyModifier::Alt => Modifier::Alt,
            },
            down,
        },
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
        note_activity();
        e.ab = e.levels();
        let input = match e.decoder.transition(e.ab) {
            1 => UiInput::Backward,
            -1 => UiInput::Forward,
            _ => return,
        };
        if alert_active() {
            return;
        }
        finish_gesture(input, start_gesture());
    });
}

#[embassy_executor::task]
pub async fn coordinator() {
    loop {
        CHANGED.reset();
        let (mode, epoch) = control(|c| (c.policy.mode, c.policy.epoch));
        if mode == Mode::Interactive {
            input_gate::captured(epoch);
            CHANGED.wait().await;
            continue;
        }
        // The interactive guard is still held during the ownership transfer.
        let (mut encoder, raced) = critical_section::with(|cs| {
            let mut e = ENCODER.borrow_ref_mut(cs).take().unwrap();
            let raced = e.a.is_interrupt_set()
                || e.b.is_interrupt_set()
                || e.levels() != e.ab
                || input_gate::navigation_pending()
                || control(|c| c.policy.activity_since_dark());
            e.a.unlisten();
            e.b.unlisten();
            (e, raced)
        });
        if mode == Mode::Shutdown {
            restore(encoder, false);
            input_gate::coordinator_stopped(epoch);
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

#[embassy_executor::task(pool_size = 2)]
pub async fn button_task(mut pin: Input<'static>, boot: bool) {
    let stop = if boot { &STOP_BOOT } else { &STOP_PRESS };
    select(run_button(&mut pin, boot), stop.wait()).await;
    drop(pin);
    input_gate::stopped();
}

async fn run_button(pin: &mut Input<'static>, boot: bool) {
    let mut debounce = Debounce::new(false);
    let mut press_cycle = PressLatch::default();
    let mut shutdown_at = None;
    let mut silenced = false;
    // The press going down reached the interface, so its coming up does
    // too, and only its: a release must never wake the panel.
    let mut delivered = false;
    let mut debounce_guard = None;
    loop {
        let now = Instant::now();
        let raw = pin.is_low();
        if !boot && raw != debounce.observed() {
            note_activity();
        }
        if press_cycle.observe(raw, now.as_millis()) && !boot {
            let gate = start_gesture();
            control(|c| c.policy.begin_press(gate));
        }
        if let Some(pressed) = debounce.sample(raw, now.as_millis()) {
            if boot {
                if pressed {
                    silenced = alert_active();
                    if silenced {
                        cancel_alert();
                    }
                } else if shutdown_at.is_some() && !silenced {
                    input_gate::LOCK.signal(());
                }
                shutdown_at = pressed.then_some(now + Duration::from_secs(4));
            } else if pressed {
                let disposition = control(|c| c.policy.press_disposition());
                delivered = disposition == Gesture::Navigate && !alert_active();
                finish_gesture(UiInput::Select, disposition);
            } else {
                control(|c| c.policy.release_press());
                if core::mem::take(&mut delivered) {
                    send(UiInput::Released);
                }
            }
        }
        if shutdown_at.is_some_and(|at| now >= at) {
            SHUTDOWN_REQUEST.signal(ShutdownCause::Asked);
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
    input_gate::stopped();
}

/// The modifiers whose going down reached the interface, so that their
/// going up does too, and only theirs: a release must never wake the
/// panel, and a press that only woke it was never seen.
#[derive(Default)]
struct Modifiers {
    delivered: [bool; 2],
}

impl Modifiers {
    fn event(&mut self, modifier: Modifier, down: bool) {
        let index = match modifier {
            Modifier::Shift => 0,
            Modifier::Alt => 1,
        };
        let input = UiInput::Modifier {
            modifier: match modifier {
                Modifier::Shift => KeyModifier::Shift,
                Modifier::Alt => KeyModifier::Alt,
            },
            down,
        };
        if down {
            let gesture = start_gesture();
            self.delivered[index] = gesture == Gesture::Navigate && !alert_active();
            finish_gesture(input, gesture);
        } else if core::mem::take(&mut self.delivered[index]) {
            send(input);
        }
    }
}

/// Why a pass over the keyboard controller failed.
#[derive(Debug)]
enum KeyboardFault {
    Bus,
    /// Its interrupt stayed asserted with nothing to read.
    Stuck,
    Timeout,
}

/// The wait before the controller is tried again after a failure: it
/// doubles while failures repeat, and a display wake cuts it short.
const KEYBOARD_RETRY_FIRST: Duration = Duration::from_millis(250);
const KEYBOARD_RETRY_MOST: Duration = Duration::from_secs(8);

async fn run_keyboard(irq: &mut Input<'static>, bus: &'static board::I2cBus) {
    let mut keyboard = Keyboard::new(I2cDevice::new(bus));
    let mut modifiers = Modifiers::default();
    let mut initialized = false;
    let mut retry = KEYBOARD_RETRY_FIRST;
    loop {
        // Idle waits have no timer. Only controller transactions and
        // asserted-IRQ drains are bounded by the acquisition timeout.
        if initialized && irq.is_high() {
            irq.wait_for(Event::LowLevel).await;
        }
        let result = with_timeout(Duration::from_millis(500), async {
            if !initialized {
                keyboard.init().await.map_err(|_| KeyboardFault::Bus)?;
                initialized = true;
            }
            if irq.is_high() {
                return Ok(());
            }
            let mut read = false;
            for _ in 0..16 {
                let event = keyboard.next().await.map_err(|_| KeyboardFault::Bus)?;
                read |= event.is_some();
                match event {
                    Some(KeyEvent::BackPress) => finish_gesture(UiInput::Back, start_gesture()),
                    Some(KeyEvent::Enter) => finish_gesture(UiInput::Enter, start_gesture()),
                    Some(KeyEvent::Key { plain, alt }) => {
                        finish_gesture(UiInput::Key { plain, alt }, start_gesture())
                    }
                    Some(KeyEvent::Space) => finish_gesture(UiInput::Space, start_gesture()),
                    Some(KeyEvent::Modifier { modifier, down }) => modifiers.event(modifier, down),
                    Some(KeyEvent::Overflow) => debug_log(format_args!(
                        "pager: keyboard FIFO overflow; keyboard gestures discarded"
                    )),
                    Some(_) => {}
                    None if irq.is_high() => return Ok(()),
                    None => {}
                }
            }
            // More keys than one pass takes are taken by the next.
            if read {
                Ok(())
            } else {
                Err(KeyboardFault::Stuck)
            }
        })
        .await
        .unwrap_or(Err(KeyboardFault::Timeout));
        match result {
            Ok(()) => retry = KEYBOARD_RETRY_FIRST,
            Err(fault) => {
                // Set up afresh on the next attempt, which drains whatever
                // the controller holds.
                initialized = false;
                debug_log(format_args!(
                    "pager: keyboard {fault:?}; retry in {} ms",
                    retry.as_millis()
                ));
                KEYBOARD_RETRY.reset();
                select(Timer::after(retry), KEYBOARD_RETRY.wait()).await;
                retry = (retry * 2).min(KEYBOARD_RETRY_MOST);
            }
        }
    }
}
