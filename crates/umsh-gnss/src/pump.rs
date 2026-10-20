//! The receiver orchestration loop.
//!
//! This is the part that would otherwise be copied into every firmware:
//! power the receiver when it is wanted, read its UART, hand each
//! completed fix upward, and put it back to sleep when it is not. It is
//! generic over the three things that actually differ between boards—
//! the byte stream, the power sequencing, and what is done with a fix—
//! so a new board contributes those and nothing else.
//!
//! `#[embassy_executor::task]` functions cannot be generic, so a firmware
//! still writes a task shim; the shim is a handful of lines that
//! constructs a UART and a control type and calls [`run`]. The loop
//! itself lives here, once, for both cargo workspaces.
//!
//! # Off means off
//!
//! While disabled the receiver is powered down, not merely ignored. On
//! most of these boards it is the largest continuous load there is, so a
//! loop that kept reading and discarded the sentences would save nothing
//! that matters.
//!
//! The exception is [`rtc_read_once`], for boards whose only surviving
//! clock is the one inside the receiver. That reads the *time* out of a
//! receiver that is otherwise off, discards everything positional it sees
//! on the way, and returns the receiver to its off state. It is a clock
//! operation, and is gated on whether the receiver's time is trusted
//! rather than on whether positioning is enabled.

use core::cell::Cell;

use embassy_futures::select::{Either, select};
use embedded_hal_async::delay::DelayNs;
use embedded_io_async::Read;

use crate::driver::{Driver, Fix};

/// The exact `embedded-io-async` [`run`] is generic over.
///
/// Re-exported because a consumer that wraps its UART—to count bytes
/// during bringup, to inject a fault—has to implement *this* crate's
/// `Read`, and a workspace can easily hold two versions of it. Without
/// this the wrapper compiles and then fails the bound with an error that
/// points at the impl and says it does not exist.
pub use embedded_io_async;

/// The exact `embedded-hal-async` delay trait, re-exported for the same
/// reason.
pub use embedded_hal_async;

/// How long [`rtc_read_once`] waits for a dated sentence before giving
/// up, in milliseconds.
///
/// A receiver whose backup domain stayed powered emits a dated `RMC`
/// within a second or two of its main domain coming up—it is reading
/// its own clock, not searching for satellites. Ten seconds is generous
/// enough to cover a slow start and short enough that a receiver which
/// has lost its clock does not hold up a boot.
pub const RTC_READ_TIMEOUT_MS: u32 = 10_000;

/// How long the pump lets the board sleep through the receiver's output
/// before staying awake to hear a cycle, in milliseconds.
///
/// A board that is awake for other reasons hears every cycle and never
/// holds itself awake; one that sleeps hears nothing, and this bounds how
/// stale its fix becomes.
pub const QUIET_MS: u32 = 5 * 60 * 1000;

/// How long the pump stays awake waiting for a cycle once it has gone
/// [`QUIET_MS`] without one, in milliseconds. A receiver that is tracking
/// completes a cycle every second; one that has lost power or its mind
/// does not, and the board goes back to sleep rather than wait on it.
pub const LISTEN_MS: u32 = 10_000;

/// Pause after a read that returned nothing, in milliseconds.
const IDLE_BACKOFF_MS: u32 = 100;

/// Board-specific power sequencing for one receiver.
///
/// Implementations live in each BSP, because this is the only part that
/// genuinely differs: an enable pin here, a standby pin there, a reset
/// pulse on one board and not another.
// Single-executor embedded consumers; `Send` futures are irrelevant here,
// as with the embassy ecosystem's own async traits.
#[allow(async_fn_in_trait)]
pub trait Power {
    /// Bring the receiver up and leave it emitting sentences.
    ///
    /// Idempotent: the pump calls it whenever it believes the receiver
    /// should be running, including after an error.
    async fn power_on(&mut self);

    /// Put the receiver in the lowest power state this board can reach.
    ///
    /// On a board whose receiver holds the only surviving real-time
    /// clock, that state keeps the backup domain alive—which is not an
    /// exception to "off means off" so much as a statement that the
    /// domain in question is a clock rather than a receiver.
    async fn power_off(&mut self);
}

/// What the firmware does with what the receiver says.
///
/// Deliberately not "store this in a global": a sink decides what a fix
/// means. The runtime's implementation folds it into the ULCP property
/// surface, the wall clock, and the advertised identity; a test's counts
/// what it was given.
#[allow(async_fn_in_trait)]
pub trait Sink {
    /// One completed fix cycle.
    ///
    /// Called for every cycle, including the empty ones a searching
    /// receiver produces—"still nothing" is a fact worth having, and a
    /// sink that only heard about successes could not tell a receiver
    /// that is searching from one that is not running.
    async fn fix(&mut self, fix: &Fix);
}

/// A way to keep the board awake while the pump needs to hear the
/// receiver.
///
/// A board whose UART loses data while it sleeps lets the pump sleep
/// through the receiver's output and keeps itself awake only when the fix
/// has gone stale (see [`QUIET_MS`]). A board whose UART does not, or
/// that never sleeps, passes `()`.
pub trait Awake {
    /// Keep the board awake until [`release`](Self::release).
    /// Idempotent.
    fn hold(&self);

    /// Let the board sleep again. Idempotent.
    fn release(&self);
}

impl Awake for () {
    fn hold(&self) {}
    fn release(&self) {}
}

/// Whether the receiver should be running, and a way to wait for that to
/// change.
///
/// Separate from [`Power`] because the two have different owners: the
/// answer comes from `PROP_GNSS_ENABLED` by way of the device-domain
/// mirror, while the sequencing belongs to the board.
#[allow(async_fn_in_trait)]
pub trait Enable {
    /// Whether the receiver is wanted right now.
    fn enabled(&self) -> bool;

    /// Complete when the answer changes.
    ///
    /// **Must be cancellation-safe.** The pump drops and re-creates this
    /// future every time a byte arrives, so an implementation that loses
    /// a change it was cancelled on would leave the receiver powered
    /// after it was switched off. An `embassy_sync::watch::Watch`
    /// receiver behaves correctly; a bare `Signal` does not.
    async fn changed(&mut self);
}

/// Drive one receiver forever.
///
/// Powers the receiver whenever `enable` says it is wanted, parses
/// everything it emits, and hands each completed cycle to `sink`. Never
/// returns.
///
/// The board may sleep through the receiver's output; `awake` is held
/// only when [`QUIET_MS`] pass with no completed cycle, and released at
/// the next cycle or after [`LISTEN_MS`]. A read error is a stretch of
/// garbled or lost bytes—a byte cut short by sleep, an overrun while the
/// executor was busy—and costs only the cycle it fell in.
pub async fn run<R, P, E, S, D, A>(
    mut uart: R,
    mut power: P,
    mut enable: E,
    mut sink: S,
    delay: D,
    awake: A,
) -> !
where
    R: Read,
    P: Power,
    E: Enable,
    S: Sink,
    D: DelayNs + Clone,
    A: Awake,
{
    let mut driver = Driver::new();
    let mut buf = [0u8; 64];
    let mut idle = delay.clone();

    // Park the receiver before anything else. The pump owns its power
    // state from here on, and whatever state it was left in belongs to
    // whoever ran before—a bootloader, a previous image, or a reset
    // that did not reach the pin.
    power.power_off().await;

    loop {
        while !enable.enabled() {
            enable.changed().await;
        }

        power.power_on().await;
        // Bytes from before the power cycle describe where the device
        // was, not where it is.
        driver.reset();

        // Whether a cycle completed since the watchdog last looked.
        let heard = Cell::new(false);
        let mut watchdog_delay = delay.clone();
        let watchdog = async {
            loop {
                watchdog_delay.delay_ms(QUIET_MS).await;
                if heard.replace(false) {
                    continue;
                }
                awake.hold();
                watchdog_delay.delay_ms(LISTEN_MS).await;
                awake.release();
            }
        };
        let reading = async {
            loop {
                match select(uart.read(&mut buf), enable.changed()).await {
                    Either::First(Ok(0)) => {
                        // A closed stream is not something to spin on.
                        idle.delay_ms(IDLE_BACKOFF_MS).await;
                    }
                    Either::First(Ok(len)) => {
                        for &byte in &buf[..len] {
                            if let Some(fix) = driver.push(byte) {
                                heard.set(true);
                                awake.release();
                                sink.fix(&fix).await;
                            }
                        }
                    }
                    // Drop the cycle the error fell in and pick up at the
                    // next one.
                    Either::First(Err(_)) => driver.resync(),
                    Either::Second(()) => {
                        if !enable.enabled() {
                            return;
                        }
                    }
                }
            }
        };
        select(reading, watchdog).await;

        awake.release();
        power.power_off().await;
    }
}

/// Power the receiver just long enough to read the time out of it, then
/// return it to its off state.
///
/// For boards where the receiver's own real-time-clock domain is the only
/// clock that survives a power cycle. The domain cannot speak a UART on
/// its own, so reading it mechanically requires bringing the main domain
/// up—but what is being read is a clock, and everything positional seen
/// along the way is discarded.
///
/// Returns the first instant the receiver reports, or `None` if it
/// reports none within [`RTC_READ_TIMEOUT_MS`]—which is what a receiver
/// that lost its backup power looks like.
///
/// The caller decides whether to believe the answer: this is governed by
/// `PROP_GNSS_TIME_TRUST`, not by `PROP_GNSS_ENABLED`.
pub async fn rtc_read_once<R, P, D>(
    mut uart: R,
    power: &mut P,
    mut delay: D,
) -> Option<crate::DateTime>
where
    R: Read,
    P: Power,
    D: DelayNs,
{
    let mut driver = Driver::new();
    let mut buf = [0u8; 64];

    power.power_on().await;
    let found = match select(
        async {
            loop {
                let Ok(len) = uart.read(&mut buf).await else {
                    // Nothing to recover to: this is a bounded one-shot,
                    // and the deadline below ends it either way.
                    core::future::pending::<()>().await;
                    unreachable!()
                };
                for &byte in &buf[..len] {
                    // A cycle's position is nobody's business here; only
                    // the instant leaves this function.
                    if let Some(fix) = driver.push(byte)
                        && let Some(at) = fix.time
                    {
                        return at;
                    }
                }
            }
        },
        delay.delay_ms(RTC_READ_TIMEOUT_MS),
    )
    .await
    {
        Either::First(at) => Some(at),
        Either::Second(()) => None,
    };
    power.power_off().await;
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use core::convert::Infallible;
    use std::rc::Rc;
    use std::vec::Vec;

    /// What the mock receiver did, in order, so a test can assert on the
    /// sequencing rather than only on the outcome.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        On,
        Off,
        Hold,
        Release,
    }

    #[derive(Default)]
    struct Shared {
        events: Vec<Event>,
        fixes: Vec<Fix>,
    }

    #[derive(Clone, Default)]
    struct Log(Rc<RefCell<Shared>>);

    impl Log {
        fn events(&self) -> Vec<Event> {
            self.0.borrow().events.clone()
        }

        fn fixes(&self) -> Vec<Fix> {
            self.0.borrow().fixes.clone()
        }
    }

    struct MockPower(Log);

    impl Power for MockPower {
        async fn power_on(&mut self) {
            self.0.0.borrow_mut().events.push(Event::On);
        }

        async fn power_off(&mut self) {
            self.0.0.borrow_mut().events.push(Event::Off);
        }
    }

    /// A delay that never elapses: the pump's backoffs and the RTC-read
    /// timeout exist to bound real hardware, and a test that let them
    /// fire would be testing the clock rather than the loop.
    #[derive(Clone)]
    struct StalledDelay;

    impl DelayNs for StalledDelay {
        async fn delay_ns(&mut self, _ns: u32) {
            core::future::pending::<()>().await
        }
    }

    /// A delay that elapses immediately, for the one test that wants the
    /// timeout to win.
    #[derive(Clone)]
    struct InstantDelay;

    impl DelayNs for InstantDelay {
        async fn delay_ns(&mut self, _ns: u32) {}
    }

    /// A delay that elapses for its first `n` uses, shared by every
    /// clone, and then never again.
    #[derive(Clone)]
    struct CountedDelay(Rc<core::cell::Cell<usize>>);

    impl CountedDelay {
        fn new(n: usize) -> Self {
            Self(Rc::new(core::cell::Cell::new(n)))
        }
    }

    impl CountedDelay {
        async fn elapse(&self) {
            let left = self.0.get();
            if left == 0 {
                core::future::pending::<()>().await;
            }
            self.0.set(left - 1);
        }
    }

    // `delay_ms` is overridden because its provided form splits a long
    // delay into several `delay_ns` calls, and each is one use here.
    impl DelayNs for CountedDelay {
        async fn delay_ns(&mut self, _ns: u32) {
            self.elapse().await
        }
        async fn delay_ms(&mut self, _ms: u32) {
            self.elapse().await
        }
    }

    /// Records holds and releases that change the state.
    struct MockAwake(Log, core::cell::Cell<bool>);

    impl MockAwake {
        fn new(log: Log) -> Self {
            Self(log, core::cell::Cell::new(false))
        }
    }

    impl Awake for MockAwake {
        fn hold(&self) {
            if !self.1.replace(true) {
                self.0.0.borrow_mut().events.push(Event::Hold);
            }
        }
        fn release(&self) {
            if self.1.replace(false) {
                self.0.0.borrow_mut().events.push(Event::Release);
            }
        }
    }

    /// A port whose first read fails, as a byte cut short by sleep does,
    /// and which then plays `then`.
    struct GarbledUart {
        failed: bool,
        then: MockUart,
    }

    impl embedded_io_async::ErrorType for GarbledUart {
        type Error = embedded_io_async::ErrorKind;
    }

    impl Read for GarbledUart {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if !self.failed {
                self.failed = true;
                return Err(embedded_io_async::ErrorKind::InvalidData);
            }
            Ok(self.then.read(buf).await.unwrap_or(0))
        }
    }

    struct MockSink(Log);

    impl Sink for MockSink {
        async fn fix(&mut self, fix: &Fix) {
            self.0.0.borrow_mut().fixes.push(*fix);
        }
    }

    /// A scripted byte stream that never ends: once the script runs out
    /// it parks forever, which is what an idle UART looks like.
    struct MockUart {
        script: Vec<u8>,
        offset: usize,
        /// Shared, because the pump takes the UART by value and a test
        /// still has to see what was sent to it.
        written: Rc<RefCell<Vec<u8>>>,
    }

    impl MockUart {
        fn new(text: &str) -> Self {
            Self {
                script: text.bytes().collect(),
                offset: 0,
                written: Rc::new(RefCell::new(Vec::new())),
            }
        }

        /// A handle on everything written to this port.
        fn written(&self) -> Rc<RefCell<Vec<u8>>> {
            Rc::clone(&self.written)
        }
    }

    impl embedded_io_async::ErrorType for MockUart {
        type Error = Infallible;
    }

    impl Read for MockUart {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Infallible> {
            if self.offset == self.script.len() {
                core::future::pending::<()>().await;
                unreachable!()
            }
            // One byte a call, so the pump's buffering is exercised
            // rather than short-circuited by a single large read.
            buf[0] = self.script[self.offset];
            self.offset += 1;
            Ok(1)
        }
    }

    /// An enable source that yields a fixed script of states.
    struct MockEnable {
        states: Vec<bool>,
        index: usize,
    }

    impl MockEnable {
        fn new(states: &[bool]) -> Self {
            Self {
                states: states.to_vec(),
                index: 0,
            }
        }
    }

    impl Enable for MockEnable {
        fn enabled(&self) -> bool {
            self.states[self.index.min(self.states.len() - 1)]
        }

        async fn changed(&mut self) {
            if self.index + 1 < self.states.len() {
                self.index += 1;
            } else {
                core::future::pending::<()>().await;
            }
        }
    }

    /// A checksummed NMEA line.
    fn line(body: &str) -> std::string::String {
        let checksum = body.bytes().fold(0u8, |sum, byte| sum ^ byte);
        std::format!("${body}*{checksum:02X}\r\n")
    }

    /// Run a future until it stops making progress, which for a pump that
    /// never returns is the only way to observe it.
    fn poll_until_stalled(future: impl core::future::Future<Output = ()>) {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        const VTABLE: RawWakerVTable =
            RawWakerVTable::new(|data| RawWaker::new(data, &VTABLE), |_| {}, |_| {}, |_| {});
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut context = Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);
        // Bounded: the pump is an infinite loop, so this asks "has it
        // done everything it can with the script it was given".
        for _ in 0..10_000 {
            if let Poll::Ready(()) = future.as_mut().poll(&mut context) {
                return;
            }
        }
    }

    /// A full cycle of sentences: a three-dimensional fix.
    fn fix_cycle() -> std::string::String {
        std::format!(
            "{}{}{}",
            line("GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,"),
            line("GPGSA,A,3,04,05,,09,12,,,24,,,,,2.5,1.3,2.1"),
            line("GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230326,003.1,W"),
        )
    }

    /// The error came before any of the first cycle arrived, but nothing
    /// says what the lost bytes were: the first cycle goes with it, and
    /// the second is reported.
    #[test]
    fn a_read_error_costs_only_its_cycle() {
        let log = Log::default();
        poll_until_stalled(async {
            let _ = run(
                GarbledUart {
                    failed: false,
                    then: MockUart::new(&std::format!("{}{}", fix_cycle(), fix_cycle())),
                },
                MockPower(log.clone()),
                MockEnable::new(&[true]),
                MockSink(log.clone()),
                StalledDelay,
                (),
            )
            .await;
        });
        assert_eq!(
            log.events(),
            [Event::Off, Event::On],
            "the receiver was cycled"
        );
        assert_eq!(log.fixes().len(), 1);
    }

    #[test]
    fn a_quiet_receiver_is_listened_for_and_then_let_go() {
        let log = Log::default();
        poll_until_stalled(async {
            let _ = run(
                MockUart::new(""),
                MockPower(log.clone()),
                MockEnable::new(&[true]),
                MockSink(log.clone()),
                // The quiet period, then the listening window.
                CountedDelay::new(2),
                MockAwake::new(log.clone()),
            )
            .await;
        });
        assert_eq!(
            log.events(),
            [Event::Off, Event::On, Event::Hold, Event::Release]
        );
    }

    #[test]
    fn a_receiver_heard_in_the_quiet_period_keeps_nothing_awake() {
        let log = Log::default();
        poll_until_stalled(async {
            let _ = run(
                MockUart::new(&fix_cycle()),
                MockPower(log.clone()),
                MockEnable::new(&[true]),
                MockSink(log.clone()),
                CountedDelay::new(1),
                MockAwake::new(log.clone()),
            )
            .await;
        });
        assert_eq!(log.events(), [Event::Off, Event::On]);
    }

    #[test]
    fn a_disabled_receiver_is_powered_down_and_never_read() {
        let log = Log::default();
        poll_until_stalled(async {
            let _ = run(
                MockUart::new(&fix_cycle()),
                MockPower(log.clone()),
                MockEnable::new(&[false]),
                MockSink(log.clone()),
                StalledDelay,
                (),
            )
            .await;
        });
        assert_eq!(
            log.events(),
            [Event::Off],
            "a disabled receiver was powered"
        );
        assert!(log.fixes().is_empty(), "a disabled receiver produced a fix");
    }

    #[test]
    fn an_enabled_receiver_is_powered_and_its_fixes_reach_the_sink() {
        let log = Log::default();
        poll_until_stalled(async {
            let _ = run(
                MockUart::new(&fix_cycle()),
                MockPower(log.clone()),
                MockEnable::new(&[true]),
                MockSink(log.clone()),
                StalledDelay,
                (),
            )
            .await;
        });
        assert_eq!(log.events(), [Event::Off, Event::On]);
        let fixes = log.fixes();
        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0].quality, crate::FixQuality::ThreeD);
        assert_eq!(fixes[0].altitude_m, Some(545));
    }

    /// Switching the receiver off must actually power it down, not merely
    /// stop reporting: it is the largest continuous load on the board.
    #[test]
    fn switching_off_powers_the_receiver_down() {
        let log = Log::default();
        poll_until_stalled(async {
            let _ = run(
                MockUart::new(&fix_cycle()),
                MockPower(log.clone()),
                MockEnable::new(&[true, false]),
                MockSink(log.clone()),
                StalledDelay,
                (),
            )
            .await;
        });
        assert_eq!(log.events(), [Event::Off, Event::On, Event::Off]);
    }

    /// Switching back on re-powers the receiver and resumes parsing.
    #[test]
    fn switching_back_on_restarts_the_receiver() {
        let log = Log::default();
        poll_until_stalled(async {
            let _ = run(
                MockUart::new(&fix_cycle()),
                MockPower(log.clone()),
                MockEnable::new(&[false, true]),
                MockSink(log.clone()),
                StalledDelay,
                (),
            )
            .await;
        });
        assert_eq!(log.events(), [Event::Off, Event::On]);
        assert_eq!(log.fixes().len(), 1);
    }

    /// Every cycle reaches the sink, including the empty ones a searching
    /// receiver produces: "still nothing" is how a sink tells searching
    /// from not running.
    #[test]
    fn a_searching_receiver_still_reports_each_cycle() {
        let log = Log::default();
        let script = std::format!(
            "{}{}{}",
            line("GPRMC,,V,,,,,,,,,,N"),
            line("GPRMC,081836.00,V,,,,,,,130926,,"),
            fix_cycle(),
        );
        poll_until_stalled(async {
            let _ = run(
                MockUart::new(&script),
                MockPower(log.clone()),
                MockEnable::new(&[true]),
                MockSink(log.clone()),
                StalledDelay,
                (),
            )
            .await;
        });
        let fixes = log.fixes();
        assert_eq!(fixes.len(), 3);
        assert_eq!(fixes[0].quality, crate::FixQuality::None);
        assert_eq!(fixes[0].time, None);
        // The middle cycle is the one the receiver-RTC design rests on:
        // a time with no fix behind it.
        assert!(fixes[1].time.is_some());
        assert!(!fixes[1].time_from_fix);
        assert_eq!(fixes[2].quality, crate::FixQuality::ThreeD);
        assert!(fixes[2].time_from_fix);
    }

    /// A receiver powered up mid-sentence is the normal cold-start case;
    /// the leading garbage costs at most the sentence it landed in.
    #[test]
    fn a_torn_first_sentence_costs_only_itself() {
        let log = Log::default();
        let script = std::format!("038,N,01131.000,E*11\r\n{}", fix_cycle());
        poll_until_stalled(async {
            let _ = run(
                MockUart::new(&script),
                MockPower(log.clone()),
                MockEnable::new(&[true]),
                MockSink(log.clone()),
                StalledDelay,
                (),
            )
            .await;
        });
        assert_eq!(log.fixes().len(), 1);
    }

    #[test]
    fn the_receiver_rtc_read_powers_down_again_afterwards() {
        let log = Log::default();
        let mut power = MockPower(log.clone());
        let mut found = None;
        poll_until_stalled(async {
            found = rtc_read_once(
                MockUart::new(&line("GPRMC,081836.00,V,,,,,,,130926,,")),
                &mut power,
                StalledDelay,
            )
            .await;
        });
        assert_eq!(
            found.map(|at| (at.year, at.month, at.day, at.hour, at.minute)),
            Some((2026, 9, 13, 8, 18))
        );
        assert_eq!(
            log.events(),
            [Event::On, Event::Off],
            "the read left the receiver powered"
        );
    }

    /// A receiver whose backup domain lost power emits sentences with no
    /// date in them. The read gives up rather than hanging a boot.
    #[test]
    fn a_receiver_with_no_clock_yields_nothing_and_still_powers_down() {
        let log = Log::default();
        let mut power = MockPower(log.clone());
        let mut found = Some(crate::DateTime::EPOCH);
        poll_until_stalled(async {
            found = rtc_read_once(
                MockUart::new(&line("GPRMC,,V,,,,,,,,,,N")),
                &mut power,
                InstantDelay,
            )
            .await;
        });
        assert_eq!(found, None, "the read invented a time");
        assert_eq!(
            log.events(),
            [Event::On, Event::Off],
            "a timed-out read left the receiver powered"
        );
    }
}
