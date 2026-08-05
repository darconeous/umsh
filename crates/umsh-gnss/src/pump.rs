//! The receiver orchestration loop.
//!
//! This is the part that would otherwise be copied into every firmware:
//! power the receiver when it is wanted, read its UART, hand each
//! completed fix upward, and put it back to sleep when it is not. It is
//! generic over the three things that actually differ between boards —
//! the byte stream, the power sequencing, and what is done with a fix —
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

use embassy_futures::select::{Either, select};
use embedded_hal_async::delay::DelayNs;
use embedded_io_async::Read;

use crate::driver::{Driver, Fix};

/// The exact `embedded-io-async` [`run`] is generic over.
///
/// Re-exported because a consumer that wraps its UART — to count bytes
/// during bringup, to inject a fault — has to implement *this* crate's
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
/// within a second or two of its main domain coming up — it is reading
/// its own clock, not searching for satellites. Ten seconds is generous
/// enough to cover a slow start and short enough that a receiver which
/// has lost its clock does not hold up a boot.
pub const RTC_READ_TIMEOUT_MS: u32 = 10_000;

/// Pause before retrying a receiver whose UART stopped making sense, in
/// milliseconds. Long enough that a receiver failing hard does not become
/// a busy loop.
const RETRY_BACKOFF_MS: u32 = 500;

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
    /// clock, that state keeps the backup domain alive — which is not an
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
    /// receiver produces — "still nothing" is a fact worth having, and a
    /// sink that only heard about successes could not tell a receiver
    /// that is searching from one that is not running.
    async fn fix(&mut self, fix: &Fix);
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
/// Read errors are treated as the receiver having gone away: the pump
/// powers it down, waits a moment, and brings it back. A UART that
/// overruns because the executor was busy elsewhere is the common cause,
/// and it costs one fix cycle rather than a permanently deaf receiver.
pub async fn run<R, P, E, S, D>(
    mut uart: R,
    mut power: P,
    mut enable: E,
    mut sink: S,
    mut delay: D,
) -> !
where
    R: Read,
    P: Power,
    E: Enable,
    S: Sink,
    D: DelayNs,
{
    let mut driver = Driver::new();
    let mut buf = [0u8; 64];

    // Park the receiver before anything else. The pump owns its power
    // state from here on, and whatever state it was left in belongs to
    // whoever ran before — a bootloader, a previous image, or a reset
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

        // Read until the receiver is switched off or the link fails.
        let failed = loop {
            match select(uart.read(&mut buf), enable.changed()).await {
                Either::First(Ok(0)) => {
                    // A closed stream is not something to spin on.
                    delay.delay_ms(IDLE_BACKOFF_MS).await;
                }
                Either::First(Ok(len)) => {
                    for &byte in &buf[..len] {
                        if let Some(fix) = driver.push(byte) {
                            sink.fix(&fix).await;
                        }
                    }
                }
                // Cycle the receiver rather than keep reading a stream
                // that has stopped making sense.
                Either::First(Err(_)) => break true,
                Either::Second(()) => {
                    if !enable.enabled() {
                        break false;
                    }
                }
            }
        };

        power.power_off().await;
        if failed {
            // Pause before trying again, so a receiver that is failing
            // hard does not become a busy loop.
            delay.delay_ms(RETRY_BACKOFF_MS).await;
        }
    }
}

/// Power the receiver just long enough to read the time out of it, then
/// return it to its off state.
///
/// For boards where the receiver's own real-time-clock domain is the only
/// clock that survives a power cycle. The domain cannot speak a UART on
/// its own, so reading it mechanically requires bringing the main domain
/// up — but what is being read is a clock, and everything positional seen
/// along the way is discarded.
///
/// Returns the first instant the receiver reports, or `None` if it
/// reports none within [`RTC_READ_TIMEOUT_MS`] — which is what a receiver
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
    struct StalledDelay;

    impl DelayNs for StalledDelay {
        async fn delay_ns(&mut self, _ns: u32) {
            core::future::pending::<()>().await
        }
    }

    /// A delay that elapses immediately, for the one test that wants the
    /// timeout to win.
    struct InstantDelay;

    impl DelayNs for InstantDelay {
        async fn delay_ns(&mut self, _ns: u32) {}
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
