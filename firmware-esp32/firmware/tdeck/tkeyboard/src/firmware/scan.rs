//! The matrix: no scanning at all while no key is down, and a scan every
//! few milliseconds while any is.
//!
//! Electrically a scan is the stock firmware's: one column driven low, the
//! others pulled-up inputs, and the rows pulled up and read. Waiting for a
//! press drives every column low instead, so any key pulls its row low.
//! Asleep, nothing is driven or watched, and no key is down.

use embassy_futures::select::{select, select_array};
use embassy_time::{Duration, Instant, Ticker, Timer};
use esp_hal::{
    gpio::{AnyPin, Flex, InputConfig, Level, OutputConfig, Pull},
    rtc_cntl::WakeLock,
};
use firmware_tdeck_tkeyboard::matrix::{COLS, Debouncer, ROWS, Snapshot};

use crate::power::{self, Part};
use crate::with_keyboard;

/// Between scans while a key is down: two agreeing scans debounce a key,
/// so a press is seen 5–10 ms after it lands.
const SCAN_PERIOD: Duration = Duration::from_millis(5);
/// After a column changes, before the rows are read. A row recovers
/// through its ~45 kΩ internal pull-up in a few microseconds.
const SETTLE: Duration = Duration::from_micros(20);

pub struct Matrix {
    cols: [Flex<'static>; COLS],
    rows: [Flex<'static>; ROWS],
}

impl Matrix {
    pub fn new(cols: [AnyPin<'static>; COLS], rows: [AnyPin<'static>; ROWS]) -> Self {
        let pulled_up = InputConfig::default().with_pull(Pull::Up);
        let input = |pin| {
            let mut pin = Flex::new(pin);
            pin.apply_input_config(&pulled_up);
            pin.set_input_enable(true);
            pin
        };
        let mut cols = cols.map(input);
        for col in &mut cols {
            col.apply_output_config(&OutputConfig::default());
            col.set_level(Level::Low);
        }
        Self {
            cols,
            rows: rows.map(input),
        }
    }

    /// Drives a column low. Its pull-up is off meanwhile: a pull-up against
    /// a low output only wastes current.
    fn drive(col: &mut Flex<'static>) {
        col.apply_input_config(&InputConfig::default());
        col.set_output_enable(true);
    }

    /// Makes a column a pulled-up input again.
    fn release(col: &mut Flex<'static>) {
        col.set_output_enable(false);
        col.apply_input_config(&InputConfig::default().with_pull(Pull::Up));
    }

    async fn wait_for_press(&mut self) {
        self.cols.iter_mut().for_each(Self::drive);
        Timer::after(SETTLE).await;
        select_array(self.rows.each_mut().map(|row| row.wait_for_low())).await;
        self.cols.iter_mut().for_each(Self::release);
    }

    /// Leaves every line an undriven, pulled-up input.
    fn park(&mut self) {
        self.cols.iter_mut().for_each(Self::release);
    }

    async fn scan(&mut self) -> Snapshot {
        let mut keys = Snapshot::EMPTY;
        for (bits, col) in keys.0.iter_mut().zip(&mut self.cols) {
            Self::drive(col);
            Timer::after(SETTLE).await;
            *bits = self
                .rows
                .iter()
                .enumerate()
                .fold(0, |bits, (r, row)| bits | u8::from(row.is_low()) << r);
            Self::release(col);
        }
        keys
    }
}

#[embassy_executor::task]
pub async fn task(mut matrix: Matrix) {
    let mut asleep = power::Receiver::new();
    loop {
        let mut debouncer = Debouncer::new();
        // Awake, the keyboard is scanned at full speed, never from sleep.
        let awake = WakeLock::new();
        select(run(&mut matrix, &mut debouncer), asleep.until_asleep()).await;
        drop(awake);
        // Dropping the wait unlistens the rows. Whatever was down is up
        // as far as anyone knows, and a key still held on waking is
        // pressed anew.
        matrix.park();
        with_keyboard(|keyboard| keyboard.on_scan(Snapshot::EMPTY, Instant::now().as_millis()));
        asleep.park_until_awake(Part::Scan).await;
    }
}

async fn run(matrix: &mut Matrix, debouncer: &mut Debouncer) {
    loop {
        matrix.wait_for_press().await;
        let mut ticker = Ticker::every(SCAN_PERIOD);
        loop {
            let keys = debouncer.update(matrix.scan().await);
            with_keyboard(|keyboard| keyboard.on_scan(keys, Instant::now().as_millis()));
            if debouncer.is_idle() {
                break;
            }
            ticker.next().await;
        }
    }
}
