//! When the chip sleeps.
//!
//! The idle hook light-sleeps whenever every task is waiting and no
//! `WakeLock` is held, so the rule is: **a task that needs the chip awake
//! holds a lock for exactly as long as it does.** The I²C target holds one
//! while it serves (the driver's own), the scan task while the keyboard
//! is awake, and the light while it is on, since its PWM stops in sleep.
//! A task that waits without one lets the chip sleep.
//!
//! The host sends the keyboard to sleep. Then the matrix is not scanned
//! and the light is off: the host task asks the scan and light tasks to
//! park, waits until both have, and waits for the bus with no lock held.
//! The light fades out first, and traffic on the bus in the meantime wakes
//! the keyboard before it has slept, so a part may see the sleep and the
//! wake as one change.

use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, signal::Signal, watch};

/// The tasks that park.
#[derive(Clone, Copy)]
pub enum Part {
    Scan,
    Light,
}

const PARTS: usize = 2;

/// Whether the keyboard is asleep, or about to be.
static ASLEEP: watch::Watch<CriticalSectionRawMutex, bool, PARTS> = watch::Watch::new();
static PARKED: [Signal<CriticalSectionRawMutex, ()>; PARTS] = [const { Signal::new() }; PARTS];

pub struct Receiver(watch::Receiver<'static, CriticalSectionRawMutex, bool, PARTS>);

impl Receiver {
    /// One for each part.
    pub fn new() -> Self {
        Self(ASLEEP.receiver().unwrap())
    }

    /// The next change: whether the keyboard is now asleep. A sleep and
    /// a wake close together may come as the wake alone.
    pub async fn changed(&mut self) -> bool {
        self.0.changed().await
    }

    pub async fn until_asleep(&mut self) {
        self.0.get_and(|&asleep| asleep).await;
    }

    /// Reports `part` parked, then waits until the keyboard is awake again.
    pub async fn park_until_awake(&mut self, part: Part) {
        parked(part);
        self.0.get_and(|&asleep| !asleep).await;
    }
}

/// Reports `part` parked, for one that waits for the wake its own way.
pub fn parked(part: Part) {
    PARKED[part as usize].signal(());
}

/// Asks every part to park, and returns once all have.
pub async fn park() {
    // A part that parked for a sleep cut short by a wake has not parked
    // for this one.
    for parked in &PARKED {
        parked.reset();
    }
    ASLEEP.sender().send(true);
    for parked in &PARKED {
        parked.wait().await;
    }
}

pub fn wake() {
    ASLEEP.sender().send(false);
}
