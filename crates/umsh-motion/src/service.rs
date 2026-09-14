//! Shared observations and independently notified consumers. Subscription does
//! not itself power the sensor: consumers explicitly register their demand.
use crate::State;
use core::cell::Cell;
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    signal::Signal,
    watch::Watch,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consumer {
    Display = 1,
    Location = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    pub generation: u32,
    pub consumers: u8,
    pub shutdown: bool,
}

impl Control {
    pub fn sensing(self) -> bool {
        !self.shutdown && self.consumers != 0
    }
    pub fn display(self) -> bool {
        !self.shutdown && self.consumers & Consumer::Display as u8 != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Wake {
    pub generation: u32,
    pub at_ms: u64,
}

pub struct Service {
    control: Mutex<CriticalSectionRawMutex, Cell<Control>>,
    pub changed: Signal<CriticalSectionRawMutex, ()>,
    pub stopped: Signal<CriticalSectionRawMutex, ()>,
    pub observations: Watch<CriticalSectionRawMutex, State, 4>,
    pub display_wake: Signal<CriticalSectionRawMutex, Wake>,
}

impl Default for Service {
    fn default() -> Self {
        Self::new()
    }
}

impl Service {
    pub const fn new() -> Self {
        Self {
            control: Mutex::new(Cell::new(Control {
                generation: 0,
                consumers: 0,
                shutdown: false,
            })),
            changed: Signal::new(),
            stopped: Signal::new(),
            observations: Watch::new(),
            display_wake: Signal::new(),
        }
    }
    pub fn control(&self) -> Control {
        self.control.lock(Cell::get)
    }
    pub fn request(&self, consumer: Consumer, enabled: bool) {
        let changed = self.control.lock(|cell| {
            let mut c = cell.get();
            let consumers = if enabled {
                c.consumers | consumer as u8
            } else {
                c.consumers & !(consumer as u8)
            };
            if c.consumers == consumers {
                return false;
            }
            c.consumers = consumers;
            c.generation = c.generation.wrapping_add(1);
            cell.set(c);
            true
        });
        if changed {
            self.display_wake.reset();
            self.changed.signal(());
        }
    }
    /// Fault/reset invalidates queued wakes immediately, before async cleanup.
    pub fn cancel(&self) {
        self.control.lock(|cell| {
            let mut c = cell.get();
            c.generation = c.generation.wrapping_add(1);
            cell.set(c);
        });
        self.display_wake.reset();
    }
    pub fn shutdown(&self) {
        self.control.lock(|cell| {
            let mut c = cell.get();
            c.shutdown = true;
            c.generation = c.generation.wrapping_add(1);
            cell.set(c);
        });
        self.display_wake.reset();
        self.changed.signal(());
    }
    pub fn accept(&self, wake: Wake, now_ms: u64) -> bool {
        let c = self.control();
        c.display()
            && c.generation == wake.generation
            && now_ms >= wake.at_ms
            && now_ms - wake.at_ms <= 250
    }
}
