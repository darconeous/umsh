//! Cancellation-safe mailbox between a host request and a dedicated sensor
//! worker. A canceled waiter leaves acquisition running; sequence tags prevent
//! the next request from consuming its result. One onboard sensor per service.
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex, signal::Signal};

pub struct Service {
    address: AtomicU8,
    sequence: AtomicU32,
    caller: Mutex<CriticalSectionRawMutex, ()>,
    request: Signal<CriticalSectionRawMutex, u32>,
    result: Signal<CriticalSectionRawMutex, (u32, Option<u16>)>,
}

impl Default for Service {
    fn default() -> Self {
        Self::new()
    }
}
impl Service {
    pub const fn new() -> Self {
        Self {
            address: AtomicU8::new(0),
            sequence: AtomicU32::new(0),
            caller: Mutex::new(()),
            request: Signal::new(),
            result: Signal::new(),
        }
    }
    /// Publish once at boot, after probing and before starting host service.
    pub fn detected(&self, address: u8) {
        self.address.store(address, Ordering::Release);
    }
    pub fn address(&self) -> Option<u8> {
        match self.address.load(Ordering::Acquire) {
            0 => None,
            value => Some(value),
        }
    }
    pub async fn sample(&self) -> Option<u16> {
        self.address()?;
        let _caller = self.caller.lock().await;
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        self.request.signal(id);
        loop {
            let (completed, result) = self.result.wait().await;
            if completed == id {
                return result;
            }
        }
    }
    pub async fn request(&self) -> u32 {
        self.request.wait().await
    }
    pub fn complete(&self, id: u32, value: Option<u16>) {
        self.result.signal((id, value));
    }
}
