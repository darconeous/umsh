//! `Vext` power-domain control (GPIO21, active high).
//!
//! GPIO21 gates two things at once (hardware doc §9.1): the external
//! `Vext` 3.3 V rail that powers the OLED, and the low-side MOSFET that
//! completes the battery measurement divider. That coupling is why the
//! rail is a process-wide singleton behind [`VextHandle`] rather than an
//! owned pin: the display task and the battery sampler are separate
//! tasks that both need it, and neither may cut power out from under the
//! other. The Heltec V3 has an independent divider gate and hands its
//! `Vext` to the display task by value; here the handle is `Copy` and
//! every holder talks to the same rail.
//!
//! After [`VextHandle::disable`], the OLED has lost power and must go
//! through the full reset + init sequence again (see [`crate::display`]),
//! and GPIO13 no longer carries a valid battery voltage.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::Timer;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::peripherals::GPIO21;

/// How long to wait after switching the rail on before trusting either
/// the OLED supply or the battery divider. The rail itself settles fast;
/// the divider's 320 kΩ impedance and the OLED's power-on both justify a
/// few milliseconds of margin (hardware doc §9.4).
const SETTLE_MS: u64 = 10;

/// The one owned rail. `None` until [`init`] claims GPIO21.
static RAIL: Mutex<CriticalSectionRawMutex, RefCell<Option<Output<'static>>>> =
    Mutex::new(RefCell::new(None));

/// Shared handle to the `Vext` power domain. `Copy`, because the rail it
/// names is a singleton — cloning a handle does not clone the rail.
#[derive(Clone, Copy)]
pub struct VextHandle(());

/// Claim GPIO21 and return the shared handle. The rail starts off.
///
/// Panics if called twice: the rail is a singleton and a second claim
/// would mean two owners of one pin.
pub fn init(pin: GPIO21<'static>) -> VextHandle {
    let pin = Output::new(pin, Level::Low, OutputConfig::default());
    RAIL.lock(|cell| {
        let mut slot = cell.borrow_mut();
        assert!(slot.is_none(), "Vext claimed twice");
        *slot = Some(pin);
    });
    VextHandle(())
}

impl VextHandle {
    /// Switch the rail on and wait for it to settle. Idempotent: if the
    /// rail is already on, returns immediately without re-settling.
    pub async fn enable(&mut self) {
        if self.set(Level::High) {
            Timer::after_millis(SETTLE_MS).await;
        }
    }

    /// Switch the rail off. The OLED loses power and the battery divider
    /// disconnects.
    pub fn disable(&mut self) {
        self.set(Level::Low);
    }

    pub fn is_on(&self) -> bool {
        RAIL.lock(|cell| {
            cell.borrow()
                .as_ref()
                .expect("Vext not initialized")
                .output_level()
                == Level::High
        })
    }

    /// Drive the rail to `level`; returns whether that changed it.
    fn set(&mut self, level: Level) -> bool {
        RAIL.lock(|cell| {
            let mut slot = cell.borrow_mut();
            let pin = slot.as_mut().expect("Vext not initialized");
            if pin.output_level() == level {
                return false;
            }
            pin.set_level(level);
            true
        })
    }
}
