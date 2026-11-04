//! Wait for the STOP requested by embassy-nrf's async error path before
//! another transaction can reuse this controller or its DMA buffers, and
//! recover the controller when a transaction is abandoned mid-transfer.
//!
//! embassy-nrf 0.11's async transaction has no drop guard: a deadline that
//! drops it leaves the controller running against buffers that are about
//! to be released, and every later transaction starts on top of it. The
//! guard here stops the abandoned transfer, takes the controller off the
//! lines, clocks the bus clear, and puts it back. Disabling is the
//! backstop when the STOP cannot complete, as with SCL held low; it is
//! also how Zephyr's nrfx TWIM driver abandons a transfer that timed out.

use crate::i2c_stop::{BusLines, StopEvents, clear_bus, finish_error_stop, stop_abandoned};
use embassy_nrf::{Peri, gpio::Pin, interrupt::typelevel::Binding, pac, peripherals, twim};
use embedded_hal_async::i2c::{ErrorType, I2c, Operation};

/// 5 µs at the 64 MHz core clock: a 100 kHz bus clock.
const HALF_CLOCK_CYCLES: u32 = 64 * 5;

mod sealed {
    pub trait Registers {
        fn registers() -> embassy_nrf::pac::twim::Twim;
    }
    impl Registers for embassy_nrf::peripherals::TWISPI0 {
        fn registers() -> embassy_nrf::pac::twim::Twim {
            embassy_nrf::pac::TWIM0
        }
    }
    impl Registers for embassy_nrf::peripherals::TWISPI1 {
        fn registers() -> embassy_nrf::pac::twim::Twim {
            embassy_nrf::pac::TWIM1
        }
    }
}

pub trait Instance: twim::Instance + sealed::Registers {}
impl Instance for peripherals::TWISPI0 {}
impl Instance for peripherals::TWISPI1 {}

pub struct Controller {
    inner: twim::Twim<'static>,
    registers: pac::twim::Twim,
}

impl Controller {
    pub fn new<T: Instance>(
        peripheral: Peri<'static, T>,
        irq: impl Binding<T::Interrupt, twim::InterruptHandler<T>> + 'static,
        sda: Peri<'static, impl Pin>,
        scl: Peri<'static, impl Pin>,
        config: twim::Config,
        tx: &'static mut [u8],
    ) -> Self {
        Self {
            inner: twim::Twim::new(peripheral, irq, sda, scl, config, tx),
            registers: T::registers(),
        }
    }

    fn finish_error_stop(&mut self, error: twim::Error) {
        // These errors can return through async_wait's early error path.
        // Buffer/setup errors never requested STOP; receive/transmit length
        // checks run only after the HAL consumed a completion event.
        if !matches!(
            error,
            twim::Error::AddressNack
                | twim::Error::DataNack
                | twim::Error::Overrun
                | twim::Error::Timeout
        ) {
            return;
        }
        if !finish_error_stop(&mut self.registers) {
            // Never release buffers that DMA may still own.
            recover(self.registers);
        }
    }
}

/// Take the controller off a transfer it cannot finish and hand it back
/// idle: disabled, so DMA cannot touch the buffers about to be released;
/// bus cleared, so a target left mid-octet lets go of SDA; re-enabled for
/// the next transaction. A bus that stays stuck is left for that
/// transaction to report.
fn recover(registers: pac::twim::Twim) {
    registers.intenclr().write(|w| w.0 = 0xFFFF_FFFF);
    registers.shorts().write_value(Default::default());
    let mut lines = Lines {
        scl: Line::of(registers.psel().scl().read()),
        sda: Line::of(registers.psel().sda().read()),
    };
    // GPIO drives the pins once the controller lets go; released first,
    // they stay high through the handover.
    lines.release_scl();
    lines.release_sda();
    registers
        .enable()
        .write(|w| w.set_enable(pac::twim::vals::Enable::Disabled));
    let _ = clear_bus(&mut lines);
    registers.events_suspended().write_value(0);
    registers.events_stopped().write_value(0);
    registers.events_error().write_value(0);
    registers
        .enable()
        .write(|w| w.set_enable(pac::twim::vals::Enable::Enabled));
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Armed for the length of a transaction. Dropped armed, the transaction's
/// future was abandoned while the controller was still working on it.
struct Abandonment {
    registers: pac::twim::Twim,
    armed: bool,
}

impl Drop for Abandonment {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = stop_abandoned(&mut self.registers);
        // A STOP that completed leaves an idle controller, but whatever
        // stalled the transfer may still be holding the bus.
        recover(self.registers);
    }
}

#[derive(Clone, Copy)]
struct Line {
    port: pac::gpio::Gpio,
    pin: usize,
}

impl Line {
    fn of(psel: pac::shared::regs::Psel) -> Self {
        Self {
            port: if psel.port() { pac::P1 } else { pac::P0 },
            pin: psel.pin() as usize,
        }
    }
    // The HAL configured both pins as open-drain outputs: a set bit
    // releases the line, a clear bit pulls it low.
    fn release(self) {
        self.port.outset().write(|w| w.set_pin(self.pin, true));
    }
    fn pull(self) {
        self.port.outclr().write(|w| w.set_pin(self.pin, true));
    }
    fn is_high(self) -> bool {
        self.port.in_().read().pin(self.pin)
    }
}

struct Lines {
    scl: Line,
    sda: Line,
}

impl BusLines for Lines {
    fn release_scl(&mut self) {
        self.scl.release();
    }
    fn pull_scl(&mut self) {
        self.scl.pull();
    }
    fn release_sda(&mut self) {
        self.sda.release();
    }
    fn pull_sda(&mut self) {
        self.sda.pull();
    }
    fn sda_high(&self) -> bool {
        self.sda.is_high()
    }
    fn half_clock(&mut self) {
        cortex_m::asm::delay(HALF_CLOCK_CYCLES);
    }
}

impl StopEvents for pac::twim::Twim {
    fn error_pending(&self) -> bool {
        self.events_error().read() != 0
    }
    fn suspended(&self) -> bool {
        self.events_suspended().read() != 0
    }
    fn stopped(&mut self) -> bool {
        self.events_stopped().read() != 0
    }
    fn resume_and_stop(&mut self) {
        self.shorts().write_value(Default::default());
        self.events_suspended().write_value(0);
        self.tasks_resume().write_value(1);
        self.tasks_stop().write_value(1);
    }
    fn acknowledge_stop(&mut self) {
        self.intenclr().write(|w| w.set_stopped(true));
        self.events_stopped().write_value(0);
    }
}

impl ErrorType for Controller {
    type Error = twim::Error;
}

impl I2c for Controller {
    async fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        let mut abandonment = Abandonment {
            registers: self.registers,
            armed: true,
        };
        let result = self.inner.transaction(address, operations).await;
        abandonment.armed = false;
        if let Err(error) = result {
            self.finish_error_stop(error);
        }
        result
    }
}
