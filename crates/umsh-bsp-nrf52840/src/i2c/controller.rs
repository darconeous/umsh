//! Wait for the STOP requested by embassy-nrf's async error path before
//! another transaction can reuse this controller or its DMA buffers.
//! Cancellation of an unfinished transaction remains a separate limitation.

use crate::i2c_stop::{StopEvents, finish_error_stop};
use embassy_nrf::{Peri, gpio::Pin, interrupt::typelevel::Binding, pac, peripherals, twim};
use embedded_hal_async::i2c::{ErrorType, I2c, Operation};

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
            cortex_m::peripheral::SCB::sys_reset();
        }
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
        let result = self.inner.transaction(address, operations).await;
        if let Err(error) = result {
            self.finish_error_stop(error);
        }
        result
    }
}
