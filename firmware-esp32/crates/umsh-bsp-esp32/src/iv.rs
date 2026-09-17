//! Wake-aware radio `InterfaceVariant`, shared by every ESP32 board.
//!
//! GPIO level waits wake the chip through esp-hal's digital wake path.
//! The radio latches its IRQ and buffers the frame in its own FIFO, so
//! the sub-millisecond wake latency loses nothing. BUSY waits keep an
//! explicit wake lock across one command's short setup interval.
//!
//! None of the boards this workspace supports put RF-switch control on
//! host GPIOs (DIO2 does it internally on the SX126x boards; the V2's
//! SX1276 module needs none), so the switch hooks are no-ops.

use embedded_hal_async::delay::DelayNs;
use esp_hal::gpio::{Event, Input, Output};
use lora_phy::mod_params::RadioError;
use lora_phy::mod_traits::InterfaceVariant;

/// One struct for both radio families: `busy` is `Some` on the SX126x
/// boards and `None` on the SX127x board.
pub struct EspInterfaceVariant {
    reset: Output<'static>,
    irq: Input<'static>,
    busy: Option<Input<'static>>,
}

impl EspInterfaceVariant {
    /// SX126x shape: DIO1 carries the IRQs, BUSY gates every command.
    pub fn sx126x(reset: Output<'static>, dio1: Input<'static>, busy: Input<'static>) -> Self {
        Self {
            reset,
            irq: dio1,
            busy: Some(busy),
        }
    }

    /// SX127x shape: DIO0 carries the IRQs, no BUSY line exists.
    pub fn sx127x(reset: Output<'static>, dio0: Input<'static>) -> Self {
        Self {
            reset,
            irq: dio0,
            busy: None,
        }
    }
}

impl InterfaceVariant for EspInterfaceVariant {
    async fn reset(&mut self, delay: &mut impl DelayNs) -> Result<(), RadioError> {
        // The SX126x timing (10/20/10 ms); comfortably beyond the
        // SX127x's ≥100 µs low requirement, so both families share it.
        delay.delay_ms(10).await;
        self.reset.set_low();
        delay.delay_ms(20).await;
        self.reset.set_high();
        delay.delay_ms(10).await;
        Ok(())
    }

    async fn wait_on_busy(&mut self) -> Result<(), RadioError> {
        if let Some(busy) = &mut self.busy {
            let _guard = esp_hal::rtc_cntl::WakeLock::new();
            busy.wait_for(Event::LowLevel).await;
        }
        Ok(())
    }

    async fn await_irq(&mut self) -> Result<(), RadioError> {
        self.irq.wait_for(Event::HighLevel).await;
        Ok(())
    }

    async fn enable_rf_switch_rx(&mut self) -> Result<(), RadioError> {
        Ok(())
    }

    async fn enable_rf_switch_tx(&mut self) -> Result<(), RadioError> {
        Ok(())
    }

    async fn disable_rf_switch(&mut self) -> Result<(), RadioError> {
        Ok(())
    }
}
