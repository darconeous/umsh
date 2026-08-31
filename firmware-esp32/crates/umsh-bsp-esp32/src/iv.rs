//! Wake-aware radio `InterfaceVariant`, shared by every ESP32 board.
//!
//! lora-phy's generic variants drive their pins through
//! `embedded_hal_async::digital::Wait`, and esp-hal's implementation of
//! that trait holds a [`WakeLock`](esp_hal::rtc_cntl::WakeLock) for the
//! whole wait — which for a continuous-RX radio is essentially forever,
//! pinning the scheduler out of light sleep. This variant is the same
//! logic driven through esp-hal's `Input` directly, with the IRQ wait
//! wake-enabled: the pin becomes a light-sleep wake source (level
//! events only — exactly what an SX12xx IRQ line is) instead of a lock
//! holder, and a frame arriving mid-sleep wakes the chip. The radio
//! latches its IRQ and buffers the frame in its own FIFO, so the
//! sub-millisecond wake latency loses nothing.
//!
//! The BUSY wait (SX126x only) keeps the plain locked wait: it spans
//! one command's setup time, and a lock held for microseconds is
//! correct, not a leak.
//!
//! None of the boards this workspace supports put RF-switch control on
//! host GPIOs (DIO2 does it internally on the SX126x boards; the V2's
//! SX1276 module needs none), so the switch hooks are no-ops.

use embedded_hal_async::delay::DelayNs;
use esp_hal::gpio::{Event, Input, Output, WaitForOptions};
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
            busy.wait_for(Event::LowLevel).await;
        }
        Ok(())
    }

    async fn await_irq(&mut self) -> Result<(), RadioError> {
        self.irq
            .wait_for_with_options(
                Event::HighLevel,
                WaitForOptions::default().with_wake_enable(true),
            )
            .await
            .map_err(|_| RadioError::Irq)
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
