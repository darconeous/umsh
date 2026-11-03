//! One concrete `RadioKind` for a board that takes either of two chips.
//!
//! `RadioKind` has `async fn`s and `impl DelayNs` arguments, so it cannot
//! be a trait object, and an Embassy task cannot be generic. A board whose
//! chip is known only at boot builds one of two drivers and wraps it here;
//! the task, the runner, and everything above them see a single type.

use embedded_hal_async::delay::DelayNs;
use lora_phy::{
    RxMode,
    mod_params::{
        Bandwidth, CodingRate, ModulationParams, PacketParams, PacketStatus, RadioError, RadioMode,
        SpreadingFactor,
    },
    mod_traits::{IrqState, RadioKind},
};

/// Whichever of two drivers the board found a chip for.
pub enum EitherRadioKind<A, B> {
    A(A),
    B(B),
}

/// Forward one call to the variant that is present.
macro_rules! forward {
    ($self:ident.$method:ident($($arg:expr),*).await) => {
        match $self {
            EitherRadioKind::A(radio) => radio.$method($($arg),*).await,
            EitherRadioKind::B(radio) => radio.$method($($arg),*).await,
        }
    };
    ($self:ident.$method:ident($($arg:expr),*)) => {
        match $self {
            EitherRadioKind::A(radio) => radio.$method($($arg),*),
            EitherRadioKind::B(radio) => radio.$method($($arg),*),
        }
    };
}

impl<A: RadioKind, B: RadioKind> RadioKind for EitherRadioKind<A, B> {
    async fn init_lora(&mut self, sync_word: u8) -> Result<(), RadioError> {
        forward!(self.init_lora(sync_word).await)
    }

    fn create_modulation_params(
        &self,
        spreading_factor: SpreadingFactor,
        bandwidth: Bandwidth,
        coding_rate: CodingRate,
        frequency_in_hz: u32,
    ) -> Result<ModulationParams, RadioError> {
        forward!(self.create_modulation_params(
            spreading_factor,
            bandwidth,
            coding_rate,
            frequency_in_hz
        ))
    }

    fn create_packet_params(
        &self,
        preamble_length: u16,
        implicit_header: bool,
        payload_length: u8,
        crc_on: bool,
        iq_inverted: bool,
        modulation_params: &ModulationParams,
    ) -> Result<PacketParams, RadioError> {
        forward!(self.create_packet_params(
            preamble_length,
            implicit_header,
            payload_length,
            crc_on,
            iq_inverted,
            modulation_params
        ))
    }

    async fn reset(&mut self, delay: &mut impl DelayNs) -> Result<(), RadioError> {
        forward!(self.reset(delay).await)
    }

    async fn ensure_ready(&mut self, mode: RadioMode) -> Result<(), RadioError> {
        forward!(self.ensure_ready(mode).await)
    }

    async fn set_standby(&mut self) -> Result<(), RadioError> {
        forward!(self.set_standby().await)
    }

    async fn set_sleep(
        &mut self,
        warm_start_if_possible: bool,
        delay: &mut impl DelayNs,
    ) -> Result<(), RadioError> {
        forward!(self.set_sleep(warm_start_if_possible, delay).await)
    }

    async fn set_tx_rx_buffer_base_address(
        &mut self,
        tx_base_addr: usize,
        rx_base_addr: usize,
    ) -> Result<(), RadioError> {
        forward!(
            self.set_tx_rx_buffer_base_address(tx_base_addr, rx_base_addr)
                .await
        )
    }

    async fn set_tx_power_and_ramp_time(
        &mut self,
        output_power: i32,
        mdltn_params: Option<&ModulationParams>,
        is_tx_prep: bool,
    ) -> Result<(), RadioError> {
        forward!(
            self.set_tx_power_and_ramp_time(output_power, mdltn_params, is_tx_prep)
                .await
        )
    }

    async fn set_modulation_params(
        &mut self,
        mdltn_params: &ModulationParams,
    ) -> Result<(), RadioError> {
        forward!(self.set_modulation_params(mdltn_params).await)
    }

    async fn set_packet_params(&mut self, pkt_params: &PacketParams) -> Result<(), RadioError> {
        forward!(self.set_packet_params(pkt_params).await)
    }

    async fn calibrate_image(&mut self, frequency_in_hz: u32) -> Result<(), RadioError> {
        forward!(self.calibrate_image(frequency_in_hz).await)
    }

    async fn set_channel(&mut self, frequency_in_hz: u32) -> Result<(), RadioError> {
        forward!(self.set_channel(frequency_in_hz).await)
    }

    async fn set_payload(&mut self, payload: &[u8]) -> Result<(), RadioError> {
        forward!(self.set_payload(payload).await)
    }

    async fn do_tx(&mut self) -> Result<(), RadioError> {
        forward!(self.do_tx().await)
    }

    async fn do_rx(&mut self, rx_mode: RxMode) -> Result<(), RadioError> {
        forward!(self.do_rx(rx_mode).await)
    }

    async fn get_rx_payload(
        &mut self,
        rx_pkt_params: &PacketParams,
        receiving_buffer: &mut [u8],
    ) -> Result<u8, RadioError> {
        forward!(self.get_rx_payload(rx_pkt_params, receiving_buffer).await)
    }

    async fn get_rx_packet_status(&mut self) -> Result<PacketStatus, RadioError> {
        forward!(self.get_rx_packet_status().await)
    }

    async fn get_rssi(&mut self) -> Result<i16, RadioError> {
        forward!(self.get_rssi().await)
    }

    async fn do_cad(&mut self, mdltn_params: &ModulationParams) -> Result<(), RadioError> {
        forward!(self.do_cad(mdltn_params).await)
    }

    async fn set_irq_params(&mut self, radio_mode: Option<RadioMode>) -> Result<(), RadioError> {
        forward!(self.set_irq_params(radio_mode).await)
    }

    async fn set_tx_continuous_wave_mode(&mut self) -> Result<(), RadioError> {
        forward!(self.set_tx_continuous_wave_mode().await)
    }

    async fn await_irq(&mut self) -> Result<(), RadioError> {
        forward!(self.await_irq().await)
    }

    async fn process_irq_event(
        &mut self,
        radio_mode: RadioMode,
        cad_activity_detected: Option<&mut bool>,
        clear_interrupts: bool,
    ) -> Result<Option<IrqState>, RadioError> {
        forward!(
            self.process_irq_event(radio_mode, cad_activity_detected, clear_interrupts)
                .await
        )
    }

    async fn get_irq_state(
        &mut self,
        radio_mode: RadioMode,
        cad_activity_detected: Option<&mut bool>,
    ) -> Result<Option<IrqState>, RadioError> {
        forward!(self.get_irq_state(radio_mode, cad_activity_detected).await)
    }

    async fn clear_irq_status(&mut self) -> Result<(), RadioError> {
        forward!(self.clear_irq_status().await)
    }
}
