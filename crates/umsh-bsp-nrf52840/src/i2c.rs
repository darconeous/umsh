//! Shared TWIM controllers and host access for nRF52840 boards.
//!
//! Error returns wait for the HAL's pending STOP before releasing the bus.
//! Known limitation: cancellation of an unfinished embassy-nrf 0.11
//! transaction still does not confirm DMA shutdown. Host access is enabled
//! while that recovery fix remains pending; deadlines are not a cancellation-safety
//! guarantee. See docs/ulcp-i2c-proposal.md for the qualification limits.

use embassy_sync::{blocking_mutex::raw::ThreadModeRawMutex, mutex::Mutex};

mod controller;
pub use controller::Controller;

pub type Bus = Mutex<ThreadModeRawMutex, Controller>;
pub type Handle = embassy_embedded_hal::shared_bus::asynch::i2c::I2cDevice<
    'static,
    ThreadModeRawMutex,
    Controller,
>;

#[cfg(feature = "ulcp-i2c")]
pub use host::Buses;

#[cfg(feature = "ulcp-i2c")]
mod host {
    use super::Bus;
    use embassy_time::Duration;
    use umsh_ulcp::{
        Status,
        i2c::{BusInfo, ScanRequest, TransferRequest},
    };
    use umsh_ulcp_runtime::i2c::{self, Reservation};

    const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
    static RESERVED: Reservation = Reservation::new();

    #[derive(Clone, Copy)]
    pub struct Buses<const N: usize> {
        buses: [&'static Bus; N],
        info: &'static [BusInfo<'static>],
    }

    impl<const N: usize> Buses<N> {
        /// Controllers follow the same order as the board's bus table.
        pub fn new(buses: [&'static Bus; N], info: &'static [BusInfo<'static>]) -> Self {
            assert_eq!(N, info.len());
            Self { buses, info }
        }

        fn select(&self, id: u8) -> Result<(&'static Bus, u16), Status> {
            let index = self
                .info
                .iter()
                .position(|info| info.bus == id)
                .ok_or(Status::ITEM_NOT_FOUND)?;
            Ok((self.buses[index], self.info[index].speed_khz))
        }

        pub async fn transfer(
            &self,
            request: TransferRequest<'_>,
            out: &mut [u8],
        ) -> Result<usize, Status> {
            let (bus, speed) = self.select(request.bus)?;
            i2c::guarded_transfer(
                bus,
                &RESERVED,
                LOCK_TIMEOUT,
                i2c::transfer_deadline(request.shape(), speed),
                request,
                out,
            )
            .await
        }

        pub async fn scan(&self, request: ScanRequest, out: &mut [u8]) -> Result<usize, Status> {
            let (bus, speed) = self.select(request.bus)?;
            i2c::guarded_scan(
                bus,
                &RESERVED,
                LOCK_TIMEOUT,
                i2c::scan_deadline(&request, speed),
                request,
                out,
            )
            .await
        }
    }
}
