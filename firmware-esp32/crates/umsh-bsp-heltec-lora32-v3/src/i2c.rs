//! Host access to the board's shared I2C buses.
use crate::I2cBus;
use embassy_time::Duration;
use umsh_ulcp::{
    Status,
    i2c::{BusInfo, DeviceInfo, ScanRequest, TransferRequest},
};
use umsh_ulcp_runtime::i2c::{self as bus_access, Reservation};

pub const BUSES: &[BusInfo<'static>] = &[BusInfo {
    bus: 0,
    speed_khz: 400,
    max_data: umsh_ulcp_device::I2C_DATA_MAX as u16,
    max_ops: umsh_ulcp_device::I2C_MAX_OPS as u8,
    name: "I2C0 SDA GPIO17 SCL GPIO18",
}];

pub const DEVICES: &[DeviceInfo<'static>] = &[DeviceInfo {
    bus: 0,
    addr: 0x3C,
    name: "SSD1306 OLED",
}];

const BUS_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

const _: () = umsh_ulcp_device::assert_i2c_tables_fit(BUSES, DEVICES);
static RESERVED: Reservation = Reservation::new();

/// The shared controllers handed to the ULCP driver.
#[derive(Clone, Copy)]
pub struct Buses {
    pub bus: &'static I2cBus,
}

impl Buses {
    fn select(&self, bus: u8) -> Result<(&'static I2cBus, u16), Status> {
        if bus != 0 {
            return Err(Status::ITEM_NOT_FOUND);
        }
        Ok((self.bus, BUSES[0].speed_khz))
    }

    pub async fn transfer(
        &self,
        request: TransferRequest<'_>,
        out: &mut [u8],
    ) -> Result<usize, Status> {
        let (bus, speed) = self.select(request.bus)?;

        bus_access::guarded_transfer(
            bus,
            &RESERVED,
            BUS_LOCK_TIMEOUT,
            bus_access::transfer_deadline(request.shape(), speed),
            request,
            out,
        )
        .await
    }

    pub async fn scan(&self, request: ScanRequest, out: &mut [u8]) -> Result<usize, Status> {
        let (bus, speed) = self.select(request.bus)?;

        bus_access::guarded_scan(
            bus,
            &RESERVED,
            BUS_LOCK_TIMEOUT,
            bus_access::scan_deadline(&request, speed),
            request,
            out,
        )
        .await
    }
}
