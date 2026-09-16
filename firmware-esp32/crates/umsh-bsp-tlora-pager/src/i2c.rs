//! Host access to the board's shared I2C buses.
use crate::I2cBus;
use embassy_time::Duration;
use umsh_ulcp::{
    Status,
    i2c::{BusInfo, DeviceInfo, ScanRequest, TransferRequest},
};
use umsh_ulcp_runtime::i2c::{self as bus_access, Reservation};

/// The clock `power_up` configures the bus for.
const BUS_SPEED_KHZ: u16 = 400;

/// The bus a host may drive through `CMD_I2C_TRANSFER`: the one every
/// peripheral on this board hangs off. The limits are the session's
/// ceilings; esp-hal chunks long operations through its FIFO itself.
pub const BUSES: &[BusInfo<'static>] = &[BusInfo {
    bus: 0,
    speed_khz: BUS_SPEED_KHZ,
    max_data: umsh_ulcp_device::I2C_DATA_MAX as u16,
    max_ops: umsh_ulcp_device::I2C_MAX_OPS as u8,
    name: "I2C0 SDA GPIO3 SCL GPIO2",
}];

/// What is on the bus, so a host can annotate a scan and think twice
/// before writing to the charger. The audio codec and the haptic driver
/// are here because they answer a scan, not because anything in this
/// firmware drives them.
pub const DEVICES: &[DeviceInfo<'static>] = &[
    DeviceInfo {
        bus: 0,
        addr: 0x18,
        name: "ES8311 audio codec",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x20,
        name: "XL9555 I/O expander (power domains)",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x28,
        name: "BHI260AP motion sensor",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x34,
        name: "TCA8418 keyboard controller",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x51,
        name: "PCF85063 real-time clock",
    },
    DeviceInfo {
        bus: 0,
        addr: GAUGE_ADDRESS,
        name: "BQ27220 battery gauge",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x5A,
        name: "DRV2605 haptic driver",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x6B,
        name: "BQ25896 charger",
    },
];

const GAUGE_ADDRESS: u8 = 0x55;

/// How long a host transfer waits for the bus before answering
/// `STATUS_BUSY`. The battery, keyboard, motion, and RTC tasks hold it
/// for one transaction at a time, so a wait this long means something
/// is wrong rather than merely busy.
const BUS_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

const _: () = umsh_ulcp_device::assert_i2c_tables_fit(BUSES, DEVICES);

/// The gauge, while one of its multi-transaction procedures runs. The
/// bus mutex is released between the procedure's transactions, and a
/// host transfer landing in that gap would run inside an unsealed
/// gauge; the guarded transfer refuses the address instead.
pub static GAUGE_PROCEDURE: Reservation = Reservation::new();

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
            &GAUGE_PROCEDURE,
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
            &GAUGE_PROCEDURE,
            BUS_LOCK_TIMEOUT,
            bus_access::scan_deadline(&request, speed),
            request,
            out,
        )
        .await
    }
}
