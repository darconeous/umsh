//! Host access to the board's shared I2C buses.
use crate::I2cBus;
use embassy_time::Duration;
use umsh_ulcp::{
    Status,
    i2c::{BusInfo, DeviceInfo, ScanRequest, TransferRequest},
};
use umsh_ulcp_runtime::i2c::{self as bus_access, Reservation};

pub const BUSES: &[BusInfo<'static>] = &[
    BusInfo {
        bus: 0,
        speed_khz: 400,
        max_data: umsh_ulcp_device::I2C_DATA_MAX as u16,
        max_ops: umsh_ulcp_device::I2C_MAX_OPS as u8,
        name: "I2C0 sensors SDA GPIO17 SCL GPIO18",
    },
    BusInfo {
        bus: 1,
        speed_khz: 100,
        max_data: umsh_ulcp_device::I2C_DATA_MAX as u16,
        max_ops: umsh_ulcp_device::I2C_MAX_OPS as u8,
        name: "I2C1 PMU SDA GPIO42 SCL GPIO41",
    },
];

pub const DEVICES: &[DeviceInfo<'static>] = &[
    DeviceInfo {
        bus: 0,
        addr: 0x1C,
        name: "QMC6310U magnetometer (population)",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x3C,
        name: "SH1106 OLED or QMC6310N magnetometer, by population",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x3D,
        name: "SH1106 OLED (alternate address)",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x76,
        name: "BME280 sensor (strap-selected)",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x77,
        name: "BME280 sensor (strap-selected)",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x7C,
        name: "QMC6309 magnetometer (population)",
    },
    DeviceInfo {
        bus: 1,
        addr: 0x34,
        name: "AXP2101 PMIC",
    },
    DeviceInfo {
        bus: 1,
        addr: 0x51,
        name: "PCF8563 real-time clock",
    },
];

const BUS_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

const _: () = umsh_ulcp_device::assert_i2c_tables_fit(BUSES, DEVICES);
static RESERVED: Reservation = Reservation::new();

/// The shared controllers handed to the ULCP driver.
#[derive(Clone, Copy)]
pub struct Buses {
    pub sensor: &'static I2cBus,
    pub pmu: &'static I2cBus,
}

impl Buses {
    fn select(&self, bus: u8) -> Result<(&'static I2cBus, u16), Status> {
        match bus {
            0 => Ok((self.sensor, BUSES[0].speed_khz)),
            1 => Ok((self.pmu, BUSES[1].speed_khz)),
            _ => Err(Status::ITEM_NOT_FOUND),
        }
    }

    pub async fn transfer(
        &self,
        request: TransferRequest<'_>,
        out: &mut [u8],
    ) -> Result<usize, Status> {
        let (bus, speed) = self.select(request.bus)?;
        let _power = self.sensor_power(request.bus).await?;
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
        let _power = self.sensor_power(request.bus).await?;
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

// Hold the PMU bus through sensor access: even a raw host write must not
// turn ALDO1 off between checking it and completing the transaction.
type PowerGuard = embassy_sync::mutex::MutexGuard<
    'static,
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    esp_hal::i2c::master::I2c<'static, esp_hal::Async>,
>;

impl Buses {
    async fn sensor_power(&self, bus: u8) -> Result<Option<PowerGuard>, Status> {
        if bus != 0 {
            return Ok(None);
        }
        let mut guard = embassy_time::with_timeout(BUS_LOCK_TIMEOUT, self.pmu.lock())
            .await
            .map_err(|_| Status::BUSY)?;
        let mut pmic = umsh_pmic_axp2101::Axp2101::new(&mut *guard);
        let enabled = embassy_time::with_timeout(
            bus_access::deadline_for(3, BUSES[1].speed_khz),
            pmic.rail_enabled(crate::SENSOR_RAIL),
        )
        .await
        .map_err(|_| Status::BUS_ERROR)?
        .map_err(|_| Status::BUS_ERROR)?;
        if !enabled {
            return Err(Status::INVALID_STATE);
        }
        Ok(Some(guard))
    }
}
