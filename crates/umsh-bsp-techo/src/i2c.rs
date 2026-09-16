//! Board bus inventory for raw host I2C access. Expansion devices are not fixed.
pub use umsh_bsp_nrf52840::i2c::{Bus, Handle};
use umsh_ulcp::i2c::{BusInfo, DeviceInfo};
pub type Buses = umsh_bsp_nrf52840::i2c::Buses<1>;

pub const BUSES: &[BusInfo<'static>] = &[BusInfo {
    bus: 0,
    speed_khz: 100,
    max_data: umsh_ulcp_device::I2C_DATA_MAX as u16,
    max_ops: umsh_ulcp_device::I2C_MAX_OPS as u8,
    name: "TWIM0 SDA P0.26 SCL P0.27",
}];
pub const DEVICES: &[DeviceInfo<'static>] = &[
    DeviceInfo {
        bus: 0,
        addr: 0x51,
        name: "PCF8563 real-time clock",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x77,
        name: "BME280 environmental sensor",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x28,
        name: "BHI260 IMU (Plus only)",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x5A,
        name: "DRV2605 haptic driver (Plus only)",
    },
];

const _: () = umsh_ulcp_device::assert_i2c_tables_fit(BUSES, DEVICES);
