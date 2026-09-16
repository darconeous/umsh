//! Board bus inventory for raw host I2C access. Expansion devices are not fixed.
pub use umsh_bsp_nrf52840::i2c::{Bus, Handle};
use umsh_ulcp::i2c::{BusInfo, DeviceInfo};
pub type Buses = umsh_bsp_nrf52840::i2c::Buses<2>;

pub const BUSES: &[BusInfo<'static>] = &[
    BusInfo {
        bus: 0,
        speed_khz: 100,
        max_data: umsh_ulcp_device::I2C_DATA_MAX as u16,
        max_ops: umsh_ulcp_device::I2C_MAX_OPS as u8,
        name: "TWIM0 OLED SDA P0.06 SCL P0.05",
    },
    BusInfo {
        bus: 1,
        speed_khz: 100,
        max_data: umsh_ulcp_device::I2C_DATA_MAX as u16,
        max_ops: umsh_ulcp_device::I2C_MAX_OPS as u8,
        name: "TWIM1 Grove SDA P1.12 SCL P1.11",
    },
];
pub const DEVICES: &[DeviceInfo<'static>] = &[DeviceInfo {
    bus: 0,
    addr: 0x3D,
    name: "SH1106 OLED",
}];

const _: () = umsh_ulcp_device::assert_i2c_tables_fit(BUSES, DEVICES);
