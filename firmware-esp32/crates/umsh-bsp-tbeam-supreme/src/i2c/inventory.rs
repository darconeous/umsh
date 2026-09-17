//! Startup inventory for the T-Beam Supreme's known onboard addresses.
//!
//! Chip-ID reads select the sensor population. The SH1106 has no chip-ID
//! register; its idle status at a board-supported panel address identifies
//! the panel candidate, which the caller must successfully initialize.
//! No sensor configuration or measurement registers are written.

use embedded_hal_async::i2c::I2c;
use umsh_ulcp::i2c::DeviceInfo;

const UNKNOWN: &str = "Unknown I2C device";
const OLED: &str = "SH1106 OLED";
// SH1106 status: D7=BUSY, D6=display off, D5..D3 unspecified,
// D2..D0=0 (SH1106 v2.3, Read Status). Do not test unspecified bits.
fn idle_panel_status(status: u8) -> bool {
    status & 0x87 == 0
}
const EMPTY: DeviceInfo<'static> = DeviceInfo {
    bus: 0,
    addr: 0,
    name: "",
};

// Six sensor-bus addresses and two PMU-bus addresses. Use the longest
// possible label at each address to check the session's encoding bound.
pub const MAX_DEVICES: [DeviceInfo<'static>; 8] = [
    DeviceInfo {
        bus: 0,
        addr: 0x1C,
        name: "QMC6310U magnetometer",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x3C,
        name: "QMC6310N magnetometer",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x3D,
        name: UNKNOWN,
    },
    DeviceInfo {
        bus: 0,
        addr: 0x76,
        name: "BME280 environmental sensor",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x77,
        name: "BME280 environmental sensor",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x7C,
        name: "QMC6309 magnetometer",
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

pub struct Inventory {
    devices: [DeviceInfo<'static>; MAX_DEVICES.len()],
    len: usize,
    panel: Option<u8>,
}

impl Inventory {
    pub const fn new() -> Self {
        Self {
            devices: [EMPTY; MAX_DEVICES.len()],
            len: 0,
            panel: None,
        }
    }

    pub fn devices(&self) -> &[DeviceInfo<'static>] {
        &self.devices[..self.len]
    }

    pub fn panel_address(&self) -> Option<u8> {
        self.panel
    }

    fn record(&mut self, bus: u8, addr: u8, name: &'static str) {
        self.devices[self.len] = DeviceInfo { bus, addr, name };
        self.len += 1;
    }

    /// Run once after ALDO1 settles, before display or host traffic.
    /// The caller bounds the discovery future with a startup timeout.
    pub async fn discover<I: I2c>(&mut self, bus: &mut I) {
        // Prefer 0x3D, as the display driver does, but do not equate an
        // arbitrary ACK with a panel. Validate the defined status bits.
        let mut status = [0];
        if bus.read(0x3D, &mut status).await.is_ok() {
            if idle_panel_status(status[0]) {
                self.panel = Some(0x3D);
            }
            self.record(0, 0x3D, UNKNOWN);
        }

        for (addr, register, expected, name) in [
            (0x1C, 0x00, 0x80, "QMC6310U magnetometer"),
            (0x3C, 0x00, 0x80, "QMC6310N magnetometer"),
            (0x76, 0xD0, 0x60, "BME280 environmental sensor"),
            (0x77, 0xD0, 0x60, "BME280 environmental sensor"),
            (0x7C, 0x00, 0x90, "QMC6309 magnetometer"),
        ] {
            let mut id = [0];
            if bus.write_read(addr, &[register], &mut id).await.is_ok() {
                // At 0x3C, [0x00] is either the QMC chip-ID pointer or
                // an SH1106 control byte with no following command.
                if addr == 0x3C && id[0] == 0x80 && self.panel.is_none() {
                    // 0x80 is also SH1106's BUSY status. Without the
                    // alternate panel responding, leave this ambiguous
                    // result unnamed and never initialize it as a panel.
                    self.record(0, addr, UNKNOWN);
                } else if id[0] == expected {
                    self.record(0, addr, name);
                } else {
                    if addr == 0x3C && self.panel.is_none() && idle_panel_status(id[0]) {
                        self.panel = Some(addr);
                    }
                    self.record(0, addr, UNKNOWN);
                }
            }
        }
    }

    /// Reuse startup driver results; property reads never touch the bus.
    pub fn finish(&mut self, panel_initialized: bool, pmic_present: bool, rtc_present: bool) {
        if panel_initialized {
            if let Some(addr) = self.panel {
                for device in &mut self.devices[..self.len] {
                    if device.bus == 0 && device.addr == addr {
                        device.name = OLED;
                    }
                }
            }
        }
        if pmic_present {
            self.record(1, 0x34, "AXP2101 PMIC");
        }
        if rtc_present {
            self.record(1, 0x51, "PCF8563 real-time clock");
        }
        self.devices[..self.len].sort_unstable_by_key(|device| (device.bus, device.addr));
    }
}
