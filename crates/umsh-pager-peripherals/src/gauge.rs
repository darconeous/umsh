//! Temporary Pager BQ27220 RAM profile override (TI SLUUBD4A, chapters 5–6).
//! No OTP programming, calibration, or changes to charger policy.
//! Production firmware should trust factory-programmed parameters instead.
use embedded_hal_async::{delay::DelayNs, i2c::I2c};

const ADDRESS: u8 = 0x55;
// Selected Pager profile; 1800 mAh is an estimate pending cell qualification.
pub const STOCK_CAPACITY_MAH: u16 = 1800;
pub const TAPER_CURRENT_MA: u16 = 220;
const TAPER_ADDRESS: u16 = 0x9201;
const CONFIG_UPDATE: u16 = 1 << 10;
const SECURITY: u16 = 6;
const FULL_ACCESS: u16 = 2;
const UNSEALED: u16 = 4;
const SEALED: u16 = 6;

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError<E> {
    Bus(E),
    Timeout,
    InvalidSecurity,
    ConfigurationBusy,
    InvalidField,
    InvalidBlock {
        address: u16,
        echoed: u16,
        length: u8,
        checksum: u8,
        calculated: u8,
    },
    MemoryVerify([u8; 6]),
    TaperVerify(u16),
    CapacityVerify {
        design_mah: u16,
        full_mah: u16,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct CapacityConfig {
    pub changed: bool,
    pub design_mah: u16,
    pub full_mah: u16,
    pub taper_ma: u16,
}

struct Gauge<'a, I, D> {
    i2c: &'a mut I,
    delay: &'a mut D,
}

impl<I: I2c, D: DelayNs> Gauge<'_, I, D> {
    // TI security-state-machine FAQ (E2E 1106900): no communication to the
    // gauge for four seconds before a key sequence; halves within four seconds.
    // The battery owner keeps ordinary polling suspended while we await this.
    async fn inspection_key(
        &mut self,
        first: u16,
        second: u16,
        expected: u16,
    ) -> Result<(), ConfigError<I::Error>> {
        self.delay.delay_ms(4000).await;
        self.command(first).await?;
        self.command(second).await?;
        self.wait(SECURITY, expected).await
    }

    async fn inspection_unseal(&mut self) -> Result<(), ConfigError<I::Error>> {
        match self.inspection_key(0x0414, 0x3672, UNSEALED).await {
            Err(ConfigError::Timeout) => self.inspection_key(0x8000, 0x8000, UNSEALED).await,
            result => result,
        }
    }

    async fn configuration_block(
        &mut self,
        address: u16,
        required: usize,
    ) -> Result<[u8; 32], ConfigError<I::Error>> {
        let [lo, hi] = address.to_le_bytes();
        self.byte(0x3e, lo).await?;
        self.delay.delay_ms(10).await;
        self.byte(0x3f, hi).await?;
        self.delay.delay_ms(10).await;
        // Read the echoed address, data, checksum and length together. Never
        // write MACData, checksum or length: those would commit parameters.
        let mut block = [0; 36];
        self.read(0x3e, &mut block).await?;
        let length = usize::from(block[35]);
        let calculated = !block[..length.saturating_sub(2).min(34)]
            .iter()
            .copied()
            .fold(0u8, u8::wrapping_add);
        if !(4..=36).contains(&length)
            || length - 4 < required
            || block[..2] != [lo, hi]
            || block[..length - 2]
                .iter()
                .copied()
                .fold(0u8, u8::wrapping_add)
                != !block[34]
        {
            return Err(ConfigError::InvalidBlock {
                address,
                echoed: u16::from_le_bytes([block[0], block[1]]),
                length: block[35],
                checksum: block[34],
                calculated,
            });
        }
        let mut data = [0; 32];
        data.copy_from_slice(&block[2..34]);
        Ok(data)
    }

    async fn read(&mut self, reg: u8, out: &mut [u8]) -> Result<(), ConfigError<I::Error>> {
        let result = self.i2c.write_read(ADDRESS, &[reg], out).await;
        self.delay.delay_us(100).await;
        result.map_err(ConfigError::Bus)
    }

    async fn word(&mut self, reg: u8) -> Result<u16, ConfigError<I::Error>> {
        let mut bytes = [0; 2];
        self.read(reg, &mut bytes).await?;
        Ok(u16::from_le_bytes(bytes))
    }

    async fn byte(&mut self, reg: u8, value: u8) -> Result<(), ConfigError<I::Error>> {
        // TI requires single-byte writes above 100 kHz and >=66 us bus-free.
        let result = self.i2c.write(ADDRESS, &[reg, value]).await;
        self.delay.delay_us(100).await;
        result.map_err(ConfigError::Bus)
    }

    async fn command(&mut self, command: u16) -> Result<(), ConfigError<I::Error>> {
        let [lo, hi] = command.to_le_bytes();
        self.byte(0, lo).await?;
        self.byte(1, hi).await?;
        self.delay.delay_ms(10).await;
        Ok(())
    }

    async fn wait(&mut self, mask: u16, expected: u16) -> Result<(), ConfigError<I::Error>> {
        for _ in 0..6 {
            self.delay.delay_ms(500).await;
            if self.word(0x3a).await? & mask == expected {
                return Ok(());
            }
        }
        Err(ConfigError::Timeout)
    }

    async fn restore_access(&mut self, security: u16) -> Result<(), ConfigError<I::Error>> {
        if self.word(0x3a).await? & SECURITY == security {
            return Ok(());
        }
        self.command(0x0030).await?;
        self.wait(SECURITY, SEALED).await?;
        if security == UNSEALED {
            self.inspection_unseal().await?;
        }
        Ok(())
    }

    async fn write_capacities(&mut self) -> Result<(), ConfigError<I::Error>> {
        // Contiguous RAM parameters: FCC at 0x929D, design at 0x929F.
        // Address is LE, parameter values are BE (unlike standard commands).
        // One checksum commit updates the pair, so a failed partial transfer
        // cannot leave a corrected design capacity beside the old default FCC.
        let [hi, lo] = STOCK_CAPACITY_MAH.to_be_bytes();
        let data = [0x9d, 0x92, hi, lo, hi, lo];
        self.select_capacity_ram().await?;
        for (offset, value) in data[2..].iter().copied().enumerate() {
            self.byte(0x40 + offset as u8, value).await?;
        }
        let sum = data.into_iter().fold(0u8, u8::wrapping_add);
        self.byte(0x60, !sum).await?;
        self.byte(0x61, 8).await?; // address + four data bytes + checksum/length
        self.delay.delay_ms(10).await;

        self.select_capacity_ram().await?;
        let mut actual = [0; 6];
        self.read(0x3e, &mut actual).await?;
        if actual != data {
            return Err(ConfigError::MemoryVerify(actual));
        }
        Ok(())
    }

    async fn taper_current(&mut self) -> Result<u16, ConfigError<I::Error>> {
        let data = self.configuration_block(TAPER_ADDRESS, 2).await?;
        Ok(u16::from_be_bytes([data[0], data[1]]))
    }

    async fn write_taper(&mut self) -> Result<(), ConfigError<I::Error>> {
        let [lo, hi] = TAPER_ADDRESS.to_le_bytes();
        let [value_hi, value_lo] = TAPER_CURRENT_MA.to_be_bytes();
        self.byte(0x3e, lo).await?;
        self.delay.delay_ms(10).await;
        self.byte(0x3f, hi).await?;
        self.delay.delay_ms(10).await;
        self.byte(0x40, value_hi).await?;
        self.byte(0x41, value_lo).await?;
        let sum = [lo, hi, value_hi, value_lo]
            .into_iter()
            .fold(0u8, u8::wrapping_add);
        self.byte(0x60, !sum).await?;
        self.byte(0x61, 6).await?;
        self.delay.delay_ms(10).await;
        let actual = self.taper_current().await?;
        if actual != TAPER_CURRENT_MA {
            return Err(ConfigError::TaperVerify(actual));
        }
        Ok(())
    }

    async fn select_capacity_ram(&mut self) -> Result<(), ConfigError<I::Error>> {
        // Match LilyGo's address-selection settling time. The 100 us bus-free
        // interval alone does not let the gauge populate its MAC buffer before
        // we modify it; on hardware that caused the capacity write to be lost.
        self.byte(0x3e, 0x9d).await?;
        self.delay.delay_ms(10).await;
        self.byte(0x3f, 0x92).await?;
        self.delay.delay_ms(10).await;
        Ok(())
    }
}

/// Inspect the live RAM profile without entering configuration mode, committing
/// data, resetting the gauge, or changing learned capacity. The caller must not
/// cancel this future: cleanup must finish even if the requesting host leaves.
pub async fn inspect_configuration<I: I2c>(
    i2c: &mut I,
    delay: &mut impl DelayNs,
) -> Result<umsh_ulcp::battery_gauge_config::Config, ConfigError<I::Error>> {
    use umsh_ulcp::battery_gauge_config::{Config, FIELDS};
    let mut gauge = Gauge { i2c, delay };
    let operation = gauge.word(0x3a).await?;
    let security = operation & SECURITY;
    if !matches!(security, FULL_ACCESS | UNSEALED | SEALED) {
        return Err(ConfigError::InvalidSecurity);
    }
    if operation & CONFIG_UPDATE != 0 {
        return Err(ConfigError::ConfigurationBusy);
    }
    let result = async {
        if security == SEALED {
            gauge.inspection_unseal().await?;
        }
        // On BQ27220, UNSEALED alone does not grant RAM access: address
        // selection is ignored and MACData still contains the prior command's
        // reply. FULL_ACCESS permits reads without entering CFGUPDATE.
        if security != FULL_ACCESS {
            gauge.inspection_key(0xffff, 0xffff, FULL_ACCESS).await?;
        }
        let mut config = Config::default();
        for (address, len) in CONFIG_BLOCKS {
            let data = gauge.configuration_block(address, len).await?;
            for (index, field) in FIELDS.iter().enumerate() {
                if field.address >= address
                    && usize::from(field.address - address) + field.width <= len
                {
                    let start = usize::from(field.address - address);
                    let value = data[start..start + field.width]
                        .iter()
                        .fold(0u32, |value, byte| (value << 8) | u32::from(*byte));
                    config
                        .set(index, value)
                        .map_err(|_| ConfigError::InvalidField)?;
                }
            }
        }
        Ok(config)
    }
    .await;
    // Always attempt sealing after an attempted unseal, even when the access
    // read or a key write failed. Do not let an I2C error skip this cleanup.
    if security != FULL_ACCESS {
        gauge.command(0x0030).await?;
        if gauge.word(0x3a).await? & SECURITY != SEALED {
            gauge.wait(SECURITY, SEALED).await?;
        }
        if security == UNSEALED {
            gauge.inspection_unseal().await?;
        }
    }
    result
}

pub(crate) const CONFIG_BLOCKS: [(u16, usize); 8] = [
    (0x9184, 8),
    (0x91de, 2),
    (0x91fb, 16),
    (0x9228, 6),
    (0x9251, 32),
    (0x9271, 32),
    (0x929a, 26),
    (0x92b4, 31),
];

/// Called by the battery owner before normal sampling. Correct a mismatched
/// capacity/taper profile; preserve learned FCC when design already matches.
/// Inspect taper RAM on every boot, but only enter configuration mode on mismatch.
/// Every wait is bounded. Once configuration entry is attempted, always try to
/// leave it, including on I2C errors, and restore the original security mode.
pub async fn ensure_stock_capacity<I: I2c>(
    i2c: &mut I,
    delay: &mut impl DelayNs,
) -> Result<CapacityConfig, ConfigError<I::Error>> {
    let mut gauge = Gauge { i2c, delay };
    let operation = gauge.word(0x3a).await?;
    let security = operation & SECURITY;
    if !matches!(security, FULL_ACCESS | UNSEALED | SEALED) {
        return Err(ConfigError::InvalidSecurity);
    }
    // Recover a configuration pass interrupted by an ESP32 reset.
    if operation & CONFIG_UPDATE != 0 {
        gauge.command(0x0091).await?;
        gauge.wait(CONFIG_UPDATE, 0).await?;
    }
    let design = gauge.word(0x3c).await?;
    let previous_full = gauge.word(0x12).await?;
    let capacity_changed = design != STOCK_CAPACITY_MAH;

    let mut entry_attempted = false;
    let update = async {
        if security == SEALED {
            gauge.inspection_unseal().await?;
        }
        if security != FULL_ACCESS {
            gauge.inspection_key(0xffff, 0xffff, FULL_ACCESS).await?;
        }
        let taper = gauge.taper_current().await?;
        if design == STOCK_CAPACITY_MAH && taper == TAPER_CURRENT_MA {
            return Ok(false);
        }
        entry_attempted = true;
        gauge.command(0x0090).await?;
        // TI specifies at least 1100 ms before using configuration mode.
        gauge.delay.delay_ms(1100).await;
        gauge.wait(CONFIG_UPDATE, CONFIG_UPDATE).await?;
        if taper != TAPER_CURRENT_MA {
            gauge.write_taper().await?;
        }
        if design != STOCK_CAPACITY_MAH {
            gauge.write_capacities().await?;
        }
        Ok(true)
    }
    .await;

    let exit = if entry_attempted {
        async {
            gauge.command(0x0091).await?;
            gauge.wait(CONFIG_UPDATE, 0).await
        }
        .await
    } else {
        Ok(())
    };
    // Also attempt restoration after a failed exit, without hiding that error.
    let restore = if security != FULL_ACCESS {
        gauge.restore_access(security).await
    } else {
        Ok(())
    };
    exit?;
    restore?;
    let changed = update?;
    if !changed {
        return Ok(CapacityConfig {
            changed: false,
            design_mah: design,
            full_mah: previous_full,
            taper_ma: TAPER_CURRENT_MA,
        });
    }
    // Standard readback, after reinitialization, is the final acceptance gate.
    gauge.delay.delay_ms(2000).await;
    let design = gauge.word(0x3c).await?;
    let full = gauge.word(0x12).await?;
    if design != STOCK_CAPACITY_MAH
        || full
            != if capacity_changed {
                STOCK_CAPACITY_MAH
            } else {
                previous_full
            }
    {
        return Err(ConfigError::CapacityVerify {
            design_mah: design,
            full_mah: full,
        });
    }
    Ok(CapacityConfig {
        changed: true,
        design_mah: design,
        full_mah: full,
        taper_ma: TAPER_CURRENT_MA,
    })
}
