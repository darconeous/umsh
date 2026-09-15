//! Stock-cell BQ27220 RAM configuration (TI SLUUBD4A, chapters 5–6).
//! No OTP programming, calibration, or changes to charger policy.
use embedded_hal_async::{delay::DelayNs, i2c::I2c};

const ADDRESS: u8 = 0x55;
pub const STOCK_CAPACITY_MAH: u16 = 1500;
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
    MemoryVerify([u8; 6]),
    CapacityVerify { design_mah: u16, full_mah: u16 },
}

#[derive(Debug, PartialEq, Eq)]
pub struct CapacityConfig {
    pub changed: bool,
    pub design_mah: u16,
    pub full_mah: u16,
}

struct Gauge<'a, I, D> {
    i2c: &'a mut I,
    delay: &'a mut D,
}

impl<I: I2c, D: DelayNs> Gauge<'_, I, D> {
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

    async fn unseal(&mut self) -> Result<(), ConfigError<I::Error>> {
        // LilyGo's factory key (also TI chapter 6's example).
        self.command(0x0414).await?;
        self.command(0x3672).await?;
        if self.word(0x3a).await? & SECURITY == SEALED {
            // TI section 3.3 also documents this ROM-default key.
            self.command(0x8000).await?;
            self.command(0x8000).await?;
        }
        self.wait(SECURITY, UNSEALED).await
    }

    async fn restore_access(&mut self, security: u16) -> Result<(), ConfigError<I::Error>> {
        if self.word(0x3a).await? & SECURITY == security {
            return Ok(());
        }
        self.command(0x0030).await?;
        self.wait(SECURITY, SEALED).await?;
        if security == UNSEALED {
            self.unseal().await?;
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

/// Called by the battery owner before normal sampling. Correct a mismatched
/// stock-cell profile; preserve the learned FCC when design is already 1500.
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
    if design == STOCK_CAPACITY_MAH {
        return Ok(CapacityConfig {
            changed: false,
            design_mah: design,
            full_mah: gauge.word(0x12).await?,
        });
    }

    let mut entry_attempted = false;
    let update = async {
        if security == SEALED {
            gauge.unseal().await?;
        }
        if security != FULL_ACCESS {
            gauge.command(0xffff).await?;
            gauge.command(0xffff).await?;
            gauge.wait(SECURITY, FULL_ACCESS).await?;
        }
        entry_attempted = true;
        gauge.command(0x0090).await?;
        // TI specifies at least 1100 ms before using configuration mode.
        gauge.delay.delay_ms(1100).await;
        gauge.wait(CONFIG_UPDATE, CONFIG_UPDATE).await?;
        gauge.write_capacities().await
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
    update?;
    // Standard readback, after reinitialization, is the final acceptance gate.
    gauge.delay.delay_ms(2000).await;
    let design = gauge.word(0x3c).await?;
    let full = gauge.word(0x12).await?;
    if design != STOCK_CAPACITY_MAH || full != STOCK_CAPACITY_MAH {
        return Err(ConfigError::CapacityVerify {
            design_mah: design,
            full_mah: full,
        });
    }
    Ok(CapacityConfig {
        changed: true,
        design_mah: design,
        full_mah: full,
    })
}
