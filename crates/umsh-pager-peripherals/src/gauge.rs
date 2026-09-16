//! Read-only BQ27220 RAM inspection (TI SLUUBD4A, chapters 5–6).
//! Battery parameters are provisioned externally; startup never rewrites them.
use embedded_hal_async::{delay::DelayNs, i2c::I2c};

const ADDRESS: u8 = 0x55;
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
