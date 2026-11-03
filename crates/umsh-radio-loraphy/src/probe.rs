//! Tell an SX126x from an LR11xx on a board that takes either.
//!
//! Both families share a pinout on boards like the T-LoRa Pager: SPI,
//! NSS, RESET, BUSY, and an IRQ line. [`identify`] talks to whatever is
//! fitted over raw SPI before a driver takes the bus, and names the
//! family only on a positive answer from that family's own command:
//!
//! - **LR11xx** `GetVersion` (opcode `0x0101`): a separate response read
//!   whose `Stat1` reports success and whose chip-type byte is LR1110,
//!   LR1120, or LR1121. An SX126x clocks out status bytes or idle bus
//!   levels there, never a chip type in that range.
//! - **SX126x** `ReadRegister 0x0320`: the 16-byte version string,
//!   `"SX1261 …"` on both the SX1261 and SX1262. This is the check
//!   RadioLib uses.
//!
//! The other family's opcode raises only a command error in the chip
//! that receives it. `LoRa::new` resets the chip before configuring it,
//! so nothing the probe leaves behind reaches the driver.

use core::future::Future;

use embassy_futures::select::{Either, select};
use embedded_hal::digital::{InputPin, OutputPin};
use embedded_hal_async::{
    delay::DelayNs,
    spi::{Operation, SpiDevice},
};
use lora_phy::lr1110::{ChipType, CommandStatus, Stat1, Version};

/// How long any one BUSY wait may last. An LR11xx boots from reset in
/// tens of milliseconds and either family finishes a command in
/// microseconds; this is generous for both, and short enough that a
/// stuck chip is reported well inside a caller's overall deadline.
pub const BUSY_LIMIT_MS: u32 = 300;

/// BUSY is sampled this often while waiting.
const BUSY_POLL_US: u32 = 100;

/// NRESET low time. Both families need at least 100 µs.
const RESET_LOW_MS: u32 = 1;

const LR11XX_GET_VERSION: [u8; 2] = [0x01, 0x01];
const SX126X_READ_REGISTER: u8 = 0x1D;
const SX126X_VERSION_STRING: u16 = 0x0320;
const SX126X_VERSION_PREFIX: &[u8] = b"SX126";

/// The radio family that answered.
#[derive(Clone, Copy, Debug)]
pub enum ChipFamily {
    /// An SX1261/SX1262/SX1268: the version string does not tell them apart.
    Sx126x,
    /// An LR1110, LR1120, or LR1121, with what it reported.
    Lr11xx(Version),
}

/// The step after which BUSY failed to fall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Reset,
    GetVersion,
    ReadRegister,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// BUSY stayed high for [`BUSY_LIMIT_MS`] after `after`.
    BusyStuck { after: Step },
    /// The SPI bus or a control pin returned an error.
    Bus,
    /// Something answered, but as neither family.
    Unknown,
}

/// Reset the radio and identify its family.
///
/// Leaves the chip idle. Every BUSY wait is bounded by
/// [`BUSY_LIMIT_MS`]; callers should still put the probe and driver
/// initialization together under one deadline with [`init_within`].
pub async fn identify<S, R, B, D>(
    spi: &mut S,
    reset: &mut R,
    busy: &mut B,
    delay: &mut D,
) -> Result<ChipFamily, ProbeError>
where
    S: SpiDevice,
    R: OutputPin,
    B: InputPin,
    D: DelayNs,
{
    reset.set_low().map_err(|_| ProbeError::Bus)?;
    delay.delay_ms(RESET_LOW_MS).await;
    reset.set_high().map_err(|_| ProbeError::Bus)?;
    wait_busy_low(busy, delay, Step::Reset).await?;

    // LR11xx: the command, then its response in a transaction of its own.
    spi.write(&LR11XX_GET_VERSION)
        .await
        .map_err(|_| ProbeError::Bus)?;
    wait_busy_low(busy, delay, Step::GetVersion).await?;
    let mut response = [0u8; 5];
    spi.read(&mut response).await.map_err(|_| ProbeError::Bus)?;
    if let Some(version) = lr11xx_version(&response) {
        return Ok(ChipFamily::Lr11xx(version));
    }

    // SX126x: opcode, address, a status byte, then the register bytes.
    wait_busy_low(busy, delay, Step::GetVersion).await?;
    let [high, low] = SX126X_VERSION_STRING.to_be_bytes();
    let mut version = [0u8; 16];
    spi.transaction(&mut [
        Operation::Write(&[SX126X_READ_REGISTER, high, low, 0x00]),
        Operation::Read(&mut version),
    ])
    .await
    .map_err(|_| ProbeError::Bus)?;
    wait_busy_low(busy, delay, Step::ReadRegister).await?;
    if version.starts_with(SX126X_VERSION_PREFIX) {
        return Ok(ChipFamily::Sx126x);
    }
    Err(ProbeError::Unknown)
}

/// Decode a `GetVersion` response (`Stat1`, hardware, type, firmware),
/// or `None` if it is not one.
fn lr11xx_version(response: &[u8; 5]) -> Option<Version> {
    let stat1 = Stat1::from(response[0]);
    if !matches!(
        stat1.command_status,
        CommandStatus::Ok | CommandStatus::Data
    ) {
        return None;
    }
    let chip_type = ChipType::from(response[2]);
    if chip_type == ChipType::Unknown {
        return None;
    }
    Some(Version {
        hw: response[1],
        chip_type,
        fw: u16::from_be_bytes([response[3], response[4]]),
    })
}

async fn wait_busy_low<B: InputPin, D: DelayNs>(
    busy: &mut B,
    delay: &mut D,
    after: Step,
) -> Result<(), ProbeError> {
    for _ in 0..BUSY_LIMIT_MS * 1_000 / BUSY_POLL_US {
        if busy.is_low().map_err(|_| ProbeError::Bus)? {
            return Ok(());
        }
        delay.delay_us(BUSY_POLL_US).await;
    }
    Err(ProbeError::BusyStuck { after })
}

/// `deadline` completed before `init` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimedOut;

/// Run a board's whole radio bring-up—probe, driver construction, and
/// `LoRa::new`—under one deadline, so a chip that wedges anywhere in it
/// cannot hang boot. `init` is dropped when `deadline` completes first.
pub async fn init_within<T>(
    deadline: impl Future<Output = ()>,
    init: impl Future<Output = T>,
) -> Result<T, TimedOut> {
    match select(init, deadline).await {
        Either::First(value) => Ok(value),
        Either::Second(()) => Err(TimedOut),
    }
}
