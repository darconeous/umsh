//! `phy`: report or set the radio's enable state and LoRa parameters.
//!
//! The PHY must be enabled before the radio can receive, forward, or
//! transmit—so an autonomous node or repeater needs `phy on`.

use anyhow::{Result, bail};

use umsh::ulcp::{FrameLink, UlcpDevice, UlcpError};
use umsh::ulcp_wire::Status;
use umsh::ulcp_wire::ids::prop;

use super::{decode_u32, persist};
use crate::App;
use crate::output::field;

#[derive(Debug, clap::Subcommand)]
pub enum PhyOp {
    /// Print the enable state and LoRa parameters.
    Show,
    /// Enable the radio.
    On,
    /// Disable the radio.
    Off,
    /// Set the frequency in kHz.
    Freq {
        #[arg(value_name = "KHZ")]
        khz: u32,
    },
    /// Set the LoRa spreading factor.
    Sf {
        #[arg(value_parser = clap::value_parser!(u8).range(5..=12))]
        sf: u8,
    },
    /// Set the LoRa bandwidth in Hz.
    Bw {
        #[arg(value_name = "HZ")]
        hz: u32,
    },
    /// Set the LoRa coding-rate denominator (4/N).
    Cr {
        #[arg(value_parser = clap::value_parser!(u8).range(5..=8))]
        cr: u8,
    },
    /// Set the transmit power in dBm.
    Power {
        #[arg(value_name = "DBM", allow_hyphen_values = true)]
        dbm: i8,
    },
}

pub async fn run(app: &mut App, op: Option<PhyOp>) -> Result<()> {
    let no_save = app.no_save;
    let device = app.device()?;
    match op.unwrap_or(PhyOp::Show) {
        PhyOp::Show => return report(device).await,
        PhyOp::On => set_enabled(device, true).await?,
        PhyOp::Off => set_enabled(device, false).await?,
        PhyOp::Freq { khz } => {
            let echoed = device.set_prop(prop::PHY_FREQ, &khz.to_le_bytes()).await?;
            println!("phy freq {} kHz", decode_u32(&echoed).unwrap_or(khz));
        }
        PhyOp::Sf { sf } => {
            let echoed = device.set_prop(prop::PHY_LORA_SF, &[sf]).await?;
            println!("phy SF{}", echoed.first().copied().unwrap_or(sf));
        }
        PhyOp::Bw { hz } => {
            let echoed = device
                .set_prop(prop::PHY_LORA_BW, &hz.to_le_bytes())
                .await?;
            println!("phy BW {} Hz", decode_u32(&echoed).unwrap_or(hz));
        }
        PhyOp::Cr { cr } => {
            let echoed = device.set_prop(prop::PHY_LORA_CR, &[cr]).await?;
            println!("phy CR 4/{}", echoed.first().copied().unwrap_or(cr));
        }
        PhyOp::Power { dbm } => {
            let echoed = device.set_prop(prop::PHY_TX_POWER, &[dbm as u8]).await?;
            let dbm = echoed.first().copied().map_or(dbm, |byte| byte as i8);
            println!("phy TX {dbm} dBm");
        }
    }
    persist(device, no_save).await
}

async fn set_enabled<L: FrameLink>(device: &mut UlcpDevice<L>, on: bool) -> Result<()> {
    let echoed = device.set_prop(prop::PHY_ENABLED, &[on as u8]).await?;
    let on = echoed.first().copied().unwrap_or(on as u8) != 0;
    println!("phy {}", if on { "enabled" } else { "disabled" });
    Ok(())
}

/// What `phy` reports and `capture` narrates, asked for together.
const RF_KEYS: [u32; 6] = [
    prop::PHY_FREQ,
    prop::PHY_LORA_BW,
    prop::PHY_LORA_SF,
    prop::PHY_LORA_CR,
    prop::PHY_LORA_SW,
    prop::PHY_TX_POWER,
];

/// Print the current PHY enable state and LoRa parameters on one line.
pub async fn report<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<()> {
    let mut keys = vec![prop::PHY_ENABLED];
    keys.extend(RF_KEYS);
    let answers = device.read_each(&keys).await?;
    let Some((enabled, rf)) = answers.split_first() else {
        bail!("the device answered none of the PHY properties");
    };
    let enabled = match enabled {
        Ok(value) => value.first().copied().unwrap_or(0) != 0,
        Err(status) => return Err(UlcpError::Status(*status).into()),
    };
    let mut parts = vec![if enabled { "enabled" } else { "disabled" }.to_string()];
    parts.extend(rf_parts_of(rf));
    field("phy", parts.join(", "));
    Ok(())
}

/// The frequency, LoRa modulation, and transmit power, in one exchange.
pub async fn rf_parts<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<Vec<String>> {
    Ok(rf_parts_of(&device.read_each(&RF_KEYS).await?))
}

/// [`RF_KEYS`]'s answers as report fragments, each omitted when the
/// device would not report it.
fn rf_parts_of(answers: &[Result<Vec<u8>, Status>]) -> Vec<String> {
    let value = |key: u32| {
        RF_KEYS
            .iter()
            .position(|&asked| asked == key)
            .and_then(|index| answers.get(index))
            .and_then(|answer| answer.as_deref().ok())
    };
    let mut parts = Vec::new();
    if let Some(freq) = value(prop::PHY_FREQ).and_then(decode_u32) {
        parts.push(format!("{freq} kHz"));
    }
    if let Some(bw) = value(prop::PHY_LORA_BW).and_then(decode_u32) {
        parts.push(format!("BW {bw} Hz"));
    }
    if let Some(&sf) = value(prop::PHY_LORA_SF).and_then(<[u8]>::first) {
        parts.push(format!("SF{sf}"));
    }
    if let Some(&cr) = value(prop::PHY_LORA_CR).and_then(<[u8]>::first) {
        parts.push(format!("CR 4/{cr}"));
    }
    if let Some(sw) = value(prop::PHY_LORA_SW)
        .and_then(|value| <[u8; 2]>::try_from(value).ok())
        .map(u16::from_le_bytes)
    {
        parts.push(format!("sync 0x{sw:04x}"));
    }
    if let Some(&power) = value(prop::PHY_TX_POWER).and_then(<[u8]>::first) {
        parts.push(format!("TX {} dBm", power as i8));
    }
    parts
}
