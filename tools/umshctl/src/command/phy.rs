//! `phy`: report or set the radio's enable state and LoRa parameters.
//!
//! The PHY must be enabled before the radio can receive, forward, or
//! transmit — so an autonomous node or repeater needs `phy on`.

use anyhow::Result;

use umsh::ulcp::{FrameLink, UlcpDevice};
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

/// Print the current PHY enable state and LoRa parameters on one line.
pub async fn report<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<()> {
    let enabled = device
        .get_prop(prop::PHY_ENABLED)
        .await?
        .first()
        .copied()
        .unwrap_or(0)
        != 0;
    let mut parts = vec![if enabled { "enabled" } else { "disabled" }.to_string()];
    if let Some(freq) = device
        .get_prop(prop::PHY_FREQ)
        .await
        .ok()
        .and_then(|value| decode_u32(&value))
    {
        parts.push(format!("{freq} kHz"));
    }
    parts.extend(lora_parts(device).await);
    parts.extend(power_part(device).await);
    field("phy", parts.join(", "));
    Ok(())
}

/// The LoRa modulation parameters, each omitted when the device will not
/// report it.
pub async fn lora_parts<L: FrameLink>(device: &mut UlcpDevice<L>) -> Vec<String> {
    let mut parts = Vec::new();
    if let Some(bw) = device
        .get_prop(prop::PHY_LORA_BW)
        .await
        .ok()
        .and_then(|value| decode_u32(&value))
    {
        parts.push(format!("BW {bw} Hz"));
    }
    if let Some(sf) = device
        .get_prop(prop::PHY_LORA_SF)
        .await
        .ok()
        .and_then(|value| value.first().copied())
    {
        parts.push(format!("SF{sf}"));
    }
    if let Some(cr) = device
        .get_prop(prop::PHY_LORA_CR)
        .await
        .ok()
        .and_then(|value| value.first().copied())
    {
        parts.push(format!("CR 4/{cr}"));
    }
    if let Some(sw) = device
        .get_prop(prop::PHY_LORA_SW)
        .await
        .ok()
        .and_then(|value| <[u8; 2]>::try_from(value.as_slice()).ok())
        .map(u16::from_le_bytes)
    {
        parts.push(format!("sync 0x{sw:04x}"));
    }
    parts
}

pub async fn power_part<L: FrameLink>(device: &mut UlcpDevice<L>) -> Option<String> {
    device
        .get_prop(prop::PHY_TX_POWER)
        .await
        .ok()
        .and_then(|value| value.first().copied())
        .map(|power| format!("TX {} dBm", power as i8))
}
