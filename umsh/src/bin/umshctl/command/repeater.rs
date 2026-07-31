//! `repeater`: report or set autonomous forwarding
//! (`PROP_MAC_REPEATER_*`).
//!
//! Persisted device-domain state: it takes effect once a device identity
//! is provisioned (store-and-defer) and survives reboot. Enabling it
//! makes the on-board node forward overheard routable frames and
//! advertise as a repeater.

use anyhow::{Result, bail};

use umsh::core::RegionCode;
use umsh::ulcp_wire::ids::prop;

use super::persist;
use super::values::{MinRssiArg, MinSnrArg, OptRegionArg, RegionListArg};
use crate::App;
use crate::output::{subfield, warn};

#[derive(Debug, clap::Subcommand)]
pub enum RepeaterOp {
    /// Print the whole forwarding policy.
    Show,
    /// Forward overheard frames and advertise as a repeater.
    On,
    /// Stop forwarding.
    Off,
    /// Only flood-forward packets tagged with one of these regions;
    /// `none` clears the filter, which forwards regardless of region.
    Regions {
        #[arg(value_name = "CODE[,...]|none")]
        list: RegionListArg,
    },
    /// Tag untagged floods with this region before forwarding; `none`
    /// forwards them untagged.
    DefaultRegion {
        #[arg(value_name = "CODE|none")]
        code: OptRegionArg,
    },
    /// Only forward frames heard at or above this RSSI.
    MinRssi {
        #[arg(value_name = "DBM|none", allow_hyphen_values = true)]
        dbm: MinRssiArg,
    },
    /// Only forward frames heard at or above this SNR.
    MinSnr {
        #[arg(value_name = "DB|none", allow_hyphen_values = true)]
        db: MinSnrArg,
    },
}

pub async fn run(app: &mut App, op: Option<RepeaterOp>) -> Result<()> {
    let no_save = app.no_save;
    let device = app.device()?;
    match op.unwrap_or(RepeaterOp::Show) {
        RepeaterOp::Show => {
            let Some(policy) = device.repeater_policy().await? else {
                bail!("device does not advertise CAP_REPEATER");
            };
            print_enabled(Some(policy.enabled as u8));
            subfield("regions", format_regions(&policy.regions));
            match policy.default_region {
                Some(code) => subfield("default", code),
                None => subfield("default", "none (forwards untagged floods untagged)"),
            }
            match policy.min_rssi {
                Some(dbm) => subfield("min rssi", format!("{dbm} dBm")),
                None => subfield("min rssi", "any"),
            }
            match policy.min_snr {
                Some(db) => subfield("min snr", format!("{db} dB")),
                None => subfield("min snr", "any"),
            }
            if policy.enabled
                && policy.default_region.is_some_and(|code| {
                    !policy.regions.is_empty() && !policy.regions.contains(&code)
                })
            {
                // Legal, and not enforced by the device: the two
                // properties are written independently. Still almost
                // always a mistake, since this repeater tags floods with
                // a region it will not itself forward.
                warn(
                    "the default region is not in the forwarding list; floods this repeater \
                     tags will not be forwarded by it",
                );
            }
            return Ok(());
        }
        RepeaterOp::On => set_enabled(device, true).await?,
        RepeaterOp::Off => set_enabled(device, false).await?,
        RepeaterOp::Regions { list } => {
            let stored = device.set_repeater_regions(&list.0).await?;
            println!("repeater regions {}", format_regions(&stored));
            if stored.len() < list.0.len() {
                warn(format!(
                    "the device kept {} of {} regions (capacity)",
                    stored.len(),
                    list.0.len()
                ));
            }
        }
        RepeaterOp::DefaultRegion { code } => {
            match device.set_repeater_default_region(code.0).await? {
                Some(code) => println!("repeater default region {code}"),
                None => println!("repeater default region none (forwards untagged)"),
            }
        }
        RepeaterOp::MinRssi { dbm } => match device.set_repeater_min_rssi(dbm.0).await? {
            Some(dbm) => println!("repeater min rssi {dbm} dBm"),
            None => println!("repeater min rssi any"),
        },
        RepeaterOp::MinSnr { db } => match device.set_repeater_min_snr(db.0).await? {
            Some(db) => println!("repeater min snr {db} dB"),
            None => println!("repeater min snr any"),
        },
    }
    persist(device, no_save).await
}

async fn set_enabled(
    device: &mut umsh::ulcp::UlcpDevice<crate::connection::SessionLink>,
    enabled: bool,
) -> Result<()> {
    let echoed = device
        .set_prop(prop::MAC_REPEATER_ENABLED, &[enabled as u8])
        .await?;
    print_enabled(echoed.first().copied());
    Ok(())
}

fn print_enabled(byte: Option<u8>) {
    match byte {
        Some(0) => println!("repeater off"),
        Some(_) => println!("repeater on (on-board node forwards overheard frames)"),
        None => println!("repeater state unknown (empty value)"),
    }
}

/// Render a region list for display, naming the empty list as what it
/// means rather than printing nothing.
pub fn format_regions(regions: &[RegionCode]) -> String {
    if regions.is_empty() {
        return "any (no regional restriction)".to_string();
    }
    regions
        .iter()
        .map(RegionCode::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_region_list_says_what_it_means() {
        assert_eq!(format_regions(&[]), "any (no regional restriction)");
        assert_eq!(
            format_regions(&[RegionCode::from_iata("SJC").unwrap()]),
            "SJC"
        );
    }
}
