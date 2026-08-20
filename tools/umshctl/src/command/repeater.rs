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
use super::values::{MinRssiArg, MinSnrArg, OptRegionArg, RegionArg, RegionListArg};
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
    /// Only flood-forward packets tagged with one of these regions.
    Regions {
        #[command(subcommand)]
        op: Option<RegionOp>,
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

/// A region is written as a short code, a name, or a literal
/// `0x1234`; the device stores the string and derives the 2-octet code
/// its forwarding filter compares.
#[derive(Debug, clap::Subcommand)]
pub enum RegionOp {
    /// List the regions the device forwards for.
    List,
    /// Add one region to the filter.
    Add {
        #[arg(value_name = "REGION")]
        region: RegionArg,
    },
    /// Remove one region from the filter.
    Remove {
        #[arg(value_name = "REGION")]
        region: RegionArg,
    },
    /// Replace the whole filter; `none` clears it, which forwards
    /// regardless of region.
    Set {
        #[arg(value_name = "REGION[,...]|none")]
        list: RegionListArg,
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
                    !policy.regions.is_empty() && !region_codes(&policy.regions).contains(&code)
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
        RepeaterOp::Regions { op } => match op.unwrap_or(RegionOp::List) {
            RegionOp::List => {
                let regions = device.repeater_regions().await?;
                println!("repeater regions {}", format_regions(&regions));
                return Ok(());
            }
            RegionOp::Add { region } => {
                device.add_repeater_region(&region.0).await?;
                println!("repeater region added: {}", format_region(&region.0));
            }
            RegionOp::Remove { region } => {
                device.remove_repeater_region(&region.0).await?;
                println!("repeater region removed: {}", format_region(&region.0));
            }
            RegionOp::Set { list } => {
                let stored = device.set_repeater_regions(&list.0).await?;
                println!("repeater regions {}", format_regions(&stored));
                if stored.len() < list.0.len() {
                    warn(format!(
                        "the device kept {} of {} regions (repeats collapse)",
                        stored.len(),
                        list.0.len()
                    ));
                }
            }
        },
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

/// The codes a stored region list derives to, for the cross-checks that
/// compare against a default region.
fn region_codes(regions: &[String]) -> Vec<RegionCode> {
    regions
        .iter()
        .filter_map(|region| region.parse::<RegionCode>().ok())
        .collect()
}

/// Render one region as the operator wrote it, with the code the
/// forwarding filter actually compares — a hashed name is otherwise
/// unrecognizable in a packet capture.
///
/// A short code is shown uppercase whatever case it was written in, which
/// is how airport and country codes are written everywhere else. A name is
/// the operator's to capitalize and is left alone.
pub fn format_region(region: &str) -> String {
    let Ok(code) = region.parse::<RegionCode>() else {
        return region.to_string();
    };
    let hex = format!("0x{:04X}", code.as_u16());
    if region.eq_ignore_ascii_case(&hex) {
        return hex;
    }
    match RegionCode::from_short_code(region).is_ok() {
        true => format!("{} ({hex})", region.to_uppercase()),
        false => format!("{region} ({hex})"),
    }
}

/// Render a region list for display, naming the empty list as what it
/// means rather than printing nothing.
pub fn format_regions(regions: &[String]) -> String {
    if regions.is_empty() {
        return "any (no regional restriction)".to_string();
    }
    regions
        .iter()
        .map(|region| format_region(region))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_region_list_says_what_it_means() {
        assert_eq!(format_regions(&[]), "any (no regional restriction)");
    }

    #[test]
    fn a_region_prints_the_code_its_string_derives_to() {
        assert_eq!(format_region("SJC"), "SJC (0x7853)");
        assert_eq!(format_region("Rogue Valley"), "Rogue Valley (0xC0F9)");
        // A literal already is its code; quoting it twice says nothing.
        assert_eq!(format_region("0x1234"), "0x1234");
    }

    #[test]
    fn a_short_code_prints_uppercase_however_it_was_written() {
        assert_eq!(format_region("sjc"), "SJC (0x7853)");
        assert_eq!(format_region("Sjc"), "SJC (0x7853)");
        assert_eq!(format_region("wa"), "WA (0x8FE8)");
        // A digit-bearing short code has no reading, but it is still a
        // code and is written like one.
        assert_eq!(format_region("w7"), format!("W7 (0x{:04X})", short("w7")));
        // A name keeps the operator's capitalization.
        assert_eq!(format_region("rogue valley"), "rogue valley (0xC0F9)");
    }

    fn short(code: &str) -> u16 {
        RegionCode::from_short_code(code).unwrap().as_u16()
    }
}
