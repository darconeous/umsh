//! `repeater`: report or set autonomous forwarding
//! (`PROP_MAC_REPEATER_*`).
//!
//! Persisted device-domain state: it takes effect once a device identity
//! is provisioned (store-and-defer) and survives reboot. Enabling it
//! makes the on-board node forward overheard routable frames and
//! advertise as a repeater.

use anyhow::{Result, bail};

use umsh::core::RegionCode;
use umsh::ulcp::{MeshCoreRegionPolicy, RepeaterMode, UlcpError, meshcore_identity_allowed};
use umsh::ulcp_wire::Status;
use umsh::ulcp_wire::ids::prop;

use super::persist;
use super::values::{
    MeshCoreRegionArg, MeshCoreRegionListArg, MinRssiArg, MinSnrArg, OptRegionArg, RegionArg,
    RegionListArg,
};
use crate::App;
use crate::output::{UNAVAILABLE, or_unavailable, subfield, warn};

#[derive(Debug, clap::Subcommand)]
pub enum RepeaterOp {
    /// Print the whole forwarding policy.
    Show,
    /// Forward overheard frames and advertise as a repeater.
    On,
    /// Forward only what no repeater was heard carrying.
    Adaptive,
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
    /// Forward MeshCore traffic too.
    Meshcore {
        #[command(subcommand)]
        op: MeshCoreOp,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum MeshCoreOp {
    /// Forward MeshCore traffic.
    On,
    /// Stop forwarding MeshCore traffic.
    Off,
    /// Which MeshCore floods to forward by region scope.
    Policy {
        #[arg(value_name = "open|scoped|ignore", value_parser = parse_policy)]
        policy: MeshCoreRegionPolicy,
    },
    /// The MeshCore regions whose scoped floods are forwarded.
    Regions {
        #[command(subcommand)]
        op: Option<MeshCoreRegionOp>,
    },
}

/// MeshCore region names are case-sensitive and written without their
/// `#`, which the device supplies; a typed `#` is dropped.
#[derive(Debug, clap::Subcommand)]
pub enum MeshCoreRegionOp {
    /// List the MeshCore regions.
    List,
    /// Add one MeshCore region.
    Add {
        #[arg(value_name = "NAME")]
        name: MeshCoreRegionArg,
    },
    /// Remove one MeshCore region.
    Remove {
        #[arg(value_name = "NAME")]
        name: MeshCoreRegionArg,
    },
    /// Replace the whole list; `none` clears it.
    Set {
        #[arg(value_name = "NAME[,...]|none")]
        list: MeshCoreRegionListArg,
    },
}

fn parse_policy(name: &str) -> Result<MeshCoreRegionPolicy, String> {
    name.parse()
        .map_err(|()| "expected open, scoped, or ignore".to_string())
}

/// Shown wherever MeshCore forwarding is unavailable under the identity.
const RESERVED_IDENTITY: &str = "MeshCore reserves identity keys beginning 00 or FF";

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
            print_mode(policy.mode.map(RepeaterMode::as_byte));
            subfield(
                "regions",
                or_unavailable(policy.regions.as_deref(), format_regions),
            );
            subfield(
                "default",
                or_unavailable(policy.default_region, |code| match code {
                    Some(code) => code.to_string(),
                    None => "none (forwards untagged floods untagged)".into(),
                }),
            );
            subfield(
                "min rssi",
                or_unavailable(policy.min_rssi, |dbm| match dbm {
                    Some(dbm) => format!("{dbm} dBm"),
                    None => "any".into(),
                }),
            );
            subfield(
                "min snr",
                or_unavailable(policy.min_snr, |db| match db {
                    Some(db) => format!("{db} dB"),
                    None => "any".into(),
                }),
            );
            if let Some(meshcore) = device.meshcore_forwarding().await? {
                subfield(
                    "meshcore",
                    format!(
                        "{}, policy {}",
                        or_unavailable(meshcore.enabled, |enabled| match enabled {
                            true => "on".into(),
                            false => "off".into(),
                        }),
                        or_unavailable(meshcore.region_policy, |policy| policy.to_string()),
                    ),
                );
                subfield(
                    "meshcore regions",
                    or_unavailable(meshcore.regions.as_deref(), format_meshcore_regions),
                );
                if meshcore.enabled == Some(true) && !identity_allowed(device).await? {
                    warn(format!(
                        "MeshCore forwarding is inactive: {RESERVED_IDENTITY}"
                    ));
                }
            }
            if policy.mode.is_some_and(RepeaterMode::forwards)
                && let (Some(Some(code)), Some(regions)) = (policy.default_region, &policy.regions)
                && !regions.is_empty()
                && !region_codes(regions).contains(&code)
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
        RepeaterOp::On => set_mode(device, RepeaterMode::On).await?,
        RepeaterOp::Adaptive => set_mode(device, RepeaterMode::Adaptive).await?,
        RepeaterOp::Off => set_mode(device, RepeaterMode::Off).await?,
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
        RepeaterOp::Meshcore { op } => match op {
            MeshCoreOp::On => match device.set_meshcore_forwarding_enabled(true).await {
                Ok(_) => println!("repeater meshcore on"),
                Err(UlcpError::Status(Status::INVALID_STATE))
                    if !identity_allowed(device).await? =>
                {
                    bail!("{RESERVED_IDENTITY}");
                }
                Err(error) => return Err(error.into()),
            },
            MeshCoreOp::Off => {
                device.set_meshcore_forwarding_enabled(false).await?;
                println!("repeater meshcore off");
            }
            MeshCoreOp::Policy { policy } => {
                let stored = device.set_meshcore_region_policy(policy).await?;
                println!("repeater meshcore policy {stored}");
            }
            MeshCoreOp::Regions { op } => match op.unwrap_or(MeshCoreRegionOp::List) {
                MeshCoreRegionOp::List => {
                    let Some(meshcore) = device.meshcore_forwarding().await? else {
                        bail!("device does not advertise CAP_MESHCORE_FORWARDER");
                    };
                    println!(
                        "repeater meshcore regions {}",
                        or_unavailable(meshcore.regions.as_deref(), format_meshcore_regions)
                    );
                    return Ok(());
                }
                MeshCoreRegionOp::Add { name } => {
                    device.add_meshcore_region(&name.0).await?;
                    println!("repeater meshcore region added: {}", name.0);
                }
                MeshCoreRegionOp::Remove { name } => {
                    device.remove_meshcore_region(&name.0).await?;
                    println!("repeater meshcore region removed: {}", name.0);
                }
                MeshCoreRegionOp::Set { list } => {
                    let stored = device.set_meshcore_regions(&list.0).await?;
                    println!(
                        "repeater meshcore regions {}",
                        format_meshcore_regions(&stored)
                    );
                    if stored.len() < list.0.len() {
                        warn(format!(
                            "the device kept {} of {} regions (repeats collapse)",
                            stored.len(),
                            list.0.len()
                        ));
                    }
                }
            },
        },
    }
    persist(device, no_save).await
}

/// Whether the device identity's key is one MeshCore lets a repeater
/// run under. An identity the device will not report is given the
/// benefit of the doubt: this only decides whether to warn.
async fn identity_allowed(
    device: &mut umsh::ulcp::UlcpDevice<crate::connection::SessionLink>,
) -> Result<bool> {
    let key = match device.get_prop(prop::DEV_KEY).await {
        Ok(key) => key,
        Err(UlcpError::Status(_)) => return Ok(true),
        Err(error) => return Err(error.into()),
    };
    Ok(<[u8; 32]>::try_from(key.as_slice()).map_or(true, |key| meshcore_identity_allowed(&key)))
}

async fn set_mode(
    device: &mut umsh::ulcp::UlcpDevice<crate::connection::SessionLink>,
    mode: RepeaterMode,
) -> Result<()> {
    let echoed = device
        .set_prop(prop::MAC_REPEATER_MODE, &[mode.as_byte()])
        .await?;
    print_mode(echoed.first().copied());
    Ok(())
}

fn print_mode(byte: Option<u8>) {
    match byte.map(RepeaterMode::from_byte) {
        Some(Some(RepeaterMode::Off)) => println!("repeater off"),
        Some(Some(RepeaterMode::On)) => {
            println!("repeater on (on-board node forwards overheard frames)")
        }
        Some(Some(RepeaterMode::Adaptive)) => {
            println!("repeater adaptive (forwards what no repeater was heard carrying)")
        }
        // A mode this tool does not know still forwards.
        Some(None) => println!("repeater on (mode {})", byte.unwrap_or_default()),
        None => println!("repeater state {UNAVAILABLE}"),
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
/// forwarding filter actually compares—a hashed name is otherwise
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
/// MeshCore region names as stored, without their `#`.
pub fn format_meshcore_regions(regions: &[String]) -> String {
    match regions.is_empty() {
        true => "none".to_string(),
        false => regions.join(", "),
    }
}

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
