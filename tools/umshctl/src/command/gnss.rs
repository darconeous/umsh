//! `gnss`: report the receiver's state, switch it on or off, and set the
//! policy for what is done with a fix (`PROP_GNSS_*`).
//!
//! The switch is persisted device-domain state, so a receiver left on
//! comes back on. Off means the lowest power state the board can reach —
//! on most of them the receiver is the largest continuous load there is.

use anyhow::{Result, bail};

use umsh::node::location::NodeLocation;
use umsh::ulcp::GnssStatus;
use umsh::ulcp_wire::gnss::FixKind;

use super::persist;
use crate::App;
use crate::output::{field, note, subfield};

#[derive(Debug, clap::Subcommand)]
pub enum GnssOp {
    /// Print the receiver state, the current fix, and the policy.
    Status,
    /// Power the receiver up and start looking for a fix.
    On,
    /// Power the receiver down to its lowest reachable state.
    Off,
    /// Refresh the advertised node identity's location from fixes, or
    /// stop doing so.
    IdentUpdate {
        #[command(subcommand)]
        op: ToggleOp,
    },
    /// Clamp the advertised location to this many bytes of precision
    /// (1 coarsest, 7 finest).
    IdentPrecision {
        #[arg(value_name = "1-7")]
        bytes: u8,
    },
    /// Whether receiver-derived time may set the wall clock. Turn it off
    /// to keep a hand-set clock safe from a jammed or spoofed sky.
    Trust {
        #[command(subcommand)]
        op: ToggleOp,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum ToggleOp {
    On,
    Off,
}

impl ToggleOp {
    fn enabled(&self) -> bool {
        matches!(self, Self::On)
    }
}

pub async fn run(app: &mut App, op: Option<GnssOp>) -> Result<()> {
    let no_save = app.no_save;
    let device = app.device()?;
    match op.unwrap_or(GnssOp::Status) {
        GnssOp::Status => {
            let Some(status) = device.gnss_status().await? else {
                bail!("device does not advertise CAP_GNSS");
            };
            report(&status);
            return Ok(());
        }
        GnssOp::On => {
            let enabled = device.set_gnss_enabled(true).await?;
            println!("gnss {}", if enabled { "on" } else { "off" });
        }
        GnssOp::Off => {
            let enabled = device.set_gnss_enabled(false).await?;
            println!("gnss {}", if enabled { "on" } else { "off" });
        }
        GnssOp::IdentUpdate { op } => {
            let enabled = device.set_gnss_ident_update(op.enabled()).await?;
            println!(
                "gnss identity update {}",
                if enabled { "on" } else { "off" }
            );
        }
        GnssOp::IdentPrecision { bytes } => {
            let stored = device.set_gnss_ident_precision(bytes).await?;
            println!(
                "gnss identity precision {stored} bytes ({})",
                precision_cell(stored)
            );
        }
        GnssOp::Trust { op } => {
            let trust = device.set_gnss_time_trust(op.enabled()).await?;
            println!("gnss time trust {}", if trust { "on" } else { "off" });
            if !trust {
                note("receiver time will not set the clock; set it with `time sync`");
            }
        }
    }
    persist(device, no_save).await
}

fn report(status: &GnssStatus) {
    field("gnss", if status.enabled { "on" } else { "off" });
    subfield(
        "fix",
        match status.fix.fix {
            FixKind::None if status.enabled => "none (searching)",
            FixKind::None => "none (receiver off)",
            FixKind::TwoD => "2D",
            FixKind::ThreeD => "3D",
        },
    );
    match status.fix.sats_in_view {
        Some(in_view) => subfield(
            "satellites",
            format!("{} used of {in_view} in view", status.fix.sats_used),
        ),
        None => subfield("satellites", format!("{} used", status.fix.sats_used)),
    }
    let location = status.fix.location();
    if location.is_empty() {
        subfield("location", "none");
    } else {
        subfield("location", format_location(location));
        subfield("position", format_position(location));
    }
    match status.fix.altitude_m {
        Some(meters) => subfield("altitude", format!("{meters} m")),
        None => subfield("altitude", "unknown"),
    }
    match status.fix.accuracy_dm {
        // Reported to a tenth because that is the resolution the property
        // carries; it is an estimate scaled from dilution of precision,
        // not a measured error bound.
        Some(dm) => subfield(
            "precision",
            format!("~{}.{} m (estimated)", dm / 10, dm % 10),
        ),
        None => subfield("precision", "unknown"),
    }
    subfield(
        "identity update",
        match status.ident_update {
            true => format!(
                "on, clamped to {} bytes ({})",
                status.ident_precision,
                precision_cell(status.ident_precision)
            ),
            false => format!("off (would clamp to {} bytes)", status.ident_precision),
        },
    );
    subfield(
        "time trust",
        match status.time_trust {
            true => "on (fixes set the clock)",
            false => "off (fixes never set the clock)",
        },
    );
}

/// Render the encoded location as hex, which is what it is: a grid code,
/// not a coordinate pair. The cell size travels with it so the degrees
/// on the next line are read as the cell they name.
fn format_location(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2 + 16);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out.push_str(&format!(
        " ({} bytes, {})",
        bytes.len(),
        precision_cell(bytes.len() as u8)
    ));
    out
}

/// The cell center in degrees. `NodeLocation`'s own rendering already
/// matches its decimal places to the encoded precision, so the digits
/// stop where the grid code stops saying anything.
fn format_position(bytes: &[u8]) -> String {
    format!("{} (lat, lon)", NodeLocation::from_bytes(bytes))
}

/// The approximate cell size one precision names, at the equator. What
/// makes a precision meaningful to an operator is how big an area it
/// discloses, and nothing else on the wire says.
fn precision_cell(bytes: u8) -> &'static str {
    match bytes {
        1 => "~2500 km",
        2 => "~156 km",
        3 => "~9.8 km",
        4 => "~610 m",
        5 => "~38 m",
        6 => "~2.4 m",
        7 => "~15 cm",
        _ => "out of range",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_names_the_area_it_discloses() {
        assert_eq!(precision_cell(5), "~38 m");
        assert_eq!(precision_cell(0), "out of range");
        assert_eq!(precision_cell(8), "out of range");
    }

    #[test]
    fn a_location_renders_as_the_grid_code_it_is() {
        assert_eq!(
            format_location(&[0x8a, 0x1f, 0x4c]),
            "8a1f4c (3 bytes, ~9.8 km)"
        );
    }

    #[test]
    fn a_position_renders_as_degrees_at_the_encoded_precision() {
        // Three bytes name a ~9.8 km cell, so it prints two decimals and
        // stops — the same grid code as the test above.
        assert_eq!(
            format_position(&[0x8a, 0x1f, 0x4c]),
            "0.90, 67.19 (lat, lon)"
        );
    }
}
