//! `time`: read, set, or clear the device's wall clock (`PROP_TIME`,
//! `PROP_TZ_OFFSET`).
//!
//! The clock is not persisted — an epoch written to flash accumulates
//! unbounded error while the device is off — so it comes back from a real
//! source or not at all. The time zone *is* persisted: where a device is
//! meant to be is known even when the time is not.

use anyhow::{Result, bail};

use umsh_gnss::DateTime;

use super::persist;
use crate::App;
use crate::output::{field, note, subfield};

#[derive(Debug, clap::Subcommand)]
pub enum TimeOp {
    /// Print the device's clock, in UTC and in its configured local time.
    Show,
    /// Set the clock from this host's clock.
    Sync,
    /// Set the clock to an explicit Unix second count.
    Set {
        #[arg(value_name = "UNIX-SECONDS")]
        epoch: u32,
    },
    /// Return the device to not knowing what time it is. A device with a
    /// screen stops showing a clock at all.
    Clear,
    /// Show or set the local time-zone offset.
    Tz {
        #[command(subcommand)]
        op: Option<TzOp>,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum TzOp {
    /// Print the configured offset.
    Show,
    /// Set the offset, as `±HH:MM`, `±HHMM`, `±H`, or a minute count.
    Set {
        #[arg(value_name = "±HH:MM|MINUTES", allow_hyphen_values = true)]
        offset: TzOffsetArg,
    },
    /// Set the offset from this host's current time zone.
    ///
    /// It is the offset in effect right now that is copied, not the
    /// zone: a device configured in July under daylight saving keeps
    /// that offset into the winter, because the device has no zone
    /// database to shift it with.
    Sync,
}

/// A time-zone offset in minutes east of UTC.
///
/// Accepts the shapes people actually type — `-08:00`, `+0530`, `-8`,
/// `330` — because the one thing a time-zone argument must not do is
/// silently mean a different zone than it looks like.
#[derive(Clone, Copy, Debug)]
pub struct TzOffsetArg(pub i16);

impl std::str::FromStr for TzOffsetArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err("empty time-zone offset".to_string());
        }
        let (sign, rest) = match trimmed.as_bytes()[0] {
            b'-' => (-1i32, &trimmed[1..]),
            b'+' => (1, &trimmed[1..]),
            _ => (1, trimmed),
        };
        let minutes = if let Some((hours, minutes)) = rest.split_once(':') {
            parse_part(hours)? * 60 + parse_part(minutes)?
        } else if rest.len() == 4 && rest.chars().all(|c| c.is_ascii_digit()) {
            // `+0530`: hours and minutes run together, the shape RFC 3339
            // and NMEA both use.
            parse_part(&rest[..2])? * 60 + parse_part(&rest[2..])?
        } else {
            let value = parse_part(rest)?;
            // A bare number small enough to be an hour count is one; the
            // zones people name in whole hours vastly outnumber the ones
            // anybody expresses as 60 minutes.
            if value <= 14 { value * 60 } else { value }
        };
        let minutes = sign * minutes;
        if !(-12 * 60..=14 * 60).contains(&minutes) {
            return Err(format!(
                "{trimmed} is outside the range of real time zones (UTC-12:00 to UTC+14:00)"
            ));
        }
        Ok(Self(minutes as i16))
    }
}

fn parse_part(text: &str) -> Result<i32, String> {
    text.parse::<i32>()
        .map_err(|_| format!("{text} is not a number"))
}

pub async fn run(app: &mut App, op: Option<TimeOp>) -> Result<()> {
    let no_save = app.no_save;
    let device = app.device()?;
    match op.unwrap_or(TimeOp::Show) {
        TimeOp::Show => {
            let Some(time) = device.time().await? else {
                bail!("device does not advertise CAP_TIME");
            };
            match time.epoch {
                Some(epoch) => {
                    field("time", format_utc(epoch));
                    subfield("epoch", epoch);
                    match DateTime::from_unix(epoch).shifted(time.tz_offset_min) {
                        Some(local) => subfield(
                            "local",
                            format!("{} {}", format_civil(local), format_tz(time.tz_offset_min)),
                        ),
                        None => subfield("local", "outside the representable range"),
                    }
                }
                None => {
                    field("time", "not set");
                    note("the device does not know what time it is and shows no clock");
                    subfield("zone", format_tz(time.tz_offset_min));
                }
            }
            return Ok(());
        }
        TimeOp::Sync => {
            let now = host_epoch()?;
            let stored = device.set_time(Some(now)).await?;
            report_set(stored);
        }
        TimeOp::Set { epoch } => {
            let stored = device.set_time(Some(epoch)).await?;
            report_set(stored);
        }
        TimeOp::Clear => {
            device.set_time(None).await?;
            println!("time cleared: the device no longer knows what time it is");
        }
        TimeOp::Tz { op } => match op.unwrap_or(TzOp::Show) {
            TzOp::Show => {
                let Some(time) = device.time().await? else {
                    bail!("device does not advertise CAP_TIME");
                };
                println!("time zone {}", format_tz(time.tz_offset_min));
                return Ok(());
            }
            TzOp::Set { offset } => {
                let stored = device.set_tz_offset(offset.0).await?;
                println!("time zone {}", format_tz(stored));
            }
            TzOp::Sync => {
                let offset = host_tz_offset()?;
                let stored = device.set_tz_offset(offset).await?;
                println!("time zone {} (from this host)", format_tz(stored));
            }
        },
    }
    persist(device, no_save).await
}

fn report_set(stored: Option<u32>) {
    match stored {
        Some(epoch) => println!("time {}", format_utc(epoch)),
        None => println!("time not set (the device refused the value)"),
    }
}

/// This host's wall clock as a Unix second count.
fn host_epoch() -> Result<u32> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    u32::try_from(now.as_secs())
        .map_err(|_| anyhow::anyhow!("this host's clock is outside the range PROP_TIME can carry"))
}

/// This host's current UTC offset, in minutes east.
///
/// Read through the C library rather than a date crate: `localtime_r`
/// resolves `TZ`, the zone database, and today's daylight-saving state
/// the same way every other program on the machine does, which is what
/// "the system time zone" means to the person typing this.
#[cfg(unix)]
fn host_tz_offset() -> Result<i16> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let seconds = libc::time_t::try_from(now.as_secs())
        .map_err(|_| anyhow::anyhow!("this host's clock is outside the range time_t can carry"))?;
    let mut parts: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are to live, correctly typed locals, and
    // `localtime_r` writes only through the second.
    if unsafe { libc::localtime_r(&seconds, &mut parts) }.is_null() {
        bail!("this host has no readable local time zone");
    }
    let minutes = parts.tm_gmtoff / 60;
    i16::try_from(minutes)
        .map_err(|_| anyhow::anyhow!("this host's UTC offset ({minutes} minutes) is not a zone"))
}

#[cfg(not(unix))]
fn host_tz_offset() -> Result<i16> {
    bail!("this platform exposes no system time zone; give the offset with `time tz set`")
}

pub fn format_utc(epoch: u32) -> String {
    format!("{}Z", format_civil(DateTime::from_unix(epoch)))
}

fn format_civil(at: DateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        at.year, at.month, at.day, at.hour, at.minute, at.second
    )
}

/// Render an offset the way it is written, so a mistyped one is visible
/// as a zone rather than as a minute count nobody checks.
pub fn format_tz(minutes: i16) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let magnitude = minutes.unsigned_abs();
    format!("UTC{sign}{:02}:{:02}", magnitude / 60, magnitude % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn offsets_parse_in_every_shape_people_write_them() {
        for (text, expected) in [
            ("-08:00", -480),
            ("+05:30", 330),
            ("+0530", 330),
            ("-0800", -480),
            ("-8", -480),
            ("+14", 840),
            ("0", 0),
            ("330", 330),
            ("-330", -330),
        ] {
            assert_eq!(
                TzOffsetArg::from_str(text).unwrap().0,
                expected,
                "parsing {text}"
            );
        }
    }

    #[test]
    fn offsets_outside_the_real_range_are_refused() {
        for text in ["+15:00", "-13:00", "900", "nonsense", ""] {
            assert!(TzOffsetArg::from_str(text).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn offsets_render_as_zones() {
        assert_eq!(format_tz(0), "UTC+00:00");
        assert_eq!(format_tz(-480), "UTC-08:00");
        assert_eq!(format_tz(330), "UTC+05:30");
        assert_eq!(format_tz(-30), "UTC-00:30");
    }

    #[test]
    fn the_host_zone_is_a_real_zone() {
        // Whatever the build machine's TZ is, the answer has to be one a
        // device would accept — the same range `TzOffsetArg` enforces.
        let minutes = host_tz_offset().expect("a host has a time zone");
        assert!((-12 * 60..=14 * 60).contains(&minutes), "{minutes}");
    }

    #[test]
    fn instants_render_as_civil_time() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(format_utc(1_000_000_000), "2001-09-09 01:46:40Z");
    }
}
