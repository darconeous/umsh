//! `advert`: what the device announces without being asked
//! (`PROP_ADVERT_INTERVAL`, `PROP_BEACON_INTERVAL`,
//! `PROP_STARTUP_BEACON`).
//!
//! Two schedules rather than one, because the two announcements cost very
//! different amounts of airtime and say different things. A beacon is an
//! empty broadcast that collects a trace on its way out, so what it
//! publishes is the path back to the device; an advertisement carries the
//! signed node identity and goes only as far as the device's own
//! neighbours. A mesh normally wants the first often and the second
//! rarely.

use anyhow::{Result, bail};

use umsh::ulcp::AdvertPolicy;
use umsh::ulcp_wire::ids::{MAX_AUTO_ANNOUNCE_INTERVAL_S, MIN_AUTO_ANNOUNCE_INTERVAL_S};

use super::{format_duration, persist};
use crate::App;
use crate::output::{field, subfield};

#[derive(Debug, clap::Subcommand)]
pub enum AdvertOp {
    /// Print both schedules and the startup-beacon setting.
    Status,
    /// Seconds between signed identity advertisements, or `off`.
    Interval {
        #[arg(value_name = "SECONDS|off")]
        period: Period,
    },
    /// Seconds between empty beacons, or `off`.
    BeaconInterval {
        #[arg(value_name = "SECONDS|off")]
        period: Period,
    },
    /// Whether one beacon goes out once the device comes up.
    Startup {
        #[command(subcommand)]
        op: ToggleOp,
    },
}

/// An interval, where "off" and zero are the same thing on the wire.
///
/// The device holds to the same bounds; checking them here too is what
/// turns a refusal into a sentence the operator can act on.
#[derive(Debug, Clone, Copy)]
pub struct Period(u32);

impl std::str::FromStr for Period {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.eq_ignore_ascii_case("off") || text == "0" {
            return Ok(Self(0));
        }
        let seconds: u32 = text
            .parse()
            .map_err(|_| format!("expected a number of seconds or `off`, got `{text}`"))?;
        if seconds < MIN_AUTO_ANNOUNCE_INTERVAL_S {
            return Err(format!(
                "the shortest accepted interval is {} ({MIN_AUTO_ANNOUNCE_INTERVAL_S} s); use `off` to send none",
                format_duration(MIN_AUTO_ANNOUNCE_INTERVAL_S)
            ));
        }
        if seconds > MAX_AUTO_ANNOUNCE_INTERVAL_S {
            return Err(format!(
                "the longest accepted interval is {} ({MAX_AUTO_ANNOUNCE_INTERVAL_S} s); use `off` to send none",
                format_duration(MAX_AUTO_ANNOUNCE_INTERVAL_S)
            ));
        }
        Ok(Self(seconds))
    }
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

pub async fn run(app: &mut App, op: Option<AdvertOp>) -> Result<()> {
    let no_save = app.no_save;
    let device = app.device()?;
    match op.unwrap_or(AdvertOp::Status) {
        AdvertOp::Status => {
            let Some(policy) = device.advert_policy().await? else {
                bail!("device does not advertise CAP_ADVERT");
            };
            report(&policy);
            return Ok(());
        }
        AdvertOp::Interval { period } => {
            let stored = device.set_advert_interval(period.0).await?;
            println!("advertisement {}", format_interval(stored));
        }
        AdvertOp::BeaconInterval { period } => {
            let stored = device.set_beacon_interval(period.0).await?;
            println!("beacon {}", format_interval(stored));
        }
        AdvertOp::Startup { op } => {
            let enabled = device.set_startup_beacon(op.enabled()).await?;
            println!("startup beacon {}", if enabled { "on" } else { "off" });
        }
    }
    persist(device, no_save).await
}

fn report(policy: &AdvertPolicy) {
    field("advert", format_interval(policy.advert_interval_s));
    subfield("beacon", format_interval(policy.beacon_interval_s));
    subfield(
        "startup beacon",
        if policy.startup_beacon { "on" } else { "off" },
    );
    // An interval is a floor, not a period. Said once here rather than
    // hedged into every reading above.
    if policy.advert_interval_s > 0 || policy.beacon_interval_s > 0 {
        subfield("scatter", "each period runs up to 25% longer");
    }
}

/// Seconds as written, with the human-scale reading beside them — the
/// difference between 3600 and 36000 is easy to miss in a bare number.
fn format_interval(seconds: u32) -> String {
    if seconds == 0 {
        return "off".to_string();
    }
    format!("every {seconds} s ({})", format_duration(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_and_zero_are_the_same_interval() {
        assert_eq!("off".parse::<Period>().unwrap().0, 0);
        assert_eq!("OFF".parse::<Period>().unwrap().0, 0);
        assert_eq!("0".parse::<Period>().unwrap().0, 0);
    }

    /// Both bounds are rejected at the command line so the operator sees
    /// why, rather than getting a bare INVALID_ARGUMENT from the device.
    #[test]
    fn an_interval_outside_the_bounds_is_refused_with_its_reason() {
        let error = "30".parse::<Period>().unwrap_err();
        assert!(error.contains("20m"), "{error}");
        assert!(error.contains("off"), "{error}");

        let error = "90000".parse::<Period>().unwrap_err();
        // The shared formatter carries days, so the 24-hour ceiling
        // states itself as one.
        assert!(error.contains("1d"), "{error}");

        // Both ends themselves are reachable.
        assert_eq!(
            "1200".parse::<Period>().unwrap().0,
            MIN_AUTO_ANNOUNCE_INTERVAL_S
        );
        assert_eq!(
            "86400".parse::<Period>().unwrap().0,
            MAX_AUTO_ANNOUNCE_INTERVAL_S
        );
    }

    #[test]
    fn an_interval_reads_back_at_human_scale() {
        assert_eq!(format_interval(0), "off");
        assert_eq!(format_interval(14400), "every 14400 s (4h)");
        assert_eq!(format_interval(3600), "every 3600 s (1h)");
        assert_eq!(format_interval(1200), "every 1200 s (20m)");
        assert_eq!(format_interval(5400), "every 5400 s (1h30m)");
        // The 24-hour maximum reads as a day, now that the shared
        // formatter carries one.
        assert_eq!(format_interval(86400), "every 86400 s (1d)");
    }
}
