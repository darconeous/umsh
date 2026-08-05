//! Conversion between broken-down civil time and the Unix epoch.
//!
//! Receivers report the date and time of day as separate fields, and
//! `PROP_TIME` carries one `UINT32` second count, so something has to
//! convert between them. Hosts need the same conversion in reverse to
//! show an operator what the device thinks the time is.
//!
//! The arithmetic is Howard Hinnant's days-from-civil algorithm: integer
//! only, no lookup tables, and correct for the whole proleptic Gregorian
//! calendar rather than only for the years a leap-year table happens to
//! cover.
//!
//! Everything here is UTC. A local time-zone offset is presentation,
//! applied by whatever is doing the presenting — see
//! [`DateTime::shifted`].

/// The largest second count [`u32`] can express: 2106-02-07T06:28:15Z.
///
/// `PROP_TIME` is unsigned, which is what buys the extra 68 years over
/// the signed encoding everyone worries about; nothing here needs to
/// handle a wrap before then.
pub const MAX_EPOCH: u32 = u32::MAX;

/// The earliest instant a receiver is believed: 2020-01-01T00:00:00Z.
///
/// A receiver whose backup domain has lost power does not report *no*
/// time. It reports the start of its own epoch — a T1000-E's AG3335 comes
/// back saying 1980-01-06, the GPS epoch — and an RMC carrying that is
/// well-formed in every respect except being wrong by decades.
///
/// Nothing downstream can catch this. The wall clock's precedence rules
/// are about *which* source wins, not whether a source is lying, and an
/// unset clock accepts a receiver-RTC restore by design. So the check
/// belongs here, at the parse: an instant from before any of this software
/// existed is not an instant, and a receiver reporting one is a receiver
/// with no clock — which is a state the design already handles.
///
/// # The 2080 cliff
///
/// This floor combines with the GPS-epoch two-digit-year window to accept
/// **2020 through 2079** and nothing else. In 2080 a receiver reports `80`,
/// the window reads that as 1980, and this rejects it — the same reading
/// that makes a reset receiver detectable today.
///
/// Two digits cannot distinguish "the receiver's clock was lost" from "it
/// is fifty-four years later", so the ambiguity is inherent rather than
/// chosen; every NMEA consumer windowing on the GPS epoch shares it. The
/// alternative — windowing forward, so `80` means 2080 — buys a working
/// 2080 at the cost of believing every clock-less receiver between now and
/// then, which is the failure that actually happens. `PROP_TIME`'s `u32`
/// runs out in 2106 regardless.
pub const MIN_PLAUSIBLE_EPOCH: u32 = 1_577_836_800;

/// A broken-down civil date and time, in UTC unless a caller has
/// deliberately shifted it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DateTime {
    /// Proleptic Gregorian year.
    pub year: i32,
    /// Month, 1–12.
    pub month: u8,
    /// Day of month, 1–31.
    pub day: u8,
    /// Hour, 0–23.
    pub hour: u8,
    /// Minute, 0–59.
    pub minute: u8,
    /// Second, 0–59. Leap seconds are not represented: receivers report
    /// UTC with the leap second smeared or repeated, and a second that
    /// cannot be encoded is worse than one that is merely repeated.
    pub second: u8,
}

impl DateTime {
    /// The Unix epoch itself, 1970-01-01T00:00:00Z.
    pub const EPOCH: Self = Self {
        year: 1970,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    };

    /// Whether every field is in range and the day exists in its month.
    ///
    /// Note what this does *not* check: a year outside the range
    /// [`to_unix`](Self::to_unix) can encode is still a valid date, and is
    /// rejected there instead.
    pub const fn is_valid(&self) -> bool {
        self.month >= 1
            && self.month <= 12
            && self.day >= 1
            && self.day <= days_in_month(self.year, self.month)
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59
    }

    /// Seconds since the Unix epoch, or `None` when the date is invalid
    /// or falls outside what `PROP_TIME` can carry.
    ///
    /// A receiver reporting a date before 1970 or past 2106 is reporting
    /// a receiver fault, not a time, so refusing is the right answer:
    /// silently clamping would set a clock to a value the device would
    /// then defend.
    pub const fn to_unix(&self) -> Option<u32> {
        if !self.is_valid() {
            return None;
        }
        let days = days_from_civil(self.year, self.month, self.day);
        let seconds =
            days * 86_400 + self.hour as i64 * 3_600 + self.minute as i64 * 60 + self.second as i64;
        if seconds < 0 || seconds > MAX_EPOCH as i64 {
            return None;
        }
        Some(seconds as u32)
    }

    /// Break a Unix second count down into civil fields.
    ///
    /// Total: every `u32` names a real UTC instant, so unlike
    /// [`to_unix`](Self::to_unix) there is nothing to refuse.
    pub const fn from_unix(seconds: u32) -> Self {
        let days = (seconds / 86_400) as i64;
        let rest = seconds % 86_400;
        let (year, month, day) = civil_from_days(days);
        Self {
            year,
            month,
            day,
            hour: (rest / 3_600) as u8,
            minute: (rest % 3_600 / 60) as u8,
            second: (rest % 60) as u8,
        }
    }

    /// This instant shifted by a time-zone offset in minutes east of UTC,
    /// for rendering a local time.
    ///
    /// The result is a wall-clock reading, not an instant: it no longer
    /// converts back through [`to_unix`](Self::to_unix) to what it came
    /// from, which is exactly what makes it presentation. `None` when the
    /// shift leaves the representable range.
    pub const fn shifted(&self, offset_minutes: i16) -> Option<Self> {
        let Some(seconds) = self.to_unix() else {
            return None;
        };
        let shifted = seconds as i64 + offset_minutes as i64 * 60;
        if shifted < 0 || shifted > MAX_EPOCH as i64 {
            return None;
        }
        Some(Self::from_unix(shifted as u32))
    }
}

/// Days in `month` of `year`, 1-indexed. Zero for an out-of-range month,
/// which makes an invalid month fail the day check in
/// [`DateTime::is_valid`] rather than needing its own branch.
pub const fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// The proleptic Gregorian leap-year rule.
pub const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
///
/// Hinnant's algorithm: shift the year so March is the first month, which
/// puts the leap day at the end of the year and lets the day-of-year
/// become a closed-form expression, then count 400-year eras — the cycle
/// over which the Gregorian calendar exactly repeats.
pub const fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let y = if month <= 2 { year - 1 } else { year } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    // Year within the era, 0–399.
    let yoe = y - era * 400;
    let m = month as i64;
    let d = day as i64;
    // Day within the March-based year, 0–365.
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    // Day within the era, 0–146096.
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    // 719468 is the day number of 1970-01-01 counted from the era start.
    era * 146_097 + doe - 719_468
}

/// The proleptic Gregorian date `days` after 1970-01-01. The inverse of
/// [`days_from_civil`].
pub const fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m as u8, d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn round_trip(seconds: u32, expected: DateTime) {
        assert_eq!(DateTime::from_unix(seconds), expected, "from {seconds}");
        assert_eq!(expected.to_unix(), Some(seconds), "to {seconds}");
    }

    #[test]
    fn known_instants_round_trip() {
        round_trip(0, DateTime::EPOCH);
        round_trip(
            1_000_000_000,
            DateTime {
                year: 2001,
                month: 9,
                day: 9,
                hour: 1,
                minute: 46,
                second: 40,
            },
        );
        // The 32-bit signed rollover everyone worries about is an
        // ordinary instant here, because PROP_TIME is unsigned.
        round_trip(
            2_147_483_648,
            DateTime {
                year: 2038,
                month: 1,
                day: 19,
                hour: 3,
                minute: 14,
                second: 8,
            },
        );
        // The last second the encoding can express.
        round_trip(
            MAX_EPOCH,
            DateTime {
                year: 2106,
                month: 2,
                day: 7,
                hour: 6,
                minute: 28,
                second: 15,
            },
        );
    }

    #[test]
    fn leap_days_are_real_days() {
        // 2000 is a leap year (the 400 rule), 1900 was not (the 100
        // rule), 2024 is (the 4 rule).
        assert!(is_leap_year(2000));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2024));
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2023, 2), 28);

        let leap_day = DateTime {
            year: 2024,
            month: 2,
            day: 29,
            hour: 12,
            minute: 0,
            second: 0,
        };
        assert!(leap_day.is_valid());
        let seconds = leap_day.to_unix().unwrap();
        assert_eq!(DateTime::from_unix(seconds), leap_day);

        let no_such_day = DateTime {
            day: 29,
            year: 2023,
            ..leap_day
        };
        assert!(!no_such_day.is_valid());
        assert_eq!(no_such_day.to_unix(), None);
    }

    /// Every day for eight years, across two leap years and a century
    /// boundary that is *not* a leap year, must survive the round trip.
    #[test]
    fn every_day_of_several_years_round_trips() {
        for year in 1897..=1905 {
            for month in 1..=12u8 {
                for day in 1..=days_in_month(year, month) {
                    // Before 1970 there is no epoch second, but the
                    // calendar arithmetic must still invert.
                    let days = days_from_civil(year, month, day);
                    assert_eq!(civil_from_days(days), (year, month, day));
                }
            }
        }
        for year in 2020..=2028 {
            for month in 1..=12u8 {
                for day in 1..=days_in_month(year, month) {
                    let civil = DateTime {
                        year,
                        month,
                        day,
                        hour: 6,
                        minute: 30,
                        second: 15,
                    };
                    let seconds = civil.to_unix().expect("in range");
                    assert_eq!(DateTime::from_unix(seconds), civil);
                }
            }
        }
    }

    #[test]
    fn out_of_range_instants_are_refused_rather_than_clamped() {
        // A receiver reporting 1969 is reporting a fault.
        let before = DateTime {
            year: 1969,
            month: 12,
            day: 31,
            hour: 23,
            minute: 59,
            second: 59,
        };
        assert!(before.is_valid());
        assert_eq!(before.to_unix(), None);

        let after = DateTime {
            year: 2107,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        };
        assert!(after.is_valid());
        assert_eq!(after.to_unix(), None);
    }

    #[test]
    fn field_ranges_are_checked() {
        let base = DateTime {
            year: 2026,
            month: 8,
            day: 4,
            hour: 12,
            minute: 0,
            second: 0,
        };
        assert!(base.is_valid());
        assert!(!DateTime { month: 0, ..base }.is_valid());
        assert!(!DateTime { month: 13, ..base }.is_valid());
        assert!(!DateTime { day: 0, ..base }.is_valid());
        assert!(!DateTime { day: 32, ..base }.is_valid());
        assert!(!DateTime { hour: 24, ..base }.is_valid());
        assert!(!DateTime { minute: 60, ..base }.is_valid());
        // A leap second is not representable; the receiver's next
        // sentence carries an ordinary one.
        assert!(!DateTime { second: 60, ..base }.is_valid());
    }

    #[test]
    fn shifting_produces_a_local_reading_across_a_date_boundary() {
        // 2026-08-04T02:30:00Z is the previous evening in California.
        let utc = DateTime {
            year: 2026,
            month: 8,
            day: 4,
            hour: 2,
            minute: 30,
            second: 0,
        };
        assert_eq!(
            utc.shifted(-7 * 60),
            Some(DateTime {
                year: 2026,
                month: 8,
                day: 3,
                hour: 19,
                minute: 30,
                second: 0,
            })
        );
        // ...and the next morning in Auckland.
        assert_eq!(
            utc.shifted(12 * 60),
            Some(DateTime {
                year: 2026,
                month: 8,
                day: 4,
                hour: 14,
                minute: 30,
                second: 0,
            })
        );
        assert_eq!(utc.shifted(0), Some(utc));
        // A shift off the end of the encoding has no reading.
        assert_eq!(DateTime::from_unix(MAX_EPOCH).shifted(60), None);
        assert_eq!(DateTime::EPOCH.shifted(-60), None);
    }
}
