//! Device › Clock: whether the receiver sets the clock, setting it by hand
//! a part at a time, the time zone, and how hours are written; and the time
//! zone first run asks for.
//!
//! Setting the time by hand: turning moves between the parts, and pressing
//! one lets turning change it until it is pressed again. Digits type the
//! focused part. Set takes the minute from its start.

use core::ops::RangeInclusive;

use buoyant::focus::FocusState;
use heapless::{String, Vec};
use umsh_hal::tz::{civil, days_from_civil};

use crate::clock::Local;
use crate::model::{State, word_match};
use crate::nav::{DevicePage, Screen, SetupPage, keys};
use crate::zones::{self, ZONES};

/// The letters a list of time zones is narrowed to.
pub type ZoneFind = String<16>;

/// A screen under Device › Clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClockPage {
    /// The settings.
    Main,
    /// The date and time, being set by hand.
    SetTime {
        parts: DateParts,
        /// Turning changes the focused part.
        editing: bool,
        /// The digits typed into a part so far.
        typed: Option<(Part, u16)>,
    },
    /// The time zones.
    Zones { find: ZoneFind },
}

/// A part of the date and time being set, in the order they are shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Part {
    Month,
    Day,
    Year,
    Hour,
    Minute,
    /// AM or PM, on a 12-hour clock.
    Half,
}

impl Part {
    pub const ALL: [Self; 6] = [
        Self::Month,
        Self::Day,
        Self::Year,
        Self::Hour,
        Self::Minute,
        Self::Half,
    ];

    #[must_use]
    pub const fn from_index(index: usize) -> Option<Self> {
        if index < Self::ALL.len() {
            Some(Self::ALL[index])
        } else {
            None
        }
    }

    /// How many digits it is typed in.
    const fn digits(self) -> u32 {
        match self {
            Self::Year => 4,
            Self::Half => 0,
            _ => 2,
        }
    }
}

/// A local date and time, to the minute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateParts {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    /// 0 to 23.
    pub hour: u8,
    pub minute: u8,
}

/// The years that can be set: `PROP_TIME` counts to 2106.
const YEARS: RangeInclusive<u16> = 2024..=2105;

impl DateParts {
    /// What the parts start at while the clock is not known.
    pub const UNKNOWN: Self = Self {
        year: 2026,
        month: 1,
        day: 1,
        hour: 12,
        minute: 0,
    };

    #[must_use]
    pub fn at(local: Local) -> Self {
        let (year, month, day) = civil(i64::from(local.day));
        Self {
            year: (year as u16).clamp(*YEARS.start(), *YEARS.end()),
            month: month as u8,
            day: day as u8,
            hour: (local.minute / 60) as u8,
            minute: (local.minute % 60) as u8,
        }
    }

    fn days_in_month(&self) -> u8 {
        let next = if self.month == 12 {
            days_from_civil(i64::from(self.year) + 1, 1, 1)
        } else {
            days_from_civil(i64::from(self.year), u32::from(self.month) + 1, 1)
        };
        (next - days_from_civil(i64::from(self.year), u32::from(self.month), 1)) as u8
    }

    /// Turns `part` by `steps`, wrapping round, and keeps the day within
    /// its month. The year stops at its ends.
    pub fn turn(&mut self, part: Part, steps: i8) {
        let wrap = |value: u8, first: u8, count: u8| {
            let offset = i16::from(value - first) + i16::from(steps);
            first + offset.rem_euclid(i16::from(count)) as u8
        };
        match part {
            Part::Month => self.month = wrap(self.month, 1, 12),
            Part::Day => self.day = wrap(self.day, 1, self.days_in_month()),
            Part::Year => {
                let year = i32::from(self.year) + i32::from(steps);
                self.year = year.clamp(i32::from(*YEARS.start()), i32::from(*YEARS.end())) as u16;
            }
            Part::Hour => self.hour = wrap(self.hour, 0, 24),
            Part::Minute => self.minute = wrap(self.minute, 0, 60),
            Part::Half => self.hour = (self.hour + 12) % 24,
        }
        self.day = self.day.min(self.days_in_month());
    }

    /// Sets `part` to `value` if it can be, on a 24-hour clock or not.
    fn set(&mut self, part: Part, value: u16, hour24: bool) -> bool {
        let fits = match part {
            Part::Month => (1..=12).contains(&value),
            Part::Day => value >= 1 && value <= u16::from(self.days_in_month()),
            Part::Year => YEARS.contains(&value),
            Part::Hour if hour24 => value <= 23,
            Part::Hour => (1..=12).contains(&value),
            Part::Minute => value <= 59,
            Part::Half => false,
        };
        if !fits {
            return false;
        }
        if part == Part::Year {
            return self.set_year(value);
        }
        let value = value as u8;
        match part {
            Part::Month => self.month = value,
            Part::Day => self.day = value,
            Part::Year => {}
            Part::Hour if hour24 => self.hour = value,
            Part::Hour => self.hour = value % 12 + if self.hour >= 12 { 12 } else { 0 },
            Part::Minute => self.minute = value,
            Part::Half => {}
        }
        self.day = self.day.min(self.days_in_month());
        true
    }

    /// Types `digit` into `part`, after the digits typed into it so far,
    /// and returns what has been typed into it now. A part takes its digits
    /// as soon as they make a value it can hold.
    fn type_digit(
        &mut self,
        part: Part,
        typed: Option<(Part, u16)>,
        digit: u8,
        hour24: bool,
    ) -> Option<(Part, u16)> {
        let digit = u16::from(digit);
        let before = typed.filter(|(at, _)| *at == part).map(|(_, value)| value);
        let value = match before {
            Some(before) => before * 10 + digit,
            None => digit,
        };
        let count = if value == 0 { 1 } else { value.ilog10() + 1 };
        if part == Part::Year {
            if count < part.digits() {
                return Some((part, value));
            }
            _ = self.set(part, value, hour24);
            return None;
        }
        if self.set(part, value, hour24) {
            return (count < part.digits()).then_some((part, value));
        }
        // Too large with the digit before it: the digit starts afresh.
        _ = self.set(part, digit, hour24);
        (before.is_some() && part.digits() > 1).then_some((part, digit))
    }

    fn set_year(&mut self, year: u16) -> bool {
        if !YEARS.contains(&year) {
            return false;
        }
        self.year = year;
        self.day = self.day.min(self.days_in_month());
        true
    }

    /// The reading in seconds, as if local time were UTC.
    #[must_use]
    pub fn local_seconds(&self) -> i64 {
        days_from_civil(
            i64::from(self.year),
            u32::from(self.month),
            u32::from(self.day),
        ) * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.minute) * 60
    }
}

/// The zones whose names match `find`, by their place in [`ZONES`]: every
/// zone while it is empty.
#[must_use]
pub fn matching(find: &str) -> Vec<u8, { ZONES.len() }> {
    ZONES
        .iter()
        .enumerate()
        .filter(|(_, zone)| find.is_empty() || word_match(zone.name, find).is_some())
        .map(|(i, _)| i as u8)
        .collect()
}

impl State {
    /// Shows the clock's settings.
    pub fn open_clock(&mut self) {
        let first = if self.clock.automatic.is_some() {
            keys::CLOCK_AUTOMATIC
        } else {
            keys::CLOCK_TIME
        };
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Clock {
                page: ClockPage::Main,
            },
            focus: FocusState::requesting(first),
        });
    }

    pub fn toggle_clock_automatic(&mut self) {
        if let Some(on) = self.clock.automatic {
            self.node.set_clock_automatic(!on);
            self.refresh_settings();
        }
    }

    pub fn toggle_hour24(&mut self) {
        self.node.set_hour24(!self.clock.hour24);
        self.refresh_settings();
    }

    /// Opens Date and time, at the time it is, unless the receiver sets
    /// the clock.
    pub fn open_set_time(&mut self) {
        if self.clock.automatic == Some(true) {
            return;
        }
        let parts = self
            .wall_time
            .map_or(DateParts::UNKNOWN, |time| DateParts::at(self.local(time)));
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Clock {
                page: ClockPage::SetTime {
                    parts,
                    editing: false,
                    typed: None,
                },
            },
            focus: FocusState::requesting(keys::time_part(Part::Month)),
        });
    }

    fn set_time_mut(&mut self) -> Option<(&mut DateParts, &mut bool, &mut Option<(Part, u16)>)> {
        match self.screens.last_mut() {
            Some(Screen::Device {
                page:
                    DevicePage::Clock {
                        page:
                            ClockPage::SetTime {
                                parts,
                                editing,
                                typed,
                            },
                    },
                ..
            }) => Some((parts, editing, typed)),
            _ => None,
        }
    }

    /// The focused part of the date and time being set.
    fn focused_part(&self) -> Option<Part> {
        self.screen().focus().current().and_then(keys::part_of)
    }

    /// Whatever part is being changed is done with.
    pub fn end_part_edit(&mut self) {
        if let Some((_, editing, typed)) = self.set_time_mut() {
            *editing = false;
            *typed = None;
        }
    }

    /// A part was pressed: AM or PM changes over, and any other starts or
    /// stops being changed by turning.
    pub fn press_part(&mut self, part: Part) {
        let Some((parts, editing, typed)) = self.set_time_mut() else {
            return;
        };
        *typed = None;
        if part == Part::Half {
            parts.turn(Part::Half, 1);
        } else {
            *editing = !*editing;
        }
    }

    /// The wheel turned `detents` while a part is being changed: changes it,
    /// and returns whether it did.
    pub fn turn_set_time(&mut self, detents: i8) -> bool {
        let Some(part) = self.focused_part() else {
            return false;
        };
        let Some((parts, editing, typed)) = self.set_time_mut() else {
            return false;
        };
        if !*editing {
            return false;
        }
        *typed = None;
        parts.turn(part, detents);
        true
    }

    /// A digit typed while Date and time is shown: into the focused part.
    pub fn type_time_digit(&mut self, digit: u8) {
        let Some(part) = self.focused_part() else {
            return;
        };
        let hour24 = self.clock.hour24;
        if let Some((parts, _, typed)) = self.set_time_mut() {
            *typed = parts.type_digit(part, *typed, digit, hour24);
        }
    }

    /// Sets the clock to the date and time shown, at the start of its
    /// minute, and returns to Clock.
    pub fn submit_set_time(&mut self) {
        let zone = self.clock.zone;
        let Some((parts, _, _)) = self.set_time_mut() else {
            return;
        };
        let Ok(time) = u32::try_from(zone.to_utc(parts.local_seconds())) else {
            return;
        };
        self.node.set_time(time);
        self.set_wall_time(Some(time));
        self.back();
    }

    /// Where the time zone list opens: on the zone set, or the one nearest
    /// it.
    fn current_zone(&self) -> usize {
        zones::find(&self.clock.zone)
            .unwrap_or_else(|| zones::nearest(self.clock.zone.std_offset_min()))
    }

    /// Shows the time zones, the one set focused.
    pub fn open_zones(&mut self) {
        let current = self.current_zone();
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Clock {
                page: ClockPage::Zones {
                    find: ZoneFind::new(),
                },
            },
            focus: FocusState::requesting(keys::zone(current)),
        });
    }

    /// Asks for the time zone on first run, after the radio profile.
    pub(crate) fn ask_setup_zone(&mut self) {
        let current = self.current_zone();
        _ = self.screens.push(Screen::Setup {
            page: SetupPage::Zone {
                find: ZoneFind::new(),
            },
            focus: FocusState::requesting(keys::zone(current)),
        });
    }

    fn zone_find_mut(&mut self) -> Option<&mut ZoneFind> {
        match self.screens.last_mut() {
            Some(Screen::Device {
                page:
                    DevicePage::Clock {
                        page: ClockPage::Zones { find },
                    },
                ..
            })
            | Some(Screen::Setup {
                page: SetupPage::Zone { find },
                ..
            }) => Some(find),
            _ => None,
        }
    }

    /// Narrows the time zones by a letter typed, unless none would be left.
    pub fn find_zone(&mut self, c: char) {
        let Some(find) = self.zone_find_mut() else {
            return;
        };
        if find.push(c).is_err() {
            return;
        }
        if matching(find).is_empty() {
            find.pop();
            return;
        }
        self.focus_matching_zone();
    }

    /// Takes back the last letter the time zones were narrowed by, and
    /// returns whether there was one.
    pub fn unfind_zone(&mut self) -> bool {
        let taken = self.zone_find_mut().and_then(|find| find.pop()).is_some();
        if taken {
            self.focus_matching_zone();
        }
        taken
    }

    /// Keeps focus on a zone the list still shows.
    fn focus_matching_zone(&mut self) {
        let Some(find) = self.zone_find_mut().map(|find| find.clone()) else {
            return;
        };
        let shown = matching(&find);
        let focused = self.screen().focus().current().and_then(keys::zone_of);
        if let Some(&first) = shown.first()
            && !focused.is_some_and(|i| shown.contains(&(i as u8)))
        {
            self.focus().request(keys::zone(usize::from(first)));
        }
    }

    /// Sets the time zone at `index`, and goes on: to the Chats screen on
    /// first run, back to Clock otherwise.
    pub fn choose_zone(&mut self, index: usize) {
        let Some(zone) = ZONES.get(index) else {
            return;
        };
        self.node.set_zone(zone.rule);
        self.refresh_settings();
        match self.screens.last() {
            Some(Screen::Setup { .. }) => self.finish_setup(),
            _ => _ = self.back(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(year: u16, month: u8, day: u8, hour: u8, minute: u8) -> DateParts {
        DateParts {
            year,
            month,
            day,
            hour,
            minute,
        }
    }

    #[test]
    fn turning_wraps_each_part_and_keeps_the_day_in_its_month() {
        let mut at = parts(2026, 1, 31, 23, 59);
        at.turn(Part::Minute, 1);
        assert_eq!(at.minute, 0, "the minute wraps without carrying");
        assert_eq!(at.hour, 23);
        at.turn(Part::Hour, 2);
        assert_eq!(at.hour, 1);
        at.turn(Part::Month, 1);
        assert_eq!((at.month, at.day), (2, 28), "January 31 into February");
        at.turn(Part::Month, -2);
        assert_eq!(at.month, 12);
        at.turn(Part::Day, 4);
        assert_eq!(at.day, 1);
        at.turn(Part::Year, -10);
        assert_eq!(at.year, 2024, "the year stops at its first");
        at.turn(Part::Half, 1);
        assert_eq!(at.hour, 13);
    }

    #[test]
    fn digits_type_a_part_and_start_afresh_when_too_large() {
        let mut at = parts(2026, 10, 19, 14, 32);
        let typed = at.type_digit(Part::Minute, None, 4, true);
        assert_eq!(at.minute, 4);
        let typed = at.type_digit(Part::Minute, typed, 5, true);
        assert_eq!((at.minute, typed), (45, None));
        // 1 then 3 is a 13th month: the 3 starts it over.
        let typed = at.type_digit(Part::Month, None, 1, true);
        assert_eq!(at.month, 1);
        at.type_digit(Part::Month, typed, 3, true);
        assert_eq!(at.month, 3);
        // On a 12-hour clock, the hour keeps its half.
        at.type_digit(Part::Hour, None, 9, false);
        assert_eq!(at.hour, 21);
        // The year takes four digits before it changes.
        let mut typed = None;
        for digit in [2, 0, 2, 7] {
            typed = at.type_digit(Part::Year, typed, digit, true);
        }
        assert_eq!((at.year, typed), (2027, None));
    }

    #[test]
    fn local_seconds_count_from_the_epoch() {
        assert_eq!(parts(1970, 1, 1, 0, 1).local_seconds(), 60);
        assert_eq!(parts(2026, 10, 19, 14, 32).local_seconds(), 1_792_420_320);
    }

    #[test]
    fn letters_narrow_the_zones_by_word() {
        let all = matching("");
        assert_eq!(all.len(), ZONES.len());
        let pacific = matching("pac");
        assert!(!pacific.is_empty());
        assert!(
            pacific
                .iter()
                .all(|&i| word_match(ZONES[usize::from(i)].name, "pac").is_some())
        );
        assert!(matching("qqq").is_empty());
    }
}
