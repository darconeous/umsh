//! The time zones the clock offers: a row for each rule the zone database
//! follows today, west to east, under the name people know it by.
//!
//! `scripts/tz_rules.py --check` lists the rules the database follows that
//! are missing here, and those here that no zone follows any more.

use heapless::String;

use crate::model::Rule;

/// A time zone: what it is called, and the POSIX TZ rule it keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Zone {
    pub name: &'static str,
    pub rule: &'static str,
}

const fn zone(name: &'static str, rule: &'static str) -> Zone {
    Zone { name, rule }
}

/// West to east by standard time, and by name within an offset.
pub static ZONES: [Zone; 88] = [
    zone("Niue Time", "<-11>11"),
    zone("Samoa Standard Time", "SST11"),
    zone("Aleutian Time", "HST10HDT,M3.2.0,M11.1.0"),
    zone("Hawaii Time", "HST10"),
    zone("Tahiti Time", "<-10>10"),
    zone("Marquesas Time", "<-0930>9:30"),
    zone("Alaska Time", "AKST9AKDT,M3.2.0,M11.1.0"),
    zone("Gambier Time", "<-09>9"),
    zone("Pacific Time", "PST8PDT,M3.2.0,M11.1.0"),
    zone("Pitcairn Time", "<-08>8"),
    zone("Arizona", "MST7"),
    zone("Mountain Time", "MST7MDT,M3.2.0,M11.1.0"),
    zone("Central Standard Time", "CST6"),
    zone("Central Time", "CST6CDT,M3.2.0,M11.1.0"),
    zone("Easter Island Time", "<-06>6<-05>,M9.1.6/22,M4.1.6/22"),
    zone("Gal\u{e1}pagos Time", "<-06>6"),
    zone("Cuba Time", "CST5CDT,M3.2.0/0,M11.1.0/1"),
    zone("Eastern Standard Time", "EST5"),
    zone("Eastern Time", "EST5EDT,M3.2.0,M11.1.0"),
    zone("UTC\u{2212}5", "<-05>5"),
    zone("Atlantic Standard Time", "AST4"),
    zone("Atlantic Time", "AST4ADT,M3.2.0,M11.1.0"),
    zone("Chile Time", "<-04>4<-03>,M9.1.6/24,M4.1.6/24"),
    zone("UTC\u{2212}4", "<-04>4"),
    zone("Newfoundland Time", "NST3:30NDT,M3.2.0,M11.1.0"),
    zone("St. Pierre and Miquelon Time", "<-03>3<-02>,M3.2.0,M11.1.0"),
    zone("UTC\u{2212}3", "<-03>3"),
    zone("Greenland Time", "<-02>2<-01>,M3.5.0/-1,M10.5.0/0"),
    zone("UTC\u{2212}2", "<-02>2"),
    zone("Azores Time", "<-01>1<+00>,M3.5.0/0,M10.5.0/1"),
    zone("Cape Verde Time", "<-01>1"),
    zone("Greenwich Mean Time", "GMT0"),
    zone("Irish Time", "GMT0IST,M3.5.0/1,M10.5.0"),
    zone("Morocco Time", "<+00>0"),
    zone("Troll Time", "<+00>0<+02>-2,M3.5.0/1,M10.5.0/3"),
    zone("United Kingdom Time", "GMT0BST,M3.5.0/1,M10.5.0"),
    zone("Western European Time", "WET0WEST,M3.5.0/1,M10.5.0"),
    zone("Central European Standard Time", "CET-1"),
    zone("Central European Time", "CET-1CEST,M3.5.0,M10.5.0/3"),
    zone("West Africa Time", "WAT-1"),
    zone("Central Africa Time", "CAT-2"),
    zone("Eastern European Standard Time", "EET-2"),
    zone("Eastern European Time", "EET-2EEST,M3.5.0/3,M10.5.0/4"),
    zone("Egypt Time", "EET-2EEST,M4.5.5/0,M10.5.4/24"),
    zone("Israel Time", "IST-2IDT,M3.4.4/26,M10.5.0"),
    zone("Lebanon Time", "EET-2EEST,M3.5.0/0,M10.5.0/0"),
    zone("Palestine Time", "EET-2EEST,M3.4.4/50,M10.4.4/50"),
    zone("South Africa Time", "SAST-2"),
    zone("Arabia Time", "<+03>-3"),
    zone("East Africa Time", "EAT-3"),
    zone("Moscow Time", "MSK-3"),
    zone("Iran Time", "<+0330>-3:30"),
    zone("Gulf Time", "<+04>-4"),
    zone("Afghanistan Time", "<+0430>-4:30"),
    zone("Pakistan Time", "PKT-5"),
    zone("UTC+5", "<+05>-5"),
    zone("India Time", "IST-5:30"),
    zone("Sri Lanka Time", "<+0530>-5:30"),
    zone("Nepal Time", "<+0545>-5:45"),
    zone("UTC+6", "<+06>-6"),
    zone("Myanmar Time", "<+0630>-6:30"),
    zone("Indochina Time", "<+07>-7"),
    zone("Western Indonesia Time", "WIB-7"),
    zone("Central Indonesia Time", "WITA-8"),
    zone("China Time", "CST-8"),
    zone("Hong Kong Time", "HKT-8"),
    zone("Philippine Time", "PST-8"),
    zone("UTC+8", "<+08>-8"),
    zone("Western Australia Time", "AWST-8"),
    zone("Eucla Time", "<+0845>-8:45"),
    zone("Eastern Indonesia Time", "WIT-9"),
    zone("Japan Time", "JST-9"),
    zone("Korea Time", "KST-9"),
    zone("UTC+9", "<+09>-9"),
    zone("Northern Territory Time", "ACST-9:30"),
    zone("South Australia Time", "ACST-9:30ACDT,M10.1.0,M4.1.0/3"),
    zone("Chamorro Time", "ChST-10"),
    zone("Eastern Australia Time", "AEST-10AEDT,M10.1.0,M4.1.0/3"),
    zone("Queensland Time", "AEST-10"),
    zone("UTC+10", "<+10>-10"),
    zone("Lord Howe Time", "<+1030>-10:30<+11>-11,M10.1.0,M4.1.0"),
    zone("Norfolk Island Time", "<+11>-11<+12>,M10.1.0,M4.1.0/3"),
    zone("UTC+11", "<+11>-11"),
    zone("New Zealand Time", "NZST-12NZDT,M9.5.0,M4.1.0/3"),
    zone("UTC+12", "<+12>-12"),
    zone(
        "Chatham Islands Time",
        "<+1245>-12:45<+1345>,M9.5.0/2:45,M4.1.0/3:45",
    ),
    zone("UTC+13", "<+13>-13"),
    zone("Line Islands Time", "<+14>-14"),
];

impl Zone {
    /// The rule, read.
    #[must_use]
    pub fn read(&self) -> Rule {
        Rule::parse(self.rule).unwrap_or(Rule::UTC)
    }

    /// Whether the name already says the offset, as `UTC+5` does.
    #[must_use]
    pub fn named_by_offset(&self) -> bool {
        self.name.starts_with("UTC")
    }
}

/// Where `rule` is among [`ZONES`]: the zone written the same, or failing
/// that the first that keeps the same time.
#[must_use]
pub fn find(rule: &Rule) -> Option<usize> {
    ZONES
        .iter()
        .position(|zone| zone.read() == *rule)
        .or_else(|| ZONES.iter().position(|zone| zone.read().same_time_as(rule)))
}

/// The zone whose standard time is nearest `offset_min` minutes east, for
/// a list to start on when nothing better is known.
#[must_use]
pub fn nearest(offset_min: i16) -> usize {
    let mut best = 0;
    for (i, zone) in ZONES.iter().enumerate() {
        let away = |i: usize| (ZONES[i].read().std_offset_min() - offset_min).unsigned_abs();
        if (zone.read().std_offset_min() - offset_min).unsigned_abs() < away(best) {
            best = i;
        }
    }
    best
}

/// An offset as a zone list writes it: `UTC`, `UTC+2`, `UTC−3:30`.
#[must_use]
pub fn offset_text(offset_min: i16) -> String<12> {
    let mut text = String::new();
    _ = text.push_str("UTC");
    if offset_min != 0 {
        let sign = if offset_min < 0 { '\u{2212}' } else { '+' };
        let magnitude = offset_min.unsigned_abs();
        _ = core::fmt::write(&mut text, format_args!("{sign}{}", magnitude / 60));
        if !magnitude.is_multiple_of(60) {
            _ = core::fmt::write(&mut text, format_args!(":{:02}", magnitude % 60));
        }
    }
    text
}

/// What to call `rule`: its zone's name, or for a rule no zone keeps, its
/// abbreviations, such as `PST/PDT`.
#[must_use]
pub fn name(rule: &Rule) -> String<24> {
    let mut text = String::new();
    match find(rule) {
        Some(i) => _ = text.push_str(ZONES[i].name),
        None => {
            let std = rule.std_name();
            let plain = |name: &str| !name.starts_with(['+', '-']);
            match rule.dst_name() {
                _ if !plain(std) => _ = text.push_str(&offset_text(rule.std_offset_min())),
                Some(dst) if plain(dst) => {
                    _ = core::fmt::write(&mut text, format_args!("{std}/{dst}"));
                }
                _ => _ = text.push_str(std),
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_reads_and_runs_west_to_east() {
        let mut last = i16::MIN;
        for zone in &ZONES {
            let rule = Rule::parse(zone.rule).unwrap_or_else(|_| panic!("{}", zone.rule));
            assert!(
                rule.std_offset_min() >= last,
                "{} is out of order",
                zone.name
            );
            last = rule.std_offset_min();
        }
    }

    #[test]
    fn names_and_rules_are_each_listed_once() {
        for (i, a) in ZONES.iter().enumerate() {
            for b in &ZONES[i + 1..] {
                assert_ne!(a.name, b.name);
                assert_ne!(a.rule, b.rule);
            }
        }
    }

    #[test]
    fn a_rule_is_found_as_written_before_by_its_time() {
        let korea = Rule::parse("KST-9").unwrap();
        assert_eq!(ZONES[find(&korea).unwrap()].name, "Korea Time");
        // The same time, by other names: the first zone that keeps it.
        let eastern = Rule::parse("<-05>5<-04>,M3.2.0/2,M11.1.0").unwrap();
        assert_eq!(ZONES[find(&eastern).unwrap()].name, "Eastern Time");
        assert_eq!(name(&eastern).as_str(), "Eastern Time");
    }

    #[test]
    fn a_rule_no_zone_keeps_is_called_by_its_abbreviations() {
        let odd = Rule::parse("XST3XDT,M4.1.0,M10.1.0").unwrap();
        assert_eq!(find(&odd), None);
        assert_eq!(name(&odd).as_str(), "XST/XDT");
        let numeric = Rule::parse("<-0320>3:20").unwrap();
        assert_eq!(name(&numeric).as_str(), "UTC\u{2212}3:20");
    }

    #[test]
    fn offsets_are_written_as_zones() {
        assert_eq!(offset_text(0).as_str(), "UTC");
        assert_eq!(offset_text(120).as_str(), "UTC+2");
        assert_eq!(offset_text(-210).as_str(), "UTC\u{2212}3:30");
        assert_eq!(offset_text(345).as_str(), "UTC+5:45");
    }

    #[test]
    fn the_nearest_zone_is_by_standard_time() {
        assert_eq!(ZONES[nearest(-480)].read().std_offset_min(), -480);
        assert_eq!(ZONES[nearest(-470)].read().std_offset_min(), -480);
        assert_eq!(ZONES[nearest(14 * 60)].name, "Line Islands Time");
    }
}
