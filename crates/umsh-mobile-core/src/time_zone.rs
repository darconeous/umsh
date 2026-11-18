//! The phone's time zone as the POSIX TZ rule `PROP_TZ_RULE` carries.

use umsh_hal::tz::{Rule, tzif_rule};
use umsh_ulcp_device::session::TZ_RULE_MAX_LEN;

/// Where the zone database lives on Apple's platforms, as on most Unix
/// systems.
#[cfg(not(target_os = "android"))]
const ZONEINFO: &str = "/usr/share/zoneinfo";

/// Android keeps every zone in one packed file instead. Bionic looks for it
/// in this order: a staged update under `/data` (Android 12 and 13 still
/// check there), the updatable time zone APEX, then the system image.
#[cfg(target_os = "android")]
const PACKED_TZDATA: [&str; 3] = [
    "/data/misc/zoneinfo/current/tzdata",
    "/apex/com.android.tzdata/etc/tz/tzdata",
    "/system/usr/share/zoneinfo/tzdata",
];

/// The zone's TZif record.
#[cfg(not(target_os = "android"))]
fn zone_tzif(identifier: &str) -> Option<Vec<u8>> {
    std::fs::read(format!("{ZONEINFO}/{identifier}")).ok()
}

/// The zone's TZif record, from the first packed file that is readable and
/// well formed. As in bionic, a zone missing from that file is missing: the
/// older files beneath it are not searched.
#[cfg(target_os = "android")]
fn zone_tzif(identifier: &str) -> Option<Vec<u8>> {
    let packed = PACKED_TZDATA
        .iter()
        .filter_map(|path| std::fs::read(path).ok())
        .find(|packed| packed_layout(packed).is_some())?;
    packed_record(&packed, identifier).map(<[u8]>::to_vec)
}

#[cfg(any(target_os = "android", test))]
const PACKED_HEADER_LEN: usize = 24;
#[cfg(any(target_os = "android", test))]
const PACKED_NAME_LEN: usize = 40;
#[cfg(any(target_os = "android", test))]
const PACKED_ENTRY_LEN: usize = PACKED_NAME_LEN + 12;

/// Big-endian `i32` at `at`, when it is there and not negative.
#[cfg(any(target_os = "android", test))]
fn packed_word(packed: &[u8], at: usize) -> Option<usize> {
    let bytes = packed.get(at..at.checked_add(4)?)?;
    usize::try_from(i32::from_be_bytes(bytes.try_into().ok()?)).ok()
}

/// The index and data offsets of a packed `tzdata` file, when its header is
/// well formed.
///
/// The file is a 24-byte header (`tzdata` and a version, NUL-terminated in
/// 12 bytes, then the index, data, and final offsets), an index of 52-byte
/// entries (a NUL-padded 40-byte name, then the record's start relative to
/// the data offset, its length, and an unused word), and the records. Every
/// number is a big-endian `i32`.
#[cfg(any(target_os = "android", test))]
fn packed_layout(packed: &[u8]) -> Option<(usize, usize)> {
    if packed.len() < PACKED_HEADER_LEN || !packed.starts_with(b"tzdata") || packed[11] != 0 {
        return None;
    }
    let (index, data) = (packed_word(packed, 12)?, packed_word(packed, 16)?);
    (PACKED_HEADER_LEN..=data)
        .contains(&index)
        .then_some((index, data))
}

/// The record named `identifier` in a packed `tzdata` file.
#[cfg(any(target_os = "android", test))]
fn packed_record<'a>(packed: &'a [u8], identifier: &str) -> Option<&'a [u8]> {
    let (index, data) = packed_layout(packed)?;
    let count = (data - index) / PACKED_ENTRY_LEN;
    let entry = (0..count)
        .map(|i| index + i * PACKED_ENTRY_LEN)
        .find(|&at| {
            packed.get(at..at + PACKED_NAME_LEN).is_some_and(|stored| {
                let end = stored
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(PACKED_NAME_LEN);
                &stored[..end] == identifier.as_bytes()
            })
        })?;
    let start = data.checked_add(packed_word(packed, entry + PACKED_NAME_LEN)?)?;
    let len = packed_word(packed, entry + PACKED_NAME_LEN + 4)?;
    packed.get(start..start.checked_add(len)?)
}

/// Whether a device accepts `rule` as its `PROP_TZ_RULE`: it parses, fits,
/// and keeps offsets within UTC−12:00 through UTC+14:00.
pub(crate) fn device_accepts(rule: &str) -> bool {
    if rule.len() > TZ_RULE_MAX_LEN {
        return false;
    }
    let Ok(parsed) = Rule::parse(rule) else {
        return false;
    };
    let civil = -12 * 60..=14 * 60;
    core::iter::once(parsed.std_offset_min())
        .chain(parsed.dst_offset_min())
        .all(|minutes| civil.contains(&minutes))
}

/// The rule a zone such as `America/Los_Angeles` follows now, from the
/// system's zone database. `None` when the zone is not there or its rule
/// is not one a device accepts.
#[uniffi::export]
pub fn zone_rule(identifier: String) -> Option<String> {
    if identifier.is_empty() || identifier.starts_with('/') || identifier.contains("..") {
        return None;
    }
    let tzif = zone_tzif(&identifier)?;
    let rule = tzif_rule(&tzif)?;
    device_accepts(rule).then(|| rule.to_owned())
}

/// A rule for a zone that keeps `minutes_east` all year, named by its
/// offset: −420 is `<-07>7`, 330 is `<+0530>-5:30`, and 0 is `UTC0`.
#[uniffi::export]
pub fn fixed_offset_rule(minutes_east: i16) -> String {
    if minutes_east == 0 {
        return "UTC0".to_owned();
    }
    let magnitude = minutes_east.unsigned_abs();
    let (hours, minutes) = (magnitude / 60, magnitude % 60);
    // A rule's offset is the one to add to local time to reach UTC, the
    // opposite sign of the abbreviation's.
    let (name_sign, rule_sign) = if minutes_east > 0 {
        ('+', "-")
    } else {
        ('-', "")
    };
    if minutes == 0 {
        format!("<{name_sign}{hours:02}>{rule_sign}{hours}")
    } else {
        format!("<{name_sign}{hours:02}{minutes:02}>{rule_sign}{hours}:{minutes:02}")
    }
}

/// The offset `rule` keeps at `unix_seconds`, in minutes east of UTC.
#[uniffi::export]
pub fn rule_offset_min(rule: String, unix_seconds: i64) -> Option<i16> {
    Rule::parse(&rule)
        .ok()
        .map(|parsed| parsed.offset_at(unix_seconds))
}

/// The abbreviation `rule` uses at `unix_seconds`, such as `PDT` or
/// `+0530`.
#[uniffi::export]
pub fn rule_abbreviation(rule: String, unix_seconds: i64) -> Option<String> {
    let parsed = Rule::parse(&rule).ok()?;
    let name = if parsed.is_dst_at(unix_seconds) {
        parsed.dst_name()?
    } else {
        parsed.std_name()
    };
    Some(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_offset_rules_read_back_as_their_offset() {
        assert_eq!(fixed_offset_rule(-420), "<-07>7");
        assert_eq!(fixed_offset_rule(330), "<+0530>-5:30");
        assert_eq!(fixed_offset_rule(0), "UTC0");
        assert_eq!(fixed_offset_rule(-570), "<-0930>9:30");
        assert_eq!(fixed_offset_rule(840), "<+14>-14");
        for minutes in -12 * 60..=14 * 60 {
            let rule = fixed_offset_rule(minutes);
            assert!(device_accepts(&rule), "{rule}");
            let parsed = Rule::parse(&rule).unwrap();
            assert_eq!(parsed.std_offset_min(), minutes, "{rule}");
            assert_eq!(parsed.dst_offset_min(), None, "{rule}");
        }
    }

    #[test]
    fn rule_offset_follows_daylight_saving() {
        let rule = "PST8PDT,M3.2.0,M11.1.0".to_owned();
        // 2026-01-15 and 2026-07-15, both at 12:00 UTC.
        assert_eq!(rule_offset_min(rule.clone(), 1_768_478_400), Some(-480));
        assert_eq!(rule_offset_min(rule.clone(), 1_784_116_800), Some(-420));
        assert_eq!(
            rule_abbreviation(rule.clone(), 1_784_116_800).as_deref(),
            Some("PDT")
        );
        assert_eq!(
            rule_abbreviation(rule, 1_768_478_400).as_deref(),
            Some("PST")
        );
        assert_eq!(rule_offset_min("nonsense".to_owned(), 0), None);
    }

    #[test]
    fn device_accepts_only_civil_rules() {
        assert!(device_accepts("UTC0"));
        assert!(device_accepts("CET-1CEST,M3.5.0,M10.5.0/3"));
        assert!(!device_accepts("<-13>13"));
        assert!(!device_accepts("<+15>-15"));
        assert!(!device_accepts(""));
        assert!(!device_accepts(&format!(
            "UTC0{}",
            " ".repeat(TZ_RULE_MAX_LEN)
        )));
    }

    #[test]
    fn zone_identifiers_stay_inside_the_database() {
        assert_eq!(zone_rule("../../etc/passwd".to_owned()), None);
        assert_eq!(zone_rule("/etc/passwd".to_owned()), None);
        assert_eq!(zone_rule(String::new()), None);
    }

    /// A packed file in Android's layout holding `records` in order.
    fn packed(records: &[(&str, &[u8])]) -> Vec<u8> {
        let index = 24;
        let data = index + 52 * records.len();
        let mut out = b"tzdata2026a\0".to_vec();
        for offset in [index, data, data] {
            out.extend_from_slice(&(offset as i32).to_be_bytes());
        }
        let mut start = 0;
        for (name, record) in records {
            let mut stored = [0u8; 40];
            stored[..name.len()].copy_from_slice(name.as_bytes());
            out.extend_from_slice(&stored);
            out.extend_from_slice(&(start as i32).to_be_bytes());
            out.extend_from_slice(&(record.len() as i32).to_be_bytes());
            out.extend_from_slice(&0i32.to_be_bytes());
            start += record.len();
        }
        for (_, record) in records {
            out.extend_from_slice(record);
        }
        out
    }

    #[test]
    fn packed_tzdata_yields_the_named_record() {
        let file = packed(&[
            ("America/Los_Angeles", b"first"),
            ("Asia/Kolkata", b"second record"),
            ("UTC", b""),
        ]);
        assert_eq!(
            packed_record(&file, "America/Los_Angeles"),
            Some(&b"first"[..])
        );
        assert_eq!(
            packed_record(&file, "Asia/Kolkata"),
            Some(&b"second record"[..])
        );
        assert_eq!(packed_record(&file, "UTC"), Some(&b""[..]));
        assert_eq!(packed_record(&file, "America/Los"), None);
        assert_eq!(packed_record(&file, "Europe/Paris"), None);
        assert_eq!(packed_record(&file, &"A".repeat(41)), None);
    }

    #[test]
    fn packed_tzdata_rejects_a_damaged_file() {
        let file = packed(&[("UTC", b"record")]);
        assert_eq!(packed_record(&file[..20], "UTC"), None);
        assert_eq!(packed_record(&file[..file.len() - 1], "UTC"), None);
        let mut wrong_magic = file.clone();
        wrong_magic[0] = b'x';
        assert_eq!(packed_record(&wrong_magic, "UTC"), None);
        assert!(packed_layout(&file).is_some());
        assert_eq!(packed_layout(&wrong_magic), None);
        let mut index_inside_header = file.clone();
        index_inside_header[12..16].copy_from_slice(&8i32.to_be_bytes());
        assert_eq!(packed_record(&index_inside_header, "UTC"), None);
        let mut negative_start = file.clone();
        negative_start[24 + 40..24 + 44].copy_from_slice(&(-1i32).to_be_bytes());
        assert_eq!(packed_record(&negative_start, "UTC"), None);
    }

    /// A real zone, packed the way Android packs it, yields the same rule
    /// as reading it from the system database.
    #[cfg(not(target_os = "android"))]
    #[test]
    fn packed_tzdata_record_carries_the_rule() {
        let Ok(tzif) = std::fs::read(format!("{ZONEINFO}/America/Los_Angeles")) else {
            return;
        };
        let file = packed(&[("Etc/UTC", b"x"), ("America/Los_Angeles", &tzif)]);
        let record = packed_record(&file, "America/Los_Angeles").unwrap();
        assert_eq!(tzif_rule(record), Some("PST8PDT,M3.2.0,M11.1.0"));
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn zone_rule_reads_the_system_database() {
        // Where the host has a database at all: Apple's and most Linux
        // systems ship one, a minimal container may not.
        if !std::path::Path::new(ZONEINFO).join("UTC").exists() {
            return;
        }
        let rule = zone_rule("America/Los_Angeles".to_owned()).unwrap();
        assert_eq!(rule, "PST8PDT,M3.2.0,M11.1.0");
    }
}
