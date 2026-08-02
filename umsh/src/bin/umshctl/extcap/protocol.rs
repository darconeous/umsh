//! Rendering the extcap control protocol.
//!
//! Wireshark parses these as `keyword {key=value}{key=value}` lines, one
//! per line, so every interpolated value has to be kept clear of the
//! delimiters. Nothing here does I/O: the whole wire format is a pure
//! function of the tool's state, which is what makes it testable without
//! a radio or a Wireshark.

use crate::connection::{DefaultDevice, Found};

/// The interface name. Wireshark writes this into its `recent` file and
/// into the preference keys for the configuration dialog, so it is
/// permanent: changing it silently orphans saved capture setups.
pub const INTERFACE: &str = "umsh";

/// pcap `LINKTYPE_LORATAP`. The radio frame arrives under a header
/// describing the channel it was heard on, so nothing has to be
/// invented the way the synthetic Ethernet encapsulation does.
pub const DLT_LORATAP: u32 = 270;

/// The `{call=}` of the reloadable radio selector.
pub const CALL_RADIO: &str = "--radio";

/// Strip the delimiters of the extcap grammar out of a value.
///
/// Device names come off the radio, so a name containing a brace or a
/// newline would otherwise be able to forge fields or whole lines.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '{' | '}' => '(',
            '\r' | '\n' | '\t' => ' ',
            other => other,
        })
        .collect()
}

/// The reply to `--extcap-interfaces`.
///
/// A saved default device is named here purely so the interface is
/// recognizable in Wireshark's list. It is read from the preferences
/// file, never from the radio: Wireshark runs this on every startup and
/// every refresh of the interface list, so it must not touch hardware.
pub fn interfaces(default: Option<&DefaultDevice>) -> String {
    let mut out = format!(
        "extcap {{version={}}}{{display=UMSH radio}}\n",
        env!("CARGO_PKG_VERSION"),
    );
    let display = match default.and_then(|device| device.name.as_deref()) {
        Some(name) => format!("UMSH radio ({})", sanitize(name)),
        None => "UMSH radio".to_string(),
    };
    out.push_str(&format!(
        "interface {{value={INTERFACE}}}{{display={display}}}\n"
    ));
    out
}

/// The reply to `--extcap-dlts`.
///
/// Exactly one line: Wireshark never passes a chosen DLT back on
/// `--capture`, so a second link type would be unactionable.
pub fn dlts() -> String {
    format!("dlt {{number={DLT_LORATAP}}}{{name=LORATAP}}{{display=LoRaTap}}\n")
}

/// The reply to `--extcap-config`: the capture-options dialog.
///
/// The RF overrides are strings rather than numbers on purpose. A
/// numeric extcap argument renders as a spin box that always holds a
/// value and is always passed, which would rewrite the live PHY of a
/// radio the user only wanted to listen to. Empty means "leave the
/// radio alone".
pub fn config() -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "arg {{number=0}}{{call={CALL_RADIO}}}{{display=Radio}}\
         {{tooltip=BLE radio to capture from. Leave empty to use the saved default, \
         then discover.}}{{type=selector}}{{reload=true}}{{placeholder=Scan for radios}}\
         {{required=false}}{{group=Connection}}\n"
    ));
    out.push_str(&radio_value_auto());
    out.push_str(
        "arg {number=1}{call=--serial-port}{display=Serial port}\
         {tooltip=Capture over a named serial port instead of BLE. A port must be named: \
         umshctl never probes serial ports, because opening one can reset or DFU-trigger \
         hardware.}{type=string}{required=false}{group=Connection}\n",
    );
    out.push_str(
        "arg {number=2}{call=--baud}{display=Serial bit rate}{type=unsigned}\
         {default=115200}{required=false}{group=Connection}\n",
    );
    out.push_str(
        "arg {number=3}{call=--umsh-only}{display=UMSH frames only}\
         {tooltip=Drop frames that are not valid UMSH before they reach Wireshark.}\
         {type=boolflag}{default=false}{group=Capture}\n",
    );
    out.push_str(
        "arg {number=4}{call=--idle-probe-secs}{display=Idle health probe (s)}\
         {tooltip=Seconds of silence before the link and channel RSSI are re-checked.}\
         {type=unsigned}{default=10}{range=1,3600}{group=Capture}\n",
    );
    out.push_str(
        "arg {number=5}{call=--no-reconnect}{display=Do not recover a dropped BLE link}\
         {type=boolflag}{default=false}{group=Capture}\n",
    );
    for (number, call, display, hint) in [
        (6, "--freq-khz", "Frequency (kHz)", ""),
        (7, "--bw-hz", "Bandwidth (Hz)", ""),
        (8, "--sf", "Spreading factor", " (5-12)"),
        (9, "--cr", "Coding rate denominator", " (5-8)"),
        (10, "--sync-word", "Sync word (hex)", ""),
    ] {
        out.push_str(&format!(
            "arg {{number={number}}}{{call={call}}}{{display={display}{hint}}}\
             {{tooltip=Live-only override, never saved to the radio. Leave empty to \
             capture on the radio's current configuration.}}{{type=string}}\
             {{required=false}}{{group=RF overrides}}\n"
        ));
    }
    out
}

/// The always-present first entry of the radio selector.
fn radio_value_auto() -> String {
    "value {arg=0}{value=}{display=Auto (saved default, then discover)}{default=true}\n".to_string()
}

/// The reply to `--extcap-reload-option=--radio`: what a scan just saw.
///
/// This is the one phase allowed to touch the radio, and only because
/// the user pressed Reload in the dialog.
pub fn radio_values(found: &[Found]) -> String {
    let mut out = radio_value_auto();
    for entry in found {
        let name = entry.name.as_deref().unwrap_or("(no name)");
        let rssi = match entry.rssi {
            Some(rssi) => format!("  ({rssi} dBm)"),
            None => String::new(),
        };
        out.push_str(&format!(
            "value {{arg=0}}{{value={}}}{{display={}{}}}\n",
            sanitize(&entry.id),
            sanitize(name),
            rssi,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(id: &str, name: Option<&str>, rssi: Option<i16>) -> Found {
        Found {
            id: id.to_string(),
            name: name.map(str::to_string),
            rssi,
        }
    }

    #[test]
    fn interfaces_names_the_saved_default() {
        let plain = interfaces(None);
        assert!(plain.contains("interface {value=umsh}{display=UMSH radio}"));

        let device = DefaultDevice {
            selector: "ABC-123".to_string(),
            name: Some("T-Echo".to_string()),
        };
        let named = interfaces(Some(&device));
        assert!(named.contains("{display=UMSH radio (T-Echo)}"), "{named}");
    }

    /// Wireshark cannot tell us which DLT the user picked, so offering a
    /// choice would be a lie.
    #[test]
    fn exactly_one_dlt_is_offered() {
        let text = dlts();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("{number=270}"));
    }

    #[test]
    fn config_numbers_are_contiguous_and_calls_unique() {
        let text = config();
        let mut numbers = Vec::new();
        let mut calls = Vec::new();
        for line in text.lines().filter(|line| line.starts_with("arg ")) {
            let number = line
                .split("{number=")
                .nth(1)
                .and_then(|rest| rest.split('}').next())
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let call = line
                .split("{call=")
                .nth(1)
                .and_then(|rest| rest.split('}').next())
                .unwrap()
                .to_string();
            numbers.push(number);
            calls.push(call);
        }
        assert_eq!(
            numbers,
            (0..numbers.len()).collect::<Vec<_>>(),
            "a gap or duplicate silently drops an argument from the dialog",
        );
        let mut unique = calls.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), calls.len(), "duplicate {{call=}}: {calls:?}");
    }

    /// Every `type=selector` needs at least one value line, or the
    /// dialog renders an empty, unusable dropdown.
    #[test]
    fn the_radio_selector_always_offers_auto() {
        assert!(config().contains("value {arg=0}{value=}"));
        assert!(radio_values(&[]).contains("{value=}"));
    }

    #[test]
    fn radio_values_render_name_and_rssi() {
        let text = radio_values(&[
            found("id-1", Some("T-Echo"), Some(-52)),
            found("id-2", None, None),
        ]);
        assert!(
            text.contains("{value=id-1}{display=T-Echo  (-52 dBm)}"),
            "{text}"
        );
        assert!(text.contains("{value=id-2}{display=(no name)}"), "{text}");
    }

    /// A device names itself over the air, so the name is untrusted
    /// input to a brace-delimited grammar.
    #[test]
    fn a_hostile_device_name_cannot_forge_lines() {
        let text = radio_values(&[found("id", Some("evil}\ninterface {value=fake"), None)]);
        assert_eq!(
            text.lines().count(),
            2,
            "auto entry plus exactly one device: {text}",
        );
        assert!(!text.contains("interface {value=fake"));
    }
}
