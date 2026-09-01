//! What `info` reports, subject by subject.
//!
//! Each topic names the properties it needs, renders them as report
//! lines, and renders them again as shell assignments. Nothing here
//! touches a device: a topic is a function from fetched octets to text,
//! which is what lets the whole report cost one exchange and lets every
//! rendering be tested without a radio.

use umsh::core::{PublicKey, RegionCode};
use umsh::node::location::NodeLocation;
use umsh::ulcp::{decode_capabilities, decode_filter_table, decode_status};
use umsh::ulcp_wire::Status;
use umsh::ulcp_wire::battery::BatteryStatus;
use umsh::ulcp_wire::ids::{DUTY_LIMIT_DISABLED, cap, prop, saved};
use umsh::ulcp_wire::items;

use super::props::PropSet;
use super::{battery_display, format_millilux};
use crate::command::values::FilterArg;
use crate::command::{duty_percent, format_duration};
use crate::output::hex;

/// What the renderers know beyond the properties themselves.
pub struct Context {
    /// The device's advertised capability codes.
    pub caps: Vec<u32>,
    /// Whether this device is reached over the mesh, where the
    /// host domain is not visible at all.
    pub remote: bool,
    /// `--expect-host-key`, which turns the host ownership line from a
    /// statement into a verdict.
    pub expect_host_key: Option<[u8; 32]>,
    /// Read during the attach handshake, so free to print.
    pub dev_version: String,
    pub dev_model: Option<String>,
}

impl Context {
    fn has(&self, capability: u32) -> bool {
        self.caps.contains(&capability)
    }
}

/// One line of a report: a label and what it says.
pub type Line = (String, String);

/// One subject the device can be asked about.
pub struct Topic {
    /// What to type after `info`.
    pub name: &'static str,
    /// What `--env` prefixes this topic's variables with.
    pub prefix: &'static str,
    /// Whether this device has anything to say on the subject.
    pub gate: fn(&Context) -> bool,
    /// The properties the renderers below read.
    pub keys: fn(&Context) -> Vec<u32>,
    pub render: fn(&PropSet, &Context) -> Vec<Line>,
    /// `NAME=VALUE` pairs, unprefixed — the caller adds [`Self::prefix`].
    ///
    /// A component the device did not report is an *absent* variable
    /// rather than an empty one, so `${RADIO_SF:-}` is how a script asks
    /// whether there is a spreading factor at all.
    pub env: fn(&PropSet, &Context) -> Vec<Line>,
}

/// Every subject, in the order a bare report prints them.
pub const TOPICS: &[Topic] = &[
    Topic {
        name: "device",
        prefix: "DEVICE",
        gate: |_| true,
        keys: |_| {
            vec![
                prop::DEV_NAME,
                prop::PROTOCOL_VERSION,
                prop::UPTIME,
                prop::SAVED,
                prop::BLE_ENABLED,
            ]
        },
        render: render_device,
        env: env_device,
    },
    Topic {
        name: "radio",
        prefix: "RADIO",
        gate: |_| true,
        keys: radio_keys,
        render: render_radio,
        env: env_radio,
    },
    Topic {
        name: "stats",
        prefix: "STATS",
        gate: |ctx| ctx.has(cap::STATS),
        keys: |_| {
            vec![
                prop::STAT_TX_PACKETS,
                prop::STAT_TX_CHANNEL_BUSY,
                prop::STAT_RX_PACKETS,
                prop::STAT_RX_BAD_CRC,
                prop::STAT_RX_NON_UMSH,
                prop::STAT_RX_ACCEPTED,
                prop::STAT_FORWARDED,
                prop::STAT_FORWARD_DROPPED,
                prop::STAT_FORWARD_CANCELLED,
                prop::PHY_DUTY_NOW,
                prop::UPTIME,
            ]
        },
        render: render_stats,
        env: env_stats,
    },
    Topic {
        name: "battery",
        prefix: "BATTERY",
        gate: |ctx| ctx.has(cap::BATTERY),
        keys: |_| vec![prop::BATTERY],
        render: render_battery,
        env: env_battery,
    },
    Topic {
        name: "identity",
        prefix: "IDENTITY",
        gate: |ctx| ctx.has(cap::DEV_IDENTITY) || ctx.has(cap::IDENT),
        keys: identity_keys,
        render: render_identity,
        env: env_identity,
    },
    Topic {
        name: "repeater",
        prefix: "REPEATER",
        gate: |ctx| ctx.has(cap::REPEATER),
        keys: |_| {
            vec![
                prop::MAC_REPEATER_ENABLED,
                prop::MAC_REPEATER_REGIONS,
                prop::MAC_REPEATER_DEFAULT_REGION,
                prop::MAC_REPEATER_MIN_RSSI,
                prop::MAC_REPEATER_MIN_SNR,
            ]
        },
        render: render_repeater,
        env: env_repeater,
    },
    Topic {
        name: "advert",
        prefix: "ADVERT",
        gate: |ctx| ctx.has(cap::ADVERT),
        keys: |_| {
            vec![
                prop::ADVERT_INTERVAL,
                prop::BEACON_INTERVAL,
                prop::STARTUP_BEACON,
            ]
        },
        render: render_advert,
        env: env_advert,
    },
    Topic {
        name: "gnss",
        prefix: "GNSS",
        gate: |ctx| ctx.has(cap::GNSS),
        keys: |_| {
            vec![
                prop::GNSS_ENABLED,
                prop::GNSS_FIX,
                prop::GNSS_SATELLITES,
                prop::GNSS_LOCATION,
                prop::GNSS_ALTITUDE,
                prop::GNSS_PRECISION,
                prop::GNSS_IDENT_UPDATE,
                prop::GNSS_IDENT_PRECISION,
                prop::GNSS_TIME_TRUST,
            ]
        },
        render: render_gnss,
        env: env_gnss,
    },
    Topic {
        name: "time",
        prefix: "TIME",
        gate: |ctx| ctx.has(cap::TIME),
        keys: |_| vec![prop::TIME, prop::TZ_OFFSET],
        render: render_time,
        env: env_time,
    },
    Topic {
        name: "sensors",
        prefix: "SENSORS",
        gate: |ctx| ctx.has(cap::ILLUMINANCE),
        keys: |_| vec![prop::ILLUMINANCE],
        render: render_sensors,
        env: env_sensors,
    },
    Topic {
        name: "host",
        // The host domain is a wire relationship: the mesh binding
        // cannot see it, so over a mesh session the topic is not offered
        // rather than offered and refused.
        prefix: "HOST",
        gate: |ctx| !ctx.remote && (ctx.has(cap::HOST_FILTER) || ctx.has(cap::HOST_KEYS)),
        keys: host_keys,
        render: render_host,
        env: env_host,
    },
];

/// The topic of that name, if there is one.
pub fn topic(name: &str) -> Option<&'static Topic> {
    TOPICS.iter().find(|topic| topic.name == name)
}

// ─── device ──────────────────────────────────────────────────────────

fn render_device(set: &PropSet, ctx: &Context) -> Vec<Line> {
    let mut lines = Vec::new();
    if let Some(name) = set.text(prop::DEV_NAME) {
        lines.push(("name".into(), format!("{name:?}")));
    }
    lines.push(("firmware".into(), ctx.dev_version.clone()));
    if let Some(model) = &ctx.dev_model {
        lines.push(("model".into(), model.clone()));
    }
    if let Some([major, minor, ..]) = set.bytes(prop::PROTOCOL_VERSION) {
        lines.push(("protocol".into(), format!("{major}.{minor}")));
    }
    if let Some(status) = set.bytes(prop::LAST_STATUS) {
        lines.push(("status".into(), format!("{:?}", decode_status(status))));
    }
    if let Some(seconds) = set.u32(prop::UPTIME) {
        lines.push((
            "uptime".into(),
            format!("{} ({seconds} s)", format_duration(seconds)),
        ));
    }
    if let Some(state) = set.u8(prop::SAVED) {
        lines.push((
            "saved".into(),
            match state {
                saved::NONE => "no".to_string(),
                saved::CURRENT => "yes".to_string(),
                saved::FALLBACK => "yes, but running on an older generation (re-save)".to_string(),
                saved::UNREADABLE => "unreadable — booted with defaults".to_string(),
                other => format!("unknown state {other}"),
            },
        ));
    }
    if let Some(enabled) = set.bool(prop::BLE_ENABLED) {
        lines.push(("bluetooth".into(), on_off(enabled).into()));
    }
    lines.push(("capabilities".into(), capability_list(set)));
    lines
}

fn env_device(set: &PropSet, ctx: &Context) -> Vec<Line> {
    let mut env = Vec::new();
    if let Some(name) = set.text(prop::DEV_NAME) {
        env.push(("NAME".into(), name));
    }
    env.push(("FIRMWARE".into(), ctx.dev_version.clone()));
    if let Some(model) = &ctx.dev_model {
        env.push(("MODEL".into(), model.clone()));
    }
    if let Some(status) = set.bytes(prop::LAST_STATUS) {
        env.push(("STATUS".into(), status_token(decode_status(status))));
    }
    if let Some(seconds) = set.u32(prop::UPTIME) {
        env.push(("UPTIME_S".into(), seconds.to_string()));
    }
    if let Some(state) = set.u8(prop::SAVED) {
        env.push((
            "SAVED".into(),
            u8::from(state == saved::CURRENT).to_string(),
        ));
    }
    if let Some(enabled) = set.bool(prop::BLE_ENABLED) {
        env.push(("BLUETOOTH".into(), bit(enabled)));
    }
    let caps = decode_capabilities(set.bytes(prop::CAPS).unwrap_or_default()).unwrap_or_default();
    env.push((
        "CAPABILITIES".into(),
        caps.iter()
            .map(|&code| capability_name(code))
            .collect::<Vec<_>>()
            .join(" "),
    ));
    env
}

/// A status as the bare mnemonic, without the Rust path a debug format
/// carries. `[ "$DEVICE_STATUS" = RESET_POWER_ON ]` is what a script
/// wants to write, and a status this build cannot name still reads as
/// something a script can compare.
fn status_token(status: Status) -> String {
    let debug = format!("{status:?}");
    debug
        .rsplit_once("::")
        .map_or(debug.clone(), |(_, name)| name.to_string())
}

fn capability_list(set: &PropSet) -> String {
    match decode_capabilities(set.bytes(prop::CAPS).unwrap_or_default()) {
        Ok(caps) if !caps.is_empty() => caps
            .iter()
            .map(|&code| capability_name(code))
            .collect::<Vec<_>>()
            .join(" "),
        Ok(_) => "none".to_string(),
        Err(_) => "malformed".to_string(),
    }
}

/// The spec mnemonic, or the bare number for a capability this build has
/// never heard of — a device newer than the tool still reports honestly.
fn capability_name(code: u32) -> String {
    umsh::ulcp_wire::capability_name(code).map_or_else(|| code.to_string(), str::to_owned)
}

// ─── radio ───────────────────────────────────────────────────────────

fn radio_keys(ctx: &Context) -> Vec<u32> {
    let mut keys = vec![
        prop::PHY_ENABLED,
        prop::PHY_FREQ,
        prop::PHY_TX_POWER,
        prop::PHY_MTU,
    ];
    if ctx.has(cap::PHY_LORA) {
        keys.extend([
            prop::PHY_LORA_BW,
            prop::PHY_LORA_SF,
            prop::PHY_LORA_CR,
            prop::PHY_LORA_SW,
        ]);
    }
    if ctx.has(cap::PHY_DUTY_LIMIT) {
        keys.extend([prop::PHY_DUTY_NOW, prop::PHY_DUTY_LIMIT]);
    }
    keys
}

fn render_radio(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let mut lines = Vec::new();
    if let Some(enabled) = set.bool(prop::PHY_ENABLED) {
        lines.push((
            "phy".into(),
            if enabled { "enabled" } else { "disabled" }.into(),
        ));
    }
    if let Some(khz) = set.u32(prop::PHY_FREQ) {
        lines.push(("frequency".into(), format!("{khz} kHz")));
    }
    let mut modulation = Vec::new();
    if let Some(bw) = set.u32(prop::PHY_LORA_BW) {
        modulation.push(format!("BW {bw} Hz"));
    }
    if let Some(sf) = set.u8(prop::PHY_LORA_SF) {
        modulation.push(format!("SF{sf}"));
    }
    if let Some(cr) = set.u8(prop::PHY_LORA_CR) {
        modulation.push(format!("CR 4/{cr}"));
    }
    if let Some(sw) = set.u16(prop::PHY_LORA_SW) {
        modulation.push(format!("sync 0x{sw:04x}"));
    }
    if !modulation.is_empty() {
        lines.push(("modulation".into(), modulation.join(", ")));
    }
    if let Some(dbm) = set.i8(prop::PHY_TX_POWER) {
        lines.push(("tx power".into(), format!("{dbm} dBm")));
    }
    if let Some(mtu) = set.u16(prop::PHY_MTU) {
        lines.push(("mtu".into(), format!("{mtu} bytes")));
    }
    if set.answered(prop::PHY_DUTY_NOW) || set.answered(prop::PHY_DUTY_LIMIT) {
        let now = set
            .u16(prop::PHY_DUTY_NOW)
            .map_or("unknown".to_string(), |raw| {
                format!("{:.1}%", duty_percent(raw))
            });
        let limit = set
            .u16(prop::PHY_DUTY_LIMIT)
            .map_or("unknown".to_string(), duty_limit);
        lines.push(("duty".into(), format!("now {now}, limit {limit}")));
    }
    lines
}

fn env_radio(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let mut env = Vec::new();
    if let Some(enabled) = set.bool(prop::PHY_ENABLED) {
        env.push(("ENABLED".into(), bit(enabled)));
    }
    if let Some(khz) = set.u32(prop::PHY_FREQ) {
        env.push(("FREQ_KHZ".into(), khz.to_string()));
    }
    if let Some(bw) = set.u32(prop::PHY_LORA_BW) {
        env.push(("BW_HZ".into(), bw.to_string()));
    }
    if let Some(sf) = set.u8(prop::PHY_LORA_SF) {
        env.push(("SF".into(), sf.to_string()));
    }
    if let Some(cr) = set.u8(prop::PHY_LORA_CR) {
        env.push(("CR".into(), cr.to_string()));
    }
    if let Some(dbm) = set.i8(prop::PHY_TX_POWER) {
        env.push(("TX_DBM".into(), dbm.to_string()));
    }
    if let Some(mtu) = set.u16(prop::PHY_MTU) {
        env.push(("MTU".into(), mtu.to_string()));
    }
    if let Some(raw) = set.u16(prop::PHY_DUTY_NOW) {
        env.push(("DUTY_PERCENT".into(), format!("{:.2}", duty_percent(raw))));
    }
    if let Some(raw) = set.u16(prop::PHY_DUTY_LIMIT) {
        env.push((
            "DUTY_LIMIT_PERCENT".into(),
            if raw == DUTY_LIMIT_DISABLED {
                "0".to_string()
            } else {
                format!("{:.2}", duty_percent(raw))
            },
        ));
    }
    env
}

fn duty_limit(raw: u16) -> String {
    if raw == DUTY_LIMIT_DISABLED {
        "disabled".to_string()
    } else {
        format!("{:.1}%", duty_percent(raw))
    }
}

// ─── statistics ──────────────────────────────────────────────────────

const STAT_FIELDS: &[(u32, &str, &str)] = &[
    (prop::STAT_TX_PACKETS, "tx packets", "TX_PACKETS"),
    (
        prop::STAT_TX_CHANNEL_BUSY,
        "tx channel busy",
        "TX_CHANNEL_BUSY",
    ),
    (prop::STAT_RX_PACKETS, "rx UMSH", "RX_PACKETS"),
    (prop::STAT_RX_BAD_CRC, "rx bad CRC", "RX_BAD_CRC"),
    (prop::STAT_RX_NON_UMSH, "rx non-UMSH", "RX_NON_UMSH"),
    (prop::STAT_RX_ACCEPTED, "rx accepted", "RX_ACCEPTED"),
    (prop::STAT_FORWARDED, "forwarded", "FORWARDED"),
    (
        prop::STAT_FORWARD_DROPPED,
        "forward policy drops",
        "FORWARD_DROPPED",
    ),
    (
        prop::STAT_FORWARD_CANCELLED,
        "forwards cancelled",
        "FORWARD_CANCELLED",
    ),
];

fn render_stats(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let mut lines = STAT_FIELDS
        .iter()
        .filter_map(|&(key, label, _)| {
            set.u32(key)
                .map(|value| (label.to_string(), value.to_string()))
        })
        .collect::<Vec<_>>();
    if let Some(raw) = set.u16(prop::PHY_DUTY_NOW) {
        lines.push(("tx duty cycle".into(), format!("{:.1}%", duty_percent(raw))));
    }
    if let Some(seconds) = set.u32(prop::UPTIME) {
        lines.push((
            "uptime".into(),
            format!("{} ({seconds} s)", format_duration(seconds)),
        ));
    }
    lines
}

fn env_stats(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let mut env = STAT_FIELDS
        .iter()
        .filter_map(|&(key, _, name)| {
            set.u32(key)
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect::<Vec<_>>();
    if let Some(raw) = set.u16(prop::PHY_DUTY_NOW) {
        env.push((
            "TX_DUTY_PERCENT".into(),
            format!("{:.2}", duty_percent(raw)),
        ));
    }
    if let Some(seconds) = set.u32(prop::UPTIME) {
        env.push(("UPTIME_S".into(), seconds.to_string()));
    }
    env
}

// ─── battery ─────────────────────────────────────────────────────────

fn render_battery(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    match battery_status(set) {
        Some(status) => vec![("battery".into(), battery_display(&status))],
        None => vec![("battery".into(), "not battery powered".into())],
    }
}

/// Kept exactly as it has always been spelled: scripts read these names,
/// and the point of an interface a shell `eval`s is that it does not move.
fn env_battery(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let Some(status) = battery_status(set) else {
        return vec![("PRESENT".into(), "0".into())];
    };
    let mut env = vec![("PRESENT".into(), "1".into())];
    if let Some(percent) = status.level_percent {
        env.push(("LEVEL".into(), format!("{:.2}", f32::from(percent) / 100.0)));
    }
    if let Some(mv) = status.voltage_mv {
        env.push(("VOLTS".into(), format!("{:.3}", f32::from(mv) / 1000.0)));
    }
    if let Some(state) = status.charge_state {
        env.push(("STATE".into(), charge_state_name(state).into()));
    }
    env
}

fn battery_status(set: &PropSet) -> Option<BatteryStatus> {
    BatteryStatus::decode(set.non_empty(prop::BATTERY)?).ok()
}

fn charge_state_name(state: umsh::ulcp_wire::battery::BatteryChargeState) -> &'static str {
    use umsh::ulcp_wire::battery::BatteryChargeState::{Charged, Charging, Discharging};
    match state {
        Discharging => "DISCHARGING",
        Charging => "CHARGING",
        Charged => "CHARGED",
    }
}

// ─── identity ────────────────────────────────────────────────────────

fn identity_keys(ctx: &Context) -> Vec<u32> {
    let mut keys = Vec::new();
    if ctx.has(cap::DEV_IDENTITY) {
        keys.extend([prop::DEV_KEY, prop::DEV_DISCOVERABLE]);
    }
    if ctx.has(cap::IDENT) {
        keys.extend([
            prop::IDENT_ROLE,
            prop::IDENT_MOBILE,
            prop::IDENT_LOCATION,
            prop::IDENT_ALTITUDE,
        ]);
    }
    keys
}

fn render_identity(set: &PropSet, ctx: &Context) -> Vec<Line> {
    let mut lines = Vec::new();
    if ctx.has(cap::DEV_IDENTITY) {
        lines.push((
            "key".into(),
            match set.key32(prop::DEV_KEY) {
                Some(key) => PublicKey(key).to_string(),
                None => "none (run `identity generate`)".to_string(),
            },
        ));
    }
    if let Some(role) = set.u8(prop::IDENT_ROLE) {
        lines.push(("role".into(), role.to_string()));
    } else if set.answered(prop::IDENT_ROLE) {
        lines.push(("role".into(), "derived from what the device does".into()));
    }
    if let Some(mobile) = set.bool(prop::IDENT_MOBILE) {
        lines.push((
            "mobility".into(),
            if mobile { "mobile" } else { "fixed" }.into(),
        ));
    }
    if let Some(discoverable) = set.bool(prop::DEV_DISCOVERABLE) {
        lines.push(("discoverable".into(), on_off(discoverable).into()));
    }
    match set.non_empty(prop::IDENT_LOCATION) {
        Some(location) => {
            lines.push((
                "location".into(),
                format!(
                    "{} ({} bytes, {})",
                    NodeLocation::from_bytes(location),
                    location.len(),
                    precision_cell(location.len() as u8)
                ),
            ));
        }
        None if set.answered(prop::IDENT_LOCATION) => {
            lines.push(("location".into(), "none advertised".into()));
        }
        None => {}
    }
    if let Some(meters) = set.non_empty(prop::IDENT_ALTITUDE).and_then(decode_sint) {
        lines.push(("altitude".into(), format!("{meters} m")));
    }
    lines
}

fn env_identity(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let mut env = Vec::new();
    if let Some(key) = set.key32(prop::DEV_KEY) {
        env.push(("KEY".into(), PublicKey(key).to_string()));
    }
    if let Some(role) = set.u8(prop::IDENT_ROLE) {
        env.push(("ROLE".into(), role.to_string()));
    }
    if let Some(mobile) = set.bool(prop::IDENT_MOBILE) {
        env.push(("MOBILE".into(), bit(mobile)));
    }
    if let Some(discoverable) = set.bool(prop::DEV_DISCOVERABLE) {
        env.push(("DISCOVERABLE".into(), bit(discoverable)));
    }
    if let Some(location) = set.non_empty(prop::IDENT_LOCATION) {
        env.push(("LOCATION".into(), hex(location)));
    }
    if let Some(meters) = set.non_empty(prop::IDENT_ALTITUDE).and_then(decode_sint) {
        env.push(("ALTITUDE_M".into(), meters.to_string()));
    }
    env
}

/// Decode the minimal-length signed integer `PROP_IDENT_ALTITUDE` uses:
/// as many octets as the value needs, big-endian, sign-extended from the
/// first.
fn decode_sint(value: &[u8]) -> Option<i32> {
    let (&first, _) = value.split_first()?;
    if value.len() > 4 {
        return None;
    }
    let mut wide = if first & 0x80 != 0 { -1i32 } else { 0 };
    for &byte in value {
        wide = (wide << 8) | i32::from(byte);
    }
    Some(wide)
}

/// The approximate cell size one precision names, at the equator. What
/// makes a precision meaningful is how large an area it discloses.
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

// ─── repeater ────────────────────────────────────────────────────────

fn render_repeater(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let enabled = set.bool(prop::MAC_REPEATER_ENABLED).unwrap_or(false);
    let mut lines = vec![("forwarding".into(), on_off(enabled).into())];
    // The gates are inert while forwarding is off, and printing five
    // settings that do nothing invites reading them as if they did.
    if !enabled {
        return lines;
    }
    lines.push((
        "regions".into(),
        crate::command::repeater::format_regions(&regions(set)),
    ));
    lines.push((
        "tags".into(),
        match default_region(set) {
            Some(code) => code.to_string(),
            None => "untagged".to_string(),
        },
    ));
    let rssi = set
        .non_empty(prop::MAC_REPEATER_MIN_RSSI)
        .and_then(|value| <[u8; 2]>::try_from(value).ok())
        .map(i16::from_le_bytes);
    let snr = set
        .non_empty(prop::MAC_REPEATER_MIN_SNR)
        .and_then(|value| value.first().copied())
        .map(|byte| byte as i8);
    lines.push((
        "floor".into(),
        format!(
            "{}/{}",
            rssi.map_or("any".to_string(), |dbm| format!("{dbm} dBm")),
            snr.map_or("any".to_string(), |db| format!("{db} dB"))
        ),
    ));
    lines
}

fn env_repeater(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let enabled = set.bool(prop::MAC_REPEATER_ENABLED).unwrap_or(false);
    let mut env = vec![("ENABLED".into(), bit(enabled))];
    let regions = regions(set);
    if !regions.is_empty() {
        env.push(("REGIONS".into(), regions.join(" ")));
    }
    if let Some(code) = default_region(set) {
        env.push(("DEFAULT_REGION".into(), code.to_string()));
    }
    env
}

fn regions(set: &PropSet) -> Vec<String> {
    set.bytes(prop::MAC_REPEATER_REGIONS)
        .and_then(|value| umsh::ulcp::decode_region_list(value).ok())
        .unwrap_or_default()
}

fn default_region(set: &PropSet) -> Option<RegionCode> {
    let value = set.non_empty(prop::MAC_REPEATER_DEFAULT_REGION)?;
    let bytes = <[u8; 2]>::try_from(value).ok()?;
    Some(RegionCode::from_bytes(bytes))
}

// ─── advert ──────────────────────────────────────────────────────────

fn render_advert(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let mut lines = Vec::new();
    if let Some(seconds) = set.u32(prop::ADVERT_INTERVAL) {
        lines.push(("interval".into(), interval(seconds)));
    }
    if let Some(seconds) = set.u32(prop::BEACON_INTERVAL) {
        lines.push(("beacon".into(), interval(seconds)));
    }
    if let Some(startup) = set.bool(prop::STARTUP_BEACON) {
        lines.push(("at startup".into(), on_off(startup).into()));
    }
    lines
}

fn env_advert(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let mut env = Vec::new();
    if let Some(seconds) = set.u32(prop::ADVERT_INTERVAL) {
        env.push(("INTERVAL_S".into(), seconds.to_string()));
    }
    if let Some(seconds) = set.u32(prop::BEACON_INTERVAL) {
        env.push(("BEACON_S".into(), seconds.to_string()));
    }
    if let Some(startup) = set.bool(prop::STARTUP_BEACON) {
        env.push(("STARTUP_BEACON".into(), bit(startup)));
    }
    env
}

fn interval(seconds: u32) -> String {
    if seconds == 0 {
        return "off".to_string();
    }
    format!("every {seconds} s ({})", format_duration(seconds))
}

// ─── gnss ────────────────────────────────────────────────────────────

fn render_gnss(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let enabled = set.bool(prop::GNSS_ENABLED).unwrap_or(false);
    let mut lines = vec![("receiver".into(), on_off(enabled).into())];
    if let Some(fix) = set.u8(prop::GNSS_FIX) {
        lines.push((
            "fix".into(),
            match fix {
                0 if enabled => "none (searching)".to_string(),
                0 => "none (receiver off)".to_string(),
                1 => "2D".to_string(),
                2 => "3D".to_string(),
                other => format!("unknown quality {other}"),
            },
        ));
    }
    if let Some([used, rest @ ..]) = set.bytes(prop::GNSS_SATELLITES) {
        lines.push((
            "satellites".into(),
            match rest.first() {
                Some(in_view) => format!("{used} used of {in_view} in view"),
                None => format!("{used} used"),
            },
        ));
    }
    if let Some(location) = set.non_empty(prop::GNSS_LOCATION) {
        lines.push((
            "location".into(),
            format!(
                "{} ({} bytes, {})",
                NodeLocation::from_bytes(location),
                location.len(),
                precision_cell(location.len() as u8)
            ),
        ));
    }
    if let Some(meters) = set.i32(prop::GNSS_ALTITUDE) {
        lines.push(("altitude".into(), format!("{meters} m")));
    }
    if let Some(dm) = set.u16(prop::GNSS_PRECISION) {
        lines.push((
            "precision".into(),
            format!("~{}.{} m (estimated)", dm / 10, dm % 10),
        ));
    }
    if let Some(update) = set.bool(prop::GNSS_IDENT_UPDATE) {
        let clamp = set.u8(prop::GNSS_IDENT_PRECISION).unwrap_or(5);
        lines.push((
            "identity update".into(),
            match update {
                true => format!("on, clamped to {clamp} bytes ({})", precision_cell(clamp)),
                false => format!("off (would clamp to {clamp} bytes)"),
            },
        ));
    }
    if let Some(trust) = set.bool(prop::GNSS_TIME_TRUST) {
        lines.push((
            "time trust".into(),
            match trust {
                true => "on (fixes set the clock)".to_string(),
                false => "off (fixes never set the clock)".to_string(),
            },
        ));
    }
    lines
}

fn env_gnss(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let mut env = Vec::new();
    if let Some(enabled) = set.bool(prop::GNSS_ENABLED) {
        env.push(("ENABLED".into(), bit(enabled)));
    }
    if let Some(fix) = set.u8(prop::GNSS_FIX) {
        env.push(("FIX".into(), fix.to_string()));
    }
    if let Some(used) = set.u8(prop::GNSS_SATELLITES) {
        env.push(("SATELLITES".into(), used.to_string()));
    }
    if let Some(location) = set.non_empty(prop::GNSS_LOCATION) {
        env.push(("LOCATION".into(), hex(location)));
    }
    if let Some(meters) = set.i32(prop::GNSS_ALTITUDE) {
        env.push(("ALTITUDE_M".into(), meters.to_string()));
    }
    if let Some(dm) = set.u16(prop::GNSS_PRECISION) {
        env.push(("PRECISION_DM".into(), dm.to_string()));
    }
    env
}

// ─── time ────────────────────────────────────────────────────────────

fn render_time(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let offset = set.i16(prop::TZ_OFFSET).unwrap_or(0);
    let mut lines = Vec::new();
    match set.u32(prop::TIME) {
        Some(epoch) => {
            lines.push(("clock".into(), crate::command::time::format_utc(epoch)));
            lines.push(("epoch".into(), epoch.to_string()));
        }
        // Empty is the device saying it does not know, which is a
        // different answer from a device without a clock at all.
        None => lines.push(("clock".into(), "not set".into())),
    }
    lines.push(("zone".into(), crate::command::time::format_tz(offset)));
    lines
}

fn env_time(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    let mut env = Vec::new();
    if let Some(epoch) = set.u32(prop::TIME) {
        env.push(("EPOCH".into(), epoch.to_string()));
    }
    if let Some(offset) = set.i16(prop::TZ_OFFSET) {
        env.push(("TZ_MINUTES".into(), offset.to_string()));
    }
    env
}

// ─── sensors ─────────────────────────────────────────────────────────

fn render_sensors(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    match set.u32(prop::ILLUMINANCE) {
        Some(millilux) => vec![("illuminance".into(), format_millilux(millilux))],
        None => vec![("illuminance".into(), "no reading".into())],
    }
}

fn env_sensors(set: &PropSet, _ctx: &Context) -> Vec<Line> {
    match set.u32(prop::ILLUMINANCE) {
        Some(millilux) => vec![("ILLUMINANCE_MLUX".into(), millilux.to_string())],
        None => Vec::new(),
    }
}

// ─── host ────────────────────────────────────────────────────────────

fn host_keys(ctx: &Context) -> Vec<u32> {
    let mut keys = vec![prop::HOST_KEY];
    if ctx.has(cap::HOST_FILTER) {
        keys.push(prop::HOST_RX_FILTERS);
    }
    if ctx.has(cap::HOST_KEYS) {
        keys.extend([prop::HOST_CHANNEL_KEYS, prop::HOST_PEER_KEYS]);
    }
    if ctx.has(cap::HOST_AUTO_ACK) {
        keys.push(prop::HOST_AUTO_ACK);
    }
    if ctx.has(cap::HOST_RX_QUEUE) {
        keys.extend([
            prop::HOST_RX_QUEUE_COUNT,
            prop::HOST_RX_QUEUE_CAPACITY,
            prop::HOST_RX_QUEUE_DROPPED,
        ]);
    }
    keys
}

fn render_host(set: &PropSet, ctx: &Context) -> Vec<Line> {
    let mut lines = vec![("owner".into(), ownership(set, ctx))];
    if let Some(filters) = filters(set) {
        lines.push(("filters".into(), filter_list(&filters)));
    }
    if let Some(ids) = digest_items(set, prop::HOST_CHANNEL_KEYS, 2) {
        let display = match ids.is_empty() {
            true => "none".to_string(),
            false => ids.iter().map(|id| hex(id)).collect::<Vec<_>>().join(", "),
        };
        lines.push((
            "channel keys".into(),
            format!("{} (ids: {display})", ids.len()),
        ));
    }
    if let Some(peers) = digest_items(set, prop::HOST_PEER_KEYS, 32) {
        let display = match peers.is_empty() {
            true => "none".to_string(),
            false => peers
                .iter()
                .map(|key| crate::output::address(key))
                .collect::<Vec<_>>()
                .join(", "),
        };
        lines.push(("peer keys".into(), format!("{} ({display})", peers.len())));
    }
    if let Some(auto_ack) = set.bool(prop::HOST_AUTO_ACK) {
        lines.push(("auto-ack".into(), on_off(auto_ack).into()));
    }
    if let (Some(count), Some(dropped)) = (
        set.u16(prop::HOST_RX_QUEUE_COUNT),
        set.u32(prop::HOST_RX_QUEUE_DROPPED),
    ) {
        let capacity = set
            .u16(prop::HOST_RX_QUEUE_CAPACITY)
            .map_or("?".to_string(), |capacity| capacity.to_string());
        lines.push((
            "rx queue".into(),
            format!("{count} buffered of {capacity}, {dropped} dropped since boot"),
        ));
    }
    lines
}

fn env_host(set: &PropSet, ctx: &Context) -> Vec<Line> {
    let mut env = Vec::new();
    // An unclaimed device has no key to report, so the variable is
    // absent and CLAIMED is what a script tests.
    if set.answered(prop::HOST_KEY) {
        env.push((
            "CLAIMED".into(),
            bit(set.non_empty(prop::HOST_KEY).is_some()),
        ));
    }
    if let Some(key) = set.key32(prop::HOST_KEY) {
        env.push(("KEY".into(), PublicKey(key).to_string()));
        if let Some(expected) = ctx.expect_host_key {
            env.push(("OURS".into(), bit(expected == key)));
        }
    }
    if let Some(auto_ack) = set.bool(prop::HOST_AUTO_ACK) {
        env.push(("AUTO_ACK".into(), bit(auto_ack)));
    }
    if let Some(count) = set.u16(prop::HOST_RX_QUEUE_COUNT) {
        env.push(("QUEUE_COUNT".into(), count.to_string()));
    }
    if let Some(dropped) = set.u32(prop::HOST_RX_QUEUE_DROPPED) {
        env.push(("QUEUE_DROPPED".into(), dropped.to_string()));
    }
    env
}

/// Who this device answers to, and whether that is who was expected.
fn ownership(set: &PropSet, ctx: &Context) -> String {
    match (set.non_empty(prop::HOST_KEY), ctx.expect_host_key) {
        (None, _) if set.answered(prop::HOST_KEY) => "unclaimed (no host)".to_string(),
        (None, _) => "unsupported".to_string(),
        (Some(key), Some(expected)) if key == expected => "matches --expect-host-key".to_string(),
        (Some(key), Some(_)) => format!("ANOTHER HOST: {}", crate::output::address(key)),
        (Some(key), None) => crate::output::address(key),
    }
}

fn filters(set: &PropSet) -> Option<Vec<items::Filter>> {
    decode_filter_table(set.bytes(prop::HOST_RX_FILTERS)?).ok()
}

fn filter_list(filters: &[items::Filter]) -> String {
    if filters.is_empty() {
        return "none".to_string();
    }
    filters
        .iter()
        .map(|filter| FilterArg(*filter).to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Split a digest table of fixed-width items. A table whose length is
/// not a multiple of the item width is not one this can read, and saying
/// so beats printing a plausible-looking prefix.
fn digest_items(set: &PropSet, key: u32, width: usize) -> Option<Vec<&[u8]>> {
    let value = set.bytes(key)?;
    if !value.len().is_multiple_of(width) {
        return None;
    }
    Some(value.chunks_exact(width).collect())
}

// ─── shared spellings ────────────────────────────────────────────────

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

/// Booleans in `--env` output are 0 or 1: `[ "$RADIO_ENABLED" = 1 ]` is
/// the shell's natural test, and "on" would only invite string
/// comparison against a word that might change.
fn bit(value: bool) -> String {
    u8::from(value).to_string()
}

/// Status codes and keys are safe by construction, but a device name is
/// whatever somebody typed into it. Everything that could carry a space
/// or a quote goes through this before a shell sees it.
pub fn shell_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '+'));
    if safe {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// A refusal worth reporting rather than passing over in silence.
///
/// Absent is the ordinary answer for an optional property, so a topic
/// prints nothing for one. A device that refused for a reason of its own
/// is different, and worth one line.
pub fn refusals(set: &PropSet, keys: &[u32]) -> Vec<(u32, Status)> {
    keys.iter()
        .filter_map(|&key| set.refusal(key).map(|status| (key, status)))
        .filter(|(_, status)| !matches!(*status, Status::UNIMPLEMENTED | Status::PROP_NOT_FOUND))
        .collect()
}
