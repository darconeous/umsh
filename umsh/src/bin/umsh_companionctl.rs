//! Companion-radio management: inspection, provisioning, device
//! identity, persistence, and pairing-PIN configuration for an NCP
//! over USB serial or BLE.
//!
//! Attaches with the full-protocol non-resetting handshake
//! ([`CompanionRadio::attach_existing`]), so pointing this tool at an
//! autonomously operating board never disturbs its configuration —
//! only the command explicitly given changes anything.

#![cfg_attr(
    not(any(feature = "serial-radio", feature = "ble-radio")),
    allow(unused_variables, dead_code)
)]

use umsh::companion::ids::{DUTY_LIMIT_DISABLED, cap, prop};
use umsh::companion::items::{Filter, PeerKeyEntry};
use umsh::companion_radio::{
    CompanionRadio, CompanionRadioConfig, FrameLink, HostOwnership, HostProvisioning,
};
use umsh::core::PublicKey;

const USAGE: &str = "\
usage: umsh-companionctl <serial-port> <command> [options]\n\
       umsh-companionctl --ble[=selector] <command> [options]\n\
       umsh-companionctl --ble-scan\n\n\
Manages a companion-radio NCP without disturbing it: attaches with the\n\
non-resetting full-protocol handshake, so an autonomously operating\n\
board keeps its configuration unless the command changes it.\n\n\
Commands:\n\
  info                  print capabilities, ownership, PHY state, and\n\
                        provisioning digests; changes nothing\n\
  provision             establish host provisioning (options below)\n\
  identity              print the device identity public key\n\
  identity generate     generate a device identity if none exists\n\
  set-name <name>       set the human-readable device name\n\
  save                  persist live state across reboots (CMD_SAVE)\n\
  restore               revert live state to the saved snapshot\n\
  clear                 erase persisted state; live state keeps running\n\
  factory-reset         clear + reboot into factory state (needs --yes)\n\
  reset                 protocol reset (CMD_RST): state returns to its\n\
                        post-reset values, restoring any saved\n\
                        snapshot; the MCU does not reboot\n\
  pin <6-digits|clear>  set or clear the persisted BLE pairing PIN\n\
  duty                  print duty-cycle usage and limit\n\
  duty limit <N|off>    set PROP_PHY_DUTY_LIMIT on its raw 0-65535\n\
                        scale (655 \u{2248} 1% of the hour); `off` disables\n\
                        enforcement\n\
  dev-channel [list]    list device-identity channel ids (digest form)\n\
  dev-channel add <KEY>    add a device channel key (the on-board node\n\
                           joins it and processes its multicast)\n\
  dev-channel remove <KEY> remove a device channel key\n\
  dev-peer [list]       list device-identity peer public keys\n\
  dev-peer add <KEY>       add a device peer public key\n\
  dev-peer remove <KEY>    remove a device peer public key\n\n\
--ble-scan lists nearby companion radios (id, name, RSSI) without\n\
connecting; the id works as a --ble= selector.\n\n\
Options:\n\
  --baud=115200           serial bit rate\n\
  --trace                 print every companion frame on stderr\n\
  --expect-host-key=KEY   info: report ownership relative to this key\n\
  --host-key=KEY          provision: host identity public key (required)\n\
  --channel-key=KEY       provision: channel key; repeatable\n\
  --peer=PUB,KENC,KMIC    provision: peer public key plus 16-byte hex\n\
                          pairwise secrets; repeatable\n\
  --filter=SPEC           provision: dest-hint:HHHHHH, channel-id:HHHH,\n\
                          or pkt-type:N; repeatable\n\
  --auto-ack=on|off       provision: delegated MAC acks (default on)\n\
  --file=PATH             provision: read the same settings from a file\n\
                          (`setting = value` lines, `#` comments)\n\
  --force                 provision: displace another host's provisioning\n\
  --no-save               leave a mutation live-only (mutating commands\n\
                          otherwise persist automatically via CMD_SAVE)\n\
  --yes                   factory-reset: confirm the wipe\n\n\
KEY values are 44-character base58 or 64-character hex. Secrets are\n\
never echoed in output or traces.\n";

const COMMANDS: &[&str] = &[
    "info",
    "provision",
    "identity",
    "set-name",
    "save",
    "restore",
    "clear",
    "factory-reset",
    "reset",
    "pin",
    "duty",
    "dev-channel",
    "dev-peer",
];

#[derive(Debug, PartialEq, Eq)]
enum Transport {
    Serial(String),
    Ble(Option<String>),
    /// `--ble-scan`: list companion radios without connecting.
    BleScan,
}

#[derive(Debug)]
enum Command {
    Info { expected: Option<[u8; 32]> },
    Provision { desired: HostProvisioning, force: bool },
    IdentityShow,
    IdentityGenerate,
    SetName(String),
    Save,
    Restore,
    Clear,
    FactoryReset,
    Reset,
    Pin(Option<u32>),
    /// `duty` (`None`: report usage + limit) / `duty limit <value>`.
    Duty(Option<u16>),
    DevChannel(TableOp),
    DevPeer(TableOp),
    /// `--ble-scan` (a transport mode more than a command; carried here
    /// so the invocation stays one shape).
    BleScan,
}

/// One operation on a device-domain key table (`PROP_DEV_CHANNEL_KEYS`
/// / `PROP_DEV_PEERS`).
#[derive(Debug, PartialEq, Eq)]
enum TableOp {
    List,
    Add([u8; 32]),
    Remove([u8; 32]),
}

#[derive(Debug)]
struct Invocation {
    transport: Transport,
    baud: u32,
    trace: bool,
    /// Skip the automatic `CMD_SAVE` after a mutating command. As a
    /// one-command-per-invocation tool there is no later "save before
    /// quitting?" moment, so mutations persist by default.
    no_save: bool,
    command: Command,
}

/// Provisioning inputs accumulated from flags and file lines; both
/// sources share the same `setting = value` vocabulary.
#[derive(Debug, Default)]
struct ProvisionArgs {
    host_key: Option<[u8; 32]>,
    channel_keys: Vec<[u8; 32]>,
    peer_keys: Vec<PeerKeyEntry>,
    filters: Vec<Filter>,
    auto_ack: Option<bool>,
}

impl ProvisionArgs {
    fn add(&mut self, setting: &str, value: &str) -> Result<(), String> {
        match setting {
            "host-key" => {
                if self.host_key.is_some() {
                    return Err("host-key given more than once".into());
                }
                self.host_key = Some(parse_key32(value)?);
            }
            "channel-key" => self.channel_keys.push(parse_key32(value)?),
            "peer" => self.peer_keys.push(parse_peer(value)?),
            "filter" => self.filters.push(parse_filter(value)?),
            "auto-ack" => {
                if self.auto_ack.is_some() {
                    return Err("auto-ack given more than once".into());
                }
                self.auto_ack = Some(parse_bool(value)?);
            }
            other => return Err(format!("unknown provisioning setting {other:?}")),
        }
        Ok(())
    }

    fn finish(self) -> Result<HostProvisioning, String> {
        Ok(HostProvisioning {
            host_key: self
                .host_key
                .ok_or("provisioning requires a host-key (flag or file)")?,
            filters: self.filters,
            channel_keys: self.channel_keys,
            peer_keys: self.peer_keys,
            auto_ack: self.auto_ack.unwrap_or(true),
        })
    }
}

fn parse_key32(text: &str) -> Result<[u8; 32], String> {
    text.parse::<PublicKey>()
        .map(|key| key.0)
        .map_err(|error| format!("expected 44-char base58 or 64-char hex key: {error}"))
}

fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let text = text.trim();
    if text.len() != 2 * N || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("expected {} hex characters, got {text:?}", 2 * N));
    }
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16)
            .map_err(|error| error.to_string())?;
    }
    Ok(out)
}

fn parse_bool(text: &str) -> Result<bool, String> {
    match text {
        "on" | "true" | "1" => Ok(true),
        "off" | "false" | "0" => Ok(false),
        other => Err(format!("expected on or off, got {other:?}")),
    }
}

/// `PUB,KENC,KMIC` (or whitespace-separated): a peer public key and the
/// two 16-byte pairwise secrets, hex.
fn parse_peer(text: &str) -> Result<PeerKeyEntry, String> {
    let fields: Vec<&str> = text
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|field| !field.is_empty())
        .collect();
    let [public_key, k_enc, k_mic] = fields[..] else {
        return Err(format!(
            "expected peer as PUB,KENC,KMIC (got {} fields)",
            fields.len()
        ));
    };
    Ok(PeerKeyEntry {
        public_key: parse_key32(public_key)?,
        k_enc: parse_hex::<16>(k_enc)?,
        k_mic: parse_hex::<16>(k_mic)?,
    })
}

/// `dest-hint:HHHHHH`, `channel-id:HHHH`, or `pkt-type:N` (`:` or
/// whitespace between type and value).
fn parse_filter(text: &str) -> Result<Filter, String> {
    let fields: Vec<&str> = text
        .split(|c: char| c == ':' || c.is_whitespace())
        .filter(|field| !field.is_empty())
        .collect();
    let [kind, value] = fields[..] else {
        return Err(format!("expected filter as TYPE:VALUE, got {text:?}"));
    };
    match kind {
        "dest-hint" => Ok(Filter::DestHint(parse_hex::<3>(value)?)),
        "channel-id" => Ok(Filter::ChannelId(parse_hex::<2>(value)?)),
        "pkt-type" => {
            let pkt_type = match value.strip_prefix("0x") {
                Some(hex) => u8::from_str_radix(hex, 16),
                None => value.parse(),
            }
            .map_err(|error| format!("pkt-type: {error}"))?;
            Ok(Filter::PktType(pkt_type))
        }
        other => Err(format!(
            "unknown filter type {other:?}; expected dest-hint, channel-id, or pkt-type"
        )),
    }
}

fn parse_pin(text: &str) -> Result<u32, String> {
    if text.len() == 6 && text.chars().all(|c| c.is_ascii_digit()) {
        text.parse::<u32>().map_err(|error| error.to_string())
    } else {
        Err(format!("expected a 6-digit PIN or `clear`, got {text:?}"))
    }
}

fn parse_provision_file(text: &str, prov: &mut ProvisionArgs) -> Result<(), String> {
    for (number, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (setting, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected `setting = value`", number + 1))?;
        prov.add(setting.trim(), value.trim())
            .map_err(|error| format!("line {}: {error}", number + 1))?;
    }
    Ok(())
}

fn parse_invocation(args: &[String]) -> Result<Invocation, String> {
    let mut index = 0;
    let first = args.get(index).ok_or("missing transport")?.clone();
    index += 1;
    let transport = if first == "--ble-scan" {
        if let Some(extra) = args.get(index) {
            return Err(format!("--ble-scan takes no arguments (got {extra:?})"));
        }
        return Ok(Invocation {
            transport: Transport::BleScan,
            baud: 115_200,
            trace: false,
            no_save: false,
            command: Command::BleScan,
        });
    } else if let Some(rest) = first.strip_prefix("--ble") {
        let selector = match rest.strip_prefix('=') {
            Some(selector) => Some(selector.to_string()),
            None if rest.is_empty() => match args.get(index) {
                Some(next) if !next.starts_with('-') && !COMMANDS.contains(&next.as_str()) => {
                    index += 1;
                    Some(next.clone())
                }
                _ => None,
            },
            None => return Err(format!("unrecognized transport {first:?}")),
        };
        Transport::Ble(selector)
    } else if first.starts_with('-') {
        return Err(format!("unrecognized option {first:?}; transport comes first"));
    } else {
        Transport::Serial(first)
    };

    let word = args.get(index).ok_or("missing command")?.clone();
    index += 1;
    if !COMMANDS.contains(&word.as_str()) {
        return Err(format!("unknown command {word:?}"));
    }

    let mut baud = 115_200u32;
    let mut trace = false;
    let mut expect_host_key = None;
    let mut force = false;
    let mut no_save = false;
    let mut yes = false;
    let mut file: Option<String> = None;
    let mut prov = ProvisionArgs::default();
    let mut positionals: Vec<String> = Vec::new();

    while index < args.len() {
        let arg = args[index].clone();
        if !arg.starts_with("--") {
            positionals.push(arg);
            index += 1;
            continue;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (name.to_string(), Some(value.to_string())),
            None => (arg, None),
        };
        let take = |index: &mut usize| -> Result<String, String> {
            if let Some(value) = &inline {
                return Ok(value.clone());
            }
            *index += 1;
            args.get(*index)
                .cloned()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        let provision_only = || -> Result<(), String> {
            if word == "provision" {
                Ok(())
            } else {
                Err(format!("{name} only applies to provision"))
            }
        };
        let no_value = || -> Result<(), String> {
            if inline.is_some() {
                Err(format!("{name} takes no value"))
            } else {
                Ok(())
            }
        };
        match name.as_str() {
            "--baud" => {
                baud = take(&mut index)?
                    .parse()
                    .map_err(|error| format!("--baud: {error}"))?;
            }
            "--trace" => {
                no_value()?;
                trace = true;
            }
            "--expect-host-key" => {
                if word != "info" {
                    return Err("--expect-host-key only applies to info".into());
                }
                expect_host_key = Some(parse_key32(&take(&mut index)?)?);
            }
            "--host-key" => {
                provision_only()?;
                let value = take(&mut index)?;
                prov.add("host-key", &value)?;
            }
            "--channel-key" => {
                provision_only()?;
                let value = take(&mut index)?;
                prov.add("channel-key", &value)?;
            }
            "--peer" => {
                provision_only()?;
                let value = take(&mut index)?;
                prov.add("peer", &value)?;
            }
            "--filter" => {
                provision_only()?;
                let value = take(&mut index)?;
                prov.add("filter", &value)?;
            }
            "--auto-ack" => {
                provision_only()?;
                let value = take(&mut index)?;
                prov.add("auto-ack", &value)?;
            }
            "--file" => {
                provision_only()?;
                file = Some(take(&mut index)?);
            }
            "--force" => {
                provision_only()?;
                no_value()?;
                force = true;
            }
            "--no-save" => {
                if !matches!(
                    word.as_str(),
                    "provision" | "set-name" | "duty" | "dev-channel" | "dev-peer"
                ) {
                    return Err(format!("{name} only applies to mutating commands"));
                }
                no_value()?;
                no_save = true;
            }
            "--yes" => {
                if word != "factory-reset" {
                    return Err("--yes only applies to factory-reset".into());
                }
                no_value()?;
                yes = true;
            }
            other => return Err(format!("unknown option {other}")),
        }
        index += 1;
    }

    let no_positionals = |positionals: &[String]| -> Result<(), String> {
        match positionals.first() {
            Some(extra) => Err(format!("{word} does not take {extra:?}")),
            None => Ok(()),
        }
    };
    let command = match word.as_str() {
        "info" => {
            no_positionals(&positionals)?;
            Command::Info {
                expected: expect_host_key,
            }
        }
        "provision" => {
            no_positionals(&positionals)?;
            if let Some(path) = &file {
                let text = std::fs::read_to_string(path)
                    .map_err(|error| format!("{path}: {error}"))?;
                parse_provision_file(&text, &mut prov)
                    .map_err(|error| format!("{path}: {error}"))?;
            }
            Command::Provision {
                desired: prov.finish()?,
                force,
            }
        }
        "identity" => match positionals.first().map(String::as_str) {
            None => Command::IdentityShow,
            Some("generate") if positionals.len() == 1 => Command::IdentityGenerate,
            Some(other) => return Err(format!("identity does not take {other:?}")),
        },
        "set-name" => {
            let [name] = &positionals[..] else {
                return Err("set-name takes exactly one name".into());
            };
            Command::SetName(name.clone())
        }
        "save" => {
            no_positionals(&positionals)?;
            Command::Save
        }
        "restore" => {
            no_positionals(&positionals)?;
            Command::Restore
        }
        "clear" => {
            no_positionals(&positionals)?;
            Command::Clear
        }
        "factory-reset" => {
            no_positionals(&positionals)?;
            if !yes {
                return Err(
                    "factory-reset erases all persisted provisioning, including the \
                     device identity; re-run with --yes to confirm"
                        .into(),
                );
            }
            Command::FactoryReset
        }
        "reset" => {
            no_positionals(&positionals)?;
            Command::Reset
        }
        "pin" => match positionals.first().map(String::as_str) {
            Some("clear") if positionals.len() == 1 => Command::Pin(None),
            Some(digits) if positionals.len() == 1 => Command::Pin(Some(parse_pin(digits)?)),
            _ => return Err("pin takes exactly one argument: a 6-digit PIN or `clear`".into()),
        },
        "duty" => match positionals.first().map(String::as_str) {
            None => Command::Duty(None),
            Some("limit") => {
                let [_, value] = &positionals[..] else {
                    return Err("duty limit takes exactly one value (0-65535 or `off`)".into());
                };
                Command::Duty(Some(parse_duty_limit(value)?))
            }
            Some(other) => return Err(format!("duty does not take {other:?}")),
        },
        "dev-channel" => Command::DevChannel(parse_table_op(&word, &positionals)?),
        "dev-peer" => Command::DevPeer(parse_table_op(&word, &positionals)?),
        _ => unreachable!("command word validated above"),
    };

    Ok(Invocation {
        transport,
        baud,
        trace,
        no_save,
        command,
    })
}

fn parse_table_op(word: &str, positionals: &[String]) -> Result<TableOp, String> {
    match positionals.first().map(String::as_str) {
        None | Some("list") if positionals.len() <= 1 => Ok(TableOp::List),
        Some("add") if positionals.len() == 2 => Ok(TableOp::Add(parse_key32(&positionals[1])?)),
        Some("remove") if positionals.len() == 2 => {
            Ok(TableOp::Remove(parse_key32(&positionals[1])?))
        }
        _ => Err(format!("{word} takes `list`, `add <KEY>`, or `remove <KEY>`")),
    }
}

/// The RF parameters here only size the driver's airtime-derived
/// timeouts; `attach_existing` never writes PHY configuration.
fn attach_config() -> CompanionRadioConfig {
    CompanionRadioConfig::new(910_525, 62_500, 7, 5)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn cap_name(code: u32) -> String {
    match code {
        cap::WRITABLE_RAW_STREAM => "WRITABLE_RAW_STREAM".into(),
        cap::PHY_DUTY_LIMIT => "PHY_DUTY_LIMIT".into(),
        cap::PHY_LORA => "PHY_LORA".into(),
        cap::HOST_FILTER => "HOST_FILTER".into(),
        cap::HOST_RX_QUEUE => "HOST_RX_QUEUE".into(),
        cap::HOST_KEYS => "HOST_KEYS".into(),
        cap::HOST_AUTO_ACK => "HOST_AUTO_ACK".into(),
        cap::SAVE => "SAVE".into(),
        cap::DEV_IDENTITY => "DEV_IDENTITY".into(),
        cap::DEV_NAME => "DEV_NAME".into(),
        other => other.to_string(),
    }
}

fn filter_display(filter: &Filter) -> String {
    match filter {
        Filter::DestHint(hint) => format!("dest-hint:{}", hex(hint)),
        Filter::ChannelId(id) => format!("channel-id:{}", hex(id)),
        Filter::PktType(pkt_type) => format!("pkt-type:{pkt_type}"),
    }
}

fn decode_u16(value: &[u8]) -> Option<u16> {
    <[u8; 2]>::try_from(value).ok().map(u16::from_le_bytes)
}

fn duty_percent(raw: u16) -> f64 {
    f64::from(raw) * 100.0 / 65535.0
}

async fn info<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
    expected: Option<[u8; 32]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sync = radio.sync(expected.as_ref()).await?;

    println!("{:<14}{:?}", "device name:", sync.device_name);
    match (sync.has_capability(cap::DEV_IDENTITY), sync.dev_key) {
        (true, Some(key)) => println!("{:<14}{}", "identity:", PublicKey(key)),
        (true, None) => println!("{:<14}none (run `identity generate`)", "identity:"),
        (false, _) => println!("{:<14}unsupported", "identity:"),
    }
    if sync.reset_since_last_contact {
        println!(
            "{:<14}{:?} (reset since last host contact)",
            "status:", sync.last_status
        );
    } else {
        println!("{:<14}{:?}", "status:", sync.last_status);
    }
    println!(
        "{:<14}{}",
        "capabilities:",
        sync.capabilities
            .iter()
            .map(|&code| cap_name(code))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let ownership = match (sync.ownership, expected.is_some()) {
        (HostOwnership::Ours, _) => "configured host key matches --expect-host-key".to_string(),
        (HostOwnership::Unclaimed, _) => "unclaimed (no host provisioned)".to_string(),
        (HostOwnership::Unsupported, _) => "unsupported (minimal protocol)".to_string(),
        (HostOwnership::OtherHost(key), true) => {
            format!("ANOTHER HOST: {}", PublicKey(key))
        }
        (HostOwnership::OtherHost(key), false) => PublicKey(key).to_string(),
    };
    println!("{:<14}{ownership}", "host:");

    let mut phy = vec![
        if sync.phy_enabled {
            "enabled".to_string()
        } else {
            "disabled".to_string()
        },
        format!("{} kHz", sync.freq_khz),
    ];
    if sync.has_capability(cap::PHY_LORA) {
        if let Some(bw) = radio.get_prop(prop::PHY_LORA_BW).await.ok().and_then(|v| {
            <[u8; 4]>::try_from(v.as_slice()).ok().map(u32::from_le_bytes)
        }) {
            phy.push(format!("BW {bw} Hz"));
        }
        if let Some(sf) = radio
            .get_prop(prop::PHY_LORA_SF)
            .await
            .ok()
            .and_then(|v| v.first().copied())
        {
            phy.push(format!("SF{sf}"));
        }
        if let Some(cr) = radio
            .get_prop(prop::PHY_LORA_CR)
            .await
            .ok()
            .and_then(|v| v.first().copied())
        {
            phy.push(format!("CR 4/{cr}"));
        }
        if let Some(sw) = radio
            .get_prop(prop::PHY_LORA_SW)
            .await
            .ok()
            .and_then(|v| decode_u16(&v))
        {
            phy.push(format!("sync 0x{sw:04x}"));
        }
    }
    if let Some(power) = radio
        .get_prop(prop::PHY_TX_POWER)
        .await
        .ok()
        .and_then(|v| v.first().copied())
    {
        phy.push(format!("TX {} dBm", power as i8));
    }
    println!("{:<14}{}", "phy:", phy.join(", "));

    if sync.has_capability(cap::PHY_DUTY_LIMIT) {
        let now = radio
            .get_prop(prop::PHY_DUTY_NOW)
            .await
            .ok()
            .and_then(|v| decode_u16(&v));
        let limit = radio
            .get_prop(prop::PHY_DUTY_LIMIT)
            .await
            .ok()
            .and_then(|v| decode_u16(&v));
        let now = now.map_or("unknown".to_string(), |raw| {
            format!("{:.1}%", duty_percent(raw))
        });
        let limit = limit.map_or("unknown".to_string(), |raw| {
            if raw == DUTY_LIMIT_DISABLED {
                "disabled".to_string()
            } else {
                format!("{:.1}%", duty_percent(raw))
            }
        });
        println!("{:<14}now {now}, limit {limit}", "duty:");
    }
    if let Some(saved) = sync.saved {
        println!(
            "{:<14}{}",
            "saved:",
            if saved { "yes" } else { "no" }
        );
    }
    if let (Some(count), Some(dropped)) = (sync.queue_count, sync.queue_dropped) {
        let capacity = radio
            .get_prop(prop::HOST_RX_QUEUE_CAPACITY)
            .await
            .ok()
            .and_then(|v| decode_u16(&v))
            .map_or("?".to_string(), |capacity| capacity.to_string());
        println!(
            "{:<14}{count} buffered of {capacity}, {dropped} dropped since boot",
            "rx queue:"
        );
    }
    if let Some(filters) = &sync.filters {
        let display = if filters.is_empty() {
            "none".to_string()
        } else {
            filters
                .iter()
                .map(filter_display)
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!("{:<14}{display}", "filters:");
    }
    if let Some(ids) = &sync.host_channel_ids {
        let display = if ids.is_empty() {
            "none".to_string()
        } else {
            ids.iter().map(|id| hex(id)).collect::<Vec<_>>().join(", ")
        };
        println!("{:<14}{} (ids: {display})", "channel keys:", ids.len());
    }
    if let Some(peers) = &sync.host_peer_keys {
        let display = if peers.is_empty() {
            "none".to_string()
        } else {
            peers
                .iter()
                .map(|key| PublicKey(*key).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!("{:<14}{} ({display})", "peer keys:", peers.len());
    }
    if let Some(auto_ack) = sync.auto_ack {
        println!(
            "{:<14}{}",
            "auto-ack:",
            if auto_ack { "on" } else { "off" }
        );
    }
    Ok(())
}

async fn provision<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
    desired: HostProvisioning,
    force: bool,
    no_save: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let sync = radio.sync(Some(&desired.host_key)).await?;
    match sync.ownership {
        HostOwnership::Unsupported => {
            return Err("this NCP does not support host provisioning (no CAP_HOST_FILTER)".into());
        }
        HostOwnership::OtherHost(other) if !force => {
            return Err(format!(
                "the NCP is provisioned for another host ({}); re-run with --force to \
                 displace it (its host domain will be wiped)",
                PublicKey(other)
            )
            .into());
        }
        _ => {}
    }
    let report = radio.provision(&desired).await?;
    if report.host_replaced {
        println!("host identity replaced; the previous host domain was wiped");
    }
    if report.filters_replaced {
        println!("filter table replaced ({} entries)", desired.filters.len());
    }
    if report.channels_replaced {
        println!(
            "channel-key table replaced ({} keys)",
            desired.channel_keys.len()
        );
    } else if report.channels_inserted > 0 {
        println!("channel keys inserted: {}", report.channels_inserted);
    }
    if report.peers_inserted > 0 {
        println!("peer entries inserted: {}", report.peers_inserted);
    }
    if report.peers_removed > 0 {
        println!("peer entries removed: {}", report.peers_removed);
    }
    if report.auto_ack_changed {
        println!(
            "auto-ack set to {}",
            if desired.auto_ack { "on" } else { "off" }
        );
    }
    if !report.changed() {
        println!("already provisioned as requested; nothing changed");
    }
    persist_mutation(radio, no_save, report.changed()).await
}

/// Finish a mutating command: persist by default (there is no later
/// "save before quitting?" moment in a one-shot tool), or report the
/// live-only state under `--no-save`.
async fn persist_mutation<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
    no_save: bool,
    changed: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !changed {
        return Ok(());
    }
    if no_save {
        println!("note: --no-save — changes are live only; the save command persists them");
    } else {
        radio.save().await?;
        println!("saved: changes persist across reboots");
    }
    Ok(())
}

async fn identity_show<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
) -> Result<(), Box<dyn std::error::Error>> {
    let value = radio.get_prop(prop::DEV_KEY).await?;
    match <[u8; 32]>::try_from(value.as_slice()) {
        Ok(key) => println!("device identity: {}", PublicKey(key)),
        Err(_) if value.is_empty() => {
            println!("no device identity configured (run `identity generate`)");
        }
        Err(_) => return Err("malformed PROP_DEV_KEY".into()),
    }
    Ok(())
}

async fn identity_generate<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
) -> Result<(), Box<dyn std::error::Error>> {
    let value = radio.get_prop(prop::DEV_KEY).await?;
    if let Ok(key) = <[u8; 32]>::try_from(value.as_slice()) {
        println!("device identity already exists: {}", PublicKey(key));
        println!("(identities are never regenerated in place; factory-reset discards one)");
        return Ok(());
    }
    let key = radio.ensure_device_identity().await?;
    println!("generated device identity: {}", PublicKey(key));
    println!("(persisted immediately; device identities are independent of save/restore)");
    Ok(())
}

async fn dispatch<L: FrameLink>(
    link: L,
    invocation: Invocation,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = CompanionRadio::attach_existing(link, attach_config()).await?;
    if invocation.trace {
        radio.set_frame_trace(Some(Box::new(|direction, line| {
            eprintln!("trace {direction} {line}");
        })));
    }
    println!(
        "attached: ncp={} boot_status={:?}",
        radio.ncp_version(),
        radio.boot_status()
    );
    let no_save = invocation.no_save;
    match invocation.command {
        Command::Info { expected } => info(&mut radio, expected).await,
        Command::Provision { desired, force } => {
            provision(&mut radio, desired, force, no_save).await
        }
        Command::IdentityShow => identity_show(&mut radio).await,
        Command::IdentityGenerate => identity_generate(&mut radio).await,
        Command::SetName(name) => {
            radio.set_device_name(&name).await?;
            println!("device name set to {name:?}");
            persist_mutation(&mut radio, no_save, true).await
        }
        Command::Save => {
            radio.save().await?;
            println!("saved: live state persists across reboots");
            Ok(())
        }
        Command::Restore => {
            let completion = radio.restore().await?;
            println!("restored live state from the saved snapshot ({completion:?} form)");
            Ok(())
        }
        Command::Clear => {
            radio.clear().await?;
            println!(
                "cleared: persisted state erased; live state keeps running until reboot \
                 (BLE bonds and pairing PIN are retained)"
            );
            Ok(())
        }
        Command::FactoryReset => {
            radio.clear().await?;
            let status = radio.reset().await?;
            println!(
                "factory reset complete ({status:?}); BLE bonds and pairing PIN are retained"
            );
            Ok(())
        }
        Command::Reset => {
            let status = radio.reset().await?;
            println!("reset complete ({status:?})");
            Ok(())
        }
        Command::Pin(pin) => {
            radio.set_ble_pairing_pin(pin).await?;
            match pin {
                Some(_) => println!("BLE pairing PIN set (persisted; applies to new pairings)"),
                None => println!("BLE pairing PIN cleared"),
            }
            Ok(())
        }
        Command::Duty(limit) => duty(&mut radio, limit, no_save).await,
        Command::DevChannel(op) => {
            dev_table(&mut radio, prop::DEV_CHANNEL_KEYS, "channel", op, no_save).await
        }
        Command::DevPeer(op) => {
            dev_table(&mut radio, prop::DEV_PEERS, "peer", op, no_save).await
        }
        // --ble-scan never dispatches: it is handled before any link is
        // opened.
        Command::BleScan => unreachable!("scan handled in run()"),
    }
}

fn parse_duty_limit(value: &str) -> Result<u16, String> {
    if value == "off" {
        return Ok(u16::MAX);
    }
    value
        .parse::<u16>()
        .map_err(|_| format!("expected 0-65535 or `off`, got {value:?}"))
}

fn print_duty_limit(raw: u16) {
    match raw {
        u16::MAX => println!("duty limit off (enforcement disabled)"),
        raw => println!("duty limit {raw} ({:.2}% of the hour)", duty_percent(raw)),
    }
}

/// Report or bound the combined duty-cycle budget. The limit spans
/// every radio client on the device (host transmits, delegated acks,
/// and the on-board node's own traffic draw from one ledger), and
/// `PROP_PHY_DUTY_NOW` reports that combined figure.
async fn duty<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
    limit: Option<u16>,
    no_save: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(limit) = limit {
        let echoed = radio.set_prop(prop::PHY_DUTY_LIMIT, &limit.to_le_bytes()).await?;
        print_duty_limit(decode_u16(&echoed).ok_or("malformed PHY_DUTY_LIMIT echo")?);
        return persist_mutation(radio, no_save, true).await;
    }
    let now = radio.get_prop(prop::PHY_DUTY_NOW).await?;
    let now = decode_u16(&now).ok_or("malformed PHY_DUTY_NOW")?;
    let limit = radio.get_prop(prop::PHY_DUTY_LIMIT).await?;
    println!("duty now   {now} ({:.2}% of the hour)", duty_percent(now));
    print_duty_limit(decode_u16(&limit).ok_or("malformed PHY_DUTY_LIMIT")?);
    Ok(())
}

/// Operate on one device-domain key table. The digest form differs by
/// table (2-byte channel id vs the 32-byte peer key itself), so
/// listings and mutation reports print whatever digest the NCP quotes.
async fn dev_table<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
    key: u32,
    noun: &str,
    op: TableOp,
    no_save: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match op {
        TableOp::List => {
            let value = radio.get_prop(key).await?;
            let digest_len = if key == prop::DEV_CHANNEL_KEYS { 2 } else { 32 };
            if value.is_empty() {
                println!("no device {noun}s provisioned");
            } else if value.len() % digest_len != 0 {
                return Err(format!("malformed device {noun} listing").into());
            } else {
                for digest in value.chunks(digest_len) {
                    println!("{}", hex(digest));
                }
            }
            Ok(())
        }
        TableOp::Add(item) => {
            let digest = radio.insert_prop_item(key, &item).await?;
            println!("device {noun} added (digest {})", hex(&digest));
            persist_mutation(radio, no_save, true).await
        }
        TableOp::Remove(item) => {
            let digest = radio.remove_prop_item(key, &item).await?;
            println!("device {noun} removed (digest {})", hex(&digest));
            persist_mutation(radio, no_save, true).await
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print!("{USAGE}");
        std::process::exit(if args.is_empty() { 2 } else { 0 });
    }
    let invocation = match parse_invocation(&args) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("error: {error}");
            eprintln!();
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(error) = run(invocation).await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run(invocation: Invocation) -> Result<(), Box<dyn std::error::Error>> {
    match &invocation.transport {
        Transport::Serial(port) => {
            #[cfg(feature = "serial-radio")]
            {
                use tokio_serial::SerialPortBuilderExt;
                use umsh::companion_radio::SerialFrameLink;
                let stream = tokio_serial::new(port, invocation.baud).open_native_async()?;
                return dispatch(SerialFrameLink::new(stream), invocation).await;
            }
            #[cfg(not(feature = "serial-radio"))]
            Err("the serial-radio feature is required for a serial port".into())
        }
        Transport::Ble(selector) => {
            #[cfg(feature = "ble-radio")]
            {
                use umsh::companion_radio::{BleFrameLink, BleFrameLinkConfig};
                let link =
                    BleFrameLink::connect(selector.as_deref(), BleFrameLinkConfig::default())
                        .await?;
                return dispatch(link, invocation).await;
            }
            #[cfg(not(feature = "ble-radio"))]
            Err("the ble-radio feature is required for --ble".into())
        }
        Transport::BleScan => {
            #[cfg(feature = "ble-radio")]
            {
                use umsh::companion_radio::BleFrameLink;
                let timeout = std::time::Duration::from_secs(5);
                println!("scanning for companion radios ({timeout:?})...");
                let results = BleFrameLink::scan(timeout).await?;
                if results.is_empty() {
                    println!("no companion radios found");
                } else {
                    for result in results {
                        let name = result.name.as_deref().unwrap_or("(no name)");
                        match result.rssi {
                            Some(rssi) => {
                                println!("{}  {name}  rssi {rssi} dBm", result.id)
                            }
                            None => println!("{}  {name}", result.id),
                        }
                    }
                }
                return Ok(());
            }
            #[cfg(not(feature = "ble-radio"))]
            Err("the ble-radio feature is required for --ble-scan".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    const KEY_HEX: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";

    #[test]
    fn parses_serial_transport_and_command() {
        let invocation = parse_invocation(&args(&["/dev/cu.usbmodem101", "info"])).unwrap();
        assert_eq!(
            invocation.transport,
            Transport::Serial("/dev/cu.usbmodem101".into())
        );
        assert!(matches!(invocation.command, Command::Info { expected: None }));
        assert_eq!(invocation.baud, 115_200);
    }

    #[test]
    fn ble_selector_forms_are_unambiguous() {
        let bare = parse_invocation(&args(&["--ble", "info"])).unwrap();
        assert_eq!(bare.transport, Transport::Ble(None));

        let next_arg = parse_invocation(&args(&["--ble", "UMSH T-Echo NCP", "info"])).unwrap();
        assert_eq!(
            next_arg.transport,
            Transport::Ble(Some("UMSH T-Echo NCP".into()))
        );

        let equals = parse_invocation(&args(&["--ble=UMSH T-1000E NCP", "info"])).unwrap();
        assert_eq!(
            equals.transport,
            Transport::Ble(Some("UMSH T-1000E NCP".into()))
        );

        // A selector that collides with a command word needs the = form.
        let collision = parse_invocation(&args(&["--ble=info", "info"])).unwrap();
        assert_eq!(collision.transport, Transport::Ble(Some("info".into())));
    }

    #[test]
    fn provision_flags_build_the_desired_state() {
        let invocation = parse_invocation(&args(&[
            "--ble",
            "provision",
            &format!("--host-key={KEY_HEX}"),
            "--channel-key",
            KEY_HEX,
            &format!("--peer={KEY_HEX},{},{}", "e0".repeat(16), "50".repeat(16)),
            "--filter=pkt-type:1",
            "--filter",
            "channel-id:9b68",
            "--auto-ack=off",
            "--force",
            "--no-save",
        ]))
        .unwrap();
        let Command::Provision { desired, force } = invocation.command else {
            panic!("expected provision");
        };
        assert!(force && invocation.no_save);
        assert_eq!(desired.host_key, [0xC4; 32]);
        assert_eq!(desired.channel_keys, vec![[0xC4; 32]]);
        assert_eq!(desired.peer_keys.len(), 1);
        assert_eq!(desired.peer_keys[0].k_enc, [0xE0; 16]);
        assert_eq!(desired.peer_keys[0].k_mic, [0x50; 16]);
        assert_eq!(
            desired.filters,
            vec![Filter::PktType(1), Filter::ChannelId([0x9B, 0x68])]
        );
        assert!(!desired.auto_ack);
    }

    #[test]
    fn provision_requires_a_host_key() {
        let error = parse_invocation(&args(&["--ble", "provision"])).unwrap_err();
        assert!(error.contains("host-key"), "{error}");
    }

    #[test]
    fn provision_file_lines_share_the_flag_vocabulary() {
        let mut prov = ProvisionArgs::default();
        let text = format!(
            "# operator provisioning\n\
             host-key = {KEY_HEX}\n\
             auto-ack = on\n\
             channel-key = {KEY_HEX}   # primary channel\n\
             peer = {KEY_HEX} {} {}\n\
             filter = pkt-type 1\n",
            "e0".repeat(16),
            "50".repeat(16),
        );
        parse_provision_file(&text, &mut prov).unwrap();
        let desired = prov.finish().unwrap();
        assert_eq!(desired.host_key, [0xC4; 32]);
        assert!(desired.auto_ack);
        assert_eq!(desired.channel_keys.len(), 1);
        assert_eq!(desired.peer_keys.len(), 1);
        assert_eq!(desired.filters, vec![Filter::PktType(1)]);
    }

    #[test]
    fn duplicate_scalar_settings_are_rejected() {
        let mut prov = ProvisionArgs::default();
        prov.add("host-key", KEY_HEX).unwrap();
        let error = prov.add("host-key", KEY_HEX).unwrap_err();
        assert!(error.contains("more than once"), "{error}");
    }

    #[test]
    fn parses_filters() {
        assert_eq!(
            parse_filter("dest-hint:a1b2c3").unwrap(),
            Filter::DestHint([0xA1, 0xB2, 0xC3])
        );
        assert_eq!(
            parse_filter("channel-id 9b68").unwrap(),
            Filter::ChannelId([0x9B, 0x68])
        );
        assert_eq!(parse_filter("pkt-type:0x0a").unwrap(), Filter::PktType(10));
        assert!(parse_filter("src-hint:aabbcc").is_err());
        assert!(parse_filter("dest-hint:zzzzzz").is_err());
    }

    #[test]
    fn pin_requires_six_digits_or_clear() {
        let set = parse_invocation(&args(&["--ble", "pin", "042319"])).unwrap();
        assert!(matches!(set.command, Command::Pin(Some(42_319))));
        let clear = parse_invocation(&args(&["--ble", "pin", "clear"])).unwrap();
        assert!(matches!(clear.command, Command::Pin(None)));
        assert!(parse_invocation(&args(&["--ble", "pin", "12345"])).is_err());
        assert!(parse_invocation(&args(&["--ble", "pin", "1234567"])).is_err());
        assert!(parse_invocation(&args(&["--ble", "pin"])).is_err());
    }

    #[test]
    fn duty_parses_show_and_limit_forms() {
        let show = parse_invocation(&args(&["--ble", "duty"])).unwrap();
        assert!(matches!(show.command, Command::Duty(None)));
        let raw = parse_invocation(&args(&["--ble", "duty", "limit", "655"])).unwrap();
        assert!(matches!(raw.command, Command::Duty(Some(655))));
        let off = parse_invocation(&args(&["--ble", "duty", "limit", "off"])).unwrap();
        assert!(matches!(off.command, Command::Duty(Some(u16::MAX))));
        let no_save =
            parse_invocation(&args(&["--ble", "duty", "limit", "1", "--no-save"])).unwrap();
        assert!(no_save.no_save);
        assert!(parse_invocation(&args(&["--ble", "duty", "limit"])).is_err());
        assert!(parse_invocation(&args(&["--ble", "duty", "limit", "70000"])).is_err());
        assert!(parse_invocation(&args(&["--ble", "duty", "now"])).is_err());
    }

    #[test]
    fn factory_reset_requires_confirmation() {
        let error = parse_invocation(&args(&["--ble", "factory-reset"])).unwrap_err();
        assert!(error.contains("--yes"), "{error}");
        let confirmed =
            parse_invocation(&args(&["--ble", "factory-reset", "--yes"])).unwrap();
        assert!(matches!(confirmed.command, Command::FactoryReset));
    }

    #[test]
    fn misplaced_options_are_rejected() {
        assert!(parse_invocation(&args(&["--ble", "info", "--force"])).is_err());
        assert!(parse_invocation(&args(&["--ble", "save", "--host-key", KEY_HEX])).is_err());
        assert!(
            parse_invocation(&args(&["--ble", "info", &format!("--expect-host-key={KEY_HEX}")]))
                .is_ok()
        );
    }
}
