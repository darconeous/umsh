//! Sans-IO host engine for browser and native companion protocol tools.
//!
//! Browser APIs, clocks, and presentation deliberately live outside this
//! crate. Callers feed transport bytes, drain transport writes, and consume a
//! stable stream of serializable events.

use std::collections::VecDeque;

use serde::Serialize;
use umsh_companion::{
    BufferedRxMeta, Frame, FrameDescription, PropPayload, StreamPayload, capability_name,
    frame::{self, Cmd, TID_MAX},
    gatt, hdlc,
    ids::{PROTOCOL_MAJOR_VERSION, prop, stream},
    items::{self, Filter},
    meta::{RX_FLAG_ACKED, RX_FLAG_BUFFERED},
    property_name, pui,
};
use umsh_core::{PacketHeader, PacketType, ParsedOptions, PayloadType, PublicKey, SourceAddrRef};

#[cfg(feature = "sim-ncp")]
mod sim;
#[cfg(feature = "sim-ncp")]
pub use sim::SimulatedNcp;

const FRAME_CAPACITY: usize = gatt::MAX_FRAME;
const RESPONSE_TIMEOUT_MS: u64 = 2_000;

/// The framing carried by the browser-owned physical link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    SerialHdlc,
    BleSar,
}

/// Structured engine output. The JSON representation is the public browser
/// contract and can be reused by other web frontends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Trace {
        timestamp_ms: u64,
        direction: Direction,
        summary: String,
        raw_hex: Option<String>,
        redacted: bool,
    },
    Property {
        key: u32,
        name: Option<&'static str>,
        value_hex: String,
        decoded: Option<DecodedValue>,
        unsolicited: bool,
    },
    PropertyError {
        key: u32,
        name: Option<&'static str>,
        status: String,
    },
    CommandResult {
        command: &'static str,
        status: String,
        success: bool,
    },
    StreamRx {
        timestamp_ms: u64,
        stream: u32,
        data_hex: String,
        metadata: Option<RxMetadata>,
        metadata_error: Option<String>,
        packet: Option<PacketSummary>,
        packet_error: Option<String>,
    },
    Attached {
        protocol_major: u8,
        protocol_minor: u8,
        ncp_version: String,
        boot_status: String,
        capabilities: Vec<Capability>,
        phy_mtu: u16,
    },
    ProtocolError {
        message: String,
    },
    Detached {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    HostToNcp,
    NcpToHost,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Capability {
    pub code: u32,
    pub name: Option<&'static str>,
}

/// Human-readable interpretation that accompanies, but never replaces, the
/// property's authoritative raw octets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DecodedValue {
    pub kind: &'static str,
    pub display: String,
    pub edit: Option<String>,
}

/// Presentation-neutral description of a known property. Web frontends can
/// render this as a table, form, or conversational settings surface without
/// carrying a second copy of the protocol schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PropertySpec {
    pub key: u32,
    pub name: &'static str,
    pub group: &'static str,
    pub description: &'static str,
    pub readable: bool,
    pub writable: bool,
    pub editor: &'static str,
    pub unit: Option<&'static str>,
    pub capability: Option<u32>,
    pub choices: &'static [PropertyChoice],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PropertyChoice {
    pub value: &'static str,
    pub label: &'static str,
}

const SF_CHOICES: &[PropertyChoice] = &[
    choice("5", "SF5"),
    choice("6", "SF6"),
    choice("7", "SF7"),
    choice("8", "SF8"),
    choice("9", "SF9"),
    choice("10", "SF10"),
    choice("11", "SF11"),
    choice("12", "SF12"),
];
const BW_CHOICES: &[PropertyChoice] = &[
    choice("7810", "7.81 kHz"),
    choice("10420", "10.42 kHz"),
    choice("15630", "15.63 kHz"),
    choice("20830", "20.83 kHz"),
    choice("31250", "31.25 kHz"),
    choice("41670", "41.67 kHz"),
    choice("62500", "62.5 kHz"),
    choice("125000", "125 kHz"),
    choice("250000", "250 kHz"),
    choice("500000", "500 kHz"),
];
const CR_CHOICES: &[PropertyChoice] = &[
    choice("5", "4/5"),
    choice("6", "4/6"),
    choice("7", "4/7"),
    choice("8", "4/8"),
];

const fn choice(value: &'static str, label: &'static str) -> PropertyChoice {
    PropertyChoice { value, label }
}

const PROPERTY_SPECS: &[PropertySpec] = &[
    spec(
        prop::LAST_STATUS,
        "Protocol",
        "Last operation or reset status",
        true,
        false,
        "none",
        None,
        None,
    ),
    spec(
        prop::PROTOCOL_VERSION,
        "Protocol",
        "Companion protocol version",
        true,
        false,
        "none",
        None,
        None,
    ),
    spec(
        prop::NCP_VERSION,
        "Protocol",
        "NCP firmware version",
        true,
        false,
        "none",
        None,
        None,
    ),
    spec(
        prop::INTERFACE_TYPE,
        "Protocol",
        "Network interface type",
        true,
        false,
        "none",
        None,
        None,
    ),
    spec(
        prop::CAPS,
        "Protocol",
        "Supported protocol capabilities",
        true,
        false,
        "none",
        None,
        None,
    ),
    spec(
        prop::PHY_ENABLED,
        "Radio",
        "Radio enabled",
        true,
        true,
        "boolean",
        None,
        None,
    ),
    spec(
        prop::PHY_FREQ,
        "Radio",
        "Center frequency",
        true,
        true,
        "integer",
        Some("kHz"),
        None,
    ),
    spec(
        prop::PHY_TX_POWER,
        "Radio",
        "Transmit power",
        true,
        true,
        "integer",
        Some("dBm"),
        None,
    ),
    spec(
        prop::PHY_RSSI,
        "Radio",
        "Current received signal strength",
        true,
        false,
        "none",
        Some("dBm"),
        None,
    ),
    spec(
        prop::PHY_LORA_BW,
        "Radio",
        "LoRa bandwidth",
        true,
        true,
        "integer",
        Some("Hz"),
        Some(umsh_companion::ids::cap::PHY_LORA),
    ),
    spec(
        prop::PHY_LORA_SF,
        "Radio",
        "LoRa spreading factor",
        true,
        true,
        "integer",
        None,
        Some(umsh_companion::ids::cap::PHY_LORA),
    ),
    spec(
        prop::PHY_LORA_CR,
        "Radio",
        "LoRa coding-rate denominator",
        true,
        true,
        "integer",
        None,
        Some(umsh_companion::ids::cap::PHY_LORA),
    ),
    spec(
        prop::PHY_MTU,
        "Radio",
        "Maximum raw radio frame size",
        true,
        false,
        "none",
        Some("octets"),
        None,
    ),
    spec(
        prop::PHY_LORA_SW,
        "Radio",
        "LoRa sync word",
        true,
        true,
        "hex_integer",
        None,
        Some(umsh_companion::ids::cap::PHY_LORA),
    ),
    spec(
        prop::PHY_DUTY_NOW,
        "Radio",
        "Current transmit duty usage",
        true,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::PHY_DUTY_LIMIT),
    ),
    spec(
        prop::PHY_DUTY_LIMIT,
        "Radio",
        "Transmit duty limit (0–65535)",
        true,
        true,
        "integer",
        None,
        Some(umsh_companion::ids::cap::PHY_DUTY_LIMIT),
    ),
    spec(
        prop::MAC_PROMISCUOUS,
        "Host session",
        "Deliver every received frame",
        true,
        true,
        "boolean",
        None,
        Some(umsh_companion::ids::cap::HOST_FILTER),
    ),
    spec(
        prop::SAVED,
        "Device",
        "Saved autonomous snapshot exists",
        true,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::SAVE),
    ),
    spec(
        prop::DEV_KEY,
        "Device",
        "Device identity public key",
        true,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::DEV_IDENTITY),
    ),
    spec(
        prop::DEV_PRIVATE_KEY,
        "Device",
        "Install or generate device identity",
        false,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::DEV_IDENTITY),
    ),
    spec(
        prop::DEV_CHANNEL_KEYS,
        "Device",
        "Device channel identifiers",
        true,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::DEV_IDENTITY),
    ),
    spec(
        prop::DEV_PEERS,
        "Device",
        "Recognized device peers",
        true,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::DEV_IDENTITY),
    ),
    spec(
        prop::DEV_NAME,
        "Device",
        "Human-readable device name",
        true,
        true,
        "text",
        None,
        Some(umsh_companion::ids::cap::DEV_NAME),
    ),
    spec(
        prop::BATTERY,
        "Device",
        "Battery status snapshot (sampled on request)",
        true,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::BATTERY),
    ),
    spec(
        prop::HOST_KEY,
        "Host",
        "Attached host identity",
        true,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::HOST_FILTER),
    ),
    spec(
        prop::HOST_CHANNEL_KEYS,
        "Host",
        "Host channel identifiers",
        true,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::HOST_KEYS),
    ),
    spec(
        prop::HOST_PEER_KEYS,
        "Host",
        "Provisioned host peers",
        true,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::HOST_KEYS),
    ),
    spec(
        prop::HOST_RX_FILTERS,
        "Host",
        "Explicit receive filters",
        true,
        false,
        "none",
        None,
        Some(umsh_companion::ids::cap::HOST_FILTER),
    ),
    spec(
        prop::HOST_AUTO_ACK,
        "Host",
        "Delegate acknowledgements to the NCP",
        true,
        true,
        "boolean",
        None,
        Some(umsh_companion::ids::cap::HOST_AUTO_ACK),
    ),
    spec(
        prop::HOST_RX_QUEUE_COUNT,
        "Host",
        "Queued inbound frames",
        true,
        false,
        "none",
        Some("frames"),
        Some(umsh_companion::ids::cap::HOST_RX_QUEUE),
    ),
    spec(
        prop::HOST_RX_QUEUE_CAPACITY,
        "Host",
        "Inbound queue capacity",
        true,
        true,
        "integer",
        Some("frames"),
        Some(umsh_companion::ids::cap::HOST_RX_QUEUE),
    ),
    spec(
        prop::HOST_RX_QUEUE_DROPPED,
        "Host",
        "Frames dropped from the inbound queue",
        true,
        false,
        "none",
        Some("frames"),
        Some(umsh_companion::ids::cap::HOST_RX_QUEUE),
    ),
    spec(
        prop::BLE_PAIRING_PIN,
        "Bluetooth",
        "Pairing PIN (write-only)",
        false,
        false,
        "none",
        None,
        None,
    ),
];

const fn spec(
    key: u32,
    group: &'static str,
    description: &'static str,
    readable: bool,
    writable: bool,
    editor: &'static str,
    unit: Option<&'static str>,
    capability: Option<u32>,
) -> PropertySpec {
    PropertySpec {
        key,
        name: match property_name(key) {
            Some(name) => name,
            None => "UNKNOWN",
        },
        group,
        description,
        readable,
        writable,
        editor,
        unit,
        capability,
        choices: match key {
            prop::PHY_LORA_BW => BW_CHOICES,
            prop::PHY_LORA_SF => SF_CHOICES,
            prop::PHY_LORA_CR => CR_CHOICES,
            _ => &[],
        },
    }
}

pub fn property_specs() -> &'static [PropertySpec] {
    PROPERTY_SPECS
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RxMetadata {
    pub rssi_dbm: Option<i16>,
    pub lqi: Option<u8>,
    pub snr_cb: Option<i16>,
    pub buffered: bool,
    pub acknowledged: bool,
    pub age_s: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PacketSummary {
    pub packet_type: String,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub channel_hex: Option<String>,
    pub frame_counter: Option<u32>,
    pub encrypted: bool,
    pub ack_requested: bool,
    pub flood_remaining: Option<u8>,
    pub flood_accumulated: Option<u8>,
    pub header_len: usize,
    pub body_len: usize,
    pub mic_len: usize,
    pub body_hex: String,
    pub payload_type: Option<String>,
    pub options: Option<PacketOptionsSummary>,
    pub options_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PacketOptionsSummary {
    pub region_code: Option<String>,
    pub source_route_len: Option<usize>,
    pub trace_route_len: Option<usize>,
    pub min_rssi_dbm: Option<i16>,
    pub min_snr_db: Option<i8>,
    pub route_retry: bool,
    pub unknown_critical: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pending {
    key: u32,
    deadline_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonCommand {
    Nop,
    QueueDrain,
    Save,
    Clear,
    Restore,
}

impl CommonCommand {
    const fn name(self) -> &'static str {
        match self {
            Self::Nop => "nop",
            Self::QueueDrain => "queue_drain",
            Self::Save => "save",
            Self::Clear => "clear",
            Self::Restore => "restore",
        }
    }
}

#[derive(Default)]
struct AttachState {
    requested: bool,
    boot_status: Option<String>,
    protocol: Option<(u8, u8)>,
    ncp_version: Option<String>,
    capabilities: Option<Vec<u32>>,
    phy_mtu: Option<u16>,
    announced: bool,
}

/// Transport-neutral debugger state machine.
pub struct DebuggerEngine {
    transport: Transport,
    hdlc: hdlc::Decoder<FRAME_CAPACITY>,
    sar: gatt::Reassembler<FRAME_CAPACITY>,
    outbound: VecDeque<Vec<u8>>,
    queued_gets: VecDeque<u32>,
    events: VecDeque<Event>,
    pending: [Option<Pending>; TID_MAX as usize + 1],
    pending_commands: [Option<CommonCommand>; TID_MAX as usize + 1],
    reset_requested: bool,
    next_tid: u8,
    now_ms: u64,
    ble_segment_payload: usize,
    attach: AttachState,
}

impl Default for DebuggerEngine {
    fn default() -> Self {
        Self::new(Transport::SerialHdlc)
    }
}

impl DebuggerEngine {
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            hdlc: hdlc::Decoder::new(),
            sar: gatt::Reassembler::new(),
            outbound: VecDeque::new(),
            queued_gets: VecDeque::new(),
            events: VecDeque::new(),
            pending: [None; TID_MAX as usize + 1],
            pending_commands: [None; TID_MAX as usize + 1],
            reset_requested: false,
            next_tid: 1,
            now_ms: 0,
            ble_segment_payload: 19,
            attach: AttachState::default(),
        }
    }

    pub fn set_transport(&mut self, transport: Transport) {
        self.transport = transport;
        self.hdlc.reset();
        self.sar.reset();
        self.outbound.clear();
        self.queued_gets.clear();
        self.pending.fill(None);
        self.pending_commands.fill(None);
        self.reset_requested = false;
        self.attach = AttachState::default();
    }

    /// Set the number of frame octets carried after each one-byte SAR header.
    pub fn set_ble_segment_payload(&mut self, size: usize) -> Result<(), &'static str> {
        if !(1..=511).contains(&size) {
            return Err("BLE segment payload must be between 1 and 511 octets");
        }
        self.ble_segment_payload = size;
        Ok(())
    }

    /// Queue the non-destructive full-protocol attach reads.
    pub fn attach(&mut self) -> Result<(), &'static str> {
        self.attach = AttachState {
            requested: true,
            ..AttachState::default()
        };
        for key in [
            prop::LAST_STATUS,
            prop::PROTOCOL_VERSION,
            prop::NCP_VERSION,
            prop::CAPS,
            prop::PHY_MTU,
        ] {
            self.prop_get(key)?;
        }
        Ok(())
    }

    pub fn prop_get(&mut self, key: u32) -> Result<(), &'static str> {
        let tid = self.reserve_tid(key)?;
        let mut buf = [0u8; FRAME_CAPACITY];
        let len = frame::prop_get(&mut buf, tid, key).map_err(|_| "property id is too large")?;
        self.queue_frame(&buf[..len]);
        Ok(())
    }

    pub fn refresh_known_properties(&mut self) {
        if let Some(capabilities) = self.attach.capabilities.clone() {
            self.queue_supported_property_refresh(&capabilities);
        }
    }

    pub fn prop_set(&mut self, key: u32, value: &[u8]) -> Result<(), &'static str> {
        let tid = self.reserve_tid(key)?;
        let mut buf = [0u8; FRAME_CAPACITY];
        let len = frame::prop_set(&mut buf, tid, key, value)
            .map_err(|_| "property value does not fit in a companion frame")?;
        self.queue_frame(&buf[..len]);
        Ok(())
    }

    /// Encode a user-facing value according to the known property schema.
    pub fn prop_set_text(&mut self, key: u32, value: &str) -> Result<(), String> {
        let encoded = encode_property_text(key, value)?;
        self.prop_set(key, &encoded).map_err(str::to_owned)
    }

    pub fn prop_insert(&mut self, key: u32, value: &[u8]) -> Result<(), &'static str> {
        let tid = self.reserve_tid(key)?;
        let mut buf = [0u8; FRAME_CAPACITY];
        let len = frame::prop_insert(&mut buf, tid, key, value)
            .map_err(|_| "property item does not fit in a companion frame")?;
        self.queue_frame(&buf[..len]);
        Ok(())
    }

    pub fn prop_remove(&mut self, key: u32, value: &[u8]) -> Result<(), &'static str> {
        let tid = self.reserve_tid(key)?;
        let mut buf = [0u8; FRAME_CAPACITY];
        let len = frame::prop_remove(&mut buf, tid, key, value)
            .map_err(|_| "property selector does not fit in a companion frame")?;
        self.queue_frame(&buf[..len]);
        Ok(())
    }

    pub fn command(&mut self, command: &str) -> Result<(), &'static str> {
        if command == "reset" {
            let mut buf = [0u8; 4];
            let len = frame::reset(&mut buf, 0).map_err(|_| "could not encode reset command")?;
            self.reset_requested = true;
            self.queue_frame(&buf[..len]);
            return Ok(());
        }
        let command = match command {
            "nop" => CommonCommand::Nop,
            "queue_drain" => CommonCommand::QueueDrain,
            "save" => CommonCommand::Save,
            "clear" => CommonCommand::Clear,
            "restore" => CommonCommand::Restore,
            _ => return Err("unknown common command"),
        };
        let tid = self.reserve_tid(prop::LAST_STATUS)?;
        let mut buf = [0u8; 4];
        let encoded = match command {
            CommonCommand::Nop => frame::nop(&mut buf, tid),
            CommonCommand::QueueDrain => frame::queue_drain(&mut buf, tid),
            CommonCommand::Save => frame::save(&mut buf, tid),
            CommonCommand::Clear => frame::clear(&mut buf, tid),
            CommonCommand::Restore => frame::restore(&mut buf, tid),
        };
        let len = match encoded {
            Ok(len) => len,
            Err(_) => {
                self.pending[tid as usize] = None;
                return Err("could not encode common command");
            }
        };
        self.pending_commands[tid as usize] = Some(command);
        self.queue_frame(&buf[..len]);
        Ok(())
    }

    /// Feed a byte-stream chunk (serial) or one ATT value (BLE).
    pub fn ingest(&mut self, bytes: &[u8]) {
        match self.transport {
            Transport::SerialHdlc => {
                for &byte in bytes {
                    let outcome = self
                        .hdlc
                        .push(byte)
                        .map(|result| result.map(<[u8]>::to_vec));
                    if let Some(outcome) = outcome {
                        match outcome {
                            Ok(frame) => self.ingest_frame(&frame),
                            Err(error) => {
                                self.protocol_error(format!("HDLC decode error: {error:?}"))
                            }
                        }
                    }
                }
            }
            Transport::BleSar => {
                let outcome = self
                    .sar
                    .push(bytes)
                    .map(|result| result.map(<[u8]>::to_vec));
                if let Some(outcome) = outcome {
                    match outcome {
                        Ok(frame) => self.ingest_frame(&frame),
                        Err(error) => {
                            self.protocol_error(format!("BLE SAR decode error: {error:?}"))
                        }
                    }
                }
            }
        }
    }

    pub fn tick(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        for tid in 1..=TID_MAX {
            if self.pending[tid as usize].is_some_and(|pending| pending.deadline_ms <= now_ms) {
                let pending = self.pending[tid as usize].take().unwrap();
                if let Some(command) = self.pending_commands[tid as usize].take() {
                    self.events.push_back(Event::CommandResult {
                        command: command.name(),
                        status: "TIMEOUT".into(),
                        success: false,
                    });
                }
                self.protocol_error(format!(
                    "timed out waiting for {} (TID {tid})",
                    property_name(pending.key).unwrap_or("property response")
                ));
            }
        }
        self.pump_gets();
    }

    pub fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    pub fn take_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn disconnected(&mut self, reason: impl Into<String>) {
        self.pending.fill(None);
        self.pending_commands.fill(None);
        self.reset_requested = false;
        self.queued_gets.clear();
        self.events.push_back(Event::Detached {
            reason: reason.into(),
        });
    }

    fn queue_supported_property_refresh(&mut self, capabilities: &[u32]) {
        for spec in PROPERTY_SPECS {
            if !spec.readable
                || matches!(
                    spec.key,
                    prop::LAST_STATUS
                        | prop::PROTOCOL_VERSION
                        | prop::NCP_VERSION
                        | prop::CAPS
                        | prop::PHY_MTU
                )
                || spec
                    .capability
                    .is_some_and(|cap| !capabilities.contains(&cap))
            {
                continue;
            }
            if !self.queued_gets.contains(&spec.key)
                && !self
                    .pending
                    .iter()
                    .flatten()
                    .any(|pending| pending.key == spec.key)
            {
                self.queued_gets.push_back(spec.key);
            }
        }
        self.pump_gets();
    }

    fn pump_gets(&mut self) {
        while let Some(key) = self.queued_gets.pop_front() {
            match self.prop_get(key) {
                Ok(()) => {}
                Err("all companion transaction identifiers are busy") => {
                    self.queued_gets.push_front(key);
                    break;
                }
                Err(error) => {
                    self.protocol_error(format!("could not refresh property {key}: {error}"))
                }
            }
        }
    }

    fn reserve_tid(&mut self, key: u32) -> Result<u8, &'static str> {
        for _ in 0..TID_MAX {
            let tid = self.next_tid;
            self.next_tid = if tid == TID_MAX { 1 } else { tid + 1 };
            if self.pending[tid as usize].is_none() {
                self.pending[tid as usize] = Some(Pending {
                    key,
                    deadline_ms: self.now_ms.saturating_add(RESPONSE_TIMEOUT_MS),
                });
                return Ok(tid);
            }
        }
        Err("all companion transaction identifiers are busy")
    }

    fn queue_frame(&mut self, bytes: &[u8]) {
        self.trace(Direction::HostToNcp, bytes);
        match self.transport {
            Transport::SerialHdlc => {
                let mut encoded = vec![0; hdlc::max_encoded_len(bytes.len())];
                let len =
                    hdlc::encode_frame(bytes, &mut encoded).expect("sized for HDLC worst case");
                encoded.truncate(len);
                self.outbound.push_back(encoded);
            }
            Transport::BleSar => {
                for segment in gatt::segments(bytes, self.ble_segment_payload) {
                    let mut encoded = vec![0; segment.payload().len() + 1];
                    let len = segment
                        .write_to(&mut encoded)
                        .expect("exact SAR segment size");
                    encoded.truncate(len);
                    self.outbound.push_back(encoded);
                }
            }
        }
    }

    fn ingest_frame(&mut self, bytes: &[u8]) {
        self.trace(Direction::NcpToHost, bytes);
        let Ok(frame) = Frame::parse(bytes) else {
            self.protocol_error("malformed companion frame".into());
            return;
        };
        let Some(command) = frame.command() else {
            self.protocol_error(format!("unknown companion command {}", frame.cmd));
            return;
        };
        if command == Cmd::StrRecv {
            self.ingest_stream(frame.payload);
            return;
        }
        if !matches!(command, Cmd::PropIs | Cmd::PropInserted | Cmd::PropRemoved) {
            return;
        }
        let Ok(payload) = PropPayload::parse(frame.payload) else {
            self.protocol_error("malformed property payload".into());
            return;
        };
        let tid = frame.header.tid();
        let unsolicited = tid == 0;
        let pending = if unsolicited {
            None
        } else {
            match self.pending[tid as usize].take() {
                Some(pending) if pending.key == payload.key || payload.key == prop::LAST_STATUS => {
                    Some(pending)
                }
                Some(pending) => {
                    self.pending[tid as usize] = Some(pending);
                    self.protocol_error(format!(
                        "TID {tid} returned unexpected property {}",
                        payload.key
                    ));
                    None
                }
                None => {
                    self.protocol_error(format!("response for unused TID {tid}"));
                    None
                }
            }
        };
        let mut refresh_after_command = false;
        if payload.key == prop::LAST_STATUS && !unsolicited {
            if let Some(command) = self.pending_commands[tid as usize].take() {
                let (status, success) = match pui::decode(payload.value) {
                    Ok((code, _)) => (format!("{:?}", umsh_companion::Status(code)), code == 0),
                    Err(_) => ("MALFORMED STATUS".into(), false),
                };
                self.events.push_back(Event::CommandResult {
                    command: command.name(),
                    status,
                    success,
                });
                refresh_after_command = success;
            }
        }
        if payload.key == prop::LAST_STATUS
            && pending.is_some_and(|pending| pending.key != prop::LAST_STATUS)
        {
            let requested = pending.expect("checked above").key;
            let status = pui::decode(payload.value)
                .map(|(code, _)| format!("{:?}", umsh_companion::Status(code)))
                .unwrap_or_else(|_| "MALFORMED STATUS".into());
            self.events.push_back(Event::PropertyError {
                key: requested,
                name: property_name(requested),
                status,
            });
            self.pump_gets();
            return;
        }
        self.events.push_back(Event::Property {
            key: payload.key,
            name: property_name(payload.key),
            value_hex: hex(payload.value),
            decoded: decode_property(payload.key, payload.value),
            unsolicited,
        });
        if payload.key == prop::LAST_STATUS && unsolicited && self.attach.announced {
            if let Ok((code, _)) = pui::decode(payload.value) {
                let status = umsh_companion::Status(code);
                if status.is_reset() {
                    let restore_tid = (1..=TID_MAX).find(|tid| {
                        self.pending_commands[*tid as usize] == Some(CommonCommand::Restore)
                    });
                    if self.reset_requested {
                        self.events.push_back(Event::CommandResult {
                            command: "reset",
                            status: format!("{status:?}"),
                            success: true,
                        });
                    } else if status == umsh_companion::Status::RESET_RESTORED {
                        if let Some(tid) = restore_tid {
                            self.events.push_back(Event::CommandResult {
                                command: "restore",
                                status: format!("{status:?}"),
                                success: true,
                            });
                            self.pending[tid as usize] = None;
                        }
                    }
                    self.reset_requested = false;
                    self.pending.fill(None);
                    self.pending_commands.fill(None);
                    self.queued_gets.clear();
                    refresh_after_command = true;
                }
            }
        }
        if self.attach.requested {
            self.capture_attach_property(payload.key, payload.value);
            self.maybe_announce_attached();
        }
        if refresh_after_command {
            self.refresh_known_properties();
        }
        self.pump_gets();
    }

    fn ingest_stream(&mut self, payload: &[u8]) {
        let Ok(payload) = StreamPayload::parse(payload) else {
            self.protocol_error("malformed stream payload".into());
            return;
        };
        let (metadata, metadata_error) = match BufferedRxMeta::decode(payload.metadata) {
            Ok(meta) => (
                Some(RxMetadata {
                    rssi_dbm: meta.rx.rssi_dbm,
                    lqi: meta.rx.lqi.map(|value| value.get()),
                    snr_cb: meta.rx.snr_cb,
                    buffered: meta.flags & RX_FLAG_BUFFERED != 0,
                    acknowledged: meta.flags & RX_FLAG_ACKED != 0,
                    age_s: meta.age_s,
                }),
                None,
            ),
            Err(error) => (None, Some(format!("{error:?}"))),
        };
        let (packet, packet_error) = if payload.stream == stream::PHY_RAW {
            match PacketHeader::parse(payload.data) {
                Ok(header) => (Some(summarize_packet(payload.data, &header)), None),
                Err(error) => (None, Some(format!("{error:?}"))),
            }
        } else {
            (None, None)
        };
        self.events.push_back(Event::StreamRx {
            timestamp_ms: self.now_ms,
            stream: payload.stream,
            data_hex: hex(payload.data),
            metadata,
            metadata_error,
            packet,
            packet_error,
        });
    }

    fn capture_attach_property(&mut self, key: u32, value: &[u8]) {
        match key {
            prop::LAST_STATUS => {
                self.attach.boot_status = Some(match pui::decode(value) {
                    Ok((status, consumed)) if consumed == value.len() => {
                        format!("{:?}", umsh_companion::Status(status))
                    }
                    _ => "MALFORMED".into(),
                });
            }
            prop::PROTOCOL_VERSION if value.len() == 2 => {
                self.attach.protocol = Some((value[0], value[1]));
                if value[0] != PROTOCOL_MAJOR_VERSION {
                    self.protocol_error(format!(
                        "unsupported protocol major version {}; expected {PROTOCOL_MAJOR_VERSION}",
                        value[0]
                    ));
                }
            }
            prop::NCP_VERSION => {
                let value = value.strip_suffix(&[0]).unwrap_or(value);
                self.attach.ncp_version = Some(String::from_utf8_lossy(value).into_owned());
            }
            prop::CAPS => {
                let mut rest = value;
                let mut caps = Vec::new();
                while !rest.is_empty() {
                    match pui::decode(rest) {
                        Ok((cap, used)) => {
                            caps.push(cap);
                            rest = &rest[used..];
                        }
                        Err(_) => {
                            self.protocol_error("malformed PROP_CAPS".into());
                            return;
                        }
                    }
                }
                self.attach.capabilities = Some(caps);
            }
            prop::PHY_MTU if value.len() == 2 => {
                self.attach.phy_mtu = Some(u16::from_le_bytes([value[0], value[1]]));
            }
            _ => {}
        }
    }

    fn maybe_announce_attached(&mut self) {
        if self.attach.announced {
            return;
        }
        let (
            Some(boot_status),
            Some((protocol_major, protocol_minor)),
            Some(ncp_version),
            Some(capabilities),
            Some(phy_mtu),
        ) = (
            self.attach.boot_status.clone(),
            self.attach.protocol,
            self.attach.ncp_version.clone(),
            self.attach.capabilities.clone(),
            self.attach.phy_mtu,
        )
        else {
            return;
        };
        self.attach.announced = true;
        self.events.push_back(Event::Attached {
            protocol_major,
            protocol_minor,
            ncp_version,
            boot_status,
            capabilities: capabilities
                .iter()
                .copied()
                .map(|code| Capability {
                    code,
                    name: capability_name(code),
                })
                .collect(),
            phy_mtu,
        });
        self.queue_supported_property_refresh(&capabilities);
    }

    fn trace(&mut self, direction: Direction, bytes: &[u8]) {
        let redacted = direction == Direction::HostToNcp && secret_bearing_write(bytes);
        self.events.push_back(Event::Trace {
            timestamp_ms: self.now_ms,
            direction,
            summary: FrameDescription(bytes).to_string(),
            raw_hex: (!redacted).then(|| hex(bytes)),
            redacted,
        });
    }

    fn protocol_error(&mut self, message: String) {
        self.events.push_back(Event::ProtocolError { message });
    }
}

fn decode_property(key: u32, value: &[u8]) -> Option<DecodedValue> {
    let decoded = match key {
        prop::LAST_STATUS => {
            let (code, used) = pui::decode(value).ok()?;
            let status = format!("{:?}", umsh_companion::Status(code));
            let detail = value.get(used..)?;
            let detail = detail.strip_suffix(&[0]).unwrap_or(detail);
            let detail = String::from_utf8_lossy(detail);
            let display = if detail.is_empty() {
                status
            } else {
                format!("{status}: {detail}")
            };
            ("status", display)
        }
        prop::PROTOCOL_VERSION if value.len() == 2 => {
            ("version", format!("{}.{}", value[0], value[1]))
        }
        prop::NCP_VERSION => {
            let value = value.strip_suffix(&[0]).unwrap_or(value);
            ("string", String::from_utf8(value.to_vec()).ok()?)
        }
        prop::DEV_NAME => ("string", String::from_utf8(value.to_vec()).ok()?),
        prop::INTERFACE_TYPE => {
            let (interface, used) = pui::decode(value).ok()?;
            if used != value.len() {
                return None;
            }
            let display = if interface == umsh_companion::ids::INTERFACE_TYPE {
                format!("UMSH ({interface})")
            } else {
                interface.to_string()
            };
            ("enum", display)
        }
        prop::CAPS => {
            let mut rest = value;
            let mut items = Vec::new();
            while !rest.is_empty() {
                let (code, used) = pui::decode(rest).ok()?;
                let item = capability_name(code)
                    .map(|name| format!("{name} ({code})"))
                    .unwrap_or_else(|| code.to_string());
                items.push(item);
                rest = &rest[used..];
            }
            (
                "capability_list",
                if items.is_empty() {
                    "none".into()
                } else {
                    items.join(", ")
                },
            )
        }
        prop::PHY_ENABLED | prop::MAC_PROMISCUOUS | prop::SAVED | prop::HOST_AUTO_ACK
            if value.len() == 1 && value[0] <= 1 =>
        {
            ("boolean", (value[0] != 0).to_string())
        }
        prop::PHY_TX_POWER | prop::PHY_RSSI if value.len() == 1 => {
            ("dbm", format!("{} dBm", value[0] as i8))
        }
        prop::PHY_LORA_SF | prop::PHY_LORA_CR if value.len() == 1 => {
            ("uint8", value[0].to_string())
        }
        prop::PHY_MTU | prop::HOST_RX_QUEUE_COUNT | prop::HOST_RX_QUEUE_CAPACITY
            if value.len() == 2 =>
        {
            let number = u16::from_le_bytes(value.try_into().ok()?);
            let suffix = if key == prop::PHY_MTU {
                " octets"
            } else {
                " frames"
            };
            ("uint16", format!("{number}{suffix}"))
        }
        prop::PHY_LORA_SW if value.len() == 2 => (
            "uint16",
            format!("0x{:04x}", u16::from_le_bytes(value.try_into().ok()?)),
        ),
        prop::PHY_DUTY_NOW | prop::PHY_DUTY_LIMIT if value.len() == 2 => {
            let number = u16::from_le_bytes(value.try_into().ok()?);
            (
                "duty_cycle",
                format!("{:.3}% ({number})", f64::from(number) * 100.0 / 65535.0),
            )
        }
        prop::PHY_FREQ | prop::PHY_LORA_BW | prop::HOST_RX_QUEUE_DROPPED if value.len() == 4 => {
            let number = u32::from_le_bytes(value.try_into().ok()?);
            let suffix = match key {
                prop::PHY_FREQ => " kHz",
                prop::PHY_LORA_BW => " Hz",
                _ => " frames",
            };
            ("uint32", format!("{number}{suffix}"))
        }
        prop::BATTERY => {
            let status = umsh_companion::battery::BatteryStatus::decode(value).ok()?;
            let display = if status.is_empty() {
                "reporting unsupported".to_string()
            } else {
                let voltage = status
                    .voltage_mv
                    .map_or("voltage unsupported".to_string(), |mv| format!("{mv} mV"));
                let level = status
                    .level_percent
                    .map_or("level unsupported".to_string(), |percent| {
                        format!("{percent}%")
                    });
                let state = match status.charge_state {
                    Some(umsh_companion::battery::BatteryChargeState::Discharging) => {
                        "discharging"
                    }
                    Some(umsh_companion::battery::BatteryChargeState::Charging) => "charging",
                    Some(umsh_companion::battery::BatteryChargeState::Charged) => "charged",
                    None => "charge state unsupported",
                };
                format!("{voltage}, {level}, {state}")
            };
            ("battery", display)
        }
        prop::DEV_KEY | prop::HOST_KEY if value.is_empty() => {
            ("public_key", "not configured".into())
        }
        prop::DEV_KEY | prop::HOST_KEY if value.len() == 32 => {
            let key = PublicKey(value.try_into().ok()?);
            ("public_key", key.to_string())
        }
        prop::DEV_CHANNEL_KEYS | prop::HOST_CHANNEL_KEYS => {
            let items = items::fixed_items::<2>(value).ok()?;
            let values = items.map(|item| hex(item)).collect::<Vec<_>>();
            ("channel_list", display_list(values))
        }
        prop::DEV_PEERS | prop::HOST_PEER_KEYS => {
            let items = items::fixed_items::<32>(value).ok()?;
            let values = items
                .map(|item| PublicKey(*item).to_string())
                .collect::<Vec<_>>();
            ("public_key_list", display_list(values))
        }
        prop::HOST_RX_FILTERS => {
            let prefixed = items::prefixed_items(value)
                .map(|item| item.and_then(Filter::decode))
                .collect::<Result<Vec<_>, _>>();
            let filters = match prefixed {
                Ok(filters) => filters,
                Err(_) => vec![Filter::decode(value).ok()?],
            };
            let values = filters.into_iter().map(format_filter).collect();
            ("filter_list", display_list(values))
        }
        _ => return None,
    };
    Some(DecodedValue {
        kind: decoded.0,
        display: decoded.1,
        edit: editable_property_text(key, value),
    })
}

fn editable_property_text(key: u32, value: &[u8]) -> Option<String> {
    match key {
        prop::PHY_ENABLED | prop::MAC_PROMISCUOUS | prop::HOST_AUTO_ACK
            if value.len() == 1 && value[0] <= 1 =>
        {
            Some((value[0] != 0).to_string())
        }
        prop::PHY_TX_POWER if value.len() == 1 => Some((value[0] as i8).to_string()),
        prop::PHY_LORA_SF | prop::PHY_LORA_CR if value.len() == 1 => Some(value[0].to_string()),
        prop::PHY_MTU | prop::HOST_RX_QUEUE_CAPACITY | prop::PHY_DUTY_LIMIT if value.len() == 2 => {
            Some(u16::from_le_bytes(value.try_into().ok()?).to_string())
        }
        prop::PHY_LORA_SW if value.len() == 2 => Some(format!(
            "0x{:04x}",
            u16::from_le_bytes(value.try_into().ok()?)
        )),
        prop::PHY_FREQ | prop::PHY_LORA_BW if value.len() == 4 => {
            Some(u32::from_le_bytes(value.try_into().ok()?).to_string())
        }
        prop::DEV_NAME => String::from_utf8(value.to_vec()).ok(),
        _ => None,
    }
}

fn encode_property_text(key: u32, value: &str) -> Result<Vec<u8>, String> {
    let text = value;
    let value = value.trim();
    match key {
        prop::PHY_ENABLED | prop::MAC_PROMISCUOUS | prop::HOST_AUTO_ACK => {
            let parsed = match value.to_ascii_lowercase().as_str() {
                "true" | "1" | "on" | "yes" => 1,
                "false" | "0" | "off" | "no" => 0,
                _ => return Err("enter true or false".into()),
            };
            Ok(vec![parsed])
        }
        prop::PHY_TX_POWER => Ok(vec![
            parse_integer::<i8>(value, "an 8-bit signed integer")? as u8
        ]),
        prop::PHY_LORA_SF | prop::PHY_LORA_CR => Ok(vec![parse_integer::<u8>(
            value,
            "an 8-bit unsigned integer",
        )?]),
        prop::PHY_LORA_SW => Ok(parse_u16(value)?.to_le_bytes().to_vec()),
        prop::PHY_DUTY_LIMIT | prop::HOST_RX_QUEUE_CAPACITY => {
            Ok(parse_integer::<u16>(value, "a number from 0 to 65535")?
                .to_le_bytes()
                .to_vec())
        }
        prop::PHY_FREQ | prop::PHY_LORA_BW => {
            Ok(parse_integer::<u32>(value, "a 32-bit unsigned integer")?
                .to_le_bytes()
                .to_vec())
        }
        prop::DEV_NAME => {
            if text.is_empty() || text.len() > 64 || text.contains('\0') {
                return Err("device name must contain 1–64 UTF-8 octets".into());
            }
            Ok(text.as_bytes().to_vec())
        }
        _ => Err("this property does not have a typed editor".into()),
    }
}

fn parse_integer<T>(value: &str, expected: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    value
        .replace('_', "")
        .parse()
        .map_err(|_| format!("enter {expected}"))
}

fn parse_u16(value: &str) -> Result<u16, String> {
    let compact = value.replace('_', "");
    if let Some(hex) = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16).map_err(|_| "enter a 16-bit integer such as 0x1424".into())
    } else {
        parse_integer(&compact, "a 16-bit integer such as 0x1424")
    }
}

fn display_list(values: Vec<String>) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values.join(", ")
    }
}

fn format_filter(filter: Filter) -> String {
    match filter {
        Filter::DestHint(bytes) => format!("destination {}", umsh_core::NodeHint(bytes)),
        Filter::ChannelId(bytes) => format!("channel {}", hex(&bytes)),
        Filter::PktType(packet_type) => format!("packet type {packet_type}"),
    }
}

fn summarize_packet(bytes: &[u8], header: &PacketHeader) -> PacketSummary {
    let source = match header.source {
        SourceAddrRef::Hint(hint) => Some(hint.to_string()),
        SourceAddrRef::FullKeyAt { offset } => bytes
            .get(offset..offset + 32)
            .and_then(|bytes| <&[u8; 32]>::try_from(bytes).ok())
            .map(|bytes| PublicKey(*bytes).to_string()),
        SourceAddrRef::Encrypted { .. } => Some("encrypted".into()),
        SourceAddrRef::None => None,
    };
    let encrypted = header
        .sec_info
        .is_some_and(|security| security.scf.encrypted());
    let payload_type = (!encrypted && header.packet_type() != PacketType::MacAck)
        .then(|| {
            bytes
                .get(header.body_range.start)
                .and_then(|byte| PayloadType::from_byte(*byte))
                .map(|payload_type| format!("{payload_type:?}"))
        })
        .flatten();
    let (options, options_error) = match ParsedOptions::extract(bytes, header.options_range.clone())
    {
        Ok(options) => (
            Some(PacketOptionsSummary {
                region_code: options
                    .region_code
                    .map(|region| String::from_utf8_lossy(&region).into_owned()),
                source_route_len: options.source_route.map(|route| route.len()),
                trace_route_len: options.trace_route.map(|route| route.len()),
                min_rssi_dbm: options.min_rssi,
                min_snr_db: options.min_snr,
                route_retry: options.route_retry,
                unknown_critical: options.has_unknown_critical,
            }),
            None,
        ),
        Err(error) => (None, Some(format!("{error:?}"))),
    };
    PacketSummary {
        packet_type: format!("{:?}", header.packet_type()),
        source,
        destination: header.dst.or(header.ack_dst).map(|hint| hint.to_string()),
        channel_hex: header.channel.map(|channel| hex(&channel.0)),
        frame_counter: header.sec_info.map(|info| info.frame_counter),
        encrypted,
        ack_requested: header.ack_requested(),
        flood_remaining: header.flood_hops.map(|hops| hops.remaining()),
        flood_accumulated: header.flood_hops.map(|hops| hops.accumulated()),
        header_len: header.body_range.start,
        body_len: header.body_range.len(),
        mic_len: header.mic_range.len(),
        body_hex: hex(&bytes[header.body_range.clone()]),
        payload_type,
        options,
        options_error,
    }
}

fn secret_bearing_write(bytes: &[u8]) -> bool {
    let Ok(frame) = Frame::parse(bytes) else {
        return false;
    };
    if !matches!(frame.command(), Some(Cmd::PropSet | Cmd::PropInsert)) {
        return false;
    }
    let Ok(payload) = PropPayload::parse(frame.payload) else {
        return false;
    };
    matches!(
        payload.key,
        prop::DEV_PRIVATE_KEY
            | prop::DEV_CHANNEL_KEYS
            | prop::HOST_CHANNEL_KEYS
            | prop::HOST_PEER_KEYS
            | prop::BLE_PAIRING_PIN
    )
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    /// Minimal wasm-bindgen adapter. JSON events keep generated glue small and
    /// make the interface consumable by any browser UI architecture.
    #[wasm_bindgen(js_name = DebuggerEngine)]
    pub struct WebDebuggerEngine(DebuggerEngine);

    #[cfg(feature = "sim-ncp")]
    #[wasm_bindgen(js_name = SimulatedNcp)]
    pub struct WebSimulatedNcp(SimulatedNcp);

    #[wasm_bindgen(js_name = propertySpecs)]
    pub fn web_property_specs() -> String {
        serde_json::to_string(property_specs()).expect("property schema serialization")
    }

    #[wasm_bindgen(js_class = DebuggerEngine)]
    impl WebDebuggerEngine {
        #[wasm_bindgen(constructor)]
        pub fn new(transport: &str) -> Result<WebDebuggerEngine, JsError> {
            Ok(Self(DebuggerEngine::new(parse_transport(transport)?)))
        }

        pub fn set_transport(&mut self, transport: &str) -> Result<(), JsError> {
            self.0.set_transport(parse_transport(transport)?);
            Ok(())
        }

        pub fn set_ble_segment_payload(&mut self, size: usize) -> Result<(), JsError> {
            self.0.set_ble_segment_payload(size).map_err(JsError::new)
        }

        pub fn attach(&mut self) -> Result<(), JsError> {
            self.0.attach().map_err(JsError::new)
        }

        pub fn prop_get(&mut self, key: u32) -> Result<(), JsError> {
            self.0.prop_get(key).map_err(JsError::new)
        }

        pub fn refresh_known_properties(&mut self) {
            self.0.refresh_known_properties();
        }

        pub fn prop_set(&mut self, key: u32, value: &[u8]) -> Result<(), JsError> {
            self.0.prop_set(key, value).map_err(JsError::new)
        }

        pub fn prop_set_text(&mut self, key: u32, value: &str) -> Result<(), JsError> {
            self.0
                .prop_set_text(key, value)
                .map_err(|error| JsError::new(&error))
        }

        pub fn prop_insert(&mut self, key: u32, value: &[u8]) -> Result<(), JsError> {
            self.0.prop_insert(key, value).map_err(JsError::new)
        }

        pub fn prop_remove(&mut self, key: u32, value: &[u8]) -> Result<(), JsError> {
            self.0.prop_remove(key, value).map_err(JsError::new)
        }

        pub fn command(&mut self, command: &str) -> Result<(), JsError> {
            self.0.command(command).map_err(JsError::new)
        }

        pub fn ingest(&mut self, bytes: &[u8]) {
            self.0.ingest(bytes);
        }

        pub fn tick(&mut self, now_ms: f64) {
            self.0.tick(browser_millis(now_ms));
        }

        pub fn take_outbound(&mut self) -> Option<Vec<u8>> {
            self.0.take_outbound()
        }

        pub fn take_event(&mut self) -> Option<String> {
            self.0
                .take_event()
                .map(|event| serde_json::to_string(&event).expect("event serialization"))
        }

        pub fn disconnected(&mut self, reason: String) {
            self.0.disconnected(reason);
        }
    }

    #[cfg(feature = "sim-ncp")]
    #[wasm_bindgen(js_class = SimulatedNcp)]
    impl WebSimulatedNcp {
        #[wasm_bindgen(constructor)]
        pub fn new() -> WebSimulatedNcp {
            Self(SimulatedNcp::new())
        }

        pub fn attach(&mut self) {
            self.0.attach();
        }

        pub fn detach(&mut self) {
            self.0.detach();
        }

        pub fn ingest(&mut self, bytes: &[u8], now_ms: f64) -> Result<(), JsError> {
            self.0
                .ingest(bytes, browser_millis(now_ms))
                .map_err(|error| JsError::new(&error))
        }

        pub fn take_outbound(&mut self) -> Option<Vec<u8>> {
            self.0.take_outbound()
        }

        pub fn inject_radio_rx(&mut self, bytes: &[u8], now_ms: f64) {
            self.0.inject_radio_rx(bytes, browser_millis(now_ms));
        }

        pub fn inject_demo_rx(&mut self, now_ms: f64) {
            self.0.inject_demo_rx(browser_millis(now_ms));
        }
    }

    fn browser_millis(value: f64) -> u64 {
        if value.is_finite() && value > 0.0 {
            value.min(u64::MAX as f64) as u64
        } else {
            0
        }
    }

    fn parse_transport(value: &str) -> Result<Transport, JsError> {
        match value {
            "serial_hdlc" => Ok(Transport::SerialHdlc),
            "ble_sar" => Ok(Transport::BleSar),
            _ => Err(JsError::new("transport must be serial_hdlc or ble_sar")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain_serial_frame(engine: &mut DebuggerEngine) -> Vec<u8> {
        let wire = engine.take_outbound().unwrap();
        let mut decoder = hdlc::Decoder::<FRAME_CAPACITY>::new();
        wire.into_iter()
            .find_map(|byte| decoder.push(byte).map(|result| result.unwrap().to_vec()))
            .unwrap()
    }

    fn send_property(engine: &mut DebuggerEngine, request: &[u8], value: &[u8]) {
        let parsed = Frame::parse(request).unwrap();
        let payload = PropPayload::parse(parsed.payload).unwrap();
        let mut response = [0; FRAME_CAPACITY];
        let len = frame::prop_is(&mut response, parsed.header.tid(), payload.key, value).unwrap();
        let mut wire = vec![0; hdlc::max_encoded_len(len)];
        let wire_len = hdlc::encode_frame(&response[..len], &mut wire).unwrap();
        engine.ingest(&wire[..wire_len]);
    }

    fn ingest_serial_frame(engine: &mut DebuggerEngine, companion_frame: &[u8]) {
        let mut wire = vec![0; hdlc::max_encoded_len(companion_frame.len())];
        let wire_len = hdlc::encode_frame(companion_frame, &mut wire).unwrap();
        engine.ingest(&wire[..wire_len]);
    }

    #[test]
    fn attach_correlates_properties_and_announces_dashboard() {
        let mut engine = DebuggerEngine::default();
        engine.attach().unwrap();
        let values: [&[u8]; 5] = [
            &[1],
            &[PROTOCOL_MAJOR_VERSION, 0],
            b"test-ncp\0",
            &[8, 0x83, 0x04],
            &255u16.to_le_bytes(),
        ];
        for value in values {
            let request = drain_serial_frame(&mut engine);
            send_property(&mut engine, &request, value);
        }
        let events: Vec<_> = std::iter::from_fn(|| engine.take_event()).collect();
        assert!(events.iter().any(|event| matches!(event, Event::Attached {
            protocol_major: PROTOCOL_MAJOR_VERSION,
            ncp_version,
            phy_mtu: 255,
            capabilities,
            ..
        } if ncp_version == "test-ncp"
            && capabilities.iter().map(|cap| cap.code).collect::<Vec<_>>() == [8, 515])));
    }

    #[test]
    fn ble_segments_round_trip_and_secret_writes_are_redacted() {
        let mut engine = DebuggerEngine::new(Transport::BleSar);
        engine.set_ble_segment_payload(3).unwrap();
        engine.prop_set(prop::BLE_PAIRING_PIN, b"123456").unwrap();
        assert!(matches!(
            engine.take_event(),
            Some(Event::Trace {
                redacted: true,
                raw_hex: None,
                ..
            })
        ));

        let segments: Vec<_> = std::iter::from_fn(|| engine.take_outbound()).collect();
        assert!(segments.len() > 1);
        let mut reassembler = gatt::Reassembler::<FRAME_CAPACITY>::new();
        let frame = segments
            .into_iter()
            .find_map(|segment| {
                reassembler
                    .push(&segment)
                    .map(|result| result.unwrap().to_vec())
            })
            .unwrap();
        assert_eq!(
            PropPayload::parse(Frame::parse(&frame).unwrap().payload)
                .unwrap()
                .value,
            b"123456"
        );
    }

    #[test]
    fn timeout_releases_transaction_identifier() {
        let mut engine = DebuggerEngine::default();
        engine.prop_get(prop::PHY_MTU).unwrap();
        engine.tick(RESPONSE_TIMEOUT_MS);
        assert!(matches!(engine.take_event(), Some(Event::Trace { .. })));
        assert!(
            matches!(engine.take_event(), Some(Event::ProtocolError { message }) if message.contains("timed out"))
        );
    }

    #[test]
    fn property_values_keep_raw_bytes_and_add_typed_display() {
        assert_eq!(
            decode_property(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
            Some(DecodedValue {
                kind: "uint32",
                display: "915000 kHz".into(),
                edit: Some("915000".into()),
            })
        );
        assert_eq!(
            decode_property(prop::PHY_ENABLED, &[1]).unwrap().display,
            "true"
        );
        assert!(decode_property(prop::PHY_ENABLED, &[2]).is_none());
        assert!(decode_property(2_000, &[1, 2, 3]).is_none());
        assert_eq!(
            decode_property(prop::HOST_CHANNEL_KEYS, &[0x12, 0x34, 0x56, 0x78])
                .unwrap()
                .display,
            "1234, 5678"
        );
        assert_eq!(
            decode_property(prop::HOST_RX_FILTERS, &[2, 2, 0])
                .unwrap()
                .display,
            "packet type 0"
        );
    }

    #[test]
    fn battery_snapshots_decode_to_distinct_presentations() {
        // The empty value: battery powered, reporting unsupported.
        assert_eq!(
            decode_property(prop::BATTERY, &[]).unwrap().display,
            "reporting unsupported"
        );
        // The T-1000E shape: voltage + charge state, no level.
        assert_eq!(
            decode_property(prop::BATTERY, &[0b101, 0x74, 0x0E, 0])
                .unwrap()
                .display,
            "3700 mV, level unsupported, discharging"
        );
        // The full simulator shape.
        assert_eq!(
            decode_property(prop::BATTERY, &[0b111, 0x0F, 0x10, 87, 1])
                .unwrap()
                .display,
            "4111 mV, 87%, charging"
        );
        // Malformed: reserved bit, bad length, unknown charge code.
        assert!(decode_property(prop::BATTERY, &[0b1000, 1]).is_none());
        assert!(decode_property(prop::BATTERY, &[0b001, 0x74]).is_none());
        assert!(decode_property(prop::BATTERY, &[0b100, 3]).is_none());
        // Battery is read-only: no typed editor.
        assert!(
            decode_property(prop::BATTERY, &[0b100, 2])
                .unwrap()
                .edit
                .is_none()
        );
    }

    #[test]
    fn known_property_schema_and_typed_writes_share_protocol_types() {
        let mut keys = property_specs()
            .iter()
            .map(|spec| spec.key)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), property_specs().len());
        assert!(
            property_specs()
                .iter()
                .all(|spec| property_name(spec.key) == Some(spec.name))
        );

        let mut engine = DebuggerEngine::default();
        engine.prop_set_text(prop::PHY_FREQ, "915_000").unwrap();
        let request = drain_serial_frame(&mut engine);
        let payload = PropPayload::parse(Frame::parse(&request).unwrap().payload).unwrap();
        assert_eq!(payload.key, prop::PHY_FREQ);
        assert_eq!(payload.value, &915_000u32.to_le_bytes());
        assert_eq!(encode_property_text(prop::PHY_ENABLED, "on").unwrap(), [1]);
        assert!(encode_property_text(prop::PHY_ENABLED, "maybe").is_err());
    }

    #[test]
    fn status_response_is_attributed_to_the_requested_property() {
        let mut engine = DebuggerEngine::default();
        engine.prop_get(prop::PHY_RSSI).unwrap();
        let request = drain_serial_frame(&mut engine);
        let request = Frame::parse(&request).unwrap();
        let mut response = [0; 16];
        let len = frame::last_status(
            &mut response,
            request.header.tid(),
            umsh_companion::Status::INVALID_STATE,
        )
        .unwrap();
        ingest_serial_frame(&mut engine, &response[..len]);
        assert!(matches!(engine.take_event(), Some(Event::Trace { .. })));
        assert!(matches!(engine.take_event(), Some(Event::Trace { .. })));
        assert!(matches!(engine.take_event(), Some(Event::PropertyError {
            key: prop::PHY_RSSI,
            status,
            ..
        }) if status == "Status::INVALID_STATE"));
    }

    #[test]
    fn late_property_response_still_updates_observed_state() {
        let mut engine = DebuggerEngine::default();
        engine.prop_get(prop::PHY_FREQ).unwrap();
        let request = drain_serial_frame(&mut engine);
        while engine.take_event().is_some() {}
        engine.tick(RESPONSE_TIMEOUT_MS);
        while engine.take_event().is_some() {}

        send_property(&mut engine, &request, &915_000u32.to_le_bytes());
        let events = std::iter::from_fn(|| engine.take_event()).collect::<Vec<_>>();
        assert!(events.iter().any(
            |event| matches!(event, Event::ProtocolError { message } if message.contains("unused TID"))
        ));
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Property {
                key: prop::PHY_FREQ,
                decoded: Some(DecodedValue { edit: Some(value), .. }),
                ..
            } if value == "915000"
        )));
    }

    #[test]
    fn mismatched_property_response_is_visible_without_consuming_request() {
        let mut engine = DebuggerEngine::default();
        engine.prop_get(prop::PHY_MTU).unwrap();
        let request = drain_serial_frame(&mut engine);
        let request = Frame::parse(&request).unwrap();
        while engine.take_event().is_some() {}

        let mut response = [0; 16];
        let len =
            frame::prop_is(&mut response, request.header.tid(), prop::PHY_ENABLED, &[1]).unwrap();
        ingest_serial_frame(&mut engine, &response[..len]);
        let events = std::iter::from_fn(|| engine.take_event()).collect::<Vec<_>>();
        assert!(events.iter().any(
            |event| matches!(event, Event::ProtocolError { message } if message.contains("unexpected property"))
        ));
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Property {
                key: prop::PHY_ENABLED,
                ..
            }
        )));
        assert!(engine.pending[request.header.tid() as usize].is_some());
    }

    #[test]
    fn common_command_reports_correlated_status() {
        let mut engine = DebuggerEngine::default();
        engine.command("save").unwrap();
        let request = drain_serial_frame(&mut engine);
        let request = Frame::parse(&request).unwrap();
        assert_eq!(request.command(), Some(Cmd::Save));

        let mut response = [0; 16];
        let len = frame::last_status(
            &mut response,
            request.header.tid(),
            umsh_companion::Status::OK,
        )
        .unwrap();
        ingest_serial_frame(&mut engine, &response[..len]);
        let events = std::iter::from_fn(|| engine.take_event()).collect::<Vec<_>>();
        assert!(events.iter().any(|event| matches!(
            event,
            Event::CommandResult {
                command: "save",
                success: true,
                ..
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Property {
                key: prop::LAST_STATUS,
                ..
            }
        )));
    }

    #[test]
    fn lora_property_choices_match_ncp_constraints() {
        let bandwidth = property_specs()
            .iter()
            .find(|spec| spec.key == prop::PHY_LORA_BW)
            .unwrap();
        assert_eq!(bandwidth.choices.first().unwrap().value, "7810");
        assert_eq!(bandwidth.choices.last().unwrap().value, "500000");
        let spreading = property_specs()
            .iter()
            .find(|spec| spec.key == prop::PHY_LORA_SF)
            .unwrap();
        assert_eq!(spreading.choices.len(), 8);
        assert_eq!(spreading.choices.first().unwrap().value, "5");
        assert_eq!(spreading.choices.last().unwrap().value, "12");
    }

    #[test]
    fn stream_receive_decodes_metadata_and_packet_header() {
        let mut companion_frame = [0; FRAME_CAPACITY];
        let packet = [0xC0, 0xA1, 0xB2, 0x03];
        let metadata = [
            91,
            200,
            0xCB,
            0xFF,
            RX_FLAG_BUFFERED | RX_FLAG_ACKED,
            7,
            0,
            0,
            0,
        ];
        let len =
            frame::str_recv(&mut companion_frame, stream::PHY_RAW, &packet, &metadata).unwrap();
        let mut engine = DebuggerEngine::default();
        ingest_serial_frame(&mut engine, &companion_frame[..len]);

        assert!(matches!(engine.take_event(), Some(Event::Trace { .. })));
        assert!(matches!(engine.take_event(), Some(Event::StreamRx {
            stream: stream::PHY_RAW,
            metadata: Some(RxMetadata {
                rssi_dbm: Some(-91),
                lqi: Some(200),
                snr_cb: Some(-53),
                buffered: true,
                acknowledged: true,
                age_s: 7,
            }),
            packet: Some(PacketSummary {
                packet_type,
                encrypted: false,
                header_len: 4,
                body_len: 0,
                mic_len: 0,
                payload_type: None,
                ..
            }),
            packet_error: None,
            ..
        }) if packet_type == "Broadcast"));
    }

    #[cfg(feature = "sim-ncp")]
    #[test]
    fn host_engine_attaches_through_real_simulated_session() {
        let mut engine = DebuggerEngine::default();
        let mut ncp = SimulatedNcp::new();
        ncp.attach();
        engine.tick(1_000);
        engine.attach().unwrap();

        while let Some(wire) = engine.take_outbound() {
            ncp.ingest(&wire, 1_000).unwrap();
            while let Some(response) = ncp.take_outbound() {
                engine.ingest(&response);
            }
        }

        let events: Vec<_> = std::iter::from_fn(|| engine.take_event()).collect();
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Attached {
                protocol_major: PROTOCOL_MAJOR_VERSION,
                ncp_version,
                phy_mtu: 255,
                ..
            } if ncp_version == "umsh-web-sim/0.1"
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Property {
                key: prop::PHY_FREQ,
                decoded: Some(_),
                ..
            }
        )));
        assert!(
            events
                .iter()
                .filter(|event| matches!(event, Event::Trace { .. }))
                .count()
                > 10
        );
    }
}
