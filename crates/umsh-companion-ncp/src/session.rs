//! The NCP protocol session state machine.

use umsh_companion::Status;
use umsh_companion::airtime::lora_airtime_ms;
use umsh_companion::frame::{self, Cmd, Frame, PropPayload, StreamPayload, TID_UNSOLICITED};
use umsh_companion::ids::{self, cap, prop, stream};
use umsh_companion::meta::{self, RxMeta, TxMeta};
use umsh_companion::pui;

use crate::duty::DutyTracker;

/// Largest radio payload the session can carry (SX126x-class limit).
pub const MAX_MTU: usize = 255;

/// Maximum UTF-8 byte length of `PROP_DEV_NAME`.
pub const MAX_DEVICE_NAME_LEN: usize = 64;

/// Room for a `CMD_STR_RECV` frame around a full-MTU payload.
const SCRATCH: usize = MAX_MTU + 24;

/// LoRa bandwidths accepted for `PROP_PHY_LORA_BW`, in Hz.
const SUPPORTED_BW_HZ: [u32; 10] = [
    7_810, 10_420, 15_630, 20_830, 31_250, 41_670, 62_500, 125_000, 250_000, 500_000,
];

/// Radio configuration owned by the session and pushed to the radio
/// via [`Effect::ApplyRadio`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadioSettings {
    pub enabled: bool,
    pub freq_khz: u32,
    pub bw_hz: u32,
    pub sf: u8,
    pub cr_denom: u8,
    pub tx_power_dbm: i8,
}

/// Transmit power selection for one pending transmit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxPower {
    /// Use the configured `PROP_PHY_TX_POWER`.
    Default,
    /// Transmit at the radio's maximum power.
    Max,
    /// Explicit per-frame override in dBm.
    Dbm(i8),
}

/// Fixed properties of the device this session runs on.
#[derive(Clone, Copy, Debug)]
pub struct SessionConfig {
    /// `PROP_NCP_VERSION` string (without NUL terminator).
    pub ncp_version: &'static str,
    /// Factory/post-reset value of `PROP_DEV_NAME`.
    pub default_device_name: &'static str,
    /// `PROP_PHY_MTU`; must not exceed [`MAX_MTU`].
    pub mtu: u16,
    /// The only sync word this firmware can use; `PROP_PHY_LORA_SW`
    /// sets must match it (v0 limitation).
    pub sync_word: u16,
    /// Lowest transmit power the radio supports, in dBm.
    pub min_tx_power_dbm: i8,
    /// Highest transmit power the radio supports, in dBm.
    pub max_tx_power_dbm: i8,
    /// Tunable frequency range in kHz, inclusive.
    pub freq_khz_min: u32,
    pub freq_khz_max: u32,
    /// Post-reset radio settings. `enabled` is forced off on reset per
    /// the spec regardless of what this carries.
    pub defaults: RadioSettings,
    /// Post-reset `PROP_PHY_DUTY_LIMIT`.
    pub default_duty_limit: u16,
}

/// A radio side effect for the caller to execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The radio configuration changed; (re)apply it.
    ApplyRadio(RadioSettings),
    /// Begin transmitting [`Session::tx_data`] at
    /// [`Session::tx_power`]; report completion with
    /// [`Session::on_tx_result`].
    StartTransmit,
    /// Sample the current instantaneous RSSI from the radio and feed the
    /// result back with [`Session::respond_rssi`], quoting this `tid`. Emitted
    /// for a `PROP_PHY_RSSI` get while the PHY is enabled, because the session
    /// itself has no live view of the radio.
    SampleRssi { tid: u8 },
    /// Apply and persist a new BLE pairing PIN, then complete the deferred
    /// property transaction with [`Session::respond_pin_set`].
    SetPairingPin { tid: u8, pin: Option<u32> },
    /// The live human-readable device name changed. Transports that expose a
    /// name should refresh it without disrupting the active session.
    DeviceNameChanged,
}

struct PendingTx {
    tid: u8,
    airtime_ms: u32,
    power: TxPower,
}

/// Outcome of dispatching a property key for encoding.
enum PropValue {
    Encoded(usize),
    Unimplemented,
    Unknown,
}

pub struct Session {
    config: SessionConfig,
    settings: RadioSettings,
    duty_limit: u16,
    duty: DutyTracker,
    last_status: Status,
    device_name: [u8; MAX_DEVICE_NAME_LEN],
    device_name_len: usize,
    pending: Option<PendingTx>,
    tx_buf: [u8; MAX_MTU],
    tx_len: usize,
    scratch: [u8; SCRATCH],
}

impl Session {
    pub fn new(config: SessionConfig) -> Self {
        debug_assert!(usize::from(config.mtu) <= MAX_MTU);
        debug_assert!(valid_device_name(config.default_device_name.as_bytes()));
        let mut settings = config.defaults;
        settings.enabled = false;
        let mut device_name = [0; MAX_DEVICE_NAME_LEN];
        let device_name_len = config.default_device_name.len();
        device_name[..device_name_len].copy_from_slice(config.default_device_name.as_bytes());
        Self {
            config,
            settings,
            duty_limit: config.default_duty_limit,
            duty: DutyTracker::new(),
            last_status: Status::RESET_POWER_ON,
            device_name,
            device_name_len,
            pending: None,
            tx_buf: [0; MAX_MTU],
            tx_len: 0,
            scratch: [0; SCRATCH],
        }
    }

    /// The active radio settings.
    pub fn settings(&self) -> RadioSettings {
        self.settings
    }

    /// Current UTF-8 `PROP_DEV_NAME` value.
    pub fn device_name(&self) -> &str {
        core::str::from_utf8(&self.device_name[..self.device_name_len])
            .expect("validated device name")
    }

    /// Payload of the transmit requested by [`Effect::StartTransmit`].
    pub fn tx_data(&self) -> &[u8] {
        &self.tx_buf[..self.tx_len]
    }

    /// Power selection for the pending transmit.
    pub fn tx_power(&self) -> TxPower {
        self.pending
            .as_ref()
            .map(|pending| pending.power)
            .unwrap_or(TxPower::Default)
    }

    /// Whether a transmit is awaiting [`Session::on_tx_result`].
    pub fn has_pending_tx(&self) -> bool {
        self.pending.is_some()
    }

    /// Reset all protocol state to post-reset defaults, announce the
    /// reset with the given reason, and return the radio effect
    /// restoring the default (disabled) radio configuration.
    ///
    /// Used for `CMD_RST` (with [`Status::RESET_SOFTWARE`]). Host attach uses
    /// [`Self::attach`] so device-domain configuration survives attachment.
    pub fn reset(&mut self, reason: Status, emit: &mut impl FnMut(&[u8])) -> Effect {
        self.reset_inner(reason, true, emit)
    }

    /// Reset host-session state for a newly attached transport while
    /// preserving device-domain configuration such as `PROP_DEV_NAME`.
    pub fn attach(&mut self, reason: Status, emit: &mut impl FnMut(&[u8])) -> Effect {
        self.reset_inner(reason, false, emit)
    }

    fn reset_inner(
        &mut self,
        reason: Status,
        reset_device_name: bool,
        emit: &mut impl FnMut(&[u8]),
    ) -> Effect {
        self.settings = self.config.defaults;
        self.settings.enabled = false;
        if reset_device_name {
            self.device_name_len = self.config.default_device_name.len();
            self.device_name[..self.device_name_len]
                .copy_from_slice(self.config.default_device_name.as_bytes());
        }
        self.duty_limit = self.config.default_duty_limit;
        self.duty.reset();
        self.pending = None;
        self.send_status(TID_UNSOLICITED, reason, emit);
        Effect::ApplyRadio(self.settings)
    }

    /// Handle one decoded companion-link frame from the host.
    pub fn handle_frame(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
        emit: &mut impl FnMut(&[u8]),
    ) -> Option<Effect> {
        // Malformed frames (bad flag, reserved bits, command MSB) are
        // ignored per the spec.
        let received = Frame::parse(bytes).ok()?;
        let tid = received.header.tid();
        match received.command() {
            Some(Cmd::Nop) => {
                self.send_status(tid, Status::OK, emit);
                None
            }
            Some(Cmd::Reset) => Some(self.reset(Status::RESET_SOFTWARE, emit)),
            Some(Cmd::PropGet) => match PropPayload::parse(received.payload) {
                Ok(payload) => self.prop_get(tid, payload.key, now_ms, emit),
                Err(_) => {
                    self.fail(tid, Status::PARSE_ERROR, emit);
                    None
                }
            },
            Some(Cmd::PropSet) => match PropPayload::parse(received.payload) {
                Ok(payload) => self.prop_set(tid, payload.key, payload.value, now_ms, emit),
                Err(_) => {
                    self.fail(tid, Status::PARSE_ERROR, emit);
                    None
                }
            },
            Some(Cmd::StrSend) => match StreamPayload::parse(received.payload) {
                Ok(payload) => self.str_send(tid, &payload, now_ms, emit),
                Err(_) => {
                    self.fail(tid, Status::PARSE_ERROR, emit);
                    None
                }
            },
            // NCP-to-host commands arriving from the host, or reserved
            // insert/remove identifiers.
            Some(Cmd::PropIs | Cmd::StrRecv) => {
                self.fail(tid, Status::INVALID_COMMAND, emit);
                None
            }
            None => {
                let status = match received.cmd {
                    4 | 5 | 7 | 8 => Status::UNIMPLEMENTED,
                    _ => Status::INVALID_COMMAND,
                };
                self.fail(tid, status, emit);
                None
            }
        }
    }

    /// Report a frame received on air. Emits `CMD_STR_RECV` unless the
    /// PHY is disabled.
    pub fn on_radio_rx(
        &mut self,
        data: &[u8],
        rssi_dbm: i16,
        snr_cb: i16,
        lqi: Option<core::num::NonZeroU8>,
        emit: &mut impl FnMut(&[u8]),
    ) {
        if !self.settings.enabled || data.len() > usize::from(self.config.mtu) {
            return;
        }
        let mut rx_meta = [0u8; RxMeta::WIRE_LEN];
        let meta_len = RxMeta {
            rssi_dbm: Some(rssi_dbm),
            lqi,
            snr_cb: Some(snr_cb),
        }
        .encode(&mut rx_meta)
        .expect("buffer sized with WIRE_LEN");
        if let Ok(len) = frame::str_recv(
            &mut self.scratch,
            stream::PHY_RAW,
            data,
            &rx_meta[..meta_len],
        ) {
            emit(&self.scratch[..len]);
        }
    }

    /// Report completion of the transmit started by
    /// [`Effect::StartTransmit`].
    pub fn on_tx_result(&mut self, success: bool, now_ms: u64, emit: &mut impl FnMut(&[u8])) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if success {
            self.duty.record(now_ms, pending.airtime_ms);
            if pending.tid != TID_UNSOLICITED {
                self.send_status(pending.tid, Status::OK, emit);
            } else {
                self.last_status = Status::OK;
            }
        } else {
            self.fail(pending.tid, Status::FAILURE, emit);
        }
    }

    // ─── Command implementations ─────────────────────────────────────

    fn prop_get(
        &mut self,
        tid: u8,
        key: u32,
        now_ms: u64,
        emit: &mut impl FnMut(&[u8]),
    ) -> Option<Effect> {
        // PROP_PHY_RSSI is an instantaneous radio reading the session cannot
        // produce on its own. While the PHY is enabled (in RX), defer to the
        // caller to sample it; while disabled there is no ambient RSSI to read.
        if key == prop::BLE_PAIRING_PIN {
            self.fail(tid, Status::UNIMPLEMENTED, emit);
            return None;
        }
        if key == prop::PHY_RSSI {
            if self.settings.enabled {
                return Some(Effect::SampleRssi { tid });
            }
            self.fail(tid, Status::INVALID_STATE, emit);
            return None;
        }
        let mut value = [0u8; 96];
        match self.encode_prop(key, now_ms, &mut value) {
            PropValue::Encoded(len) => self.send_prop_is(tid, key, &value[..len], emit),
            PropValue::Unimplemented => self.fail(tid, Status::UNIMPLEMENTED, emit),
            PropValue::Unknown => self.fail(tid, Status::PROP_NOT_FOUND, emit),
        }
        None
    }

    /// Complete a deferred `PROP_PHY_RSSI` read requested via
    /// [`Effect::SampleRssi`]. `rssi` is the sampled value in dBm, or `Err` if
    /// the radio read failed. Quote the same `tid` the effect carried.
    pub fn respond_rssi(&mut self, tid: u8, rssi: Result<i16, ()>, emit: &mut impl FnMut(&[u8])) {
        match rssi {
            Ok(dbm) => {
                let clamped = dbm.clamp(i16::from(i8::MIN), i16::from(i8::MAX)) as i8;
                self.send_prop_is(tid, prop::PHY_RSSI, &[clamped as u8], emit);
            }
            Err(()) => self.fail(tid, Status::FAILURE, emit),
        }
    }

    /// Complete a deferred write of the write-only BLE pairing PIN.
    pub fn respond_pin_set(
        &mut self,
        tid: u8,
        result: Result<(), ()>,
        emit: &mut impl FnMut(&[u8]),
    ) {
        self.send_status(
            tid,
            if result.is_ok() {
                Status::OK
            } else {
                Status::INTERNAL_ERROR
            },
            emit,
        );
    }

    fn prop_set(
        &mut self,
        tid: u8,
        key: u32,
        value: &[u8],
        now_ms: u64,
        emit: &mut impl FnMut(&[u8]),
    ) -> Option<Effect> {
        if key == prop::BLE_PAIRING_PIN {
            let pin = if value.is_empty() {
                None
            } else {
                match parse_u32(value) {
                    Ok(pin) if pin <= 999_999 => Some(pin),
                    _ => {
                        self.fail(tid, Status::INVALID_ARGUMENT, emit);
                        return None;
                    }
                }
            };
            return Some(Effect::SetPairingPin { tid, pin });
        }
        if key == prop::DEV_NAME {
            if !valid_device_name(value) {
                self.fail(tid, Status::INVALID_ARGUMENT, emit);
                return None;
            }
            self.device_name[..value.len()].copy_from_slice(value);
            self.device_name_len = value.len();
            self.send_prop_is(tid, key, value, emit);
            return Some(Effect::DeviceNameChanged);
        }
        let radio_affecting = match self.apply_prop_set(key, value) {
            Ok(radio_affecting) => radio_affecting,
            Err(status) => {
                self.fail(tid, status, emit);
                return None;
            }
        };
        // Echo the authoritative value back from session state.
        let mut encoded = [0u8; 96];
        if let PropValue::Encoded(len) = self.encode_prop(key, now_ms, &mut encoded) {
            self.send_prop_is(tid, key, &encoded[..len], emit);
        }
        radio_affecting.then_some(Effect::ApplyRadio(self.settings))
    }

    /// Validate and apply a property write. Returns whether the radio
    /// configuration changed.
    fn apply_prop_set(&mut self, key: u32, value: &[u8]) -> Result<bool, Status> {
        match key {
            prop::PHY_ENABLED => {
                self.settings.enabled = parse_bool(value)?;
                Ok(true)
            }
            prop::PHY_FREQ => {
                let freq_khz = parse_u32(value)?;
                if !(self.config.freq_khz_min..=self.config.freq_khz_max).contains(&freq_khz) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.settings.freq_khz = freq_khz;
                Ok(true)
            }
            prop::PHY_TX_POWER => {
                let power = parse_i8(value)?;
                if !(self.config.min_tx_power_dbm..=self.config.max_tx_power_dbm).contains(&power) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.settings.tx_power_dbm = power;
                Ok(true)
            }
            prop::PHY_LORA_BW => {
                let bw_hz = parse_u32(value)?;
                if !SUPPORTED_BW_HZ.contains(&bw_hz) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.settings.bw_hz = bw_hz;
                Ok(true)
            }
            prop::PHY_LORA_SF => {
                let sf = parse_u8(value)?;
                if !(5..=12).contains(&sf) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.settings.sf = sf;
                Ok(true)
            }
            prop::PHY_LORA_CR => {
                let cr = parse_u8(value)?;
                if !(5..=8).contains(&cr) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.settings.cr_denom = cr;
                Ok(true)
            }
            prop::PHY_LORA_SW => {
                // v0: the sync word is fixed at build time; accept only
                // a write of the same value.
                if parse_u16(value)? != self.config.sync_word {
                    return Err(Status::INVALID_ARGUMENT);
                }
                Ok(false)
            }
            prop::PHY_DUTY_LIMIT => {
                self.duty_limit = parse_u16(value)?;
                Ok(false)
            }
            // Known read-only properties.
            prop::LAST_STATUS
            | prop::PROTOCOL_VERSION
            | prop::NCP_VERSION
            | prop::INTERFACE_TYPE
            | prop::CAPS
            | prop::PHY_RSSI
            | prop::PHY_MTU
            | prop::PHY_DUTY_NOW => Err(Status::INVALID_ARGUMENT),
            _ => Err(Status::PROP_NOT_FOUND),
        }
    }

    fn str_send(
        &mut self,
        tid: u8,
        payload: &StreamPayload<'_>,
        now_ms: u64,
        emit: &mut impl FnMut(&[u8]),
    ) -> Option<Effect> {
        if payload.stream != stream::PHY_RAW {
            self.fail(tid, Status::PROP_NOT_FOUND, emit);
            return None;
        }
        if !self.settings.enabled {
            self.fail(tid, Status::INVALID_STATE, emit);
            return None;
        }
        if payload.data.len() > usize::from(self.config.mtu) {
            self.fail(tid, Status::INVALID_ARGUMENT, emit);
            return None;
        }
        let Ok(tx_meta) = TxMeta::decode(payload.metadata) else {
            self.fail(tid, Status::PARSE_ERROR, emit);
            return None;
        };
        if self.pending.is_some() {
            self.fail(tid, Status::BUSY, emit);
            return None;
        }

        let airtime_ms = lora_airtime_ms(
            self.settings.sf,
            self.settings.bw_hz,
            self.settings.cr_denom,
            payload.data.len(),
        );
        if tx_meta.flags & meta::TX_FLAG_NODUTY == 0
            && self.duty.would_exceed(now_ms, airtime_ms, self.duty_limit)
        {
            self.fail(tid, Status::DUTY_LIMIT, emit);
            return None;
        }
        // v0: the CCA flag is ignored — this firmware's radio path has
        // no CAD gate, so every transmit behaves as NOCCA.

        self.tx_buf[..payload.data.len()].copy_from_slice(payload.data);
        self.tx_len = payload.data.len();
        self.pending = Some(PendingTx {
            tid,
            airtime_ms,
            power: match tx_meta.power {
                meta::TX_POWER_DEFAULT => TxPower::Default,
                meta::TX_POWER_MAX => TxPower::Max,
                dbm => TxPower::Dbm(dbm),
            },
        });
        Some(Effect::StartTransmit)
    }

    // ─── Property encoding ───────────────────────────────────────────

    fn encode_prop(&mut self, key: u32, now_ms: u64, out: &mut [u8; 96]) -> PropValue {
        let len = match key {
            prop::LAST_STATUS => pui::encode(self.last_status.0, out).unwrap_or(0),
            prop::PROTOCOL_VERSION => {
                out[0] = ids::PROTOCOL_MAJOR_VERSION;
                out[1] = ids::PROTOCOL_MINOR_VERSION;
                2
            }
            prop::NCP_VERSION => {
                let bytes = self.config.ncp_version.as_bytes();
                let len = bytes.len().min(out.len() - 1);
                out[..len].copy_from_slice(&bytes[..len]);
                out[len] = 0; // NUL terminator per spec
                len + 1
            }
            prop::INTERFACE_TYPE => pui::encode(ids::INTERFACE_TYPE, out).unwrap_or(0),
            prop::CAPS => {
                let mut len = 0;
                for capability in [
                    cap::WRITABLE_RAW_STREAM,
                    cap::PHY_DUTY_LIMIT,
                    cap::DEV_NAME,
                    cap::PHY_LORA,
                ] {
                    len += pui::encode(capability, &mut out[len..]).unwrap_or(0);
                }
                len
            }
            prop::PHY_ENABLED => {
                out[0] = self.settings.enabled as u8;
                1
            }
            prop::PHY_FREQ => put(out, &self.settings.freq_khz.to_le_bytes()),
            prop::PHY_TX_POWER => {
                out[0] = self.settings.tx_power_dbm as u8;
                1
            }
            prop::PHY_RSSI => return PropValue::Unimplemented,
            prop::PHY_LORA_BW => put(out, &self.settings.bw_hz.to_le_bytes()),
            prop::PHY_LORA_SF => {
                out[0] = self.settings.sf;
                1
            }
            prop::PHY_LORA_CR => {
                out[0] = self.settings.cr_denom;
                1
            }
            prop::PHY_MTU => put(out, &self.config.mtu.to_le_bytes()),
            prop::PHY_LORA_SW => put(out, &self.config.sync_word.to_le_bytes()),
            prop::DEV_NAME => put(out, &self.device_name[..self.device_name_len]),
            prop::PHY_DUTY_NOW => put(out, &self.duty.usage(now_ms).to_le_bytes()),
            prop::PHY_DUTY_LIMIT => put(out, &self.duty_limit.to_le_bytes()),
            _ => return PropValue::Unknown,
        };
        PropValue::Encoded(len)
    }

    // ─── Emission helpers ────────────────────────────────────────────

    /// Emit `CMD_PROP_IS` for `key` with `value`.
    fn send_prop_is(&mut self, tid: u8, key: u32, value: &[u8], emit: &mut impl FnMut(&[u8])) {
        let mut buf = [0u8; 112];
        if let Ok(len) = frame::prop_is(&mut buf, tid, key, value) {
            emit(&buf[..len]);
        }
    }

    /// Emit `PROP_LAST_STATUS` unconditionally (success paths and
    /// unsolicited notices).
    fn send_status(&mut self, tid: u8, status: Status, emit: &mut impl FnMut(&[u8])) {
        self.last_status = status;
        let mut buf = [0u8; 16];
        if let Ok(len) = frame::last_status(&mut buf, tid, status) {
            emit(&buf[..len]);
        }
    }

    /// Record a failure. Correlated commands get an error response;
    /// fire-and-forget (TID 0) failures only update `PROP_LAST_STATUS`.
    fn fail(&mut self, tid: u8, status: Status, emit: &mut impl FnMut(&[u8])) {
        if tid == TID_UNSOLICITED {
            self.last_status = status;
        } else {
            self.send_status(tid, status, emit);
        }
    }
}

fn put(out: &mut [u8], bytes: &[u8]) -> usize {
    out[..bytes.len()].copy_from_slice(bytes);
    bytes.len()
}

fn parse_bool(value: &[u8]) -> Result<bool, Status> {
    match value {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(Status::INVALID_ARGUMENT),
    }
}

fn parse_u8(value: &[u8]) -> Result<u8, Status> {
    match value {
        [byte] => Ok(*byte),
        _ => Err(Status::INVALID_ARGUMENT),
    }
}

fn parse_i8(value: &[u8]) -> Result<i8, Status> {
    parse_u8(value).map(|byte| byte as i8)
}

fn parse_u16(value: &[u8]) -> Result<u16, Status> {
    match value {
        [lo, hi] => Ok(u16::from_le_bytes([*lo, *hi])),
        _ => Err(Status::INVALID_ARGUMENT),
    }
}

fn parse_u32(value: &[u8]) -> Result<u32, Status> {
    match value {
        [a, b, c, d] => Ok(u32::from_le_bytes([*a, *b, *c, *d])),
        _ => Err(Status::INVALID_ARGUMENT),
    }
}

fn valid_device_name(value: &[u8]) -> bool {
    (1..=MAX_DEVICE_NAME_LEN).contains(&value.len())
        && !value.contains(&0)
        && core::str::from_utf8(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> Session {
        Session::new(SessionConfig {
            ncp_version: "test-ncp/0.1",
            default_device_name: "Test UMSH NCP",
            mtu: 255,
            sync_word: 0x1424,
            min_tx_power_dbm: -9,
            max_tx_power_dbm: 22,
            freq_khz_min: 150_000,
            freq_khz_max: 960_000,
            defaults: RadioSettings {
                enabled: false,
                freq_khz: 910_525,
                bw_hz: 62_500,
                sf: 7,
                cr_denom: 5,
                tx_power_dbm: 14,
            },
            default_duty_limit: 0xFFFF,
        })
    }

    /// Drive `handle_frame` and collect emitted frames.
    fn dispatch(
        session: &mut Session,
        request: &[u8],
        now_ms: u64,
    ) -> (Vec<Vec<u8>>, Option<Effect>) {
        let mut emitted = Vec::new();
        let effect = session.handle_frame(request, now_ms, &mut |bytes: &[u8]| {
            emitted.push(bytes.to_vec())
        });
        (emitted, effect)
    }

    /// Parse an emitted frame as `CMD_PROP_IS` and return (tid, key, value).
    fn parse_prop_is(bytes: &[u8]) -> (u8, u32, Vec<u8>) {
        let parsed = Frame::parse(bytes).unwrap();
        assert_eq!(parsed.command(), Some(Cmd::PropIs));
        let payload = PropPayload::parse(parsed.payload).unwrap();
        (parsed.header.tid(), payload.key, payload.value.to_vec())
    }

    fn expect_status(bytes: &[u8], tid: u8, status: Status) {
        let (response_tid, key, value) = parse_prop_is(bytes);
        assert_eq!(response_tid, tid);
        assert_eq!(key, prop::LAST_STATUS);
        assert_eq!(pui::decode(&value).unwrap().0, status.0);
    }

    fn get(session: &mut Session, key: u32) -> Vec<u8> {
        let mut buf = [0u8; 16];
        let len = frame::prop_get(&mut buf, 1, key).unwrap();
        let (emitted, effect) = dispatch(session, &buf[..len], 0);
        assert!(effect.is_none());
        let (_, response_key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(response_key, key);
        value
    }

    fn set(session: &mut Session, key: u32, value: &[u8]) -> (Vec<Vec<u8>>, Option<Effect>) {
        let mut buf = [0u8; 80];
        let len = frame::prop_set(&mut buf, 2, key, value).unwrap();
        dispatch(session, &buf[..len], 0)
    }

    fn send_packet(
        session: &mut Session,
        tid: u8,
        data: &[u8],
        meta: &[u8],
        now_ms: u64,
    ) -> (Vec<Vec<u8>>, Option<Effect>) {
        let mut buf = [0u8; 320];
        let len = frame::str_send(&mut buf, tid, stream::PHY_RAW, data, meta).unwrap();
        dispatch(session, &buf[..len], now_ms)
    }

    fn enable(session: &mut Session) {
        let (_, effect) = set(session, prop::PHY_ENABLED, &[1]);
        assert!(matches!(effect, Some(Effect::ApplyRadio(settings)) if settings.enabled));
    }

    #[test]
    fn nop_replies_ok() {
        let mut session = test_session();
        let mut buf = [0u8; 4];
        let len = frame::nop(&mut buf, 3).unwrap();
        let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 3, Status::OK);
    }

    #[test]
    fn reset_returns_to_defaults() {
        let mut session = test_session();
        enable(&mut session);
        set(&mut session, prop::PHY_LORA_SF, &[12]);

        let mut buf = [0u8; 4];
        let len = frame::reset(&mut buf, 0).unwrap();
        let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
        expect_status(&emitted[0], TID_UNSOLICITED, Status::RESET_SOFTWARE);
        let Some(Effect::ApplyRadio(settings)) = effect else {
            panic!("expected ApplyRadio, got {effect:?}");
        };
        assert!(!settings.enabled);
        assert_eq!(settings.sf, 7);
        assert_eq!(get(&mut session, prop::PHY_ENABLED), [0]);
    }

    #[test]
    fn identity_properties() {
        let mut session = test_session();
        assert_eq!(get(&mut session, prop::PROTOCOL_VERSION), [6, 0]);
        assert_eq!(get(&mut session, prop::NCP_VERSION), b"test-ncp/0.1\0");
        assert_eq!(get(&mut session, prop::DEV_NAME), b"Test UMSH NCP");
        assert_eq!(get(&mut session, prop::PHY_MTU), 255u16.to_le_bytes());
        assert_eq!(
            pui::decode(&get(&mut session, prop::INTERFACE_TYPE))
                .unwrap()
                .0,
            ids::INTERFACE_TYPE
        );
        // Post-reset LAST_STATUS is the reset reason.
        assert_eq!(
            pui::decode(&get(&mut session, prop::LAST_STATUS))
                .unwrap()
                .0,
            Status::RESET_POWER_ON.0
        );
    }

    #[test]
    fn caps_list_decodes() {
        let mut session = test_session();
        let raw = get(&mut session, prop::CAPS);
        let mut caps = Vec::new();
        let mut offset = 0;
        while offset < raw.len() {
            let (value, used) = pui::decode(&raw[offset..]).unwrap();
            caps.push(value);
            offset += used;
        }
        assert_eq!(
            caps,
            [
                cap::WRITABLE_RAW_STREAM,
                cap::PHY_DUTY_LIMIT,
                cap::DEV_NAME,
                cap::PHY_LORA
            ]
        );
    }

    #[test]
    fn device_name_round_trips_survives_attach_and_resets_to_default() {
        let mut session = test_session();
        let configured = "Field Radio 📻";
        let (emitted, effect) = set(&mut session, prop::DEV_NAME, configured.as_bytes());
        let (_, key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(key, prop::DEV_NAME);
        assert_eq!(value, configured.as_bytes());
        assert_eq!(effect, Some(Effect::DeviceNameChanged));
        assert_eq!(session.device_name(), configured);

        let _ = session.attach(Status::RESET_EXTERNAL, &mut |_| {});
        assert_eq!(get(&mut session, prop::DEV_NAME), configured.as_bytes());

        let _ = session.reset(Status::RESET_SOFTWARE, &mut |_| {});
        assert_eq!(get(&mut session, prop::DEV_NAME), b"Test UMSH NCP");
    }

    #[test]
    fn device_name_rejects_empty_invalid_nul_and_oversize_values() {
        let mut session = test_session();
        let oversize = [b'x'; MAX_DEVICE_NAME_LEN + 1];
        for bad in [&[][..], &[0xff][..], b"bad\0name", &oversize[..]] {
            let (emitted, effect) = set(&mut session, prop::DEV_NAME, bad);
            assert!(effect.is_none());
            expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);
        }
        assert_eq!(session.device_name(), "Test UMSH NCP");
    }

    #[test]
    fn rf_property_round_trip() {
        let mut session = test_session();
        let (emitted, effect) = set(&mut session, prop::PHY_FREQ, &906_875u32.to_le_bytes());
        let (_, key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(key, prop::PHY_FREQ);
        assert_eq!(value, 906_875u32.to_le_bytes());
        assert!(matches!(effect, Some(Effect::ApplyRadio(s)) if s.freq_khz == 906_875));
        assert_eq!(get(&mut session, prop::PHY_FREQ), 906_875u32.to_le_bytes());
    }

    #[test]
    fn invalid_values_rejected() {
        let mut session = test_session();
        for (key, bad) in [
            (prop::PHY_LORA_SF, &[4][..]),
            (prop::PHY_LORA_SF, &[13][..]),
            (prop::PHY_LORA_CR, &[9][..]),
            (prop::PHY_LORA_BW, &123_456u32.to_le_bytes()[..]),
            (prop::PHY_FREQ, &10_000u32.to_le_bytes()[..]),
            (prop::PHY_TX_POWER, &[40][..]),
            (prop::PHY_ENABLED, &[2][..]),
            (prop::PHY_LORA_SW, &0xBEEFu16.to_le_bytes()[..]),
            // Wrong width.
            (prop::PHY_FREQ, &[1, 2][..]),
        ] {
            let (emitted, effect) = set(&mut session, key, bad);
            assert!(effect.is_none(), "key {key} accepted {bad:?}");
            expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);
        }
    }

    #[test]
    fn read_only_and_unknown_props() {
        let mut session = test_session();
        let (emitted, _) = set(&mut session, prop::PHY_MTU, &[0, 1]);
        expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);

        let (emitted, _) = set(&mut session, 9_999, &[0]);
        expect_status(&emitted[0], 2, Status::PROP_NOT_FOUND);

        let mut buf = [0u8; 16];
        let len = frame::prop_get(&mut buf, 1, 9_999).unwrap();
        let (emitted, _) = dispatch(&mut session, &buf[..len], 0);
        expect_status(&emitted[0], 1, Status::PROP_NOT_FOUND);

        // PHY_RSSI while the PHY is disabled: no ambient RSSI to read.
        let len = frame::prop_get(&mut buf, 1, prop::PHY_RSSI).unwrap();
        let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 1, Status::INVALID_STATE);
    }

    #[test]
    fn phy_rssi_defers_to_radio_when_enabled() {
        let mut session = test_session();
        enable(&mut session);

        // A GET while enabled defers instead of answering inline.
        let mut buf = [0u8; 16];
        let len = frame::prop_get(&mut buf, 3, prop::PHY_RSSI).unwrap();
        let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
        assert!(emitted.is_empty(), "no response until the radio is sampled");
        assert_eq!(effect, Some(Effect::SampleRssi { tid: 3 }));

        // The caller feeds the sample back; the session emits PROP_IS.
        let mut out = Vec::new();
        session.respond_rssi(3, Ok(-91), &mut |bytes: &[u8]| out.push(bytes.to_vec()));
        let (tid, key, value) = parse_prop_is(&out[0]);
        assert_eq!(tid, 3);
        assert_eq!(key, prop::PHY_RSSI);
        assert_eq!(value, [(-91i8) as u8]);

        // A failed radio read surfaces as STATUS_FAILURE.
        let mut out = Vec::new();
        session.respond_rssi(4, Err(()), &mut |bytes: &[u8]| out.push(bytes.to_vec()));
        expect_status(&out[0], 4, Status::FAILURE);
    }

    #[test]
    fn pairing_pin_set_clear_validate_and_defer() {
        let mut session = test_session();

        let (emitted, effect) = set(
            &mut session,
            prop::BLE_PAIRING_PIN,
            &123_456u32.to_le_bytes(),
        );
        assert!(
            emitted.is_empty(),
            "PIN must not be acknowledged before apply"
        );
        assert_eq!(
            effect,
            Some(Effect::SetPairingPin {
                tid: 2,
                pin: Some(123_456)
            })
        );

        let (emitted, effect) = set(&mut session, prop::BLE_PAIRING_PIN, &[]);
        assert!(emitted.is_empty());
        assert_eq!(effect, Some(Effect::SetPairingPin { tid: 2, pin: None }));

        for bad in [&1_000_000u32.to_le_bytes()[..], &[1, 2, 3][..]] {
            let (emitted, effect) = set(&mut session, prop::BLE_PAIRING_PIN, bad);
            assert!(effect.is_none());
            expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);
        }
    }

    #[test]
    fn pairing_pin_completion_and_get_refusal() {
        let mut session = test_session();
        let mut emitted = Vec::new();
        session.respond_pin_set(7, Ok(()), &mut |frame| emitted.push(frame.to_vec()));
        expect_status(&emitted[0], 7, Status::OK);
        emitted.clear();
        session.respond_pin_set(6, Err(()), &mut |frame| emitted.push(frame.to_vec()));
        expect_status(&emitted[0], 6, Status::INTERNAL_ERROR);

        let mut request = [0; 16];
        let len = frame::prop_get(&mut request, 5, prop::BLE_PAIRING_PIN).unwrap();
        let (emitted, effect) = dispatch(&mut session, &request[..len], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 5, Status::UNIMPLEMENTED);
    }

    #[test]
    fn reset_has_no_pairing_pin_effect() {
        let mut session = test_session();
        let mut request = [0; 4];
        let len = frame::reset(&mut request, 1).unwrap();
        let (_, effect) = dispatch(&mut session, &request[..len], 0);
        assert!(matches!(effect, Some(Effect::ApplyRadio(_))));
    }

    #[test]
    fn transmit_lifecycle() {
        let mut session = test_session();
        enable(&mut session);

        let packet = [0xAAu8; 32];
        let (emitted, effect) = send_packet(&mut session, 4, &packet, &[], 0);
        assert!(emitted.is_empty(), "no response until TX completes");
        assert_eq!(effect, Some(Effect::StartTransmit));
        assert_eq!(session.tx_data(), &packet);
        assert_eq!(session.tx_power(), TxPower::Default);

        // A second confirmed send while busy fails with BUSY.
        let (emitted, effect) = send_packet(&mut session, 5, &packet, &[], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 5, Status::BUSY);

        // Completion emits OK with the original TID and records duty.
        let mut emitted = Vec::new();
        session.on_tx_result(true, 0, &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        expect_status(&emitted[0], 4, Status::OK);
        assert!(!session.has_pending_tx());
        let duty = get(&mut session, prop::PHY_DUTY_NOW);
        assert!(u16::from_le_bytes([duty[0], duty[1]]) > 0);
    }

    #[test]
    fn transmit_requires_enabled_phy() {
        let mut session = test_session();
        let (emitted, effect) = send_packet(&mut session, 4, &[0u8; 8], &[], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 4, Status::INVALID_STATE);
    }

    #[test]
    fn transmit_power_override() {
        let mut session = test_session();
        enable(&mut session);
        let meta = [22u8, 0x00];
        let (_, effect) = send_packet(&mut session, 4, &[0u8; 8], &meta, 0);
        assert_eq!(effect, Some(Effect::StartTransmit));
        assert_eq!(session.tx_power(), TxPower::Dbm(22));
    }

    #[test]
    fn duty_limit_blocks_and_noduty_bypasses() {
        let mut session = test_session();
        enable(&mut session);
        // Slowest settings: one full frame is minutes of airtime.
        set(&mut session, prop::PHY_LORA_SF, &[12]);
        set(&mut session, prop::PHY_LORA_BW, &7_810u32.to_le_bytes());
        // 0.1% limit.
        set(&mut session, prop::PHY_DUTY_LIMIT, &65u16.to_le_bytes());

        let packet = [0u8; 255];
        let (emitted, effect) = send_packet(&mut session, 3, &packet, &[], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 3, Status::DUTY_LIMIT);

        // NODUTY flag bypasses the limit.
        let meta = [meta::TX_POWER_DEFAULT as u8, meta::TX_FLAG_NODUTY];
        let (_, effect) = send_packet(&mut session, 3, &packet, &meta, 0);
        assert_eq!(effect, Some(Effect::StartTransmit));
    }

    #[test]
    fn fire_and_forget_failures_are_silent() {
        let mut session = test_session();
        // PHY disabled: a TID-0 send fails without emitting anything.
        let (emitted, effect) = send_packet(&mut session, 0, &[0u8; 4], &[], 0);
        assert!(effect.is_none());
        assert!(emitted.is_empty());
        // ... but LAST_STATUS records it.
        assert_eq!(
            pui::decode(&get(&mut session, prop::LAST_STATUS))
                .unwrap()
                .0,
            Status::INVALID_STATE.0
        );
    }

    #[test]
    fn radio_rx_emits_str_recv() {
        let mut session = test_session();
        enable(&mut session);
        let mut emitted = Vec::new();
        session.on_radio_rx(&[1, 2, 3], -91, -53, None, &mut |bytes: &[u8]| {
            emitted.push(bytes.to_vec())
        });
        let parsed = Frame::parse(&emitted[0]).unwrap();
        assert_eq!(parsed.command(), Some(Cmd::StrRecv));
        assert_eq!(parsed.header.tid(), TID_UNSOLICITED);
        let payload = StreamPayload::parse(parsed.payload).unwrap();
        assert_eq!(payload.data, &[1, 2, 3]);
        let rx_meta = RxMeta::decode(payload.metadata).unwrap();
        assert_eq!(rx_meta.rssi_dbm, Some(-91));
        assert_eq!(rx_meta.snr_cb, Some(-53));
    }

    #[test]
    fn radio_rx_suppressed_while_disabled() {
        let mut session = test_session();
        let mut emitted = Vec::new();
        session.on_radio_rx(&[1, 2, 3], -91, -53, None, &mut |bytes: &[u8]| {
            emitted.push(bytes.to_vec())
        });
        assert!(emitted.is_empty());
    }

    #[test]
    fn reserved_commands_unimplemented() {
        let mut session = test_session();
        for cmd in [4u8, 5, 7, 8] {
            let (emitted, effect) = dispatch(&mut session, &[0x81, cmd], 0);
            assert!(effect.is_none());
            expect_status(&emitted[0], 1, Status::UNIMPLEMENTED);
        }
        // Unknown non-reserved command.
        let (emitted, _) = dispatch(&mut session, &[0x81, 42], 0);
        expect_status(&emitted[0], 1, Status::INVALID_COMMAND);
    }

    #[test]
    fn malformed_frames_ignored() {
        let mut session = test_session();
        for bad in [&[][..], &[0x81][..], &[0x00, 0x00][..], &[0xB8, 0x00][..]] {
            let (emitted, effect) = dispatch(&mut session, bad, 0);
            assert!(emitted.is_empty());
            assert!(effect.is_none());
        }
    }
}
