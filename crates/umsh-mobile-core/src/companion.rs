use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use umsh_companion::{
    BatteryChargeState, BatteryStatus, Cmd, Frame, PropPayload, frame,
    gatt::{self, MAX_FRAME, Reassembler},
    ids::{INTERFACE_TYPE, PROTOCOL_MAJOR_VERSION, PROTOCOL_MINOR_VERSION, cap, prop},
    items::{self, Filter},
    pui,
};

use crate::MobileError;

/// One header-prefixed ATT value produced by companion GATT segmentation.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GattSegmentRecord {
    pub value: Vec<u8>,
}

/// A validated property-bearing companion frame.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionPropertyFrameRecord {
    pub transaction_id: u8,
    pub command: u8,
    pub property_id: u32,
    pub value: Vec<u8>,
}

/// UI-relevant fields from a validated `PROP_BATTERY` value.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionBatteryRecord {
    pub percentage: Option<u8>,
    pub is_externally_powered: Option<bool>,
}

/// Read-only, capability-gated companion state gathered after host ownership
/// has been resolved. Counts describe digest forms and contain no key material.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionSyncRecord {
    pub capability_count: u32,
    pub has_host_filtering: bool,
    pub supports_offline_queue: bool,
    pub supports_delegated_ack: bool,
    pub phy_enabled: bool,
    pub frequency_khz: u32,
    pub saved: Option<bool>,
    pub queued_frames: Option<u16>,
    pub dropped_frames: Option<u32>,
    pub filter_count: Option<u32>,
    pub host_channel_count: Option<u32>,
    pub host_peer_count: Option<u32>,
    pub auto_ack: Option<bool>,
}

/// Long-lived host-session phase. Swift maps this value to UI link state but
/// does not implement companion protocol transitions itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CompanionSessionPhase {
    Idle,
    Synchronizing,
    AwaitingHost,
    Claiming,
    Attached,
}

/// Authoritative comparison of `PROP_HOST_KEY` with the selected phone identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CompanionHostOwnership {
    Unknown,
    LocalIdentityUnavailable,
    Unsupported,
    Unclaimed,
    Ours,
    OtherHost,
}

/// Typed state published after each bounded companion-session transition.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionSessionSnapshotRecord {
    pub generation: u64,
    pub phase: CompanionSessionPhase,
    pub host_ownership: CompanionHostOwnership,
    pub device_key: Option<Vec<u8>>,
    pub device_name: Option<String>,
    pub battery: Option<CompanionBatteryRecord>,
    pub provisioning: Option<CompanionSyncRecord>,
}

/// Work produced by the Rust companion session. Frames are complete companion
/// frames; the platform adapter remains responsible for GATT segmentation and
/// write backpressure.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionSessionUpdateRecord {
    pub outbound_frames: Vec<Vec<u8>>,
    pub snapshot: CompanionSessionSnapshotRecord,
    pub waiting_for_responses: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionStage {
    Idle,
    Initial,
    Inspection,
    Claiming,
    Saving,
    AwaitingHost,
    Attached,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedResponse {
    Property(u32),
    Claim,
    Save,
}

struct CompanionSessionState {
    generation: u64,
    stage: SessionStage,
    next_tid: u8,
    expected: HashMap<u8, ExpectedResponse>,
    selected_host_key: Option<[u8; 32]>,
    radio_host_key: Option<Vec<u8>>,
    host_key_unsupported: bool,
    responses: HashMap<u32, CompanionPropertyFrameRecord>,
    inspection_queue: VecDeque<u32>,
    device_key: Option<Vec<u8>>,
    device_name: Option<String>,
    battery: Option<CompanionBatteryRecord>,
    provisioning: Option<CompanionSyncRecord>,
}

impl Default for CompanionSessionState {
    fn default() -> Self {
        Self {
            generation: 0,
            stage: SessionStage::Idle,
            next_tid: 1,
            expected: HashMap::new(),
            selected_host_key: None,
            radio_host_key: None,
            host_key_unsupported: false,
            responses: HashMap::new(),
            inspection_queue: VecDeque::new(),
            device_key: None,
            device_name: None,
            battery: None,
            provisioning: None,
        }
    }
}

/// Stateful mobile host session for the companion protocol.
///
/// This is the protocol boundary: it consumes complete reassembled companion
/// frames and owns TIDs, response matching, capability-driven synchronization,
/// host ownership, and claim/save choreography. Platform code owns only the
/// transport lifecycle, byte shuttling, and timers.
#[derive(uniffi::Object)]
pub struct MobileCompanionSession {
    inner: Mutex<CompanionSessionState>,
}

#[uniffi::export]
impl MobileCompanionSession {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(CompanionSessionState::default()),
        })
    }

    /// Begin post-attach synchronization for a new transport generation.
    pub fn begin(
        &self,
        selected_host_key: Option<Vec<u8>>,
    ) -> Result<CompanionSessionUpdateRecord, MobileError> {
        let selected_host_key = selected_host_key
            .map(|key| {
                key.try_into()
                    .map_err(|_| MobileError::InvalidPublicKeyLength)
            })
            .transpose()?;
        let mut state = self.inner.lock().expect("companion session mutex poisoned");
        let generation = state.generation.wrapping_add(1);
        *state = CompanionSessionState {
            generation,
            stage: SessionStage::Initial,
            selected_host_key,
            ..CompanionSessionState::default()
        };

        let mut outbound = Vec::new();
        for property in [
            prop::LAST_STATUS,
            prop::PROTOCOL_VERSION,
            prop::CAPS,
            prop::DEV_KEY,
            prop::DEV_NAME,
            prop::BATTERY,
            prop::HOST_KEY,
        ] {
            outbound.push(state.get_property(property)?);
        }
        Ok(state.update(outbound))
    }

    /// Replace an unclaimed or other-host configuration with this phone's key.
    pub fn claim(&self, host_key: Vec<u8>) -> Result<CompanionSessionUpdateRecord, MobileError> {
        let host_key: [u8; 32] = host_key
            .try_into()
            .map_err(|_| MobileError::InvalidPublicKeyLength)?;
        let mut state = self.inner.lock().expect("companion session mutex poisoned");
        if state.stage != SessionStage::AwaitingHost
            || !matches!(
                state.ownership(),
                CompanionHostOwnership::Unclaimed | CompanionHostOwnership::OtherHost
            )
        {
            return Err(MobileError::InvalidCompanionFrame);
        }
        state.selected_host_key = Some(host_key);
        state.stage = SessionStage::Claiming;
        state.expected.clear();
        let tid = state.allocate_tid();
        state.expected.insert(tid, ExpectedResponse::Claim);
        let frame = companion_prop_set(tid, prop::HOST_KEY, host_key.to_vec())?;
        Ok(state.update(vec![frame]))
    }

    /// Consume one complete companion frame and advance the session reducer.
    pub fn consume(&self, frame: Vec<u8>) -> Result<CompanionSessionUpdateRecord, MobileError> {
        let response = inspect_companion_property_frame(frame)?;
        let mut state = self.inner.lock().expect("companion session mutex poisoned");
        let mut outbound = Vec::new();

        if response.transaction_id == frame::TID_UNSOLICITED {
            if response.command == Cmd::PropIs as u8 {
                state
                    .responses
                    .insert(response.property_id, response.clone());
            }
            state.apply_property(&response)?;
            state.refresh_attached_snapshot()?;
            return Ok(state.update(outbound));
        }

        let expected = state
            .expected
            .remove(&response.transaction_id)
            .ok_or(MobileError::InvalidCompanionFrame)?;
        match expected {
            ExpectedResponse::Property(property) => {
                if response.property_id == prop::LAST_STATUS && property != prop::LAST_STATUS {
                    if state.stage == SessionStage::Initial
                        && matches!(property, prop::DEV_KEY | prop::DEV_NAME | prop::BATTERY)
                    {
                        // Optional device properties may be absent on minimal radios.
                    } else if state.stage == SessionStage::Initial && property == prop::HOST_KEY {
                        state.host_key_unsupported = true;
                    } else {
                        return Err(MobileError::InvalidCompanionFrame);
                    }
                } else {
                    if response.property_id != property || response.command != Cmd::PropIs as u8 {
                        return Err(MobileError::InvalidCompanionFrame);
                    }
                    state.responses.insert(property, response.clone());
                    state.apply_property(&response)?;
                }
            }
            ExpectedResponse::Claim => {
                if response.property_id != prop::HOST_KEY || response.command != Cmd::PropIs as u8 {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                let selected = state
                    .selected_host_key
                    .ok_or(MobileError::InvalidCompanionFrame)?;
                if response.value.as_slice() != selected {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                state.radio_host_key = Some(response.value.clone());
                state.responses.insert(prop::HOST_KEY, response);
                if state.has_capability(cap::SAVE)? {
                    state.stage = SessionStage::Saving;
                    let tid = state.allocate_tid();
                    state.expected.insert(tid, ExpectedResponse::Save);
                    outbound.push(companion_save(tid)?);
                } else {
                    state.start_inspection(&mut outbound)?;
                }
            }
            ExpectedResponse::Save => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                if inspect_companion_status(response.value)? != 0 {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                state.start_inspection(&mut outbound)?;
            }
        }

        if state.expected.is_empty() {
            state.advance_completed_stage(&mut outbound)?;
        }
        Ok(state.update(outbound))
    }

    /// Invalidate all outstanding transactions for a disconnected transport.
    pub fn reset(&self) -> CompanionSessionUpdateRecord {
        let mut state = self.inner.lock().expect("companion session mutex poisoned");
        let generation = state.generation.wrapping_add(1);
        *state = CompanionSessionState {
            generation,
            ..CompanionSessionState::default()
        };
        state.update(Vec::new())
    }
}

impl CompanionSessionState {
    fn allocate_tid(&mut self) -> u8 {
        let tid = self.next_tid;
        self.next_tid = if tid >= frame::TID_MAX { 1 } else { tid + 1 };
        tid
    }

    fn get_property(&mut self, property: u32) -> Result<Vec<u8>, MobileError> {
        let tid = self.allocate_tid();
        self.expected
            .insert(tid, ExpectedResponse::Property(property));
        companion_prop_get(tid, property)
    }

    fn phase(&self) -> CompanionSessionPhase {
        match self.stage {
            SessionStage::Idle => CompanionSessionPhase::Idle,
            SessionStage::Initial | SessionStage::Inspection | SessionStage::Saving => {
                CompanionSessionPhase::Synchronizing
            }
            SessionStage::AwaitingHost => CompanionSessionPhase::AwaitingHost,
            SessionStage::Claiming => CompanionSessionPhase::Claiming,
            SessionStage::Attached => CompanionSessionPhase::Attached,
        }
    }

    fn ownership(&self) -> CompanionHostOwnership {
        if self.host_key_unsupported {
            return CompanionHostOwnership::Unsupported;
        }
        let Some(radio_key) = self.radio_host_key.as_deref() else {
            return CompanionHostOwnership::Unknown;
        };
        if radio_key.is_empty() {
            return CompanionHostOwnership::Unclaimed;
        }
        match self.selected_host_key {
            None => CompanionHostOwnership::LocalIdentityUnavailable,
            Some(selected) if radio_key == selected => CompanionHostOwnership::Ours,
            Some(_) => CompanionHostOwnership::OtherHost,
        }
    }

    fn update(&self, outbound_frames: Vec<Vec<u8>>) -> CompanionSessionUpdateRecord {
        CompanionSessionUpdateRecord {
            outbound_frames,
            snapshot: CompanionSessionSnapshotRecord {
                generation: self.generation,
                phase: self.phase(),
                host_ownership: self.ownership(),
                device_key: self.device_key.clone(),
                device_name: self.device_name.clone(),
                battery: self.battery.clone(),
                provisioning: self.provisioning.clone(),
            },
            waiting_for_responses: !self.expected.is_empty(),
        }
    }

    fn apply_property(
        &mut self,
        response: &CompanionPropertyFrameRecord,
    ) -> Result<(), MobileError> {
        if response.command != Cmd::PropIs as u8 {
            // Insert/remove notifications are valid protocol frames, but none
            // of the mobile snapshot fields are multi-value payloads.
            return Ok(());
        }
        match response.property_id {
            prop::DEV_KEY => {
                if response.value.is_empty() {
                    self.device_key = None;
                } else if response.value.len() == items::PUBLIC_KEY_LEN {
                    self.device_key = Some(response.value.clone());
                } else {
                    return Err(MobileError::InvalidCompanionFrame);
                }
            }
            prop::DEV_NAME => {
                let name = core::str::from_utf8(&response.value)
                    .map_err(|_| MobileError::InvalidCompanionFrame)?;
                self.device_name = (!name.is_empty()).then(|| name.to_owned());
            }
            prop::BATTERY => {
                self.battery = Some(inspect_companion_battery(response.value.clone())?);
            }
            prop::HOST_KEY => {
                if !response.value.is_empty() && response.value.len() != items::PUBLIC_KEY_LEN {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                self.radio_host_key = Some(response.value.clone());
            }
            _ => {}
        }
        Ok(())
    }

    fn has_capability(&self, capability: u32) -> Result<bool, MobileError> {
        let capabilities = self
            .responses
            .get(&prop::CAPS)
            .ok_or(MobileError::InvalidCompanionFrame)?;
        Ok(decode_capabilities(&capabilities.value)?.contains(&capability))
    }

    fn advance_completed_stage(&mut self, outbound: &mut Vec<Vec<u8>>) -> Result<(), MobileError> {
        match self.stage {
            SessionStage::Initial => {
                let version = self
                    .responses
                    .get(&prop::PROTOCOL_VERSION)
                    .ok_or(MobileError::InvalidCompanionFrame)?;
                if version.value != [PROTOCOL_MAJOR_VERSION, PROTOCOL_MINOR_VERSION] {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                let capabilities = self
                    .responses
                    .get(&prop::CAPS)
                    .ok_or(MobileError::InvalidCompanionFrame)?;
                self.inspection_queue =
                    companion_inspection_properties(capabilities.value.clone())?.into();
                let advertises_host_filter = self.has_capability(cap::HOST_FILTER)?;
                if advertises_host_filter == self.host_key_unsupported {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                match self.ownership() {
                    CompanionHostOwnership::Ours | CompanionHostOwnership::Unsupported => {
                        self.start_inspection(outbound)?;
                    }
                    _ => self.stage = SessionStage::AwaitingHost,
                }
            }
            SessionStage::Inspection => self.start_inspection(outbound)?,
            SessionStage::Claiming
            | SessionStage::Saving
            | SessionStage::AwaitingHost
            | SessionStage::Attached
            | SessionStage::Idle => {}
        }
        Ok(())
    }

    fn start_inspection(&mut self, outbound: &mut Vec<Vec<u8>>) -> Result<(), MobileError> {
        self.stage = SessionStage::Inspection;
        if self.inspection_queue.is_empty() {
            let responses = self.responses.values().cloned().collect();
            self.provisioning = Some(inspect_companion_sync(responses)?);
            self.stage = SessionStage::Attached;
            return Ok(());
        }
        for _ in 0..usize::from(frame::TID_MAX) {
            let Some(property) = self.inspection_queue.pop_front() else {
                break;
            };
            outbound.push(self.get_property(property)?);
        }
        Ok(())
    }

    fn refresh_attached_snapshot(&mut self) -> Result<(), MobileError> {
        if self.stage != SessionStage::Attached {
            return Ok(());
        }
        let responses = self.responses.values().cloned().collect();
        self.provisioning = Some(inspect_companion_sync(responses)?);
        if !matches!(
            self.ownership(),
            CompanionHostOwnership::Ours | CompanionHostOwnership::Unsupported
        ) {
            self.stage = SessionStage::AwaitingHost;
        }
        Ok(())
    }
}

/// Return the authoritative properties needed for the read-only post-attach
/// inspection, gated by the supplied `PROP_CAPS` value.
#[uniffi::export]
pub fn companion_inspection_properties(capabilities: Vec<u8>) -> Result<Vec<u32>, MobileError> {
    let capabilities = decode_capabilities(&capabilities)?;
    validate_capability_dependencies(&capabilities)?;
    let has = |capability| capabilities.contains(&capability);

    let mut properties = vec![prop::INTERFACE_TYPE, prop::PHY_ENABLED, prop::PHY_FREQ];
    if has(cap::SAVE) {
        properties.push(prop::SAVED);
    }
    if has(cap::HOST_FILTER) {
        properties.push(prop::HOST_RX_FILTERS);
    }
    if has(cap::HOST_KEYS) {
        properties.extend([prop::HOST_CHANNEL_KEYS, prop::HOST_PEER_KEYS]);
    }
    if has(cap::HOST_RX_QUEUE) {
        properties.extend([prop::HOST_RX_QUEUE_COUNT, prop::HOST_RX_QUEUE_DROPPED]);
    }
    if has(cap::HOST_AUTO_ACK) {
        properties.push(prop::HOST_AUTO_ACK);
    }
    Ok(properties)
}

/// Validate and reduce the property responses from the read-only post-attach
/// inspection. Every capability-gated property must be present and well formed.
#[uniffi::export]
pub fn inspect_companion_sync(
    responses: Vec<CompanionPropertyFrameRecord>,
) -> Result<CompanionSyncRecord, MobileError> {
    let value = |key| property_value(&responses, key);
    let capabilities = decode_capabilities(value(prop::CAPS)?)?;
    validate_capability_dependencies(&capabilities)?;
    let has = |capability| capabilities.contains(&capability);

    let interface = decode_exact_pui(value(prop::INTERFACE_TYPE)?)?;
    if interface != INTERFACE_TYPE {
        return Err(MobileError::InvalidCompanionFrame);
    }
    let phy_enabled = decode_bool(value(prop::PHY_ENABLED)?)?;
    let frequency_khz = decode_u32(value(prop::PHY_FREQ)?)?;
    let saved = has(cap::SAVE)
        .then(|| decode_bool(value(prop::SAVED)?))
        .transpose()?;
    let queued_frames = has(cap::HOST_RX_QUEUE)
        .then(|| decode_u16(value(prop::HOST_RX_QUEUE_COUNT)?))
        .transpose()?;
    let dropped_frames = has(cap::HOST_RX_QUEUE)
        .then(|| decode_u32(value(prop::HOST_RX_QUEUE_DROPPED)?))
        .transpose()?;
    let filter_count = has(cap::HOST_FILTER)
        .then(|| decode_filter_count(value(prop::HOST_RX_FILTERS)?))
        .transpose()?;
    let host_channel_count = has(cap::HOST_KEYS)
        .then(|| decode_fixed_count::<{ items::CHANNEL_ID_LEN }>(value(prop::HOST_CHANNEL_KEYS)?))
        .transpose()?;
    let host_peer_count = has(cap::HOST_KEYS)
        .then(|| decode_fixed_count::<{ items::PUBLIC_KEY_LEN }>(value(prop::HOST_PEER_KEYS)?))
        .transpose()?;
    let auto_ack = has(cap::HOST_AUTO_ACK)
        .then(|| decode_bool(value(prop::HOST_AUTO_ACK)?))
        .transpose()?;

    Ok(CompanionSyncRecord {
        capability_count: capabilities
            .len()
            .try_into()
            .map_err(|_| MobileError::InvalidCompanionFrame)?,
        has_host_filtering: has(cap::HOST_FILTER),
        supports_offline_queue: has(cap::HOST_RX_QUEUE),
        supports_delegated_ack: has(cap::HOST_AUTO_ACK),
        phy_enabled,
        frequency_khz,
        saved,
        queued_frames,
        dropped_frames,
        filter_count,
        host_channel_count,
        host_peer_count,
        auto_ack,
    })
}

fn property_value(
    responses: &[CompanionPropertyFrameRecord],
    key: u32,
) -> Result<&[u8], MobileError> {
    let mut matching = responses
        .iter()
        .filter(|response| response.property_id == key);
    let response = matching.next().ok_or(MobileError::InvalidCompanionFrame)?;
    if matching.next().is_some() || response.command != Cmd::PropIs as u8 {
        return Err(MobileError::InvalidCompanionFrame);
    }
    Ok(&response.value)
}

fn decode_capabilities(value: &[u8]) -> Result<Vec<u32>, MobileError> {
    let mut capabilities = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (capability, used) =
            pui::decode(rest).map_err(|_| MobileError::InvalidCompanionFrame)?;
        if capabilities.contains(&capability) {
            return Err(MobileError::InvalidCompanionFrame);
        }
        capabilities.push(capability);
        rest = &rest[used..];
    }
    Ok(capabilities)
}

fn validate_capability_dependencies(capabilities: &[u32]) -> Result<(), MobileError> {
    let has = |capability| capabilities.contains(&capability);
    if has(cap::HOST_RX_QUEUE) && !has(cap::HOST_FILTER)
        || has(cap::HOST_KEYS) && !has(cap::HOST_FILTER)
        || has(cap::HOST_AUTO_ACK) && (!has(cap::HOST_KEYS) || !has(cap::HOST_RX_QUEUE))
    {
        return Err(MobileError::InvalidCompanionFrame);
    }
    Ok(())
}

fn decode_exact_pui(value: &[u8]) -> Result<u32, MobileError> {
    let (decoded, used) = pui::decode(value).map_err(|_| MobileError::InvalidCompanionFrame)?;
    (used == value.len())
        .then_some(decoded)
        .ok_or(MobileError::InvalidCompanionFrame)
}

fn decode_bool(value: &[u8]) -> Result<bool, MobileError> {
    match value {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(MobileError::InvalidCompanionFrame),
    }
}

fn decode_u16(value: &[u8]) -> Result<u16, MobileError> {
    value
        .try_into()
        .map(u16::from_le_bytes)
        .map_err(|_| MobileError::InvalidCompanionFrame)
}

fn decode_u32(value: &[u8]) -> Result<u32, MobileError> {
    value
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| MobileError::InvalidCompanionFrame)
}

fn decode_fixed_count<const N: usize>(value: &[u8]) -> Result<u32, MobileError> {
    let count = items::fixed_items::<N>(value)
        .map_err(|_| MobileError::InvalidCompanionFrame)?
        .count();
    count
        .try_into()
        .map_err(|_| MobileError::InvalidCompanionFrame)
}

fn decode_filter_count(value: &[u8]) -> Result<u32, MobileError> {
    let mut count = 0u32;
    for item in items::prefixed_items(value) {
        let item = item.map_err(|_| MobileError::InvalidCompanionFrame)?;
        Filter::decode(item).map_err(|_| MobileError::InvalidCompanionFrame)?;
        count = count
            .checked_add(1)
            .ok_or(MobileError::InvalidCompanionFrame)?;
    }
    Ok(count)
}

/// Split a companion frame into ATT values using the negotiated maximum write
/// length. The returned values include the one-octet SAR header.
#[uniffi::export]
pub fn companion_gatt_segments(
    frame: Vec<u8>,
    maximum_value_length: u16,
) -> Result<Vec<GattSegmentRecord>, MobileError> {
    let segment_payload = usize::from(maximum_value_length)
        .checked_sub(1)
        .filter(|length| *length > 0)
        .ok_or(MobileError::InvalidGattSegment)?;
    if frame.len() > MAX_FRAME {
        return Err(MobileError::InvalidCompanionFrame);
    }

    Ok(gatt::segments(&frame, segment_payload)
        .map(|segment| {
            let mut value = vec![0; segment.payload().len() + 1];
            let length = segment
                .write_to(&mut value)
                .expect("sized from the segment payload");
            value.truncate(length);
            GattSegmentRecord { value }
        })
        .collect())
}

/// Encode a `CMD_PROP_GET` request with the shared companion protocol codec.
#[uniffi::export]
pub fn companion_prop_get(transaction_id: u8, property_id: u32) -> Result<Vec<u8>, MobileError> {
    let mut output = [0; 8];
    let length = frame::prop_get(&mut output, transaction_id, property_id)
        .map_err(|_| MobileError::InvalidCompanionFrame)?;
    Ok(output[..length].to_vec())
}

/// Encode a `CMD_PROP_SET` request with the shared companion protocol codec.
#[uniffi::export]
pub fn companion_prop_set(
    transaction_id: u8,
    property_id: u32,
    value: Vec<u8>,
) -> Result<Vec<u8>, MobileError> {
    if value.len() > MAX_FRAME {
        return Err(MobileError::InvalidCompanionFrame);
    }
    let mut output = vec![0; MAX_FRAME];
    let length = frame::prop_set(&mut output, transaction_id, property_id, &value)
        .map_err(|_| MobileError::InvalidCompanionFrame)?;
    output.truncate(length);
    Ok(output)
}

/// Encode a `CMD_SAVE` request with the shared companion protocol codec.
#[uniffi::export]
pub fn companion_save(transaction_id: u8) -> Result<Vec<u8>, MobileError> {
    let mut output = [0; 2];
    let length =
        frame::save(&mut output, transaction_id).map_err(|_| MobileError::InvalidCompanionFrame)?;
    Ok(output[..length].to_vec())
}

/// Decode an exact packed status value from `PROP_LAST_STATUS`.
#[uniffi::export]
pub fn inspect_companion_status(value: Vec<u8>) -> Result<u32, MobileError> {
    decode_exact_pui(&value)
}

/// Parse and validate a property notification or response.
#[uniffi::export]
pub fn inspect_companion_property_frame(
    bytes: Vec<u8>,
) -> Result<CompanionPropertyFrameRecord, MobileError> {
    let parsed = Frame::parse(&bytes).map_err(|_| MobileError::InvalidCompanionFrame)?;
    if !matches!(
        parsed.command(),
        Some(Cmd::PropIs | Cmd::PropInserted | Cmd::PropRemoved)
    ) {
        return Err(MobileError::InvalidCompanionFrame);
    }
    let payload =
        PropPayload::parse(parsed.payload).map_err(|_| MobileError::InvalidCompanionFrame)?;
    Ok(CompanionPropertyFrameRecord {
        transaction_id: parsed.header.tid(),
        command: parsed.cmd,
        property_id: payload.key,
        value: payload.value.to_vec(),
    })
}

/// Validate and reduce a `PROP_BATTERY` value to fields used by mobile UI.
#[uniffi::export]
pub fn inspect_companion_battery(value: Vec<u8>) -> Result<CompanionBatteryRecord, MobileError> {
    let battery = BatteryStatus::decode(&value).map_err(|_| MobileError::InvalidCompanionFrame)?;
    Ok(CompanionBatteryRecord {
        percentage: battery.level_percent,
        is_externally_powered: battery.charge_state.map(|state| {
            matches!(
                state,
                BatteryChargeState::Charging | BatteryChargeState::Charged
            )
        }),
    })
}

/// Stateful, bounded receiver for Frame Out notifications.
#[derive(uniffi::Object)]
pub struct MobileGattReassembler {
    inner: Mutex<Reassembler<MAX_FRAME>>,
}

#[uniffi::export]
impl MobileGattReassembler {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Reassembler::new()),
        })
    }

    /// Consume one ATT value, returning a complete companion frame when the
    /// segment ends one. Invalid input resets the shared reassembly state.
    pub fn push(&self, segment: Vec<u8>) -> Result<Option<Vec<u8>>, MobileError> {
        let mut reassembler = self.inner.lock().expect("GATT reassembler mutex poisoned");
        match reassembler.push(&segment) {
            None => Ok(None),
            Some(Ok(frame)) => Ok(Some(frame.to_vec())),
            Some(Err(_)) => Err(MobileError::InvalidGattSegment),
        }
    }

    pub fn reset(&self) {
        self.inner
            .lock()
            .expect("GATT reassembler mutex poisoned")
            .reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(property_id: u32, value: &[u8]) -> CompanionPropertyFrameRecord {
        CompanionPropertyFrameRecord {
            transaction_id: 1,
            command: Cmd::PropIs as u8,
            property_id,
            value: value.to_vec(),
        }
    }

    fn property_request(bytes: &[u8]) -> (u8, u32) {
        let parsed = Frame::parse(bytes).unwrap();
        assert_eq!(parsed.command(), Some(Cmd::PropGet));
        let (property, used) = pui::decode(parsed.payload).unwrap();
        assert_eq!(used, parsed.payload.len());
        (parsed.header.tid(), property)
    }

    fn property_response(tid: u8, property: u32, value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; MAX_FRAME];
        let length = frame::prop_is(&mut bytes, tid, property, value).unwrap();
        bytes.truncate(length);
        bytes
    }

    fn answer_requests(
        session: &MobileCompanionSession,
        requests: Vec<Vec<u8>>,
        value: impl Fn(u32) -> (u32, Vec<u8>),
    ) -> CompanionSessionUpdateRecord {
        let mut last = None;
        for request in requests {
            let (tid, requested) = property_request(&request);
            let (returned, bytes) = value(requested);
            last = Some(
                session
                    .consume(property_response(tid, returned, &bytes))
                    .unwrap(),
            );
        }
        last.unwrap()
    }

    #[test]
    fn exported_gatt_round_trip_uses_shared_codec() {
        let frame = companion_prop_get(3, 4_864).unwrap();
        let segments = companion_gatt_segments(frame.clone(), 4).unwrap();
        let receiver = MobileGattReassembler::new();
        let mut completed = None;
        for segment in segments {
            if let Some(value) = receiver.push(segment.value).unwrap() {
                completed = Some(value);
            }
        }
        assert_eq!(completed, Some(frame));
    }

    #[test]
    fn property_response_is_validated_and_typed() {
        let mut bytes = [0; 16];
        let length = frame::prop_is(&mut bytes, 5, 64, &[1, 2, 3]).unwrap();
        assert_eq!(
            inspect_companion_property_frame(bytes[..length].to_vec()).unwrap(),
            CompanionPropertyFrameRecord {
                transaction_id: 5,
                command: Cmd::PropIs as u8,
                property_id: 64,
                value: vec![1, 2, 3],
            }
        );
    }

    #[test]
    fn property_set_uses_shared_frame_codec() {
        let encoded = companion_prop_set(6, 96, vec![7; 32]).unwrap();
        let parsed = Frame::parse(&encoded).unwrap();
        assert_eq!(parsed.header.tid(), 6);
        assert_eq!(parsed.command(), Some(Cmd::PropSet));
        let payload = PropPayload::parse(parsed.payload).unwrap();
        assert_eq!(payload.key, 96);
        assert_eq!(payload.value, &[7; 32]);
    }

    #[test]
    fn save_and_status_use_shared_frame_codec() {
        let encoded = companion_save(7).unwrap();
        let parsed = Frame::parse(&encoded).unwrap();
        assert_eq!(parsed.header.tid(), 7);
        assert_eq!(parsed.command(), Some(Cmd::Save));
        assert!(parsed.payload.is_empty());

        assert_eq!(inspect_companion_status(vec![0]).unwrap(), 0);
        assert_eq!(
            inspect_companion_status(vec![0x80]),
            Err(MobileError::InvalidCompanionFrame)
        );
    }

    #[test]
    fn exported_transport_rejects_invalid_bounds_and_segments() {
        assert_eq!(
            companion_gatt_segments(vec![0; MAX_FRAME + 1], 20),
            Err(MobileError::InvalidCompanionFrame)
        );
        assert_eq!(
            companion_gatt_segments(vec![1], 1),
            Err(MobileError::InvalidGattSegment)
        );
        assert_eq!(
            MobileGattReassembler::new().push(vec![]),
            Err(MobileError::InvalidGattSegment)
        );
    }

    #[test]
    fn battery_reduction_preserves_supported_ui_fields() {
        assert_eq!(
            inspect_companion_battery(vec![0b110, 82, 1]).unwrap(),
            CompanionBatteryRecord {
                percentage: Some(82),
                is_externally_powered: Some(true),
            }
        );
        assert_eq!(
            inspect_companion_battery(vec![]).unwrap(),
            CompanionBatteryRecord {
                percentage: None,
                is_externally_powered: None,
            }
        );
    }

    #[test]
    fn minimal_inspection_is_small_and_validated() {
        assert_eq!(
            companion_inspection_properties(vec![cap::WRITABLE_RAW_STREAM as u8]).unwrap(),
            [prop::INTERFACE_TYPE, prop::PHY_ENABLED, prop::PHY_FREQ]
        );
        let sync = inspect_companion_sync(vec![
            response(prop::CAPS, &[cap::WRITABLE_RAW_STREAM as u8]),
            response(prop::INTERFACE_TYPE, &[INTERFACE_TYPE as u8]),
            response(prop::PHY_ENABLED, &[1]),
            response(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
        ])
        .unwrap();
        assert!(sync.phy_enabled);
        assert_eq!(sync.frequency_khz, 915_000);
        assert!(!sync.has_host_filtering);
        assert_eq!(sync.queued_frames, None);
    }

    #[test]
    fn full_inspection_reports_only_digest_counts() {
        let capabilities = (cap::HOST_FILTER..=cap::BATTERY)
            .map(|capability| capability as u8)
            .collect::<Vec<_>>();
        let properties = companion_inspection_properties(capabilities.clone()).unwrap();
        assert!(properties.contains(&prop::HOST_RX_FILTERS));
        assert!(properties.contains(&prop::HOST_RX_QUEUE_COUNT));
        assert!(properties.contains(&prop::HOST_AUTO_ACK));

        let sync = inspect_companion_sync(vec![
            response(prop::CAPS, &capabilities),
            response(prop::INTERFACE_TYPE, &[INTERFACE_TYPE as u8]),
            response(prop::PHY_ENABLED, &[1]),
            response(prop::PHY_FREQ, &868_100u32.to_le_bytes()),
            response(prop::SAVED, &[1]),
            response(prop::HOST_RX_FILTERS, &[]),
            response(prop::HOST_CHANNEL_KEYS, &[1, 2, 3, 4]),
            response(prop::HOST_PEER_KEYS, &[7; 32]),
            response(prop::HOST_RX_QUEUE_COUNT, &3u16.to_le_bytes()),
            response(prop::HOST_RX_QUEUE_DROPPED, &4u32.to_le_bytes()),
            response(prop::HOST_AUTO_ACK, &[1]),
        ])
        .unwrap();
        assert_eq!(sync.saved, Some(true));
        assert_eq!(sync.queued_frames, Some(3));
        assert_eq!(sync.dropped_frames, Some(4));
        assert_eq!(sync.filter_count, Some(0));
        assert_eq!(sync.host_channel_count, Some(2));
        assert_eq!(sync.host_peer_count, Some(1));
        assert_eq!(sync.auto_ack, Some(true));
    }

    #[test]
    fn invalid_capability_dependencies_and_values_fail_closed() {
        assert_eq!(
            companion_inspection_properties(vec![cap::HOST_RX_QUEUE as u8]),
            Err(MobileError::InvalidCompanionFrame)
        );
        assert_eq!(
            inspect_companion_sync(vec![
                response(prop::CAPS, &[]),
                response(prop::INTERFACE_TYPE, &[7]),
                response(prop::PHY_ENABLED, &[1]),
                response(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
            ]),
            Err(MobileError::InvalidCompanionFrame)
        );
    }

    #[test]
    fn mobile_session_owns_sync_tids_and_attaches_transparent_radio() {
        let session = MobileCompanionSession::new();
        let begin = session.begin(Some(vec![0xAA; 32])).unwrap();
        assert_eq!(begin.snapshot.phase, CompanionSessionPhase::Synchronizing);
        assert_eq!(begin.outbound_frames.len(), 7);
        assert_eq!(
            begin
                .outbound_frames
                .iter()
                .map(|request| property_request(request).0)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6, 7]
        );

        let inspection =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (property, vec![cap::WRITABLE_RAW_STREAM as u8]),
                prop::DEV_KEY => (property, Vec::new()),
                prop::DEV_NAME => (property, b"Transparent".to_vec()),
                prop::BATTERY => (property, Vec::new()),
                prop::HOST_KEY => (prop::LAST_STATUS, vec![2]),
                _ => unreachable!(),
            });
        assert_eq!(inspection.outbound_frames.len(), 3);
        assert_eq!(
            inspection.snapshot.host_ownership,
            CompanionHostOwnership::Unsupported
        );

        let attached =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 915_000u32.to_le_bytes().to_vec()),
                    _ => unreachable!(),
                },
            );
        assert_eq!(attached.snapshot.phase, CompanionSessionPhase::Attached);
        assert_eq!(
            attached.snapshot.device_name.as_deref(),
            Some("Transparent")
        );
        assert_eq!(
            attached.snapshot.provisioning.unwrap().frequency_khz,
            915_000
        );
    }

    #[test]
    fn mobile_session_owns_claim_then_save_choreography() {
        let host_key = vec![0xAA; 32];
        let session = MobileCompanionSession::new();
        let begin = session.begin(Some(host_key.clone())).unwrap();
        let awaiting =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (property, vec![cap::HOST_FILTER as u8, cap::SAVE as u8]),
                prop::DEV_KEY | prop::DEV_NAME | prop::BATTERY | prop::HOST_KEY => {
                    (property, Vec::new())
                }
                _ => unreachable!(),
            });
        assert_eq!(awaiting.snapshot.phase, CompanionSessionPhase::AwaitingHost);
        assert_eq!(
            awaiting.snapshot.host_ownership,
            CompanionHostOwnership::Unclaimed
        );

        let claim = session.claim(host_key.clone()).unwrap();
        assert_eq!(claim.snapshot.phase, CompanionSessionPhase::Claiming);
        assert_eq!(claim.outbound_frames.len(), 1);
        let parsed_claim = Frame::parse(&claim.outbound_frames[0]).unwrap();
        assert_eq!(parsed_claim.command(), Some(Cmd::PropSet));
        let payload = PropPayload::parse(parsed_claim.payload).unwrap();
        assert_eq!(payload.key, prop::HOST_KEY);
        assert_eq!(payload.value, host_key);

        let save = session
            .consume(property_response(
                parsed_claim.header.tid(),
                prop::HOST_KEY,
                &host_key,
            ))
            .unwrap();
        assert_eq!(save.outbound_frames.len(), 1);
        let parsed_save = Frame::parse(&save.outbound_frames[0]).unwrap();
        assert_eq!(parsed_save.command(), Some(Cmd::Save));

        let inspection = session
            .consume(property_response(
                parsed_save.header.tid(),
                prop::LAST_STATUS,
                &[0],
            ))
            .unwrap();
        assert_eq!(inspection.outbound_frames.len(), 5);
        let attached =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 868_100u32.to_le_bytes().to_vec()),
                    prop::SAVED => (property, vec![1]),
                    prop::HOST_RX_FILTERS => (property, Vec::new()),
                    _ => unreachable!(),
                },
            );
        assert_eq!(attached.snapshot.phase, CompanionSessionPhase::Attached);
        assert_eq!(
            attached.snapshot.host_ownership,
            CompanionHostOwnership::Ours
        );
        assert_eq!(attached.snapshot.provisioning.unwrap().saved, Some(true));

        let changed_host = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::HOST_KEY,
                &[0xBB; 32],
            ))
            .unwrap();
        assert_eq!(
            changed_host.snapshot.phase,
            CompanionSessionPhase::AwaitingHost
        );
        assert_eq!(
            changed_host.snapshot.host_ownership,
            CompanionHostOwnership::OtherHost
        );
    }

    #[test]
    fn mobile_session_rejects_mismatched_transaction_response() {
        let session = MobileCompanionSession::new();
        let begin = session.begin(None).unwrap();
        let (tid, _) = property_request(&begin.outbound_frames[0]);
        assert_eq!(
            session.consume(property_response(tid, prop::PHY_FREQ, &[0; 4])),
            Err(MobileError::InvalidCompanionFrame)
        );
    }
}
