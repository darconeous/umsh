use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use umsh_companion::{
    BatteryChargeState, BatteryStatus, Cmd, Frame, StreamPayload, frame,
    gatt::{self, MAX_FRAME, Reassembler},
    host::{PropertyNotification, PropertyNotificationKind, TidAllocator},
    ids::{INTERFACE_TYPE, PROTOCOL_MAJOR_VERSION, PROTOCOL_MINOR_VERSION, cap, prop},
    items::{self, Filter},
    meta::{BufferedRxMeta, RX_FLAG_ACKED, RX_FLAG_BUFFERED},
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
    pub supports_device_name: bool,
    pub supports_lora: bool,
    pub supports_duty_cycle_limit: bool,
    pub phy_enabled: bool,
    pub frequency_khz: u32,
    pub transmit_power_dbm: i8,
    pub bandwidth_hz: Option<u32>,
    pub spreading_factor: Option<u8>,
    pub coding_rate_denom: Option<u8>,
    pub duty_cycle_now: Option<u16>,
    pub duty_cycle_limit: Option<u16>,
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
    Configuring,
    Attached,
}

/// Complete desired live radio configuration. Capability-gated fields must be
/// omitted when the companion does not advertise their associated capability.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionRadioSettingsRecord {
    pub device_name: Option<String>,
    pub phy_enabled: bool,
    pub frequency_khz: u32,
    pub transmit_power_dbm: i8,
    pub bandwidth_hz: Option<u32>,
    pub spreading_factor: Option<u8>,
    pub coding_rate_denom: Option<u8>,
    pub duty_cycle_limit: Option<u16>,
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

/// What the platform adapter should do after a completed raw PHY request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CompanionRawTransmitDisposition {
    Sent,
    Retry,
    Rejected,
}

/// Typed completion of one host-requested raw PHY transmission.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionRawTransmitResultRecord {
    pub transaction_id: u8,
    pub status_code: u32,
    pub status_name: String,
    pub disposition: CompanionRawTransmitDisposition,
}

/// A correlated CRP operation completed with a non-OK `PROP_LAST_STATUS`.
/// This is an operation failure, never evidence that the transport framing is
/// corrupt or that the BLE connection should be closed.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionOperationErrorRecord {
    pub operation: String,
    pub status_code: u32,
    pub status_name: String,
}

/// Work produced by the Rust companion session. Frames are complete companion
/// frames; the platform adapter remains responsible for GATT segmentation and
/// write backpressure.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionSessionUpdateRecord {
    pub outbound_frames: Vec<Vec<u8>>,
    pub received_frames: Vec<CompanionReceivedFrameRecord>,
    pub snapshot: CompanionSessionSnapshotRecord,
    pub waiting_for_responses: bool,
    /// True while one host-requested raw PHY transmission is awaiting the
    /// radio's `PROP_LAST_STATUS` completion.
    pub raw_transmit_pending: bool,
    /// Transaction allocated by `transmit_raw` in this update, if any.
    pub raw_transmit_started_transaction_id: Option<u8>,
    /// Completion for the raw PHY transmission consumed by this update.
    /// Rejections are ordinary radio-level send failures, not malformed
    /// companion frames.
    pub raw_transmit_result: Option<CompanionRawTransmitResultRecord>,
    /// Non-transmit operation error consumed by this update. The companion
    /// session has already recovered to a stable stage and remains usable.
    pub operation_error: Option<CompanionOperationErrorRecord>,
}

/// One validated raw mesh frame delivered by the companion radio.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionReceivedFrameRecord {
    pub data: Vec<u8>,
    pub rssi_dbm: Option<i16>,
    pub lqi: Option<u8>,
    pub snr_cb: Option<i16>,
    pub was_buffered: bool,
    pub was_acknowledged: bool,
    pub age_seconds: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionStage {
    Idle,
    Initial,
    Inspection,
    Refreshing,
    Claiming,
    Saving,
    Configuring,
    SavingConfiguration,
    AwaitingHost,
    Attached,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExpectedResponse {
    Property(u32),
    Claim,
    Save,
    ConfigurationProperty(u32, Vec<u8>),
    SaveConfiguration,
    RawTransmit,
}

struct CompanionSessionState {
    generation: u64,
    stage: SessionStage,
    tids: TidAllocator,
    expected: HashMap<u8, ExpectedResponse>,
    selected_host_key: Option<[u8; 32]>,
    radio_host_key: Option<Vec<u8>>,
    host_key_unsupported: bool,
    responses: HashMap<u32, CompanionPropertyFrameRecord>,
    inspection_queue: VecDeque<u32>,
    configuration_queue: VecDeque<(u32, Vec<u8>)>,
    device_key: Option<Vec<u8>>,
    device_name: Option<String>,
    battery: Option<CompanionBatteryRecord>,
    provisioning: Option<CompanionSyncRecord>,
    stage_failure_pending: bool,
}

impl Default for CompanionSessionState {
    fn default() -> Self {
        Self {
            generation: 0,
            stage: SessionStage::Idle,
            tids: TidAllocator::new(),
            expected: HashMap::new(),
            selected_host_key: None,
            radio_host_key: None,
            host_key_unsupported: false,
            responses: HashMap::new(),
            inspection_queue: VecDeque::new(),
            configuration_queue: VecDeque::new(),
            device_key: None,
            device_name: None,
            battery: None,
            provisioning: None,
            stage_failure_pending: false,
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

    /// Apply, verify, and persist a complete radio-settings snapshot.
    pub fn configure(
        &self,
        settings: CompanionRadioSettingsRecord,
    ) -> Result<CompanionSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("companion session mutex poisoned");
        if state.stage != SessionStage::Attached {
            return Err(MobileError::InvalidCompanionFrame);
        }
        validate_radio_settings(&settings, &state)?;

        state.stage = SessionStage::Configuring;
        state.expected.clear();
        let mut values = Vec::new();
        // Disable before changing live PHY parameters, but enable only after
        // the complete new profile is in place.
        if !settings.phy_enabled {
            values.push((prop::PHY_ENABLED, vec![0]));
        }
        if let Some(name) = settings.device_name {
            values.push((prop::DEV_NAME, name.into_bytes()));
        }
        values.extend([
            (
                prop::PHY_FREQ,
                settings.frequency_khz.to_le_bytes().to_vec(),
            ),
            (prop::PHY_TX_POWER, vec![settings.transmit_power_dbm as u8]),
        ]);
        if let (Some(bandwidth), Some(sf), Some(cr)) = (
            settings.bandwidth_hz,
            settings.spreading_factor,
            settings.coding_rate_denom,
        ) {
            values.extend([
                (prop::PHY_LORA_BW, bandwidth.to_le_bytes().to_vec()),
                (prop::PHY_LORA_SF, vec![sf]),
                (prop::PHY_LORA_CR, vec![cr]),
            ]);
        }
        if let Some(limit) = settings.duty_cycle_limit {
            values.push((prop::PHY_DUTY_LIMIT, limit.to_le_bytes().to_vec()));
        }
        if settings.phy_enabled {
            values.push((prop::PHY_ENABLED, vec![1]));
        }

        state.configuration_queue = values.into();
        let mut outbound = Vec::new();
        state.start_configuration(&mut outbound)?;
        Ok(state.update(outbound))
    }

    /// Re-read every capability-gated property represented by the mobile
    /// snapshot. The existing snapshot remains usable while the bounded
    /// refresh is in flight; authoritative provisioning is published when
    /// the full capability-gated read completes.
    pub fn refresh(&self) -> Result<CompanionSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("companion session mutex poisoned");
        if state.stage != SessionStage::Attached || !state.expected.is_empty() {
            return Err(MobileError::InvalidCompanionFrame);
        }
        let capabilities = state
            .responses
            .get(&prop::CAPS)
            .ok_or(MobileError::InvalidCompanionFrame)?
            .value
            .clone();
        state.inspection_queue = companion_refresh_properties(capabilities)?.into();
        let mut outbound = Vec::new();
        state.start_refresh(&mut outbound)?;
        Ok(state.update(outbound))
    }

    /// Queue one complete raw UMSH frame on `STR_PHY_RAW`.
    ///
    /// The platform adapter supplies only opaque bytes from `MobileMeshSession`;
    /// Rust owns the companion command, stream identifier, metadata, TID, and
    /// confirmation matching.
    pub fn transmit_raw(&self, data: Vec<u8>) -> Result<CompanionSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("companion session mutex poisoned");
        let raw_pipeline_active = state
            .expected
            .values()
            .all(|expected| matches!(expected, ExpectedResponse::RawTransmit));
        if state.stage != SessionStage::Attached || !raw_pipeline_active || data.is_empty() {
            return Err(MobileError::InvalidCompanionFrame);
        }
        let mut available_tid = None;
        for _ in 0..usize::from(frame::TID_MAX) {
            let candidate = state.allocate_tid();
            if !state.expected.contains_key(&candidate) {
                available_tid = Some(candidate);
                break;
            }
        }
        let tid = available_tid.ok_or(MobileError::InvalidCompanionFrame)?;
        state.expected.insert(tid, ExpectedResponse::RawTransmit);
        let mut metadata = [0u8; umsh_companion::TxMeta::WIRE_LEN];
        umsh_companion::TxMeta::default()
            .encode(&mut metadata)
            .map_err(|_| MobileError::InvalidCompanionFrame)?;
        let mut frame = vec![0u8; data.len() + 16];
        let len = umsh_companion::frame::str_send(
            &mut frame,
            tid,
            umsh_companion::ids::stream::PHY_RAW,
            &data,
            &metadata,
        )
        .map_err(|_| MobileError::InvalidCompanionFrame)?;
        frame.truncate(len);
        let mut update = state.update(vec![frame]);
        update.raw_transmit_started_transaction_id = Some(tid);
        Ok(update)
    }

    /// Consume one complete companion frame and advance the session reducer.
    pub fn consume(&self, frame: Vec<u8>) -> Result<CompanionSessionUpdateRecord, MobileError> {
        let parsed = Frame::parse(&frame).map_err(|_| MobileError::InvalidCompanionFrame)?;
        if parsed.command() == Some(Cmd::StrRecv) {
            if parsed.header.tid() != frame::TID_UNSOLICITED {
                return Err(MobileError::InvalidCompanionFrame);
            }
            let payload = StreamPayload::parse(parsed.payload)
                .map_err(|_| MobileError::InvalidCompanionFrame)?;
            if payload.stream != umsh_companion::ids::stream::PHY_RAW {
                return Err(MobileError::InvalidCompanionFrame);
            }
            let metadata = BufferedRxMeta::decode(payload.metadata)
                .map_err(|_| MobileError::InvalidCompanionFrame)?;
            let state = self.inner.lock().expect("companion session mutex poisoned");
            if state.stage == SessionStage::Idle {
                return Err(MobileError::InvalidCompanionFrame);
            }
            return Ok(
                state.update_with_received(vec![CompanionReceivedFrameRecord {
                    data: payload.data.to_vec(),
                    rssi_dbm: metadata.rx.rssi_dbm,
                    lqi: metadata.rx.lqi.map(core::num::NonZeroU8::get),
                    snr_cb: metadata.rx.snr_cb,
                    was_buffered: metadata.flags & RX_FLAG_BUFFERED != 0,
                    was_acknowledged: metadata.flags & RX_FLAG_ACKED != 0,
                    age_seconds: metadata.age_s,
                }]),
            );
        }
        let response = inspect_companion_property_frame(frame)?;
        let mut state = self.inner.lock().expect("companion session mutex poisoned");
        let mut outbound = Vec::new();
        let mut raw_transmit_result = None;
        let mut operation_error = None;

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
                    operation_error = Some(companion_operation_error(
                        format!("read property {property}"),
                        response.value.as_slice(),
                    )?);
                    let optional_initial_property = state.stage == SessionStage::Initial
                        && matches!(
                            property,
                            prop::DEV_KEY | prop::DEV_NAME | prop::BATTERY | prop::HOST_KEY
                        );
                    state.stage_failure_pending |= !optional_initial_property;
                    if state.stage == SessionStage::Initial && property == prop::HOST_KEY {
                        state.host_key_unsupported = true;
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
                if response.property_id == prop::LAST_STATUS {
                    operation_error = Some(companion_operation_error(
                        "claim host identity".to_owned(),
                        response.value.as_slice(),
                    )?);
                    state.stage_failure_pending = true;
                } else {
                    if response.property_id != prop::HOST_KEY
                        || response.command != Cmd::PropIs as u8
                    {
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
            }
            ExpectedResponse::Save => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                if inspect_companion_status(response.value.clone())? != 0 {
                    operation_error = Some(companion_operation_error(
                        "save claimed host identity".to_owned(),
                        response.value.as_slice(),
                    )?);
                    state.stage_failure_pending = true;
                } else {
                    state.start_inspection(&mut outbound)?;
                }
            }
            ExpectedResponse::ConfigurationProperty(property, expected_value) => {
                if response.property_id == prop::LAST_STATUS {
                    operation_error = Some(companion_operation_error(
                        format!("set property {property}"),
                        response.value.as_slice(),
                    )?);
                    state.stage_failure_pending = true;
                } else if response.property_id != property
                    || response.command != Cmd::PropIs as u8
                    || response.value != expected_value
                {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                state.responses.insert(property, response.clone());
                state.apply_property(&response)?;
            }
            ExpectedResponse::SaveConfiguration => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                if inspect_companion_status(response.value.clone())? != 0 {
                    operation_error = Some(companion_operation_error(
                        "save radio configuration".to_owned(),
                        response.value.as_slice(),
                    )?);
                    state.stage_failure_pending = true;
                } else {
                    state.finish_configuration()?;
                }
            }
            ExpectedResponse::RawTransmit => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidCompanionFrame);
                }
                let status_code = inspect_companion_status(response.value)?;
                let status = umsh_companion::Status(status_code);
                raw_transmit_result = Some(CompanionRawTransmitResultRecord {
                    transaction_id: response.transaction_id,
                    status_code,
                    status_name: format!("{status:?}"),
                    disposition: if status == umsh_companion::Status::OK {
                        CompanionRawTransmitDisposition::Sent
                    } else if status == umsh_companion::Status::BUSY {
                        CompanionRawTransmitDisposition::Retry
                    } else {
                        CompanionRawTransmitDisposition::Rejected
                    },
                });
            }
        }

        if state.expected.is_empty() {
            if state.stage_failure_pending {
                state.stage_failure_pending = false;
                state.recover_from_operation_failure(&mut outbound)?;
            } else {
                state.advance_completed_stage(&mut outbound)?;
            }
        }
        Ok(state.update_with(outbound, Vec::new(), raw_transmit_result, operation_error))
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

    /// Abandon raw transactions whose GATT writes were rejected locally.
    /// Their late correlated responses are ignored once; the attachment and
    /// all non-raw session state remain intact.
    pub fn abandon_raw_transmits(&self, transaction_ids: Vec<u8>) -> CompanionSessionUpdateRecord {
        let mut state = self.inner.lock().expect("companion session mutex poisoned");
        for tid in transaction_ids {
            if matches!(
                state.expected.get(&tid),
                Some(ExpectedResponse::RawTransmit)
            ) {
                state.expected.remove(&tid);
            }
        }
        state.update(Vec::new())
    }
}

impl CompanionSessionState {
    fn allocate_tid(&mut self) -> u8 {
        self.tids.allocate()
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
            // A refresh deliberately preserves the attached phase so live UI
            // does not disappear while fresh authoritative values are read.
            SessionStage::Refreshing => CompanionSessionPhase::Attached,
            SessionStage::AwaitingHost => CompanionSessionPhase::AwaitingHost,
            SessionStage::Claiming => CompanionSessionPhase::Claiming,
            SessionStage::Configuring | SessionStage::SavingConfiguration => {
                CompanionSessionPhase::Configuring
            }
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
        self.update_with(outbound_frames, Vec::new(), None, None)
    }

    fn update_with_received(
        &self,
        received_frames: Vec<CompanionReceivedFrameRecord>,
    ) -> CompanionSessionUpdateRecord {
        self.update_with(Vec::new(), received_frames, None, None)
    }

    fn update_with(
        &self,
        outbound_frames: Vec<Vec<u8>>,
        received_frames: Vec<CompanionReceivedFrameRecord>,
        raw_transmit_result: Option<CompanionRawTransmitResultRecord>,
        operation_error: Option<CompanionOperationErrorRecord>,
    ) -> CompanionSessionUpdateRecord {
        let raw_transmit_pending = self
            .expected
            .values()
            .any(|expected| matches!(expected, ExpectedResponse::RawTransmit));
        CompanionSessionUpdateRecord {
            outbound_frames,
            received_frames,
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
            raw_transmit_pending,
            raw_transmit_started_transaction_id: None,
            raw_transmit_result,
            operation_error,
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
            SessionStage::Refreshing => self.start_refresh(outbound)?,
            SessionStage::Configuring => {
                if !self.configuration_queue.is_empty() {
                    self.start_configuration(outbound)?;
                } else if self.has_capability(cap::SAVE)? {
                    self.stage = SessionStage::SavingConfiguration;
                    let tid = self.allocate_tid();
                    self.expected
                        .insert(tid, ExpectedResponse::SaveConfiguration);
                    outbound.push(companion_save(tid)?);
                } else {
                    self.finish_configuration()?;
                }
            }
            SessionStage::Claiming
            | SessionStage::Saving
            | SessionStage::AwaitingHost
            | SessionStage::Attached
            | SessionStage::SavingConfiguration
            | SessionStage::Idle => {}
        }
        Ok(())
    }

    /// Abort only the failed operation stage. A correlated CRP status error
    /// never invalidates GATT framing and therefore never resets the session.
    fn recover_from_operation_failure(
        &mut self,
        outbound: &mut Vec<Vec<u8>>,
    ) -> Result<(), MobileError> {
        self.configuration_queue.clear();
        self.inspection_queue.clear();
        match self.stage {
            SessionStage::Claiming => self.stage = SessionStage::AwaitingHost,
            SessionStage::Saving => {
                // The host-key write succeeded even if persistence did not.
                // Continue attaching while reporting that SAVE failed.
                self.start_inspection(outbound)?;
            }
            SessionStage::Refreshing
            | SessionStage::Configuring
            | SessionStage::SavingConfiguration => {
                // Retain the last authoritative snapshot. Property echoes that
                // completed before the failed operation remain available for
                // the next explicit refresh.
                self.stage = SessionStage::Attached;
            }
            SessionStage::Inspection if self.provisioning.is_some() => {
                self.stage = SessionStage::Attached;
            }
            SessionStage::Initial | SessionStage::Inspection => {
                // The transport is healthy but the initial snapshot is not
                // trustworthy enough to attach. Stay connected and report the
                // operation error; reconnect/refresh may retry synchronization.
                self.stage = SessionStage::Initial;
            }
            SessionStage::Attached | SessionStage::AwaitingHost | SessionStage::Idle => {}
        }
        Ok(())
    }

    fn finish_configuration(&mut self) -> Result<(), MobileError> {
        let responses = self.responses.values().cloned().collect();
        self.provisioning = Some(inspect_companion_sync(responses)?);
        self.stage = SessionStage::Attached;
        Ok(())
    }

    fn start_configuration(&mut self, outbound: &mut Vec<Vec<u8>>) -> Result<(), MobileError> {
        self.stage = SessionStage::Configuring;
        for _ in 0..usize::from(frame::TID_MAX) {
            let Some((property, value)) = self.configuration_queue.pop_front() else {
                break;
            };
            let tid = self.allocate_tid();
            self.expected.insert(
                tid,
                ExpectedResponse::ConfigurationProperty(property, value.clone()),
            );
            outbound.push(companion_prop_set(tid, property, value)?);
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

    fn start_refresh(&mut self, outbound: &mut Vec<Vec<u8>>) -> Result<(), MobileError> {
        self.stage = SessionStage::Refreshing;
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

    let mut properties = vec![
        prop::INTERFACE_TYPE,
        prop::PHY_ENABLED,
        prop::PHY_FREQ,
        prop::PHY_TX_POWER,
    ];
    if has(cap::PHY_LORA) {
        properties.extend([prop::PHY_LORA_BW, prop::PHY_LORA_SF, prop::PHY_LORA_CR]);
    }
    if has(cap::PHY_DUTY_LIMIT) {
        properties.extend([prop::PHY_DUTY_NOW, prop::PHY_DUTY_LIMIT]);
    }
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

fn companion_refresh_properties(capabilities: Vec<u8>) -> Result<Vec<u32>, MobileError> {
    let decoded = decode_capabilities(&capabilities)?;
    validate_capability_dependencies(&decoded)?;
    let has = |capability| decoded.contains(&capability);
    let mut properties = Vec::new();
    if has(cap::DEV_IDENTITY) {
        properties.push(prop::DEV_KEY);
    }
    if has(cap::DEV_NAME) {
        properties.push(prop::DEV_NAME);
    }
    if has(cap::BATTERY) {
        properties.push(prop::BATTERY);
    }
    if has(cap::HOST_FILTER) {
        properties.push(prop::HOST_KEY);
    }
    properties.extend(companion_inspection_properties(capabilities)?);
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
    let transmit_power_dbm = decode_i8(value(prop::PHY_TX_POWER)?)?;
    let bandwidth_hz = has(cap::PHY_LORA)
        .then(|| decode_u32(value(prop::PHY_LORA_BW)?))
        .transpose()?;
    let spreading_factor = has(cap::PHY_LORA)
        .then(|| decode_u8(value(prop::PHY_LORA_SF)?))
        .transpose()?;
    let coding_rate_denom = has(cap::PHY_LORA)
        .then(|| decode_u8(value(prop::PHY_LORA_CR)?))
        .transpose()?;
    let duty_cycle_now = has(cap::PHY_DUTY_LIMIT)
        .then(|| decode_u16(value(prop::PHY_DUTY_NOW)?))
        .transpose()?;
    let duty_cycle_limit = has(cap::PHY_DUTY_LIMIT)
        .then(|| decode_u16(value(prop::PHY_DUTY_LIMIT)?))
        .transpose()?;
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
        supports_device_name: has(cap::DEV_NAME),
        supports_lora: has(cap::PHY_LORA),
        supports_duty_cycle_limit: has(cap::PHY_DUTY_LIMIT),
        phy_enabled,
        frequency_khz,
        transmit_power_dbm,
        bandwidth_hz,
        spreading_factor,
        coding_rate_denom,
        duty_cycle_now,
        duty_cycle_limit,
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

fn decode_u8(value: &[u8]) -> Result<u8, MobileError> {
    value
        .first()
        .copied()
        .filter(|_| value.len() == 1)
        .ok_or(MobileError::InvalidCompanionFrame)
}

fn decode_i8(value: &[u8]) -> Result<i8, MobileError> {
    decode_u8(value).map(|value| value as i8)
}

fn validate_radio_settings(
    settings: &CompanionRadioSettingsRecord,
    state: &CompanionSessionState,
) -> Result<(), MobileError> {
    if settings.frequency_khz == 0 {
        return Err(MobileError::InvalidCompanionFrame);
    }
    if let Some(name) = &settings.device_name {
        if !state.has_capability(cap::DEV_NAME)?
            || name.is_empty()
            || name.len() > 64
            || name.as_bytes().contains(&0)
        {
            return Err(MobileError::InvalidCompanionFrame);
        }
    }
    let lora = (
        settings.bandwidth_hz,
        settings.spreading_factor,
        settings.coding_rate_denom,
    );
    match lora {
        (None, None, None) if !state.has_capability(cap::PHY_LORA)? => {}
        (Some(bandwidth), Some(sf), Some(cr))
            if state.has_capability(cap::PHY_LORA)?
                && bandwidth > 0
                && (5..=12).contains(&sf)
                && (5..=8).contains(&cr) => {}
        _ => return Err(MobileError::InvalidCompanionFrame),
    }
    if settings.duty_cycle_limit.is_some() != state.has_capability(cap::PHY_DUTY_LIMIT)? {
        return Err(MobileError::InvalidCompanionFrame);
    }
    Ok(())
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

fn companion_operation_error(
    operation: String,
    value: &[u8],
) -> Result<CompanionOperationErrorRecord, MobileError> {
    let status_code = inspect_companion_status(value.to_vec())?;
    let status = umsh_companion::Status(status_code);
    if status == umsh_companion::Status::OK {
        // A property operation that promised an echoed value cannot silently
        // substitute status-only success. That is a real session violation,
        // not a reported operation error.
        return Err(MobileError::InvalidCompanionFrame);
    }
    Ok(CompanionOperationErrorRecord {
        operation,
        status_code,
        status_name: format!("{status:?}"),
    })
}

/// Parse and validate a property notification or response.
#[uniffi::export]
pub fn inspect_companion_property_frame(
    bytes: Vec<u8>,
) -> Result<CompanionPropertyFrameRecord, MobileError> {
    let parsed =
        PropertyNotification::parse(&bytes).map_err(|_| MobileError::InvalidCompanionFrame)?;
    let command = match parsed.kind {
        PropertyNotificationKind::Is => Cmd::PropIs,
        PropertyNotificationKind::Inserted => Cmd::PropInserted,
        PropertyNotificationKind::Removed => Cmd::PropRemoved,
    };
    Ok(CompanionPropertyFrameRecord {
        transaction_id: parsed.tid,
        command: command as u8,
        property_id: parsed.key,
        value: parsed.value.to_vec(),
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
    use umsh_companion::PropPayload;

    fn response(property_id: u32, value: &[u8]) -> CompanionPropertyFrameRecord {
        CompanionPropertyFrameRecord {
            transaction_id: 1,
            command: Cmd::PropIs as u8,
            property_id,
            value: value.to_vec(),
        }
    }

    fn encoded_capabilities(values: &[u32]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for value in values {
            let mut bytes = [0; pui::MAX_LEN];
            let len = pui::encode(*value, &mut bytes).unwrap();
            encoded.extend_from_slice(&bytes[..len]);
        }
        encoded
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
            [
                prop::INTERFACE_TYPE,
                prop::PHY_ENABLED,
                prop::PHY_FREQ,
                prop::PHY_TX_POWER,
            ]
        );
        let sync = inspect_companion_sync(vec![
            response(prop::CAPS, &[cap::WRITABLE_RAW_STREAM as u8]),
            response(prop::INTERFACE_TYPE, &[INTERFACE_TYPE as u8]),
            response(prop::PHY_ENABLED, &[1]),
            response(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
            response(prop::PHY_TX_POWER, &[14]),
        ])
        .unwrap();
        assert!(sync.phy_enabled);
        assert_eq!(sync.frequency_khz, 915_000);
        assert_eq!(sync.transmit_power_dbm, 14);
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
            response(prop::PHY_TX_POWER, &[22]),
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
        assert_eq!(inspection.outbound_frames.len(), 4);
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
                    prop::PHY_TX_POWER => (property, vec![14]),
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
        assert_eq!(inspection.outbound_frames.len(), 6);
        let attached =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 868_100u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![14]),
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

    #[test]
    fn mobile_session_emits_typed_raw_receive_during_sync() {
        let session = MobileCompanionSession::new();
        session.begin(None).unwrap();

        let metadata = BufferedRxMeta {
            rx: umsh_companion::RxMeta {
                rssi_dbm: Some(-87),
                lqi: core::num::NonZeroU8::new(42),
                snr_cb: Some(125),
            },
            flags: RX_FLAG_BUFFERED | RX_FLAG_ACKED,
            age_s: 9,
        };
        let mut metadata_bytes = [0; BufferedRxMeta::WIRE_LEN];
        metadata.encode(&mut metadata_bytes).unwrap();
        let mut bytes = vec![0; MAX_FRAME];
        let len = frame::str_recv(
            &mut bytes,
            umsh_companion::ids::stream::PHY_RAW,
            &[1, 2, 3],
            &metadata_bytes,
        )
        .unwrap();
        bytes.truncate(len);

        let update = session.consume(bytes).unwrap();
        assert_eq!(update.received_frames.len(), 1);
        assert_eq!(
            update.received_frames[0],
            CompanionReceivedFrameRecord {
                data: vec![1, 2, 3],
                rssi_dbm: Some(-87),
                lqi: Some(42),
                snr_cb: Some(125),
                was_buffered: true,
                was_acknowledged: true,
                age_seconds: 9,
            }
        );
        assert!(update.outbound_frames.is_empty());
        assert!(update.waiting_for_responses);
    }

    #[test]
    fn mobile_session_reports_raw_transmit_rejection_without_ending_session() {
        let session = MobileCompanionSession::new();
        let begin = session.begin(None).unwrap();
        let inspection =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (property, vec![cap::WRITABLE_RAW_STREAM as u8]),
                prop::DEV_KEY | prop::DEV_NAME | prop::BATTERY => (property, Vec::new()),
                prop::HOST_KEY => (prop::LAST_STATUS, vec![2]),
                _ => unreachable!(),
            });
        let attached =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 915_000u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![14]),
                    _ => unreachable!(),
                },
            );
        assert_eq!(attached.snapshot.phase, CompanionSessionPhase::Attached);

        let transmit = session.transmit_raw(vec![1, 2, 3]).unwrap();
        assert!(transmit.raw_transmit_pending);
        assert_eq!(transmit.raw_transmit_result, None);
        assert_eq!(transmit.outbound_frames.len(), 1);
        let second_transmit = session.transmit_raw(vec![4]).unwrap();
        assert_ne!(
            transmit.raw_transmit_started_transaction_id,
            second_transmit.raw_transmit_started_transaction_id
        );

        let request = Frame::parse(&transmit.outbound_frames[0]).unwrap();
        let rejected = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_companion::Status::INVALID_STATE.0 as u8],
            ))
            .unwrap();
        assert_eq!(rejected.snapshot.phase, CompanionSessionPhase::Attached);
        assert!(rejected.raw_transmit_pending);
        assert_eq!(
            rejected.raw_transmit_result,
            Some(CompanionRawTransmitResultRecord {
                transaction_id: request.header.tid(),
                status_code: umsh_companion::Status::INVALID_STATE.0,
                status_name: "Status::INVALID_STATE".into(),
                disposition: CompanionRawTransmitDisposition::Rejected,
            })
        );
        let second_request = Frame::parse(&second_transmit.outbound_frames[0]).unwrap();
        let completed = session
            .consume(property_response(
                second_request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_companion::Status::OK.0 as u8],
            ))
            .unwrap();
        assert!(!completed.raw_transmit_pending);

        // A radio-level rejection completes only that send; the attached
        // session remains usable for the next raw frame.
        let retryable = session.transmit_raw(vec![5]).unwrap();
        let request = Frame::parse(&retryable.outbound_frames[0]).unwrap();
        let busy = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_companion::Status::BUSY.0 as u8],
            ))
            .unwrap();
        assert_eq!(
            busy.raw_transmit_result.unwrap().disposition,
            CompanionRawTransmitDisposition::Retry
        );

        let abandoned = session.transmit_raw(vec![6]).unwrap();
        let abandoned_request = Frame::parse(&abandoned.outbound_frames[0]).unwrap();
        assert!(
            !session
                .abandon_raw_transmits(vec![abandoned_request.header.tid()])
                .raw_transmit_pending
        );

        // A status error for an ordinary property operation is also
        // nonfatal. Finish the rest of the bounded batch, recover to Attached,
        // and prove the same session can issue another raw transmission.
        let configured = session
            .configure(CompanionRadioSettingsRecord {
                device_name: None,
                phy_enabled: true,
                frequency_khz: 915_000,
                transmit_power_dbm: 14,
                bandwidth_hz: None,
                spreading_factor: None,
                coding_rate_denom: None,
                duty_cycle_limit: None,
            })
            .unwrap();
        let mut final_update = None;
        for (index, request) in configured.outbound_frames.into_iter().enumerate() {
            let parsed = Frame::parse(&request).unwrap();
            let payload = PropPayload::parse(parsed.payload).unwrap();
            let response = if index == 0 {
                property_response(
                    parsed.header.tid(),
                    prop::LAST_STATUS,
                    &[umsh_companion::Status::INVALID_ARGUMENT.0 as u8],
                )
            } else {
                property_response(parsed.header.tid(), payload.key, payload.value)
            };
            let update = session.consume(response).unwrap();
            if index == 0 {
                assert_eq!(
                    update.operation_error,
                    Some(CompanionOperationErrorRecord {
                        operation: format!("set property {}", payload.key),
                        status_code: umsh_companion::Status::INVALID_ARGUMENT.0,
                        status_name: "Status::INVALID_ARGUMENT".into(),
                    })
                );
            }
            final_update = Some(update);
        }
        assert_eq!(
            final_update.unwrap().snapshot.phase,
            CompanionSessionPhase::Attached
        );
        assert!(session.transmit_raw(vec![6]).is_ok());
    }

    #[test]
    fn mobile_session_verifies_radio_configuration_then_saves() {
        let session = MobileCompanionSession::new();
        let begin = session.begin(None).unwrap();
        let inspection =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (
                    property,
                    encoded_capabilities(&[
                        cap::SAVE,
                        cap::DEV_NAME,
                        cap::PHY_LORA,
                        cap::PHY_DUTY_LIMIT,
                    ]),
                ),
                prop::DEV_NAME => (property, b"Old name".to_vec()),
                prop::DEV_KEY | prop::BATTERY => (property, Vec::new()),
                prop::HOST_KEY => (prop::LAST_STATUS, vec![2]),
                _ => unreachable!(),
            });
        let partial =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 915_000u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![14]),
                    prop::PHY_LORA_BW => (property, 125_000u32.to_le_bytes().to_vec()),
                    prop::PHY_LORA_SF => (property, vec![9]),
                    prop::PHY_LORA_CR => (property, vec![5]),
                    _ => unreachable!(),
                },
            );
        let attached = answer_requests(
            &session,
            partial.outbound_frames,
            |property| match property {
                prop::PHY_DUTY_NOW => (property, 65u16.to_le_bytes().to_vec()),
                prop::PHY_DUTY_LIMIT => (property, 655u16.to_le_bytes().to_vec()),
                prop::SAVED => (property, vec![1]),
                _ => unreachable!(),
            },
        );
        assert_eq!(attached.snapshot.phase, CompanionSessionPhase::Attached);

        let configured = session
            .configure(CompanionRadioSettingsRecord {
                device_name: Some("Trail radio".into()),
                phy_enabled: true,
                frequency_khz: 868_100,
                transmit_power_dbm: 20,
                bandwidth_hz: Some(250_000),
                spreading_factor: Some(10),
                coding_rate_denom: Some(6),
                duty_cycle_limit: Some(6_553),
            })
            .unwrap();
        assert_eq!(
            configured.snapshot.phase,
            CompanionSessionPhase::Configuring
        );
        assert_eq!(
            configured.outbound_frames.len(),
            usize::from(frame::TID_MAX)
        );
        let mut pending = VecDeque::from(configured.outbound_frames);
        let mut configured_properties = Vec::new();
        let save_tid = loop {
            let request = pending.pop_front().unwrap();
            let parsed = Frame::parse(&request).unwrap();
            if parsed.command() == Some(Cmd::Save) {
                break parsed.header.tid();
            }
            assert_eq!(parsed.command(), Some(Cmd::PropSet));
            let payload = PropPayload::parse(parsed.payload).unwrap();
            configured_properties.push(payload.key);
            let update = session
                .consume(property_response(
                    parsed.header.tid(),
                    payload.key,
                    payload.value,
                ))
                .unwrap_or_else(|error| {
                    panic!(
                        "configuration response for property {} failed: {error:?}",
                        payload.key
                    )
                });
            pending.extend(update.outbound_frames);
        };
        assert_eq!(configured_properties.last(), Some(&prop::PHY_ENABLED));
        let attached = session
            .consume(property_response(save_tid, prop::LAST_STATUS, &[0]))
            .unwrap();
        assert_eq!(attached.snapshot.phase, CompanionSessionPhase::Attached);
        assert_eq!(
            attached.snapshot.device_name.as_deref(),
            Some("Trail radio")
        );
        let provisioning = attached.snapshot.provisioning.unwrap();
        assert_eq!(provisioning.frequency_khz, 868_100);
        assert_eq!(provisioning.transmit_power_dbm, 20);
        assert_eq!(provisioning.bandwidth_hz, Some(250_000));
        assert_eq!(provisioning.spreading_factor, Some(10));
        assert_eq!(provisioning.coding_rate_denom, Some(6));
        assert_eq!(provisioning.duty_cycle_now, Some(65));
        assert_eq!(provisioning.duty_cycle_limit, Some(6_553));

        let pushed = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::PHY_DUTY_NOW,
                &131u16.to_le_bytes(),
            ))
            .unwrap();
        assert_eq!(
            pushed.snapshot.provisioning.unwrap().duty_cycle_now,
            Some(131)
        );

        let refresh = session.refresh().unwrap();
        assert_eq!(refresh.snapshot.phase, CompanionSessionPhase::Attached);
        assert!(refresh.waiting_for_responses);
        let refresh_tail =
            answer_requests(
                &session,
                refresh.outbound_frames,
                |property| match property {
                    prop::DEV_NAME => (property, b"Fresh name".to_vec()),
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 910_525u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![18]),
                    prop::PHY_LORA_BW => (property, 62_500u32.to_le_bytes().to_vec()),
                    prop::PHY_LORA_SF => (property, vec![7]),
                    _ => unreachable!(),
                },
            );
        let refreshed =
            answer_requests(
                &session,
                refresh_tail.outbound_frames,
                |property| match property {
                    prop::PHY_LORA_CR => (property, vec![5]),
                    prop::PHY_DUTY_NOW => (property, 262u16.to_le_bytes().to_vec()),
                    prop::PHY_DUTY_LIMIT => (property, 655u16.to_le_bytes().to_vec()),
                    prop::SAVED => (property, vec![1]),
                    _ => unreachable!(),
                },
            );
        assert_eq!(refreshed.snapshot.phase, CompanionSessionPhase::Attached);
        assert!(!refreshed.waiting_for_responses);
        assert_eq!(
            refreshed.snapshot.device_name.as_deref(),
            Some("Fresh name")
        );
        let refreshed = refreshed.snapshot.provisioning.unwrap();
        assert_eq!(refreshed.frequency_khz, 910_525);
        assert_eq!(refreshed.duty_cycle_now, Some(262));
        assert_eq!(refreshed.duty_cycle_limit, Some(655));
    }
}
