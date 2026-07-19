use std::sync::{Arc, Mutex};

use umsh_companion::{
    BatteryChargeState, BatteryStatus, Cmd, Frame, PropPayload, frame,
    gatt::{self, MAX_FRAME, Reassembler},
    ids::{INTERFACE_TYPE, cap, prop},
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
}
