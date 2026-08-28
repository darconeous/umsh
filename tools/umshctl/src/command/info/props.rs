//! A bag of property values, and the reading of one.
//!
//! Everything `info` prints comes from a set of properties fetched
//! together. Once fetched, a renderer works against this rather than
//! against a device handle, which is what makes the renderers testable
//! without a radio and what keeps the round trips in one place.

use std::collections::HashMap;

use umsh::ulcp::{FrameLink, UlcpDevice};
use umsh::ulcp_wire::Status;
use umsh::ulcp_wire::ids::cap;

/// Properties fetched together, each either answered or refused.
///
/// A refusal is an answer: an OPTIONAL property a device does not
/// implement refuses the read, and over the mesh the unreachable half of
/// the property space refuses every position. Both mean "absent", which
/// is why the accessors collapse them.
///
/// An *empty* value is not absent. Several properties spell "no fix",
/// "no threshold", or "never tag" as zero octets, so [`Self::bytes`]
/// hands back an empty slice rather than `None` when the device answered
/// with one.
#[derive(Debug, Default)]
pub struct PropSet {
    values: HashMap<u32, Result<Vec<u8>, Status>>,
}

impl PropSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: u32, answer: Result<Vec<u8>, Status>) {
        self.values.insert(key, answer);
    }

    /// Whether the device answered this property at all.
    pub fn answered(&self, key: u32) -> bool {
        matches!(self.values.get(&key), Some(Ok(_)))
    }

    /// The octets the device answered with, if it answered.
    pub fn bytes(&self, key: u32) -> Option<&[u8]> {
        match self.values.get(&key) {
            Some(Ok(value)) => Some(value),
            _ => None,
        }
    }

    /// The octets, treating an empty answer as no answer.
    ///
    /// For the properties where empty is the device saying it has
    /// nothing rather than saying zero.
    pub fn non_empty(&self, key: u32) -> Option<&[u8]> {
        self.bytes(key).filter(|value| !value.is_empty())
    }

    /// The status a refused property came back with.
    pub fn refusal(&self, key: u32) -> Option<Status> {
        match self.values.get(&key) {
            Some(Err(status)) => Some(*status),
            _ => None,
        }
    }

    pub fn bool(&self, key: u32) -> Option<bool> {
        self.bytes(key)?.first().map(|&byte| byte != 0)
    }

    pub fn u8(&self, key: u32) -> Option<u8> {
        self.bytes(key)?.first().copied()
    }

    pub fn i8(&self, key: u32) -> Option<i8> {
        self.u8(key).map(|byte| byte as i8)
    }

    pub fn u16(&self, key: u32) -> Option<u16> {
        <[u8; 2]>::try_from(self.bytes(key)?)
            .ok()
            .map(u16::from_le_bytes)
    }

    pub fn i16(&self, key: u32) -> Option<i16> {
        <[u8; 2]>::try_from(self.bytes(key)?)
            .ok()
            .map(i16::from_le_bytes)
    }

    pub fn u32(&self, key: u32) -> Option<u32> {
        <[u8; 4]>::try_from(self.bytes(key)?)
            .ok()
            .map(u32::from_le_bytes)
    }

    pub fn i32(&self, key: u32) -> Option<i32> {
        <[u8; 4]>::try_from(self.bytes(key)?)
            .ok()
            .map(i32::from_le_bytes)
    }

    /// A STRING property, without the NUL the wire carries.
    pub fn text(&self, key: u32) -> Option<String> {
        let value = self.bytes(key)?;
        Some(
            String::from_utf8_lossy(value)
                .trim_end_matches('\0')
                .to_owned(),
        )
    }

    pub fn key32(&self, key: u32) -> Option<[u8; 32]> {
        <[u8; 32]>::try_from(self.bytes(key)?).ok()
    }
}

/// Read `keys` in as few exchanges as the device allows.
///
/// One `CMD_PROP_MULTI_GET`, continued where a reply ran out of room.
/// A device without `CAP_CMD_MULTI` never learned the command, so it
/// gets the same questions one at a time — the report is identical
/// either way, and only the cost differs.
///
/// A key the device refuses lands in the set as a refusal rather than
/// ending the read: assembling a report is exactly the case where one
/// unimplemented property must not cost the other eleven.
pub async fn fetch<L: FrameLink>(
    device: &mut UlcpDevice<L>,
    keys: &[u32],
    batched: bool,
) -> anyhow::Result<PropSet> {
    let mut set = PropSet::new();
    if keys.is_empty() {
        return Ok(set);
    }
    if batched {
        let answers = device.read_each(keys).await?;
        for (&key, answer) in keys.iter().zip(answers) {
            set.insert(key, answer);
        }
        return Ok(set);
    }
    for &key in keys {
        let answer = match device.get_prop(key).await {
            Ok(value) => Ok(value),
            // A device that refused says which way; a link that failed
            // has ended the conversation, and pressing on with eleven
            // more questions it cannot hear helps nobody.
            Err(umsh::ulcp::UlcpError::Status(status)) => Err(status),
            Err(error) => return Err(error.into()),
        };
        set.insert(key, answer);
    }
    Ok(set)
}

/// Whether this device serves the multi-property commands.
pub fn batched(caps: &[u32]) -> bool {
    caps.contains(&cap::CMD_MULTI)
}
