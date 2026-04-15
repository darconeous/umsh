use alloc::string::String;
use alloc::vec::Vec;

use umsh_core::PublicKey;

use crate::{Capabilities, MacCommand, NodeIdentityPayload, NodeRole};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedNodeIdentityPayload {
    pub timestamp: u32,
    pub role: NodeRole,
    pub capabilities: Capabilities,
    pub name: Option<String>,
    pub options: Option<Vec<u8>>,
    pub signature: Option<[u8; 64]>,
}

impl OwnedNodeIdentityPayload {
    pub fn as_borrowed(&self) -> NodeIdentityPayload<'_> {
        NodeIdentityPayload {
            timestamp: self.timestamp,
            role: self.role,
            capabilities: self.capabilities,
            name: self.name.as_deref(),
            options: self.options.as_deref(),
            signature: self.signature.as_ref(),
        }
    }
}

impl From<NodeIdentityPayload<'_>> for OwnedNodeIdentityPayload {
    fn from(value: NodeIdentityPayload<'_>) -> Self {
        Self {
            timestamp: value.timestamp,
            role: value.role,
            capabilities: value.capabilities,
            name: value.name.map(String::from),
            options: value.options.map(Vec::from),
            signature: value.signature.copied(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnedMacCommand {
    BeaconRequest {
        nonce: Option<u32>,
    },
    IdentityRequest,
    SignalReportRequest,
    SignalReportResponse {
        rssi: u8,
        snr: i8,
    },
    EchoRequest {
        data: Vec<u8>,
    },
    EchoResponse {
        data: Vec<u8>,
    },
    PfsSessionRequest {
        ephemeral_key: PublicKey,
        duration_minutes: u16,
    },
    PfsSessionResponse {
        ephemeral_key: PublicKey,
        duration_minutes: u16,
    },
    EndPfsSession,
}

impl From<MacCommand<'_>> for OwnedMacCommand {
    fn from(value: MacCommand<'_>) -> Self {
        match value {
            MacCommand::BeaconRequest { nonce } => Self::BeaconRequest { nonce },
            MacCommand::IdentityRequest => Self::IdentityRequest,
            MacCommand::SignalReportRequest => Self::SignalReportRequest,
            MacCommand::SignalReportResponse { rssi, snr } => {
                Self::SignalReportResponse { rssi, snr }
            }
            MacCommand::EchoRequest { data } => Self::EchoRequest {
                data: Vec::from(data),
            },
            MacCommand::EchoResponse { data } => Self::EchoResponse {
                data: Vec::from(data),
            },
            MacCommand::PfsSessionRequest {
                ephemeral_key,
                duration_minutes,
            } => Self::PfsSessionRequest {
                ephemeral_key,
                duration_minutes,
            },
            MacCommand::PfsSessionResponse {
                ephemeral_key,
                duration_minutes,
            } => Self::PfsSessionResponse {
                ephemeral_key,
                duration_minutes,
            },
            MacCommand::EndPfsSession => Self::EndPfsSession,
        }
    }
}
