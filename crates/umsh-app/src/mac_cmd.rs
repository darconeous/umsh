use crate::util::{copy_into, fixed, push_byte};
use crate::{EncodeError, ParseError};

/// Registered MAC-command identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandId {
    /// Request that the peer send a beacon.
    BeaconRequest = 0,
    /// Request the peer's node-identity payload.
    IdentityRequest = 1,
    /// Request a signal-quality report.
    SignalReportRequest = 2,
    /// Response carrying RSSI and SNR.
    SignalReportResponse = 3,
    /// Echo request used for reachability or latency checks.
    EchoRequest = 4,
    /// Echo response containing the original echo bytes.
    EchoResponse = 5,
    /// Begin a perfect-forward-secrecy session.
    PfsSessionRequest = 6,
    /// Accept or parameterize a perfect-forward-secrecy session.
    PfsSessionResponse = 7,
    /// End an active perfect-forward-secrecy session.
    EndPfsSession = 8,
}

/// Parsed MAC-command payload.
///
/// Commands that carry arbitrary data borrow that data from the input slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacCommand<'a> {
    /// Beacon request with an optional echoed nonce.
    BeaconRequest { nonce: Option<u32> },
    /// Request the peer's node-identity payload.
    IdentityRequest,
    /// Request signal-report metrics.
    SignalReportRequest,
    /// Response carrying RSSI and SNR.
    SignalReportResponse { rssi: u8, snr: i8 },
    /// Echo request bytes.
    EchoRequest { data: &'a [u8] },
    /// Echo response bytes.
    EchoResponse { data: &'a [u8] },
    /// PFS session request.
    PfsSessionRequest {
        ephemeral_key: umsh_core::PublicKey,
        duration_minutes: u16,
    },
    /// PFS session response.
    PfsSessionResponse {
        ephemeral_key: umsh_core::PublicKey,
        duration_minutes: u16,
    },
    /// End an active PFS session.
    EndPfsSession,
}

/// Parse a MAC-command payload body.
pub fn parse(payload: &[u8]) -> Result<MacCommand<'_>, ParseError> {
    let (&command_id, body) = payload
        .split_first()
        .ok_or(ParseError::Core(umsh_core::ParseError::Truncated))?;

    match command_id {
        0 => match body {
            [] => Ok(MacCommand::BeaconRequest { nonce: None }),
            [a, b, c, d] => Ok(MacCommand::BeaconRequest {
                nonce: Some(u32::from_be_bytes([*a, *b, *c, *d])),
            }),
            _ => Err(ParseError::InvalidLength {
                expected: 4,
                actual: body.len(),
            }),
        },
        1 => {
            if body.is_empty() {
                Ok(MacCommand::IdentityRequest)
            } else {
                Err(ParseError::InvalidOptionValue)
            }
        }
        2 => {
            if body.is_empty() {
                Ok(MacCommand::SignalReportRequest)
            } else {
                Err(ParseError::InvalidOptionValue)
            }
        }
        3 => match body {
            [rssi, snr] => Ok(MacCommand::SignalReportResponse {
                rssi: *rssi,
                snr: *snr as i8,
            }),
            _ => Err(ParseError::InvalidLength {
                expected: 2,
                actual: body.len(),
            }),
        },
        4 => Ok(MacCommand::EchoRequest { data: body }),
        5 => Ok(MacCommand::EchoResponse { data: body }),
        6 => parse_pfs(body, true),
        7 => parse_pfs(body, false),
        8 => {
            if body.is_empty() {
                Ok(MacCommand::EndPfsSession)
            } else {
                Err(ParseError::InvalidOptionValue)
            }
        }
        other => Err(ParseError::InvalidCommandId(other)),
    }
}

fn parse_pfs(payload: &[u8], request: bool) -> Result<MacCommand<'_>, ParseError> {
    if payload.len() != 34 {
        return Err(ParseError::InvalidLength {
            expected: 34,
            actual: payload.len(),
        });
    }
    let ephemeral_key = umsh_core::PublicKey(*fixed(&payload[..32])?);
    let duration_minutes = u16::from_be_bytes(*fixed(&payload[32..34])?);
    Ok(if request {
        MacCommand::PfsSessionRequest {
            ephemeral_key,
            duration_minutes,
        }
    } else {
        MacCommand::PfsSessionResponse {
            ephemeral_key,
            duration_minutes,
        }
    })
}

/// Encode a MAC-command payload body into `buf`.
pub fn encode(cmd: &MacCommand<'_>, buf: &mut [u8]) -> Result<usize, EncodeError> {
    let mut pos = 0usize;
    match cmd {
        MacCommand::BeaconRequest { nonce } => {
            push_byte(buf, &mut pos, CommandId::BeaconRequest as u8)?;
            if let Some(nonce) = nonce {
                copy_into(buf, &mut pos, &nonce.to_be_bytes())?;
            }
        }
        MacCommand::IdentityRequest => push_byte(buf, &mut pos, CommandId::IdentityRequest as u8)?,
        MacCommand::SignalReportRequest => {
            push_byte(buf, &mut pos, CommandId::SignalReportRequest as u8)?;
        }
        MacCommand::SignalReportResponse { rssi, snr } => {
            push_byte(buf, &mut pos, CommandId::SignalReportResponse as u8)?;
            push_byte(buf, &mut pos, *rssi)?;
            push_byte(buf, &mut pos, *snr as u8)?;
        }
        MacCommand::EchoRequest { data } => {
            push_byte(buf, &mut pos, CommandId::EchoRequest as u8)?;
            copy_into(buf, &mut pos, data)?;
        }
        MacCommand::EchoResponse { data } => {
            push_byte(buf, &mut pos, CommandId::EchoResponse as u8)?;
            copy_into(buf, &mut pos, data)?;
        }
        MacCommand::PfsSessionRequest {
            ephemeral_key,
            duration_minutes,
        } => {
            push_byte(buf, &mut pos, CommandId::PfsSessionRequest as u8)?;
            copy_into(buf, &mut pos, &ephemeral_key.0)?;
            copy_into(buf, &mut pos, &duration_minutes.to_be_bytes())?;
        }
        MacCommand::PfsSessionResponse {
            ephemeral_key,
            duration_minutes,
        } => {
            push_byte(buf, &mut pos, CommandId::PfsSessionResponse as u8)?;
            copy_into(buf, &mut pos, &ephemeral_key.0)?;
            copy_into(buf, &mut pos, &duration_minutes.to_be_bytes())?;
        }
        MacCommand::EndPfsSession => push_byte(buf, &mut pos, CommandId::EndPfsSession as u8)?,
    }
    Ok(pos)
}