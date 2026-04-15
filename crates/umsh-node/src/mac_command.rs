use crate::app_util::{copy_into, fixed, push_byte};
use crate::{AppEncodeError, AppParseError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandId {
    BeaconRequest = 0,
    IdentityRequest = 1,
    SignalReportRequest = 2,
    SignalReportResponse = 3,
    EchoRequest = 4,
    EchoResponse = 5,
    PfsSessionRequest = 6,
    PfsSessionResponse = 7,
    EndPfsSession = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacCommand<'a> {
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
        data: &'a [u8],
    },
    EchoResponse {
        data: &'a [u8],
    },
    PfsSessionRequest {
        ephemeral_key: umsh_core::PublicKey,
        duration_minutes: u16,
    },
    PfsSessionResponse {
        ephemeral_key: umsh_core::PublicKey,
        duration_minutes: u16,
    },
    EndPfsSession,
}

pub fn parse(payload: &[u8]) -> Result<MacCommand<'_>, AppParseError> {
    let (&command_id, body) = payload
        .split_first()
        .ok_or(AppParseError::Core(umsh_core::ParseError::Truncated))?;

    match command_id {
        0 => match body {
            [] => Ok(MacCommand::BeaconRequest { nonce: None }),
            [a, b, c, d] => Ok(MacCommand::BeaconRequest {
                nonce: Some(u32::from_be_bytes([*a, *b, *c, *d])),
            }),
            _ => Err(AppParseError::InvalidLength {
                expected: 4,
                actual: body.len(),
            }),
        },
        1 => {
            if body.is_empty() {
                Ok(MacCommand::IdentityRequest)
            } else {
                Err(AppParseError::InvalidOptionValue)
            }
        }
        2 => {
            if body.is_empty() {
                Ok(MacCommand::SignalReportRequest)
            } else {
                Err(AppParseError::InvalidOptionValue)
            }
        }
        3 => match body {
            [rssi, snr] => Ok(MacCommand::SignalReportResponse {
                rssi: *rssi,
                snr: *snr as i8,
            }),
            _ => Err(AppParseError::InvalidLength {
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
                Err(AppParseError::InvalidOptionValue)
            }
        }
        other => Err(AppParseError::InvalidCommandId(other)),
    }
}

fn parse_pfs(payload: &[u8], request: bool) -> Result<MacCommand<'_>, AppParseError> {
    if payload.len() != 34 {
        return Err(AppParseError::InvalidLength {
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

pub fn encode(cmd: &MacCommand<'_>, buf: &mut [u8]) -> Result<usize, AppEncodeError> {
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
