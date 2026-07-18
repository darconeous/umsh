use alloc::vec::Vec;

use umsh_core::PublicKey;

use crate::app_util::{copy_into, fixed, push_byte};
use crate::{AppEncodeError, AppParseError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandId {
    AdvertisementRequest = 0,
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
    AdvertisementRequest {
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
            [] => Ok(MacCommand::AdvertisementRequest { nonce: None }),
            [a, b, c, d] => Ok(MacCommand::AdvertisementRequest {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnedMacCommand {
    AdvertisementRequest {
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
            MacCommand::AdvertisementRequest { nonce } => Self::AdvertisementRequest { nonce },
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

pub fn encode(cmd: &MacCommand<'_>, buf: &mut [u8]) -> Result<usize, AppEncodeError> {
    let mut pos = 0usize;
    match cmd {
        MacCommand::AdvertisementRequest { nonce } => {
            push_byte(buf, &mut pos, CommandId::AdvertisementRequest as u8)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_decode(cmd: MacCommand<'_>) {
        let mut buf = [0u8; 64];
        let len = encode(&cmd, &mut buf).expect("encode failed");
        let decoded = parse(&buf[..len]).expect("parse failed");
        assert_eq!(cmd, decoded, "round-trip failed for {cmd:?}");
    }

    // --- round-trips ---

    #[test]
    fn advertisement_request_no_nonce() {
        encode_decode(MacCommand::AdvertisementRequest { nonce: None });
        let mut buf = [0u8; 4];
        let len = encode(&MacCommand::AdvertisementRequest { nonce: None }, &mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x00]);
    }

    #[test]
    fn advertisement_request_with_nonce() {
        let cmd = MacCommand::AdvertisementRequest {
            nonce: Some(0x12345678),
        };
        encode_decode(cmd);
        let mut buf = [0u8; 8];
        let len = encode(&cmd, &mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x00, 0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn identity_request() {
        encode_decode(MacCommand::IdentityRequest);
        let mut buf = [0u8; 4];
        let len = encode(&MacCommand::IdentityRequest, &mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x01]);
    }

    #[test]
    fn signal_report_request() {
        encode_decode(MacCommand::SignalReportRequest);
    }

    #[test]
    fn signal_report_response() {
        encode_decode(MacCommand::SignalReportResponse {
            rssi: 200,
            snr: -10,
        });
        let mut buf = [0u8; 8];
        let len = encode(
            &MacCommand::SignalReportResponse {
                rssi: 0xAB,
                snr: -1,
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..len], &[0x03, 0xAB, 0xFF]);
    }

    #[test]
    fn echo_request() {
        encode_decode(MacCommand::EchoRequest {
            data: &[0x01, 0x02, 0x03],
        });
        encode_decode(MacCommand::EchoRequest { data: &[] });
    }

    #[test]
    fn echo_response() {
        encode_decode(MacCommand::EchoResponse {
            data: &[0xDE, 0xAD],
        });
    }

    #[test]
    fn pfs_session_request() {
        let key = PublicKey([0xABu8; 32]);
        encode_decode(MacCommand::PfsSessionRequest {
            ephemeral_key: key,
            duration_minutes: 60,
        });
        let mut buf = [0u8; 40];
        let len = encode(
            &MacCommand::PfsSessionRequest {
                ephemeral_key: key,
                duration_minutes: 0x0102,
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(len, 1 + 32 + 2);
        assert_eq!(buf[0], 0x06);
        assert_eq!(&buf[1..33], &[0xABu8; 32]);
        assert_eq!(&buf[33..35], &[0x01, 0x02]);
    }

    #[test]
    fn pfs_session_response() {
        let key = PublicKey([0x55u8; 32]);
        encode_decode(MacCommand::PfsSessionResponse {
            ephemeral_key: key,
            duration_minutes: 120,
        });
    }

    #[test]
    fn end_pfs_session() {
        encode_decode(MacCommand::EndPfsSession);
        let mut buf = [0u8; 4];
        let len = encode(&MacCommand::EndPfsSession, &mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x08]);
    }

    // --- OwnedMacCommand From conversion ---

    #[test]
    fn owned_from_borrowed_echo() {
        let cmd = MacCommand::EchoRequest {
            data: &[0x01, 0x02],
        };
        let owned = OwnedMacCommand::from(cmd);
        assert_eq!(
            owned,
            OwnedMacCommand::EchoRequest {
                data: alloc::vec![0x01, 0x02]
            }
        );
    }

    // --- parse error cases ---

    #[test]
    fn parse_empty_returns_truncated() {
        assert!(matches!(
            parse(&[]),
            Err(crate::AppParseError::Core(umsh_core::ParseError::Truncated))
        ));
    }

    #[test]
    fn parse_unknown_command_id() {
        assert!(matches!(
            parse(&[0xFF]),
            Err(crate::AppParseError::InvalidCommandId(0xFF))
        ));
    }

    #[test]
    fn parse_advertisement_request_wrong_body_length() {
        assert!(parse(&[0x00, 0x01, 0x02]).is_err()); // 3-byte body, not 0 or 4
    }

    #[test]
    fn parse_identity_request_nonempty_body() {
        assert!(parse(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn parse_signal_report_response_wrong_length() {
        assert!(parse(&[0x03, 0x01]).is_err()); // need exactly 2 body bytes
    }

    #[test]
    fn parse_pfs_request_wrong_length() {
        assert!(parse(&[0x06, 0x00]).is_err()); // need exactly 34 body bytes
    }

    #[test]
    fn parse_end_pfs_nonempty_body() {
        assert!(parse(&[0x08, 0x00]).is_err());
    }
}
