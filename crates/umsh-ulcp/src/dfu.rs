//! Bootloader modes selected by `CMD_DFU`.

use crate::Status;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum DfuMode {
    /// The platform's fixed default, independent of the current transport.
    #[default]
    Default = 0,
    Serial = 1,
    Uf2 = 2,
    Ble = 3,
}

impl DfuMode {
    pub fn parse(payload: &[u8]) -> Result<Self, Status> {
        match payload {
            [] | [0] => Ok(Self::Default),
            [1] => Ok(Self::Serial),
            [2] => Ok(Self::Uf2),
            [3] => Ok(Self::Ble),
            [_] => Err(Status::INVALID_ARGUMENT),
            _ => Err(Status::PARSE_ERROR),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Frame, frame};

    #[test]
    fn optional_mode_and_invalid_payloads() {
        let mut buf = [0; 8];
        for mode in [
            None,
            Some(DfuMode::Default),
            Some(DfuMode::Serial),
            Some(DfuMode::Uf2),
            Some(DfuMode::Ble),
        ] {
            let len = frame::dfu(&mut buf, 3, mode).unwrap();
            let request = Frame::parse(&buf[..len]).unwrap();
            assert_eq!(request.command(), Some(frame::Cmd::Dfu));
            assert_eq!(request.header.tid(), 3);
            assert_eq!(
                DfuMode::parse(request.payload),
                Ok(mode.unwrap_or_default())
            );
            assert_eq!(request.payload.len(), usize::from(mode.is_some()));
        }
        for value in 4..=255 {
            assert_eq!(DfuMode::parse(&[value]), Err(Status::INVALID_ARGUMENT));
        }
        assert_eq!(DfuMode::parse(&[0, 0]), Err(Status::PARSE_ERROR));
    }
}
