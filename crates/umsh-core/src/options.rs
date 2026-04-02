use crate::{EncodeError, ParseError};

#[derive(Debug)]
pub struct OptionEncoder<'a> {
    buf: &'a mut [u8],
    pos: usize,
    last_number: u16,
    wrote_any: bool,
}

impl<'a> OptionEncoder<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            last_number: 0,
            wrote_any: false,
        }
    }

    pub fn with_last_number(buf: &'a mut [u8], last_number: u16) -> Self {
        Self {
            buf,
            pos: 0,
            last_number,
            wrote_any: true,
        }
    }

    pub fn put(&mut self, number: u16, value: &[u8]) -> Result<(), EncodeError> {
        if self.wrote_any && number < self.last_number {
            return Err(EncodeError::OptionOutOfOrder);
        }
        let delta = if self.wrote_any {
            number - self.last_number
        } else {
            number
        };
        let delta_len = encoded_len(delta);
        let value_len = encoded_len(value.len() as u16);
        let required = 1 + delta_len + value_len + value.len();
        if self.pos + required > self.buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }

        let header_pos = self.pos;
        self.pos += 1;
        let delta_nibble = write_extended(&mut self.buf[self.pos..], delta)?;
        self.pos += delta_len;
        let len_nibble = write_extended(&mut self.buf[self.pos..], value.len() as u16)?;
        self.pos += value_len;
        self.buf[header_pos] = (delta_nibble << 4) | len_nibble;
        self.buf[self.pos..self.pos + value.len()].copy_from_slice(value);
        self.pos += value.len();
        self.last_number = number;
        self.wrote_any = true;
        Ok(())
    }

    pub fn end_marker(&mut self) -> Result<(), EncodeError> {
        if self.pos >= self.buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        self.buf[self.pos] = 0xFF;
        self.pos += 1;
        Ok(())
    }

    pub fn finish(self) -> usize {
        self.pos
    }
}

#[derive(Clone, Debug)]
pub struct OptionDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    last_number: u16,
    finished: bool,
    errored: bool,
}

impl<'a> OptionDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            last_number: 0,
            finished: false,
            errored: false,
        }
    }

    pub fn remainder(&self) -> &'a [u8] {
        if self.finished {
            &self.data[self.pos..]
        } else {
            &[]
        }
    }
}

impl<'a> Iterator for OptionDecoder<'a> {
    type Item = Result<(u16, &'a [u8]), ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.errored {
            return None;
        }
        if self.pos >= self.data.len() {
            self.errored = true;
            return Some(Err(ParseError::MissingOptionTerminator));
        }

        let first = self.data[self.pos];
        if first == 0xFF {
            self.pos += 1;
            self.finished = true;
            return None;
        }

        self.pos += 1;
        let delta_nibble = first >> 4;
        let len_nibble = first & 0x0F;
        let (delta, delta_len) = match read_extended(&self.data[self.pos..], delta_nibble) {
            Ok(value) => value,
            Err(err) => {
                self.errored = true;
                return Some(Err(err));
            }
        };
        self.pos += delta_len;
        let (len, len_len) = match read_extended(&self.data[self.pos..], len_nibble) {
            Ok(value) => value,
            Err(err) => {
                self.errored = true;
                return Some(Err(err));
            }
        };
        self.pos += len_len;

        if self.pos + len as usize > self.data.len() {
            self.errored = true;
            return Some(Err(ParseError::Truncated));
        }

        let number = self
            .last_number
            .checked_add(delta)
            .ok_or(ParseError::MalformedOption);
        let number = match number {
            Ok(value) => value,
            Err(err) => {
                self.errored = true;
                return Some(Err(err));
            }
        };
        let value = &self.data[self.pos..self.pos + len as usize];
        self.pos += len as usize;
        self.last_number = number;
        Some(Ok((number, value)))
    }
}

fn encoded_len(value: u16) -> usize {
    match value {
        0..=12 => 0,
        13..=268 => 1,
        _ => 2,
    }
}

fn write_extended(buf: &mut [u8], value: u16) -> Result<u8, EncodeError> {
    match value {
        0..=12 => Ok(value as u8),
        13..=268 => {
            if buf.is_empty() {
                return Err(EncodeError::BufferTooSmall);
            }
            buf[0] = (value - 13) as u8;
            Ok(13)
        }
        _ => {
            if buf.len() < 2 {
                return Err(EncodeError::BufferTooSmall);
            }
            let extended = value - 269;
            buf[..2].copy_from_slice(&extended.to_be_bytes());
            Ok(14)
        }
    }
}

fn read_extended(data: &[u8], nibble: u8) -> Result<(u16, usize), ParseError> {
    match nibble {
        0..=12 => Ok((nibble as u16, 0)),
        13 => {
            if data.is_empty() {
                return Err(ParseError::Truncated);
            }
            Ok((data[0] as u16 + 13, 1))
        }
        14 => {
            if data.len() < 2 {
                return Err(ParseError::Truncated);
            }
            Ok((u16::from_be_bytes([data[0], data[1]]) + 269, 2))
        }
        _ => Err(ParseError::InvalidOptionNibble),
    }
}
