use core::{marker::PhantomData, ops::Range};

use crate::{
    options::OptionEncoder, BuildError, ChannelId, Fcf, FloodHops, MicSize, NodeHint,
    OptionNumber, PacketType, PublicKey, Scf, SecInfo, UnsealedPacket,
};

pub mod state {
    pub struct NeedsSource;
    pub struct NeedsCounter;
    pub struct Configuring;
    pub struct Complete;
}

pub struct PacketBuilder<'a> {
    buf: &'a mut [u8],
}

impl<'a> PacketBuilder<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }

    pub fn broadcast(self) -> BroadcastBuilder<'a, state::NeedsSource> {
        Builder::new(self.buf, PacketType::Broadcast)
    }

    pub fn mac_ack(self, dst: [u8; 2], ack_tag: [u8; 8]) -> MacAckBuilder<'a, state::Configuring> {
        let mut builder = Builder::new(self.buf, PacketType::MacAck);
        builder.ack_dst = Some(dst);
        builder.ack_tag = Some(ack_tag);
        builder
    }

    pub fn unicast(self, dst: NodeHint) -> UnicastBuilder<'a, state::NeedsSource> {
        let mut builder = Builder::new(self.buf, PacketType::Unicast);
        builder.dst = Some(dst);
        builder
    }

    pub fn multicast(self, channel: ChannelId) -> MulticastBuilder<'a, state::NeedsSource> {
        let mut builder = Builder::new(self.buf, PacketType::Multicast);
        builder.channel = Some(channel);
        builder
    }

    pub fn blind_unicast(self, channel: ChannelId, dst: NodeHint) -> BlindUnicastBuilder<'a, state::NeedsSource> {
        let mut builder = Builder::new(self.buf, PacketType::BlindUnicast);
        builder.channel = Some(channel);
        builder.dst = Some(dst);
        builder
    }
}

pub type BroadcastBuilder<'a, S> = Builder<'a, BroadcastKind, S>;
pub type MacAckBuilder<'a, S> = Builder<'a, MacAckKind, S>;
pub type UnicastBuilder<'a, S> = Builder<'a, UnicastKind, S>;
pub type MulticastBuilder<'a, S> = Builder<'a, MulticastKind, S>;
pub type BlindUnicastBuilder<'a, S> = Builder<'a, BlindUnicastKind, S>;

pub struct BroadcastKind;
pub struct MacAckKind;
pub struct UnicastKind;
pub struct MulticastKind;
pub struct BlindUnicastKind;

enum SourceValue {
    Hint(NodeHint),
    Full(PublicKey),
}

pub struct Builder<'a, K, S> {
    buf: &'a mut [u8],
    packet_type: PacketType,
    options_used: bool,
    options_finalized: bool,
    options_len: usize,
    last_option_number: Option<u16>,
    option_error: Option<BuildError>,
    source: Option<SourceValue>,
    dst: Option<NodeHint>,
    channel: Option<ChannelId>,
    ack_dst: Option<[u8; 2]>,
    ack_tag: Option<[u8; 8]>,
    frame_counter: Option<u32>,
    encrypted: bool,
    mic_size: MicSize,
    salt: Option<u16>,
    flood_hops: Option<FloodHops>,
    payload: Option<Range<usize>>,
    blind_addr: Option<Range<usize>>,
    _marker: PhantomData<(K, S)>,
}

impl<'a, K, S> Builder<'a, K, S> {
    fn new(buf: &'a mut [u8], packet_type: PacketType) -> Self {
        Self {
            buf,
            packet_type,
            options_used: false,
            options_finalized: false,
            options_len: 0,
            last_option_number: None,
            option_error: None,
            source: None,
            dst: None,
            channel: None,
            ack_dst: None,
            ack_tag: None,
            frame_counter: None,
            encrypted: matches!(packet_type, PacketType::BlindUnicast | PacketType::BlindUnicastAckReq),
            mic_size: MicSize::Mic16,
            salt: None,
            flood_hops: None,
            payload: None,
            blind_addr: None,
            _marker: PhantomData,
        }
    }

    fn with_state<NS>(self) -> Builder<'a, K, NS> {
        Builder {
            buf: self.buf,
            packet_type: self.packet_type,
            options_used: self.options_used,
            options_finalized: self.options_finalized,
            options_len: self.options_len,
            last_option_number: self.last_option_number,
            option_error: self.option_error,
            source: self.source,
            dst: self.dst,
            channel: self.channel,
            ack_dst: self.ack_dst,
            ack_tag: self.ack_tag,
            frame_counter: self.frame_counter,
            encrypted: self.encrypted,
            mic_size: self.mic_size,
            salt: self.salt,
            flood_hops: self.flood_hops,
            payload: self.payload,
            blind_addr: self.blind_addr,
            _marker: PhantomData,
        }
    }

    fn push_option(&mut self, number: u16, value: &[u8]) {
        if self.option_error.is_some() {
            return;
        }
        if let Some(last) = self.last_option_number {
            if number < last {
                self.option_error = Some(BuildError::OptionOutOfOrder);
                return;
            }
        }
        let mut live = match self.last_option_number {
            Some(last_number) => OptionEncoder::with_last_number(&mut self.buf[1 + self.options_len..], last_number),
            None => OptionEncoder::new(&mut self.buf[1 + self.options_len..]),
        };
        match live.put(number, value) {
            Ok(()) => {
                self.options_len += live.finish();
                self.options_used = true;
                self.last_option_number = Some(number);
            }
            Err(err) => self.option_error = Some(err.into()),
        }
    }

    fn finalize_options(&mut self) -> Result<(), BuildError> {
        if !self.options_used || self.options_finalized {
            return Ok(());
        }
        let mut encoder = OptionEncoder::new(&mut self.buf[1 + self.options_len..]);
        encoder.end_marker()?;
        self.options_len += encoder.finish();
        self.options_finalized = true;
        Ok(())
    }

    fn write_common_prefix(&mut self) -> Result<usize, BuildError> {
        if let Some(err) = self.option_error {
            return Err(err);
        }
        self.finalize_options()?;
        let full_source = matches!(self.source, Some(SourceValue::Full(_)));
        let fcf = Fcf::new(self.packet_type, full_source, self.options_used, self.flood_hops.is_some());
        if self.buf.is_empty() {
            return Err(BuildError::BufferTooSmall);
        }
        self.buf[0] = fcf.0;
        let mut cursor = 1;
        cursor += self.options_len;
        if let Some(fhops) = self.flood_hops {
            self.buf.get_mut(cursor).ok_or(BuildError::BufferTooSmall).map(|slot| *slot = fhops.0)?;
            cursor += 1;
        }
        Ok(cursor)
    }

    fn write_source(&mut self, cursor: &mut usize) -> Result<(), BuildError> {
        match self.source {
            Some(SourceValue::Hint(hint)) => {
                let end = *cursor + 3;
                self.buf.get_mut(*cursor..end).ok_or(BuildError::BufferTooSmall)?.copy_from_slice(&hint.0);
                *cursor = end;
            }
            Some(SourceValue::Full(key)) => {
                let end = *cursor + 32;
                self.buf.get_mut(*cursor..end).ok_or(BuildError::BufferTooSmall)?.copy_from_slice(&key.0);
                *cursor = end;
            }
            None => return Err(BuildError::MissingSource),
        }
        Ok(())
    }

    fn stage_payload(&mut self, data: &[u8]) {
        let scratch_start = match self.buf.len().checked_sub(data.len()) {
            Some(value) => value,
            None => {
                self.option_error = Some(BuildError::BufferTooSmall);
                return;
            }
        };
        if let Some(slot) = self.buf.get_mut(scratch_start..scratch_start + data.len()) {
            slot.copy_from_slice(data);
            self.payload = Some(scratch_start..scratch_start + data.len());
        } else {
            self.option_error = Some(BuildError::BufferTooSmall);
        }
    }

    fn copy_staged_payload(&mut self, cursor: &mut usize) -> Result<Range<usize>, BuildError> {
        let payload = self.payload.clone().ok_or(BuildError::MissingPayload)?;
        let len = payload.end - payload.start;
        let start = *cursor;
        let end = start + len;
        if end > self.buf.len() {
            return Err(BuildError::BufferTooSmall);
        }
        self.buf.copy_within(payload, start);
        *cursor = end;
        Ok(start..end)
    }

    fn stage_blind_addr(&mut self, cursor: &mut usize) -> Result<Range<usize>, BuildError> {
        let dst = self.dst.ok_or(BuildError::MissingDestination)?;
        let start = *cursor;
        let dst_end = start + 3;
        self.buf.get_mut(start..dst_end).ok_or(BuildError::BufferTooSmall)?.copy_from_slice(&dst.0);
        *cursor = dst_end;
        self.write_source(cursor)?;
        let end = *cursor;
        Ok(start..end)
    }
}

impl<'a> BroadcastBuilder<'a, state::NeedsSource> {
    pub fn source_hint(mut self, hint: NodeHint) -> BroadcastBuilder<'a, state::Configuring> {
        self.source = Some(SourceValue::Hint(hint));
        self.with_state()
    }

    pub fn source_full(mut self, key: &PublicKey) -> BroadcastBuilder<'a, state::Configuring> {
        self.source = Some(SourceValue::Full(*key));
        self.with_state()
    }
}

impl<'a> UnicastBuilder<'a, state::NeedsSource> {
    pub fn source_hint(mut self, hint: NodeHint) -> UnicastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Hint(hint));
        self.with_state()
    }

    pub fn source_full(mut self, key: &PublicKey) -> UnicastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Full(*key));
        self.with_state()
    }
}

impl<'a> MulticastBuilder<'a, state::NeedsSource> {
    pub fn source_hint(mut self, hint: NodeHint) -> MulticastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Hint(hint));
        self.with_state()
    }

    pub fn source_full(mut self, key: &PublicKey) -> MulticastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Full(*key));
        self.with_state()
    }
}

impl<'a> BlindUnicastBuilder<'a, state::NeedsSource> {
    pub fn source_hint(mut self, hint: NodeHint) -> BlindUnicastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Hint(hint));
        self.with_state()
    }

    pub fn source_full(mut self, key: &PublicKey) -> BlindUnicastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Full(*key));
        self.with_state()
    }
}

impl<'a> UnicastBuilder<'a, state::NeedsCounter> {
    pub fn frame_counter(mut self, counter: u32) -> UnicastBuilder<'a, state::Configuring> {
        self.frame_counter = Some(counter);
        self.with_state()
    }
}

impl<'a> MulticastBuilder<'a, state::NeedsCounter> {
    pub fn frame_counter(mut self, counter: u32) -> MulticastBuilder<'a, state::Configuring> {
        self.frame_counter = Some(counter);
        self.with_state()
    }
}

impl<'a> BlindUnicastBuilder<'a, state::NeedsCounter> {
    pub fn frame_counter(mut self, counter: u32) -> BlindUnicastBuilder<'a, state::Configuring> {
        self.frame_counter = Some(counter);
        self.with_state()
    }
}

macro_rules! impl_configuring_common {
    ($name:ident<$state:ty>) => {
        impl<'a> $name<'a, $state> {
            pub fn flood_hops(mut self, remaining: u8) -> Self {
                if let Some(value) = FloodHops::new(remaining, 0) {
                    self.flood_hops = Some(value);
                }
                self
            }

            pub fn region_code(mut self, code: [u8; 2]) -> Self {
                self.push_option(OptionNumber::RegionCode.as_u16(), &code);
                self
            }

            pub fn trace_route(mut self) -> Self {
                self.push_option(OptionNumber::TraceRoute.as_u16(), &[]);
                self
            }

            pub fn source_route(mut self, hops: &[crate::RouterHint]) -> Self {
                let mut encoded = [0u8; 30];
                let needed = hops.len() * 2;
                if needed > encoded.len() {
                    self.option_error = Some(BuildError::BufferTooSmall);
                    return self;
                }
                for (index, hop) in hops.iter().enumerate() {
                    encoded[index * 2..index * 2 + 2].copy_from_slice(&hop.0);
                }
                self.push_option(OptionNumber::SourceRoute.as_u16(), &encoded[..needed]);
                self
            }

            pub fn option(mut self, number: OptionNumber, value: &[u8]) -> Self {
                self.push_option(number.as_u16(), value);
                self
            }
        }
    };
}

impl_configuring_common!(BroadcastBuilder<state::Configuring>);
impl_configuring_common!(MacAckBuilder<state::Configuring>);
impl_configuring_common!(UnicastBuilder<state::Configuring>);
impl_configuring_common!(MulticastBuilder<state::Configuring>);
impl_configuring_common!(BlindUnicastBuilder<state::Configuring>);

impl<'a> UnicastBuilder<'a, state::Configuring> {
    pub fn ack_requested(mut self) -> Self {
        self.packet_type = PacketType::UnicastAckReq;
        self
    }

    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    pub fn mic_size(mut self, size: MicSize) -> Self {
        self.mic_size = size;
        self
    }

    pub fn salt(mut self, salt: u16) -> Self {
        self.salt = Some(salt);
        self
    }

    pub fn payload(mut self, data: &[u8]) -> UnicastBuilder<'a, state::Complete> {
        self.stage_payload(data);
        self.with_state()
    }
}

impl<'a> MulticastBuilder<'a, state::Configuring> {
    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    pub fn mic_size(mut self, size: MicSize) -> Self {
        self.mic_size = size;
        self
    }

    pub fn salt(mut self, salt: u16) -> Self {
        self.salt = Some(salt);
        self
    }

    pub fn payload(mut self, data: &[u8]) -> MulticastBuilder<'a, state::Complete> {
        self.stage_payload(data);
        self.with_state()
    }
}

impl<'a> BlindUnicastBuilder<'a, state::Configuring> {
    pub fn ack_requested(mut self) -> Self {
        self.packet_type = PacketType::BlindUnicastAckReq;
        self
    }

    pub fn mic_size(mut self, size: MicSize) -> Self {
        self.mic_size = size;
        self
    }

    pub fn salt(mut self, salt: u16) -> Self {
        self.salt = Some(salt);
        self
    }

    pub fn payload(mut self, data: &[u8]) -> BlindUnicastBuilder<'a, state::Complete> {
        self.stage_payload(data);
        self.with_state()
    }
}

impl<'a> BroadcastBuilder<'a, state::Configuring> {
    pub fn payload(mut self, data: &[u8]) -> BroadcastBuilder<'a, state::Complete> {
        self.stage_payload(data);
        self.with_state()
    }

    pub fn build(mut self) -> Result<&'a [u8], BuildError> {
        let mut cursor = self.write_common_prefix()?;
        self.write_source(&mut cursor)?;
        if self.payload.is_some() {
            let _ = self.copy_staged_payload(&mut cursor)?;
        }
        Ok(&self.buf[..cursor])
    }
}

impl<'a> BroadcastBuilder<'a, state::Complete> {
    pub fn build(self) -> Result<&'a [u8], BuildError> {
        self.with_state::<state::Configuring>().build()
    }
}

impl<'a> MacAckBuilder<'a, state::Configuring> {
    pub fn build(mut self) -> Result<&'a [u8], BuildError> {
        let mut cursor = self.write_common_prefix()?;
        let dst = self.ack_dst.ok_or(BuildError::MissingDestination)?;
        self.buf.get_mut(cursor..cursor + 2).ok_or(BuildError::BufferTooSmall)?.copy_from_slice(&dst);
        cursor += 2;
        let ack_tag = self.ack_tag.ok_or(BuildError::MissingAckTag)?;
        self.buf.get_mut(cursor..cursor + 8).ok_or(BuildError::BufferTooSmall)?.copy_from_slice(&ack_tag);
        cursor += 8;
        Ok(&self.buf[..cursor])
    }
}

impl<'a> UnicastBuilder<'a, state::Complete> {
    pub fn build(self) -> Result<UnsealedPacket<'a>, BuildError> {
        self.with_state::<state::Configuring>().build()
    }
}

impl<'a> UnicastBuilder<'a, state::Configuring> {
    pub fn build(mut self) -> Result<UnsealedPacket<'a>, BuildError> {
        let mut cursor = self.write_common_prefix()?;
        let dst = self.dst.ok_or(BuildError::MissingDestination)?;
        self.buf.get_mut(cursor..cursor + 3).ok_or(BuildError::BufferTooSmall)?.copy_from_slice(&dst.0);
        cursor += 3;
        self.write_source(&mut cursor)?;
        let scf = Scf::new(self.encrypted, self.mic_size, self.salt.is_some());
        let sec_info = SecInfo { scf, frame_counter: self.frame_counter.ok_or(BuildError::MissingFrameCounter)?, salt: self.salt };
        let sec_start = cursor;
        cursor += sec_info.encode(self.buf.get_mut(cursor..).ok_or(BuildError::BufferTooSmall)?);
        let body_range = self.copy_staged_payload(&mut cursor)?;
        let mic_start = cursor;
        let mic_end = mic_start + self.mic_size.byte_len();
        self.buf.get_mut(mic_start..mic_end).ok_or(BuildError::BufferTooSmall)?.fill(0);
        cursor = mic_end;
        Ok(UnsealedPacket::new(self.buf, cursor, body_range, None, mic_start..mic_end, sec_start..sec_start + sec_info.wire_len(), 1..1 + self.options_len))
    }
}

impl<'a> MulticastBuilder<'a, state::Complete> {
    pub fn build(self) -> Result<UnsealedPacket<'a>, BuildError> {
        self.with_state::<state::Configuring>().build()
    }
}

impl<'a> MulticastBuilder<'a, state::Configuring> {
    pub fn build(mut self) -> Result<UnsealedPacket<'a>, BuildError> {
        let mut cursor = self.write_common_prefix()?;
        let channel = self.channel.ok_or(BuildError::MissingChannel)?;
        self.buf.get_mut(cursor..cursor + 2).ok_or(BuildError::BufferTooSmall)?.copy_from_slice(&channel.0);
        cursor += 2;
        let scf = Scf::new(self.encrypted, self.mic_size, self.salt.is_some());
        let sec_info = SecInfo { scf, frame_counter: self.frame_counter.ok_or(BuildError::MissingFrameCounter)?, salt: self.salt };
        let sec_start = cursor;
        cursor += sec_info.encode(self.buf.get_mut(cursor..).ok_or(BuildError::BufferTooSmall)?);
        let body_start = cursor;
        self.write_source(&mut cursor)?;
        let payload_range = self.copy_staged_payload(&mut cursor)?;
        let body_range = if self.encrypted { body_start..payload_range.end } else { payload_range };
        let mic_start = cursor;
        let mic_end = mic_start + self.mic_size.byte_len();
        self.buf.get_mut(mic_start..mic_end).ok_or(BuildError::BufferTooSmall)?.fill(0);
        cursor = mic_end;
        Ok(UnsealedPacket::new(self.buf, cursor, body_range, None, mic_start..mic_end, sec_start..sec_start + sec_info.wire_len(), 1..1 + self.options_len))
    }
}

impl<'a> BlindUnicastBuilder<'a, state::Complete> {
    pub fn build(self) -> Result<UnsealedPacket<'a>, BuildError> {
        self.with_state::<state::Configuring>().build()
    }
}

impl<'a> BlindUnicastBuilder<'a, state::Configuring> {
    pub fn build(mut self) -> Result<UnsealedPacket<'a>, BuildError> {
        let mut cursor = self.write_common_prefix()?;
        let channel = self.channel.ok_or(BuildError::MissingChannel)?;
        self.buf.get_mut(cursor..cursor + 2).ok_or(BuildError::BufferTooSmall)?.copy_from_slice(&channel.0);
        cursor += 2;
        let scf = Scf::new(true, self.mic_size, self.salt.is_some());
        let sec_info = SecInfo { scf, frame_counter: self.frame_counter.ok_or(BuildError::MissingFrameCounter)?, salt: self.salt };
        let sec_start = cursor;
        cursor += sec_info.encode(self.buf.get_mut(cursor..).ok_or(BuildError::BufferTooSmall)?);
        let blind_addr_range = self.stage_blind_addr(&mut cursor)?;
        let body_range = self.copy_staged_payload(&mut cursor)?;
        let mic_start = cursor;
        let mic_end = mic_start + self.mic_size.byte_len();
        self.buf.get_mut(mic_start..mic_end).ok_or(BuildError::BufferTooSmall)?.fill(0);
        cursor = mic_end;
        Ok(UnsealedPacket::new(
            self.buf,
            cursor,
            body_range,
            Some(blind_addr_range),
            mic_start..mic_end,
            sec_start..sec_start + sec_info.wire_len(),
            1..1 + self.options_len,
        ))
    }
}
