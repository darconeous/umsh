use core::{marker::PhantomData, ops::Range};

use crate::{
    BuildError, ChannelId, FRAME_SIGNATURE_OPTION_LEN, Fcf, FloodHops, MicSize, NodeHint,
    OptionNumber, PacketType, PublicKey, SIGNATURE_LEN, Scf, SecInfo, UnsealedPacket,
    options::OptionEncoder,
};

/// Typestate markers used by [`PacketBuilder`] and its specialized builders.
pub mod state {
    /// Builder state that still requires a source address.
    pub struct NeedsSource;
    /// Builder state that still requires a frame counter.
    pub struct NeedsCounter;
    /// Builder state where options and payload can be configured.
    pub struct Configuring;
    /// Builder state after payload bytes have been staged.
    pub struct Complete;
}

/// Entry point for typestate packet construction.
///
/// The builder consumes itself as it transitions through required stages so
/// invalid packet layouts are rejected at compile time where possible.
pub struct PacketBuilder<'a> {
    buf: &'a mut [u8],
}

impl<'a> PacketBuilder<'a> {
    /// Start building a packet into `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }

    /// Begin a broadcast packet.
    pub fn broadcast(self) -> BroadcastBuilder<'a, state::NeedsSource> {
        Builder::new(self.buf, PacketType::Broadcast)
    }

    /// Build a MAC ACK packet.
    ///
    /// The ack carries no destination hint—it is a return-routed token
    /// correlated by its trailer. `ack_trailer` is the 8-byte
    /// `ack_mic || ack_tag` value. The tag covers the ack's own options, so
    /// a real ack is built with any placeholder and then sealed in place
    /// (see the crypto engine's `seal_mac_ack`).
    pub fn mac_ack(self, ack_trailer: [u8; 8]) -> MacAckBuilder<'a, state::Configuring> {
        let mut builder = Builder::new(self.buf, PacketType::MacAck);
        builder.ack_tag = Some(ack_trailer);
        builder
    }

    /// Begin a unicast packet to `dst`.
    pub fn unicast(self, dst: NodeHint) -> UnicastBuilder<'a, state::NeedsSource> {
        let mut builder = Builder::new(self.buf, PacketType::Unicast);
        builder.dst = Some(dst);
        builder
    }

    /// Begin a multicast packet on `channel`.
    pub fn multicast(self, channel: ChannelId) -> MulticastBuilder<'a, state::NeedsSource> {
        let mut builder = Builder::new(self.buf, PacketType::Multicast);
        builder.channel = Some(channel);
        builder
    }

    /// Begin a blind-unicast packet addressed through `channel` to `dst`.
    pub fn blind_unicast(
        self,
        channel: ChannelId,
        dst: NodeHint,
    ) -> BlindUnicastBuilder<'a, state::NeedsSource> {
        let mut builder = Builder::new(self.buf, PacketType::BlindUnicast);
        builder.channel = Some(channel);
        builder.dst = Some(dst);
        builder
    }
}

/// Broadcast packet builder alias.
pub type BroadcastBuilder<'a, S> = Builder<'a, BroadcastKind, S>;
/// MAC ACK packet builder alias.
pub type MacAckBuilder<'a, S> = Builder<'a, MacAckKind, S>;
/// Unicast packet builder alias.
pub type UnicastBuilder<'a, S> = Builder<'a, UnicastKind, S>;
/// Multicast packet builder alias.
pub type MulticastBuilder<'a, S> = Builder<'a, MulticastKind, S>;
/// Blind-unicast packet builder alias.
pub type BlindUnicastBuilder<'a, S> = Builder<'a, BlindUnicastKind, S>;

/// Marker type for broadcast builders.
pub struct BroadcastKind;
/// Marker type for MAC ACK builders.
pub struct MacAckKind;
/// Marker type for unicast builders.
pub struct UnicastKind;
/// Marker type for multicast builders.
pub struct MulticastKind;
/// Marker type for blind-unicast builders.
pub struct BlindUnicastKind;

enum SourceValue {
    Hint(NodeHint),
    Full(PublicKey),
}

/// Internal generic builder implementation shared by all packet kinds.
pub struct Builder<'a, K, S> {
    buf: &'a mut [u8],
    packet_type: PacketType,
    options_len: usize,
    last_option_number: Option<u16>,
    option_error: Option<BuildError>,
    source: Option<SourceValue>,
    dst: Option<NodeHint>,
    channel: Option<ChannelId>,
    ack_tag: Option<[u8; 8]>,
    frame_counter: Option<u32>,
    encrypted: bool,
    mic_size: MicSize,
    salt: Option<u16>,
    signed: bool,
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
            options_len: 0,
            last_option_number: None,
            option_error: None,
            source: None,
            dst: None,
            channel: None,
            ack_tag: None,
            frame_counter: None,
            encrypted: matches!(
                packet_type,
                PacketType::BlindUnicast | PacketType::BlindUnicastAckReq
            ),
            mic_size: MicSize::Mic16,
            salt: None,
            signed: false,
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
            options_len: self.options_len,
            last_option_number: self.last_option_number,
            option_error: self.option_error,
            source: self.source,
            dst: self.dst,
            channel: self.channel,
            ack_tag: self.ack_tag,
            frame_counter: self.frame_counter,
            encrypted: self.encrypted,
            mic_size: self.mic_size,
            salt: self.salt,
            signed: self.signed,
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
            Some(last_number) => {
                OptionEncoder::with_last_number(&mut self.buf[1 + self.options_len..], last_number)
            }
            None => OptionEncoder::new(&mut self.buf[1 + self.options_len..]),
        };
        match live.put(number, value) {
            Ok(()) => {
                self.options_len += live.finish();
                self.last_option_number = Some(number);
            }
            Err(err) => self.option_error = Some(err.into()),
        }
    }

    fn sec_info(&self) -> Result<SecInfo, BuildError> {
        Ok(SecInfo {
            scf: Scf::new(self.encrypted, self.mic_size, self.salt.is_some())
                .with_signed(self.signed),
            frame_counter: self.frame_counter.ok_or(BuildError::MissingFrameCounter)?,
            salt: self.salt,
        })
    }

    fn source_len(&self) -> Result<usize, BuildError> {
        match self.source {
            Some(SourceValue::Hint(_)) => Ok(3),
            Some(SourceValue::Full(_)) => Ok(32),
            None => Err(BuildError::MissingSource),
        }
    }

    /// Length of everything in front of the options block: FCF, FHOPS, and
    /// whichever of DST or CHANNEL, SRC, and SECINFO this packet type puts
    /// there.
    fn prefix_len(&self) -> Result<usize, BuildError> {
        let fields = match self.packet_type {
            PacketType::Broadcast => self.source_len()?,
            PacketType::MacAck => 0,
            PacketType::Unicast | PacketType::UnicastAckReq => {
                3 + self.source_len()? + self.sec_info()?.wire_len()
            }
            PacketType::Multicast | PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {
                2 + self.sec_info()?.wire_len()
            }
            PacketType::Reserved5 => return Err(BuildError::InvalidPacket),
        };
        Ok(1 + usize::from(self.flood_hops.is_some()) + fields)
    }

    /// Step the cursor over the options block, which `write_common_prefix`
    /// already moved into place. If a payload follows, append the `0xFF`
    /// end-of-options marker.
    fn emit_options(
        &mut self,
        cursor: &mut usize,
        has_payload: bool,
    ) -> Result<Range<usize>, BuildError> {
        debug_assert_eq!(Ok(*cursor), self.prefix_len());
        let start = *cursor;
        *cursor = start + self.options_len;
        if has_payload {
            let marker_slot = *cursor;
            if marker_slot >= self.buf.len() {
                return Err(BuildError::BufferTooSmall);
            }
            self.buf[marker_slot] = 0xFF;
            *cursor = marker_slot + 1;
        }
        Ok(start..*cursor)
    }

    /// Move the options block staged at `buf[1..1 + options_len]` to its
    /// final offset, then write FCF and FHOPS in front of it. Returns the
    /// cursor after FHOPS; the caller writes the rest of the prefix up to
    /// the options block, the fields that follow it, and finally moves the
    /// staged payload left into place.
    ///
    /// The options' final end is at or before the payload's final start,
    /// which is at or before its staged start at the tail of `buf`. So when
    /// the frame fits, no write lands on bytes that have yet to be moved.
    fn write_common_prefix(&mut self) -> Result<usize, BuildError> {
        if let Some(err) = self.option_error {
            return Err(err);
        }
        let options_start = self.prefix_len()?;
        let staged_payload_start = self.payload.as_ref().map_or(self.buf.len(), |p| p.start);
        if options_start + self.options_len > staged_payload_start {
            return Err(BuildError::BufferTooSmall);
        }
        self.buf.copy_within(1..1 + self.options_len, options_start);
        let full_source = matches!(self.source, Some(SourceValue::Full(_)));
        let fcf = Fcf::new(self.packet_type, full_source, self.flood_hops.is_some());
        self.buf[0] = fcf.0;
        let mut cursor = 1;
        if let Some(fhops) = self.flood_hops {
            self.buf
                .get_mut(cursor)
                .ok_or(BuildError::BufferTooSmall)
                .map(|slot| *slot = fhops.0)?;
            cursor += 1;
        }
        Ok(cursor)
    }

    fn write_source(&mut self, cursor: &mut usize) -> Result<(), BuildError> {
        match self.source {
            Some(SourceValue::Hint(hint)) => {
                let end = *cursor + 3;
                self.buf
                    .get_mut(*cursor..end)
                    .ok_or(BuildError::BufferTooSmall)?
                    .copy_from_slice(&hint.0);
                *cursor = end;
            }
            Some(SourceValue::Full(key)) => {
                let end = *cursor + 32;
                self.buf
                    .get_mut(*cursor..end)
                    .ok_or(BuildError::BufferTooSmall)?
                    .copy_from_slice(&key.0);
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

    /// Whether the staged payload actually carries bytes.
    ///
    /// An empty payload is no payload: the `0xFF` end-of-options marker is
    /// only required when data follows the options block, so staging `&[]`
    /// must not put a marker on the wire. Packet types whose addresses
    /// follow the options block need the marker regardless and do not
    /// consult this.
    fn has_body_bytes(&self) -> bool {
        self.payload.as_ref().is_some_and(|range| !range.is_empty())
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

    /// Write the zeroed trailer, `[SIG] ‖ MIC`, at `cursor`. Returns the
    /// signature slot when the frame is signed, and the MIC slot.
    fn write_trailer(
        &mut self,
        cursor: &mut usize,
    ) -> Result<(Option<Range<usize>>, Range<usize>), BuildError> {
        let signature = self.signed.then(|| *cursor..*cursor + SIGNATURE_LEN);
        let mic_start = signature.as_ref().map_or(*cursor, |range| range.end);
        let mic_end = mic_start + self.mic_size.byte_len();
        self.buf
            .get_mut(*cursor..mic_end)
            .ok_or(BuildError::BufferTooSmall)?
            .fill(0);
        *cursor = mic_end;
        Ok((signature, mic_start..mic_end))
    }

    fn stage_blind_addr(&mut self, cursor: &mut usize) -> Result<Range<usize>, BuildError> {
        let dst = self.dst.ok_or(BuildError::MissingDestination)?;
        let start = *cursor;
        let dst_end = start + 3;
        self.buf
            .get_mut(start..dst_end)
            .ok_or(BuildError::BufferTooSmall)?
            .copy_from_slice(&dst.0);
        *cursor = dst_end;
        self.write_source(cursor)?;
        let end = *cursor;
        Ok(start..end)
    }
}

impl<'a> BroadcastBuilder<'a, state::NeedsSource> {
    /// Encode the source address as a three-byte hint.
    pub fn source_hint(mut self, hint: NodeHint) -> BroadcastBuilder<'a, state::Configuring> {
        self.source = Some(SourceValue::Hint(hint));
        self.with_state()
    }

    /// Encode the source address as a full public key.
    pub fn source_full(mut self, key: &PublicKey) -> BroadcastBuilder<'a, state::Configuring> {
        self.source = Some(SourceValue::Full(*key));
        self.with_state()
    }
}

impl<'a> UnicastBuilder<'a, state::NeedsSource> {
    /// Encode the source address as a three-byte hint.
    pub fn source_hint(mut self, hint: NodeHint) -> UnicastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Hint(hint));
        self.with_state()
    }

    /// Encode the source address as a full public key.
    pub fn source_full(mut self, key: &PublicKey) -> UnicastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Full(*key));
        self.with_state()
    }
}

impl<'a> MulticastBuilder<'a, state::NeedsSource> {
    /// Encode the source address as a three-byte hint.
    pub fn source_hint(mut self, hint: NodeHint) -> MulticastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Hint(hint));
        self.with_state()
    }

    /// Encode the source address as a full public key.
    pub fn source_full(mut self, key: &PublicKey) -> MulticastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Full(*key));
        self.with_state()
    }
}

impl<'a> BlindUnicastBuilder<'a, state::NeedsSource> {
    /// Encode the source address as a three-byte hint.
    pub fn source_hint(mut self, hint: NodeHint) -> BlindUnicastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Hint(hint));
        self.with_state()
    }

    /// Encode the source address as a full public key.
    pub fn source_full(mut self, key: &PublicKey) -> BlindUnicastBuilder<'a, state::NeedsCounter> {
        self.source = Some(SourceValue::Full(*key));
        self.with_state()
    }
}

impl<'a> UnicastBuilder<'a, state::NeedsCounter> {
    /// Set the frame counter for the secure packet.
    pub fn frame_counter(mut self, counter: u32) -> UnicastBuilder<'a, state::Configuring> {
        self.frame_counter = Some(counter);
        self.with_state()
    }
}

impl<'a> MulticastBuilder<'a, state::NeedsCounter> {
    /// Set the frame counter for the secure packet.
    pub fn frame_counter(mut self, counter: u32) -> MulticastBuilder<'a, state::Configuring> {
        self.frame_counter = Some(counter);
        self.with_state()
    }
}

impl<'a> BlindUnicastBuilder<'a, state::NeedsCounter> {
    /// Set the frame counter for the secure packet.
    pub fn frame_counter(mut self, counter: u32) -> BlindUnicastBuilder<'a, state::Configuring> {
        self.frame_counter = Some(counter);
        self.with_state()
    }
}

macro_rules! impl_configuring_common {
    ($name:ident<$state:ty>) => {
        impl<'a> $name<'a, $state> {
            /// Set the initial flood-hop budget.
            pub fn flood_hops(mut self, remaining: u8) -> Self {
                if let Some(value) = FloodHops::new(remaining, 0) {
                    self.flood_hops = Some(value);
                }
                self
            }

            /// Add the region-code option.
            pub fn region_code(mut self, code: [u8; 2]) -> Self {
                self.push_option(OptionNumber::RegionCode.as_u16(), &code);
                self
            }

            /// Add an empty Trace option, which each hop extends.
            pub fn trace(mut self) -> Self {
                self.push_option(OptionNumber::Trace.as_u16(), &[]);
                self
            }

            /// Add a source-route option from a repeater-hint slice, one hint
            /// per repeater in send order.
            pub fn source_route(mut self, hints: &[crate::RouterHint]) -> Self {
                let mut encoded = [0u8; 30];
                let needed = hints.len() * 2;
                if needed > encoded.len() {
                    self.option_error = Some(BuildError::BufferTooSmall);
                    return self;
                }
                for (index, hint) in hints.iter().enumerate() {
                    encoded[index * 2..index * 2 + 2].copy_from_slice(&hint.0);
                }
                self.push_option(OptionNumber::SourceRoute.as_u16(), &encoded[..needed]);
                self
            }

            /// Add an arbitrary option number/value pair.
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
    /// Upgrade the packet type to ACK-requested unicast.
    pub fn ack_requested(mut self) -> Self {
        self.packet_type = PacketType::UnicastAckReq;
        self
    }

    /// Mark the packet body for encryption.
    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    /// Select the MIC size reserved in the packet footer.
    pub fn mic_size(mut self, size: MicSize) -> Self {
        self.mic_size = size;
        self
    }

    /// Attach an explicit salt value to SECINFO.
    pub fn salt(mut self, salt: u16) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Set `D` and reserve a zeroed signature slot before the MIC, to be
    /// filled through [`UnsealedPacket::signature_slot_mut`] before sealing.
    pub fn signed(mut self) -> Self {
        self.signed = true;
        self
    }

    /// Stage the application payload and advance to the terminal builder state.
    pub fn payload(mut self, data: &[u8]) -> UnicastBuilder<'a, state::Complete> {
        self.stage_payload(data);
        self.with_state()
    }
}

impl<'a> MulticastBuilder<'a, state::Configuring> {
    /// Mark the packet body for encryption.
    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    /// Select the MIC size reserved in the packet footer.
    pub fn mic_size(mut self, size: MicSize) -> Self {
        self.mic_size = size;
        self
    }

    /// Attach an explicit salt value to SECINFO.
    pub fn salt(mut self, salt: u16) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Set `D` and reserve a zeroed signature slot before the MIC, to be
    /// filled through [`UnsealedPacket::signature_slot_mut`] before sealing.
    pub fn signed(mut self) -> Self {
        self.signed = true;
        self
    }

    /// Stage the application payload and advance to the terminal builder state.
    pub fn payload(mut self, data: &[u8]) -> MulticastBuilder<'a, state::Complete> {
        self.stage_payload(data);
        self.with_state()
    }
}

impl<'a> BlindUnicastBuilder<'a, state::Configuring> {
    /// Upgrade the packet type to ACK-requested blind unicast.
    pub fn ack_requested(mut self) -> Self {
        self.packet_type = PacketType::BlindUnicastAckReq;
        self
    }

    /// Mark the body and blinded address block for encryption.
    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    /// Emit a blind-unicast packet without encrypting the payload.
    ///
    /// This exists primarily for tests and for explicit policy-rejection
    /// scenarios where higher layers need to construct a frame they expect to
    /// reject. Normal blind-unicast traffic should remain encrypted.
    pub fn unencrypted(mut self) -> Self {
        self.encrypted = false;
        self
    }

    /// Select the MIC size reserved in the packet footer.
    pub fn mic_size(mut self, size: MicSize) -> Self {
        self.mic_size = size;
        self
    }

    /// Attach an explicit salt value to SECINFO.
    pub fn salt(mut self, salt: u16) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Set `D` and reserve a zeroed signature slot before the MIC, to be
    /// filled through [`UnsealedPacket::signature_slot_mut`] before sealing.
    pub fn signed(mut self) -> Self {
        self.signed = true;
        self
    }

    /// Stage the application payload and advance to the terminal builder state.
    pub fn payload(mut self, data: &[u8]) -> BlindUnicastBuilder<'a, state::Complete> {
        self.stage_payload(data);
        self.with_state()
    }
}

impl<'a> BroadcastBuilder<'a, state::Configuring> {
    /// Add a Frame Signature option carrying `counter` and a zeroed
    /// signature, to be filled once the frame is built (its location is
    /// [`crate::PacketHeader::signature`]). Option 0 leads every other
    /// option, so it is added first.
    pub fn signed(mut self, counter: u32) -> Self {
        let mut value = [0u8; FRAME_SIGNATURE_OPTION_LEN];
        value[..4].copy_from_slice(&counter.to_be_bytes());
        self.push_option(OptionNumber::FrameSignature.as_u16(), &value);
        self
    }

    /// Stage a broadcast payload.
    pub fn payload(mut self, data: &[u8]) -> BroadcastBuilder<'a, state::Complete> {
        self.stage_payload(data);
        self.with_state()
    }

    /// Finalize the broadcast packet and return the written frame bytes.
    ///
    /// Layout: `FCF [FHOPS] SRC OPTIONS [0xFF PAYLOAD]`
    pub fn build(mut self) -> Result<&'a [u8], BuildError> {
        let has_payload = self.has_body_bytes();
        let mut cursor = self.write_common_prefix()?;
        self.write_source(&mut cursor)?;
        self.emit_options(&mut cursor, has_payload)?;
        if has_payload {
            let _ = self.copy_staged_payload(&mut cursor)?;
        }
        Ok(&self.buf[..cursor])
    }
}

impl<'a> BroadcastBuilder<'a, state::Complete> {
    /// Finalize the broadcast packet and return the written frame bytes.
    pub fn build(self) -> Result<&'a [u8], BuildError> {
        self.with_state::<state::Configuring>().build()
    }
}

impl<'a> MacAckBuilder<'a, state::Configuring> {
    /// Finalize the MAC ACK packet and return the written frame bytes.
    ///
    /// Layout: `FCF [FHOPS] OPTIONS ACK_TRAILER(8)` where the trailer is
    /// `ack_mic(4) || ack_tag(4)`. There is no destination hint. The `0xFF`
    /// end-marker is omitted—the trailer is at a fixed offset from the end.
    pub fn build(mut self) -> Result<&'a [u8], BuildError> {
        let mut cursor = self.write_common_prefix()?;
        self.emit_options(&mut cursor, false)?;
        let ack_trailer = self.ack_tag.ok_or(BuildError::MissingAckTag)?;
        self.buf
            .get_mut(cursor..cursor + 8)
            .ok_or(BuildError::BufferTooSmall)?
            .copy_from_slice(&ack_trailer);
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
    /// Layout: `FCF [FHOPS] DST SRC SECINFO OPTIONS [0xFF PAYLOAD] MIC`
    pub fn build(mut self) -> Result<UnsealedPacket<'a>, BuildError> {
        let has_payload = self.has_body_bytes();
        let mut cursor = self.write_common_prefix()?;
        let dst = self.dst.ok_or(BuildError::MissingDestination)?;
        self.buf
            .get_mut(cursor..cursor + 3)
            .ok_or(BuildError::BufferTooSmall)?
            .copy_from_slice(&dst.0);
        cursor += 3;
        self.write_source(&mut cursor)?;
        let sec_info = self.sec_info()?;
        let sec_start = cursor;
        cursor += sec_info.encode(
            self.buf
                .get_mut(cursor..)
                .ok_or(BuildError::BufferTooSmall)?,
        )?;
        let opts_range = self.emit_options(&mut cursor, has_payload)?;
        let body_start = cursor;
        let body_range = if has_payload {
            self.copy_staged_payload(&mut cursor)?
        } else {
            body_start..body_start
        };
        let (signature_range, mic_range) = self.write_trailer(&mut cursor)?;
        Ok(UnsealedPacket::new(
            self.buf,
            cursor,
            body_range,
            None,
            signature_range,
            mic_range,
            sec_start..sec_start + sec_info.wire_len(),
            opts_range,
        ))
    }
}

impl<'a> MulticastBuilder<'a, state::Complete> {
    pub fn build(self) -> Result<UnsealedPacket<'a>, BuildError> {
        self.with_state::<state::Configuring>().build()
    }
}

impl<'a> MulticastBuilder<'a, state::Configuring> {
    /// Layout (E=1): `FCF [FHOPS] CHANNEL SECINFO OPTIONS 0xFF ENC(SRC+PAYLOAD) MIC`
    /// Layout (E=0): `FCF [FHOPS] CHANNEL SECINFO OPTIONS 0xFF SRC [PAYLOAD] MIC`
    pub fn build(mut self) -> Result<UnsealedPacket<'a>, BuildError> {
        let mut cursor = self.write_common_prefix()?;
        let channel = self.channel.ok_or(BuildError::MissingChannel)?;
        self.buf
            .get_mut(cursor..cursor + 2)
            .ok_or(BuildError::BufferTooSmall)?
            .copy_from_slice(&channel.0);
        cursor += 2;
        let sec_info = self.sec_info()?;
        let sec_start = cursor;
        cursor += sec_info.encode(
            self.buf
                .get_mut(cursor..)
                .ok_or(BuildError::BufferTooSmall)?,
        )?;
        // SRC (and optionally payload) always follow OPTIONS, so 0xFF is always emitted.
        let opts_range = self.emit_options(&mut cursor, true)?;
        let body_start = cursor;
        self.write_source(&mut cursor)?;
        let payload_range = self.copy_staged_payload(&mut cursor)?;
        let body_range = if self.encrypted {
            body_start..payload_range.end
        } else {
            payload_range
        };
        let (signature_range, mic_range) = self.write_trailer(&mut cursor)?;
        Ok(UnsealedPacket::new(
            self.buf,
            cursor,
            body_range,
            None,
            signature_range,
            mic_range,
            sec_start..sec_start + sec_info.wire_len(),
            opts_range,
        ))
    }
}

impl<'a> BlindUnicastBuilder<'a, state::Complete> {
    pub fn build(self) -> Result<UnsealedPacket<'a>, BuildError> {
        self.with_state::<state::Configuring>().build()
    }
}

impl<'a> BlindUnicastBuilder<'a, state::Configuring> {
    /// Layout (E=1): `FCF [FHOPS] CHANNEL SECINFO OPTIONS 0xFF ENC_DST_SRC ENC_PAYLOAD MIC`
    /// Layout (E=0): `FCF [FHOPS] CHANNEL SECINFO OPTIONS 0xFF DST SRC [PAYLOAD] MIC`
    pub fn build(mut self) -> Result<UnsealedPacket<'a>, BuildError> {
        let mut cursor = self.write_common_prefix()?;
        let channel = self.channel.ok_or(BuildError::MissingChannel)?;
        self.buf
            .get_mut(cursor..cursor + 2)
            .ok_or(BuildError::BufferTooSmall)?
            .copy_from_slice(&channel.0);
        cursor += 2;
        let sec_info = self.sec_info()?;
        let sec_start = cursor;
        cursor += sec_info.encode(
            self.buf
                .get_mut(cursor..)
                .ok_or(BuildError::BufferTooSmall)?,
        )?;
        // DST+SRC (and optionally payload) always follow OPTIONS, so 0xFF is always emitted.
        let opts_range = self.emit_options(&mut cursor, true)?;
        let blind_addr_range = self.stage_blind_addr(&mut cursor)?;
        let body_range = self.copy_staged_payload(&mut cursor)?;
        let (signature_range, mic_range) = self.write_trailer(&mut cursor)?;
        Ok(UnsealedPacket::new(
            self.buf,
            cursor,
            body_range,
            Some(blind_addr_range),
            signature_range,
            mic_range,
            sec_start..sec_start + sec_info.wire_len(),
            opts_range,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::vec::Vec;

    /// The largest LoRa frame.
    const MAX_FRAME: usize = 255;

    /// A 68-byte value under a static, non-critical option number: large
    /// enough that staging the options twice no longer fits.
    const LARGE_OPTION: OptionNumber = OptionNumber::Unknown(300);
    const LARGE_VALUE: [u8; 68] = [0xA5; 68];

    const SRC_HINT: NodeHint = NodeHint([0xA1, 0xB2, 0x03]);
    const SRC_FULL: PublicKey = PublicKey([0xA1; 32]);
    const DST: NodeHint = NodeHint([0xC3, 0xD4, 0x25]);
    const CHANNEL: ChannelId = ChannelId([0x7E, 0x5F]);

    type Build = fn(&mut [u8], &[u8]) -> Result<Vec<u8>, BuildError>;

    /// Probe the overhead with a one-byte payload, then check that a payload
    /// of exactly `MAX_FRAME - overhead` builds into a `MAX_FRAME` buffer,
    /// producing the same bytes as in a roomy buffer, and that one byte more
    /// does not.
    fn assert_exact_fit(build: Build) {
        let mut probe = [0u8; 2 * MAX_FRAME];
        let overhead = build(&mut probe, &[0x5A]).unwrap().len() - 1;
        let payload: Vec<u8> = (0..=MAX_FRAME - overhead).map(|i| i as u8).collect();
        let (fits, over) = (&payload[..MAX_FRAME - overhead], &payload[..]);

        let mut roomy = [0u8; 2 * MAX_FRAME];
        let expected = build(&mut roomy, fits).unwrap();
        assert_eq!(expected.len(), MAX_FRAME);

        let mut exact = [0u8; MAX_FRAME];
        assert_eq!(build(&mut exact, fits).unwrap(), expected);

        let mut exact = [0u8; MAX_FRAME];
        assert_eq!(build(&mut exact, over), Err(BuildError::BufferTooSmall));
    }

    #[test]
    fn broadcast_fills_max_frame() {
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .broadcast()
                .source_hint(SRC_HINT)
                .payload(payload)
                .build()
                .map(<[u8]>::to_vec)
        });
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .broadcast()
                .source_full(&SRC_FULL)
                .flood_hops(5)
                .region_code([0x78, 0x53])
                .option(LARGE_OPTION, &LARGE_VALUE)
                .payload(payload)
                .build()
                .map(<[u8]>::to_vec)
        });
    }

    #[test]
    fn unicast_fills_max_frame() {
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .unicast(DST)
                .source_hint(SRC_HINT)
                .frame_counter(42)
                .encrypted()
                .payload(payload)
                .build()
                .map(|packet| packet.as_bytes().to_vec())
        });
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .unicast(DST)
                .source_full(&SRC_FULL)
                .frame_counter(42)
                .ack_requested()
                .encrypted()
                .salt(0x1234)
                .flood_hops(3)
                .trace()
                .option(LARGE_OPTION, &LARGE_VALUE)
                .payload(payload)
                .build()
                .map(|packet| packet.as_bytes().to_vec())
        });
    }

    #[test]
    fn multicast_fills_max_frame() {
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .multicast(CHANNEL)
                .source_hint(SRC_HINT)
                .frame_counter(42)
                .encrypted()
                .payload(payload)
                .build()
                .map(|packet| packet.as_bytes().to_vec())
        });
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .multicast(CHANNEL)
                .source_full(&SRC_FULL)
                .frame_counter(42)
                .encrypted()
                .salt(0x1234)
                .flood_hops(5)
                .option(LARGE_OPTION, &LARGE_VALUE)
                .payload(payload)
                .build()
                .map(|packet| packet.as_bytes().to_vec())
        });
    }

    #[test]
    fn blind_unicast_fills_max_frame() {
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .blind_unicast(CHANNEL, DST)
                .source_hint(SRC_HINT)
                .frame_counter(42)
                .payload(payload)
                .build()
                .map(|packet| packet.as_bytes().to_vec())
        });
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .blind_unicast(CHANNEL, DST)
                .source_full(&SRC_FULL)
                .frame_counter(42)
                .ack_requested()
                .salt(0x1234)
                .flood_hops(5)
                .option(LARGE_OPTION, &LARGE_VALUE)
                .payload(payload)
                .build()
                .map(|packet| packet.as_bytes().to_vec())
        });
    }

    /// A signed frame of each type fills the frame exactly, including a
    /// full-source broadcast with its 70-byte Frame Signature option.
    #[test]
    fn signed_frames_fill_max_frame() {
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .broadcast()
                .source_full(&SRC_FULL)
                .signed(7)
                .payload(payload)
                .build()
                .map(<[u8]>::to_vec)
        });
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .unicast(DST)
                .source_full(&SRC_FULL)
                .frame_counter(42)
                .signed()
                .payload(payload)
                .build()
                .map(|packet| packet.as_bytes().to_vec())
        });
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .multicast(CHANNEL)
                .source_full(&SRC_FULL)
                .frame_counter(42)
                .encrypted()
                .signed()
                .flood_hops(5)
                .payload(payload)
                .build()
                .map(|packet| packet.as_bytes().to_vec())
        });
        assert_exact_fit(|buf, payload| {
            PacketBuilder::new(buf)
                .blind_unicast(CHANNEL, DST)
                .source_full(&SRC_FULL)
                .frame_counter(42)
                .signed()
                .payload(payload)
                .build()
                .map(|packet| packet.as_bytes().to_vec())
        });

        // The full-source signed broadcast leaves 151 payload bytes.
        let mut probe = [0u8; 2 * MAX_FRAME];
        let overhead = PacketBuilder::new(&mut probe)
            .broadcast()
            .source_full(&SRC_FULL)
            .signed(7)
            .payload(&[0])
            .build()
            .unwrap()
            .len()
            - 1;
        assert_eq!(MAX_FRAME - overhead, 151);
    }

    /// A MAC ACK has no payload, so its options fill the frame instead.
    #[test]
    fn mac_ack_fills_max_frame() {
        fn build(buf: &mut [u8], value: &[u8]) -> Result<Vec<u8>, BuildError> {
            PacketBuilder::new(buf)
                .mac_ack([0x11; 8])
                .flood_hops(5)
                .region_code([0x78, 0x53])
                .option(LARGE_OPTION, value)
                .build()
                .map(<[u8]>::to_vec)
        }
        let filler = [0xA5u8; MAX_FRAME];
        let mut roomy = [0u8; 2 * MAX_FRAME];
        let fill_len = (0..MAX_FRAME)
            .find(|&len| build(&mut roomy, &filler[..len]).unwrap().len() == MAX_FRAME)
            .unwrap();
        let expected = build(&mut roomy, &filler[..fill_len]).unwrap();

        let mut exact = [0u8; MAX_FRAME];
        assert_eq!(build(&mut exact, &filler[..fill_len]).unwrap(), expected);

        let mut short = [0u8; MAX_FRAME - 1];
        assert_eq!(
            build(&mut short, &filler[..fill_len]),
            Err(BuildError::BufferTooSmall)
        );
    }

    /// The builder adds nothing a frame was not given.
    #[test]
    fn a_frame_carries_no_fence_unless_given_one() {
        let mut buf = [0u8; 2 * MAX_FRAME];
        let frame = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(SRC_HINT)
            .payload(b"hi")
            .build()
            .unwrap()
            .to_vec();
        let header = crate::PacketHeader::parse(&frame).unwrap();
        assert_eq!(crate::iter_options(&frame, header.options_range).count(), 0);
    }

    /// The fence is recognized: it stops no forwarding and no delivery.
    #[test]
    fn the_fence_is_recognized_and_ignored() {
        let mut buf = [0u8; 2 * MAX_FRAME];
        let frame = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(SRC_HINT)
            .option(OptionNumber::Fence, &[])
            .payload(b"hi")
            .build()
            .unwrap()
            .to_vec();
        let header = crate::PacketHeader::parse(&frame).unwrap();
        let options = crate::ParsedOptions::extract(&frame, header.options_range).unwrap();
        assert!(!options.refuses_forwarding());
        assert!(!options.refuses_delivery());
        assert!(options.has_static);
    }
}
