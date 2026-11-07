#![allow(async_fn_in_trait)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Cryptographic traits and UMSH-specific key/packet operations.
//!
//! This crate separates algorithm providers from protocol logic. The low-level
//! traits such as [`AesProvider`] and [`Sha256Provider`] can be backed either by
//! software implementations or hardware accelerators, while [`CryptoEngine`]
//! implements the UMSH-specific derivation and packet-authentication rules.
//!
//! # Example
//!
//! ```rust
//! use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
//! use umsh_crypto::{CryptoEngine, NodeIdentity};
//!
//! let alice = SoftwareIdentity::from_secret_bytes(&[0x11; 32]);
//! let bob = SoftwareIdentity::from_secret_bytes(&[0x22; 32]);
//! let shared = alice.shared_secret_with(bob.public_key()).unwrap();
//! let engine = CryptoEngine::new(SoftwareAes, SoftwareSha256);
//! let keys = engine.derive_pairwise_keys(&shared, alice.public_key(), bob.public_key());
//!
//! assert_ne!(keys.k_enc, [0u8; 32]);
//! assert_ne!(keys.k_mic, [0u8; 32]);
//! ```

use core::ops::Range;

use umsh_core::{
    BlindAddr, ChannelCommitment, ChannelId, ChannelKey, ChannelTag, NodeHint, PacketHeader,
    PacketType, ParsedOptions, PublicKey, SourceAddrRef, UnsealedPacket, feed_aad,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod pool;
pub mod replay;

/// AES block-cipher instance used by the protocol engine.
pub trait AesCipher {
    /// Encrypt one 16-byte block in place.
    fn encrypt_block(&self, block: &mut [u8; 16]);
    /// Decrypt one 16-byte block in place.
    fn decrypt_block(&self, block: &mut [u8; 16]);
}

impl<C: AesCipher + ?Sized> AesCipher for &C {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        (**self).encrypt_block(block);
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        (**self).decrypt_block(block);
    }
}

/// Factory for keyed AES cipher instances.
pub trait AesProvider {
    /// Concrete cipher type returned by [`new_cipher`](Self::new_cipher).
    type Cipher: AesCipher;

    /// Create a new AES-256 cipher using `key`.
    fn new_cipher(&self, key: &[u8; 32]) -> Self::Cipher;
}

/// SHA-256 and HMAC-SHA-256 provider.
pub trait Sha256Provider {
    /// Hash a list of borrowed byte slices as one concatenated message.
    fn hash(&self, data: &[&[u8]]) -> [u8; 32];
    /// Compute HMAC-SHA-256 over a list of borrowed byte slices.
    fn hmac(&self, key: &[u8], data: &[&[u8]]) -> [u8; 32];
}

/// Raw X25519 shared secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

/// Node identity capable of signing and key agreement.
pub trait NodeIdentity {
    type Error;

    /// Return the long-term Ed25519 public key for this identity.
    fn public_key(&self) -> &PublicKey;

    /// Return the three-byte node hint derived from [`public_key`](Self::public_key).
    fn hint(&self) -> umsh_core::NodeHint {
        self.public_key().hint()
    }

    /// Sign an arbitrary message.
    async fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error>;
    /// Perform X25519-style key agreement with a peer public key.
    async fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, Self::Error>;
}

/// Protocol-level crypto failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidPublicKey,
    InvalidSharedSecret,
    InvalidPacket,
    AuthenticationFailed,
}

/// Maximum channel-name length accepted by
/// [`CryptoEngine::derive_named_channel_key`].
///
/// This is an implementation limit of the no-alloc canonicalization buffer,
/// not a protocol constant; the spec places no length bound on named
/// channels.
pub const MAX_CHANNEL_NAME_LEN: usize = 64;

/// Error returned when a channel name cannot be canonicalized for key
/// derivation (see multicast-channels.md § Named Channels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelNameError {
    /// The name contains non-ASCII characters. UTF-8 names are deferred by
    /// the spec because Unicode case-folding is non-trivial.
    NotAscii,
    /// The name exceeds [`MAX_CHANNEL_NAME_LEN`].
    TooLong,
}

/// Derived pairwise transport keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PairwiseKeys {
    pub k_enc: [u8; 32],
    pub k_mic: [u8; 32],
}

/// A blind unicast's address block, recovered by
/// [`CryptoEngine::decrypt_blind_addr`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenedBlindAddr {
    /// The destination hint.
    pub dst: NodeHint,
    /// The source, as a hint or as the offset of a full key in the
    /// (now plaintext) frame.
    pub source: SourceAddrRef,
    /// The plaintext block, which [`CryptoEngine::open_packet`] needs for
    /// the AAD.
    pub addr: BlindAddr,
}

/// Derived multicast or channel transport keys.
#[derive(Clone)]
pub struct DerivedChannelKeys {
    pub k_enc: [u8; 32],
    pub k_mic: [u8; 32],
    pub channel_id: ChannelId,
    /// What a frame signature on this channel covers. Cached so receive
    /// paths need not rerun HKDF per frame.
    pub commitment: ChannelCommitment,
}

impl Zeroize for DerivedChannelKeys {
    fn zeroize(&mut self) {
        self.k_enc.zeroize();
        self.k_mic.zeroize();
    }
}

impl Drop for DerivedChannelKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Incremental AES-CMAC state.
pub struct CmacState<C: AesCipher> {
    cipher: C,
    state: [u8; 16],
    buffer: [u8; 16],
    pos: usize,
    k1: [u8; 16],
    k2: [u8; 16],
}

impl<C: AesCipher> CmacState<C> {
    /// Initialize a new incremental CMAC state.
    pub fn new(cipher: C) -> Self {
        let mut l = [0u8; 16];
        cipher.encrypt_block(&mut l);
        let k1 = dbl(&l);
        let k2 = dbl(&k1);
        Self {
            cipher,
            state: [0u8; 16],
            buffer: [0u8; 16],
            pos: 0,
            k1,
            k2,
        }
    }

    /// Feed additional bytes into the MAC state.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let space = 16 - self.pos;
            let take = space.min(data.len());
            self.buffer[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];
            if self.pos == 16 && !data.is_empty() {
                self.process_buffer();
            }
        }
    }

    /// Finalize and return the full 16-byte CMAC value.
    pub fn finalize(self) -> [u8; 16] {
        let this = self;
        let mut last = [0u8; 16];
        if this.pos == 16 {
            last.copy_from_slice(&this.buffer);
            xor_in_place(&mut last, &this.k1);
        } else {
            last[..this.pos].copy_from_slice(&this.buffer[..this.pos]);
            last[this.pos] = 0x80;
            xor_in_place(&mut last, &this.k2);
        }

        xor_in_place(&mut last, &this.state);
        this.cipher.encrypt_block(&mut last);
        last
    }

    fn process_buffer(&mut self) {
        let mut block = self.buffer;
        xor_in_place(&mut block, &self.state);
        self.cipher.encrypt_block(&mut block);
        self.state = block;
        self.buffer = [0u8; 16];
        self.pos = 0;
    }
}

/// Incremental RFC 5297 §2.4 S2V state.
///
/// Associated-data components are absorbed one at a time with
/// [`push_component`](Self::push_component); the final vector component (the
/// plaintext) is supplied to [`finalize`](Self::finalize), which returns the
/// synthetic IV `V`. The state borrows a single keyed cipher, so one key
/// schedule serves every CMAC in the computation.
pub struct S2vState<'a, C: AesCipher> {
    cipher: &'a C,
    d: [u8; 16],
}

impl<'a, C: AesCipher> S2vState<'a, C> {
    /// Initialize the running value: `D = CMAC(K, <zero>)`.
    pub fn new(cipher: &'a C) -> Self {
        let mut cmac = CmacState::new(cipher);
        cmac.update(&[0u8; 16]);
        Self {
            cipher,
            d: cmac.finalize(),
        }
    }

    /// Absorb one associated-data component `S_i`, streamed through `feed`:
    /// `D = dbl(D) xor CMAC(K, S_i)`.
    pub fn push_component(&mut self, feed: impl FnOnce(&mut CmacState<&'a C>)) {
        let mut cmac = CmacState::new(self.cipher);
        feed(&mut cmac);
        let mac = cmac.finalize();
        self.d = dbl(&self.d);
        xor_in_place(&mut self.d, &mac);
    }

    /// Finish with the final component `S_n` and return `V`.
    ///
    /// Per RFC 5297: `V = CMAC(K, S_n xorend D)` when `S_n` fills a block,
    /// otherwise `V = CMAC(K, dbl(D) xor pad(S_n))`.
    pub fn finalize(self, last: &[u8]) -> [u8; 16] {
        let mut cmac = CmacState::new(self.cipher);
        if last.len() >= 16 {
            let split = last.len() - 16;
            cmac.update(&last[..split]);
            let mut tail = [0u8; 16];
            tail.copy_from_slice(&last[split..]);
            xor_in_place(&mut tail, &self.d);
            cmac.update(&tail);
        } else {
            let mut block = dbl(&self.d);
            for (dst, byte) in block.iter_mut().zip(last) {
                *dst ^= *byte;
            }
            block[last.len()] ^= 0x80;
            cmac.update(&block);
        }
        cmac.finalize()
    }
}

/// UMSH protocol crypto engine.
pub struct CryptoEngine<A: AesProvider, S: Sha256Provider> {
    aes: A,
    sha: S,
}

impl<A: AesProvider, S: Sha256Provider> CryptoEngine<A, S> {
    /// Create a new engine from algorithm providers.
    pub fn new(aes: A, sha: S) -> Self {
        Self { aes, sha }
    }

    /// Derive stable pairwise encryption and MIC keys from a shared secret.
    ///
    /// The 64-byte HKDF output is the RFC 5297 AES-SIV key `K = K1 || K2`:
    /// `k_mic` is the leftmost half (the S2V key `K1`) and `k_enc` is the
    /// rightmost half (the CTR key `K2`).
    pub fn derive_pairwise_keys(
        &self,
        shared_secret: &SharedSecret,
        local: &PublicKey,
        remote: &PublicKey,
    ) -> PairwiseKeys {
        let mut okm = [0u8; 64];
        self.hkdf(
            &shared_secret.0,
            b"UMSH-PAIRWISE-SALT",
            &pairwise_info(local, remote),
            &mut okm,
        );
        let mut keys = PairwiseKeys {
            k_enc: [0u8; 32],
            k_mic: [0u8; 32],
        };
        keys.k_mic.copy_from_slice(&okm[..32]);
        keys.k_enc.copy_from_slice(&okm[32..64]);
        okm.zeroize();
        keys
    }

    /// Derive the channel identifier from a raw channel key.
    pub fn derive_channel_id(&self, channel_key: &ChannelKey) -> ChannelId {
        let mut out = [0u8; 2];
        self.hkdf(&channel_key.0, b"UMSH-CHAN-ID", b"", &mut out);
        ChannelId(out)
    }

    /// Derive three bytes for presentation—a deterministic color a user
    /// interface can give a channel.
    ///
    /// This is the channel-identifier derivation run one byte longer, so the
    /// first two bytes are the channel identifier itself: HKDF-Expand emits a
    /// prefix of the same block either way. Nothing on the wire carries the
    /// third byte, and nothing depends on it.
    pub fn derive_channel_tint(&self, channel_key: &ChannelKey) -> [u8; 3] {
        let mut out = [0u8; 3];
        self.hkdf(&channel_key.0, b"UMSH-CHAN-ID", b"", &mut out);
        out
    }

    /// Derive the channel tag—a local identity wide enough to tell apart two
    /// channels whose keys derive the same channel identifier.
    ///
    /// Same derivation as the channel identifier, run to sixteen bytes, so the
    /// identifier and the presentation tint are prefixes of it.
    pub fn derive_channel_tag(&self, channel_key: &ChannelKey) -> ChannelTag {
        let mut out = [0u8; 16];
        self.hkdf(&channel_key.0, b"UMSH-CHAN-ID", b"", &mut out);
        ChannelTag(out)
    }

    /// Derive the channel commitment, which a frame signature on the channel
    /// covers.
    ///
    /// Same derivation as the channel tag, run to 32 bytes: 128 bits would
    /// leave a 2^64 collision search to someone choosing both channels, and
    /// the commitment is never transmitted, so its length costs nothing.
    pub fn derive_channel_commitment(&self, channel_key: &ChannelKey) -> ChannelCommitment {
        let mut out = [0u8; 32];
        self.hkdf(&channel_key.0, b"UMSH-CHAN-ID", b"", &mut out);
        ChannelCommitment(out)
    }

    /// Derive multicast transport keys and the channel identifier.
    ///
    /// As with [`derive_pairwise_keys`](Self::derive_pairwise_keys), the
    /// 64-byte HKDF output is the RFC 5297 AES-SIV key: S2V key first, CTR
    /// key second.
    pub fn derive_channel_keys(&self, channel_key: &ChannelKey) -> DerivedChannelKeys {
        let commitment = self.derive_channel_commitment(channel_key);
        let channel_id = commitment.channel_tag().channel_id();
        let mut info = [0u8; 15];
        info[..13].copy_from_slice(b"UMSH-MCAST-V2");
        info[13..15].copy_from_slice(&channel_id.0);
        let mut okm = [0u8; 64];
        self.hkdf(&channel_key.0, b"UMSH-MCAST-SALT", &info, &mut okm);
        let mut derived = DerivedChannelKeys {
            k_enc: [0u8; 32],
            k_mic: [0u8; 32],
            channel_id,
            commitment,
        };
        derived.k_mic.copy_from_slice(&okm[..32]);
        derived.k_enc.copy_from_slice(&okm[32..64]);
        okm.zeroize();
        derived
    }

    /// Combine pairwise and channel keys for blind-unicast payload protection.
    pub fn derive_blind_keys(
        &self,
        pairwise: &PairwiseKeys,
        channel: &DerivedChannelKeys,
    ) -> PairwiseKeys {
        let mut keys = PairwiseKeys {
            k_enc: [0u8; 32],
            k_mic: [0u8; 32],
        };
        for (dst, (left, right)) in keys
            .k_enc
            .iter_mut()
            .zip(pairwise.k_enc.iter().zip(channel.k_enc.iter()))
        {
            *dst = left ^ right;
        }
        for (dst, (left, right)) in keys
            .k_mic
            .iter_mut()
            .zip(pairwise.k_mic.iter().zip(channel.k_mic.iter()))
        {
            *dst = left ^ right;
        }
        keys
    }

    /// Derive a channel key from a human-readable channel name.
    ///
    /// The name is canonicalized first, per the spec (multicast-channels.md
    /// § Named Channels): it must be ASCII, and ASCII letters are folded to
    /// lowercase before derivation—so `Public`, `public`, and `PUBLIC` all
    /// derive the same key. Non-ASCII names are rejected (UTF-8 case-folding
    /// is deferred by the spec). Names longer than
    /// [`MAX_CHANNEL_NAME_LEN`] are rejected as an implementation limit of
    /// the no-alloc canonicalization buffer.
    pub fn derive_named_channel_key(&self, name: &str) -> Result<ChannelKey, ChannelNameError> {
        let bytes = name.as_bytes();
        if bytes.len() > MAX_CHANNEL_NAME_LEN {
            return Err(ChannelNameError::TooLong);
        }
        if !name.is_ascii() {
            return Err(ChannelNameError::NotAscii);
        }
        let mut canonical = [0u8; MAX_CHANNEL_NAME_LEN];
        for (dst, byte) in canonical.iter_mut().zip(bytes) {
            *dst = byte.to_ascii_lowercase();
        }
        Ok(ChannelKey(
            self.sha
                .hmac(b"UMSH-CHANNEL-V1", &[&canonical[..bytes.len()]]),
        ))
    }

    /// Seal a unicast or multicast packet in place.
    pub fn seal_packet(
        &self,
        packet: &mut UnsealedPacket<'_>,
        keys: &PairwiseKeys,
    ) -> Result<usize, CryptoError> {
        let header = packet.header().map_err(|_| CryptoError::InvalidPacket)?;
        let sec_info = header.sec_info.ok_or(CryptoError::InvalidPacket)?;
        let full_mac = self.packet_tag(&keys.k_mic, &header, packet.as_bytes(), None)?;

        let mic_len = sec_info
            .scf
            .mic_size()
            .map_err(|_| CryptoError::InvalidPacket)?
            .byte_len();
        packet.mic_slot()[..mic_len].copy_from_slice(&full_mac[..mic_len]);

        if sec_info.scf.encrypted() {
            let iv = self.build_ctr_iv(
                &full_mac[..mic_len],
                &packet.as_bytes()[packet.sec_info_range()],
            );
            self.aes_ctr(
                &keys.k_enc,
                &iv,
                &mut packet.as_bytes_mut()[header.protected_range()],
            );
        }

        Ok(mic_len)
    }

    /// Seal a blind-unicast packet, including its hidden address block.
    ///
    /// The MIC covers the plaintext address block through the AAD; only then
    /// is the block encrypted, under an IV derived from that MIC.
    pub fn seal_blind_packet(
        &self,
        packet: &mut UnsealedPacket<'_>,
        blind_keys: &PairwiseKeys,
        channel_keys: &DerivedChannelKeys,
    ) -> Result<usize, CryptoError> {
        let header = packet.header().map_err(|_| CryptoError::InvalidPacket)?;
        let sec_info = header.sec_info.ok_or(CryptoError::InvalidPacket)?;
        let blind_addr_range = header
            .blind_addr_range()
            .ok_or(CryptoError::InvalidPacket)?;
        let blind_addr = BlindAddr::from_plaintext(&packet.as_bytes()[blind_addr_range.clone()])
            .ok_or(CryptoError::InvalidPacket)?;
        let full_mac = self.packet_tag(
            &blind_keys.k_mic,
            &header,
            packet.as_bytes(),
            Some(&blind_addr),
        )?;

        let mic_len = sec_info
            .scf
            .mic_size()
            .map_err(|_| CryptoError::InvalidPacket)?
            .byte_len();
        let iv = self.build_ctr_iv(
            &full_mac[..mic_len],
            &packet.as_bytes()[packet.sec_info_range()],
        );
        packet.mic_slot()[..mic_len].copy_from_slice(&full_mac[..mic_len]);
        if sec_info.scf.encrypted() {
            let bytes = packet.as_bytes_mut();
            self.aes_ctr(&blind_keys.k_enc, &iv, &mut bytes[header.protected_range()]);
            self.aes_ctr(&channel_keys.k_enc, &iv, &mut bytes[blind_addr_range]);
        }
        Ok(mic_len)
    }

    /// Verify and, if needed, decrypt a received secure packet in place,
    /// returning the payload's range.
    ///
    /// A blind unicast needs its plaintext address block, from
    /// [`Self::decrypt_blind_addr`]; every other type takes `None`.
    ///
    /// A failed open leaves `buf` exactly as it was, so a caller can try the
    /// next candidate key on the same bytes.
    pub fn open_packet(
        &self,
        buf: &mut [u8],
        header: &PacketHeader,
        keys: &PairwiseKeys,
        blind_addr: Option<&BlindAddr>,
    ) -> Result<Range<usize>, CryptoError> {
        let sec_info = header.sec_info.ok_or(CryptoError::InvalidPacket)?;
        let protected = header.protected_range();
        if protected.end > buf.len() || header.mic_range.end > buf.len() {
            return Err(CryptoError::InvalidPacket);
        }
        let mut mic = [0u8; 16];
        let mic_len = header.mic_range.end - header.mic_range.start;
        mic[..mic_len].copy_from_slice(&buf[header.mic_range.clone()]);
        let iv = if sec_info.scf.encrypted() {
            let iv = self.build_ctr_iv(&mic[..mic_len], &buf[sec_info_bytes_range(header)?]);
            self.aes_ctr(&keys.k_enc, &iv, &mut buf[protected.clone()]);
            Some(iv)
        } else {
            None
        };

        let verified = self
            .packet_tag(&keys.k_mic, header, buf, blind_addr)
            .and_then(|full_mac| {
                if constant_time_eq(&mic[..mic_len], &full_mac[..mic_len]) {
                    Ok(())
                } else {
                    Err(CryptoError::AuthenticationFailed)
                }
            });
        if let Err(err) = verified {
            // CTR is its own inverse: the same keystream restores the input.
            if let Some(iv) = iv {
                self.aes_ctr(&keys.k_enc, &iv, &mut buf[protected]);
            }
            return Err(err);
        }

        let body_range = match (header.packet_type(), header.source) {
            (PacketType::Multicast, SourceAddrRef::Encrypted { len, .. }) => {
                (protected.start + len)..header.body_range.end
            }
            _ => header.body_range.clone(),
        };
        Ok(body_range)
    }

    /// Recover the plaintext address block of a blind unicast, decrypting it
    /// in place when the frame is encrypted.
    pub fn decrypt_blind_addr(
        &self,
        buf: &mut [u8],
        header: &PacketHeader,
        channel_keys: &DerivedChannelKeys,
    ) -> Result<OpenedBlindAddr, CryptoError> {
        let range = header
            .blind_addr_range()
            .ok_or(CryptoError::InvalidPacket)?;
        let source = match header.source {
            SourceAddrRef::Encrypted { offset, len } => {
                if offset != range.start + 3 {
                    return Err(CryptoError::InvalidPacket);
                }
                let iv = self.build_ctr_iv(
                    &buf[header.mic_range.clone()],
                    &buf[sec_info_bytes_range(header)?],
                );
                self.aes_ctr(&channel_keys.k_enc, &iv, &mut buf[range.clone()]);
                match len {
                    3 => SourceAddrRef::Hint(NodeHint([
                        buf[offset],
                        buf[offset + 1],
                        buf[offset + 2],
                    ])),
                    32 => SourceAddrRef::FullKeyAt { offset },
                    _ => return Err(CryptoError::InvalidPacket),
                }
            }
            source @ (SourceAddrRef::Hint(_) | SourceAddrRef::FullKeyAt { .. }) => source,
            SourceAddrRef::None => return Err(CryptoError::InvalidPacket),
        };
        let addr = BlindAddr::from_plaintext(buf.get(range).ok_or(CryptoError::InvalidPacket)?)
            .ok_or(CryptoError::InvalidPacket)?;
        Ok(OpenedBlindAddr {
            dst: addr.dst(),
            source,
            addr,
        })
    }

    /// The packet's full S2V output `V`: `S1` is the canonical AAD and `S2`
    /// the protected region ([`PacketHeader::protected_range`]), which must
    /// already be plaintext in `buf`. Its prefix is the MIC, and a MAC ack
    /// binds to all of it.
    pub fn packet_tag(
        &self,
        k_mic: &[u8; 32],
        header: &PacketHeader,
        buf: &[u8],
        blind_addr: Option<&BlindAddr>,
    ) -> Result<[u8; 16], CryptoError> {
        let protected = buf
            .get(header.protected_range())
            .ok_or(CryptoError::InvalidPacket)?;
        let mut aad = Ok(());
        let tag = self.s2v_tag(
            k_mic,
            |cmac| aad = feed_aad(header, buf, blind_addr, |chunk| cmac.update(chunk)),
            protected,
        );
        aad.map_err(|_| CryptoError::InvalidPacket)?;
        Ok(tag)
    }

    /// Compute the packet tag `V = S2V(k_mic, S1, S2)` per RFC 5297 §2.4,
    /// with the canonical AAD (streamed through `aad`) as the single
    /// associated-data component `S1` and `plaintext` as the final
    /// component `S2`.
    pub fn s2v_tag(
        &self,
        k_mic: &[u8; 32],
        aad: impl FnOnce(&mut CmacState<&A::Cipher>),
        plaintext: &[u8],
    ) -> [u8; 16] {
        let cipher = self.aes.new_cipher(k_mic);
        let mut s2v = S2vState::new(&cipher);
        s2v.push_component(aad);
        s2v.finalize(plaintext)
    }

    /// The MIC construction of a MAC ack's tag:
    /// `truncate4(S2V(k_mic, S1 = ack AAD, S2 = v, S3 = v[..4]))`.
    ///
    /// `v` is the full S2V output of the packet being acknowledged; its first
    /// four bytes are the ack's public `ack_mic`. The AAD (streamed through
    /// `aad`) is the ack's FCF with H cleared and its static options. The
    /// three components mirror an ordinary packet's—AAD, then `v` where a
    /// nonce would sit, then `ack_mic` as the payload—and the component
    /// count, with the ack's own FCF, keeps the result apart from any other
    /// MIC under the same key.
    pub fn ack_tag_mic(
        &self,
        k_mic: &[u8; 32],
        aad: impl FnOnce(&mut CmacState<&A::Cipher>),
        v: &[u8; 16],
    ) -> [u8; 4] {
        let cipher = self.aes.new_cipher(k_mic);
        let mut s2v = S2vState::new(&cipher);
        s2v.push_component(aad);
        s2v.push_component(|cmac| cmac.update(v));
        let full = s2v.finalize(&v[..4]);
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&full[..4]);
        tag
    }

    /// Seal a built MAC ack in place, writing its trailer
    /// `ack_mic || ack_tag` for the packet whose full S2V output is `v`.
    /// `keys` are the keys that sealed the acknowledged packet—pairwise, or
    /// the combined blind keys.
    pub fn seal_mac_ack(
        &self,
        keys: &PairwiseKeys,
        v: &[u8; 16],
        frame: &mut [u8],
    ) -> Result<(), CryptoError> {
        let header = parse_mac_ack(frame)?;
        let tag = self.mac_ack_tag(keys, v, &header, frame);
        let trailer = frame
            .get_mut(header.mic_range.clone())
            .filter(|trailer| trailer.len() == 8)
            .ok_or(CryptoError::InvalidPacket)?;
        trailer[..4].copy_from_slice(&v[..4]);
        trailer[4..].copy_from_slice(&tag);
        Ok(())
    }

    /// Whether a received MAC ack acknowledges the packet whose full S2V
    /// output is `v`: its `ack_mic` is `v`'s prefix and its tag verifies.
    pub fn verify_mac_ack(&self, keys: &PairwiseKeys, v: &[u8; 16], frame: &[u8]) -> bool {
        let Ok(header) = parse_mac_ack(frame) else {
            return false;
        };
        let Some(trailer) = frame
            .get(header.mic_range.clone())
            .filter(|trailer| trailer.len() == 8)
        else {
            return false;
        };
        trailer[..4] == v[..4]
            && constant_time_eq(&self.mac_ack_tag(keys, v, &header, frame), &trailer[4..])
    }

    fn mac_ack_tag(
        &self,
        keys: &PairwiseKeys,
        v: &[u8; 16],
        header: &PacketHeader,
        frame: &[u8],
    ) -> [u8; 4] {
        self.ack_tag_mic(
            &keys.k_mic,
            |cmac| {
                // `parse_mac_ack` has already decoded every option.
                let _ = feed_aad(header, frame, None, |chunk| cmac.update(chunk));
            },
            v,
        )
    }

    /// Create a reusable incremental CMAC state.
    pub fn cmac_state(&self, key: &[u8; 32]) -> CmacState<A::Cipher> {
        CmacState::new(self.aes.new_cipher(key))
    }

    /// Convenience wrapper for AES-CMAC over concatenated slices.
    pub fn aes_cmac(&self, key: &[u8; 32], data: &[&[u8]]) -> [u8; 16] {
        let mut state = self.cmac_state(key);
        for chunk in data {
            state.update(chunk);
        }
        state.finalize()
    }

    /// Apply AES-CTR using `iv` as the initial counter block.
    pub fn aes_ctr(&self, key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
        aes_ctr_with_cipher(&self.aes.new_cipher(key), iv, data);
    }

    /// Construct the CTR IV from MIC bytes and SECINFO bytes.
    ///
    /// With a 16-byte MIC the IV is the masked MIC alone—exactly the
    /// initial counter `Q` from RFC 5297 §2.6; shorter MICs are padded
    /// from the SECINFO bytes, so the IV construction of a received
    /// packet must locate SECINFO exactly (see [`sec_info_bytes_range`]).
    /// The RFC's bit-clearing of the top bit of bytes 8 and 12 is applied
    /// unconditionally, whatever bytes occupy those positions.
    pub fn build_ctr_iv(&self, mic: &[u8], sec_info_bytes: &[u8]) -> [u8; 16] {
        let mut iv = [0u8; 16];
        for (slot, byte) in iv.iter_mut().zip(mic.iter().chain(sec_info_bytes)) {
            *slot = *byte;
        }
        iv[8] &= 0x7F;
        iv[12] &= 0x7F;
        iv
    }

    /// Run HKDF-SHA256 and write the output into `okm`.
    pub fn hkdf(&self, ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) {
        hkdf_sha256(&self.sha, ikm, salt, info, okm);
    }
}

/// HKDF-SHA256 over any [`Sha256Provider`], for callers that have no
/// [`CryptoEngine`]—the entropy pool derives keys before any AES
/// provider exists.
pub fn hkdf_sha256<S: Sha256Provider>(
    sha: &S,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    okm: &mut [u8],
) {
    let prk = sha.hmac(salt, &[ikm]);
    let mut previous = [0u8; 32];
    let mut previous_len = 0usize;
    let mut written = 0usize;
    let mut counter = 1u8;
    while written < okm.len() {
        let next = sha.hmac(&prk, &[&previous[..previous_len], info, &[counter]]);
        let take = (okm.len() - written).min(next.len());
        okm[written..written + take].copy_from_slice(&next[..take]);
        previous = next;
        previous_len = 32;
        written += take;
        counter = counter.wrapping_add(1);
    }
}

fn aes_ctr_with_cipher<C: AesCipher>(cipher: &C, iv: &[u8; 16], data: &mut [u8]) {
    let mut counter = *iv;
    for chunk in data.chunks_mut(16) {
        let mut stream = counter;
        cipher.encrypt_block(&mut stream);
        for (dst, src) in chunk.iter_mut().zip(stream.iter()) {
            *dst ^= *src;
        }
        increment_counter(&mut counter);
    }
}

fn xor_in_place(dst: &mut [u8; 16], rhs: &[u8; 16]) {
    for (left, right) in dst.iter_mut().zip(rhs.iter()) {
        *left ^= *right;
    }
}

fn dbl(block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for (index, byte) in block.iter().enumerate().rev() {
        out[index] = (byte << 1) | carry;
        carry = byte >> 7;
    }
    if block[0] & 0x80 != 0 {
        out[15] ^= 0x87;
    }
    out
}

/// The on-wire SECINFO byte range of a parsed secure packet. In every
/// secure layout (unicast, multicast, blind unicast) SECINFO
/// immediately precedes the options block—not the body, which the
/// options end marker or a blind address block may separate from it.
fn sec_info_bytes_range(header: &PacketHeader) -> Result<Range<usize>, CryptoError> {
    let sec_info = header.sec_info.ok_or(CryptoError::InvalidPacket)?;
    header
        .options_range
        .start
        .checked_sub(sec_info.wire_len())
        .map(|start| start..header.options_range.start)
        .ok_or(CryptoError::InvalidPacket)
}

fn increment_counter(counter: &mut [u8; 16]) {
    for byte in counter.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

/// Parse `frame` as a MAC ack with well-formed options.
fn parse_mac_ack(frame: &[u8]) -> Result<PacketHeader, CryptoError> {
    let header = PacketHeader::parse(frame).map_err(|_| CryptoError::InvalidPacket)?;
    if header.packet_type() != PacketType::MacAck {
        return Err(CryptoError::InvalidPacket);
    }
    ParsedOptions::extract(frame, header.options_range.clone())
        .map_err(|_| CryptoError::InvalidPacket)?;
    Ok(header)
}

const PAIRWISE_INFO_LABEL: &[u8] = b"UMSH-UNICAST-V3";

/// The pairwise HKDF info, `"UMSH-UNICAST-V3" ‖ min(PK) ‖ max(PK)`. Binding
/// both full keys gives `P` and `−P`, which share an X25519 key, distinct
/// pairwise keys; sorting them gives both ends the same keys.
fn pairwise_info(a: &PublicKey, b: &PublicKey) -> [u8; PAIRWISE_INFO_LABEL.len() + 64] {
    let (low, high) = if a.0 <= b.0 { (a, b) } else { (b, a) };
    let mut info = [0u8; PAIRWISE_INFO_LABEL.len() + 64];
    let (label, keys) = info.split_at_mut(PAIRWISE_INFO_LABEL.len());
    label.copy_from_slice(PAIRWISE_INFO_LABEL);
    keys[..32].copy_from_slice(&low.0);
    keys[32..].copy_from_slice(&high.0);
    info
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let lhs = left.get(index).copied().unwrap_or(0);
        let rhs = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(lhs ^ rhs);
    }
    diff == 0
}

#[cfg(feature = "software-crypto")]
pub mod software {
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
    use curve25519_dalek::{
        edwards::{CompressedEdwardsY, EdwardsPoint},
        montgomery::MontgomeryPoint,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::CryptoRngCore;
    use sha2::{Digest, Sha256, Sha512};

    use super::*;

    pub struct SoftwareAes;

    pub struct SoftwareAesCipher(aes::Aes256);

    impl AesCipher for SoftwareAesCipher {
        fn encrypt_block(&self, block: &mut [u8; 16]) {
            self.0.encrypt_block(GenericArray::from_mut_slice(block));
        }

        fn decrypt_block(&self, block: &mut [u8; 16]) {
            self.0.decrypt_block(GenericArray::from_mut_slice(block));
        }
    }

    impl AesProvider for SoftwareAes {
        type Cipher = SoftwareAesCipher;

        fn new_cipher(&self, key: &[u8; 32]) -> Self::Cipher {
            SoftwareAesCipher(aes::Aes256::new(GenericArray::from_slice(key)))
        }
    }

    pub struct SoftwareSha256;

    impl Sha256Provider for SoftwareSha256 {
        fn hash(&self, data: &[&[u8]]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            for chunk in data {
                hasher.update(chunk);
            }
            hasher.finalize().into()
        }

        fn hmac(&self, key: &[u8], data: &[&[u8]]) -> [u8; 32] {
            const BLOCK_LEN: usize = 64;
            let mut key_block = [0u8; BLOCK_LEN];
            if key.len() > BLOCK_LEN {
                key_block[..32].copy_from_slice(&self.hash(&[key]));
            } else {
                key_block[..key.len()].copy_from_slice(key);
            }

            let mut ipad = [0x36u8; BLOCK_LEN];
            let mut opad = [0x5Cu8; BLOCK_LEN];
            for index in 0..BLOCK_LEN {
                ipad[index] ^= key_block[index];
                opad[index] ^= key_block[index];
            }

            let mut inner = Sha256::new();
            inner.update(ipad);
            for chunk in data {
                inner.update(chunk);
            }
            let inner_hash = inner.finalize();

            let mut outer = Sha256::new();
            outer.update(opad);
            outer.update(inner_hash);
            outer.finalize().into()
        }
    }

    /// Cloning is deliberate: a holder that must both hand the identity to
    /// the MAC and retain signing ability (e.g. standalone node-identity
    /// bundles) keeps a clone rather than round-tripping secret bytes.
    #[derive(Clone)]
    pub struct SoftwareIdentity {
        secret: SigningKey,
        public: PublicKey,
    }

    /// Draw a fresh identity secret.
    ///
    /// `fill` is called for each draw; a key that
    /// [`umsh_core::hint_filter::is_avoided`] matches is discarded and
    /// another drawn. There is no attempt limit: an entropy source that
    /// never produces an acceptable key is broken. An error from `fill` is
    /// returned as is.
    pub fn generate_identity_secret<E>(
        fill: impl FnMut(&mut [u8; 32]) -> Result<(), E>,
    ) -> Result<[u8; 32], E> {
        generate_identity_secret_against(&umsh_core::hint_filter::FILTER, fill)
    }

    pub(crate) fn generate_identity_secret_against<E>(
        filter: &umsh_core::hint_filter::Filter,
        mut fill: impl FnMut(&mut [u8; 32]) -> Result<(), E>,
    ) -> Result<[u8; 32], E> {
        let mut secret = [0u8; 32];
        loop {
            if let Err(error) = fill(&mut secret) {
                secret.zeroize();
                return Err(error);
            }
            let public = PublicKey(SigningKey::from_bytes(&secret).verifying_key().to_bytes());
            if !filter.avoids(&public) {
                return Ok(secret);
            }
        }
    }

    impl SoftwareIdentity {
        pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
            let mut secret = generate_identity_secret(|secret| {
                rng.fill_bytes(secret);
                Ok::<_, core::convert::Infallible>(())
            })
            .unwrap_or_else(|never| match never {});
            let identity = Self::from_secret_bytes(&secret);
            secret.zeroize();
            identity
        }

        pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
            let secret = SigningKey::from_bytes(bytes);
            let public = PublicKey(secret.verifying_key().to_bytes());
            Self { secret, public }
        }

        pub fn shared_secret_with(&self, peer: &PublicKey) -> Result<SharedSecret, CryptoError> {
            let local = signing_key_to_x25519(&self.secret);
            let remote = public_key_to_x25519(peer)?;
            let shared = local.diffie_hellman(&remote);
            let bytes = shared.to_bytes();
            if bytes.iter().all(|byte| *byte == 0) {
                return Err(CryptoError::InvalidSharedSecret);
            }
            Ok(SharedSecret(bytes))
        }
    }

    impl NodeIdentity for SoftwareIdentity {
        type Error = CryptoError;

        fn public_key(&self) -> &PublicKey {
            &self.public
        }

        async fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
            Ok(self.secret.sign(message).to_bytes())
        }

        async fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, Self::Error> {
            self.shared_secret_with(peer)
        }
    }

    pub type SoftwareCryptoEngine = CryptoEngine<SoftwareAes, SoftwareSha256>;

    fn signing_key_to_x25519(secret: &SigningKey) -> x25519_dalek::StaticSecret {
        let digest = Sha512::digest(secret.to_bytes());
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&digest[..32]);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        x25519_dalek::StaticSecret::from(scalar)
    }

    fn public_key_to_x25519(public: &PublicKey) -> Result<x25519_dalek::PublicKey, CryptoError> {
        let edwards = decode_canonical_point(public).ok_or(CryptoError::InvalidPublicKey)?;
        let mont: MontgomeryPoint = edwards.to_montgomery();
        Ok(x25519_dalek::PublicKey::from(mont.to_bytes()))
    }

    /// Decode `public` as an Ed25519 point, accepting only the canonical
    /// encoding: one that re-encodes to the same 32 bytes. A non-canonical
    /// `y` would be a second address for the same point.
    fn decode_canonical_point(public: &PublicKey) -> Option<EdwardsPoint> {
        let point = CompressedEdwardsY(public.0).decompress()?;
        (point.compress().0 == public.0).then_some(point)
    }

    /// Return `true` if `pk`'s bytes are the canonical encoding of a point
    /// on the Ed25519 curve. Used by the MAC layer and CLI to reject
    /// malformed peer keys before they can poison the peer registry.
    pub fn is_valid_ed25519_public_key(pk: &PublicKey) -> bool {
        decode_canonical_point(pk).is_some()
    }

    /// Verify a frame's signature against `key`, the sender's key.
    ///
    /// `channel` is the commitment of the channel key that authenticated the
    /// frame's MIC, never one matched by identifier alone; it is `None`
    /// exactly for frames that name no channel. A blind unicast needs its
    /// plaintext address block. The frame must already be open. `scratch`
    /// holds the signature input.
    pub fn verify_frame_signature(
        header: &PacketHeader,
        buf: &[u8],
        key: &PublicKey,
        blind_addr: Option<&BlindAddr>,
        channel: Option<&ChannelCommitment>,
        scratch: &mut [u8; umsh_core::SIGNATURE_INPUT_MAX],
    ) -> bool {
        let Some(signature) = header
            .signature()
            .and_then(|sig| buf.get(sig.range.clone()))
            .and_then(|sig| <[u8; 64]>::try_from(sig).ok())
        else {
            return false;
        };
        match umsh_core::signature_input(header, buf, blind_addr, channel, scratch) {
            Ok(len) => verify_ed25519_signature(key, &scratch[..len], &signature),
            Err(_) => false,
        }
    }

    /// Verify a detached Ed25519 signature against `pk`. Used for standalone
    /// node-identity bundles (QR codes, broadcasts) whose signed range must
    /// verify before the bundle's claims are presented as authenticated.
    pub fn verify_ed25519_signature(pk: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&pk.0) else {
            return false;
        };
        key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    }
}

#[cfg(feature = "software-crypto")]
pub use software::*;

#[cfg(test)]
mod tests {
    use crate::{constant_time_eq, dbl};

    #[cfg(feature = "software-crypto")]
    use super::*;
    #[cfg(feature = "software-crypto")]
    use umsh_core::{MicSize, NodeHint, PacketBuilder, PacketHeader, PublicKey};

    /// Stand-ins for the two parties' keys where only the KDF sees them.
    #[cfg(feature = "software-crypto")]
    const TEST_LOCAL_KEY: PublicKey = PublicKey([0x10; 32]);
    #[cfg(feature = "software-crypto")]
    const TEST_REMOTE_KEY: PublicKey = PublicKey([0xAB; 32]);

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pairwise_hkdf_is_stable() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = engine.derive_pairwise_keys(
            &SharedSecret([7u8; 32]),
            &TEST_LOCAL_KEY,
            &TEST_REMOTE_KEY,
        );
        assert_ne!(keys.k_enc, [0u8; 32]);
        assert_ne!(keys.k_mic, [0u8; 32]);
    }

    /// The pairwise HKDF output is the RFC 5297 AES-SIV key: S2V key (K1)
    /// first, CTR key (K2) second.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pairwise_okm_is_the_rfc5297_key() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let shared = SharedSecret([9u8; 32]);
        let keys = engine.derive_pairwise_keys(&shared, &TEST_LOCAL_KEY, &TEST_REMOTE_KEY);
        let mut info = std::vec::Vec::from(&b"UMSH-UNICAST-V3"[..]);
        info.extend_from_slice(&TEST_LOCAL_KEY.0);
        info.extend_from_slice(&TEST_REMOTE_KEY.0);
        let mut okm = [0u8; 64];
        engine.hkdf(&shared.0, b"UMSH-PAIRWISE-SALT", &info, &mut okm);
        assert_eq!(keys.k_mic, okm[..32]);
        assert_eq!(keys.k_enc, okm[32..]);
    }

    /// Both ends derive the same keys whichever key is "local", and a key's
    /// negation—same hint, same X25519 key—derives different ones.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn pairwise_keys_bind_both_public_keys() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let alice = SoftwareIdentity::from_secret_bytes(&[0x11; 32]);
        let bob = SoftwareIdentity::from_secret_bytes(&[0x22; 32]);
        let shared = alice.shared_secret_with(bob.public_key()).unwrap();
        let ab = engine.derive_pairwise_keys(&shared, alice.public_key(), bob.public_key());
        let ba = engine.derive_pairwise_keys(&shared, bob.public_key(), alice.public_key());
        assert_eq!(ab.k_enc, ba.k_enc);
        assert_eq!(ab.k_mic, ba.k_mic);

        let mut negated = *bob.public_key();
        negated.0[31] ^= 0x80;
        assert!(is_valid_ed25519_public_key(&negated));
        assert_eq!(negated.hint(), bob.public_key().hint());
        assert_eq!(
            alice.shared_secret_with(&negated).unwrap().0,
            shared.0,
            "P and −P share an X25519 key"
        );
        let aliased = engine.derive_pairwise_keys(&shared, alice.public_key(), &negated);
        assert_ne!(aliased.k_enc, ab.k_enc);
        assert_ne!(aliased.k_mic, ab.k_mic);
    }

    /// A `y` at or above the field prime decodes to the same point as its
    /// reduction; only the reduced (canonical) encoding is a valid key, for
    /// validation and for key agreement alike.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn non_canonical_public_keys_are_rejected() {
        // y = 1 (the identity's y) also encodes as y = p + 1.
        let mut canonical = [0u8; 32];
        canonical[0] = 1;
        let mut non_canonical = [0xFFu8; 32];
        non_canonical[0] = 0xEE;
        non_canonical[31] = 0x7F;
        assert!(is_valid_ed25519_public_key(&PublicKey(canonical)));
        assert!(!is_valid_ed25519_public_key(&PublicKey(non_canonical)));

        let alice = SoftwareIdentity::from_secret_bytes(&[0x11; 32]);
        assert!(matches!(
            alice.shared_secret_with(&PublicKey(non_canonical)),
            Err(CryptoError::InvalidPublicKey)
        ));
    }

    /// NIST SP 800-38B CMAC-AES256 example key.
    #[cfg(feature = "software-crypto")]
    const NIST_AES256_KEY: &str =
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

    #[cfg(feature = "software-crypto")]
    #[test]
    fn aes_cmac_matches_nist_aes256_example_2() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = hex_32(NIST_AES256_KEY);
        let msg = hex_vec("6bc1bee22e409f96e93d7e117393172a");
        let expected = hex_16("28a7023f452e8f82bd4bf28d8c37c35c");
        assert_eq!(engine.aes_cmac(&key, &[&msg]), expected);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn aes_cmac_matches_nist_aes256_example_1_empty() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = hex_32(NIST_AES256_KEY);
        let expected = hex_16("028962f61b7bf89efc6b551f4667d983");
        assert_eq!(engine.aes_cmac(&key, &[&[]]), expected);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn aes_cmac_matches_nist_aes256_example_4_64b() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = hex_32(NIST_AES256_KEY);
        let msg = hex_vec(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let expected = hex_16("e1992190549f6ed5696a2c056c315410");
        assert_eq!(engine.aes_cmac(&key, &[&msg]), expected);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn aes_cmac_matches_nist_aes256_example_3_40b() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = hex_32(NIST_AES256_KEY);
        let msg = hex_vec(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411",
        );
        let expected = hex_16("aaf3d8f1de5640c232f5b169b9c911e6");
        assert_eq!(engine.aes_cmac(&key, &[&msg]), expected);
    }

    /// NIST SP 800-38A Section F.5.5—AES-256 CTR mode, single block.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn aes_ctr_matches_nist_sp800_38a_block_1() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = hex_32(NIST_AES256_KEY);
        let iv = hex_16("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut data = hex_vec("6bc1bee22e409f96e93d7e117393172a");
        engine.aes_ctr(&key, &iv, &mut data);
        assert_eq!(data, hex_vec("601ec313775789a5b7a7f504bbf3d228"));
    }

    /// NIST SP 800-38A Section F.5.5—AES-256 CTR mode, 4 blocks.
    /// Verifies counter increment across multiple blocks.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn aes_ctr_matches_nist_sp800_38a_4_blocks() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = hex_32(NIST_AES256_KEY);
        let iv = hex_16("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut data = hex_vec(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let expected = hex_vec(
            "601ec313775789a5b7a7f504bbf3d228\
             f443e3ca4d62b59aca84e990cacaf5c5\
             2b0930daa23de94ce87017ba2d84988d\
             dfc9c58db67aada613c2dd08457941a6",
        );
        engine.aes_ctr(&key, &iv, &mut data);
        assert_eq!(data, expected);
    }

    /// NIST SP 800-38A Section F.5.6—CTR decrypt (symmetric operation).
    #[cfg(feature = "software-crypto")]
    #[test]
    fn aes_ctr_decrypt_matches_nist_sp800_38a() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = hex_32(NIST_AES256_KEY);
        let iv = hex_16("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut data = hex_vec(
            "601ec313775789a5b7a7f504bbf3d228\
             f443e3ca4d62b59aca84e990cacaf5c5\
             2b0930daa23de94ce87017ba2d84988d\
             dfc9c58db67aada613c2dd08457941a6",
        );
        let expected = hex_vec(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        engine.aes_ctr(&key, &iv, &mut data);
        assert_eq!(data, expected);
    }

    /// AES-CTR with partial final block (non-aligned length).
    #[cfg(feature = "software-crypto")]
    #[test]
    fn aes_ctr_partial_block() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = hex_32(NIST_AES256_KEY);
        let iv = hex_16("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        // Encrypt 5 bytes (less than one block)
        let mut data = hex_vec("6bc1bee22e");
        engine.aes_ctr(&key, &iv, &mut data);
        // Should match first 5 bytes of full block 1 ciphertext
        assert_eq!(data, hex_vec("601ec31377"));
        // Decrypt back
        engine.aes_ctr(&key, &iv, &mut data);
        assert_eq!(data, hex_vec("6bc1bee22e"));
    }

    /// AES-128 cipher for the RFC 5297 appendix vectors, which use
    /// AES-SIV-CMAC-256 (two 128-bit subkeys). The S2V and CTR cores are
    /// block-level and key-size-free, so the RFC's own vectors remain
    /// runnable even though the protocol uses AES-256.
    #[cfg(feature = "software-crypto")]
    struct Aes128TestCipher(aes::Aes128);

    #[cfg(feature = "software-crypto")]
    impl Aes128TestCipher {
        fn new(key: &[u8; 16]) -> Self {
            use aes::cipher::KeyInit;
            Self(aes::Aes128::new(
                aes::cipher::generic_array::GenericArray::from_slice(key),
            ))
        }
    }

    #[cfg(feature = "software-crypto")]
    impl AesCipher for Aes128TestCipher {
        fn encrypt_block(&self, block: &mut [u8; 16]) {
            use aes::cipher::BlockEncrypt;
            self.0
                .encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
                    block,
                ));
        }

        fn decrypt_block(&self, block: &mut [u8; 16]) {
            use aes::cipher::BlockDecrypt;
            self.0
                .decrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
                    block,
                ));
        }
    }

    /// RFC 5297 Appendix A.1—deterministic authenticated encryption.
    /// Exercises the single-AD path and S2V's dbl-and-pad branch (the
    /// 14-byte plaintext is shorter than a block).
    #[cfg(feature = "software-crypto")]
    #[test]
    fn rfc5297_a1_deterministic_aes_siv() {
        let k1 = hex_16("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0");
        let k2 = hex_16("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ad = hex_vec("101112131415161718191a1b1c1d1e1f2021222324252627");
        let plaintext = hex_vec("112233445566778899aabbccddee");

        let s2v_cipher = Aes128TestCipher::new(&k1);
        let mut s2v = S2vState::new(&s2v_cipher);
        s2v.push_component(|cmac| cmac.update(&ad));
        let v = s2v.finalize(&plaintext);
        assert_eq!(v, hex_16("85632d07c6e8f37f950acd320a2ecc93"));

        let mut q = v;
        q[8] &= 0x7F;
        q[12] &= 0x7F;
        let ctr_cipher = Aes128TestCipher::new(&k2);
        let mut data = plaintext.clone();
        aes_ctr_with_cipher(&ctr_cipher, &q, &mut data);
        assert_eq!(data, hex_vec("40c02b9690c4dc04daef7f6afe5c"));
    }

    /// RFC 5297 Appendix A.2—nonce-based authenticated encryption.
    /// Exercises multiple S2V components and the xorend branch (the
    /// 47-byte plaintext spans multiple blocks).
    #[cfg(feature = "software-crypto")]
    #[test]
    fn rfc5297_a2_nonce_based_aes_siv() {
        let k1 = hex_16("7f7e7d7c7b7a79787776757473727170");
        let k2 = hex_16("404142434445464748494a4b4c4d4e4f");
        let ad1 = hex_vec(
            "00112233445566778899aabbccddeeff\
             deaddadadeaddadaffeeddccbbaa9988\
             7766554433221100",
        );
        let ad2 = hex_vec("102030405060708090a0");
        let nonce = hex_vec("09f911029d74e35bd84156c5635688c0");
        let plaintext = hex_vec(
            "7468697320697320736f6d6520706c61\
             696e7465787420746f20656e63727970\
             74207573696e67205349562d414553",
        );

        let s2v_cipher = Aes128TestCipher::new(&k1);
        let mut s2v = S2vState::new(&s2v_cipher);
        s2v.push_component(|cmac| cmac.update(&ad1));
        s2v.push_component(|cmac| cmac.update(&ad2));
        s2v.push_component(|cmac| cmac.update(&nonce));
        let v = s2v.finalize(&plaintext);
        assert_eq!(v, hex_16("7bdb6e3b432667eb06f4d14bff2fbd0f"));

        let mut q = v;
        q[8] &= 0x7F;
        q[12] &= 0x7F;
        let ctr_cipher = Aes128TestCipher::new(&k2);
        let mut data = plaintext.clone();
        aes_ctr_with_cipher(&ctr_cipher, &q, &mut data);
        assert_eq!(
            data,
            hex_vec(
                "cb900f2fddbe404326601965c889bf17\
                 dba77ceb094fa663b7a3f748ba8af829\
                 ea64ad544a272e9c485b62a3fd5c0d"
            )
        );
    }

    /// The RFC 5297 bit-clearing applies at every MIC length, whatever
    /// bytes occupy positions 8 and 12.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn build_ctr_iv_masks_rfc5297_bits() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let mic = [0xFFu8; 16];
        let sec_info = [0xFFu8; 7];
        for mic_len in [4usize, 8, 12, 16] {
            let iv = engine.build_ctr_iv(&mic[..mic_len], &sec_info);
            assert_eq!(iv[8] & 0x80, 0, "mic_len {mic_len}");
            assert_eq!(iv[12] & 0x80, 0, "mic_len {mic_len}");
        }
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn hmac_sha256_matches_rfc4231_case_1() {
        let sha = SoftwareSha256;
        let key = [0x0bu8; 20];
        let expected = hex_32("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(sha.hmac(&key, &[b"Hi There"]), expected);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let ikm = [0x0bu8; 22];
        let salt = hex_vec("000102030405060708090a0b0c");
        let info = hex_vec("f0f1f2f3f4f5f6f7f8f9");
        let mut okm = [0u8; 42];
        engine.hkdf(&ikm, &salt, &info, &mut okm);
        assert_eq!(
            okm.to_vec(),
            hex_vec(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn cmac_doubling_matches_rfc4493_subkey_generation() {
        let l = hex_16("7df76b0c1ab899b33e42f047b91b546f");
        let expected_k1 = hex_16("fbeed618357133667c85e08f7236a8de");
        let expected_k2 = hex_16("f7ddac306ae266ccf90bc11ee46d513b");
        let k1 = dbl(&l);
        let k2 = dbl(&k1);
        assert_eq!(k1, expected_k1);
        assert_eq!(k2, expected_k2);
    }

    #[test]
    fn constant_time_eq_rejects_mismatch() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 3, 4]));
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn unicast_seal_and_open_round_trip() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = engine.derive_pairwise_keys(
            &SharedSecret([9u8; 32]),
            &TEST_LOCAL_KEY,
            &TEST_REMOTE_KEY,
        );
        let src = PublicKey([0xA1; 32]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let mut buf = [0u8; 128];
        let mut packet = PacketBuilder::new(&mut buf)
            .unicast(dst)
            .source_full(&src)
            .frame_counter(1)
            .encrypted()
            .mic_size(MicSize::Mic16)
            .payload(b"hello")
            .build()
            .unwrap();

        engine.seal_packet(&mut packet, &keys).unwrap();
        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        let mut wire = packet.as_bytes().to_vec();
        let range = engine.open_packet(&mut wire, &header, &keys, None).unwrap();
        assert_eq!(&wire[range], b"hello");
    }

    /// A sealed Mic16 packet is byte-for-byte RFC 5297 AEAD_AES_SIV_CMAC_512:
    /// the RustCrypto `aes-siv` crate, keyed with `k_mic || k_enc` and given
    /// the canonical AAD as its single header component, must reproduce the
    /// on-wire MIC and ciphertext exactly.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn mic16_packet_matches_rfc5297_aes_siv_crate() {
        use aes_siv::{KeyInit, siv::Aes256Siv};

        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = engine.derive_pairwise_keys(
            &SharedSecret([9u8; 32]),
            &TEST_LOCAL_KEY,
            &TEST_REMOTE_KEY,
        );
        let src = PublicKey([0xA1; 32]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        for payload in [&b"hello, RFC 5297 - a plaintext spanning blocks"[..], b""] {
            let mut buf = [0u8; 128];
            let mut packet = PacketBuilder::new(&mut buf)
                .unicast(dst)
                .source_full(&src)
                .frame_counter(7)
                .encrypted()
                .mic_size(MicSize::Mic16)
                .payload(payload)
                .build()
                .unwrap();
            engine.seal_packet(&mut packet, &keys).unwrap();

            let wire = packet.as_bytes().to_vec();
            let header = PacketHeader::parse(&wire).unwrap();
            let mut aad = std::vec::Vec::new();
            feed_aad(&header, &wire, None, |chunk| aad.extend_from_slice(chunk)).unwrap();

            let mut siv_key = [0u8; 64];
            siv_key[..32].copy_from_slice(&keys.k_mic);
            siv_key[32..].copy_from_slice(&keys.k_enc);
            let mut siv = Aes256Siv::new((&siv_key).into());
            let sealed = siv.encrypt([&aad], payload).unwrap();

            // RFC 5297 output is V || C; UMSH carries C in the body and V at
            // the end of the packet.
            assert_eq!(sealed[..16], wire[header.mic_range.clone()]);
            assert_eq!(sealed[16..], wire[header.body_range.clone()]);
        }
    }

    /// For truncated MICs only the IV construction differs: the full S2V tag
    /// still matches the `aes-siv` crate's tag for the same inputs.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn short_mic_tag_matches_rfc5297_s2v() {
        use aes_siv::{KeyInit, siv::Aes256Siv};

        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = engine.derive_pairwise_keys(
            &SharedSecret([11u8; 32]),
            &TEST_LOCAL_KEY,
            &TEST_REMOTE_KEY,
        );
        let payload = b"short-tag payload";
        let src = PublicKey([0xB2; 32]);
        let dst = NodeHint([0x10, 0x20, 0x30]);
        let mut buf = [0u8; 128];
        let mut packet = PacketBuilder::new(&mut buf)
            .unicast(dst)
            .source_full(&src)
            .frame_counter(3)
            .encrypted()
            .mic_size(MicSize::Mic4)
            .payload(payload)
            .build()
            .unwrap();

        let full_tag = {
            let header = packet.header().unwrap();
            engine
                .packet_tag(&keys.k_mic, &header, packet.as_bytes(), None)
                .unwrap()
        };
        let mut aad = std::vec::Vec::new();
        {
            let header = packet.header().unwrap();
            feed_aad(&header, packet.as_bytes(), None, |chunk| {
                aad.extend_from_slice(chunk)
            })
            .unwrap();
        }
        engine.seal_packet(&mut packet, &keys).unwrap();

        let mut siv_key = [0u8; 64];
        siv_key[..32].copy_from_slice(&keys.k_mic);
        siv_key[32..].copy_from_slice(&keys.k_enc);
        let mut siv = Aes256Siv::new((&siv_key).into());
        let sealed = siv.encrypt([&aad], payload).unwrap();
        assert_eq!(sealed[..16], full_tag);

        // The on-wire MIC is the prefix truncation of that tag.
        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        assert_eq!(packet.as_bytes()[header.mic_range.clone()], full_tag[..4]);
    }

    /// Regression: with a MIC shorter than 16 bytes the CTR IV includes
    /// SECINFO bytes, and SECINFO precedes the options block—not the
    /// body, which the options end marker separates from it. The IV of
    /// a received packet must be built from the true SECINFO position
    /// or decryption diverges from sealing.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn short_mic_encrypted_unicast_round_trip() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = engine.derive_pairwise_keys(
            &SharedSecret([9u8; 32]),
            &TEST_LOCAL_KEY,
            &TEST_REMOTE_KEY,
        );
        let mut buf = [0u8; 128];
        let mut packet = PacketBuilder::new(&mut buf)
            .unicast(NodeHint([0xC3, 0xD4, 0x25]))
            .source_hint(NodeHint([0xA1, 0xA1, 0xA1]))
            .frame_counter(7)
            .encrypted()
            .mic_size(MicSize::Mic8)
            .payload(b"short mic")
            .build()
            .unwrap();
        engine.seal_packet(&mut packet, &keys).unwrap();
        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        let mut wire = packet.as_bytes().to_vec();
        let range = engine.open_packet(&mut wire, &header, &keys, None).unwrap();
        assert_eq!(&wire[range], b"short mic");
    }

    /// Regression companion to the above for blind unicast, where the
    /// concealed address block also sits between SECINFO and the body:
    /// address decryption and payload opening must both locate SECINFO
    /// correctly with a short MIC.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn short_mic_blind_unicast_round_trip() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let channel_key = ChannelKey([0x5A; 32]);
        let channel_keys = engine.derive_channel_keys(&channel_key);
        let pairwise = engine.derive_pairwise_keys(
            &SharedSecret([9u8; 32]),
            &TEST_LOCAL_KEY,
            &TEST_REMOTE_KEY,
        );
        let blind_keys = engine.derive_blind_keys(&pairwise, &channel_keys);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let src = NodeHint([0xA1, 0xA1, 0xA1]);

        let mut buf = [0u8; 128];
        let mut packet = PacketBuilder::new(&mut buf)
            .blind_unicast(channel_keys.channel_id, dst)
            .source_hint(src)
            .frame_counter(7)
            .ack_requested()
            .encrypted()
            .mic_size(MicSize::Mic8)
            .payload(b"blind")
            .build()
            .unwrap();
        engine
            .seal_blind_packet(&mut packet, &blind_keys, &channel_keys)
            .unwrap();

        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        let mut wire = packet.as_bytes().to_vec();
        let opened = engine
            .decrypt_blind_addr(&mut wire, &header, &channel_keys)
            .unwrap();
        let (decrypted_dst, decrypted_src) = (opened.dst, opened.source);
        assert_eq!(decrypted_dst, dst);
        assert_eq!(decrypted_src, SourceAddrRef::Hint(src));
        let range = engine
            .open_packet(&mut wire, &header, &blind_keys, Some(&opened.addr))
            .unwrap();
        assert_eq!(&wire[range], b"blind");
    }

    #[cfg(feature = "software-crypto")]
    fn ack_test_keys() -> PairwiseKeys {
        PairwiseKeys {
            k_enc: [0x11; 32],
            k_mic: [0x22; 32],
        }
    }

    #[cfg(feature = "software-crypto")]
    const ACK_TEST_V: [u8; 16] = [
        0xAA, 0x17, 0x13, 0x06, 0x26, 0x1C, 0xE7, 0xFF, 0xF2, 0xFF, 0x01, 0x7F, 0x90, 0x10, 0xA7,
        0xD9,
    ];

    /// Build an unsealed ack into `buf` and return its length.
    #[cfg(feature = "software-crypto")]
    fn build_test_ack(
        buf: &mut [u8; 64],
        flood_hops: Option<u8>,
        trace: bool,
        callsign: Option<&[u8]>,
    ) -> usize {
        let mut builder = PacketBuilder::new(buf).mac_ack([0u8; 8]);
        if let Some(hops) = flood_hops {
            builder = builder.flood_hops(hops);
        }
        if let Some(callsign) = callsign {
            builder = builder.option(umsh_core::OptionNumber::OperatorCallsign, callsign);
        }
        if trace {
            builder = builder.trace();
        }
        builder.build().unwrap().len()
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn a_sealed_ack_carries_v_prefix_and_verifies() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = ack_test_keys();
        let v = ACK_TEST_V;
        for callsign in [None, Some(&[0x12u8, 0x34, 0x56, 0x78][..])] {
            let mut buf = [0u8; 64];
            let len = build_test_ack(&mut buf, None, false, callsign);
            let frame = &mut buf[..len];
            engine.seal_mac_ack(&keys, &v, frame).unwrap();
            assert_eq!(frame[len - 8..len - 4], v[..4], "ack_mic is v's prefix");
            assert!(engine.verify_mac_ack(&keys, &v, frame));
        }
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn the_mic_covers_static_options_and_ignores_dynamic_ones() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = ack_test_keys();
        let v = ACK_TEST_V;
        let mut sealed = [0u8; 64];
        let sealed_len = build_test_ack(&mut sealed, None, false, Some(&[0x12, 0x34]));
        engine
            .seal_mac_ack(&keys, &v, &mut sealed[..sealed_len])
            .unwrap();
        let trailer = &sealed[sealed_len - 8..sealed_len];

        // Forwarding adds flood hops and a trace; the tag still holds.
        let mut forwarded = [0u8; 64];
        let forwarded_len = build_test_ack(&mut forwarded, Some(3), true, Some(&[0x12, 0x34]));
        forwarded[forwarded_len - 8..forwarded_len].copy_from_slice(trailer);
        assert!(engine.verify_mac_ack(&keys, &v, &forwarded[..forwarded_len]));

        // A changed static option does not.
        let mut tampered = [0u8; 64];
        let tampered_len = build_test_ack(&mut tampered, None, false, Some(&[0x12, 0x35]));
        tampered[tampered_len - 8..tampered_len].copy_from_slice(trailer);
        assert!(!engine.verify_mac_ack(&keys, &v, &tampered[..tampered_len]));
    }

    /// The tag binds the whole of `v`, not just the public `ack_mic`, and the
    /// keys that sealed the request.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn verify_rejects_another_requests_ack() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = ack_test_keys();
        let v = ACK_TEST_V;
        let mut buf = [0u8; 64];
        let len = build_test_ack(&mut buf, None, false, None);
        engine.seal_mac_ack(&keys, &v, &mut buf[..len]).unwrap();

        let mut same_prefix = v;
        same_prefix[15] ^= 1;
        assert!(!engine.verify_mac_ack(&keys, &same_prefix, &buf[..len]));

        let mut other_prefix = v;
        other_prefix[0] ^= 1;
        assert!(!engine.verify_mac_ack(&keys, &other_prefix, &buf[..len]));

        let other_keys = PairwiseKeys {
            k_enc: [0x33; 32],
            k_mic: [0x44; 32],
        };
        assert!(!engine.verify_mac_ack(&other_keys, &v, &buf[..len]));
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn encrypted_multicast_round_trip_preserves_source_prefix() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let channel_key = ChannelKey([0x5Au8; 32]);
        let derived = engine.derive_channel_keys(&channel_key);
        let src = PublicKey([0xA1; 32]);
        let mut buf = [0u8; 160];
        let mut packet = PacketBuilder::new(&mut buf)
            .multicast(derived.channel_id)
            .source_hint(src.hint())
            .frame_counter(5)
            .encrypted()
            .mic_size(MicSize::Mic16)
            .payload(b"hello")
            .build()
            .unwrap();

        let multicast_keys = PairwiseKeys {
            k_enc: derived.k_enc,
            k_mic: derived.k_mic,
        };
        engine.seal_packet(&mut packet, &multicast_keys).unwrap();
        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        let mut wire = packet.as_bytes().to_vec();
        let range = engine
            .open_packet(&mut wire, &header, &multicast_keys, None)
            .unwrap();
        assert_eq!(
            &wire[header.body_range.start..header.body_range.start + 3],
            &src.hint().0
        );
        assert_eq!(&wire[range], b"hello");
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn blind_unicast_round_trip_recovers_addresses_and_payload() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let shared = SharedSecret([0x33u8; 32]);
        let pairwise = engine.derive_pairwise_keys(&shared, &TEST_LOCAL_KEY, &TEST_REMOTE_KEY);
        let channel_key = ChannelKey([0x5Au8; 32]);
        let channel = engine.derive_channel_keys(&channel_key);
        let blind_keys = engine.derive_blind_keys(&pairwise, &channel);
        let src = PublicKey([
            0xA1, 0xB2, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let mut buf = [0u8; 160];
        let mut packet = PacketBuilder::new(&mut buf)
            .blind_unicast(channel.channel_id, dst)
            .source_full(&src)
            .frame_counter(5)
            .mic_size(MicSize::Mic16)
            .payload(b"hello")
            .build()
            .unwrap();

        engine
            .seal_blind_packet(&mut packet, &blind_keys, &channel)
            .unwrap();
        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        let mut wire = packet.as_bytes().to_vec();
        let opened = engine
            .decrypt_blind_addr(&mut wire, &header, &channel)
            .unwrap();
        let (decoded_dst, decoded_src) = (opened.dst, opened.source);
        let range = engine
            .open_packet(&mut wire, &header, &blind_keys, Some(&opened.addr))
            .unwrap();

        assert_eq!(decoded_dst, dst);
        assert_eq!(
            decoded_src,
            SourceAddrRef::FullKeyAt {
                offset: header.body_range.start - 32
            }
        );
        assert_eq!(
            &wire[header.body_range.start - 32..header.body_range.start],
            &src.0
        );
        assert_eq!(&wire[range], b"hello");
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn software_identity_agreement_is_symmetric() {
        let alice = SoftwareIdentity::from_secret_bytes(&[
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
            0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
            0x2D, 0x2E, 0x2F, 0x30,
        ]);
        let bob = SoftwareIdentity::from_secret_bytes(&[
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
            0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
            0x4D, 0x4E, 0x4F, 0x50,
        ]);

        let ab = alice.shared_secret_with(bob.public_key()).unwrap();
        let ba = bob.shared_secret_with(alice.public_key()).unwrap();
        assert_eq!(ab.0, ba.0);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn channel_tint_extends_the_channel_identifier() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = ChannelKey([0x5Au8; 32]);
        let tint = engine.derive_channel_tint(&key);
        // The presentation color is the identifier derivation run one byte
        // longer, so a caller holding either can recognize the other.
        assert_eq!(&tint[..2], &engine.derive_channel_id(&key).0[..]);
        assert_eq!(tint, engine.derive_channel_tint(&key));
        assert_ne!(tint, engine.derive_channel_tint(&ChannelKey([0x5Bu8; 32])));
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn channel_tag_extends_the_channel_identifier_and_tint() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = ChannelKey([0x5Au8; 32]);
        let tag = engine.derive_channel_tag(&key);
        // One derivation, three lengths: whoever holds the tag can recover the
        // identifier and the tint without the key.
        assert_eq!(tag.channel_id(), engine.derive_channel_id(&key));
        assert_eq!(&tag.0[..3], &engine.derive_channel_tint(&key)[..]);
        assert_eq!(tag, engine.derive_channel_tag(&key));
        assert_ne!(tag, engine.derive_channel_tag(&ChannelKey([0x5Bu8; 32])));
    }

    // ── derive_named_channel_key ──────────────────────────────────────────────

    #[cfg(feature = "software-crypto")]
    #[test]
    fn derive_named_channel_key_is_deterministic() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let k1 = engine.derive_named_channel_key("lobby").unwrap();
        let k2 = engine.derive_named_channel_key("lobby").unwrap();
        let k3 = engine.derive_named_channel_key("other").unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, ChannelKey([0u8; 32]));
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn derive_named_channel_key_folds_ascii_case() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let lower = engine.derive_named_channel_key("public").unwrap();
        assert_eq!(engine.derive_named_channel_key("Public").unwrap(), lower);
        assert_eq!(engine.derive_named_channel_key("PUBLIC").unwrap(), lower);
        // Digits and symbols are untouched by the fold.
        assert_eq!(
            engine.derive_named_channel_key("Mesh-42!").unwrap(),
            engine.derive_named_channel_key("mesh-42!").unwrap()
        );
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn derive_named_channel_key_rejects_invalid_names() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        assert_eq!(
            engine.derive_named_channel_key("caf\u{e9}"),
            Err(ChannelNameError::NotAscii)
        );
        let too_long = "x".repeat(MAX_CHANNEL_NAME_LEN + 1);
        assert_eq!(
            engine.derive_named_channel_key(&too_long),
            Err(ChannelNameError::TooLong)
        );
        // Exactly at the limit is fine.
        let at_limit = "x".repeat(MAX_CHANNEL_NAME_LEN);
        assert!(engine.derive_named_channel_key(&at_limit).is_ok());
    }

    // ── SoftwareIdentity::generate ────────────────────────────────────────────

    #[cfg(feature = "software-crypto")]
    #[test]
    fn software_identity_generate_produces_valid_key() {
        use rand_core::{CryptoRng, RngCore};

        // Minimal deterministic RNG for testing—counter-based, not cryptographically
        // strong, but sufficient to exercise the generate() code path.
        struct CounterRng(u64);
        impl RngCore for CounterRng {
            fn next_u32(&mut self) -> u32 {
                self.next_u64() as u32
            }
            fn next_u64(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(1);
                self.0
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for chunk in dest.chunks_mut(8) {
                    let bytes = self.next_u64().to_le_bytes();
                    chunk.copy_from_slice(&bytes[..chunk.len()]);
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl CryptoRng for CounterRng {}

        let mut rng1 = CounterRng(0);
        let mut rng2 = CounterRng(1000);
        let id1 = SoftwareIdentity::generate(&mut rng1);
        let id2 = SoftwareIdentity::generate(&mut rng2);
        assert_ne!(id1.public_key(), id2.public_key());
        let ss1 = id1.shared_secret_with(id2.public_key()).unwrap();
        let ss2 = id2.shared_secret_with(id1.public_key()).unwrap();
        assert_eq!(ss1.0, ss2.0);
    }

    // ── generate_identity_secret ──────────────────────────────────────────────

    #[cfg(feature = "software-crypto")]
    fn filter_avoiding(secret: &[u8; 32]) -> umsh_core::hint_filter::Filter {
        use umsh_core::hint_filter::{Filter, text_key};

        let public = *SoftwareIdentity::from_secret_bytes(secret).public_key();
        let digits = umsh_core::base58::encode(&public.0);
        let mut filter = Filter::empty(0);
        filter.insert(text_key(&digits[..4]).unwrap());
        assert!(filter.avoids(&public));
        filter
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn generate_identity_secret_redraws_avoided_keys() {
        let filter = filter_avoiding(&[1; 32]);
        let clean = SoftwareIdentity::from_secret_bytes(&[2; 32]);
        assert!(!filter.avoids(clean.public_key()));

        let mut draws = [[1u8; 32], [1; 32], [2; 32]].into_iter();
        let secret = generate_identity_secret_against(&filter, |secret| {
            *secret = draws.next().unwrap();
            Ok::<_, ()>(())
        });
        assert_eq!(secret, Ok([2; 32]));
        assert_eq!(draws.next(), None);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn generate_identity_secret_returns_entropy_errors() {
        let filter = filter_avoiding(&[1; 32]);
        let mut calls = 0;
        let secret = generate_identity_secret_against(&filter, |secret| {
            calls += 1;
            if calls == 1 {
                *secret = [1; 32];
                Ok(())
            } else {
                Err("no entropy")
            }
        });
        assert_eq!(secret, Err("no entropy"));
        assert_eq!(calls, 2);
    }

    // ── seal_blind_packet wrong packet type ───────────────────────────────────

    #[cfg(feature = "software-crypto")]
    #[test]
    fn seal_blind_packet_rejects_non_blind_packet() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let shared = SharedSecret([0x11u8; 32]);
        let pairwise = engine.derive_pairwise_keys(&shared, &TEST_LOCAL_KEY, &TEST_REMOTE_KEY);
        let channel_key = ChannelKey([0x5Au8; 32]);
        let channel = engine.derive_channel_keys(&channel_key);
        let blind_keys = engine.derive_blind_keys(&pairwise, &channel);
        let src = PublicKey([0xA1u8; 32]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let mut buf = [0u8; 128];
        // Build a regular unicast packet (not a blind unicast).
        let mut packet = PacketBuilder::new(&mut buf)
            .unicast(dst)
            .source_full(&src)
            .frame_counter(1)
            .encrypted()
            .mic_size(MicSize::Mic16)
            .payload(b"test")
            .build()
            .unwrap();
        assert!(matches!(
            engine.seal_blind_packet(&mut packet, &blind_keys, &channel),
            Err(CryptoError::InvalidPacket)
        ));
    }

    // ── open_packet authentication failure ────────────────────────────────────

    #[cfg(feature = "software-crypto")]
    #[test]
    fn open_packet_fails_on_tampered_ciphertext() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = engine.derive_pairwise_keys(
            &SharedSecret([9u8; 32]),
            &TEST_LOCAL_KEY,
            &TEST_REMOTE_KEY,
        );
        let src = PublicKey([0xA1; 32]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let mut buf = [0u8; 128];
        let mut packet = PacketBuilder::new(&mut buf)
            .unicast(dst)
            .source_full(&src)
            .frame_counter(1)
            .encrypted()
            .mic_size(MicSize::Mic16)
            .payload(b"hello")
            .build()
            .unwrap();
        engine.seal_packet(&mut packet, &keys).unwrap();

        // Flip a bit in the sealed packet body.
        let mut wire = packet.as_bytes().to_vec();
        let header = PacketHeader::parse(&wire).unwrap();
        wire[header.body_range.start] ^= 0x01;
        let tampered = wire.clone();

        assert!(matches!(
            engine.open_packet(&mut wire, &header, &keys, None),
            Err(CryptoError::AuthenticationFailed)
        ));
        // A failed open leaves its input exactly as it was, so the next
        // candidate key starts from the wire bytes.
        assert_eq!(wire, tampered);
    }

    // ── decrypt_blind_addr: encrypted hint source (len == 3) ─────────────────

    /// Unencrypted multicast puts SRC in S2 just as encrypted multicast
    /// does, so altering it fails the MIC.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn unencrypted_multicast_source_is_covered_by_the_mic() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let derived = engine.derive_channel_keys(&ChannelKey([0x42; 32]));
        let keys = PairwiseKeys {
            k_enc: derived.k_enc,
            k_mic: derived.k_mic,
        };
        let src = PublicKey([0xA1; 32]);
        let mut buf = [0u8; 128];
        let mut packet = PacketBuilder::new(&mut buf)
            .multicast(derived.channel_id)
            .source_hint(src.hint())
            .frame_counter(3)
            .mic_size(MicSize::Mic16)
            .payload(b"hello")
            .build()
            .unwrap();
        engine.seal_packet(&mut packet, &keys).unwrap();
        let wire = packet.as_bytes().to_vec();
        let header = PacketHeader::parse(&wire).unwrap();

        let mut opened = wire.clone();
        let range = engine
            .open_packet(&mut opened, &header, &keys, None)
            .unwrap();
        assert_eq!(&opened[range], b"hello");

        let mut tampered = wire.clone();
        tampered[header.protected_range().start] ^= 0x01;
        assert_eq!(
            engine.open_packet(&mut tampered, &header, &keys, None),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    /// The MIC covers a blind unicast's plaintext addresses, so flipping a
    /// bit of the encrypted DST or SRC—including SRC's sign bit, which
    /// would otherwise turn `P` into `−P`—fails at the true destination.
    #[cfg(feature = "software-crypto")]
    #[test]
    fn blind_unicast_addresses_are_authenticated() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let channel = engine.derive_channel_keys(&ChannelKey([0x5A; 32]));
        let pairwise = engine.derive_pairwise_keys(
            &SharedSecret([0x33; 32]),
            &TEST_LOCAL_KEY,
            &TEST_REMOTE_KEY,
        );
        let blind_keys = engine.derive_blind_keys(&pairwise, &channel);
        let src = PublicKey([0xA1; 32]);
        let mut buf = [0u8; 160];
        let mut packet = PacketBuilder::new(&mut buf)
            .blind_unicast(channel.channel_id, NodeHint([0xC3, 0xD4, 0x25]))
            .source_full(&src)
            .frame_counter(5)
            .encrypted()
            .mic_size(MicSize::Mic16)
            .payload(b"hello")
            .build()
            .unwrap();
        engine
            .seal_blind_packet(&mut packet, &blind_keys, &channel)
            .unwrap();
        let wire = packet.as_bytes().to_vec();
        let header = PacketHeader::parse(&wire).unwrap();
        let addr = header.blind_addr_range().unwrap();

        for flip in [addr.start, addr.end - 1] {
            let mut tampered = wire.clone();
            tampered[flip] ^= if flip == addr.end - 1 { 0x80 } else { 0x01 };
            let opened = engine
                .decrypt_blind_addr(&mut tampered, &header, &channel)
                .unwrap();
            assert_eq!(
                engine.open_packet(&mut tampered, &header, &blind_keys, Some(&opened.addr)),
                Err(CryptoError::AuthenticationFailed)
            );
        }

        let mut intact = wire.clone();
        let opened = engine
            .decrypt_blind_addr(&mut intact, &header, &channel)
            .unwrap();
        assert!(
            engine
                .open_packet(&mut intact, &header, &blind_keys, None)
                .is_err(),
            "a blind unicast cannot be opened without its address block"
        );
        let range = engine
            .open_packet(&mut intact, &header, &blind_keys, Some(&opened.addr))
            .unwrap();
        assert_eq!(&intact[range], b"hello");
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn decrypt_blind_addr_encrypted_hint_source() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let shared = SharedSecret([0x33u8; 32]);
        let pairwise = engine.derive_pairwise_keys(&shared, &TEST_LOCAL_KEY, &TEST_REMOTE_KEY);
        let channel_key = ChannelKey([0x5Au8; 32]);
        let channel = engine.derive_channel_keys(&channel_key);
        let blind_keys = engine.derive_blind_keys(&pairwise, &channel);
        let src = PublicKey([0xA1u8; 32]);
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let mut buf = [0u8; 128];
        // Use source_hint → produces Encrypted { len: 3 } in blind unicast.
        let mut packet = PacketBuilder::new(&mut buf)
            .blind_unicast(channel.channel_id, dst)
            .source_hint(src.hint())
            .frame_counter(5)
            .encrypted()
            .mic_size(MicSize::Mic16)
            .payload(b"hi")
            .build()
            .unwrap();
        engine
            .seal_blind_packet(&mut packet, &blind_keys, &channel)
            .unwrap();
        let mut wire = packet.as_bytes().to_vec();
        let header = PacketHeader::parse(&wire).unwrap();
        let opened = engine
            .decrypt_blind_addr(&mut wire, &header, &channel)
            .unwrap();
        let (decoded_dst, decoded_src) = (opened.dst, opened.source);
        assert_eq!(decoded_dst, dst);
        assert_eq!(decoded_src, SourceAddrRef::Hint(src.hint()));
    }

    // ── SoftwareAes::decrypt_block ────────────────────────────────────────────

    #[cfg(feature = "software-crypto")]
    #[test]
    fn aes_decrypt_block_inverts_encrypt_block() {
        let key = hex_32(NIST_AES256_KEY);
        let cipher = SoftwareAes.new_cipher(&key);
        let original = hex_16("6bc1bee22e409f96e93d7e117393172a");
        let mut block = original;
        cipher.encrypt_block(&mut block);
        assert_ne!(block, original);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, original);
    }

    // ── NodeIdentity trait: sign and agree ────────────────────────────────────

    #[cfg(feature = "software-crypto")]
    #[test]
    fn sign_and_agree_via_trait() {
        use core::future::Future;
        use core::pin::pin;
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn block_on<F: Future>(future: F) -> F::Output {
            let raw = RawWaker::new(
                core::ptr::null(),
                &RawWakerVTable::new(|_| panic!(), |_| {}, |_| {}, |_| {}),
            );
            let waker = unsafe { Waker::from_raw(raw) };
            let mut ctx = Context::from_waker(&waker);
            match pin!(future).poll(&mut ctx) {
                Poll::Ready(v) => v,
                Poll::Pending => panic!("future unexpectedly pending"),
            }
        }

        let alice = SoftwareIdentity::from_secret_bytes(&[0x11u8; 32]);
        let bob = SoftwareIdentity::from_secret_bytes(&[0x22u8; 32]);

        let sig = block_on(alice.sign(b"test message")).unwrap();
        assert_eq!(sig.len(), 64);

        let shared = block_on(alice.agree(bob.public_key())).unwrap();
        assert_ne!(shared.0, [0u8; 32]);
    }

    // ── NodeIdentity::hint default impl ───────────────────────────────────────

    #[cfg(feature = "software-crypto")]
    #[test]
    fn node_identity_hint_matches_public_key_hint() {
        let id = SoftwareIdentity::from_secret_bytes(&[0x11u8; 32]);
        // Calls the NodeIdentity::hint() default impl, which derives from public_key().
        assert_eq!(NodeIdentity::hint(&id), id.public_key().hint());
    }

    // ── uppercase hex in decode_hex ───────────────────────────────────────────

    #[test]
    fn hex_vec_accepts_uppercase() {
        assert_eq!(hex_vec("DEADBEEF"), hex_vec("deadbeef"));
        assert_eq!(hex_vec("0A1B2C3D"), hex_vec("0a1b2c3d"));
    }

    fn hex_vec(input: &str) -> std::vec::Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        let mut out = std::vec::Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();
        for index in (0..bytes.len()).step_by(2) {
            out.push((decode_hex(bytes[index]) << 4) | decode_hex(bytes[index + 1]));
        }
        out
    }

    fn hex_16(input: &str) -> [u8; 16] {
        let bytes = hex_vec(input);
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        out
    }

    #[cfg(feature = "software-crypto")]
    fn hex_32(input: &str) -> [u8; 32] {
        let bytes = hex_vec(input);
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn decode_hex(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex"),
        }
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn is_valid_ed25519_public_key_accepts_real_key() {
        // Any verifying key produced by a SigningKey is by construction a
        // valid Ed25519 point—the validator must accept it.
        let identity = SoftwareIdentity::from_secret_bytes(&[0x11; 32]);
        assert!(is_valid_ed25519_public_key(identity.public_key()));
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn is_valid_ed25519_public_key_rejects_non_curve_bytes() {
        // Y = 2 (little-endian) is not on the Ed25519 curve: the
        // recovered x^2 from the curve equation has no square root in
        // GF(2^255 - 19). Confirm the validator rejects it—this is
        // the exact failure mode a user typo trips when they paste a
        // mistyped hex pubkey on the CLI.
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        let bogus = PublicKey(bytes);
        assert!(!is_valid_ed25519_public_key(&bogus));
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn is_valid_ed25519_public_key_handles_all_zero() {
        // The all-zero compressed Y value decompresses to the curve
        // identity point. Whatever the library's actual behavior is,
        // pin it so a curve25519-dalek update can't silently flip the
        // contract. (Today: accepted as a valid point.)
        let zero = PublicKey([0u8; 32]);
        assert!(is_valid_ed25519_public_key(&zero));
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod frame_signature_tests {
    extern crate std;
    use std::vec::Vec;

    use ed25519_dalek::{Signer, SigningKey};
    use umsh_core::{
        ChannelCommitment, MAX_FRAME_LEN, OptionNumber, PacketBuilder, SIGNATURE_INPUT_MAX,
        signature_input,
    };

    use super::*;

    const SIGNER_SEED: [u8; 32] = [0x11; 32];
    const CHANNEL_A: ChannelKey = ChannelKey([0x5A; 32]);

    fn engine() -> SoftwareCryptoEngine {
        SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256)
    }

    fn signer() -> (SigningKey, PublicKey) {
        let key = SigningKey::from_bytes(&SIGNER_SEED);
        let public = PublicKey(key.verifying_key().to_bytes());
        (key, public)
    }

    /// A key other than [`CHANNEL_A`] that derives the same identifier.
    fn channel_b() -> ChannelKey {
        let mut bytes = [0x77; 32];
        bytes[..4].copy_from_slice(&0x0001_D29Au32.to_be_bytes());
        let key = ChannelKey(bytes);
        assert_eq!(
            engine().derive_channel_id(&key),
            engine().derive_channel_id(&CHANNEL_A)
        );
        key
    }

    fn channel_pairwise(derived: &DerivedChannelKeys) -> PairwiseKeys {
        PairwiseKeys {
            k_enc: derived.k_enc,
            k_mic: derived.k_mic,
        }
    }

    fn sign(
        frame: &[u8],
        blind_addr: Option<&BlindAddr>,
        channel: Option<&ChannelCommitment>,
    ) -> [u8; 64] {
        let header = PacketHeader::parse(frame).unwrap();
        let mut input = [0u8; SIGNATURE_INPUT_MAX];
        let len = signature_input(&header, frame, blind_addr, channel, &mut input).unwrap();
        signer().0.sign(&input[..len]).to_bytes()
    }

    /// A multicast from the signer, with `signature` in its slot (or a fresh
    /// one over the channel's commitment), sealed under `channel`.
    fn multicast(channel: &ChannelKey, encrypted: bool, signature: Option<[u8; 64]>) -> Vec<u8> {
        let derived = engine().derive_channel_keys(channel);
        let (_, public) = signer();
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .multicast(derived.channel_id)
            .source_hint(public.hint())
            .frame_counter(77)
            .signed();
        let builder = if encrypted {
            builder.encrypted()
        } else {
            builder
        };
        let mut packet = builder.payload(b"mayday").build().unwrap();
        let signature =
            signature.unwrap_or_else(|| sign(packet.as_bytes(), None, Some(&derived.commitment)));
        packet
            .signature_slot_mut()
            .unwrap()
            .copy_from_slice(&signature);
        engine()
            .seal_packet(&mut packet, &channel_pairwise(&derived))
            .unwrap();
        packet.as_bytes().to_vec()
    }

    /// Open `frame` under `channel` and check its signature against that
    /// channel's commitment. `None` if the MIC fails.
    fn open_and_verify(frame: &[u8], channel: &ChannelKey) -> Option<(Vec<u8>, bool)> {
        let derived = engine().derive_channel_keys(channel);
        let mut frame = frame.to_vec();
        let header = PacketHeader::parse(&frame).unwrap();
        let payload = engine()
            .open_packet(&mut frame, &header, &channel_pairwise(&derived), None)
            .ok()?;
        let (_, public) = signer();
        let mut scratch = [0u8; SIGNATURE_INPUT_MAX];
        let verified = verify_frame_signature(
            &header,
            &frame,
            &public,
            None,
            Some(&derived.commitment),
            &mut scratch,
        );
        Some((frame[payload].to_vec(), verified))
    }

    #[test]
    fn the_channel_commitment_begins_with_the_tag_and_identifier() {
        let engine = engine();
        let commitment = engine.derive_channel_commitment(&CHANNEL_A);
        assert_eq!(
            commitment.channel_tag(),
            engine.derive_channel_tag(&CHANNEL_A)
        );
        assert_eq!(
            commitment.channel_tag().channel_id(),
            engine.derive_channel_id(&CHANNEL_A)
        );
        assert_eq!(
            engine.derive_channel_keys(&CHANNEL_A).commitment,
            commitment
        );
    }

    #[test]
    fn a_signed_multicast_opens_and_verifies_with_either_e() {
        for encrypted in [false, true] {
            let frame = multicast(&CHANNEL_A, encrypted, None);
            let (payload, verified) = open_and_verify(&frame, &CHANNEL_A).unwrap();
            assert_eq!(payload, b"mayday", "E={encrypted}");
            assert!(verified, "E={encrypted}");
        }
    }

    /// The MIC covers the signature, encrypted or not.
    #[test]
    fn a_flipped_signature_bit_fails_the_mic() {
        for encrypted in [false, true] {
            let mut frame = multicast(&CHANNEL_A, encrypted, None);
            let header = PacketHeader::parse(&frame).unwrap();
            frame[header.signature().unwrap().range.start + 5] ^= 0x20;
            assert!(
                open_and_verify(&frame, &CHANNEL_A).is_none(),
                "E={encrypted}"
            );
        }
    }

    /// Someone holding both colliding keys re-seals a signed multicast under
    /// the other key. Its MIC verifies there, but the signature, made over
    /// the first channel's commitment, does not.
    #[test]
    fn a_signed_multicast_transplanted_to_a_colliding_channel_fails_its_signature() {
        let channel_b = channel_b();
        for encrypted in [false, true] {
            let original = multicast(&CHANNEL_A, encrypted, None);
            let (_, verified) = open_and_verify(&original, &CHANNEL_A).unwrap();
            assert!(verified);

            let mut opened = original.clone();
            let header = PacketHeader::parse(&opened).unwrap();
            let derived_a = engine().derive_channel_keys(&CHANNEL_A);
            engine()
                .open_packet(&mut opened, &header, &channel_pairwise(&derived_a), None)
                .unwrap();
            let signature: [u8; 64] = opened[header.signature().unwrap().range.clone()]
                .try_into()
                .unwrap();

            let transplanted = multicast(&channel_b, encrypted, Some(signature));
            let (payload, verified) = open_and_verify(&transplanted, &channel_b).unwrap();
            assert_eq!(payload, b"mayday");
            assert!(!verified, "E={encrypted}");
        }
    }

    /// The same transplant for a blind unicast, which also needs the
    /// pairwise keys.
    #[test]
    fn a_signed_blind_unicast_transplanted_to_a_colliding_channel_fails_its_signature() {
        let engine = engine();
        let (_, public) = signer();
        let pairwise = PairwiseKeys {
            k_enc: [3; 32],
            k_mic: [4; 32],
        };
        let dst = NodeHint([0xC3, 0xD4, 0x25]);
        let seal = |channel: &ChannelKey, signature: Option<[u8; 64]>| {
            let derived = engine.derive_channel_keys(channel);
            let blind_keys = engine.derive_blind_keys(&pairwise, &derived);
            let mut buf = [0u8; 256];
            let mut packet = PacketBuilder::new(&mut buf)
                .blind_unicast(derived.channel_id, dst)
                .source_full(&public)
                .frame_counter(5)
                .signed()
                .payload(b"hello")
                .build()
                .unwrap();
            let addr = BlindAddr::from_plaintext(packet.blind_addr().unwrap()).unwrap();
            let signature = signature
                .unwrap_or_else(|| sign(packet.as_bytes(), Some(&addr), Some(&derived.commitment)));
            packet
                .signature_slot_mut()
                .unwrap()
                .copy_from_slice(&signature);
            engine
                .seal_blind_packet(&mut packet, &blind_keys, &derived)
                .unwrap();
            (packet.as_bytes().to_vec(), signature)
        };
        let open = |frame: &[u8], channel: &ChannelKey| {
            let derived = engine.derive_channel_keys(channel);
            let blind_keys = engine.derive_blind_keys(&pairwise, &derived);
            let mut frame = frame.to_vec();
            let header = PacketHeader::parse(&frame).unwrap();
            let opened = engine
                .decrypt_blind_addr(&mut frame, &header, &derived)
                .unwrap();
            engine
                .open_packet(&mut frame, &header, &blind_keys, Some(&opened.addr))
                .unwrap();
            let mut scratch = [0u8; SIGNATURE_INPUT_MAX];
            verify_frame_signature(
                &header,
                &frame,
                &public,
                Some(&opened.addr),
                Some(&derived.commitment),
                &mut scratch,
            )
        };

        let (original, signature) = seal(&CHANNEL_A, None);
        assert!(open(&original, &CHANNEL_A));
        let (transplanted, _) = seal(&channel_b(), Some(signature));
        assert!(!open(&transplanted, &channel_b()));
    }

    /// A signed unicast opens, and its signature verifies without a
    /// commitment.
    #[test]
    fn a_signed_unicast_round_trips() {
        let engine = engine();
        let (_, public) = signer();
        let keys = PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
        };
        let mut buf = [0u8; 256];
        let mut packet = PacketBuilder::new(&mut buf)
            .unicast(NodeHint([0xC3, 0xD4, 0x25]))
            .source_full(&public)
            .frame_counter(3)
            .encrypted()
            .signed()
            .payload(b"hi")
            .build()
            .unwrap();
        let signature = sign(packet.as_bytes(), None, None);
        packet
            .signature_slot_mut()
            .unwrap()
            .copy_from_slice(&signature);
        engine.seal_packet(&mut packet, &keys).unwrap();
        let mut frame = packet.as_bytes().to_vec();
        let header = PacketHeader::parse(&frame).unwrap();
        let payload = engine
            .open_packet(&mut frame, &header, &keys, None)
            .unwrap();
        assert_eq!(&frame[payload], b"hi");
        let mut scratch = [0u8; SIGNATURE_INPUT_MAX];
        assert!(verify_frame_signature(
            &header,
            &frame,
            &public,
            None,
            None,
            &mut scratch
        ));
    }

    fn signed_broadcast(
        options: impl FnOnce(
            umsh_core::BroadcastBuilder<'_, umsh_core::state::Configuring>,
        ) -> umsh_core::BroadcastBuilder<'_, umsh_core::state::Configuring>,
        payload: &[u8],
    ) -> Vec<u8> {
        let (_, public) = signer();
        let mut buf = [0u8; 512];
        let builder = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_full(&public)
            .signed(0x0000_0100);
        let builder = options(builder);
        let mut frame = if payload.is_empty() {
            builder.build()
        } else {
            builder.payload(payload).build()
        }
        .unwrap()
        .to_vec();
        let signature = sign(&frame, None, None);
        let range = PacketHeader::parse(&frame)
            .unwrap()
            .signature()
            .unwrap()
            .range
            .clone();
        frame[range].copy_from_slice(&signature);
        frame
    }

    fn verify_broadcast(frame: &[u8]) -> bool {
        let (_, public) = signer();
        let header = PacketHeader::parse(frame).unwrap();
        let mut scratch = [0u8; SIGNATURE_INPUT_MAX];
        verify_frame_signature(&header, frame, &public, None, None, &mut scratch)
    }

    #[test]
    fn a_signed_broadcast_covers_its_counter_and_payload() {
        let frame = signed_broadcast(|builder| builder, b"advert");
        assert!(verify_broadcast(&frame));

        let mut tampered = frame.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(!verify_broadcast(&tampered));

        let mut tampered = frame.clone();
        let counter = PacketHeader::parse(&frame)
            .unwrap()
            .signature()
            .unwrap()
            .range
            .start
            - 1;
        tampered[counter] ^= 1;
        assert!(!verify_broadcast(&tampered));
    }

    /// The largest input a parsed frame can produce signs and verifies.
    #[test]
    fn the_largest_signature_input_signs_and_verifies() {
        let frame = signed_broadcast(
            |mut builder| {
                // FCF and full SRC (33), option 0 (70), then empty option
                // 16s: two bytes for the first, one for each repeat.
                for _ in 0..MAX_FRAME_LEN - 33 - 70 - 1 {
                    builder = builder.option(OptionNumber::Unknown(16), &[]);
                }
                builder
            },
            &[],
        );
        assert_eq!(frame.len(), MAX_FRAME_LEN);
        assert!(verify_broadcast(&frame));
    }
}
