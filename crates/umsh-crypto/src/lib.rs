#![allow(async_fn_in_trait)]

#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::Range;

use umsh_core::{
    feed_aad, ChannelId, ChannelKey, PacketHeader, PacketType, PublicKey, SourceAddr,
    SourceAddrRef, UnsealedPacket,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub trait AesCipher {
    fn encrypt_block(&self, block: &mut [u8; 16]);
    fn decrypt_block(&self, block: &mut [u8; 16]);
}

pub trait AesProvider {
    type Cipher: AesCipher;

    fn new_cipher(&self, key: &[u8; 16]) -> Self::Cipher;
}

pub trait Sha256Provider {
    fn hash(&self, data: &[&[u8]]) -> [u8; 32];
    fn hmac(&self, key: &[u8], data: &[&[u8]]) -> [u8; 32];
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

pub trait NodeIdentity {
    type Error;

    fn public_key(&self) -> &PublicKey;

    fn hint(&self) -> umsh_core::NodeHint {
        self.public_key().hint()
    }

    async fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error>;
    async fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidPublicKey,
    InvalidSharedSecret,
    InvalidPacket,
    AuthenticationFailed,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PairwiseKeys {
    pub k_enc: [u8; 16],
    pub k_mic: [u8; 16],
}

#[derive(Clone)]
pub struct DerivedChannelKeys {
    pub k_enc: [u8; 16],
    pub k_mic: [u8; 16],
    pub channel_id: ChannelId,
}

pub struct CmacState<C: AesCipher> {
    cipher: C,
    state: [u8; 16],
    buffer: [u8; 16],
    pos: usize,
    k1: [u8; 16],
    k2: [u8; 16],
}

impl<C: AesCipher> CmacState<C> {
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

pub struct CryptoEngine<A: AesProvider, S: Sha256Provider> {
    aes: A,
    sha: S,
}

impl<A: AesProvider, S: Sha256Provider> CryptoEngine<A, S> {
    pub fn new(aes: A, sha: S) -> Self {
        Self { aes, sha }
    }

    pub fn derive_pairwise_keys(&self, shared_secret: &SharedSecret) -> PairwiseKeys {
        let mut okm = [0u8; 32];
        self.hkdf(&shared_secret.0, b"UMSH-PAIRWISE-SALT", b"UMSH-UNICAST-V1", &mut okm);
        let mut keys = PairwiseKeys {
            k_enc: [0u8; 16],
            k_mic: [0u8; 16],
        };
        keys.k_enc.copy_from_slice(&okm[..16]);
        keys.k_mic.copy_from_slice(&okm[16..32]);
        okm.zeroize();
        keys
    }

    pub fn derive_channel_id(&self, channel_key: &ChannelKey) -> ChannelId {
        let mut out = [0u8; 2];
        self.hkdf(&channel_key.0, b"UMSH-CHAN-ID", b"", &mut out);
        ChannelId(out)
    }

    pub fn derive_channel_keys(&self, channel_key: &ChannelKey) -> DerivedChannelKeys {
        let channel_id = self.derive_channel_id(channel_key);
        let mut info = [0u8; 15];
        info[..13].copy_from_slice(b"UMSH-MCAST-V1");
        info[13..15].copy_from_slice(&channel_id.0);
        let mut okm = [0u8; 32];
        self.hkdf(&channel_key.0, b"UMSH-MCAST-SALT", &info, &mut okm);
        let mut derived = DerivedChannelKeys {
            k_enc: [0u8; 16],
            k_mic: [0u8; 16],
            channel_id,
        };
        derived.k_enc.copy_from_slice(&okm[..16]);
        derived.k_mic.copy_from_slice(&okm[16..32]);
        okm.zeroize();
        derived
    }

    pub fn derive_blind_keys(&self, pairwise: &PairwiseKeys, channel: &DerivedChannelKeys) -> PairwiseKeys {
        let mut keys = PairwiseKeys {
            k_enc: [0u8; 16],
            k_mic: [0u8; 16],
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

    pub fn derive_named_channel_key(&self, name: &str) -> ChannelKey {
        ChannelKey(self.sha.hmac(b"UMSH-CHANNEL-V1", &[name.as_bytes()]))
    }

    pub fn seal_packet(&self, packet: &mut UnsealedPacket<'_>, keys: &PairwiseKeys) -> Result<usize, CryptoError> {
        let header = packet.header().map_err(|_| CryptoError::InvalidPacket)?;
        let sec_info = header.sec_info.ok_or(CryptoError::InvalidPacket)?;
        let full_mac = {
            let bytes = packet.as_bytes();
            let mut cmac = self.cmac_state(&keys.k_mic);
            feed_aad(&header, bytes, |chunk| cmac.update(chunk));
            cmac.update(packet.body());
            cmac.finalize()
        };

        let mic_len = sec_info.scf.mic_size().map_err(|_| CryptoError::InvalidPacket)?.byte_len();
        packet.mic_slot()[..mic_len].copy_from_slice(&full_mac[..mic_len]);

        if sec_info.scf.encrypted() {
            let iv = self.build_ctr_iv(&full_mac[..mic_len], &packet.as_bytes()[header.sec_info_range.clone()]);
            self.aes_ctr(&keys.k_enc, &iv, packet.body_mut());
        }

        Ok(mic_len)
    }

    pub fn seal_blind_packet(
        &self,
        packet: &mut UnsealedPacket<'_>,
        blind_keys: &PairwiseKeys,
        channel_keys: &DerivedChannelKeys,
    ) -> Result<usize, CryptoError> {
        let header = packet.header().map_err(|_| CryptoError::InvalidPacket)?;
        match header.packet_type() {
            PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {}
            _ => return Err(CryptoError::InvalidPacket),
        }

        let sec_info = header.sec_info.ok_or(CryptoError::InvalidPacket)?;
        let blind_addr_range = packet.blind_addr_range().ok_or(CryptoError::InvalidPacket)?;
        let full_mac = {
            let bytes = packet.as_bytes();
            let mut cmac = self.cmac_state(&blind_keys.k_mic);
            feed_aad(&header, bytes, |chunk| cmac.update(chunk));
            cmac.update(packet.body());
            cmac.finalize()
        };

        let mic_len = sec_info.scf.mic_size().map_err(|_| CryptoError::InvalidPacket)?.byte_len();
        let iv = self.build_ctr_iv(&full_mac[..mic_len], &packet.as_bytes()[header.sec_info_range.clone()]);
        packet.mic_slot()[..mic_len].copy_from_slice(&full_mac[..mic_len]);
        self.aes_ctr(&blind_keys.k_enc, &iv, packet.body_mut());
        self.aes_ctr(&channel_keys.k_enc, &iv, &mut packet.as_bytes_mut()[blind_addr_range]);
        Ok(mic_len)
    }

    pub fn open_packet(&self, buf: &mut [u8], header: &PacketHeader, keys: &PairwiseKeys) -> Result<Range<usize>, CryptoError> {
        let sec_info = header.sec_info.ok_or(CryptoError::InvalidPacket)?;
        let mut mic = [0u8; 16];
        let mic_len = header.mic_range.end - header.mic_range.start;
        mic[..mic_len].copy_from_slice(&buf[header.mic_range.clone()]);
        if sec_info.scf.encrypted() {
            let iv = self.build_ctr_iv(&mic[..mic_len], &buf[header.sec_info_range.clone()]);
            self.aes_ctr(&keys.k_enc, &iv, &mut buf[header.body_range.clone()]);
        }

        let full_mac = {
            let mut cmac = self.cmac_state(&keys.k_mic);
            feed_aad(header, buf, |chunk| cmac.update(chunk));
            cmac.update(&buf[header.body_range.clone()]);
            cmac.finalize()
        };
        if !constant_time_eq(&mic[..mic_len], &full_mac[..mic_len]) {
            return Err(CryptoError::AuthenticationFailed);
        }

        let body_range = match (header.packet_type(), header.source) {
            (PacketType::Multicast, SourceAddrRef::Encrypted { len, .. }) => {
                (header.body_range.start + len)..header.body_range.end
            }
            _ => header.body_range.clone(),
        };
        Ok(body_range)
    }

    pub fn decrypt_blind_addr(
        &self,
        buf: &mut [u8],
        header: &PacketHeader,
        channel_keys: &DerivedChannelKeys,
    ) -> Result<(umsh_core::NodeHint, SourceAddr), CryptoError> {
        let SourceAddrRef::Encrypted { offset, len } = header.source else {
            return Err(CryptoError::InvalidPacket);
        };
        let addr_start = offset.checked_sub(3).ok_or(CryptoError::InvalidPacket)?;
        let addr_end = addr_start + 3 + len;
        let iv = self.build_ctr_iv(&buf[header.mic_range.clone()], &buf[header.sec_info_range.clone()]);
        self.aes_ctr(&channel_keys.k_enc, &iv, &mut buf[addr_start..addr_end]);
        let dst = umsh_core::NodeHint([buf[addr_start], buf[addr_start + 1], buf[addr_start + 2]]);
        let source = if len == 3 {
            SourceAddr::Hint(umsh_core::NodeHint([
                buf[addr_start + 3],
                buf[addr_start + 4],
                buf[addr_start + 5],
            ]))
        } else if len == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&buf[addr_start + 3..addr_end]);
            SourceAddr::Full(PublicKey(key))
        } else {
            return Err(CryptoError::InvalidPacket);
        };
        Ok((dst, source))
    }

    pub fn compute_ack_tag(&self, full_cmac: &[u8; 16], k_enc: &[u8; 16]) -> [u8; 8] {
        let cipher = self.aes.new_cipher(k_enc);
        let mut block = *full_cmac;
        cipher.encrypt_block(&mut block);
        let mut ack = [0u8; 8];
        ack.copy_from_slice(&block[..8]);
        ack
    }

    pub fn cmac_state(&self, key: &[u8; 16]) -> CmacState<A::Cipher> {
        CmacState::new(self.aes.new_cipher(key))
    }

    pub fn aes_cmac(&self, key: &[u8; 16], data: &[&[u8]]) -> [u8; 16] {
        let mut state = self.cmac_state(key);
        for chunk in data {
            state.update(chunk);
        }
        state.finalize()
    }

    pub fn aes_ctr(&self, key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
        let cipher = self.aes.new_cipher(key);
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

    pub fn build_ctr_iv(&self, mic: &[u8], sec_info_bytes: &[u8]) -> [u8; 16] {
        let mut iv = [0u8; 16];
        let mut written = 0usize;
        for byte in mic.iter().chain(sec_info_bytes.iter()).take(16) {
            iv[written] = *byte;
            written += 1;
        }
        iv
    }

    pub fn hkdf(&self, ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) {
        let prk = self.sha.hmac(salt, &[ikm]);
        let mut previous = [0u8; 32];
        let mut previous_len = 0usize;
        let mut written = 0usize;
        let mut counter = 1u8;
        while written < okm.len() {
            let next = self.sha.hmac(&prk, &[&previous[..previous_len], info, &[counter]]);
            let take = (okm.len() - written).min(next.len());
            okm[written..written + take].copy_from_slice(&next[..take]);
            previous = next;
            previous_len = 32;
            written += take;
            counter = counter.wrapping_add(1);
        }
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

fn increment_counter(counter: &mut [u8; 16]) {
    for byte in counter.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (lhs, rhs) in left.iter().zip(right.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

#[cfg(feature = "software-crypto")]
pub mod software {
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
    use curve25519_dalek::{edwards::CompressedEdwardsY, montgomery::MontgomeryPoint};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::CryptoRngCore;
    use sha2::{Digest, Sha256, Sha512};

    use super::*;

    pub struct SoftwareAes;

    pub struct SoftwareAesCipher(aes::Aes128);

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

        fn new_cipher(&self, key: &[u8; 16]) -> Self::Cipher {
            SoftwareAesCipher(aes::Aes128::new(GenericArray::from_slice(key)))
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

    pub struct SoftwareIdentity {
        secret: SigningKey,
        public: PublicKey,
    }

    impl SoftwareIdentity {
        pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
            let secret = SigningKey::generate(rng);
            let public = PublicKey(secret.verifying_key().to_bytes());
            Self { secret, public }
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
        let compressed = CompressedEdwardsY(public.0);
        let edwards = compressed.decompress().ok_or(CryptoError::InvalidPublicKey)?;
        let mont: MontgomeryPoint = edwards.to_montgomery();
        Ok(x25519_dalek::PublicKey::from(mont.to_bytes()))
    }
}

#[cfg(feature = "software-crypto")]
pub use software::*;

#[cfg(test)]
mod tests {
    use crate::{constant_time_eq, dbl};

    #[cfg(feature = "software-crypto")]
    use super::{software::*, *};
    #[cfg(feature = "software-crypto")]
    use umsh_core::{MicSize, NodeHint, PacketBuilder, PacketHeader, PublicKey};

    #[cfg(feature = "software-crypto")]
    #[test]
    fn pairwise_hkdf_is_stable() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = engine.derive_pairwise_keys(&SharedSecret([7u8; 32]));
        assert_ne!(keys.k_enc, [0u8; 16]);
        assert_ne!(keys.k_mic, [0u8; 16]);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn aes_cmac_matches_rfc4493_example_2() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = hex_16("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = hex_vec("6bc1bee22e409f96e93d7e117393172a");
        let expected = hex_16("070a16b46b4d4144f79bdd9dd04a287c");
        assert_eq!(engine.aes_cmac(&key, &[&msg]), expected);
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
        assert_eq!(okm.to_vec(), hex_vec("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
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
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn unicast_seal_and_open_round_trip() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let keys = engine.derive_pairwise_keys(&SharedSecret([9u8; 32]));
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
        let range = engine.open_packet(&mut wire, &header, &keys).unwrap();
        assert_eq!(&wire[range], b"hello");
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
        let range = engine.open_packet(&mut wire, &header, &multicast_keys).unwrap();
        assert_eq!(&wire[header.body_range.start..header.body_range.start + 3], &src.hint().0);
        assert_eq!(&wire[range], b"hello");
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn blind_unicast_round_trip_recovers_addresses_and_payload() {
        let engine = SoftwareCryptoEngine::new(SoftwareAes, SoftwareSha256);
        let shared = SharedSecret([0x33u8; 32]);
        let pairwise = engine.derive_pairwise_keys(&shared);
        let channel_key = ChannelKey([0x5Au8; 32]);
        let channel = engine.derive_channel_keys(&channel_key);
        let blind_keys = engine.derive_blind_keys(&pairwise, &channel);
        let src = PublicKey([
            0xA1, 0xB2, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
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

        engine.seal_blind_packet(&mut packet, &blind_keys, &channel).unwrap();
        let header = PacketHeader::parse(packet.as_bytes()).unwrap();
        let mut wire = packet.as_bytes().to_vec();
        let (decoded_dst, decoded_src) = engine.decrypt_blind_addr(&mut wire, &header, &channel).unwrap();
        let range = engine.open_packet(&mut wire, &header, &blind_keys).unwrap();

        assert_eq!(decoded_dst, dst);
        assert_eq!(decoded_src, SourceAddr::Full(src));
        assert_eq!(&wire[range], b"hello");
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn software_identity_agreement_is_symmetric() {
        let alice = SoftwareIdentity::from_secret_bytes(&[
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        ]);
        let bob = SoftwareIdentity::from_secret_bytes(&[
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
        ]);

        let ab = alice.shared_secret_with(bob.public_key()).unwrap();
        let ba = bob.shared_secret_with(alice.public_key()).unwrap();
        assert_eq!(ab.0, ba.0);
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
}
