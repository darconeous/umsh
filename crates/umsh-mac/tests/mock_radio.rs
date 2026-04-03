use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
};
use core::convert::Infallible;

use embedded_hal_async::delay::DelayNs;
use rand::{Rng, TryCryptoRng, TryRng};
use umsh_core::{PacketBuilder, PublicKey};
use umsh_crypto::{
    AesCipher, AesProvider, CryptoEngine, NodeIdentity, PairwiseKeys, Sha256Provider,
    SharedSecret,
};
use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo};
use umsh_mac::{Mac, MacEventRef, MacHandle, OperatingPolicy, Platform, RepeaterConfig, SendOptions};

#[test]
fn mac_handle_send_unicast_queues_public_api_work() {
    let mac = RefCell::new(make_mac());
    let handle = MacHandle::new(&mac);
    let handle_clone = handle.clone();

    let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = handle_clone.add_peer(peer_key).unwrap();
    handle
        .install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] })
        .unwrap();

    let receipt = handle_clone
        .send_unicast(local_id, &peer_key, b"hello", &SendOptions::default().with_ack_requested(true).no_flood())
        .unwrap()
        .unwrap();

    {
        let borrowed = mac.borrow();
        assert_eq!(borrowed.tx_queue().len(), 1);
        assert!(borrowed.identity(local_id).unwrap().pending_ack(&receipt).is_some());
    }

    block_on(mac.borrow_mut().drain_tx_queue()).unwrap();
    assert_eq!(mac.borrow().radio().transmitted.len(), 1);
}

#[test]
fn poll_cycle_delivers_unicast_and_sends_ack_via_public_api() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_id = mac.add_peer(*remote.public_key());
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone()).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();
    mac.radio_mut().queue_received_unicast(&remote, &keys, &dst_hint, b"hello", true);

    let mut seen = None;
    block_on(mac.poll_cycle(|identity, event| {
        if let MacEventRef::Unicast { from, payload, ack_requested } = event {
            seen = Some((identity, from, payload.to_vec(), ack_requested));
        }
    }))
    .unwrap();

    assert_eq!(seen, Some((local_id, *remote.public_key(), b"hello".to_vec(), true)));
    assert_eq!(mac.radio().transmitted.len(), 1);
}

fn make_mac() -> Mac<DummyPlatform, 4, 16, 8, 16, 16, 256, 64> {
    Mac::new(
        DummyRadio::default(),
        CryptoEngine::new(DummyAes, DummySha),
        DummyClock::default(),
        DummyRng::default(),
        DummyCounterStore,
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    )
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    fn raw_waker() -> std::task::RawWaker {
        fn clone(_: *const ()) -> std::task::RawWaker { raw_waker() }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}

        static VTABLE: std::task::RawWakerVTable =
            std::task::RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        std::task::RawWaker::new(std::ptr::null(), &VTABLE)
    }

    let waker = unsafe { std::task::Waker::from_raw(raw_waker()) };
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(&waker);

    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

struct DummyIdentity {
    public_key: PublicKey,
}

impl DummyIdentity {
    fn new(bytes: [u8; 32]) -> Self {
        Self {
            public_key: PublicKey(bytes),
        }
    }
}

impl NodeIdentity for DummyIdentity {
    type Error = ();

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    async fn sign(&self, _message: &[u8]) -> Result<[u8; 64], Self::Error> {
        Ok([0u8; 64])
    }

    async fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, Self::Error> {
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = self.public_key.0[index] ^ peer.0[index];
        }
        Ok(SharedSecret(out))
    }
}

struct DummyCipher {
    key: [u8; 16],
}

impl AesCipher for DummyCipher {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        for (byte, key) in block.iter_mut().zip(self.key.iter()) {
            *byte ^= *key;
        }
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        self.encrypt_block(block);
    }
}

struct DummyAes;

impl AesProvider for DummyAes {
    type Cipher = DummyCipher;

    fn new_cipher(&self, key: &[u8; 16]) -> Self::Cipher {
        DummyCipher { key: *key }
    }
}

struct DummySha;

impl Sha256Provider for DummySha {
    fn hash(&self, data: &[&[u8]]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in data {
            for (index, byte) in chunk.iter().enumerate() {
                out[index % 32] ^= *byte;
            }
        }
        out
    }

    fn hmac(&self, key: &[u8], data: &[&[u8]]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, byte) in key.iter().enumerate() {
            out[index % 32] ^= *byte;
        }
        for chunk in data {
            for (index, byte) in chunk.iter().enumerate() {
                out[index % 32] ^= *byte;
            }
        }
        out
    }
}

#[derive(Default)]
struct DummyRadio {
    received: VecDeque<Vec<u8>>,
    transmitted: Vec<Vec<u8>>,
}

impl DummyRadio {
    fn queue_received_unicast(
        &mut self,
        source: &DummyIdentity,
        keys: &PairwiseKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
        ack_requested: bool,
    ) {
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .unicast(*dst)
            .source_full(source.public_key())
            .frame_counter(7)
            .encrypted();
        let builder = if ack_requested { builder.ack_requested() } else { builder };
        let mut packet = builder.payload(payload).build().unwrap();
        CryptoEngine::new(DummyAes, DummySha)
            .seal_packet(&mut packet, keys)
            .unwrap();
        self.received.push_back(packet.as_bytes().to_vec());
    }
}

impl Radio for DummyRadio {
    type Error = ();

    async fn transmit(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.transmitted.push(data.to_vec());
        Ok(())
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<RxInfo, Self::Error> {
        if let Some(frame) = self.received.pop_front() {
            let len = frame.len();
            buf[..len].copy_from_slice(&frame);
            Ok(RxInfo { len, rssi: -40, snr: 10 })
        } else {
            Ok(RxInfo { len: 0, rssi: 0, snr: 0 })
        }
    }

    async fn cad(&mut self) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn max_frame_size(&self) -> usize {
        256
    }

    fn t_frame_ms(&self) -> u32 {
        10
    }
}

#[derive(Default)]
struct DummyClock {
    now_ms: Cell<u64>,
}

impl Clock for DummyClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.get()
    }
}

#[derive(Clone, Copy, Default)]
struct DummyDelay;

impl DelayNs for DummyDelay {
    async fn delay_ns(&mut self, _ns: u32) {}
}

#[derive(Default)]
struct DummyRng(u8);

impl TryRng for DummyRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

impl TryCryptoRng for DummyRng {}

struct DummyCounterStore;

impl CounterStore for DummyCounterStore {
    type Error = ();

    async fn load(&self, _context: &[u8]) -> Result<u32, Self::Error> {
        Ok(0)
    }

    async fn store(&self, _context: &[u8], _value: u32) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct DummyKeyValueStore;

impl KeyValueStore for DummyKeyValueStore {
    type Error = ();

    async fn load(&self, _key: &[u8], _buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(None)
    }

    async fn store(&self, _key: &[u8], _value: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn delete(&self, _key: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct DummyPlatform;

impl Platform for DummyPlatform {
    type Identity = DummyIdentity;
    type Aes = DummyAes;
    type Sha = DummySha;
    type Radio = DummyRadio;
    type Delay = DummyDelay;
    type Clock = DummyClock;
    type Rng = DummyRng;
    type CounterStore = DummyCounterStore;
    type KeyValueStore = DummyKeyValueStore;
}