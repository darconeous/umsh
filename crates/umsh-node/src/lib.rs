#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "alloc"))]
compile_error!("umsh-node currently requires the alloc feature");

extern crate alloc;

mod endpoint;
mod error;
mod mac;
mod owned;
#[cfg(feature = "software-crypto")]
mod pfs;

pub use endpoint::{Endpoint, EndpointConfig, UiAcceptancePolicy};
pub use error::EndpointError;
pub use mac::{NodeMac, NodeMacError};
pub use owned::{DeferredAction, EndpointEvent, EventAction, OwnedMacCommand, OwnedNodeIdentityPayload, OwnedTextMessage};
#[cfg(feature = "software-crypto")]
pub use pfs::{PfsSession, PfsSessionManager, PfsState};

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        future::Future,
        pin::pin,
        rc::Rc,
        task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    };

    use umsh_core::{ChannelId, PublicKey};
    #[cfg(feature = "software-crypto")]
    use umsh_crypto::software::SoftwareIdentity;
    use umsh_crypto::{AesCipher, AesProvider, CryptoEngine, NodeIdentity, PairwiseKeys, Sha256Provider, SharedSecret};
    use umsh_hal::{Clock, CounterStore, Radio, RxInfo, Rng};
    use umsh_mac::{CapacityError, LocalIdentityId, Mac, MacEventRef, MacHandle, OperatingPolicy, PeerCryptoState, PeerId, RepeaterConfig, SendError, SendOptions, SendReceipt};

    use crate::{Endpoint, EndpointConfig, EndpointEvent, EventAction, NodeMac, NodeMacError, OwnedMacCommand, UiAcceptancePolicy};

    #[test]
    fn endpoint_send_text_queues_unicast() {
        let mac = RefCell::new(make_mac());
        let handle = MacHandle::new(&mac);
        let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        let peer_key = PublicKey([0xAB; 32]);
        let peer_id = handle.add_peer(peer_key).unwrap();
        handle.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

        let endpoint = Endpoint::new(local_id, handle, EndpointConfig::default());
        endpoint.send_text(&peer_key, "hello").unwrap();

        assert_eq!(mac.borrow().tx_queue().len(), 1);
    }

    #[test]
    fn endpoint_handle_event_parses_text_messages() {
        let mac = RefCell::new(make_mac());
        let handle = MacHandle::new(&mac);
        let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        let mut endpoint = Endpoint::new(local_id, handle, EndpointConfig::default());
        let payload = [umsh_app::PayloadType::TextMessage as u8, 0xFF, b'h', b'i'];

        match endpoint.handle_event(MacEventRef::Unicast {
            from: PublicKey([0x22; 32]),
            payload: &payload,
            ack_requested: false,
        }) {
            EventAction::Handled(Some(EndpointEvent::TextReceived { from, message })) => {
                assert_eq!(from, PublicKey([0x22; 32]));
                assert_eq!(message.body, "hi");
            }
            other => panic!("unexpected event action: {other:?}"),
        }
    }

    #[test]
    fn endpoint_beacon_schedule_fires_once_due() {
        let mac = RefCell::new(make_mac());
        let handle = MacHandle::new(&mac);
        let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        let mut endpoint = Endpoint::new(
            local_id,
            handle,
            EndpointConfig {
                beacon_interval_ms: Some(100),
                ..EndpointConfig::default()
            },
        );

        assert!(!endpoint.send_scheduled_beacon(50).unwrap());
        assert!(endpoint.send_scheduled_beacon(100).unwrap());
        assert_eq!(mac.borrow().tx_queue().len(), 1);
    }

    #[test]
    fn endpoint_sync_policy_can_filter_direct_text() {
        let mac = RefCell::new(make_mac());
        let handle = MacHandle::new(&mac);
        let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        let mut endpoint = Endpoint::new(
            local_id,
            handle,
            EndpointConfig {
                ui_acceptance: UiAcceptancePolicy {
                    allow_direct_text: false,
                    ..UiAcceptancePolicy::default()
                },
                ..EndpointConfig::default()
            },
        );
        let payload = [umsh_app::PayloadType::TextMessage as u8, 0xFF, b'h', b'i'];

        match endpoint.handle_event(MacEventRef::Unicast {
            from: PublicKey([0x22; 32]),
            payload: &payload,
            ack_requested: false,
        }) {
            EventAction::Handled(None) => {}
            other => panic!("unexpected event action: {other:?}"),
        }
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn endpoint_pfs_establishes_routes_and_tears_down() {
        let mac = FakeMac::new(vec![[3u8; 32]]);
        let peer_long_term = PublicKey([0x55; 32]);
        let peer_ephemeral = PublicKey([0x66; 32]);
        let mut endpoint = Endpoint::new(LocalIdentityId(1), mac.clone(), EndpointConfig::default());

        endpoint.request_pfs_session(&peer_long_term, 60).unwrap();

        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].from, LocalIdentityId(1));
        assert_eq!(sent[0].to, peer_long_term);
        assert_eq!(parse_owned_mac_command(&sent[0].payload), OwnedMacCommand::PfsSessionRequest {
            ephemeral_key: *SoftwareIdentity::from_secret_bytes(&[3u8; 32]).public_key(),
            duration_minutes: 60,
        });

        let response_payload = encode_mac_payload(umsh_app::MacCommand::PfsSessionResponse {
            ephemeral_key: peer_ephemeral,
            duration_minutes: 60,
        });
        let deferred = match endpoint.handle_event(MacEventRef::Unicast {
            from: peer_long_term,
            payload: &response_payload,
            ack_requested: false,
        }) {
            EventAction::NeedsAsync(deferred) => deferred,
            other => panic!("unexpected event action: {other:?}"),
        };
        let event = block_on_ready(endpoint.handle_deferred(deferred));
        assert_eq!(event, Some(EndpointEvent::PfsSessionEstablished { peer: peer_long_term }));

        endpoint.send_text(&peer_long_term, "secret").unwrap();
        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].from, LocalIdentityId(10));
        assert_eq!(sent[0].to, peer_ephemeral);

        assert!(endpoint.end_pfs_session(&peer_long_term).unwrap());
        let sent = mac.take_unicasts();
        assert_eq!(sent.len(), 1);
        assert_eq!(parse_owned_mac_command(&sent[0].payload), OwnedMacCommand::EndPfsSession);
        assert_eq!(mac.take_removed_ephemerals(), vec![LocalIdentityId(10)]);
    }

    #[cfg(feature = "software-crypto")]
    #[test]
    fn endpoint_end_pfs_session_errors_when_missing() {
        let mac = FakeMac::new(Vec::new());
        let mut endpoint = Endpoint::new(LocalIdentityId(1), mac, EndpointConfig::default());

        let error = endpoint.end_pfs_session(&PublicKey([0x77; 32])).unwrap_err();
        assert!(matches!(error, crate::EndpointError::PfsSessionMissing));
    }

    fn make_mac() -> Mac<DummyRadio, DummyIdentity, DummyAes, DummySha, DummyClock, DummyRng, DummyCounterStore, 4, 16, 8, 16, 16, 256, 64> {
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

    struct DummyIdentity {
        public_key: PublicKey,
    }

    impl DummyIdentity {
        fn new(bytes: [u8; 32]) -> Self {
            Self { public_key: PublicKey(bytes) }
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
        transmitted: Vec<Vec<u8>>,
        received: VecDeque<Vec<u8>>,
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

    #[derive(Default)]
    struct DummyRng(u8);

    impl Rng for DummyRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

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

    #[cfg(feature = "software-crypto")]
    #[derive(Clone, Default)]
    struct FakeMac {
        state: Rc<RefCell<FakeMacState>>,
    }

    #[cfg(feature = "software-crypto")]
    #[derive(Default)]
    struct FakeMacState {
        random_blocks: VecDeque<[u8; 32]>,
        next_peer_id: u8,
        next_ephemeral_id: u8,
        now_ms: u64,
        unicasts: Vec<SentUnicast>,
        removed_ephemerals: Vec<LocalIdentityId>,
        peers: Vec<(PublicKey, PeerId)>,
        installed: Vec<(LocalIdentityId, PeerId, PairwiseKeys)>,
    }

    #[cfg(feature = "software-crypto")]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SentUnicast {
        from: LocalIdentityId,
        to: PublicKey,
        payload: Vec<u8>,
        options: SendOptions,
    }

    #[cfg(feature = "software-crypto")]
    impl FakeMac {
        fn new(random_blocks: Vec<[u8; 32]>) -> Self {
            Self {
                state: Rc::new(RefCell::new(FakeMacState {
                    random_blocks: random_blocks.into(),
                    next_peer_id: 0,
                    next_ephemeral_id: 10,
                    now_ms: 1_000,
                    ..FakeMacState::default()
                })),
            }
        }

        fn take_unicasts(&self) -> Vec<SentUnicast> {
            core::mem::take(&mut self.state.borrow_mut().unicasts)
        }

        fn take_removed_ephemerals(&self) -> Vec<LocalIdentityId> {
            core::mem::take(&mut self.state.borrow_mut().removed_ephemerals)
        }
    }

    #[cfg(feature = "software-crypto")]
    impl NodeMac for FakeMac {
        type SendError = SendError;
        type CapacityError = CapacityError;

        fn add_peer(&self, key: PublicKey) -> Result<PeerId, NodeMacError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            if let Some((_, existing)) = state.peers.iter().find(|(existing_key, _)| *existing_key == key) {
                return Ok(*existing);
            }
            let peer_id = PeerId(state.next_peer_id);
            state.next_peer_id = state.next_peer_id.wrapping_add(1);
            state.peers.push((key, peer_id));
            Ok(peer_id)
        }

        fn add_private_channel(&self, _key: umsh_core::ChannelKey) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        fn add_named_channel(&self, _name: &str) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        fn install_pairwise_keys(
            &self,
            identity_id: LocalIdentityId,
            peer_id: PeerId,
            pairwise_keys: PairwiseKeys,
        ) -> Result<Option<PeerCryptoState>, NodeMacError<Self::SendError, Self::CapacityError>> {
            self.state.borrow_mut().installed.push((identity_id, peer_id, pairwise_keys));
            Ok(None)
        }

        fn send_broadcast(
            &self,
            _from: LocalIdentityId,
            _payload: &[u8],
            _options: &SendOptions,
        ) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        fn send_multicast(
            &self,
            _from: LocalIdentityId,
            _channel: &ChannelId,
            _payload: &[u8],
            _options: &SendOptions,
        ) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
            Ok(())
        }

        fn send_unicast(
            &self,
            from: LocalIdentityId,
            dst: &PublicKey,
            payload: &[u8],
            options: &SendOptions,
        ) -> Result<Option<SendReceipt>, NodeMacError<Self::SendError, Self::CapacityError>> {
            self.state.borrow_mut().unicasts.push(SentUnicast {
                from,
                to: *dst,
                payload: payload.to_vec(),
                options: options.clone(),
            });
            Ok(Some(SendReceipt(42)))
        }

        fn send_blind_unicast(
            &self,
            from: LocalIdentityId,
            dst: &PublicKey,
            _channel: &ChannelId,
            payload: &[u8],
            options: &SendOptions,
        ) -> Result<Option<SendReceipt>, NodeMacError<Self::SendError, Self::CapacityError>> {
            self.send_unicast(from, dst, payload, options)
        }

        fn fill_random(&self, dest: &mut [u8]) -> Result<(), NodeMacError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            let next = state.random_blocks.pop_front().expect("test rng exhausted");
            dest.copy_from_slice(&next[..dest.len()]);
            Ok(())
        }

        fn now_ms(&self) -> Result<u64, NodeMacError<Self::SendError, Self::CapacityError>> {
            Ok(self.state.borrow().now_ms)
        }

        fn register_ephemeral(
            &self,
            _parent: LocalIdentityId,
            _identity: SoftwareIdentity,
        ) -> Result<LocalIdentityId, NodeMacError<Self::SendError, Self::CapacityError>> {
            let mut state = self.state.borrow_mut();
            let id = LocalIdentityId(state.next_ephemeral_id);
            state.next_ephemeral_id = state.next_ephemeral_id.wrapping_add(1);
            Ok(id)
        }

        fn remove_ephemeral(&self, id: LocalIdentityId) -> Result<bool, NodeMacError<Self::SendError, Self::CapacityError>> {
            self.state.borrow_mut().removed_ephemerals.push(id);
            Ok(true)
        }
    }

    #[cfg(feature = "software-crypto")]
    fn encode_mac_payload(command: umsh_app::MacCommand<'_>) -> Vec<u8> {
        let mut body = [0u8; 80];
        let len = umsh_app::mac_command::encode(&command, &mut body).unwrap();
        let mut payload = Vec::with_capacity(len + 1);
        payload.push(umsh_app::PayloadType::MacCommand as u8);
        payload.extend_from_slice(&body[..len]);
        payload
    }

    #[cfg(feature = "software-crypto")]
    fn parse_owned_mac_command(payload: &[u8]) -> OwnedMacCommand {
        match umsh_app::parse_payload(umsh_core::PacketType::Unicast, payload).unwrap() {
            umsh_app::PayloadRef::MacCommand(command) => OwnedMacCommand::from(command),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        fn raw_waker() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker { raw_waker() }
            fn wake(_: *const ()) {}
            fn wake_by_ref(_: *const ()) {}
            fn drop(_: *const ()) {}

            RawWaker::new(core::ptr::null(), &RawWakerVTable::new(clone, wake, wake_by_ref, drop))
        }

        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut context = Context::from_waker(&waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly returned Poll::Pending"),
        }
    }
}