//! Real companion NCP session behind a deterministic in-memory virtual link.

use std::collections::VecDeque;

use umsh_companion::battery::{BatteryChargeState, BatteryStatus};
use umsh_companion::{Status, hdlc};
use umsh_companion_ncp::{
    BatteryFields, DutyLedger, Effect, IdentitySource, RadioSettings, SNAPSHOT_MAX, Session,
    SessionConfig,
};
use umsh_core::{NodeHint, PacketBuilder};
use umsh_crypto::{
    CryptoEngine, NodeIdentity,
    software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
};

const WIRE_CAPACITY: usize = umsh_companion::gatt::MAX_FRAME;

type NcpSession = Session<SoftwareAes, SoftwareSha256>;

/// A deterministic, RAM-backed NCP that speaks HDLC-Lite exactly like USB.
///
/// The storage, radio, RSSI sampler, and entropy source are small stand-ins;
/// every protocol decision is made by the production NCP [`Session`].
pub struct SimulatedNcp {
    session: NcpSession,
    decoder: hdlc::Decoder<WIRE_CAPACITY>,
    outbound: VecDeque<Vec<u8>>,
    snapshot: Option<Vec<u8>>,
    identity: Option<([u8; 32], [u8; 32])>,
    identity_seed: u8,
    pairing_pin: Option<u32>,
    air: Vec<Vec<u8>>,
    now_ms: u64,
}

impl Default for SimulatedNcp {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulatedNcp {
    pub fn new() -> Self {
        Self {
            session: NcpSession::new(
                session_config(),
                Status::RESET_POWER_ON,
                CryptoEngine::new(SoftwareAes, SoftwareSha256),
            ),
            decoder: hdlc::Decoder::new(),
            outbound: VecDeque::new(),
            snapshot: None,
            identity: None,
            identity_seed: 0,
            pairing_pin: None,
            air: Vec::new(),
            now_ms: 0,
        }
    }

    /// Attach over the virtual equivalent of a physically secure serial link.
    pub fn attach(&mut self) {
        self.decoder.reset();
        self.outbound.clear();
        self.session.attach(true);
    }

    pub fn detach(&mut self) {
        self.decoder.reset();
        self.outbound.clear();
        self.session.detach();
    }

    /// Feed an arbitrary serial byte chunk into the virtual USB link.
    pub fn ingest(&mut self, bytes: &[u8], now_ms: u64) -> Result<(), String> {
        self.now_ms = now_ms;
        for &byte in bytes {
            let outcome = self
                .decoder
                .push(byte)
                .map(|result| result.map(<[u8]>::to_vec));
            if let Some(outcome) = outcome {
                let frame = outcome.map_err(|error| format!("HDLC decode error: {error:?}"))?;
                self.handle_frame(&frame);
            }
        }
        Ok(())
    }

    pub fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    /// Put a canned radio frame through the real NCP receive path.
    pub fn inject_radio_rx(&mut self, bytes: &[u8], now_ms: u64) {
        self.now_ms = now_ms;
        let mut emitted = Vec::new();
        let effect = self
            .session
            .on_radio_rx(bytes, -82, 35, None, now_ms, &mut |frame| {
                emitted.push(frame.to_vec())
            });
        self.execute(effect, &mut emitted);
        self.queue_emitted(emitted);
    }

    /// Build and inject a small valid UMSH packet for interactive UI demos.
    pub fn inject_demo_rx(&mut self, now_ms: u64) {
        let mut bytes = [0; 64];
        let packet = PacketBuilder::new(&mut bytes)
            .broadcast()
            .source_hint(NodeHint([0x11, 0x22, 0x33]))
            .flood_hops(3)
            .payload(b"hello from the simulated radio")
            .build()
            .expect("fixed demo packet fits")
            .to_vec();
        self.inject_radio_rx(&packet, now_ms);
    }

    #[cfg(test)]
    fn transmitted_frames(&self) -> &[Vec<u8>] {
        &self.air
    }

    fn handle_frame(&mut self, frame: &[u8]) {
        let mut emitted = Vec::new();
        let effect = self.session.handle_frame(frame, self.now_ms, &mut |bytes| {
            emitted.push(bytes.to_vec())
        });
        self.execute(effect, &mut emitted);
        self.queue_emitted(emitted);
    }

    fn execute(&mut self, effect: Option<Effect>, emitted: &mut Vec<Vec<u8>>) {
        let mut emit = |frame: &[u8]| emitted.push(frame.to_vec());
        match effect {
            None | Some(Effect::ApplyRadio(_)) | Some(Effect::DeviceNameChanged) => {}
            Some(Effect::StartTransmit) => {
                self.air.push(self.session.tx_data().to_vec());
                self.session.on_tx_result(true, self.now_ms, &mut emit);
            }
            Some(Effect::SampleRssi { tid }) => {
                self.session.respond_rssi(tid, Ok(-77), &mut emit);
            }
            Some(Effect::SampleBattery { tid }) => {
                // Stable, human-recognizable simulated measurement
                // matching the configured field set below.
                self.session.respond_battery(
                    tid,
                    Ok(BatteryStatus {
                        voltage_mv: Some(4111),
                        level_percent: Some(87),
                        charge_state: Some(BatteryChargeState::Charging),
                    }),
                    &mut emit,
                );
            }
            Some(Effect::SetPairingPin { tid, pin }) => {
                self.pairing_pin = pin;
                self.session.respond_pin_set(tid, Ok(()), &mut emit);
            }
            Some(Effect::WipeHostDomain { tid }) => {
                let mut buf = [0u8; SNAPSHOT_MAX];
                if let Some(len) = self.session.encode_wiped_snapshot(&mut buf) {
                    self.snapshot = Some(buf[..len].to_vec());
                }
                self.session.respond_host_wipe(tid, Ok(()), &mut emit);
            }
            Some(Effect::DrainQueue) => while self.session.drain_step(self.now_ms, &mut emit) {},
            Some(Effect::SaveSnapshot { tid }) => {
                let mut buf = [0u8; SNAPSHOT_MAX];
                let result = match self.session.encode_snapshot(&mut buf) {
                    Some(len) => {
                        self.snapshot = Some(buf[..len].to_vec());
                        Ok(())
                    }
                    None => Err(()),
                };
                self.session.respond_save(tid, result, &mut emit);
            }
            Some(Effect::ClearSaved { tid }) => {
                self.snapshot = None;
                self.identity = None;
                self.session.respond_clear(tid, Ok(()), &mut emit);
            }
            Some(Effect::FactoryReset) => {
                // Emulate the platform wipe-and-reboot: drop every persisted
                // artifact (snapshot, identity, bonds/PIN) and bring the
                // session back up factory-fresh as from a power cycle. No
                // reply is emitted — on hardware the reboot drops the link.
                self.snapshot = None;
                self.identity = None;
                self.identity_seed = 0;
                self.pairing_pin = None;
                self.session = NcpSession::new(
                    session_config(),
                    Status::RESET_POWER_ON,
                    CryptoEngine::new(SoftwareAes, SoftwareSha256),
                );
            }
            Some(Effect::ProvisionIdentity { tid }) => {
                let result = match self.session.identity_request() {
                    Some(source) => {
                        let secret = match source {
                            IdentitySource::Install(secret) => secret,
                            IdentitySource::Generate => {
                                self.identity_seed = self.identity_seed.wrapping_add(1).max(1);
                                [self.identity_seed; 32]
                            }
                        };
                        let public = SoftwareIdentity::from_secret_bytes(&secret).public_key().0;
                        self.identity = Some((secret, public));
                        Ok(public)
                    }
                    None => Err(()),
                };
                self.session.respond_identity(tid, result, &mut emit);
            }
        }
    }

    fn queue_emitted(&mut self, emitted: Vec<Vec<u8>>) {
        for frame in emitted {
            let mut encoded = vec![0; hdlc::max_encoded_len(frame.len())];
            let len = hdlc::encode_frame(&frame, &mut encoded)
                .expect("simulated NCP output buffer uses HDLC worst-case size");
            encoded.truncate(len);
            self.outbound.push_back(encoded);
        }
    }
}

fn session_config() -> SessionConfig {
    SessionConfig {
        ncp_version: "umsh-web-sim/0.1",
        default_device_name: "Browser simulated NCP",
        mtu: 255,
        sync_word: 0x1424,
        min_tx_power_dbm: -9,
        max_tx_power_dbm: 22,
        freq_khz_min: 150_000,
        freq_khz_max: 960_000,
        defaults: RadioSettings {
            enabled: false,
            freq_khz: 910_525,
            bw_hz: 62_500,
            sf: 7,
            cr_denom: 5,
            tx_power_dbm: 14,
        },
        default_duty_limit: 0xFFFF,
        duty: Box::leak(Box::new(DutyLedger::new())),
        // The browser simulator reports all three battery measurements.
        battery: Some(BatteryFields {
            voltage: true,
            level: true,
            charge_state: true,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_companion::{Frame, PropPayload, frame, ids::prop};

    fn exchange(sim: &mut SimulatedNcp, request: &[u8]) -> Vec<Vec<u8>> {
        let mut wire = vec![0; hdlc::max_encoded_len(request.len())];
        let len = hdlc::encode_frame(request, &mut wire).unwrap();
        sim.ingest(&wire[..len], 100).unwrap();

        let mut frames = Vec::new();
        while let Some(wire) = sim.take_outbound() {
            let mut decoder = hdlc::Decoder::<WIRE_CAPACITY>::new();
            frames.push(
                wire.into_iter()
                    .find_map(|byte| decoder.push(byte).map(|frame| frame.unwrap().to_vec()))
                    .unwrap(),
            );
        }
        frames
    }

    #[test]
    fn real_session_answers_attach_property_over_hdlc() {
        let mut sim = SimulatedNcp::new();
        sim.attach();
        let mut request = [0; 16];
        let len = frame::prop_get(&mut request, 1, prop::NCP_VERSION).unwrap();
        let responses = exchange(&mut sim, &request[..len]);
        assert_eq!(responses.len(), 1);
        let response = Frame::parse(&responses[0]).unwrap();
        let payload = PropPayload::parse(response.payload).unwrap();
        assert_eq!(payload.key, prop::NCP_VERSION);
        assert_eq!(payload.value, b"umsh-web-sim/0.1\0");
    }

    #[test]
    fn real_session_executes_radio_transmit_effect() {
        let mut sim = SimulatedNcp::new();
        sim.attach();
        let mut request = [0; 64];
        let len = frame::prop_set(&mut request, 1, prop::PHY_ENABLED, &[1]).unwrap();
        exchange(&mut sim, &request[..len]);
        let len = frame::str_send(
            &mut request,
            2,
            umsh_companion::ids::stream::PHY_RAW,
            b"demo",
            &[],
        )
        .unwrap();
        exchange(&mut sim, &request[..len]);
        assert_eq!(sim.transmitted_frames(), &[b"demo".to_vec()]);
    }

    #[test]
    fn demo_packet_uses_the_real_receive_path() {
        let mut sim = SimulatedNcp::new();
        sim.attach();
        let mut request = [0; 16];
        let len = frame::prop_set(&mut request, 1, prop::PHY_ENABLED, &[1]).unwrap();
        exchange(&mut sim, &request[..len]);

        sim.inject_demo_rx(200);
        let wire = sim.take_outbound().expect("demo receive is delivered");
        let mut decoder = hdlc::Decoder::<WIRE_CAPACITY>::new();
        let response = wire
            .into_iter()
            .find_map(|byte| decoder.push(byte).map(|frame| frame.unwrap().to_vec()))
            .unwrap();
        assert_eq!(
            Frame::parse(&response).unwrap().command(),
            Some(umsh_companion::Cmd::StrRecv)
        );
    }
}
