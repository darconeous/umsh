//! Simulated ULCP device: the production device [`Session`] behind a
//! deterministic in-memory link.
//!
//! The storage, radio, RSSI sampler, and entropy source are small
//! stand-ins; every protocol decision is made by the real session. What
//! stands where a radio would is a queue: transmissions accumulate until
//! [`SimulatedDevice::take_transmitted`] drains them, so the caller
//! decides what "the air" is — the web debugger discards it, a bridge
//! copies it to real segments.
//!
//! The [`SessionConfig`] is the caller's: it names the device and
//! declares its capability surface. A simulated device has no node
//! behind it, so its configuration must leave
//! [`SessionConfig::mac_node`] unset — `Effect::ApplyBackhaul` would
//! connect the host to nothing.

use std::collections::VecDeque;

use umsh_core::{NodeHint, PacketBuilder};
use umsh_crypto::{
    CryptoEngine, NodeIdentity,
    software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
};
use umsh_ulcp::battery::{BatteryChargeState, BatteryStatus};
use umsh_ulcp::gnss::{FixKind, GnssSnapshot};
use umsh_ulcp::{Status, hdlc};
use umsh_ulcp_device::{Effect, IdentitySource, SNAPSHOT_MAX, Session, TxOutcome};

pub use umsh_ulcp_device::{
    AlertConfig, BatteryFields, DutyLedger, GnssConfig, RadioRxInfo, RadioSettings, SessionConfig,
    TimeConfig,
};

const WIRE_CAPACITY: usize = umsh_ulcp::gatt::MAX_FRAME;

/// Bonds a fresh simulated device pretends to be holding.
const SIMULATED_BONDS: u8 = 2;

type DeviceSession = Session<SoftwareAes, SoftwareSha256>;

/// A deterministic, RAM-backed device that speaks HDLC-Lite exactly like USB.
pub struct SimulatedDevice {
    session: DeviceSession,
    config: SessionConfig,
    decoder: hdlc::Decoder<WIRE_CAPACITY>,
    outbound: VecDeque<Vec<u8>>,
    snapshot: Option<Vec<u8>>,
    identity: Option<([u8; 32], [u8; 32])>,
    identity_seed: u8,
    pairing_pin: Option<u32>,
    /// Bonds the simulated transport is holding. Nothing here pairs, so
    /// the count only ever falls — it starts non-zero so a host has
    /// something to clear, which is the state the command is for.
    bond_count: u8,
    air: Vec<Vec<u8>>,
    now_ms: u64,
    /// The caller's clock reading when this device last came up.
    /// `Clock::now_ms` is specified as milliseconds since boot, and a
    /// factory reset reboots the hardware, so the simulated clock has to
    /// restart with it — otherwise a freshly reset device would report the
    /// uptime of the process driving it.
    boot_ms: u64,
    /// The simulated wall clock, as a Unix second, or `None` for a device
    /// that has not been told and has never had a fix. Starts unset so the
    /// property's most interesting state is the one you see first.
    epoch: Option<u32>,
    /// Where the simulated receiver currently thinks it is. Advanced one
    /// step per sample so a host watching `PROP_GNSS_LOCATION` sees a
    /// track rather than a fixed point.
    fix_step: u32,
}

impl SimulatedDevice {
    pub fn new(config: SessionConfig) -> Self {
        let mut session = DeviceSession::new(
            config,
            Status::RESET_POWER_ON,
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
        );
        // Nothing is attached yet, so this only seeds the value a later
        // read answers with.
        session.set_ble_bond_count(SIMULATED_BONDS, &mut |_| {});
        Self {
            session,
            config,
            decoder: hdlc::Decoder::new(),
            outbound: VecDeque::new(),
            snapshot: None,
            identity: None,
            identity_seed: 0,
            pairing_pin: None,
            bond_count: SIMULATED_BONDS,
            air: Vec::new(),
            now_ms: 0,
            boot_ms: 0,
            epoch: None,
            fix_step: 0,
        }
    }

    /// The caller's clock, rebased onto this device's boot.
    fn device_ms(&self) -> u64 {
        self.now_ms.saturating_sub(self.boot_ms)
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

    /// Everything the device has transmitted since the last drain, in
    /// order. The queue grows until drained; a caller with no air to put
    /// frames on drains and discards.
    pub fn take_transmitted(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.air)
    }

    /// Put a canned radio frame through the real device receive path.
    pub fn inject_radio_rx(&mut self, bytes: &[u8], now_ms: u64) {
        self.inject_radio_rx_with_info(bytes, &RadioRxInfo::measured(-82, 35, None), now_ms);
    }

    /// Put a radio frame through the real device receive path with the
    /// caller's own reception facts — all-`None` for a frame that
    /// crossed no air and was measured by nobody.
    pub fn inject_radio_rx_with_info(&mut self, bytes: &[u8], info: &RadioRxInfo, now_ms: u64) {
        self.now_ms = now_ms;
        let device_ms = self.device_ms();
        let mut emitted = Vec::new();
        let effect = self
            .session
            .on_radio_rx(bytes, info, device_ms, &mut |frame| {
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

    fn handle_frame(&mut self, frame: &[u8]) {
        let device_ms = self.device_ms();
        let mut emitted = Vec::new();
        let effect = self
            .session
            .handle_frame(frame, device_ms, &mut |bytes| emitted.push(bytes.to_vec()));
        self.execute(effect, &mut emitted);
        self.queue_emitted(emitted);
    }

    fn execute(&mut self, effect: Option<Effect>, emitted: &mut Vec<Vec<u8>>) {
        let mut emit = |frame: &[u8]| emitted.push(frame.to_vec());
        match effect {
            // The simulated board has no buzzer or LED to drive, so the
            // alert is purely the property value the session already holds.
            None
            | Some(Effect::ApplyRadio(_))
            | Some(Effect::DeviceNameChanged)
            // The simulated board has no node of its own, so there is
            // nothing for a backhaul to connect the host to.
            | Some(Effect::ApplyBackhaul { .. })
            | Some(Effect::ApplyAlert(_)) => {}
            Some(Effect::StartTransmit) => {
                let device_ms = self.device_ms();
                self.air.push(self.session.tx_data().to_vec());
                self.session
                    .on_tx_result(TxOutcome::Sent, device_ms, &mut emit);
            }
            Some(Effect::SampleRssi { tid }) => {
                self.session.respond_rssi(tid, Ok(-77), &mut emit);
            }
            Some(Effect::SampleBattery { tid }) => {
                // Stable, human-recognizable simulated measurement; the
                // configured field set decides what of it is reported.
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
            Some(Effect::SampleIlluminance { tid }) => {
                // A stable simulated reading: ordinary office lighting.
                self.session
                    .respond_illuminance(tid, Some(320_000), &mut emit);
            }
            // The simulated device has no device node and no signing key,
            // so PROP_IDENT reads report failure rather than a blob.
            Some(Effect::SignIdentity { tid }) => {
                self.session.respond_identity_blob(tid, Err(()), &mut emit);
            }
            Some(Effect::SetPairingPin { tid, pin }) => {
                self.pairing_pin = pin;
                self.session.respond_pin_set(tid, Ok(()), &mut emit);
            }
            Some(Effect::BleClearBonds { tid }) => {
                // The full security reset a board performs: bonds, PIN,
                // and lockout together, and the pairing window a
                // freshly-cleared device opens.
                self.bond_count = 0;
                self.pairing_pin = None;
                self.session.set_ble_bond_count(0, &mut emit);
                self.session.set_ble_pairing(true, &mut emit);
                self.session.respond_ble_clear_bonds(tid, Ok(()), &mut emit);
            }
            Some(Effect::SetBlePairing { tid, open }) => {
                // Nothing here can pair, so the window opens and nothing
                // walks through it. A full store is not a refusal —
                // enrollment at capacity evicts — and the one state that
                // would refuse an open, a pairing lockout, needs failed
                // pairings this device cannot have.
                self.session.respond_ble_pairing(tid, Ok(open), &mut emit);
            }
            Some(Effect::DrainQueue) => {
                let device_ms = self.device_ms();
                while self.session.drain_step(device_ms, &mut emit) {}
            }
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
                self.bond_count = 0;
                // The reboot restarts the monotonic clock along with
                // everything else, so uptime counts from here.
                self.boot_ms = self.now_ms;
                self.session = DeviceSession::new(
                    self.config,
                    Status::RESET_POWER_ON,
                    CryptoEngine::new(SoftwareAes, SoftwareSha256),
                );
            }
            Some(Effect::Reboot) => {
                // A power cycle and nothing else: the persisted
                // artifacts survive, the session comes back announcing
                // its power-on reset, and uptime counts from here. No
                // reply, as on hardware.
                self.boot_ms = self.now_ms;
                self.session = DeviceSession::new(
                    self.config,
                    Status::RESET_POWER_ON,
                    CryptoEngine::new(SoftwareAes, SoftwareSha256),
                );
                // A board configures itself from the saved snapshot on
                // the way up, so replay it here. The identity and the
                // pairing PIN are this simulator's own fields and are
                // answered from them, so only the snapshot has to go
                // back into the session.
                if let Some(saved) = self.snapshot.clone() {
                    let _ = self.session.restore_at_boot(&saved);
                }
                // Bonds outlive a reboot, and the fresh session starts
                // from zero, so the transport reports itself again exactly
                // as a board's does on the way up.
                self.session
                    .set_ble_bond_count(self.bond_count, &mut |_| {});
            }
            Some(Effect::ReadTime { tid }) => {
                self.session.respond_time(tid, self.epoch, &mut emit);
            }
            Some(Effect::ApplyTime { epoch }) => {
                self.epoch = epoch;
            }
            Some(Effect::SampleGnss { tid, key }) => {
                let sample = self.gnss_sample();
                self.session.respond_gnss(tid, key, Ok(sample), &mut emit);
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

    /// The simulated receiver's view, walked one cell east per sample.
    ///
    /// A receiver that has been switched off reports
    /// [`GnssSnapshot::SEARCHING`] — zero for the facts it is sure of,
    /// empty for the position it does not have — which is the state most
    /// worth being able to see in a debugger.
    fn gnss_sample(&mut self) -> GnssSnapshot {
        if !self.session.gnss_enabled() {
            return GnssSnapshot::SEARCHING;
        }
        self.fix_step = self.fix_step.wrapping_add(1);
        let mut snapshot = GnssSnapshot::SEARCHING;
        snapshot.fix = FixKind::ThreeD;
        snapshot.altitude_m = Some(64);
        snapshot.accuracy_dm = Some(GnssSnapshot::accuracy_from_hdop_centi(120));
        snapshot.sats_used = 9;
        snapshot.sats_in_view = Some(14);
        let step = (self.fix_step % 16) as u8;
        snapshot.set_location(&[0x8a, 0x1f, 0x4c, 0x00, 0xd0 | step]);
        snapshot
    }

    fn queue_emitted(&mut self, emitted: Vec<Vec<u8>>) {
        for frame in emitted {
            let mut encoded = vec![0; hdlc::max_encoded_len(frame.len())];
            let len = hdlc::encode_frame(&frame, &mut encoded)
                .expect("simulated device output buffer uses HDLC worst-case size");
            encoded.truncate(len);
            self.outbound.push_back(encoded);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_ulcp::{Frame, PropPayload, frame, ids::prop};

    fn test_config() -> SessionConfig {
        SessionConfig {
            dev_version: "umsh-simdev-test/0.1",
            dev_model: None,
            default_device_name: "Simulated test device",
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
            battery: Some(BatteryFields {
                voltage: true,
                level: true,
                charge_state: true,
            }),
            alert: Some(AlertConfig::DEFAULT),
            time: Some(TimeConfig),
            gnss: Some(GnssConfig::DEFAULT),
            illuminance: true,
            ble: true,
            ble_pairing: true,
            // A simulated power cycle is a rebuilt session, which is
            // exactly what a host watching this device would see.
            reboot: true,
            mac_node: false,
        }
    }

    fn exchange(sim: &mut SimulatedDevice, request: &[u8]) -> Vec<Vec<u8>> {
        exchange_at(sim, request, 100)
    }

    fn exchange_at(sim: &mut SimulatedDevice, request: &[u8], now_ms: u64) -> Vec<Vec<u8>> {
        let mut wire = vec![0; hdlc::max_encoded_len(request.len())];
        let len = hdlc::encode_frame(request, &mut wire).unwrap();
        sim.ingest(&wire[..len], now_ms).unwrap();

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
        let mut sim = SimulatedDevice::new(test_config());
        sim.attach();
        let mut request = [0; 16];
        let len = frame::prop_get(&mut request, 1, prop::DEV_VERSION).unwrap();
        let responses = exchange(&mut sim, &request[..len]);
        assert_eq!(responses.len(), 1);
        let response = Frame::parse(&responses[0]).unwrap();
        let payload = PropPayload::parse(response.payload).unwrap();
        assert_eq!(payload.key, prop::DEV_VERSION);
        assert_eq!(payload.value, b"umsh-simdev-test/0.1\0");
    }

    /// The simulated reboot has to restart the simulated clock, or a
    /// factory-reset device would report the uptime of whatever process
    /// happens to be driving it.
    #[test]
    fn a_factory_reset_restarts_the_uptime_clock() {
        let mut sim = SimulatedDevice::new(test_config());
        sim.attach();

        let read_uptime = |sim: &mut SimulatedDevice, now_ms: u64| -> u32 {
            let mut request = [0; 16];
            let len = frame::prop_get(&mut request, 1, prop::UPTIME).unwrap();
            let responses = exchange_at(sim, &request[..len], now_ms);
            let response = Frame::parse(&responses[0]).unwrap();
            let payload = PropPayload::parse(response.payload).unwrap();
            assert_eq!(payload.key, prop::UPTIME);
            u32::from_le_bytes(payload.value.try_into().expect("UINT32"))
        };

        assert_eq!(read_uptime(&mut sim, 5_000), 5);

        let mut request = [0; 16];
        let len = frame::factory_reset(&mut request, 2).unwrap();
        exchange_at(&mut sim, &request[..len], 5_000);

        // The caller's clock keeps running; the device's does not.
        assert_eq!(read_uptime(&mut sim, 7_000), 2);
    }

    #[test]
    fn real_session_executes_radio_transmit_effect() {
        let mut sim = SimulatedDevice::new(test_config());
        sim.attach();
        let mut request = [0; 64];
        let len = frame::prop_set(&mut request, 1, prop::PHY_ENABLED, &[1]).unwrap();
        exchange(&mut sim, &request[..len]);
        let len = frame::str_send(
            &mut request,
            2,
            umsh_ulcp::ids::stream::PHY_RAW,
            b"demo",
            &[],
        )
        .unwrap();
        exchange(&mut sim, &request[..len]);
        assert_eq!(sim.take_transmitted(), &[b"demo".to_vec()]);
        assert!(
            sim.take_transmitted().is_empty(),
            "the drain leaves nothing behind"
        );
    }

    #[test]
    fn demo_packet_uses_the_real_receive_path() {
        let mut sim = SimulatedDevice::new(test_config());
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
            Some(umsh_ulcp::Cmd::StrRecv)
        );
    }

    /// The whole point of the honest capability surface: nothing this
    /// device advertises invites a bridge to backhaul through it.
    #[test]
    fn a_simulated_device_claims_no_node() {
        let mut sim = SimulatedDevice::new(test_config());
        sim.attach();
        let mut request = [0; 16];
        let len = frame::prop_get(&mut request, 1, umsh_ulcp::ids::prop::CAPS).unwrap();
        let responses = exchange(&mut sim, &request[..len]);
        let response = Frame::parse(&responses[0]).unwrap();
        let payload = PropPayload::parse(response.payload).unwrap();
        let mut caps = Vec::new();
        let mut offset = 0;
        while offset < payload.value.len() {
            let (value, used) = umsh_ulcp::pui::decode(&payload.value[offset..]).unwrap();
            caps.push(value);
            offset += used;
        }
        assert!(!caps.contains(&umsh_ulcp::ids::cap::MAC_BACKHAUL));
        assert!(!caps.contains(&umsh_ulcp::ids::cap::REPEATER));
        assert!(caps.contains(&umsh_ulcp::ids::cap::WRITABLE_RAW_STREAM));
    }
}
