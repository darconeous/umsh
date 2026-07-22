//! Minimal companion-radio protocol responder (Phase 4, path A).
//!
//! Runs the real `umsh_companion_ncp::Session` behind the GATT frame
//! transport so the UMSH app's `attach_existing` completes instead of
//! choking on an echo. Provisioning is durable — `CMD_SAVE`, `CMD_CLEAR`,
//! and device-identity provisioning all commit to the journal tail of the
//! `umsh` partition before success is reported, and the saved snapshot +
//! identity are restored at boot. What is still deliberately missing is
//! the radio: `Effect::ApplyRadio` / `StartTransmit` / `SampleRssi` are
//! logged and dropped, so the app can attach, claim, and save, but no
//! frames go on the air. That — plus the device node — is Phase 5.
//!
//! The Session codec, framing, and command handling are the same
//! host-tested code the nRF NCPs run; only the effect execution is
//! scoped to this spike's capabilities.

use esp_println::println;

use umsh_companion::Status;
use umsh_companion::ids::DUTY_LIMIT_DISABLED;
use umsh_companion_ncp::{
    DutyLedger, Effect, IdentitySource, RadioSettings, SNAPSHOT_MAX, SessionConfig,
};
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_crypto::{CryptoEngine, NodeIdentity as _};
use umsh_journal_store::proto;

use crate::EspCryptoRng;
use crate::ble_store::{BootPayload, ProtoStore};

pub use umsh_companion::gatt::{MAX_FRAME, Reassembler, segments};

/// Host frames the session can retain between LoRa completions. The spike
/// has no radio, so the default depth is plenty.
const TX_QUEUE: usize = 4;
type Session = umsh_companion_ncp::Session<SoftwareAes, SoftwareSha256, TX_QUEUE>;

/// Combined airtime ledger the session prices its (never-sent) transmits
/// against. Required by `SessionConfig`; unused without a radio.
static DUTY_LEDGER: DutyLedger = DutyLedger::new();

const NCP_VERSION: &str = "umsh-heltec-v3-spike/0.1";
const DEVICE_NAME: &str = "UMSH Heltec V3";

/// How many response frames one inbound frame can fan out to (a queue
/// drain emits several; a single command emits one).
const OUT_FRAMES: usize = 8;

pub type OutFrame = heapless::Vec<u8, MAX_FRAME>;
pub type OutQueue = heapless::Vec<OutFrame, OUT_FRAMES>;

/// A `PROP_BLE_PAIRING_PIN` write surfaced to the caller, which owns the
/// bond journal and the live trouble stack. Apply it (persist + live
/// passkey), then complete the transaction with [`Companion::respond_pin`].
#[derive(Clone, Copy)]
pub struct PinRequest {
    pub tid: u8,
    pub pin: Option<u32>,
}

pub struct Companion {
    session: Session,
    proto: ProtoStore,
    identity: ProtoStore,
}

impl Companion {
    /// Build the session over its journals, restoring the persisted
    /// identity and saved snapshot before any host command.
    pub fn new(
        proto: ProtoStore,
        identity: ProtoStore,
        boot_snapshot: Option<BootPayload>,
        boot_identity: Option<[u8; 32]>,
    ) -> Self {
        let config = SessionConfig {
            ncp_version: NCP_VERSION,
            default_device_name: DEVICE_NAME,
            mtu: 255,
            // Private-network sync word 0x12 → SX126x 0x1424 (matches the
            // radio-bearing firmware even though we never key the radio).
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
            default_duty_limit: DUTY_LIMIT_DISABLED,
            duty: &DUTY_LEDGER,
            // No battery capability advertised, so the host never issues a
            // battery get (which we could not answer without the sampler).
            battery: None,
        };
        let mut session = Session::new(
            config,
            Status::RESET_POWER_ON,
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
        );
        if let Some(public_key) = boot_identity {
            session.set_boot_identity(public_key);
        }
        if let Some(payload) = boot_snapshot {
            let effect = session.restore_at_boot(&payload);
            println!(
                "companion: boot-restore={} effect={effect:?} (radio effects dropped)",
                if effect.is_some() { "ok" } else { "IGNORED" },
            );
        }
        Self {
            session,
            proto,
            identity,
        }
    }

    pub fn attach(&mut self) {
        self.session.attach(true);
    }

    pub fn detach(&mut self) {
        self.session.detach();
    }

    /// Feed one reassembled inbound frame to the session and collect every
    /// response frame it emits (directly and via deferred effects). A PIN
    /// write is not completed here — it is surfaced for the caller to
    /// apply against the bond journal and live stack first.
    pub async fn handle_frame(&mut self, frame: &[u8], now_ms: u64) -> (OutQueue, Option<PinRequest>) {
        let mut out = OutQueue::new();
        let effect = {
            let mut emit = |bytes: &[u8]| push_frame(&mut out, bytes);
            self.session.handle_frame(frame, now_ms, &mut emit)
        };
        let mut pin = None;
        if let Some(effect) = effect {
            pin = self.handle_effect(effect, now_ms, &mut out).await;
        }
        (out, pin)
    }

    /// Complete a previously surfaced [`PinRequest`] after the caller has
    /// applied (or failed to apply) it.
    pub fn respond_pin(&mut self, tid: u8, applied: bool) -> OutQueue {
        let mut out = OutQueue::new();
        let mut emit = |bytes: &[u8]| push_frame(&mut out, bytes);
        self.session
            .respond_pin_set(tid, applied.then_some(()).ok_or(()), &mut emit);
        out
    }

    async fn handle_effect(
        &mut self,
        effect: Effect,
        now_ms: u64,
        out: &mut OutQueue,
    ) -> Option<PinRequest> {
        match effect {
            Effect::ProvisionIdentity { tid } => {
                // Build the keypair, persist it durably, and only then
                // report the public key (spec §PROP_DEV_PRIVATE_KEY).
                let result = match self.session.identity_request() {
                    Some(source) => {
                        let secret = match source {
                            IdentitySource::Install(secret) => Ok(secret),
                            IdentitySource::Generate => new_secret(),
                        };
                        match secret {
                            Ok(secret) => {
                                let identity = SoftwareIdentity::from_secret_bytes(&secret);
                                let public_key = identity.public_key().0;
                                let payload = proto::encode_identity(&secret, &public_key);
                                self.identity.persist(&payload).await.map(|()| public_key)
                            }
                            Err(()) => Err(()),
                        }
                    }
                    None => Err(()),
                };
                println!(
                    "companion: provision identity tid={tid} persisted-ok={}",
                    result.is_ok(),
                );
                let mut emit = |bytes: &[u8]| push_frame(out, bytes);
                self.session.respond_identity(tid, result, &mut emit);
            }
            Effect::SaveSnapshot { tid } => {
                let mut buf = [0u8; SNAPSHOT_MAX];
                let result = match self.session.encode_snapshot(&mut buf) {
                    Some(len) => self.proto.persist(&buf[..len]).await,
                    None => Err(()),
                };
                println!("companion: save tid={tid} ok={}", result.is_ok());
                let mut emit = |bytes: &[u8]| push_frame(out, bytes);
                self.session.respond_save(tid, result, &mut emit);
            }
            Effect::ClearSaved { tid } => {
                // CMD_CLEAR covers all persisted provisioning: the snapshot
                // and the independently persisted device identity. Each
                // journal's tombstone is individually atomic; an
                // interruption between them reports failure and the host's
                // retry completes the erase.
                let result = match self.proto.clear().await {
                    Ok(()) => self.identity.clear().await,
                    Err(()) => Err(()),
                };
                println!("companion: clear tid={tid} ok={}", result.is_ok());
                let mut emit = |bytes: &[u8]| push_frame(out, bytes);
                self.session.respond_clear(tid, result, &mut emit);
            }
            Effect::SetPairingPin { tid, pin } => {
                // The caller owns the bond journal and the live stack;
                // surface the request and complete it via respond_pin.
                println!("companion: pin request tid={tid} present={}", pin.is_some());
                return Some(PinRequest { tid, pin });
            }
            Effect::WipeHostDomain { tid } => {
                // Durably wipe the host-domain portion of any saved
                // snapshot before the new host key takes effect — saved
                // device-domain state survives; with nothing saved the
                // wipe is trivially satisfied. (Same shape as the nRF NCP.)
                let mut buf = [0u8; SNAPSHOT_MAX];
                let result = match self.session.encode_wiped_snapshot(&mut buf) {
                    Some(len) => self.proto.persist(&buf[..len]).await,
                    None => Ok(()),
                };
                println!("companion: wipe host domain tid={tid} ok={}", result.is_ok());
                let mut emit = |bytes: &[u8]| push_frame(out, bytes);
                self.session.respond_host_wipe(tid, result, &mut emit);
            }
            Effect::DrainQueue => {
                let mut emit = |bytes: &[u8]| push_frame(out, bytes);
                while self.session.drain_step(now_ms, &mut emit) {}
            }
            other => {
                // ApplyRadio / StartTransmit / SampleRssi / SampleBattery /
                // DeviceNameChanged: no radio here (Phase 5).
                println!("companion: effect dropped (no radio): {other:?}");
            }
        }
        None
    }
}

/// Draw a fresh identity secret from the RF-gated TRNG. Uses the inherent
/// `fill_bytes` (not the rand-trait path) to avoid the rand_core version
/// split between `EspCryptoRng` and `umsh-crypto`.
fn new_secret() -> Result<[u8; 32], ()> {
    let mut rng = EspCryptoRng::new().map_err(|_| ())?;
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    Ok(secret)
}

fn push_frame(out: &mut OutQueue, bytes: &[u8]) {
    let mut frame = OutFrame::new();
    if frame.extend_from_slice(bytes).is_err() || out.push(frame).is_err() {
        println!("companion: WARN dropped emit frame len={}", bytes.len());
    }
}
