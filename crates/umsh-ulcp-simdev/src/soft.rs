//! The soft device core: the production device [`Session`] behind an
//! HDLC-Lite byte stream, with what a board would supply—storage,
//! entropy, a clock, peripherals—supplied by a [`SoftPlatform`].
//!
//! The core serves every effect that is the same on any host: putting a
//! frame on the medium, saving and restoring configuration, provisioning
//! and keeping the device identity, rebooting, and factory reset. What is
//! a property of the host—where state persists, where randomness comes
//! from, what the clock says, and any peripheral the configuration
//! advertises—comes from the platform.
//!
//! The medium is the caller's. Transmissions accumulate until
//! [`SoftDevice::take_transmitted`] drains them, and receptions go in
//! through [`SoftDevice::inject_radio_rx`]. A deterministic simulation
//! discards or replays them; a LAN virtual radio sends them to its group.
//!
//! A device with a settings interface of its own—a simulated
//! communicator—opens it with [`SoftDevice::open_device_interface`] and
//! serves it through [`SoftDevice::device_request`], as the firmware
//! driver serves its in-process requests. Its answers and everything the
//! device publishes wait in [`SoftDevice::take_device_frame`].

use std::collections::VecDeque;

use umsh_crypto::{
    CryptoEngine, NodeIdentity,
    software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
};
use umsh_ulcp::{Frame, Status, hdlc};
use umsh_ulcp_device::listeners::{Mirrors, Writes};
use umsh_ulcp_device::{
    AnnounceRequest, Effect, HELD_LISTS_MAX, IdentitySource, RadioRxInfo, SNAPSHOT_MAX,
    SavedStatus, Session, SessionConfig, TxOutcome,
};

pub(crate) const WIRE_CAPACITY: usize = umsh_ulcp::gatt::MAX_FRAME;

/// The device session a soft device runs.
pub type DeviceSession = Session<SoftwareAes, SoftwareSha256>;

/// What a host supplies to a [`SoftDevice`].
pub trait SoftPlatform {
    /// The configuration snapshot saved by `CMD_SAVE`, if any.
    fn load_snapshot(&mut self) -> Option<Vec<u8>>;
    /// Persist a snapshot, or erase it with `None`.
    fn store_snapshot(&mut self, snapshot: Option<&[u8]>) -> Result<(), ()>;
    /// The device identity's secret key, if one is stored.
    fn load_identity(&mut self) -> Option<[u8; 32]>;
    /// Persist the device identity's secret key, or erase it with `None`.
    fn store_identity(&mut self, secret: Option<&[u8; 32]>) -> Result<(), ()>;
    /// A fresh identity secret.
    fn generate_secret(&mut self) -> [u8; 32];
    /// A fresh identity secret from [`generate_secret`](Self::generate_secret),
    /// redrawn while the hint filter matches its key.
    fn generate_identity_secret(&mut self) -> [u8; 32] {
        umsh_crypto::software::generate_identity_secret(|secret| {
            *secret = self.generate_secret();
            Ok::<_, core::convert::Infallible>(())
        })
        .unwrap_or_else(|never| match never {})
    }
    /// Whether a device with no stored identity makes one as it comes up,
    /// as firmware does, rather than waiting for a host to ask.
    fn generates_identity_at_boot(&self) -> bool {
        false
    }

    /// The wall clock, as a Unix second, or `None` if unknown.
    fn wall_clock(&mut self) -> Option<u32>;
    /// A host set the wall clock.
    fn set_wall_clock(&mut self, epoch: Option<u32>) {
        let _ = epoch;
    }

    /// The channel keys the device lists hold after a reset with none
    /// kept, on a device whose own store keeps them outside the snapshot,
    /// as a communicator's does (see [`Session::hold_lists`]). `None`, the
    /// default, leaves them in the snapshot.
    fn held_lists(&self) -> Option<&'static [[u8; 32]]> {
        None
    }
    /// The record of the device lists the platform keeps, if any.
    fn load_lists(&mut self) -> Option<Vec<u8>> {
        None
    }
    /// Keep the record of the device lists, or erase it with `None`.
    fn store_lists(&mut self, record: Option<&[u8]>) -> Result<(), ()> {
        let _ = record;
        Err(())
    }

    /// The session was just constructed, before any saved state is
    /// restored into it: report what the platform's hardware is.
    fn on_boot(&mut self, session: &mut DeviceSession) {
        let _ = session;
    }
    /// Erase whatever else the platform keeps, for a factory reset.
    fn erase(&mut self) {}
    /// Serve an effect the core does not. A platform must serve every
    /// effect its [`SessionConfig`] can produce.
    fn peripheral(
        &mut self,
        effect: Effect,
        session: &mut DeviceSession,
        emit: &mut dyn FnMut(&[u8]),
    ) {
        let _ = (effect, session, emit);
    }
    /// A host frame was served: bring the platform's view up to date with
    /// what the session now holds, as a board's drivers react to the
    /// device-domain mirror. `now_ms` is the device's clock.
    fn settle(&mut self, session: &mut DeviceSession, now_ms: u64, emit: &mut dyn FnMut(&[u8])) {
        let _ = (session, now_ms, emit);
    }
}

/// The device session behind an HDLC-Lite link, on a [`SoftPlatform`].
pub struct SoftDevice<P: SoftPlatform> {
    session: DeviceSession,
    config: SessionConfig,
    platform: P,
    decoder: hdlc::Decoder<WIRE_CAPACITY>,
    outbound: VecDeque<Vec<u8>>,
    /// Whether the device has a settings interface of its own. Survives a
    /// reboot: it describes the device, not the session.
    device_interface: bool,
    /// Raw frames for that interface, oldest first: its answers, and every
    /// publication.
    device_out: VecDeque<Vec<u8>>,
    air: Vec<Vec<u8>>,
    /// Every `CMD_ANNOUNCE` taken, oldest first. A soft device has no
    /// node to put one on the air, so the record is the whole of what can
    /// be observed.
    announcements: Vec<AnnounceRequest>,
    now_ms: u64,
    /// The caller's clock reading when this device last came up.
    /// `Clock::now_ms` is milliseconds since boot, and a reboot restarts
    /// it, so a device's uptime is measured from here.
    boot_ms: u64,
}

impl<P: SoftPlatform> SoftDevice<P> {
    /// Bring the device up as from power-on, restoring whatever the
    /// platform persisted.
    pub fn new(config: SessionConfig, platform: P) -> Self {
        let mut device = Self {
            session: DeviceSession::new(
                config,
                Status::RESET_POWER_ON,
                CryptoEngine::new(SoftwareAes, SoftwareSha256),
            ),
            config,
            platform,
            decoder: hdlc::Decoder::new(),
            outbound: VecDeque::new(),
            device_interface: false,
            device_out: VecDeque::new(),
            air: Vec::new(),
            announcements: Vec::new(),
            now_ms: 0,
            boot_ms: 0,
        };
        device.boot();
        device
    }

    /// Construct a fresh session and restore the platform's state into
    /// it, as a board does on the way up.
    fn boot(&mut self) {
        self.session = DeviceSession::new(
            self.config,
            Status::RESET_POWER_ON,
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
        );
        self.platform.on_boot(&mut self.session);
        if let Some(defaults) = self.platform.held_lists() {
            let stored = self.platform.load_lists();
            self.session.hold_lists(defaults, stored.as_deref());
        }
        if self.device_interface {
            self.session.open_device_interface();
        }
        // The identity before the snapshot: a restore keeps the PHY off
        // unless the snapshot was taken under the live identity. A device
        // configured without one neither keeps nor makes one.
        let secret = if !self.config.dev_identity {
            None
        } else {
            match self.platform.load_identity() {
                Some(secret) => Some(secret),
                None if self.platform.generates_identity_at_boot() => {
                    let secret = self.platform.generate_identity_secret();
                    self.platform
                        .store_identity(Some(&secret))
                        .ok()
                        .map(|_| secret)
                }
                None => None,
            }
        };
        if let Some(secret) = secret {
            let public = SoftwareIdentity::from_secret_bytes(&secret).public_key().0;
            self.session.set_boot_identity(public);
        }
        if let Some(saved) = self.platform.load_snapshot() {
            let _ = self.session.restore_at_boot(&saved);
        }
    }

    pub fn session(&self) -> &DeviceSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut DeviceSession {
        &mut self.session
    }

    pub fn platform(&self) -> &P {
        &self.platform
    }

    pub fn platform_mut(&mut self) -> &mut P {
        &mut self.platform
    }

    /// The caller's clock, rebased onto this device's boot.
    pub fn device_ms(&self) -> u64 {
        self.now_ms.saturating_sub(self.boot_ms)
    }

    /// Attach a host over a link as secure as USB: one only this host's
    /// own processes can reach.
    pub fn attach(&mut self) {
        self.decoder.reset();
        self.outbound.clear();
        self.session.attach(true);
        self.flush_session_reset_notice();
    }

    pub fn detach(&mut self) {
        self.decoder.reset();
        self.outbound.clear();
        self.session.detach();
    }

    /// Pay whatever session-reset notice the session is owing, the way
    /// the firmware driver does at the tail of its loop.
    fn flush_session_reset_notice(&mut self) {
        let mut emitted = Vec::new();
        if self
            .session
            .take_session_reset_notice(&mut |frame: &[u8]| emitted.push(frame.to_vec()))
        {
            self.queue_emitted(emitted);
        }
    }

    /// Feed bytes from the host's side of the link.
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

    /// The next HDLC-encoded frame for the host, if any.
    pub fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    /// Give the device a settings interface of its own. From here on the
    /// device publishes whether or not a host is attached, and every
    /// publication reaches [`SoftDevice::take_device_frame`].
    pub fn open_device_interface(&mut self) {
        self.device_interface = true;
        self.session.open_device_interface();
    }

    /// Serve one raw ULCP frame from the device's own interface. Its answer
    /// waits in [`SoftDevice::take_device_frame`]; whatever the device
    /// publishes while serving it, and whatever it changes, reaches an
    /// attached host too. A change to a saved setting keeps an existing
    /// snapshot in step.
    pub fn device_request(&mut self, frame: &[u8], now_ms: u64) {
        debug_assert!(self.device_interface, "the device has no interface");
        self.now_ms = now_ms;
        let writes = Writes::with(frame, |key| self.session.snapshots(key));
        let device_ms = self.device_ms();
        let mut emitted = Vec::new();
        let effect = self
            .session
            .handle_device_frame(frame, device_ms, &mut |bytes| emitted.push(bytes.to_vec()));
        self.execute(effect, &mut emitted);
        self.session.end_admin_exchange();
        let mut published = Vec::new();
        let now_ms = self.device_ms();
        self.platform
            .settle(&mut self.session, now_ms, &mut |frame: &[u8]| {
                published.push(frame.to_vec())
            });
        for frame in emitted {
            if is_publication(&frame) {
                self.publish(frame);
            } else {
                if writes.any && self.session.is_attached() {
                    let mut mirrors = Mirrors::new(&frame);
                    while let Some(mirror) = mirrors.next() {
                        self.to_host(mirror);
                    }
                }
                self.device_out.push_back(frame);
            }
        }
        self.queue_emitted(published);
        self.flush_session_reset_notice();
        if writes.saved {
            self.keep_snapshot_in_step();
        }
        self.keep_lists();
    }

    /// The next raw frame for the device's own interface, if any.
    pub fn take_device_frame(&mut self) -> Option<Vec<u8>> {
        self.device_out.pop_front()
    }

    /// Flip `PROP_BLE_ENABLED` as the device's own control would, the way
    /// the firmware driver serves a toggle.
    pub fn toggle_ble(&mut self) {
        let mut emitted = Vec::new();
        self.session
            .toggle_ble(&mut |frame| emitted.push(frame.to_vec()));
        self.queue_emitted(emitted);
        self.keep_snapshot_in_step();
    }

    /// Hand the platform the device lists when one changed, as the
    /// firmware driver does after every event.
    fn keep_lists(&mut self) {
        let mut buf = [0u8; HELD_LISTS_MAX];
        if let Some(len) = self.session.lists_to_keep(&mut buf)
            && self.platform.store_lists(Some(&buf[..len])).is_ok()
        {
            self.session.note_lists_kept();
        }
    }

    /// Keep an existing snapshot in step with a change made at the device,
    /// as the firmware driver does: never make one, and never write over a
    /// generation boot rejected.
    fn keep_snapshot_in_step(&mut self) {
        if self.session.saved_status() != SavedStatus::Current {
            return;
        }
        let mut buf = [0u8; SNAPSHOT_MAX];
        if let Some(len) = self.session.encode_snapshot(&mut buf)
            && self.platform.store_snapshot(Some(&buf[..len])).is_ok()
        {
            self.session.note_snapshot_saved();
        }
    }

    /// Everything the device has transmitted since the last drain, in
    /// order.
    pub fn take_transmitted(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.air)
    }

    /// Every `CMD_ANNOUNCE` taken since the last drain, in order.
    pub fn take_announcements(&mut self) -> Vec<AnnounceRequest> {
        std::mem::take(&mut self.announcements)
    }

    /// Put a reception through the real device receive path.
    pub fn inject_radio_rx(&mut self, bytes: &[u8], info: &RadioRxInfo, now_ms: u64) {
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

    /// Report what became of the LAN bearer's configuration, announcing a
    /// change to an attached host.
    pub fn set_lan_bearer_state(&mut self, state: umsh_ulcp::lan::State) {
        let mut emitted = Vec::new();
        self.session
            .set_lan_bearer_state(state, &mut |frame| emitted.push(frame.to_vec()));
        self.queue_emitted(emitted);
    }

    /// Advance the device's clock: the inbound queue ages, deadlines pass.
    pub fn tick(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    fn handle_frame(&mut self, frame: &[u8]) {
        let device_ms = self.device_ms();
        let mut emitted = Vec::new();
        let effect = self
            .session
            .handle_frame(frame, device_ms, &mut |bytes| emitted.push(bytes.to_vec()));
        self.execute(effect, &mut emitted);
        // What the host changed, the device's own interface hears.
        if self.device_interface && Writes::of(frame).any {
            for answer in emitted.iter().filter(|frame| !is_publication(frame)) {
                let mut mirrors = Mirrors::new(answer);
                while let Some(mirror) = mirrors.next() {
                    self.device_out.push_back(mirror.to_vec());
                }
            }
        }
        let now_ms = self.device_ms();
        self.platform
            .settle(&mut self.session, now_ms, &mut |frame: &[u8]| {
                emitted.push(frame.to_vec())
            });
        self.queue_emitted(emitted);
        self.flush_session_reset_notice();
        self.keep_lists();
    }

    fn execute(&mut self, mut effect: Option<Effect>, emitted: &mut Vec<Vec<u8>>) {
        while let Some(current) = effect {
            self.execute_one(current, emitted);
            effect = self
                .session
                .resume_multi(self.device_ms(), &mut |frame| emitted.push(frame.to_vec()));
        }
    }

    fn execute_one(&mut self, effect: Effect, emitted: &mut Vec<Vec<u8>>) {
        let mut emit = |frame: &[u8]| emitted.push(frame.to_vec());
        match effect {
            // No hardware to apply them to: the session's own values are
            // the whole of the state.
            Effect::ApplyRadio(_) | Effect::DeviceNameChanged | Effect::ApplyAlert(_) => {}
            Effect::StartTransmit => {
                let device_ms = self.device_ms();
                self.air.push(self.session.tx_data().to_vec());
                self.session
                    .on_tx_result(TxOutcome::Sent, device_ms, &mut emit);
            }
            Effect::DrainQueue => {
                let device_ms = self.device_ms();
                while self.session.drain_step(device_ms, &mut emit) {}
            }
            Effect::SaveSnapshot { tid } => {
                let mut buf = [0u8; SNAPSHOT_MAX];
                let result = match self.session.encode_snapshot(&mut buf) {
                    Some(len) => self.platform.store_snapshot(Some(&buf[..len])),
                    None => Err(()),
                };
                self.session.respond_save(tid, result, &mut emit);
            }
            Effect::ClearSaved { tid } => {
                let mut result = self
                    .platform
                    .store_snapshot(None)
                    .and(self.platform.store_identity(None));
                if result.is_ok() && self.session.holds_lists() {
                    result = self.platform.store_lists(None);
                }
                self.session.respond_clear(tid, result, &mut emit);
            }
            Effect::FactoryReset => {
                // The platform wipe-and-reboot. No reply: on hardware the
                // reboot drops the link.
                let _ = self.platform.store_snapshot(None);
                let _ = self.platform.store_identity(None);
                if self.session.holds_lists() {
                    let _ = self.platform.store_lists(None);
                }
                self.platform.erase();
                self.boot_ms = self.now_ms;
                self.boot();
            }
            Effect::Reboot => {
                // A power cycle and nothing else: the persisted state
                // survives and is restored on the way up. No reply, as on
                // hardware.
                self.boot_ms = self.now_ms;
                self.boot();
            }
            Effect::Dfu { tid, .. } => {
                self.session
                    .respond_dfu(tid, Err(Status::UNIMPLEMENTED), &mut emit);
            }
            Effect::Announce { tid, request } => {
                self.announcements.push(request);
                self.session.respond_announce(tid, Ok(()), &mut emit);
            }
            // Signed with the device identity, as a board signs it; a
            // device without one has nothing to sign with.
            // It advertises no position or regions, so both forms are the
            // same statement.
            Effect::SignIdentity { tid, form } => {
                let blob = self
                    .platform
                    .load_identity()
                    .map(|secret| identity_blob(&self.session, &secret));
                self.session
                    .respond_identity_blob(tid, form, blob.as_deref().ok_or(()), &mut emit);
            }
            Effect::ReadTime { tid } => {
                let epoch = self.platform.wall_clock();
                self.session.respond_time(tid, epoch, &mut emit);
            }
            Effect::ApplyTime { epoch } => self.platform.set_wall_clock(epoch),
            Effect::ProvisionIdentity { tid } => {
                let result = match self.session.identity_request() {
                    Some(source) => {
                        let secret = match source {
                            IdentitySource::Install(secret) => secret,
                            IdentitySource::Generate => self.platform.generate_identity_secret(),
                        };
                        self.platform
                            .store_identity(Some(&secret))
                            .map(|()| SoftwareIdentity::from_secret_bytes(&secret).public_key().0)
                    }
                    None => Err(()),
                };
                self.session.respond_identity(tid, result, &mut emit);
            }
            other => self
                .platform
                .peripheral(other, &mut self.session, &mut emit),
        }
    }

    /// Deliver what the session emitted outside an exchange with the
    /// device's own interface: everything goes to the host, as it always
    /// has, and a publication reaches the interface too.
    fn queue_emitted(&mut self, emitted: Vec<Vec<u8>>) {
        for frame in emitted {
            if is_publication(&frame) {
                self.publish(frame);
            } else {
                self.to_host(&frame);
            }
        }
    }

    /// Everyone listening hears a publication. With the interface open,
    /// the session publishes whether or not a host is attached, so the
    /// host is sent one only while it is there to receive it.
    fn publish(&mut self, frame: Vec<u8>) {
        if self.session.is_attached() || !self.device_interface {
            self.to_host(&frame);
        }
        if self.device_interface {
            self.device_out.push_back(frame);
        }
    }

    fn to_host(&mut self, frame: &[u8]) {
        let mut encoded = vec![0; hdlc::max_encoded_len(frame.len())];
        let len = hdlc::encode_frame(frame, &mut encoded)
            .expect("soft device output buffer uses HDLC worst-case size");
        encoded.truncate(len);
        self.outbound.push_back(encoded);
    }
}

/// Whether `frame` is one everyone listening to the device receives,
/// rather than an answer for whoever asked.
fn is_publication(frame: &[u8]) -> bool {
    Frame::parse(frame).is_ok_and(|parsed| parsed.is_publication())
}

/// The device identity's node identity, as a board's node advertises it:
/// its role, what it does, and its name, signed by `secret`'s key
/// (node-identity.md). The soft device has no node to ask, so it says what
/// a chatting node says.
fn identity_blob(session: &DeviceSession, secret: &[u8; 32]) -> Vec<u8> {
    /// `ROLE` Chat, and the `TEXT_MESSAGES` and `MOBILE` capability bits.
    const CHAT: u8 = 2;
    const TEXT_MESSAGES: u8 = 0x04;
    const MOBILE: u8 = 0x02;
    let mut capabilities = TEXT_MESSAGES;
    if session.ident_mobile() {
        capabilities |= MOBILE;
    }
    let mut blob = vec![session.ident_role().unwrap_or(CHAT), capabilities];
    let name = session.device_name();
    if !name.is_empty() {
        let mut options = [0u8; 64];
        let mut encoder = umsh_core::options::OptionEncoder::new(&mut options);
        if encoder.put(0, name.as_bytes()).is_ok() {
            let len = encoder.finish();
            blob.extend_from_slice(&options[..len]);
        }
    }
    blob.push(0xFF);
    let signature = ready(SoftwareIdentity::from_secret_bytes(secret).sign(&blob))
        .expect("software signing does not fail");
    blob.extend_from_slice(&signature);
    blob
}

/// The output of a future that never waits, as software crypto's do.
fn ready<F: core::future::Future>(future: F) -> F::Output {
    let mut context = core::task::Context::from_waker(core::task::Waker::noop());
    match core::pin::pin!(future).poll(&mut context) {
        core::task::Poll::Ready(value) => value,
        core::task::Poll::Pending => panic!("software crypto never waits"),
    }
}
