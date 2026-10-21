//! The MeshCore forwarder: a third radio client beside the session and
//! the device node, forwarding MeshCore v1 traffic the way a MeshCore
//! repeater does.
//!
//! The forwarding decisions are [`umsh_meshcore_forwarder`]'s. This
//! module is what makes it a device: its virtual mux bundle
//! ([`MESHCORE_CH`]), the shared duty ledger and the CAD gate on its
//! transmits, the busy backoff it shares with the UMSH MAC, and the
//! device-domain settings that say whether it runs at all.
//!
//! It runs only while all of these hold:
//!
//! - the radio is enabled (`PROP_PHY_ENABLED`);
//! - MeshCore forwarding is enabled (`PROP_MESHCORE_FORWARDING_ENABLED`),
//!   on its own: the device node's repeater has its own switch;
//! - the identity it was brought up under has a public key MeshCore lets
//!   a repeater run under.
//!
//! When any of them stops holding, everything the forwarder had seen
//! and queued is forgotten. Its receive queue is drained regardless:
//! the mux hands every client a copy of each frame, and in backhaul mode
//! a full queue here would refuse the host's own transmissions.
//!
//! The only identity input is the public key, which supplies this
//! node's path entries. The forwarder signs nothing and originates
//! nothing.

use core::cell::RefCell;

use core::future::poll_fn;
use core::task::Poll;

use embassy_futures::join::join3;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embassy_sync::watch::Watch;
use embassy_time::{Instant, Timer};
use rand_core::RngCore;
use umsh_hal::{CadPolicy, EmbassyClock, Radio, RxOrigin, TxError, TxOptions};
use umsh_mac::MAX_CAD_ATTEMPTS;
use umsh_meshcore_forwarder::packet::{Frame, RouteType};
use umsh_meshcore_forwarder::{Environment, Forwarder, Heard, RegionPolicy, Settings, Verdict};
use umsh_radio_loraphy::{Channels, LoraphyRadio};
use umsh_ulcp::items::MESHCORE_REGION_NAME_MAX_LEN;
use umsh_ulcp::stats::{Counter, StatsLedger};
use umsh_ulcp_device::{DutyLedger, MAX_MESHCORE_REGIONS};

use crate::device_node::NodeMutex;
use crate::driver::DevDomainSnapshot;
use crate::duty_gate::DutyGatedRadio;
use crate::log::debug_log;
use crate::reseed::{ReseedSlot, ReseedingRng};

/// Forwards that may wait out their retransmit delay at once. Each holds
/// a full radio frame.
const QUEUE: usize = 8;

/// The forwarder's bulk state: its duplicate memory, its delay queue,
/// the frame being transmitted, and its generator. A few kilobytes of plain data, which
/// a board places where its RAM allows—external RAM where it has
/// some—and hands to [`forwarder_loop`].
pub struct MeshCoreStorage {
    forwarder: Forwarder<QUEUE>,
    sending: Frame,
    rng: ReseedingRng,
}

impl MeshCoreStorage {
    /// Storage for the identity whose public key is `public_key`, with a
    /// generator seeded from [`derive_seed`].
    pub fn new(public_key: [u8; 32], seed: [u8; 32]) -> Self {
        Self {
            forwarder: Forwarder::new(public_key, Settings::default()),
            sending: Frame::new(),
            rng: ReseedingRng::new(seed, &MESHCORE_RESEED),
        }
    }
}

/// The forwarder's virtual radio bundle (a mux client after the device
/// node). Static whether or not the forwarder is running, like
/// [`crate::device_node::NODE_CH`].
pub static MESHCORE_CH: Channels<NodeMutex, 4, 2> = Channels::new();

/// Fresh seeds for the forwarder's generator, from a board that harvests
/// entropy after boot.
pub static MESHCORE_RESEED: ReseedSlot = ReseedSlot::new();

/// Every region the session accepts gets a key in the forwarder.
const _: () = assert!(MAX_MESHCORE_REGIONS <= umsh_meshcore_forwarder::MAX_REGIONS);

/// The device-domain settings the forwarder follows.
#[derive(Clone, PartialEq, Eq)]
struct DomainSettings {
    /// `PROP_MESHCORE_FORWARDING_ENABLED`.
    enabled: bool,
    region_policy: RegionPolicy,
    /// `PROP_MESHCORE_REGIONS`, each name without its `#`.
    region_names:
        heapless::Vec<heapless::Vec<u8, MESHCORE_REGION_NAME_MAX_LEN>, MAX_MESHCORE_REGIONS>,
    min_rssi: Option<i16>,
    min_snr: Option<i8>,
}

/// The latest settings. A `Watch` rather than a second consumer of the
/// device node's single-consumer `DEV_SYNC`: the forwarder starts after
/// the first publication and must still see it.
static SETTINGS: Watch<NodeMutex, DomainSettings, 1> = Watch::new();

/// Raised when the radio is switched on or off, which is not a
/// device-domain change and so arrives by its own path.
static RADIO_CHANGED: Signal<NodeMutex, ()> = Signal::new();

/// Mirror a device-domain snapshot to the forwarder. Called wherever the
/// snapshot is published, so a host write, a boot restore, and a
/// `CMD_RST` all reach it by one path.
pub(crate) fn publish(snapshot: &DevDomainSnapshot) {
    SETTINGS.sender().send(DomainSettings {
        enabled: snapshot.meshcore_forwarding_enabled,
        // Validated by the session; an unassigned value cannot be stored.
        region_policy: RegionPolicy::from_u8(snapshot.meshcore_region_policy).unwrap_or_default(),
        region_names: snapshot.meshcore_region_names.clone(),
        min_rssi: snapshot.repeater_min_rssi,
        min_snr: snapshot.repeater_min_snr,
    });
}

/// Note that the radio was switched on or off.
pub(crate) fn radio_changed() {
    RADIO_CHANGED.signal(());
}

/// The forwarder's generator seed, derived from the device node's.
///
/// Both are expanded from the one boot draw, under different labels, so
/// a board need not reserve a second hardware read for a generator whose
/// only job is retransmit timing.
pub fn derive_seed(node_seed: &[u8; 32]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    umsh_crypto::hkdf_sha256(
        &umsh_crypto::software::SoftwareSha256,
        node_seed,
        &[],
        b"umsh-meshcore-forwarder-rng-v1",
        &mut seed,
    );
    seed
}

/// A uniform delay in `T_frame/40..=T_frame/4`: the UMSH MAC's backoff
/// after a busy channel, so both protocols on this radio wait the same
/// way and neither crowds the other out.
fn busy_backoff_ms(t_frame_ms: u32, draw: u32) -> u32 {
    let low = t_frame_ms / 40;
    let high = (t_frame_ms / 4).max(low);
    low + ((u64::from(draw) * u64::from(high - low + 1)) >> 32) as u32
}

/// Everything the three halves of the loop share.
struct State {
    forwarder: &'static mut Forwarder<QUEUE>,
    rng: &'static mut ReseedingRng,
    /// Whether the forwarder may run, given the settings and the radio.
    active: bool,
}

/// The device's side of [`Environment`].
struct Env<'a> {
    duty: &'static DutyLedger,
    rng: &'a mut ReseedingRng,
}

impl Environment for Env<'_> {
    fn airtime_ms(&self, len: usize) -> u32 {
        self.duty.airtime_ms(len)
    }

    fn random_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }
}

/// Tally a verdict in the device's counters: every reception is seen,
/// and is then a forward of one kind, declined, or a duplicate.
fn count(stats: Option<&StatsLedger>, verdict: Verdict, header: u8) {
    let Some(stats) = stats else {
        return;
    };
    let outcome = match verdict {
        // Another protocol, or a copy of this device's own transmission.
        Verdict::Foreign | Verdict::Remembered => return,
        Verdict::Duplicate => None,
        Verdict::Scheduled { .. } if RouteType::from_header(header).is_flood() => {
            Some(Counter::MeshCoreForwardedFlood)
        }
        Verdict::Scheduled { .. } => Some(Counter::MeshCoreForwardedRouted),
        Verdict::Malformed | Verdict::LinkGated | Verdict::Declined(_) | Verdict::QueueFull => {
            Some(Counter::MeshCoreDeclined)
        }
    };
    stats.bump(Counter::MeshCoreSeen);
    if let Some(counter) = outcome {
        stats.bump(counter);
    }
}

fn heard(origin: RxOrigin, rssi: i16, snr: umsh_hal::Snr) -> Heard {
    match origin {
        RxOrigin::Air => Heard::Air { rssi, snr },
        RxOrigin::LocalTx => Heard::LocalTx,
        RxOrigin::Backhaul | RxOrigin::Bearer(_) => Heard::Backhaul,
    }
}

/// The forwarder's gate: the radio on, forwarding enabled, and an identity
/// MeshCore lets a repeater run under. No settings yet means closed.
fn gate(identity_allowed: bool, radio_on: bool, enabled: Option<bool>) -> bool {
    identity_allowed && radio_on && enabled == Some(true)
}

/// How a queued forward left.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Transmitted,
    /// The channel stayed busy, or the duty ledger kept refusing, for
    /// every attempt.
    Abandoned,
    /// The gate closed while it waited.
    Withdrawn,
    Failed,
}

/// The UMSH MAC's channel-access rule: CAD before every attempt, and on
/// a busy channel—or a refusal from the duty ledger, which arrives the
/// same way—a random backoff and another try, up to the MAC's attempt
/// limit.
async fn transmit_with_backoff<R: Radio>(
    radio: &mut R,
    frame: &[u8],
    mut active: impl FnMut() -> bool,
    mut draw: impl FnMut() -> u32,
) -> Sent
where
    R::Error: core::fmt::Debug,
{
    for attempt in 1..=MAX_CAD_ATTEMPTS {
        if !active() {
            return Sent::Withdrawn;
        }
        let options = TxOptions {
            cad: CadPolicy::Gate,
            power_dbm: None,
        };
        match radio.transmit(frame, options).await {
            Ok(()) => return Sent::Transmitted,
            Err(TxError::CadTimeout) if attempt < MAX_CAD_ATTEMPTS => {
                Timer::after_millis(u64::from(busy_backoff_ms(radio.t_frame_ms(), draw()))).await;
            }
            Err(TxError::CadTimeout) => {}
            Err(TxError::Io(error)) => {
                debug_log(format_args!("meshcore: transmit FAILED {error:?}"));
                return Sent::Failed;
            }
        }
    }
    debug_log(format_args!(
        "meshcore: abandoned after {MAX_CAD_ATTEMPTS} busy attempts"
    ));
    Sent::Abandoned
}

fn settings_for(domain: &DomainSettings) -> Settings {
    Settings {
        region_policy: domain.region_policy,
        regions: Default::default(),
        min_rssi: domain.min_rssi,
        min_snr: domain.min_snr,
    }
    .with_region_names(domain.region_names.iter().map(|name| name.as_slice()))
}

/// Run the forwarder in `storage`, built for the identity whose public
/// key is `public_key`.
///
/// `t_frame_ms` is the worst-case frame airtime the device node's MAC
/// was given, which sizes the busy backoff the same way for both.
/// `note_external_load` is the board's battery-estimator coupling,
/// called after each completed transmit. `stats` is the device's
/// counter ledger, where a board keeps one.
pub async fn forwarder_loop(
    storage: &'static mut MeshCoreStorage,
    public_key: [u8; 32],
    t_frame_ms: u32,
    duty: &'static DutyLedger,
    stats: Option<&'static StatsLedger>,
    note_external_load: fn(),
) -> ! {
    let identity_allowed = umsh_ulcp::ids::meshcore_identity_allowed(public_key[0]);
    if !identity_allowed {
        debug_log(format_args!(
            "meshcore: identity prefix {:02x} is reserved; not forwarding",
            public_key[0]
        ));
    }
    let MeshCoreStorage {
        forwarder,
        sending,
        rng,
    } = storage;
    let state = RefCell::new(State {
        forwarder,
        rng,
        active: false,
    });
    // A forward has been queued; the transmit half re-reads its deadline.
    let queued: Signal<NoopRawMutex, ()> = Signal::new();

    let settings = async {
        let Some(mut receiver) = SETTINGS.receiver() else {
            debug_assert!(false, "meshcore: forwarder_loop is single-caller");
            return;
        };
        // Only the enable outlives an update; the rest goes straight into
        // the engine, and a copy here would cost the task its size.
        let mut enabled = None;
        loop {
            let update = select(receiver.changed(), RADIO_CHANGED.wait()).await;
            let mut state = state.borrow_mut();
            if let Either::First(domain) = &update {
                enabled = Some(domain.enabled);
                state.forwarder.set_settings(settings_for(domain));
            }
            drop(update);
            let radio_on = crate::device_node::radio_enabled() == Some(true);
            let active = gate(identity_allowed, radio_on, enabled);
            if active != state.active {
                debug_log(format_args!(
                    "meshcore: forwarding {}",
                    if active { "ON" } else { "off" }
                ));
                // Restarting with an empty duplicate memory can at most
                // repeat a frame heard just before the gate closed, which
                // every other node's duplicate suppression absorbs.
                state.forwarder.reset();
                state.active = active;
            }
        }
    };

    // Each frame is handled where the queue hands it over, so the task
    // never holds a copy of one across a wait.
    let receive = poll_fn(|cx| {
        while let Poll::Ready(frame) = MESHCORE_CH.rx.poll_receive(cx) {
            let mut guard = state.borrow_mut();
            let State {
                forwarder,
                rng,
                active,
            } = &mut *guard;
            if !*active {
                continue;
            }
            let info = frame.info;
            let verdict = forwarder.receive(
                &frame.data,
                heard(info.origin, info.rssi, info.snr),
                Instant::now().as_millis(),
                &mut Env {
                    duty,
                    rng: &mut **rng,
                },
            );
            let header = frame.data.first().copied().unwrap_or(0);
            count(stats, verdict, header);
            if verdict != Verdict::Foreign {
                debug_log(format_args!(
                    "meshcore: rx len={} header={header:02x} rssi={} snr={:?}: {verdict:?}",
                    frame.data.len(),
                    info.rssi,
                    info.snr
                ));
            }
            if let Verdict::Scheduled { .. } = verdict {
                queued.signal(());
            }
        }
        Poll::<()>::Pending
    });

    let transmit = async {
        let mut radio = DutyGatedRadio::with_load_hook(
            LoraphyRadio::new(&MESHCORE_CH, t_frame_ms),
            duty,
            EmbassyClock,
            note_external_load,
        );
        loop {
            loop {
                let now = Instant::now().as_millis();
                let next = {
                    let mut state = state.borrow_mut();
                    match state.forwarder.pop_due(now) {
                        Some(frame) => {
                            *sending = frame;
                            None
                        }
                        None => Some(state.forwarder.next_due_ms()),
                    }
                };
                let Some(next) = next else {
                    break;
                };
                match next {
                    Some(due) => {
                        let _ = select(Timer::at(Instant::from_millis(due)), queued.wait()).await;
                    }
                    None => queued.wait().await,
                }
            }
            // A gate that closed while this frame waited takes it with
            // everything else.
            transmit_with_backoff(
                &mut radio,
                sending,
                || state.borrow().active,
                || state.borrow_mut().rng.next_u32(),
            )
            .await;
        }
    };

    join3(settings, receive, transmit).await;
    unreachable!("the forwarder's loops never end");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_spans_a_fortieth_to_a_quarter_of_the_frame() {
        assert_eq!(busy_backoff_ms(1_000, 0), 25);
        assert_eq!(busy_backoff_ms(1_000, u32::MAX), 250);
        let mid = busy_backoff_ms(1_000, u32::MAX / 2);
        assert!((25..=250).contains(&mid));
        // A frame too short to divide still backs off by something sane.
        assert_eq!(busy_backoff_ms(3, u32::MAX), 0);
    }

    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        let waker = core::task::Waker::noop();
        let mut context = core::task::Context::from_waker(waker);
        loop {
            if let core::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
    }

    /// Answers busy a set number of times, then transmits.
    struct BusyRadio {
        busy: u8,
        attempts: u8,
        fail: bool,
    }

    impl Radio for BusyRadio {
        type Error = ();

        async fn transmit(&mut self, _: &[u8], options: TxOptions) -> Result<(), TxError<()>> {
            assert_eq!(options.cad, CadPolicy::Gate);
            self.attempts += 1;
            if self.fail {
                return Err(TxError::Io(()));
            }
            if self.attempts <= self.busy {
                return Err(TxError::CadTimeout);
            }
            Ok(())
        }

        fn poll_receive(
            &mut self,
            _: &mut core::task::Context<'_>,
            _: &mut [u8],
        ) -> core::task::Poll<Result<umsh_hal::RxInfo, ()>> {
            core::task::Poll::Pending
        }

        fn max_frame_size(&self) -> usize {
            255
        }

        fn t_frame_ms(&self) -> u32 {
            // Short enough that sixteen backoffs pass quickly.
            8
        }
    }

    fn send(radio: &mut BusyRadio, mut active: impl FnMut() -> bool) -> Sent {
        block_on(transmit_with_backoff(radio, &[0; 16], &mut active, || {
            u32::MAX
        }))
    }

    #[test]
    fn a_busy_channel_is_retried_and_then_abandoned() {
        let mut radio = BusyRadio {
            busy: 3,
            attempts: 0,
            fail: false,
        };
        assert_eq!(send(&mut radio, || true), Sent::Transmitted);
        assert_eq!(radio.attempts, 4);

        let mut radio = BusyRadio {
            busy: u8::MAX,
            attempts: 0,
            fail: false,
        };
        assert_eq!(send(&mut radio, || true), Sent::Abandoned);
        assert_eq!(radio.attempts, MAX_CAD_ATTEMPTS);
    }

    #[test]
    fn a_closed_gate_withdraws_a_waiting_forward() {
        let mut radio = BusyRadio {
            busy: u8::MAX,
            attempts: 0,
            fail: false,
        };
        let mut checks = 0;
        let sent = send(&mut radio, || {
            checks += 1;
            checks <= 2
        });
        assert_eq!(sent, Sent::Withdrawn);
        assert_eq!(radio.attempts, 2);
    }

    #[test]
    fn a_radio_failure_is_not_retried() {
        let mut radio = BusyRadio {
            busy: 0,
            attempts: 0,
            fail: true,
        };
        assert_eq!(send(&mut radio, || true), Sent::Failed);
        assert_eq!(radio.attempts, 1);
    }

    fn domain(enabled: bool, names: &[&[u8]]) -> DomainSettings {
        DomainSettings {
            enabled,
            region_policy: RegionPolicy::ScopedOnly,
            region_names: names
                .iter()
                .map(|name| heapless::Vec::from_slice(name).unwrap())
                .collect(),
            min_rssi: Some(-100),
            min_snr: Some(-5),
        }
    }

    #[test]
    fn every_term_of_the_gate_is_required() {
        assert!(gate(true, true, Some(true)));
        assert!(!gate(false, true, Some(true)));
        assert!(!gate(true, false, Some(true)));
        assert!(!gate(true, true, Some(false)));
        assert!(!gate(true, true, None));
    }

    #[test]
    fn the_engine_takes_the_meshcore_regions_and_shared_thresholds() {
        let settings = settings_for(&domain(true, &[b"sf-bay", b"pdx"]));
        assert_eq!(settings.region_policy, RegionPolicy::ScopedOnly);
        assert_eq!(settings.min_rssi, Some(-100));
        assert_eq!(settings.min_snr, Some(-5));
        // Each stored name derives under the `#` it is stored without.
        assert_eq!(
            settings.regions.as_slice(),
            &[
                umsh_meshcore_forwarder::TransportKey::for_region_name(b"#sf-bay").unwrap(),
                umsh_meshcore_forwarder::TransportKey::for_region_name(b"#pdx").unwrap(),
            ]
        );
    }

    #[test]
    fn every_reception_is_seen_and_then_one_thing() {
        use umsh_meshcore_forwarder::Declined;
        let stats = StatsLedger::new();
        let flood = 0x40 | 0x01;
        let direct = 0x40 | 0x02;
        count(Some(&stats), Verdict::Scheduled { due_ms: 0 }, flood);
        count(Some(&stats), Verdict::Scheduled { due_ms: 0 }, direct);
        count(Some(&stats), Verdict::Duplicate, flood);
        count(Some(&stats), Verdict::Declined(Declined::ZeroHop), direct);
        count(Some(&stats), Verdict::LinkGated, flood);
        count(Some(&stats), Verdict::QueueFull, flood);
        count(Some(&stats), Verdict::Malformed, flood);
        // Not receptions: another protocol, and this device's own frame.
        count(Some(&stats), Verdict::Foreign, 0x00);
        count(Some(&stats), Verdict::Remembered, flood);
        count(None, Verdict::Scheduled { due_ms: 0 }, flood);
        assert_eq!(stats.get(Counter::MeshCoreSeen), 7);
        assert_eq!(stats.get(Counter::MeshCoreForwardedFlood), 1);
        assert_eq!(stats.get(Counter::MeshCoreForwardedRouted), 1);
        assert_eq!(stats.get(Counter::MeshCoreDeclined), 4);
    }

    /// The whole loop, driven through its real mux bundle with a waker
    /// that reports whether a delivery woke it: every frame the mux hands
    /// over is counted, not only the first.
    #[test]
    fn every_delivered_frame_wakes_the_loop_and_is_counted() {
        use core::sync::atomic::{AtomicBool, Ordering};
        use core::task::{Context, RawWaker, RawWakerVTable, Waker};
        use umsh_hal::{RxInfo, Snr};
        use umsh_radio_loraphy::RxFrame;

        static WOKEN: AtomicBool = AtomicBool::new(false);
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        fn wake(_: *const ()) {
            WOKEN.store(true, Ordering::SeqCst);
        }
        fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, drop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);

        let key = [0x5A; 32];
        let storage: &'static mut MeshCoreStorage =
            Box::leak(Box::new(MeshCoreStorage::new(key, [1; 32])));
        let duty: &'static DutyLedger = Box::leak(Box::new(DutyLedger::new()));
        let stats: &'static StatsLedger = Box::leak(Box::new(StatsLedger::new()));
        let mut run = Box::pin(forwarder_loop(
            storage,
            key,
            1_000,
            duty,
            Some(stats),
            || {},
        ));

        crate::device_node::set_radio_enabled(true);
        SETTINGS.sender().send(domain(true, &[]));
        assert!(run.as_mut().poll(&mut cx).is_pending());

        for i in 0..6u8 {
            // An unscoped GRP_TXT flood with an empty path and a unique body.
            let mut data = heapless::Vec::new();
            data.extend_from_slice(&[0x15, 0x00, i, 1, 2, 3, 4])
                .unwrap();
            let frame = RxFrame {
                data,
                info: RxInfo {
                    len: 7,
                    rssi: -50,
                    snr: Snr::from_centibels(100),
                    lqi: None,
                    origin: RxOrigin::Air,
                    buffered: None,
                },
            };
            WOKEN.store(false, Ordering::SeqCst);
            MESHCORE_CH.rx.try_send(frame).ok().expect("queue has room");
            assert!(
                WOKEN.load(Ordering::SeqCst),
                "frame {i} did not wake the loop"
            );
            assert!(run.as_mut().poll(&mut cx).is_pending());
            assert_eq!(stats.get(Counter::MeshCoreSeen), u32::from(i) + 1);
        }
    }

    #[test]
    fn the_seed_is_not_the_node_seed() {
        let node = [7u8; 32];
        assert_ne!(derive_seed(&node), node);
        assert_eq!(derive_seed(&node), derive_seed(&node));
    }
}
