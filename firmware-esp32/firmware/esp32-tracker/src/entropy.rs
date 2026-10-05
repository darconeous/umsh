//! Entropy after boot: harvest, reseed, persist.
//!
//! The pool (see [`umsh_crypto::pool`]) makes the device cryptographically
//! strong from a stored seed, so nothing here is needed for a boot to be
//! safe. What this module adds is time: a board that stays up for months
//! keeps taking in hardware entropy, hands it to the generators that are
//! running, and keeps the stored seed current for the next boot.
//!
//! Three parties meet here:
//!
//! - **Sources** own a radio. The chip's TRNG is only true-random while
//!   RF is live, so a harvest is taken by whichever radio driver can
//!   prove that—the Bluetooth supervisor through a controller of its
//!   own, the Wi-Fi task through its running one. They ask
//!   [`harvest_due`] and [`overdue`] when, and hand over 32 octets with
//!   [`offer`].
//! - **Generators** are the ChaCha20 instances seeded at boot. Each
//!   reads a [`ReseedSlot`]; every harvest puts a fresh pool draw in
//!   each.
//! - **The seed journal** is written by [`task`], which owns the pool
//!   from the end of boot.
//!
//! Timing samples from [`jitter`] and, where a board enables it, the
//! SAR ADC noise source are mixed in alongside. Neither is trusted on
//! its own.

use core::sync::atomic::{AtomicU32, Ordering};

use embassy_futures::select::{Either3, select3};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use esp_println::println;
use umsh_bsp_esp32::jitter;
use umsh_crypto::pool::EntropyPool;
use umsh_crypto::software::SoftwareSha256;
use umsh_ulcp_runtime::device_node::NODE_RESEED;
use umsh_ulcp_runtime::reseed::ReseedSlot;

use super::debug_log;
use super::journals::SeedStore;

/// A source that can harvest without disturbing anything does so once
/// the last harvest is this old.
const HARVEST_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// With no harvest for this long, a source makes room for one.
const HARVEST_DEADLINE: Duration = Duration::from_secs(6 * 60 * 60);
/// How long a failed harvest waits before the next attempt.
const HARVEST_RETRY: Duration = Duration::from_secs(5 * 60);
/// A harvest the stored seed does not reflect is written along with any
/// other journal write once the last seed write is this old.
const SEED_PIGGYBACK_MIN: Duration = Duration::from_secs(60 * 60);
/// ...and by itself once the last seed write is this old.
const SEED_DEADLINE: Duration = Duration::from_secs(6 * 60 * 60);
/// How long a refused seed write waits before the next attempt.
const SEED_RETRY: Duration = Duration::from_secs(10 * 60);

const NEVER: u32 = u32::MAX;

/// Seconds since boot at the last harvest; [`NEVER`] until the first of
/// this boot.
static HARVESTED_S: AtomicU32 = AtomicU32::new(NEVER);
/// Seconds since boot before which a failed harvest is not retried.
static RETRY_S: AtomicU32 = AtomicU32::new(0);
/// A harvest on its way to [`task`].
static HARVEST: Signal<CriticalSectionRawMutex, [u8; 32]> = Signal::new();
static JOURNAL_WRITTEN: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// The session's secret generator (`fill_secret`).
pub static SESSION_RESEED: ReseedSlot = ReseedSlot::new();
/// The generator behind the Bluetooth identity resolving key.
#[cfg(feature = "ble")]
pub static BLE_PRIVACY_RESEED: ReseedSlot = ReseedSlot::new();
/// The bridge tunnel's TLS generator.
#[cfg(feature = "bridge-client")]
pub static BRIDGE_RESEED: ReseedSlot = ReseedSlot::new();

/// Every running generator, with the label its reseed draws under.
static GENERATORS: &[(&[u8], &ReseedSlot)] = &[
    (b"node-rng reseed", &NODE_RESEED),
    (b"identity-rng reseed", &SESSION_RESEED),
    #[cfg(feature = "ble")]
    (b"ble-privacy-rng reseed", &BLE_PRIVACY_RESEED),
    #[cfg(feature = "bridge-client")]
    (b"bridge-tls reseed", &BRIDGE_RESEED),
];

fn now_s() -> u32 {
    Instant::now().as_secs() as u32
}

/// When the last harvest becomes `age` old, or a failed attempt may be
/// repeated, whichever is later. The first harvest of a boot is wanted
/// at once.
fn harvest_at(age: Duration) -> Instant {
    let retry = Instant::from_secs(u64::from(RETRY_S.load(Ordering::Relaxed)));
    match HARVESTED_S.load(Ordering::Relaxed) {
        NEVER => retry,
        last => (Instant::from_secs(u64::from(last)) + age).max(retry),
    }
}

/// Whether a source that has its radio to hand should harvest now.
pub fn harvest_due() -> bool {
    Instant::now() >= harvest_at(HARVEST_INTERVAL)
}

/// Resolves when a harvest has been wanted for long enough that a source
/// should go out of its way for one.
pub async fn overdue() {
    loop {
        let at = harvest_at(HARVEST_DEADLINE);
        if Instant::now() >= at {
            return;
        }
        // Another source may harvest while this one sleeps.
        Timer::at(at).await;
    }
}

/// Hand over 32 octets read from the TRNG while RF was live.
pub fn offer(fresh: [u8; 32]) {
    HARVESTED_S.store(now_s(), Ordering::Relaxed);
    RETRY_S.store(0, Ordering::Relaxed);
    // Harvests are an hour apart and the service is always listening, so
    // nothing is waiting here. One that somehow is gets replaced, which
    // costs that harvest and nothing else.
    HARVEST.signal(fresh);
}

/// A harvest was attempted and the radio refused.
pub fn harvest_failed() {
    RETRY_S.store(
        now_s().saturating_add(HARVEST_RETRY.as_secs() as u32),
        Ordering::Relaxed,
    );
}

/// Some journal has just been written, so flash is awake and a seed
/// write costs nothing extra.
pub fn journal_written() {
    JOURNAL_WRITTEN.signal(());
}

/// Read the SAR ADC noise source: 32 octets, never sufficient alone.
///
/// The source borrows ADC1 and leaves the block in reset, so this runs
/// before the battery sampler is built. The TRNG mixes this source in at
/// a fraction of the rate it mixes RF noise, hence the spacing between
/// words.
#[cfg(feature = "entropy-sar-adc")]
pub fn sar_adc(
    rng: esp_hal::peripherals::RNG<'_>,
    adc: esp_hal::peripherals::ADC1<'_>,
) -> Option<[u8; 32]> {
    let source = esp_hal::rng::TrngSource::new(rng, adc);
    let mut out = [0u8; 32];
    let read = esp_hal::rng::Trng::try_new().map(|trng| {
        for word in out.chunks_exact_mut(4) {
            embassy_time::block_for(Duration::from_micros(50));
            word.copy_from_slice(&trng.random().to_le_bytes());
        }
    });
    // The source refuses to go away while a reader exists; the reader
    // ended with the closure above.
    drop(source);
    read.ok().map(|()| out)
}

/// The pool and its seed journal, from the boot commit until [`task`]
/// takes them over.
pub struct Service {
    pool: EntropyPool<SoftwareSha256>,
    seeds: SeedStore,
    /// The pool holds a harvest that no stored seed reflects.
    unwritten: bool,
    /// When the stored seed last took in a harvest, this boot.
    written: Option<Instant>,
}

impl Service {
    /// A labeled draw for something seeded at boot.
    pub fn draw(&mut self, label: &[u8], out: &mut [u8]) {
        self.pool
            .draw(label, out)
            .unwrap_or_else(|_| panic!("entropy pool draw before commit"));
    }
}

/// Bring the pool up and commit the next boot's seed.
///
/// The seed-file protocol (see [`umsh_crypto::pool`]): derive the working
/// key one-way from the stored seed plus per-boot salt, commit the next
/// boot's seed to flash, and only then draw. With no stored seed—a first
/// boot, or the boot completing a factory reset—the pool starts from
/// `harvest`, which reads the TRNG with RF live and does not return
/// without entropy.
///
/// `extra` is whatever additional noise the board could read; the boot's
/// own timing goes in as well.
pub async fn boot(
    mut seeds: SeedStore,
    extra: Option<[u8; 32]>,
    mut harvest: impl FnMut() -> [u8; 32],
) -> Service {
    let mut harvested = false;
    let mut pool = match seeds.seed() {
        Some(stored) => {
            let mut salt = [0u8; 7];
            salt[..6].copy_from_slice(&super::base_mac_bytes());
            salt[6] = esp_hal::system::reset_reason()
                .map(|r| r as u8)
                .unwrap_or(0xff);
            EntropyPool::from_seed(SoftwareSha256, &stored, &salt)
        }
        None => {
            let pool = EntropyPool::from_seed(SoftwareSha256, &harvest(), b"first-boot");
            harvested = true;
            println!("entropy pool bootstrapped from TRNG");
            pool
        }
    };
    if let Some(extra) = extra {
        pool.mix(&extra);
        println!("entropy pool mixed SAR ADC noise");
    }
    // How long flash, the PMU, and RF calibration took to get here.
    jitter::sample();
    pool.mix(&jitter::take());
    let committed = seeds.persist(pool.next_seed()).await.is_ok();
    if committed {
        pool.seed_refreshed();
    } else {
        // The commit is what makes a crash unable to replay this boot's
        // outputs. With the write refused, break the replay instead by
        // mixing in a fresh TRNG draw.
        println!("entropy seed persist FAILED—mixing TRNG for this boot");
        pool.mix(&harvest());
        harvested = true;
    }
    pool.seed_committed();
    if harvested {
        HARVESTED_S.store(now_s(), Ordering::Relaxed);
    }
    Service {
        pool,
        seeds,
        unwritten: harvested && !committed,
        written: (harvested && committed).then(Instant::now),
    }
}

/// Mix harvests into the pool, reseed the running generators, and keep
/// the stored seed current.
///
/// The first harvest of a boot is written at once: the boot commit
/// usually carries nothing the previous boot did not know. After that a
/// write waits for company—another journal write, once an hour has
/// passed—and goes alone only at the deadline.
#[embassy_executor::task]
pub async fn task(mut service: Service) -> ! {
    let mut not_before = Instant::from_ticks(0);
    loop {
        let (unwritten, written) = (service.unwritten, service.written);
        let wake = select3(
            HARVEST.wait(),
            async {
                if !unwritten {
                    core::future::pending::<()>().await;
                }
                let at = written.map_or(not_before, |at| (at + SEED_DEADLINE).max(not_before));
                Timer::at(at).await;
            },
            async {
                let Some(at) = written.filter(|_| unwritten) else {
                    return core::future::pending().await;
                };
                Timer::at((at + SEED_PIGGYBACK_MIN).max(not_before)).await;
                // Only a write from here on counts, and never this
                // task's own.
                JOURNAL_WRITTEN.reset();
                JOURNAL_WRITTEN.wait().await;
            },
        )
        .await;
        match wake {
            Either3::First(fresh) => {
                service.pool.mix(&fresh);
                service.pool.mix(&jitter::take());
                for (label, slot) in GENERATORS {
                    let mut seed = [0u8; 32];
                    service.draw(label, &mut seed);
                    slot.offer(seed);
                }
                service.unwritten = true;
                debug_log(format_args!("entropy: harvest mixed, generators reseeded"));
            }
            Either3::Second(()) | Either3::Third(()) => {
                service.pool.mix(&jitter::take());
                let next = service.pool.next_seed();
                if service.seeds.persist(next).await.is_ok() {
                    service.pool.seed_refreshed();
                    service.unwritten = false;
                    service.written = Some(Instant::now());
                    debug_log(format_args!("entropy: seed stored"));
                } else {
                    // The boot commit still protects this boot.
                    not_before = Instant::now() + SEED_RETRY;
                    debug_log(format_args!("entropy: seed write FAILED, retrying later"));
                }
            }
        }
    }
}
