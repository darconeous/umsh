//! The device node's persisted frame counters.
//!
//! A RAM image of the [`counter_map`](crate::counter_map) plus the
//! journal handle behind it. `store` upserts the map; a dirty `flush`
//! writes the whole map as one record in the counter journal.
//!
//! This is what stops a power cycle from reusing MAC frame-counter
//! space: the device identity's TX reservation boundary and each peer's
//! RX replay boundary both survive here. The MAC batches its calls (one
//! flush per persist block of secured frames), so each flush costs one
//! journal record write.

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;

use crate::counter_map::{CounterMap, ENCODED_MAX};
use crate::journal::{JournalFlash, ProtoStore, SharedFlash};
use crate::log::debug_log;

/// RAM image + journal handle behind [`NodeCounterStore`].
///
/// Lives in a board's `StaticCell` rather than a plain static because
/// the journal handle carries the board's flash reference, which is
/// deliberately only ever shared through the cell pattern.
pub struct NodeCounters<MF: RawMutex + 'static, F: JournalFlash + 'static> {
    map: CounterMap,
    dirty: bool,
    /// Mounted counter journal; `None` between [`NodeCounters::new`] and
    /// [`mount`], where flushes stay RAM-only.
    journal: Option<ProtoStore<MF, F>>,
}

impl<MF: RawMutex + 'static, F: JournalFlash + 'static> NodeCounters<MF, F> {
    /// The still-journal-less counter state. Call once, early in boot;
    /// the board attaches the journal with [`mount`] before the device
    /// node comes up.
    pub const fn new() -> Self {
        Self {
            map: CounterMap::new(),
            dirty: false,
            journal: None,
        }
    }
}

impl<MF: RawMutex + 'static, F: JournalFlash + 'static> Default for NodeCounters<MF, F> {
    fn default() -> Self {
        Self::new()
    }
}

/// The mutex a board wraps its [`NodeCounters`] in.
///
/// The counter mutex (`MC`) and the flash mutex (`MF`) are separate
/// parameters because a board can legitimately want different kinds: the
/// ESP32 image guards its uncontended flash with a `NoopRawMutex` while
/// the counter state, reached from the MAC pump, takes a critical
/// section.
pub type NodeCountersMutex<MC, MF, F> = Mutex<MC, NodeCounters<MF, F>>;

/// Mount the counter journal at `page0` and load the persisted map.
pub async fn mount<MC: RawMutex + 'static, MF: RawMutex + 'static, F: JournalFlash + 'static>(
    counters: &'static NodeCountersMutex<MC, MF, F>,
    flash: &'static SharedFlash<MF, F>,
    page0: u32,
) {
    let (journal, payload) = ProtoStore::mount(flash, page0).await;
    let map = payload
        .as_deref()
        .and_then(CounterMap::decode)
        .unwrap_or_default();
    debug_log(format_args!("counter journal: {} entries", map.len()));
    let mut counters = counters.lock().await;
    counters.map = map;
    counters.journal = Some(journal);
}

/// Drop a previous identity's persisted TX boundary (its context is the
/// raw 32-byte public key; per-peer RX boundaries are keyed by the
/// *peer* key and stay meaningful across identity replacement). The next
/// dirty flush persists the pruned map.
pub async fn prune_stale_tx<
    MC: RawMutex + 'static,
    MF: RawMutex + 'static,
    F: JournalFlash + 'static,
>(
    counters: &'static NodeCountersMutex<MC, MF, F>,
    public_key: &[u8; 32],
) {
    let mut counters = counters.lock().await;
    if counters.map.prune_tx_except(public_key) {
        counters.dirty = true;
    }
}

/// Drop all persisted device-node counters (factory clear). The RAM map
/// clears unconditionally; a failed tombstone write self-heals because
/// the map is left dirty and the next flush rewrites the (now empty)
/// state.
pub async fn clear<MC: RawMutex + 'static, MF: RawMutex + 'static, F: JournalFlash + 'static>(
    counters: &'static NodeCountersMutex<MC, MF, F>,
) {
    let mut counters = counters.lock().await;
    counters.map.clear();
    counters.dirty = match counters.journal.as_mut() {
        Some(journal) => journal.clear().await.is_err(),
        None => false,
    };
}

/// The device node's [`umsh_hal::CounterStore`].
pub struct NodeCounterStore<
    MC: RawMutex + 'static,
    MF: RawMutex + 'static,
    F: JournalFlash + 'static,
> {
    counters: &'static NodeCountersMutex<MC, MF, F>,
}

impl<MC: RawMutex + 'static, MF: RawMutex + 'static, F: JournalFlash + 'static>
    NodeCounterStore<MC, MF, F>
{
    pub fn new(counters: &'static NodeCountersMutex<MC, MF, F>) -> Self {
        Self { counters }
    }
}

impl<MC: RawMutex + 'static, MF: RawMutex + 'static, F: JournalFlash + 'static>
    umsh_hal::CounterStore for NodeCounterStore<MC, MF, F>
{
    type Error = ();

    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error> {
        // Missing entries read as 0, the MAC's "no boundary persisted
        // yet" sentinel.
        Ok(self.counters.lock().await.map.get(context).unwrap_or(0))
    }

    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error> {
        let mut counters = self.counters.lock().await;
        let changed = counters.map.set(context, value).map_err(|_| ())?;
        counters.dirty |= changed;
        Ok(())
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        let mut counters = self.counters.lock().await;
        if !counters.dirty {
            return Ok(());
        }
        let mut payload = [0u8; ENCODED_MAX];
        let len = counters.map.encode(&mut payload).ok_or(())?;
        match counters.journal.as_mut() {
            Some(journal) => journal.persist(&payload[..len]).await?,
            // No journal mounted (a board built without persistence, or
            // before the boot-time mount): RAM only. Report success so
            // the MAC marks the boundary instead of re-flushing every
            // cycle.
            None => {}
        }
        counters.dirty = false;
        Ok(())
    }
}
