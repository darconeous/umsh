//! Receive windows, one per remote key.
//!
//! A sender has one frame-counter sequence, shared by everything it sends:
//! unicast and blind unicast to any of our identities, and signed multicast
//! and broadcast. Its replay window is therefore kept once, keyed by its
//! public key, not once per local identity that happens to hear it.
//!
//! The table holds two classes of entry:
//!
//! - **Registered peers.** Persisted through the [`CounterStore`], and never
//!   evicted. A registered entry starts *unrestored*: its stored baseline
//!   has not yet been merged in, and it must be before any frame is judged
//!   against it ([`RxWindows::window_for_judging`]).
//! - **Strangers.** Kept only in RAM, evicted least recently used when the
//!   table is full, and dropped once idle for [`STRANGER_IDLE_MS`]. A new
//!   signer displaces another stranger's window at most
//!   [`STRANGER_DISPLACEMENT_QUOTA`] times within
//!   [`STRANGER_DISPLACEMENT_WINDOW_MS`]: a key costs nothing to mint, and
//!   without the bound a burst of first contacts would discard every
//!   stranger's window on demand, so that a replay of any of their frames is
//!   first contact again. Past the quota a new signer gets no window.
//!
//! Registering a key moves its entry to the registered class with its window
//! intact; unregistering moves it back. Nothing about the window is
//! discarded either way, so a promotion can never reopen counters the
//! stranger window had already spent.
//!
//! [`CounterStore`]: umsh_hal::CounterStore

use heapless::Vec;
use umsh_core::PublicKey;
use umsh_crypto::replay::{ReplayWindow, RxAcceptance};

use crate::{CapacityError, admission::Quota};

/// Accepted frames from a registered peer between baseline writes.
///
/// It counts frames, not counter distance: a sender's counter advances
/// across all of its destinations, so one frame can move the baseline by
/// far more than this. What an unexpected restart reopens is the frames
/// accepted since the last successful write, and that is what this bounds.
pub const RX_COUNTER_PERSIST_INTERVAL: u16 = 16;

/// How long a stranger's window is kept without traffic.
pub const STRANGER_IDLE_MS: u64 = 60 * 60 * 1000;
/// Strangers' windows that new signers may displace within
/// [`STRANGER_DISPLACEMENT_WINDOW_MS`].
pub const STRANGER_DISPLACEMENT_QUOTA: usize = 4;
/// The span [`STRANGER_DISPLACEMENT_QUOTA`] covers.
pub const STRANGER_DISPLACEMENT_WINDOW_MS: u64 = 10 * 60 * 1000;

/// Replay state for traffic from one remote key.
#[derive(Clone, Debug)]
pub struct RxWindow {
    key: PublicKey,
    /// Replay window over the sender's frame counters.
    pub replay_window: ReplayWindow,
    /// The baseline the store holds for this key, as far as this entry
    /// knows: what it last wrote, or what it restored.
    persisted_rx_counter: u32,
    /// Frames accepted since the last successful write.
    unpersisted_frames: u16,
    /// The baseline was set outright rather than advanced, and is written
    /// at the next pass whatever the frame count.
    write_now: bool,
    /// What the store took for this key, and has yet to flush.
    stored: Option<u32>,
    /// The stored baseline has been merged in. Meaningful only for a
    /// registered entry.
    restored: bool,
    last_used_ms: u64,
}

impl RxWindow {
    fn new(key: PublicKey, now_ms: u64) -> Self {
        Self {
            key,
            replay_window: ReplayWindow::new(),
            persisted_rx_counter: 0,
            unpersisted_frames: 0,
            write_now: false,
            stored: None,
            restored: false,
            last_used_ms: now_ms,
        }
    }

    /// The remote key this window belongs to.
    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The baseline the store holds for this key, as far as this entry knows.
    pub fn persisted_rx_counter(&self) -> u32 {
        self.persisted_rx_counter
    }

    /// Whether the stored baseline has been merged in.
    pub fn is_restored(&self) -> bool {
        self.restored
    }

    /// Frames accepted since the last successful write.
    pub fn unpersisted_frames(&self) -> u16 {
        self.unpersisted_frames
    }

    /// Accept `counter`, which the caller has checked, and count it toward
    /// the next write.
    pub fn accept(&mut self, counter: u32, mic: &[u8], now_ms: u64) -> RxAcceptance {
        self.last_used_ms = now_ms;
        self.unpersisted_frames = self.unpersisted_frames.saturating_add(1);
        self.replay_window.accept(counter, mic, now_ms)
    }

    /// Make `counter` the baseline outright, as a counter resynchronization
    /// does, and write it at the next pass. With `mic`, the frame that
    /// carried it is accepted too, so its later copies are duplicates.
    pub fn adopt_baseline(&mut self, counter: u32, mic: Option<&[u8]>, now_ms: u64) {
        self.last_used_ms = now_ms;
        self.replay_window.reset(counter, now_ms);
        if let Some(mic) = mic {
            self.replay_window.accept(counter, mic, now_ms);
        }
        self.write_now = true;
    }

    /// Merge baseline `stored` read from the store, zero meaning no record,
    /// and mark the entry restored.
    ///
    /// Restoring merges rather than picks: every counter at or before
    /// `stored` is refused from here on, and whatever the live window knows
    /// above it is kept ([`ReplayWindow::raise_floor`]).
    pub fn merge_stored(&mut self, stored: u32, now_ms: u64) {
        if stored != 0 {
            self.replay_window.raise_floor(stored, now_ms);
            self.persisted_rx_counter = stored;
        }
        self.restored = true;
    }

    /// Whether the next persistence pass should write this entry.
    pub fn needs_persist(&self) -> bool {
        self.write_now || self.unpersisted_frames >= RX_COUNTER_PERSIST_INTERVAL
    }

    /// Ask the next persistence pass to write whatever has not been
    /// written, however little. For a deliberate restart.
    pub(crate) fn force_persist(&mut self) {
        if self.unpersisted_frames > 0
            || self.replay_window.last_accepted != self.persisted_rx_counter
        {
            self.write_now = true;
        }
    }

    /// Record that `value` reached the store.
    pub(crate) fn mark_persisted(&mut self, value: u32) {
        self.persisted_rx_counter = value;
        self.unpersisted_frames = 0;
        self.write_now = false;
    }

    /// Record that the store took `value`, which is not persisted until it
    /// is flushed.
    pub(crate) fn mark_stored(&mut self, value: u32) {
        self.stored = Some(value);
    }

    /// Whether the store holds a value of this entry's yet to be flushed.
    pub(crate) fn is_stored(&self) -> bool {
        self.stored.is_some()
    }

    /// Record that a flush persisted what the store took.
    pub(crate) fn settle_stored(&mut self) {
        if let Some(value) = self.stored.take() {
            self.mark_persisted(value);
        }
    }

    fn touch(&mut self, now_ms: u64) {
        self.last_used_ms = now_ms;
    }
}

/// The window for `key` is registered but its stored baseline has not been
/// merged in. Nothing may be judged against it until
/// [`Mac`](crate::Mac) has read the store and merged what it found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeedsRestore(pub PublicKey);

/// Receive windows for up to `PEERS` registered peers and `STRANGERS`
/// strangers. See the [module documentation](self).
#[derive(Clone, Debug)]
pub struct RxWindows<const PEERS: usize, const STRANGERS: usize> {
    registered: Vec<RxWindow, PEERS>,
    strangers: Vec<RxWindow, STRANGERS>,
    /// New signers' windows that displaced another stranger's.
    displacements: Quota<STRANGER_DISPLACEMENT_QUOTA>,
}

impl<const PEERS: usize, const STRANGERS: usize> Default for RxWindows<PEERS, STRANGERS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const PEERS: usize, const STRANGERS: usize> RxWindows<PEERS, STRANGERS> {
    /// An empty table.
    pub const fn new() -> Self {
        Self {
            registered: Vec::new(),
            strangers: Vec::new(),
            displacements: Quota::new(),
        }
    }

    /// The window for `key`, in either class.
    pub fn get(&self, key: &PublicKey) -> Option<&RxWindow> {
        self.registered
            .iter()
            .chain(self.strangers.iter())
            .find(|entry| entry.key == *key)
    }

    /// The window for `key`, in either class, without regard to restore
    /// state. Judging a frame goes through
    /// [`window_for_judging`](Self::window_for_judging) instead.
    pub fn get_mut(&mut self, key: &PublicKey) -> Option<&mut RxWindow> {
        self.registered
            .iter_mut()
            .chain(self.strangers.iter_mut())
            .find(|entry| entry.key == *key)
    }

    /// The window to judge a frame from `key` against, marked used at
    /// `now_ms`. A registered window that has not merged its stored
    /// baseline yet is refused with [`NeedsRestore`].
    pub fn window_for_judging(
        &mut self,
        key: &PublicKey,
        now_ms: u64,
    ) -> Result<Option<&mut RxWindow>, NeedsRestore> {
        if let Some(entry) = self.registered.iter_mut().find(|entry| entry.key == *key) {
            if !entry.restored {
                return Err(NeedsRestore(*key));
            }
            entry.touch(now_ms);
            return Ok(Some(entry));
        }
        let mut stranger = self.strangers.iter_mut().find(|entry| entry.key == *key);
        if let Some(entry) = &mut stranger {
            entry.touch(now_ms);
        }
        Ok(stranger)
    }

    /// Whether `key` holds a registered entry.
    pub fn is_registered(&self, key: &PublicKey) -> bool {
        self.registered.iter().any(|entry| entry.key == *key)
    }

    /// Give `key` a registered entry: its stranger entry moved over with its
    /// window intact, or a new one. Either way it starts unrestored. An
    /// entry already registered is left as it is.
    ///
    /// Fails only when every registered slot is taken.
    pub fn register(&mut self, key: PublicKey, now_ms: u64) -> Result<(), CapacityError> {
        if self.is_registered(&key) {
            return Ok(());
        }
        if self.registered.is_full() {
            return Err(CapacityError);
        }
        let mut entry = match self.strangers.iter().position(|entry| entry.key == key) {
            Some(index) => self.strangers.swap_remove(index),
            None => RxWindow::new(key, now_ms),
        };
        entry.restored = false;
        let _ = self.registered.push(entry);
        Ok(())
    }

    /// Return `key`'s registered entry to the stranger class, window intact.
    /// What it never wrote stays unwritten: strangers are kept only in RAM.
    pub fn unregister(&mut self, key: &PublicKey, now_ms: u64) {
        let Some(index) = self.registered.iter().position(|entry| entry.key == *key) else {
            return;
        };
        let mut entry = self.registered.swap_remove(index);
        entry.write_now = false;
        self.insert_stranger(entry, now_ms);
    }

    /// Return every registered entry whose key `keep` refuses to the
    /// stranger class.
    pub fn unregister_unless(&mut self, mut keep: impl FnMut(&PublicKey) -> bool, now_ms: u64) {
        while let Some(index) = self.registered.iter().position(|entry| !keep(&entry.key)) {
            let key = self.registered[index].key;
            self.unregister(&key, now_ms);
        }
    }

    /// The window for `key` if it has one in either class, or else a new
    /// stranger window. A full stranger class gives up its least recently
    /// used entry, within [`STRANGER_DISPLACEMENT_QUOTA`]. `None` when the
    /// table keeps no strangers at all, or when the class is full and the
    /// quota spent.
    pub fn get_or_insert_stranger(&mut self, key: PublicKey, now_ms: u64) -> Option<&mut RxWindow> {
        if let Some(index) = self.registered.iter().position(|entry| entry.key == key) {
            let entry = &mut self.registered[index];
            entry.touch(now_ms);
            return Some(entry);
        }
        if !self.strangers.iter().any(|entry| entry.key == key) {
            self.expire_strangers(now_ms);
            if STRANGERS > 0 && self.strangers.is_full() {
                if !self
                    .displacements
                    .allows(now_ms, STRANGER_DISPLACEMENT_WINDOW_MS)
                {
                    return None;
                }
                self.displacements.note(now_ms);
            }
            self.insert_stranger(RxWindow::new(key, now_ms), now_ms);
        }
        let entry = self.strangers.iter_mut().find(|entry| entry.key == key)?;
        entry.touch(now_ms);
        Some(entry)
    }

    /// Drop every stranger idle for [`STRANGER_IDLE_MS`] or longer.
    pub fn expire_strangers(&mut self, now_ms: u64) {
        self.strangers
            .retain(|entry| now_ms.saturating_sub(entry.last_used_ms) < STRANGER_IDLE_MS);
    }

    /// Registered entries.
    pub fn registered(&self) -> impl Iterator<Item = &RxWindow> {
        self.registered.iter()
    }

    /// Registered entries, mutably.
    pub(crate) fn registered_mut(&mut self) -> impl Iterator<Item = &mut RxWindow> {
        self.registered.iter_mut()
    }

    /// The registered entry at `index`.
    pub(crate) fn registered_at(&self, index: usize) -> Option<&RxWindow> {
        self.registered.get(index)
    }

    /// Stranger entries.
    pub fn strangers(&self) -> impl Iterator<Item = &RxWindow> {
        self.strangers.iter()
    }

    fn insert_stranger(&mut self, entry: RxWindow, now_ms: u64) {
        if STRANGERS == 0 {
            return;
        }
        self.expire_strangers(now_ms);
        if self.strangers.is_full()
            && let Some(index) = self
                .strangers
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_used_ms)
                .map(|(index, _)| index)
        {
            self.strangers.swap_remove(index);
        }
        let _ = self.strangers.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_crypto::replay::ReplayVerdict;

    fn key(byte: u8) -> PublicKey {
        PublicKey([byte; 32])
    }

    #[test]
    fn full_stranger_class_evicts_the_least_recently_used() {
        let mut windows = RxWindows::<2, 2>::new();
        windows.get_or_insert_stranger(key(1), 10);
        windows.get_or_insert_stranger(key(2), 20);
        windows.get_or_insert_stranger(key(1), 30);
        windows.get_or_insert_stranger(key(3), 40);
        assert!(windows.get(&key(1)).is_some());
        assert!(windows.get(&key(2)).is_none());
        assert!(windows.get(&key(3)).is_some());
    }

    /// New signers displace strangers' windows only within the quota, and
    /// past it get none; the quota slides with its window.
    #[test]
    fn new_signers_displace_strangers_only_within_the_quota() {
        let mut windows = RxWindows::<1, 2>::new();
        windows.get_or_insert_stranger(key(1), 0).unwrap();
        windows.get_or_insert_stranger(key(2), 0).unwrap();
        for byte in 0..STRANGER_DISPLACEMENT_QUOTA as u8 {
            assert!(windows.get_or_insert_stranger(key(10 + byte), 1).is_some());
        }
        let held = |windows: &RxWindows<1, 2>| -> std::vec::Vec<PublicKey> {
            windows.strangers().map(|entry| *entry.key()).collect()
        };
        let survivors = held(&windows);
        assert!(windows.get_or_insert_stranger(key(99), 2).is_none());
        assert_eq!(held(&windows), survivors);
        // A window already held is still found.
        assert!(windows.get_or_insert_stranger(survivors[0], 3).is_some());

        assert!(
            windows
                .get_or_insert_stranger(key(99), STRANGER_DISPLACEMENT_WINDOW_MS + 1)
                .is_some()
        );
    }

    #[test]
    fn idle_strangers_expire_and_registered_entries_never_do() {
        let mut windows = RxWindows::<2, 2>::new();
        windows.register(key(1), 0).unwrap();
        windows.get_or_insert_stranger(key(2), 0);
        windows.get_or_insert_stranger(key(3), STRANGER_IDLE_MS / 2);
        windows.expire_strangers(STRANGER_IDLE_MS);
        assert!(windows.get(&key(1)).is_some());
        assert!(windows.get(&key(2)).is_none());
        assert!(windows.get(&key(3)).is_some());
    }

    #[test]
    fn registered_entries_are_never_evicted_by_strangers() {
        let mut windows = RxWindows::<2, 1>::new();
        windows.register(key(1), 0).unwrap();
        windows.register(key(2), 0).unwrap();
        for byte in 3..10 {
            windows.get_or_insert_stranger(key(byte), u64::from(byte));
        }
        assert!(windows.is_registered(&key(1)));
        assert!(windows.is_registered(&key(2)));
        assert_eq!(windows.strangers().count(), 1);
        assert_eq!(windows.register(key(3), 10), Err(CapacityError));
    }

    #[test]
    fn promotion_keeps_the_window_and_needs_a_restore() {
        let mut windows = RxWindows::<2, 2>::new();
        windows
            .get_or_insert_stranger(key(1), 0)
            .unwrap()
            .accept(100, &[1; 16], 0);
        assert!(windows.window_for_judging(&key(1), 1).is_ok());

        windows.register(key(1), 1).unwrap();
        assert_eq!(
            windows.window_for_judging(&key(1), 1).unwrap_err(),
            NeedsRestore(key(1))
        );
        let entry = windows.get_mut(&key(1)).unwrap();
        entry.merge_stored(0, 1);
        assert_eq!(
            entry.replay_window.check(100, &[1; 16], 2),
            ReplayVerdict::Replay
        );

        // Back to a stranger, still holding it.
        windows.unregister(&key(1), 2);
        assert!(!windows.is_registered(&key(1)));
        let entry = windows.window_for_judging(&key(1), 3).unwrap().unwrap();
        assert_eq!(
            entry.replay_window.check(100, &[1; 16], 3),
            ReplayVerdict::Replay
        );
    }

    #[test]
    fn writes_follow_accepted_frames_not_counter_distance() {
        let mut windows = RxWindows::<1, 0>::new();
        windows.register(key(1), 0).unwrap();
        let entry = windows.get_mut(&key(1)).unwrap();
        entry.merge_stored(0, 0);
        entry.accept(1, &[1; 16], 0);
        entry.accept(1_001, &[2; 16], 0);
        assert!(!entry.needs_persist());
        for counter in 1_002..1_002 + u32::from(RX_COUNTER_PERSIST_INTERVAL) - 3 {
            entry.accept(counter, &[3; 16], 0);
        }
        assert_eq!(entry.unpersisted_frames(), RX_COUNTER_PERSIST_INTERVAL - 1);
        assert!(!entry.needs_persist());
        entry.accept(5_000, &[4; 16], 0);
        assert!(entry.needs_persist());
        entry.mark_persisted(5_000);
        assert!(!entry.needs_persist());
    }
}
