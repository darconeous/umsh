//! Glyphs kept inflated, so a screen of them is inflated once.

use core::mem::MaybeUninit;

use crate::inflate::Tables;
use crate::store::{BLOCK, Glyph, Id, Store, palette_len, palette_record};
use crate::{LARGEST_INDICES, LARGEST_PALETTES, PALETTES, PIXELS_MAX};

/// The last `SLOTS` glyphs drawn, and the last blocks inflated.
///
/// Inflating a block costs about as much as drawing its sixteen glyphs, so
/// a glyph is copied out of it to be kept, and the block is kept too:
/// glyphs are grouped as the picker lists them, so the next one drawn is
/// often beside the last. A cache takes about 13 KB, and then 700 bytes a
/// slot.
///
/// It is plain data, with no atomics, so it can be kept in memory where
/// atomics do not work, such as PSRAM on an ESP32-S3. Every field is valid
/// as zeros, so a cache can be made in place in memory it is given
/// ([`Cache::new_in`]) rather than built aside and copied.
pub struct Cache<const SLOTS: usize> {
    inner: Inner<SLOTS>,
}

struct Inner<const SLOTS: usize> {
    tables: Tables,
    palettes: [u8; LARGEST_PALETTES],
    /// The block in `palettes`, plus one. Zero when there is none.
    palettes_key: u32,
    indices: [u8; LARGEST_INDICES],
    /// The block in `indices`: see [`key`]. Zero when there is none.
    indices_key: u32,
    /// Counts lookups, to find the least recently used slot.
    clock: u32,
    slots: [Slot; SLOTS],
}

#[derive(Clone, Copy)]
struct Slot {
    /// The glyph held: see [`key`]. Zero when empty.
    key: u32,
    used: u32,
    palette: [u8; PALETTE_MAX],
    indices: [u8; PIXELS_MAX],
}

/// The longest a palette record is.
const PALETTE_MAX: usize = 1 + 3 * 32;

/// A glyph or block of a store, never zero: every store's size is.
fn key(store: &Store, n: usize) -> u32 {
    (u32::from(store.size) << 16) | n as u32
}

impl<const SLOTS: usize> Cache<SLOTS> {
    /// An empty cache, for a `static`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: Inner {
                tables: Tables::EMPTY,
                palettes: [0; LARGEST_PALETTES],
                palettes_key: 0,
                indices: [0; LARGEST_INDICES],
                indices_key: 0,
                clock: 0,
                slots: [Slot {
                    key: 0,
                    used: 0,
                    palette: [0; PALETTE_MAX],
                    indices: [0; PIXELS_MAX],
                }; SLOTS],
            },
        }
    }

    /// An empty cache made in `slot`, without building one aside.
    pub fn new_in(slot: &mut MaybeUninit<Self>) -> &mut Self {
        // SAFETY: every field is an integer or an array of integers, for
        // which all zeros is a valid value, and an empty one.
        unsafe {
            slot.as_mut_ptr().write_bytes(0, 1);
            slot.assume_init_mut()
        }
    }
}

impl<const SLOTS: usize> Default for Cache<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize> Cache<SLOTS> {
    /// Glyph `id` of `store`, or `None` when its block is corrupt.
    pub fn glyph(&mut self, store: &Store, id: Id) -> Option<Glyph<'_>> {
        let (palette, indices) = self.inner.glyph(store, id)?;
        Some(Glyph::new(store.size, palette, indices))
    }
}

impl<const SLOTS: usize> Inner<SLOTS> {
    /// Glyph `id` of `store`: its palette record and its indices.
    fn glyph(&mut self, store: &Store, id: Id) -> Option<(&[u8], &[u8])> {
        if SLOTS == 0 {
            return None;
        }
        self.clock = self.clock.wrapping_add(1);
        let wanted = key(store, usize::from(id));
        let slot = match self.slots.iter().position(|s| s.key == wanted) {
            Some(slot) => slot,
            None => self.fill(store, id)?,
        };
        let slot = &mut self.slots[slot];
        slot.used = self.clock;
        let palette = slot.palette.get(..palette_len(slot.palette[0]))?;
        Some((palette, slot.indices.get(..store.pixels())?))
    }

    /// Copies glyph `id` of `store` into the least recently used slot,
    /// inflating what it needs. Returns the slot.
    fn fill(&mut self, store: &Store, id: Id) -> Option<usize> {
        let block = usize::from(id) / BLOCK;
        let n = usize::from(id) % BLOCK;
        if self.palettes_key != block as u32 + 1 {
            self.palettes_key = 0;
            PALETTES.inflate(block, &mut self.palettes, &mut self.tables)?;
            self.palettes_key = block as u32 + 1;
        }
        if self.indices_key != key(store, block) {
            self.indices_key = 0;
            store
                .indices
                .inflate(block, &mut self.indices, &mut self.tables)?;
            self.indices_key = key(store, block);
        }
        let palette = palette_record(&self.palettes, n)?;
        let indices = self
            .indices
            .get(n * store.pixels()..(n + 1) * store.pixels())?;
        let clock = self.clock;
        let slot = (0..SLOTS).max_by_key(|&i| clock.wrapping_sub(self.slots[i].used))?;
        let target = &mut self.slots[slot];
        target.key = 0;
        target
            .palette
            .get_mut(..palette.len())?
            .copy_from_slice(palette);
        target
            .indices
            .get_mut(..indices.len())?
            .copy_from_slice(indices);
        target.key = key(store, usize::from(id));
        Some(slot)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{STORES, find};

    #[test]
    fn every_glyph_inflates_whole() {
        let mut cache = std::boxed::Box::new(Cache::<4>::new());
        for store in STORES {
            for id in 0..crate::COUNT {
                let glyph = cache
                    .glyph(store, id)
                    .unwrap_or_else(|| panic!("glyph {id} at {}", store.size));
                let (colors, pixels) = (glyph.palette().count(), glyph.indices().len());
                assert!((1..=32).contains(&colors));
                assert_eq!(pixels, usize::from(store.size).pow(2));
            }
        }
    }

    #[test]
    fn a_cache_made_in_place_works() {
        let mut slot = std::boxed::Box::new(MaybeUninit::<Cache<2>>::uninit());
        let cache = Cache::new_in(&mut slot);
        let id = find("\u{1F600}").unwrap();
        let glyph = cache.glyph(&crate::STORE_24, id).unwrap();
        // A grinning face is opaque in the middle and clear at the corners.
        let middle = glyph.indices()[12 * 24 + 12];
        let corner = glyph.indices()[0];
        let alphas: std::vec::Vec<u8> = glyph.palette().map(|(_, a)| a).collect();
        assert_eq!(alphas[usize::from(middle)], 255);
        assert_eq!(alphas[usize::from(corner)], 0);
    }
}
