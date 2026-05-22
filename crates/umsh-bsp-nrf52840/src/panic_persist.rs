//! Persist panic messages across resets.
//!
//! On nRF52840 a region of RAM can be marked as `noinit` so its
//! contents survive a soft reset (warm boot, watchdog, panic-driven
//! `SCB::sys_reset()`). This module provides the framing layer for
//! that region — it lives here in `umsh-bsp-nrf52840` because every
//! nRF52840-based board (T1000-E, T-Echo, …) shares this mechanism.
//!
//! The [`PanicSlot`] API operates on a borrowed `&'static mut [u8]`,
//! so the framing is purely portable and unit-testable on the host.
//! The caller is responsible for declaring the `.noinit` static and
//! passing a mutable slice of it; see `umsh-bsp-nrf52840::gpregret`
//! and the board BSPs for the typical integration pattern.
//!
//! # On-region layout
//!
//! ```text
//!   offset  field      bytes  notes
//!   ------  --------   -----  -----------------------------------------
//!     0     magic        4    PANIC_MAGIC; distinguishes a captured
//!                             record from uninitialized RAM noise.
//!     4     length       2    payload length in bytes (truncated if
//!                             larger than the region).
//!     6     checksum     2    Fletcher-16 of magic ++ length ++ payload.
//!     8     payload      N    UTF-8 panic message, `length` bytes.
//! ```
//!
//! Total header = 8 bytes. Maximum payload = `region.len() - 8`.

/// A `Sync` wrapper around `UnsafeCell<MaybeUninit<T>>` for use with
/// `#[link_section = ".uninit"]` statics.
///
/// Rust 2024 made `&mut static_mut` a hard error (`static_mut_refs` lint).
/// `UnsafeCell` is the correct escape hatch: it opts into interior
/// mutability, so a raw pointer obtained via `UnsafeCell::get()` is not a
/// reference to a mutable static. The `unsafe impl Sync` is sound on a
/// single-core target where no thread can race on the cell.
pub struct SyncNoinit<T>(pub core::cell::UnsafeCell<core::mem::MaybeUninit<T>>);

// Safety: nRF52840 is a single-core device; concurrent access is impossible.
unsafe impl<T> Sync for SyncNoinit<T> {}

impl<T> SyncNoinit<T> {
    pub const fn uninit() -> Self {
        Self(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()))
    }

    /// Return a `&'static mut [u8]` slice over the inner value.
    ///
    /// # Safety
    /// The caller must ensure no other live reference to this cell exists.
    pub unsafe fn as_bytes_mut(&self) -> &'static mut [u8] {
        let ptr: *mut u8 = self.0.get().cast::<u8>();
        // SAFETY: caller ensures no other live reference; ptr is non-null and aligned.
        unsafe { core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<T>()) }
    }
}

/// A `core::fmt::Write` sink over a fixed-size byte slice.
///
/// Used to format a `core::panic::PanicInfo` into a stack buffer without
/// heap allocation. Truncates silently when the buffer fills — acceptable
/// for a best-effort panic message capture.
pub struct SliceWriter<'a> {
    pub buf: &'a mut [u8],
    pub pos: usize,
}

impl<'a> core::fmt::Write for SliceWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let avail = self.buf.len().saturating_sub(self.pos);
        let n = s.len().min(avail);
        self.buf[self.pos..self.pos + n].copy_from_slice(&s.as_bytes()[..n]);
        self.pos += n;
        Ok(())
    }
}

const PANIC_MAGIC: u32 = 0x554D_5350; // "UMSP" — UMSH Panic
const HEADER_LEN: usize = 8;

/// Framing wrapper around a borrowed RAM region.
///
/// One instance is constructed at boot from the BSP-provided
/// `&'static mut [u8]`. Pass the same region (the literal same RAM,
/// not a fresh copy) every reset so the previous boot's panic can be
/// recovered.
#[derive(Debug)]
pub struct PanicSlot<'a> {
    region: &'a mut [u8],
}

impl<'a> PanicSlot<'a> {
    /// Wrap a RAM region. Region must be at least
    /// [`HEADER_LEN`] + 1 byte; smaller regions panic in debug and
    /// silently truncate writes to zero payload bytes in release.
    pub fn new(region: &'a mut [u8]) -> Self {
        debug_assert!(
            region.len() > HEADER_LEN,
            "panic slot region must hold at least the 8-byte header plus 1 payload byte"
        );
        Self { region }
    }

    /// Capacity available for payload bytes.
    pub fn payload_capacity(&self) -> usize {
        self.region.len().saturating_sub(HEADER_LEN)
    }

    /// Write a panic message. Truncates if `msg` is larger than the
    /// payload capacity. Returns the number of payload bytes actually
    /// stored. Designed to be callable from a panic handler, so it
    /// allocates nothing and uses only direct slice writes.
    pub fn capture(&mut self, msg: &[u8]) -> usize {
        if self.region.len() <= HEADER_LEN {
            return 0;
        }
        let cap = self.payload_capacity();
        let len = msg.len().min(cap);

        self.region[0..4].copy_from_slice(&PANIC_MAGIC.to_le_bytes());
        self.region[4..6].copy_from_slice(&(len as u16).to_le_bytes());
        self.region[8..8 + len].copy_from_slice(&msg[..len]);

        let cksum = checksum(&self.region[0..6], &self.region[8..8 + len]);
        self.region[6..8].copy_from_slice(&cksum.to_le_bytes());
        len
    }

    /// Borrow the previously-captured payload, if a valid record is
    /// present. Returns `None` for an uninitialized region, a stale /
    /// foreign record (wrong magic), a corrupt record (bad checksum),
    /// or an out-of-bounds length.
    pub fn read(&self) -> Option<&[u8]> {
        if self.region.len() <= HEADER_LEN {
            return None;
        }

        let magic = u32::from_le_bytes(self.region[0..4].try_into().ok()?);
        if magic != PANIC_MAGIC {
            return None;
        }

        let len = u16::from_le_bytes(self.region[4..6].try_into().ok()?) as usize;
        if len > self.payload_capacity() {
            return None;
        }

        let stored_cksum = u16::from_le_bytes(self.region[6..8].try_into().ok()?);
        let computed = checksum(&self.region[0..6], &self.region[8..8 + len]);
        if stored_cksum != computed {
            return None;
        }

        Some(&self.region[8..8 + len])
    }

    /// Invalidate the record. Subsequent [`read`](Self::read) calls
    /// return `None` until another [`capture`](Self::capture) writes a
    /// new one. Cheap: zeroes only the 4-byte magic.
    pub fn clear(&mut self) {
        if self.region.len() >= 4 {
            self.region[0..4].fill(0);
        }
    }
}

/// Fletcher-16 over two byte slices (header front + payload). The
/// header's checksum field itself is skipped by construction — callers
/// pass `header[0..6]` (magic + length, omitting bytes 6..8 where the
/// checksum will be stored).
fn checksum(header_front: &[u8], payload: &[u8]) -> u16 {
    let mut s1: u16 = 0;
    let mut s2: u16 = 0;
    for &b in header_front.iter().chain(payload.iter()) {
        s1 = (s1.wrapping_add(b as u16)) % 255;
        s2 = (s2.wrapping_add(s1)) % 255;
    }
    (s2 << 8) | s1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(region: &mut [u8]) -> PanicSlot<'_> {
        PanicSlot::new(region)
    }

    #[test]
    fn empty_region_returns_none() {
        let mut buf = [0u8; 64];
        let s = slot(&mut buf);
        assert_eq!(s.read(), None);
    }

    #[test]
    fn round_trip_basic_message() {
        let mut buf = [0u8; 64];
        let mut s = slot(&mut buf);
        assert_eq!(s.capture(b"oops"), 4);
        assert_eq!(s.read(), Some(&b"oops"[..]));
    }

    #[test]
    fn round_trip_full_capacity() {
        let mut buf = [0u8; 64];
        let cap = buf.len() - HEADER_LEN;
        let payload = [b'x'; 56]; // 64 - HEADER_LEN
        assert_eq!(payload.len(), cap);
        let mut s = slot(&mut buf);
        assert_eq!(s.capture(&payload), cap);
        assert_eq!(s.read(), Some(&payload[..]));
    }

    #[test]
    fn truncates_when_payload_exceeds_capacity() {
        let mut buf = [0u8; 16]; // capacity = 8
        let mut s = slot(&mut buf);
        assert_eq!(s.capture(b"this is way too long"), 8);
        assert_eq!(s.read(), Some(&b"this is "[..]));
    }

    #[test]
    fn random_uninitialized_bytes_do_not_read_as_valid() {
        let mut buf: [u8; 64] = [0xA5; 64]; // not the magic
        let s = slot(&mut buf);
        assert_eq!(s.read(), None);
    }

    #[test]
    fn clear_invalidates_record() {
        let mut buf = [0u8; 64];
        let mut s = slot(&mut buf);
        s.capture(b"oops");
        assert!(s.read().is_some());
        s.clear();
        assert_eq!(s.read(), None);
    }

    #[test]
    fn corrupted_payload_is_rejected() {
        let mut buf = [0u8; 64];
        {
            let mut s = slot(&mut buf);
            s.capture(b"hello world");
        }
        // Flip a byte inside the payload.
        buf[10] ^= 0xFF;
        let s = slot(&mut buf);
        assert_eq!(s.read(), None);
    }

    #[test]
    fn corrupted_length_is_rejected() {
        let mut buf = [0u8; 64];
        {
            let mut s = slot(&mut buf);
            s.capture(b"hello");
        }
        // Bump length to claim more bytes than the payload contains.
        buf[4] = 200;
        let s = slot(&mut buf);
        assert_eq!(s.read(), None);
    }

    #[test]
    fn length_beyond_region_is_rejected() {
        let mut buf = [0u8; 64];
        {
            let mut s = slot(&mut buf);
            s.capture(b"x");
        }
        // Length larger than the region's payload capacity.
        let bogus_len: u16 = 1024;
        buf[4..6].copy_from_slice(&bogus_len.to_le_bytes());
        let s = slot(&mut buf);
        assert_eq!(s.read(), None);
    }

    #[test]
    fn second_capture_overwrites_first() {
        let mut buf = [0u8; 64];
        let mut s = slot(&mut buf);
        s.capture(b"first");
        s.capture(b"second");
        assert_eq!(s.read(), Some(&b"second"[..]));
    }

    #[test]
    fn read_does_not_mutate_region() {
        let mut buf = [0u8; 64];
        {
            let mut s = slot(&mut buf);
            s.capture(b"persisting");
        }
        let snapshot = buf;
        {
            let s = slot(&mut buf);
            let _ = s.read();
        }
        assert_eq!(snapshot, buf);
    }

    #[test]
    fn payload_capacity_excludes_header() {
        let mut buf = [0u8; 100];
        let s = slot(&mut buf);
        assert_eq!(s.payload_capacity(), 100 - HEADER_LEN);
    }

    #[test]
    fn empty_payload_is_valid() {
        let mut buf = [0u8; 64];
        let mut s = slot(&mut buf);
        assert_eq!(s.capture(b""), 0);
        assert_eq!(s.read(), Some(&b""[..]));
    }
}
