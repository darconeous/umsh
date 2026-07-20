//! Outbound fragmentation planning and fixed-capacity reassembly.
//!
//! Reassembly storage is one global page pool shared by all conversations: a
//! fragment's bytes are stored in linked 80-byte pages, and a slot holds only
//! its key, presence bitmaps, per-fragment lengths/page heads, first-fragment
//! metadata, and deadlines. A conversation with no incomplete fragmented
//! message consumes no page storage.

use crate::engine::sequence::{MessageHandle, StreamKey};
use crate::model::{FRAGMENT_BODY_MAX, FRAGMENT_COUNT_MAX, MessageType, Regarding};

pub const PAGE_SIZE: usize = 80;
const PAGE_NONE: u8 = 0xFF;

/// Message-level metadata retained from fragment zero (spec: options from the
/// first fragment apply to the entire reassembled message).
///
/// Only fields consulted on *later* receive calls are retained. Presentation
/// metadata (sender handle, colors) is not: the announcing Insert mutation is
/// always emitted during the call that delivered fragment zero, so it borrows
/// those directly from the validated content, at full fidelity.
#[derive(Clone, Copy, Debug, Default)]
pub struct FirstMeta {
    pub message_type_byte: u8,
    pub regarding: Option<Regarding>,
    pub editing: Option<u8>,
}

impl FirstMeta {
    pub fn message_type(&self) -> MessageType {
        MessageType::from_byte(self.message_type_byte)
    }
}

/// One in-progress reassembly.
#[derive(Clone, Debug)]
pub struct Slot {
    pub stream: StreamKey,
    pub epoch: u16,
    pub message_id: u8,
    pub count: u8,
    /// Bitmap of fragments whose bytes are stored.
    pub present: u16,
    /// Bitmap of fragments the sender reported unavailable.
    pub unavailable: u16,
    /// Missing fragments whose automatic repair budget was exhausted. This
    /// is separate from `unavailable`: the body remains pending until the
    /// reassembly TTL, but the scheduler must not reset and retry forever.
    pub repair_exhausted: u16,
    pub frag_len: [u8; FRAGMENT_COUNT_MAX as usize],
    frag_head: [u8; FRAGMENT_COUNT_MAX as usize],
    pub meta: FirstMeta,
    pub have_meta: bool,
    /// An Insert mutation has been emitted for this slot's handle.
    pub announced: bool,
    pub handle: MessageHandle,
    pub created_ms: u64,
    pub deadline_ms: u64,
    /// Next time repair scheduling may consider this slot.
    pub repair_at_ms: u64,
    /// When the newest fragment was stored; arrivals defer repair from here.
    pub last_fragment_ms: u64,
}

impl Slot {
    pub fn is_complete(&self) -> bool {
        let all = (1u16 << self.count) - 1;
        self.present == all
    }

    /// Every fragment is either present or reported unavailable, so no
    /// further repair can improve this slot.
    pub fn is_settled(&self) -> bool {
        let all = (1u16 << self.count) - 1;
        (self.present | self.unavailable) == all
    }

    pub fn missing(&self) -> impl Iterator<Item = u8> + '_ {
        (0..self.count).filter(|index| {
            let bit = 1u16 << index;
            self.present & bit == 0 && self.unavailable & bit == 0
        })
    }

    pub fn repairable_missing(&self) -> impl Iterator<Item = u8> + '_ {
        self.missing().filter(|index| {
            let bit = 1u16 << index;
            self.repair_exhausted & bit == 0
        })
    }

    fn fragment_len(&self, index: u8) -> usize {
        self.frag_len[index as usize] as usize
    }
}

/// Outcome of storing one received fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Stored; the slot may now be complete.
    Stored,
    /// The fragment was already present with identical bytes.
    Duplicate,
    /// The fragment was already present with different bytes; the original
    /// authenticated bytes were kept.
    Conflict,
    /// No page capacity; the caller should evict and retry or drop.
    NoSpace,
    /// The fragment body exceeds the wire maximum and was not stored.
    TooLarge,
}

/// Fixed-capacity reassembly pool.
pub struct ReassemblyPool<const SLOTS: usize, const PAGES: usize> {
    pages: [[u8; PAGE_SIZE]; PAGES],
    next_page: [u8; PAGES],
    free_head: u8,
    pub slots: [Option<Slot>; SLOTS],
}

impl<const SLOTS: usize, const PAGES: usize> ReassemblyPool<SLOTS, PAGES> {
    pub fn new() -> Self {
        assert!(PAGES < PAGE_NONE as usize, "page index must fit in u8");
        let mut next_page = [PAGE_NONE; PAGES];
        for (index, next) in next_page
            .iter_mut()
            .enumerate()
            .take(PAGES.saturating_sub(1))
        {
            *next = (index + 1) as u8;
        }
        Self {
            pages: [[0; PAGE_SIZE]; PAGES],
            next_page,
            free_head: if PAGES == 0 { PAGE_NONE } else { 0 },
            slots: [const { None }; SLOTS],
        }
    }

    fn free_pages(&self) -> usize {
        let mut count = 0;
        let mut cursor = self.free_head;
        while cursor != PAGE_NONE {
            count += 1;
            cursor = self.next_page[cursor as usize];
        }
        count
    }

    fn alloc_chain(&mut self, len: usize) -> Option<u8> {
        let needed = len.div_ceil(PAGE_SIZE).max(1);
        if self.free_pages() < needed {
            return None;
        }
        let head = self.free_head;
        let mut cursor = head;
        for _ in 1..needed {
            cursor = self.next_page[cursor as usize];
        }
        self.free_head = self.next_page[cursor as usize];
        self.next_page[cursor as usize] = PAGE_NONE;
        Some(head)
    }

    fn free_chain(&mut self, head: u8) {
        if head == PAGE_NONE {
            return;
        }
        let mut cursor = head;
        while self.next_page[cursor as usize] != PAGE_NONE {
            cursor = self.next_page[cursor as usize];
        }
        self.next_page[cursor as usize] = self.free_head;
        self.free_head = head;
    }

    fn write_chain(&mut self, head: u8, bytes: &[u8]) {
        let mut cursor = head;
        for chunk in bytes.chunks(PAGE_SIZE) {
            self.pages[cursor as usize][..chunk.len()].copy_from_slice(chunk);
            cursor = self.next_page[cursor as usize];
        }
    }

    fn read_chain(&self, head: u8, len: usize, out: &mut [u8]) {
        let mut cursor = head;
        let mut offset = 0;
        while offset < len {
            let take = (len - offset).min(PAGE_SIZE);
            out[offset..offset + take].copy_from_slice(&self.pages[cursor as usize][..take]);
            offset += take;
            cursor = self.next_page[cursor as usize];
        }
    }

    /// Copy a stored fragment into `out` (which must hold
    /// [`FRAGMENT_BODY_MAX`] bytes), returning its length.
    pub fn read_fragment(&self, slot_index: usize, fragment: u8, out: &mut [u8]) -> usize {
        let slot = self.slots[slot_index].as_ref().expect("occupied slot");
        let len = slot.fragment_len(fragment);
        self.read_chain(slot.frag_head[fragment as usize], len, out);
        len
    }

    pub fn find_slot(&self, stream: &StreamKey, epoch: u16, message_id: u8) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref().is_some_and(|slot| {
                slot.stream == *stream && slot.epoch == epoch && slot.message_id == message_id
            })
        })
    }

    pub fn open_slot(&mut self, slot: Slot) -> Option<usize> {
        let index = self.slots.iter().position(Option::is_none)?;
        self.slots[index] = Some(slot);
        Some(index)
    }

    /// Index of the oldest incomplete slot, for eviction under pressure.
    pub fn oldest_slot(&self) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.as_ref().map(|slot| (index, slot.created_ms)))
            .min_by_key(|(_, created)| *created)
            .map(|(index, _)| index)
    }

    /// Release a slot and all its pages, returning it.
    pub fn close_slot(&mut self, index: usize) -> Option<Slot> {
        let slot = self.slots[index].take()?;
        for head in slot.frag_head {
            self.free_chain(head);
        }
        Some(slot)
    }

    /// Drop every slot belonging to `stream` (after a sequence reset),
    /// returning how many were dropped.
    pub fn drop_stream(&mut self, stream: &StreamKey) -> usize {
        let mut dropped = 0;
        for index in 0..SLOTS {
            if self.slots[index]
                .as_ref()
                .is_some_and(|slot| slot.stream == *stream)
            {
                self.close_slot(index);
                dropped += 1;
            }
        }
        dropped
    }

    /// Store one fragment's bytes into a slot.
    pub fn insert_fragment(&mut self, index: usize, fragment: u8, bytes: &[u8]) -> InsertOutcome {
        // The wire maximum is enforced at validation; this guard keeps the
        // pool's u8 lengths and fixed read buffers sound regardless.
        if bytes.len() > FRAGMENT_BODY_MAX {
            return InsertOutcome::TooLarge;
        }
        let slot = self.slots[index].as_ref().expect("occupied slot");
        let bit = 1u16 << fragment;
        if slot.present & bit != 0 {
            let mut existing = [0u8; FRAGMENT_BODY_MAX];
            let len = self.read_fragment(index, fragment, &mut existing);
            return if &existing[..len] == bytes {
                InsertOutcome::Duplicate
            } else {
                InsertOutcome::Conflict
            };
        }
        let Some(head) = self.alloc_chain(bytes.len()) else {
            return InsertOutcome::NoSpace;
        };
        self.write_chain(head, bytes);
        let slot = self.slots[index].as_mut().expect("occupied slot");
        slot.frag_head[fragment as usize] = head;
        slot.frag_len[fragment as usize] = bytes.len() as u8;
        slot.present |= bit;
        slot.unavailable &= !bit;
        InsertOutcome::Stored
    }
}

impl<const SLOTS: usize, const PAGES: usize> Default for ReassemblyPool<SLOTS, PAGES> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn empty_slot(
    stream: StreamKey,
    epoch: u16,
    message_id: u8,
    count: u8,
    handle: MessageHandle,
    now_ms: u64,
) -> Slot {
    Slot {
        stream,
        epoch,
        message_id,
        count,
        present: 0,
        unavailable: 0,
        repair_exhausted: 0,
        frag_len: [0; FRAGMENT_COUNT_MAX as usize],
        frag_head: [PAGE_NONE; FRAGMENT_COUNT_MAX as usize],
        meta: FirstMeta::default(),
        have_meta: false,
        announced: false,
        handle,
        created_ms: now_ms,
        deadline_ms: now_ms,
        repair_at_ms: now_ms,
        last_fragment_ms: now_ms,
    }
}

/// Incremental UTF-8 writer that carries partial code points across fragment
/// boundaries and replaces invalid bytes with U+FFFD.
struct LossyWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
    carry: [u8; 4],
    carry_len: usize,
    truncated: bool,
    had_invalid: bool,
}

impl<'a> LossyWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self {
            out,
            pos: 0,
            carry: [0; 4],
            carry_len: 0,
            truncated: false,
            had_invalid: false,
        }
    }

    fn emit(&mut self, bytes: &[u8]) {
        let space = self.out.len() - self.pos;
        if bytes.len() > space {
            // Truncate at a code-point boundary.
            let mut take = space;
            while take > 0 && bytes[take] & 0xC0 == 0x80 {
                take -= 1;
            }
            self.out[self.pos..self.pos + take].copy_from_slice(&bytes[..take]);
            self.pos += take;
            self.truncated = true;
            return;
        }
        self.out[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    fn emit_replacement(&mut self) {
        self.had_invalid = true;
        self.emit("\u{FFFD}".as_bytes());
    }

    /// Push raw bytes, validating incrementally.
    fn push(&mut self, mut bytes: &[u8]) {
        // Complete a carried partial code point first.
        while self.carry_len > 0 && !bytes.is_empty() {
            let needed = utf8_len(self.carry[0]).unwrap_or(1);
            let take = (needed - self.carry_len).min(bytes.len());
            self.carry[self.carry_len..self.carry_len + take].copy_from_slice(&bytes[..take]);
            self.carry_len += take;
            bytes = &bytes[take..];
            if self.carry_len == needed {
                let carried = self.carry;
                let carry_len = self.carry_len;
                self.carry_len = 0;
                match core::str::from_utf8(&carried[..carry_len]) {
                    Ok(_) => self.emit(&carried[..carry_len]),
                    Err(_) => {
                        // The lead byte's sequence is invalid; resynchronize
                        // after the lead byte.
                        self.emit_replacement();
                        let rest = carry_len - 1;
                        let resume: [u8; 4] = carried;
                        // Reprocess the bytes after the bad lead byte.
                        self.push_inner(&resume[1..1 + rest]);
                    }
                }
            }
        }
        self.push_inner(bytes);
    }

    fn push_inner(&mut self, mut bytes: &[u8]) {
        loop {
            match core::str::from_utf8(bytes) {
                Ok(text) => {
                    self.emit(text.as_bytes());
                    return;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    self.emit(&bytes[..valid]);
                    match error.error_len() {
                        Some(bad) => {
                            self.emit_replacement();
                            bytes = &bytes[valid + bad..];
                        }
                        None => {
                            // Incomplete trailing sequence: carry it.
                            let tail = &bytes[valid..];
                            self.carry[..tail.len()].copy_from_slice(tail);
                            self.carry_len = tail.len();
                            return;
                        }
                    }
                }
            }
        }
    }

    /// End a run of contiguous fragments. When the run borders a gap, an
    /// incomplete trailing code point is discarded (the sentinel covers it);
    /// at true end of message it is invalid input and becomes U+FFFD.
    fn end_run(&mut self, at_gap: bool) {
        if self.carry_len > 0 {
            if !at_gap {
                self.emit_replacement();
            }
            self.carry_len = 0;
        }
    }
}

fn utf8_len(lead: u8) -> Option<usize> {
    match lead {
        0x00..=0x7F => Some(1),
        0xC0..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

/// Sentinels inserted for absent portions of a partial message.
#[derive(Clone, Copy, Debug)]
pub struct RenderSentinels {
    pub pending: &'static str,
    pub missing: &'static str,
    pub unavailable: &'static str,
}

impl Default for RenderSentinels {
    fn default() -> Self {
        Self {
            pending: "[PENDING]",
            missing: "[MISSING]",
            unavailable: "[UNAVAILABLE]",
        }
    }
}

/// Result of rendering a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenderResult {
    pub len: usize,
    pub complete: bool,
    pub had_invalid: bool,
    pub truncated: bool,
}

/// Render a slot's fragments into `out` as UTF-8, inserting one sentinel per
/// absent run and skipping code points damaged by missing byte boundaries.
pub fn render_slot<const SLOTS: usize, const PAGES: usize>(
    pool: &ReassemblyPool<SLOTS, PAGES>,
    slot_index: usize,
    sentinels: &RenderSentinels,
    final_render: bool,
    out: &mut [u8],
) -> RenderResult {
    let slot = pool.slots[slot_index].as_ref().expect("occupied slot");
    let mut writer = LossyWriter::new(out);
    let mut index = 0u8;
    let mut after_gap = false;
    while index < slot.count {
        let bit = 1u16 << index;
        if slot.present & bit != 0 {
            let mut buffer = [0u8; FRAGMENT_BODY_MAX];
            let len = pool.read_fragment(slot_index, index, &mut buffer);
            let mut bytes = &buffer[..len];
            if after_gap {
                // Skip continuation bytes orphaned by the missing boundary.
                while let Some((first, rest)) = bytes.split_first() {
                    if first & 0xC0 == 0x80 {
                        bytes = rest;
                    } else {
                        break;
                    }
                }
                after_gap = false;
            }
            writer.push(bytes);
            index += 1;
            continue;
        }
        // A gap: absent fragments sharing one repair state render as one
        // sentinel, and the run splits where that state changes, so a
        // disclaimed portion reads [UNAVAILABLE] immediately even when it
        // borders a still-repairable one. Sentinel count is bounded by the
        // fragment count.
        writer.end_run(true);
        while index < slot.count && slot.present & (1u16 << index) == 0 {
            let run_unavailable = slot.unavailable & (1u16 << index) != 0;
            while index < slot.count
                && slot.present & (1u16 << index) == 0
                && (slot.unavailable & (1u16 << index) != 0) == run_unavailable
            {
                index += 1;
            }
            let sentinel = if run_unavailable {
                sentinels.unavailable
            } else if final_render {
                sentinels.missing
            } else {
                sentinels.pending
            };
            writer.emit(sentinel.as_bytes());
        }
        after_gap = true;
    }
    writer.end_run(false);
    RenderResult {
        len: writer.pos,
        complete: slot.is_complete(),
        had_invalid: writer.had_invalid,
        truncated: writer.truncated,
    }
}

/// The body exceeds the wire maximum of 10 fragments × 160 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyTooLarge;

/// Plan for splitting an outbound body into fragments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentPlan {
    pub count: u8,
    body_len: usize,
}

impl FragmentPlan {
    /// Plan fragmentation for a body. Returns `None` when the body fits in a
    /// single frame (given its encoded option overhead) and `Some` plan
    /// otherwise. Errors when the body exceeds the wire maximum.
    pub fn plan(body_len: usize, single_frame_budget: usize) -> Result<Option<Self>, BodyTooLarge> {
        if body_len <= single_frame_budget && body_len <= FRAGMENT_BODY_MAX {
            return Ok(None);
        }
        let count = body_len.div_ceil(FRAGMENT_BODY_MAX);
        if count > FRAGMENT_COUNT_MAX as usize || count < 2 {
            if count < 2 {
                // Options alone exceed the frame; still send as two fragments.
                return Ok(Some(Self { count: 2, body_len }));
            }
            return Err(BodyTooLarge);
        }
        Ok(Some(Self {
            count: count as u8,
            body_len,
        }))
    }

    /// Byte range of fragment `index` within the body.
    pub fn range(&self, index: u8) -> core::ops::Range<usize> {
        let per = self
            .body_len
            .div_ceil(self.count as usize)
            .min(FRAGMENT_BODY_MAX);
        let start = per * index as usize;
        let end = (start + per).min(self.body_len);
        start..end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConversationKey, SenderScope};
    use umsh_core::ChannelId;

    fn stream() -> StreamKey {
        StreamKey {
            conversation: ConversationKey::ChannelGroup {
                channel: ChannelId([1, 2]),
            },
            sender: SenderScope::ClaimedMember(umsh_core::NodeHint([9, 9, 9])),
        }
    }

    fn pool_with_slot(count: u8) -> (ReassemblyPool<4, 24>, usize) {
        let mut pool = ReassemblyPool::<4, 24>::new();
        let slot = empty_slot(stream(), 0, 7, count, MessageHandle(1), 0);
        let index = pool.open_slot(slot).unwrap();
        (pool, index)
    }

    #[test]
    fn duplicate_and_conflict_detection() {
        let (mut pool, index) = pool_with_slot(3);
        assert_eq!(
            pool.insert_fragment(index, 0, b"hello"),
            InsertOutcome::Stored
        );
        assert_eq!(
            pool.insert_fragment(index, 0, b"hello"),
            InsertOutcome::Duplicate
        );
        assert_eq!(
            pool.insert_fragment(index, 0, b"jello"),
            InsertOutcome::Conflict
        );
    }

    #[test]
    fn partial_render_inserts_sentinel_and_skips_split_code_point() {
        let (mut pool, index) = pool_with_slot(3);
        // "héllo" split so the é (0xC3 0xA9) straddles the gap boundary.
        pool.insert_fragment(index, 0, b"ab h\xC3").unwrap_stored();
        pool.insert_fragment(index, 2, b"\xA9nd tail")
            .unwrap_stored();
        let mut out = [0u8; 128];
        let result = render_slot(&pool, index, &RenderSentinels::default(), false, &mut out);
        let text = core::str::from_utf8(&out[..result.len]).unwrap();
        assert_eq!(text, "ab h[PENDING]nd tail");
        assert!(!result.complete);
    }

    #[test]
    fn complete_render_heals_boundary_code_points() {
        let (mut pool, index) = pool_with_slot(2);
        pool.insert_fragment(index, 0, b"h\xC3").unwrap_stored();
        pool.insert_fragment(index, 1, b"\xA9!").unwrap_stored();
        let mut out = [0u8; 64];
        let result = render_slot(&pool, index, &RenderSentinels::default(), true, &mut out);
        assert!(result.complete);
        assert_eq!(core::str::from_utf8(&out[..result.len]).unwrap(), "hé!");
    }

    #[test]
    fn oversized_fragment_is_rejected_not_truncated() {
        let (mut pool, index) = pool_with_slot(2);
        let big = [b'x'; FRAGMENT_BODY_MAX + 40];
        assert_eq!(
            pool.insert_fragment(index, 0, &big),
            InsertOutcome::TooLarge
        );
        // Nothing was stored: no pages consumed, no presence bit set.
        assert_eq!(pool.free_pages(), 24);
        assert!(pool.slots[index].as_ref().unwrap().present == 0);
    }

    #[test]
    fn split_absent_run_renders_one_sentinel_per_repair_state() {
        let (mut pool, index) = pool_with_slot(5);
        pool.insert_fragment(index, 0, b"a").unwrap_stored();
        pool.insert_fragment(index, 4, b"z").unwrap_stored();
        // Fragments 1..=3 are absent; 2 is disclaimed, its neighbors pending.
        pool.slots[index].as_mut().unwrap().unavailable = 1 << 2;
        let mut out = [0u8; 128];
        let result = render_slot(&pool, index, &RenderSentinels::default(), false, &mut out);
        let text = core::str::from_utf8(&out[..result.len]).unwrap();
        assert_eq!(text, "a[PENDING][UNAVAILABLE][PENDING]z");

        // At final render, pending sub-runs become missing.
        let result = render_slot(&pool, index, &RenderSentinels::default(), true, &mut out);
        let text = core::str::from_utf8(&out[..result.len]).unwrap();
        assert_eq!(text, "a[MISSING][UNAVAILABLE][MISSING]z");
    }

    #[test]
    fn pages_recycle_after_close() {
        let (mut pool, index) = pool_with_slot(2);
        let big = [b'x'; 160];
        pool.insert_fragment(index, 0, &big).unwrap_stored();
        pool.insert_fragment(index, 1, &big).unwrap_stored();
        let free_before = pool.free_pages();
        pool.close_slot(index);
        assert!(pool.free_pages() > free_before);
        assert_eq!(pool.free_pages(), 24);
    }

    trait UnwrapStored {
        fn unwrap_stored(self);
    }
    impl UnwrapStored for InsertOutcome {
        fn unwrap_stored(self) {
            assert_eq!(self, InsertOutcome::Stored);
        }
    }

    #[test]
    fn fragment_plan_ranges_cover_body() {
        let plan = FragmentPlan::plan(400, 200).unwrap().unwrap();
        assert_eq!(plan.count, 3);
        let mut covered = 0;
        for index in 0..plan.count {
            let range = plan.range(index);
            assert_eq!(range.start, covered);
            covered = range.end;
            assert!(range.len() <= FRAGMENT_BODY_MAX);
        }
        assert_eq!(covered, 400);
    }
}
