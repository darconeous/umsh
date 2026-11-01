//! Message and draft text, shared rather than copied.
//!
//! A screen's views and both of its render trees each hold the text they
//! draw. A message can be ten fragments long, and copies of a conversation's
//! worth of those would fill the stack while a frame is built, so a message's
//! text is kept once, on a heap the device chooses, and everything that shows
//! it holds a counted reference. A draft is kept the same way, and copied
//! anew with each edit.

use core::alloc::{GlobalAlloc, Layout};
use core::ops::Range;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering, fence};

use buoyant::view::EditText;

use crate::model::MESSAGE_LEN;

/// Where message text is kept.
pub type TextHeap = &'static (dyn GlobalAlloc + Sync);

/// What precedes the text in its allocation.
struct Header {
    refs: AtomicUsize,
    len: usize,
    heap: TextHeap,
}

/// Immutable text, shared by counted reference, as `Arc<str>` is but on a
/// [`TextHeap`] of the device's choosing.
pub struct SharedText(NonNull<Header>);

// SAFETY: the text never changes once made, the count is atomic, and the heap
// it returns to is `Sync`: sharing or sending a reference is as sound as it
// is for `Arc<str>`.
unsafe impl Send for SharedText {}
unsafe impl Sync for SharedText {}

impl SharedText {
    /// Copies `text` onto `heap`, or returns `None` when there is no room.
    #[must_use]
    pub fn new(heap: TextHeap, text: &str) -> Option<Self> {
        Self::joined(heap, &[text])
    }

    /// Copies `parts`, one after another, onto `heap`, or returns `None`
    /// when there is no room.
    #[must_use]
    pub fn joined(heap: TextHeap, parts: &[&str]) -> Option<Self> {
        let len = parts.iter().map(|part| part.len()).sum();
        let layout = layout(len)?;
        // SAFETY: the layout is never zero-sized, as it holds the header.
        let header = NonNull::new(unsafe { heap.alloc(layout) }.cast::<Header>())?;
        // SAFETY: the allocation fits the header and then the parts, and
        // nothing else refers to it yet.
        unsafe {
            header.as_ptr().write(Header {
                refs: AtomicUsize::new(1),
                len,
                heap,
            });
            let mut at = bytes(header);
            for part in parts {
                core::ptr::copy_nonoverlapping(part.as_ptr(), at, part.len());
                at = at.add(part.len());
            }
        }
        Some(Self(header))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        // SAFETY: the bytes were copied from a `str`, and live as long as
        // this reference does.
        unsafe {
            let len = self.0.as_ref().len;
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(bytes(self.0), len))
        }
    }

    /// The heap the text is kept on.
    #[must_use]
    pub fn heap(&self) -> TextHeap {
        self.header().heap
    }

    fn header(&self) -> &Header {
        // SAFETY: the header lives as long as any reference to it.
        unsafe { self.0.as_ref() }
    }
}

/// The allocation for a text `len` bytes long.
fn layout(len: usize) -> Option<Layout> {
    let (layout, _) = Layout::new::<Header>()
        .extend(Layout::array::<u8>(len).ok()?)
        .ok()?;
    Some(layout.pad_to_align())
}

/// The text after the header. A byte array needs no alignment, so it begins
/// where the header ends.
fn bytes(header: NonNull<Header>) -> *mut u8 {
    // SAFETY: the allocation extends past the header by the text's length.
    unsafe { header.as_ptr().add(1).cast::<u8>() }
}

impl Clone for SharedText {
    fn clone(&self) -> Self {
        // As in `Arc`: a new reference is made from an existing one, so no
        // ordering is needed, and a count near overflow means references
        // are being leaked.
        let before = self.header().refs.fetch_add(1, Ordering::Relaxed);
        assert!(before < isize::MAX as usize, "shared text count overflow");
        Self(self.0)
    }
}

impl Drop for SharedText {
    fn drop(&mut self) {
        if self.header().refs.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        // Every other reference's use of the text happens before it is freed.
        fence(Ordering::Acquire);
        let Header { len, heap, .. } = *self.header();
        let layout = layout(len).expect("it was allocated with this layout");
        // SAFETY: this was the last reference, and the allocation was made on
        // `heap` with `layout`.
        unsafe {
            heap.dealloc(self.0.as_ptr().cast(), layout);
        }
    }
}

impl core::ops::Deref for SharedText {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for SharedText {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for SharedText {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for SharedText {}

impl core::fmt::Debug for SharedText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl core::fmt::Display for SharedText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self)
    }
}

/// A draft's text: shared as [`SharedText`] is, and copied only when it is
/// edited, so the composer shows it without copying it. Empty, it holds
/// nothing on the heap.
#[derive(Clone)]
pub struct DraftText {
    heap: TextHeap,
    text: Option<SharedText>,
    /// The most its chat's messages take, in bytes.
    limit: usize,
}

impl DraftText {
    /// An empty draft, whose text will be kept on `heap`, up to a message
    /// long.
    #[must_use]
    pub const fn new(heap: TextHeap) -> Self {
        Self {
            heap,
            text: None,
            limit: MESSAGE_LEN,
        }
    }

    /// The same draft, growing to at most `limit` bytes, and never past a
    /// message. Text already longer is kept, to be shortened.
    #[must_use]
    pub fn with_limit(self, limit: usize) -> Self {
        Self {
            limit: limit.min(MESSAGE_LEN),
            ..self
        }
    }

    /// The most the draft grows to, in bytes.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl AsRef<str> for DraftText {
    fn as_ref(&self) -> &str {
        self.text.as_deref().unwrap_or_default()
    }
}

impl EditText for DraftText {
    /// The edited text is a new copy, so whatever still shows the old one is
    /// left as it was. An edit that grows the draft past its limit, or one
    /// there is no room for, is refused.
    fn splice(&mut self, range: Range<usize>, with: &str) -> bool {
        let old = self.as_ref();
        let len = old.len() - range.len() + with.len();
        if len > self.limit && len > old.len() {
            return false;
        }
        let parts = [&old[..range.start], with, &old[range.end..]];
        if parts.iter().all(|part| part.is_empty()) {
            self.text = None;
            return true;
        }
        match SharedText::joined(self.heap, &parts) {
            Some(text) => {
                self.text = Some(text);
                true
            }
            None => false,
        }
    }
}

impl PartialEq for DraftText {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for DraftText {}

impl core::fmt::Debug for DraftText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_ref(), f)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::alloc::System;

    /// The system heap, counting what is live on it.
    struct Counting(AtomicUsize);

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            self.0.fetch_add(1, Ordering::Relaxed);
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            self.0.fetch_sub(1, Ordering::Relaxed);
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[test]
    fn the_text_is_freed_with_its_last_reference() {
        static HEAP: Counting = Counting(AtomicUsize::new(0));
        let text = SharedText::new(&HEAP, "Snow starts about 200 m above the hut").unwrap();
        let copy = text.clone();
        assert_eq!(HEAP.0.load(Ordering::Relaxed), 1);
        drop(text);
        assert_eq!(copy.as_str(), "Snow starts about 200 m above the hut");
        assert_eq!(HEAP.0.load(Ordering::Relaxed), 1);
        drop(copy);
        assert_eq!(HEAP.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn empty_and_odd_lengths_keep_their_bytes() {
        for text in ["", "a", "ünïcödé", "seven b"] {
            let shared = SharedText::new(&System, text).unwrap();
            assert_eq!(&*shared, text);
            assert_eq!(shared.clone(), shared);
        }
    }

    /// A heap with no room.
    struct Full;

    unsafe impl GlobalAlloc for Full {
        unsafe fn alloc(&self, _: Layout) -> *mut u8 {
            core::ptr::null_mut()
        }

        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {
            unreachable!("nothing was allocated");
        }
    }

    #[test]
    fn a_full_heap_makes_no_text() {
        assert!(SharedText::new(&Full, "hello").is_none());
    }

    #[test]
    fn an_edited_draft_leaves_the_text_shown_as_it_was() {
        let mut draft = DraftText::new(&System);
        assert!(draft.splice(0..0, "hut"));
        let shown = draft.clone();
        assert!(draft.splice(0..0, "the "));
        assert!(draft.splice(7..7, "!"));
        assert_eq!(draft.as_ref(), "the hut!");
        assert_eq!(shown.as_ref(), "hut");
        assert!(draft.splice(0..8, ""));
        assert!(draft.text.is_none());
    }

    #[test]
    fn a_draft_is_at_most_a_message_long() {
        let mut draft = DraftText::new(&System);
        let message = "x".repeat(MESSAGE_LEN);
        assert!(draft.splice(0..0, &message));
        assert!(!draft.splice(0..0, "y"));
        assert!(draft.splice(0..1, "y"));
    }

    #[test]
    fn a_draft_grows_only_to_its_limit() {
        let mut draft = DraftText::new(&System).with_limit(4);
        assert!(draft.splice(0..0, "hut!"));
        assert!(!draft.splice(4..4, "!"));
        assert!(draft.splice(3..4, "s"));
        assert_eq!(draft.as_ref(), "huts");
        assert_eq!(
            DraftText::new(&System).with_limit(MESSAGE_LEN + 1).limit(),
            MESSAGE_LEN
        );
    }

    #[test]
    fn a_draft_over_a_lowered_limit_is_kept_to_be_shortened() {
        let mut draft = DraftText::new(&System);
        assert!(draft.splice(0..0, "the hut"));
        let mut draft = draft.with_limit(3);
        assert_eq!(draft.as_ref(), "the hut");
        assert!(!draft.splice(7..7, "!"));
        assert!(!draft.splice(0..1, "TT"), "a replacement may not grow it");
        assert!(draft.splice(0..1, "T"));
        assert!(draft.splice(0..4, ""));
        assert_eq!(draft.as_ref(), "hut");
        assert!(!draft.splice(3..3, "s"));
    }

    #[test]
    fn a_full_heap_leaves_the_draft_as_it_was() {
        let mut draft = DraftText::new(&Full);
        assert!(!draft.splice(0..0, "a"));
        assert_eq!(draft.as_ref(), "");
    }
}
