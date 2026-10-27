//! What a link to a device does: take a request, hand back its answer,
//! and pass on whatever the device publishes.
//!
//! The trait is synchronous and never waits. A link that is waiting on
//! something—a slot for the next request, a frame from the device—says
//! so by returning nothing, and its owner waits on whatever the link is
//! built from. That keeps the trait free of any executor, and lets one
//! model serve a device in process and a device across the mesh.

use umsh_ulcp::frame::{self, WriteError};

/// One request for a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// `CMD_PROP_GET`.
    Get(u32),
    /// `CMD_PROP_MULTI_GET`: several properties, answered in request
    /// order.
    MultiGet(&'a [u32]),
    /// `CMD_PROP_SET`.
    Set { key: u32, value: &'a [u8] },
    /// `CMD_PROP_MULTI_SET`: writes applied in order, stopping at the
    /// first that fails.
    MultiSet(&'a [(u32, &'a [u8])]),
    /// `CMD_PROP_INSERT`: one item, in the property's item form.
    Insert { key: u32, item: &'a [u8] },
    /// `CMD_PROP_REMOVE`: one item selector.
    Remove { key: u32, selector: &'a [u8] },
    /// `CMD_SAVE`.
    Save,
    /// `CMD_FACTORY_RESET`, which the device answers only by refusing: it
    /// erases everything and restarts, and the link drops.
    FactoryReset,
}

impl Request<'_> {
    /// Encode as one ULCP frame under `tid`, returning its length.
    pub fn encode(&self, tid: u8, out: &mut [u8]) -> Result<usize, WriteError> {
        match *self {
            Self::Get(key) => frame::prop_get(out, tid, key),
            Self::MultiGet(keys) => frame::prop_multi_get(out, tid, keys),
            Self::Set { key, value } => frame::prop_set(out, tid, key, value),
            Self::MultiSet(entries) => frame::prop_multi_set(out, tid, entries),
            Self::Insert { key, item } => frame::prop_insert(out, tid, key, item),
            Self::Remove { key, selector } => frame::prop_remove(out, tid, key, selector),
            Self::Save => frame::save(out, tid),
            Self::FactoryReset => frame::factory_reset(out, tid),
        }
    }
}

/// A link's name for a request it took, by which it reports the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ticket(pub u32);

/// Why a link did not take a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Busy {
    /// Not now: every slot is in use, or the device's queue is full. The
    /// request is worth offering again once something arrives.
    Full,
    /// Never: the request does not fit the link's frame.
    TooLarge,
}

/// What came back from the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrival<'b> {
    /// The answer to `ticket`: one ULCP frame, as the device emitted it.
    Answer { ticket: Ticket, frame: &'b [u8] },
    /// The link gave up on `ticket`, so whether a write it carried took
    /// effect is unknown. A local link never says this.
    Lost { ticket: Ticket },
    /// A frame the device published unasked.
    Publication { frame: &'b [u8] },
    /// The link dropped publications, so anything learned from them may
    /// be out of date.
    Overrun,
}

/// A link to one device.
pub trait Exchange {
    /// The largest answer this link hands back, which is the buffer
    /// [`Exchange::receive`] needs.
    const ANSWER_MAX: usize;

    /// Hand a request to the link.
    fn submit(&mut self, request: &Request<'_>) -> Result<Ticket, Busy>;

    /// The next thing to arrive, written into `out`.
    fn receive<'b>(&mut self, out: &'b mut [u8]) -> Option<Arrival<'b>>;
}
