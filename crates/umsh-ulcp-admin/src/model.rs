//! A cached model of one device's settings.
//!
//! The model is a reducer. Its owner makes requests—reads, writes,
//! saves—which wait in a queue, and calls [`Model::pump`] to hand them to
//! an [`Exchange`] and take in whatever has come back. Nothing it does
//! waits for an answer: a write stays pending until its answer arrives,
//! and the cache keeps showing what the device last reported until then.
//!
//! - **Reads** made one after another go out together, as one
//!   `CMD_PROP_MULTI_GET`. A device that runs out of room in its reply
//!   answers the first part, and the model asks for the rest.
//! - **Writes** go out in the order they were made, each as its own
//!   request. The answer is the value the device applied, a value it
//!   adjusted the write to, or the status it refused it with.
//! - **Publications** keep the cache current between reads. A device that
//!   resets, or a link that dropped publications, leaves every value
//!   stale, and the model reads them all again.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use umsh_ulcp::frame::{Cmd, Frame, MultiEntries, PropPayload};
use umsh_ulcp::ids::{cap, prop};
use umsh_ulcp::profiles::PhyProfile;
use umsh_ulcp::{Status, pui};

use crate::descriptor::{self, Access, COVERED, Descriptor, Kind, Value};
use crate::exchange::{Arrival, Busy, Exchange, Request, Ticket};

/// The most properties one `CMD_PROP_MULTI_GET` asks for.
pub const BUNDLE_MAX: usize = 32;

/// How far the cache can be trusted for one property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Never read.
    Unknown,
    /// As the device reported it at `at_ms`, with nothing since to say it
    /// moved.
    Fresh { at_ms: u64 },
    /// Reported once, but something since may have moved it: a reset, lost
    /// publications, or a write whose answer never came.
    Stale,
    /// The device refused to read it, with this status.
    Unavailable(Status),
}

/// Names one write: a call to a setter, [`Model::insert`],
/// [`Model::remove`], or [`Model::save`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WriteId(pub u32);

/// What became of one property's write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The device applied the value written.
    Applied,
    /// The device applied a value of its own choosing in its place, such
    /// as a transmit power clamped to what the radio can reach. The cache
    /// holds what it chose.
    Adjusted,
    /// The device refused the write.
    Refused(Status),
    /// An earlier write in the same sequence was refused, so this one was
    /// never attempted.
    Skipped,
    /// The link gave up, so whether the write took effect is unknown. The
    /// property is stale.
    Unknown,
    /// The link cannot carry a request this large.
    Unsent,
}

/// Something the owner may want to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The cached value of this property changed.
    Changed(u32),
    /// The device refused to read this property.
    Unavailable { key: u32, status: Status },
    /// A write finished.
    Written {
        id: WriteId,
        key: u32,
        outcome: WriteOutcome,
    },
    /// A `CMD_SAVE` finished.
    Saved {
        id: WriteId,
        result: Result<(), Status>,
    },
    /// The device reset, or publications were lost: every value is stale,
    /// and being read again.
    Resync,
}

/// Why a write was refused before it went anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The model does not cover this property.
    NotCovered,
    /// The property is not written this way: it is read-only, or it is a
    /// table, which changes an item at a time.
    WrongAccess,
    /// The device does not advertise the capability behind it.
    Unsupported,
    /// The value is longer than the property takes, or an item is not the
    /// property's item length.
    BadLength,
}

/// A property's place in the cache.
struct Entry {
    value: Option<Vec<u8>>,
    freshness: Freshness,
    /// A read of it is queued or in flight.
    reading: bool,
    /// Values written and not yet answered, oldest first.
    pending: Vec<(WriteId, Vec<u8>)>,
}

impl Entry {
    const fn new() -> Self {
        Self {
            value: None,
            freshness: Freshness::Unknown,
            reading: false,
            pending: Vec::new(),
        }
    }
}

/// A change waiting to go out, or out and waiting on its answer.
#[derive(Clone, Debug)]
enum Write {
    /// One `CMD_PROP_SET`, or a `CMD_PROP_MULTI_SET` of several in order.
    Set(Vec<(u32, Vec<u8>)>),
    Insert {
        key: u32,
        item: Vec<u8>,
    },
    Remove {
        key: u32,
        selector: Vec<u8>,
    },
    Save,
}

impl Write {
    /// The properties it writes, in order.
    fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        let (set, single) = match self {
            Self::Set(entries) => (Some(entries), None),
            Self::Insert { key, .. } | Self::Remove { key, .. } => (None, Some(*key)),
            Self::Save => (None, None),
        };
        set.into_iter().flatten().map(|(key, _)| *key).chain(single)
    }
}

enum Queued {
    /// A read. `solo` asks for it alone, for a value too large to share a
    /// reply with anything.
    Read {
        key: u32,
        solo: bool,
    },
    Write {
        id: WriteId,
        write: Write,
    },
}

enum Op {
    /// The properties a get or multi-get asked for, in request order.
    Read(Vec<u32>),
    Write {
        id: WriteId,
        write: Write,
    },
}

struct InFlight {
    ticket: Ticket,
    op: Op,
}

/// The cached settings of one device, and the traffic that keeps them.
pub struct Model {
    entries: BTreeMap<u32, Entry>,
    queue: VecDeque<Queued>,
    in_flight: Vec<InFlight>,
    events: VecDeque<Event>,
    next_write: u32,
    scratch: Vec<u8>,
    now_ms: u64,
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

impl Model {
    pub fn new() -> Self {
        Self {
            entries: COVERED
                .iter()
                .map(|descriptor| (descriptor.key, Entry::new()))
                .collect(),
            queue: VecDeque::new(),
            in_flight: Vec::new(),
            events: VecDeque::new(),
            next_write: 0,
            scratch: Vec::new(),
            now_ms: 0,
        }
    }

    // ─── Requests ────────────────────────────────────────────────────

    /// Read every covered property the device has, in one bundle: the
    /// cache's first fill, and how it recovers from anything that left it
    /// stale. A constant already read is not read again.
    pub fn refresh(&mut self) {
        let keys: Vec<u32> = COVERED
            .iter()
            .filter(|descriptor| self.supported(descriptor) != Some(false))
            .filter(|descriptor| !matches!(descriptor.access, Access::WriteOnly | Access::OnDemand))
            .filter(|descriptor| {
                descriptor.access != Access::Constant
                    || !matches!(self.freshness(descriptor.key), Freshness::Fresh { .. })
            })
            .map(|descriptor| descriptor.key)
            .collect();
        for key in keys {
            self.read(key);
        }
    }

    /// Read one property. A read of it already on its way is enough.
    pub fn read(&mut self, key: u32) {
        let Some(entry) = self.entries.get_mut(&key) else {
            return;
        };
        if !entry.reading {
            entry.reading = true;
            self.queue.push_back(Queued::Read { key, solo: false });
        }
    }

    /// Write one property.
    pub fn set(&mut self, key: u32, value: &[u8]) -> Result<WriteId, Refusal> {
        self.set_many(&[(key, value)])
    }

    /// Write several properties in order, as one request. The device stops
    /// at the first it refuses, and the rest are [`WriteOutcome::Skipped`].
    pub fn set_many(&mut self, entries: &[(u32, &[u8])]) -> Result<WriteId, Refusal> {
        for &(key, value) in entries {
            let descriptor = self.check(key)?;
            if !descriptor.writable() {
                return Err(Refusal::WrongAccess);
            }
            if value.len() > descriptor.max_len {
                return Err(Refusal::BadLength);
            }
        }
        let id = self.next_id();
        for &(key, value) in entries {
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.pending.push((id, value.to_vec()));
            }
        }
        let write = Write::Set(
            entries
                .iter()
                .map(|&(key, value)| (key, value.to_vec()))
                .collect(),
        );
        self.queue.push_back(Queued::Write { id, write });
        Ok(id)
    }

    /// Add an item, in its item form, to a table.
    pub fn insert(&mut self, key: u32, item: &[u8]) -> Result<WriteId, Refusal> {
        self.check_item(key, item)?;
        let id = self.next_id();
        let write = Write::Insert {
            key,
            item: item.to_vec(),
        };
        self.queue.push_back(Queued::Write { id, write });
        Ok(id)
    }

    /// Remove the item `selector` names from a table.
    pub fn remove(&mut self, key: u32, selector: &[u8]) -> Result<WriteId, Refusal> {
        self.check_item(key, selector)?;
        let id = self.next_id();
        let write = Write::Remove {
            key,
            selector: selector.to_vec(),
        };
        self.queue.push_back(Queued::Write { id, write });
        Ok(id)
    }

    /// Save the device's configuration, `CMD_SAVE`.
    pub fn save(&mut self) -> Result<WriteId, Refusal> {
        if self.has_cap(cap::SAVE) == Some(false) {
            return Err(Refusal::Unsupported);
        }
        let id = self.next_id();
        self.queue.push_back(Queued::Write {
            id,
            write: Write::Save,
        });
        Ok(id)
    }

    fn next_id(&mut self) -> WriteId {
        let id = WriteId(self.next_write);
        self.next_write = self.next_write.wrapping_add(1);
        id
    }

    fn check(&self, key: u32) -> Result<&'static Descriptor, Refusal> {
        let descriptor = descriptor::descriptor(key).ok_or(Refusal::NotCovered)?;
        if self.supported(descriptor) == Some(false) {
            return Err(Refusal::Unsupported);
        }
        Ok(descriptor)
    }

    fn check_item(&self, key: u32, item: &[u8]) -> Result<(), Refusal> {
        let descriptor = self.check(key)?;
        let Kind::Items { item_len, .. } = descriptor.kind else {
            return Err(Refusal::WrongAccess);
        };
        if item.len() != usize::from(item_len) {
            return Err(Refusal::BadLength);
        }
        Ok(())
    }

    // ─── Traffic ─────────────────────────────────────────────────────

    /// Take in everything the link has delivered, and hand it every
    /// request it will take, until neither moves. `now_ms` dates what is
    /// read.
    pub fn pump<E: Exchange>(&mut self, exchange: &mut E, now_ms: u64) {
        self.now_ms = now_ms;
        let mut scratch = core::mem::take(&mut self.scratch);
        if scratch.len() < E::ANSWER_MAX {
            scratch.resize(E::ANSWER_MAX, 0);
        }
        loop {
            let mut moved = false;
            while let Some(arrival) = exchange.receive(&mut scratch) {
                self.arrive(arrival);
                moved = true;
            }
            moved |= self.submit(exchange);
            if !moved {
                break;
            }
        }
        self.scratch = scratch;
    }

    /// The next thing that happened.
    pub fn next_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Whether anything is queued or waiting on an answer.
    pub fn busy(&self) -> bool {
        !self.queue.is_empty() || !self.in_flight.is_empty()
    }

    /// Requests the link has taken and not answered.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Hand the link what it will take, front of the queue first. Returns
    /// whether anything went.
    fn submit<E: Exchange>(&mut self, exchange: &mut E) -> bool {
        let mut moved = false;
        while let Some(front) = self.queue.front() {
            let (op, taken) = match front {
                Queued::Write { id, write } => {
                    let id = *id;
                    match submit_write(exchange, write) {
                        Ok(ticket) => {
                            let Some(Queued::Write { write, .. }) = self.queue.pop_front() else {
                                unreachable!();
                            };
                            (Op::Write { id, write }, ticket)
                        }
                        Err(Busy::Full) => break,
                        Err(Busy::TooLarge) => {
                            let Some(Queued::Write { write, .. }) = self.queue.pop_front() else {
                                unreachable!();
                            };
                            self.finish_write(id, &write, WriteOutcome::Unsent);
                            continue;
                        }
                    }
                }
                Queued::Read { .. } => {
                    let keys = self.bundle();
                    let request = match keys.as_slice() {
                        [key] => Request::Get(*key),
                        keys => Request::MultiGet(keys),
                    };
                    match exchange.submit(&request) {
                        Ok(ticket) => {
                            self.queue.drain(..keys.len());
                            (Op::Read(keys), ticket)
                        }
                        Err(Busy::Full) => break,
                        Err(Busy::TooLarge) => {
                            // Nothing this model reads is too large to ask
                            // for, so this is a link with no room at all.
                            self.queue.drain(..keys.len());
                            for key in keys {
                                self.end_read(key);
                            }
                            continue;
                        }
                    }
                }
            };
            self.in_flight.push(InFlight { ticket: taken, op });
            moved = true;
        }
        moved
    }

    /// The reads at the front of the queue that go out together.
    fn bundle(&self) -> Vec<u32> {
        let mut keys = Vec::new();
        for queued in &self.queue {
            match *queued {
                Queued::Read { key, solo } => {
                    if solo && !keys.is_empty() {
                        break;
                    }
                    keys.push(key);
                    if solo || keys.len() == BUNDLE_MAX {
                        break;
                    }
                }
                Queued::Write { .. } => break,
            }
        }
        keys
    }

    fn arrive(&mut self, arrival: Arrival<'_>) {
        match arrival {
            Arrival::Answer { ticket, frame } => {
                let Some(index) = self.in_flight.iter().position(|f| f.ticket == ticket) else {
                    return;
                };
                match self.in_flight.swap_remove(index).op {
                    Op::Read(keys) => self.answer_read(&keys, frame),
                    Op::Write { id, write } => self.answer_write(id, write, frame),
                }
            }
            Arrival::Lost { ticket } => {
                let Some(index) = self.in_flight.iter().position(|f| f.ticket == ticket) else {
                    return;
                };
                match self.in_flight.swap_remove(index).op {
                    Op::Read(keys) => {
                        for key in keys {
                            self.end_read(key);
                        }
                    }
                    Op::Write { id, write } => {
                        for key in write.keys() {
                            self.mark_stale(key);
                        }
                        self.finish_write(id, &write, WriteOutcome::Unknown);
                    }
                }
            }
            Arrival::Publication { frame } => self.publication(frame),
            Arrival::Overrun => self.resync(),
        }
    }

    fn answer_read(&mut self, keys: &[u32], frame: &[u8]) {
        let Ok(parsed) = Frame::parse(frame) else {
            for &key in keys {
                self.end_read(key);
            }
            return;
        };
        match parsed.command() {
            Some(Cmd::PropAre) => {
                let mut answered = 0;
                for (entry, &key) in MultiEntries::new(parsed.payload).zip(keys) {
                    let Ok(entry) = entry else {
                        break;
                    };
                    answered += 1;
                    self.end_read(key);
                    self.read_answer(key, entry.key, entry.value);
                }
                // The reply ran out of room. Ask for the rest, and for a
                // value that fit nothing, ask for it alone.
                for (position, &key) in keys.iter().enumerate().skip(answered) {
                    let solo = answered == 0 && position == 0;
                    self.queue.push_front(Queued::Read { key, solo });
                }
                if answered < keys.len() {
                    let requeued = keys.len() - answered;
                    self.queue.make_contiguous()[..requeued].reverse();
                }
            }
            Some(Cmd::PropIs) => match PropPayload::parse(parsed.payload) {
                // One answer, for one property or for the whole command.
                Ok(payload) if keys.len() == 1 || payload.key == prop::LAST_STATUS => {
                    for &key in keys {
                        self.end_read(key);
                        self.read_answer(key, payload.key, payload.value);
                    }
                }
                _ => {
                    for &key in keys {
                        self.end_read(key);
                    }
                }
            },
            _ => {
                for &key in keys {
                    self.end_read(key);
                }
            }
        }
    }

    /// One property's place in a read's answer.
    fn read_answer(&mut self, key: u32, answered: u32, value: &[u8]) {
        if answered == key {
            self.store(key, value);
        } else if answered == prop::LAST_STATUS {
            let status = status_of(value);
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.freshness = Freshness::Unavailable(status);
            }
            self.events.push_back(Event::Unavailable { key, status });
        }
    }

    fn answer_write(&mut self, id: WriteId, write: Write, frame: &[u8]) {
        let parsed = Frame::parse(frame).ok();
        let command = parsed.as_ref().and_then(Frame::command);
        let payload = parsed.as_ref().map_or(&[][..], |parsed| parsed.payload);
        match &write {
            Write::Set(entries) if entries.len() == 1 && command != Some(Cmd::PropAre) => {
                let (key, written) = &entries[0];
                let outcome = match PropPayload::parse(payload) {
                    Ok(answer) if command == Some(Cmd::PropIs) && answer.key == *key => {
                        self.store(*key, answer.value);
                        adjusted(written, answer.value)
                    }
                    Ok(answer) if answer.key == prop::LAST_STATUS => {
                        self.refused(*key, answer.value)
                    }
                    _ => self.unknown(*key),
                };
                self.finish_one(id, *key, outcome);
            }
            Write::Set(entries) => {
                let mut answers = MultiEntries::new(payload);
                let lone_status = (command == Some(Cmd::PropIs))
                    .then(|| PropPayload::parse(payload).ok())
                    .flatten();
                let mut failed = false;
                let mut answered = 0;
                let mut remainder = Vec::new();
                for (key, written) in entries {
                    let outcome = if failed {
                        WriteOutcome::Skipped
                    } else if let Some(answer) = lone_status {
                        // One status for the whole command: nothing in it
                        // was applied.
                        failed = true;
                        match status_of(answer.value) {
                            status if answer.key == prop::LAST_STATUS && status != Status::OK => {
                                WriteOutcome::Refused(status)
                            }
                            _ => self.unknown(*key),
                        }
                    } else {
                        match answers.next() {
                            Some(Ok(answer)) if answer.key == *key => {
                                answered += 1;
                                self.store(*key, answer.value);
                                adjusted(written, answer.value)
                            }
                            Some(Ok(answer)) if answer.key == prop::LAST_STATUS => {
                                answered += 1;
                                let outcome = self.refused(*key, answer.value);
                                // The device stops at the first failure.
                                failed = matches!(outcome, WriteOutcome::Refused(_));
                                outcome
                            }
                            // The reply ran out of room, and the device
                            // stopped rather than apply a write it could
                            // not report: the rest goes out again.
                            None if command == Some(Cmd::PropAre) => {
                                remainder.push((*key, written.clone()));
                                continue;
                            }
                            _ => {
                                failed = true;
                                self.unknown(*key)
                            }
                        }
                    };
                    self.finish_one(id, *key, outcome);
                }
                if !remainder.is_empty() {
                    if answered == 0 {
                        // Not even the first fit: it never will.
                        for (key, _) in remainder {
                            self.finish_one(id, key, WriteOutcome::Unsent);
                        }
                    } else {
                        self.queue.push_front(Queued::Write {
                            id,
                            write: Write::Set(remainder),
                        });
                    }
                }
            }
            Write::Insert { key, .. } | Write::Remove { key, .. } => {
                let inserting = matches!(write, Write::Insert { .. });
                let expected = if inserting {
                    Cmd::PropInserted
                } else {
                    Cmd::PropRemoved
                };
                let outcome = match PropPayload::parse(payload) {
                    Ok(answer) if command == Some(expected) && answer.key == *key => {
                        self.table_change(*key, answer.value, inserting);
                        WriteOutcome::Applied
                    }
                    Ok(answer) if answer.key == prop::LAST_STATUS => {
                        WriteOutcome::Refused(status_of(answer.value))
                    }
                    _ => {
                        self.mark_stale(*key);
                        WriteOutcome::Unknown
                    }
                };
                self.finish_write(id, &write, outcome);
            }
            Write::Save => {
                let result = match PropPayload::parse(payload) {
                    Ok(answer) if answer.key == prop::LAST_STATUS => {
                        match status_of(answer.value) {
                            Status::OK => Ok(()),
                            status => Err(status),
                        }
                    }
                    _ => Err(Status::FAILURE),
                };
                if result.is_ok() {
                    self.read(prop::SAVED);
                }
                self.events.push_back(Event::Saved { id, result });
            }
        }
    }

    /// A write's answer was a status: the cache stays as it was.
    fn refused(&mut self, key: u32, status: &[u8]) -> WriteOutcome {
        match status_of(status) {
            // Success without the value it set: the value is unknown.
            Status::OK => self.unknown(key),
            status => WriteOutcome::Refused(status),
        }
    }

    /// A write's answer did not say what the property became.
    fn unknown(&mut self, key: u32) -> WriteOutcome {
        self.mark_stale(key);
        self.read(key);
        WriteOutcome::Unknown
    }

    fn finish_one(&mut self, id: WriteId, key: u32, outcome: WriteOutcome) {
        if let Some(entry) = self.entries.get_mut(&key)
            && let Some(position) = entry.pending.iter().position(|(pending, _)| *pending == id)
        {
            entry.pending.remove(position);
        }
        self.events.push_back(Event::Written { id, key, outcome });
    }

    fn finish_write(&mut self, id: WriteId, write: &Write, outcome: WriteOutcome) {
        if let Write::Save = write {
            let result = match outcome {
                WriteOutcome::Refused(status) => Err(status),
                _ => Err(Status::FAILURE),
            };
            self.events.push_back(Event::Saved { id, result });
            return;
        }
        let keys: Vec<u32> = write.keys().collect();
        for key in keys {
            self.finish_one(id, key, outcome);
        }
    }

    fn publication(&mut self, frame: &[u8]) {
        let Ok(parsed) = Frame::parse(frame) else {
            return;
        };
        let Ok(payload) = PropPayload::parse(parsed.payload) else {
            return;
        };
        match parsed.command() {
            Some(Cmd::PropIs) if payload.key == prop::LAST_STATUS => {
                if status_of(payload.value).is_reset() {
                    self.resync();
                }
            }
            Some(Cmd::PropIs) => {
                if self.entries.contains_key(&payload.key) {
                    self.store(payload.key, payload.value);
                }
            }
            Some(Cmd::PropInserted) => self.table_change(payload.key, payload.value, true),
            Some(Cmd::PropRemoved) => self.table_change(payload.key, payload.value, false),
            _ => {}
        }
    }

    /// Everything is stale: read it all again.
    fn resync(&mut self) {
        for entry in self.entries.values_mut() {
            if let Freshness::Fresh { .. } = entry.freshness {
                entry.freshness = Freshness::Stale;
            }
        }
        // A constant does not change across a reset, so it is not read
        // again: what was fresh stays fresh.
        if let Some(caps) = self.entries.get_mut(&prop::CAPS)
            && caps.value.is_some()
        {
            caps.freshness = Freshness::Fresh { at_ms: self.now_ms };
        }
        self.events.push_back(Event::Resync);
        self.refresh();
    }

    /// The device reported `value` for `key`.
    fn store(&mut self, key: u32, value: &[u8]) {
        let Some(entry) = self.entries.get_mut(&key) else {
            return;
        };
        entry.freshness = Freshness::Fresh { at_ms: self.now_ms };
        if entry.value.as_deref() != Some(value) {
            entry.value = Some(value.to_vec());
            self.events.push_back(Event::Changed(key));
        }
    }

    /// An item, in reported form, joined or left a table.
    fn table_change(&mut self, key: u32, item: &[u8], inserted: bool) {
        let Some(Kind::Items { reported_len, .. }) = descriptor::descriptor(key).map(|d| d.kind)
        else {
            return;
        };
        let reported_len = usize::from(reported_len);
        let Some(entry) = self.entries.get_mut(&key) else {
            return;
        };
        if item.len() != reported_len {
            entry.freshness = Freshness::Stale;
            self.read(key);
            return;
        }
        // A table never read is not known whole, so one item says little.
        let Some(value) = entry.value.as_mut() else {
            self.read(key);
            return;
        };
        let position = value
            .chunks_exact(reported_len)
            .position(|existing| existing == item);
        let changed = match (position, inserted) {
            (None, true) => {
                value.extend_from_slice(item);
                true
            }
            (Some(index), false) => {
                value.drain(index * reported_len..(index + 1) * reported_len);
                true
            }
            _ => false,
        };
        if changed {
            self.events.push_back(Event::Changed(key));
        }
    }

    fn end_read(&mut self, key: u32) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.reading = false;
        }
    }

    fn mark_stale(&mut self, key: u32) {
        if let Some(entry) = self.entries.get_mut(&key)
            && entry.value.is_some()
        {
            entry.freshness = Freshness::Stale;
        }
    }

    // ─── The cache ───────────────────────────────────────────────────

    /// What the device last reported for `key`, as it reported it.
    pub fn raw(&self, key: u32) -> Option<&[u8]> {
        self.entries.get(&key)?.value.as_deref()
    }

    /// What the device last reported for `key`, through its codec.
    pub fn value(&self, key: u32) -> Option<Value<'_>> {
        descriptor::decode(descriptor::descriptor(key)?.codec, self.raw(key)?)
    }

    pub fn freshness(&self, key: u32) -> Freshness {
        self.entries
            .get(&key)
            .map_or(Freshness::Unknown, |entry| entry.freshness)
    }

    /// The newest value written to `key` and not yet answered.
    pub fn pending(&self, key: u32) -> Option<&[u8]> {
        let entry = self.entries.get(&key)?;
        entry.pending.last().map(|(_, value)| value.as_slice())
    }

    /// What `key` holds once its writes are answered as asked: the newest
    /// value written and not yet answered, or else what the device last
    /// reported. An interface shows this, so a change shows as it is made.
    pub fn intended(&self, key: u32) -> Option<Value<'_>> {
        let raw = self.pending(key).or_else(|| self.raw(key))?;
        descriptor::decode(descriptor::descriptor(key)?.codec, raw)
    }

    /// The device's capabilities, once read.
    pub fn caps(&self) -> Option<impl Iterator<Item = u32> + '_> {
        let mut rest = self.raw(prop::CAPS)?;
        Some(core::iter::from_fn(move || {
            let (code, consumed) = pui::decode(rest).ok()?;
            rest = &rest[consumed..];
            Some(code)
        }))
    }

    /// Whether the device advertises `capability`, once its capabilities
    /// have been read.
    pub fn has_cap(&self, capability: u32) -> Option<bool> {
        Some(self.caps()?.any(|code| code == capability))
    }

    /// Whether the device has the property `descriptor` describes, once
    /// its capabilities have been read.
    fn supported(&self, descriptor: &Descriptor) -> Option<bool> {
        match descriptor.gate {
            None => Some(true),
            Some(gate) => self.has_cap(gate),
        }
    }

    /// The items of a table, in reported form.
    pub fn items(&self, key: u32) -> Option<core::slice::ChunksExact<'_, u8>> {
        let Kind::Items { reported_len, .. } = descriptor::descriptor(key)?.kind else {
            return None;
        };
        Some(self.raw(key)?.chunks_exact(usize::from(reported_len)))
    }

    // ─── The covered settings, by name ───────────────────────────────

    /// `PROP_DEV_NAME`.
    pub fn device_name(&self) -> Option<&str> {
        match self.value(prop::DEV_NAME)? {
            Value::Text(name) => Some(name),
            _ => None,
        }
    }

    pub fn set_device_name(&mut self, name: &str) -> Result<WriteId, Refusal> {
        self.set(prop::DEV_NAME, name.as_bytes())
    }

    /// `PROP_DEV_KEY`: the device identity.
    pub fn device_key(&self) -> Option<&[u8; 32]> {
        match self.value(prop::DEV_KEY)? {
            Value::Key32(key) => Some(key),
            _ => None,
        }
    }

    /// `PROP_SAVED`, one of [`umsh_ulcp::ids::saved`].
    pub fn saved(&self) -> Option<u8> {
        self.u8(prop::SAVED)
    }

    /// The live radio profile parameters.
    pub fn radio(&self) -> Option<Radio> {
        Some(Radio {
            freq_khz: self.u32(prop::PHY_FREQ)?,
            bw_hz: self.u32(prop::PHY_LORA_BW)?,
            sf: self.u8(prop::PHY_LORA_SF)?,
            cr_denom: self.u8(prop::PHY_LORA_CR)?,
        })
    }

    /// Adopt a vetted profile: its four parameters, and the transmit power
    /// and duty limit vetted with it, in one request.
    pub fn set_profile(&mut self, profile: &PhyProfile) -> Result<WriteId, Refusal> {
        let freq = profile.freq_khz.to_le_bytes();
        let bw = profile.bw_hz.to_le_bytes();
        let sf = [profile.sf];
        let cr = [profile.cr_denom];
        let power = profile.tx_power_dbm.map(|dbm| dbm.to_le_bytes());
        let duty = profile.duty_limit.to_le_bytes();
        let mut entries: Vec<(u32, &[u8])> = Vec::from([
            (prop::PHY_FREQ, &freq[..]),
            (prop::PHY_LORA_BW, &bw[..]),
            (prop::PHY_LORA_SF, &sf[..]),
            (prop::PHY_LORA_CR, &cr[..]),
        ]);
        if let Some(power) = &power {
            entries.push((prop::PHY_TX_POWER, &power[..]));
        }
        if self.has_cap(cap::PHY_DUTY_LIMIT) != Some(false) {
            entries.push((prop::PHY_DUTY_LIMIT, &duty[..]));
        }
        self.set_many(&entries)
    }

    /// `PROP_PHY_TX_POWER`, in dBm.
    pub fn tx_power_dbm(&self) -> Option<i8> {
        match self.value(prop::PHY_TX_POWER)? {
            Value::I8(dbm) => Some(dbm),
            _ => None,
        }
    }

    pub fn set_tx_power_dbm(&mut self, dbm: i8) -> Result<WriteId, Refusal> {
        self.set(prop::PHY_TX_POWER, &dbm.to_le_bytes())
    }

    /// `PROP_PHY_DUTY_NOW`.
    pub fn duty_now(&self) -> Option<u16> {
        self.u16(prop::PHY_DUTY_NOW)
    }

    /// `PROP_PHY_DUTY_LIMIT`.
    pub fn duty_limit(&self) -> Option<u16> {
        self.u16(prop::PHY_DUTY_LIMIT)
    }

    pub fn set_duty_limit(&mut self, limit: u16) -> Result<WriteId, Refusal> {
        self.set(prop::PHY_DUTY_LIMIT, &limit.to_le_bytes())
    }

    /// `PROP_PHY_ENABLED`: whether the radio is on.
    pub fn radio_enabled(&self) -> Option<bool> {
        self.bool(prop::PHY_ENABLED)
    }

    pub fn set_radio_enabled(&mut self, enabled: bool) -> Result<WriteId, Refusal> {
        self.set(prop::PHY_ENABLED, &[u8::from(enabled)])
    }

    /// `PROP_BLE_ENABLED`: whether Bluetooth is on.
    pub fn bluetooth_enabled(&self) -> Option<bool> {
        self.bool(prop::BLE_ENABLED)
    }

    pub fn set_bluetooth_enabled(&mut self, enabled: bool) -> Result<WriteId, Refusal> {
        self.set(prop::BLE_ENABLED, &[u8::from(enabled)])
    }

    /// `PROP_BLE_PAIRING`: opens the pairing window, or closes it.
    pub fn set_pairing(&mut self, open: bool) -> Result<WriteId, Refusal> {
        self.set(prop::BLE_PAIRING, &[u8::from(open)])
    }

    /// `PROP_BLE_BOND_COUNT` set to zero: forgets every paired phone.
    pub fn clear_pairings(&mut self) -> Result<WriteId, Refusal> {
        self.set(prop::BLE_BOND_COUNT, &[0])
    }

    /// `PROP_GNSS_ENABLED`: whether the receiver is on.
    pub fn gnss_enabled(&self) -> Option<bool> {
        self.bool(prop::GNSS_ENABLED)
    }

    pub fn set_gnss_enabled(&mut self, enabled: bool) -> Result<WriteId, Refusal> {
        self.set(prop::GNSS_ENABLED, &[u8::from(enabled)])
    }

    /// `PROP_MAC_REPEATER_ENABLED`: forwarding.
    pub fn forwarding(&self) -> Option<bool> {
        self.bool(prop::MAC_REPEATER_ENABLED)
    }

    pub fn set_forwarding(&mut self, enabled: bool) -> Result<WriteId, Refusal> {
        self.set(prop::MAC_REPEATER_ENABLED, &[u8::from(enabled)])
    }

    /// `PROP_GNSS_IDENT_UPDATE`: location sharing.
    pub fn share_location(&self) -> Option<bool> {
        self.bool(prop::GNSS_IDENT_UPDATE)
    }

    pub fn set_share_location(&mut self, enabled: bool) -> Result<WriteId, Refusal> {
        self.set(prop::GNSS_IDENT_UPDATE, &[u8::from(enabled)])
    }

    /// Sets the clock, or with `None` returns the device to not knowing
    /// what time it is.
    pub fn set_time(&mut self, time: Option<u32>) -> Result<WriteId, Refusal> {
        match time {
            Some(time) => self.set(prop::TIME, &time.to_le_bytes()),
            None => self.set(prop::TIME, &[]),
        }
    }

    /// `PROP_TZ_RULE`: the zone, as a POSIX TZ rule.
    pub fn tz_rule(&self) -> Option<&str> {
        match self.value(prop::TZ_RULE)? {
            Value::Text(rule) => Some(rule),
            _ => None,
        }
    }

    pub fn set_tz_rule(&mut self, rule: &str) -> Result<WriteId, Refusal> {
        self.set(prop::TZ_RULE, rule.as_bytes())
    }

    /// `PROP_TIME_24H`.
    pub fn time_24h(&self) -> Option<bool> {
        self.bool(prop::TIME_24H)
    }

    pub fn set_time_24h(&mut self, on: bool) -> Result<WriteId, Refusal> {
        self.set(prop::TIME_24H, &[u8::from(on)])
    }

    /// `PROP_GNSS_TIME_TRUST`: whether the receiver sets the clock.
    pub fn gnss_time_trust(&self) -> Option<bool> {
        self.bool(prop::GNSS_TIME_TRUST)
    }

    pub fn set_gnss_time_trust(&mut self, trusted: bool) -> Result<WriteId, Refusal> {
        self.set(prop::GNSS_TIME_TRUST, &[u8::from(trusted)])
    }

    /// `PROP_DISPLAY_BRIGHTNESS`, from 0 (the dimmest that is not off) to
    /// 255.
    pub fn brightness(&self) -> Option<u8> {
        self.u8(prop::DISPLAY_BRIGHTNESS)
    }

    pub fn set_brightness(&mut self, brightness: u8) -> Result<WriteId, Refusal> {
        self.set(prop::DISPLAY_BRIGHTNESS, &[brightness])
    }

    /// `PROP_DISPLAY_TIMEOUT`, in seconds, 0 for never.
    pub fn display_timeout(&self) -> Option<u16> {
        self.u16(prop::DISPLAY_TIMEOUT)
    }

    pub fn set_display_timeout(&mut self, seconds: u16) -> Result<WriteId, Refusal> {
        self.set(prop::DISPLAY_TIMEOUT, &seconds.to_le_bytes())
    }

    /// `PROP_KEYBOARD_LIGHT`.
    pub fn keyboard_light(&self) -> Option<bool> {
        self.bool(prop::KEYBOARD_LIGHT)
    }

    pub fn set_keyboard_light(&mut self, lit: bool) -> Result<WriteId, Refusal> {
        self.set(prop::KEYBOARD_LIGHT, &[u8::from(lit)])
    }

    /// `PROP_KEYBOARD_AIDS`, as [`umsh_ulcp::ids::keyboard_aids`] flags.
    pub fn keyboard_aids(&self) -> Option<u8> {
        self.u8(prop::KEYBOARD_AIDS)
    }

    pub fn set_keyboard_aids(&mut self, aids: u8) -> Result<WriteId, Refusal> {
        self.set(prop::KEYBOARD_AIDS, &[aids])
    }

    /// `PROP_DEV_PEERS`: the device identity's saved peers.
    pub fn peers(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.items(prop::DEV_PEERS)
            .into_iter()
            .flatten()
            .filter_map(|item| item.try_into().ok())
    }

    pub fn save_peer(&mut self, key: &[u8; 32]) -> Result<WriteId, Refusal> {
        self.insert(prop::DEV_PEERS, key)
    }

    pub fn forget_peer(&mut self, key: &[u8; 32]) -> Result<WriteId, Refusal> {
        self.remove(prop::DEV_PEERS, key)
    }

    /// `PROP_DEV_CHANNEL_KEYS`, as the device reports it: each channel's
    /// 16-octet identifier, never its key.
    pub fn channels(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.items(prop::DEV_CHANNEL_KEYS)
            .into_iter()
            .flatten()
            .filter_map(|item| item.try_into().ok())
    }

    pub fn join_channel(&mut self, key: &[u8; 32]) -> Result<WriteId, Refusal> {
        self.insert(prop::DEV_CHANNEL_KEYS, key)
    }

    pub fn leave_channel(&mut self, key: &[u8; 32]) -> Result<WriteId, Refusal> {
        self.remove(prop::DEV_CHANNEL_KEYS, key)
    }

    fn bool(&self, key: u32) -> Option<bool> {
        match self.value(key)? {
            Value::Bool(value) => Some(value),
            _ => None,
        }
    }

    fn u8(&self, key: u32) -> Option<u8> {
        match self.value(key)? {
            Value::U8(value) => Some(value),
            _ => None,
        }
    }

    fn u16(&self, key: u32) -> Option<u16> {
        match self.value(key)? {
            Value::U16(value) => Some(value),
            _ => None,
        }
    }

    fn u32(&self, key: u32) -> Option<u32> {
        match self.value(key)? {
            Value::U32(value) => Some(value),
            _ => None,
        }
    }
}

/// The four parameters two radios must agree on to hear each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Radio {
    pub freq_khz: u32,
    pub bw_hz: u32,
    pub sf: u8,
    pub cr_denom: u8,
}

impl Radio {
    /// The vetted profile these parameters are, or `None` for a custom
    /// configuration.
    pub fn profile(&self) -> Option<&'static PhyProfile> {
        umsh_ulcp::profiles::matching(self.freq_khz, self.bw_hz, self.sf, self.cr_denom)
    }
}

fn submit_write<E: Exchange>(exchange: &mut E, write: &Write) -> Result<Ticket, Busy> {
    match write {
        Write::Set(entries) if entries.len() == 1 => exchange.submit(&Request::Set {
            key: entries[0].0,
            value: &entries[0].1,
        }),
        Write::Set(entries) => {
            let entries: Vec<(u32, &[u8])> = entries
                .iter()
                .map(|(key, value)| (*key, value.as_slice()))
                .collect();
            exchange.submit(&Request::MultiSet(&entries))
        }
        Write::Insert { key, item } => exchange.submit(&Request::Insert { key: *key, item }),
        Write::Remove { key, selector } => exchange.submit(&Request::Remove {
            key: *key,
            selector,
        }),
        Write::Save => exchange.submit(&Request::Save),
    }
}

/// Whether the device applied what was written or something of its own.
fn adjusted(written: &[u8], reported: &[u8]) -> WriteOutcome {
    if written == reported {
        WriteOutcome::Applied
    } else {
        WriteOutcome::Adjusted
    }
}

fn status_of(value: &[u8]) -> Status {
    pui::decode(value).map_or(Status::FAILURE, |(code, _)| Status(code))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::vec::Vec;

    use umsh_ulcp::frame::{self, MultiGetKeys};

    use super::*;

    /// A link the test answers by hand.
    #[derive(Default)]
    struct Script {
        /// Every request taken, as encoded, with its ticket.
        sent: Vec<(Ticket, Vec<u8>)>,
        arrivals: VecDeque<(Option<Ticket>, Option<Vec<u8>>)>,
        next: u32,
    }

    impl Script {
        fn answer(&mut self, ticket: Ticket, frame: Vec<u8>) {
            self.arrivals.push_back((Some(ticket), Some(frame)));
        }

        fn publish(&mut self, frame: Vec<u8>) {
            self.arrivals.push_back((None, Some(frame)));
        }

        fn last(&self) -> (Ticket, Frame<'_>) {
            let (ticket, frame) = self.sent.last().unwrap();
            (*ticket, Frame::parse(frame).unwrap())
        }

        fn asked(&self) -> (Ticket, Vec<u32>) {
            let (ticket, request) = self.last();
            let keys = match request.command() {
                Some(Cmd::PropGet) => Vec::from([pui::decode(request.payload).unwrap().0]),
                _ => MultiGetKeys::new(request.payload)
                    .map(Result::unwrap)
                    .collect(),
            };
            (ticket, keys)
        }
    }

    impl Exchange for Script {
        const ANSWER_MAX: usize = 300;

        fn submit(&mut self, request: &Request<'_>) -> Result<Ticket, Busy> {
            let mut frame = [0u8; 300];
            let len = request.encode(1, &mut frame).map_err(|_| Busy::TooLarge)?;
            let ticket = Ticket(self.next);
            self.next += 1;
            self.sent.push((ticket, frame[..len].to_vec()));
            Ok(ticket)
        }

        fn receive<'b>(&mut self, out: &'b mut [u8]) -> Option<Arrival<'b>> {
            let (ticket, frame) = self.arrivals.pop_front()?;
            let Some(frame) = frame else {
                return Some(Arrival::Overrun);
            };
            out[..frame.len()].copy_from_slice(&frame);
            let frame = &out[..frame.len()];
            Some(match ticket {
                Some(ticket) => Arrival::Answer { ticket, frame },
                None => Arrival::Publication { frame },
            })
        }
    }

    fn prop_is(key: u32, value: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 300];
        let len = frame::prop_is(&mut buf, 0, key, value).unwrap();
        buf[..len].to_vec()
    }

    fn status(status: Status) -> Vec<u8> {
        let mut buf = [0u8; 16];
        let len = frame::last_status(&mut buf, 0, status).unwrap();
        buf[..len].to_vec()
    }

    fn are(entries: &[(u32, &[u8])]) -> Vec<u8> {
        let mut buf = [0u8; 300];
        let mut writer = frame::prop_are(&mut buf, 1).unwrap();
        for &(key, value) in entries {
            writer.write_entry(key, value).unwrap();
        }
        let len = writer.finish();
        buf[..len].to_vec()
    }

    fn events(model: &mut Model) -> Vec<Event> {
        core::iter::from_fn(|| model.next_event()).collect()
    }

    /// A model that has read the device's capabilities, and nothing else.
    fn with_caps(caps: &[u32]) -> (Model, Script) {
        let mut model = Model::new();
        let mut script = Script::default();
        model.read(prop::CAPS);
        model.pump(&mut script, 0);
        let mut value = [0u8; 64];
        let mut len = 0;
        for &code in caps {
            len += pui::encode(code, &mut value[len..]).unwrap();
        }
        let (ticket, _) = script.last();
        script.answer(ticket, prop_is(prop::CAPS, &value[..len]));
        model.pump(&mut script, 0);
        events(&mut model);
        (model, script)
    }

    #[test]
    fn a_reply_out_of_room_is_finished_by_asking_for_the_rest() {
        let (mut model, mut script) = with_caps(&[cap::PHY_LORA]);
        for key in [prop::PHY_FREQ, prop::PHY_LORA_BW, prop::PHY_LORA_SF] {
            model.read(key);
        }
        model.pump(&mut script, 10);
        let (ticket, asked) = script.asked();
        assert_eq!(
            asked,
            [prop::PHY_FREQ, prop::PHY_LORA_BW, prop::PHY_LORA_SF]
        );

        // Room for the first only.
        script.answer(ticket, are(&[(prop::PHY_FREQ, &910_525u32.to_le_bytes())]));
        model.pump(&mut script, 20);
        assert_eq!(model.u32(prop::PHY_FREQ), Some(910_525));
        let (ticket, asked) = script.asked();
        assert_eq!(asked, [prop::PHY_LORA_BW, prop::PHY_LORA_SF]);

        // Room for nothing: the first is asked for alone, and the rest
        // after it.
        script.answer(ticket, are(&[]));
        let sent = script.sent.len();
        model.pump(&mut script, 30);
        let requests: Vec<(Ticket, Vec<u8>)> = script.sent[sent..].to_vec();
        let gets: Vec<(Option<Cmd>, u32)> = requests
            .iter()
            .map(|(_, frame)| {
                let request = Frame::parse(frame).unwrap();
                (request.command(), pui::decode(request.payload).unwrap().0)
            })
            .collect();
        assert_eq!(
            gets,
            [
                (Some(Cmd::PropGet), prop::PHY_LORA_BW),
                (Some(Cmd::PropGet), prop::PHY_LORA_SF)
            ]
        );
        script.answer(
            requests[0].0,
            prop_is(prop::PHY_LORA_BW, &62_500u32.to_le_bytes()),
        );
        script.answer(requests[1].0, prop_is(prop::PHY_LORA_SF, &[7]));
        model.pump(&mut script, 40);
        assert!(!model.busy());
        assert_eq!(model.u32(prop::PHY_LORA_BW), Some(62_500));
        assert_eq!(model.u8(prop::PHY_LORA_SF), Some(7));
    }

    #[test]
    fn a_write_sequence_out_of_room_sends_the_rest_after() {
        let (mut model, mut script) = with_caps(&[cap::PHY_LORA]);
        let id = model
            .set_many(&[(prop::PHY_LORA_SF, &[9]), (prop::PHY_LORA_CR, &[6])])
            .unwrap();
        model.pump(&mut script, 0);
        let (ticket, _) = script.last();
        script.answer(ticket, are(&[(prop::PHY_LORA_SF, &[9])]));
        model.pump(&mut script, 0);
        let (ticket, request) = script.last();
        assert_eq!(request.command(), Some(Cmd::PropSet));
        assert_eq!(model.pending(prop::PHY_LORA_CR), Some(&[6][..]));
        script.answer(ticket, prop_is(prop::PHY_LORA_CR, &[6]));
        model.pump(&mut script, 0);
        assert_eq!(
            events(&mut model)
                .into_iter()
                .filter(
                    |event| matches!(event, Event::Written { id: written, .. } if *written == id)
                )
                .count(),
            2
        );
        assert_eq!(model.pending(prop::PHY_LORA_CR), None);

        // A sequence whose first write fits no reply never will.
        let id = model
            .set_many(&[(prop::PHY_LORA_SF, &[8]), (prop::PHY_LORA_CR, &[5])])
            .unwrap();
        model.pump(&mut script, 0);
        let (ticket, _) = script.last();
        script.answer(ticket, are(&[]));
        let sent = script.sent.len();
        model.pump(&mut script, 0);
        assert_eq!(script.sent.len(), sent, "and is not sent again");
        let outcomes: Vec<WriteOutcome> = events(&mut model)
            .into_iter()
            .filter_map(|event| match event {
                Event::Written {
                    id: written,
                    outcome,
                    ..
                } if written == id => Some(outcome),
                _ => None,
            })
            .collect();
        assert_eq!(outcomes, [WriteOutcome::Unsent, WriteOutcome::Unsent]);
        assert_eq!(model.pending(prop::PHY_LORA_SF), None);
        assert!(!model.busy());
    }

    #[test]
    fn publications_keep_the_cache_current() {
        let (mut model, mut script) = with_caps(&[cap::DEV_IDENTITY, cap::REPEATER]);
        script.publish(prop_is(prop::MAC_REPEATER_ENABLED, &[1]));
        // Not covered: passed by.
        script.publish(prop_is(prop::ALERT, &[1]));
        model.pump(&mut script, 5);
        assert_eq!(model.forwarding(), Some(true));
        assert_eq!(
            model.freshness(prop::MAC_REPEATER_ENABLED),
            Freshness::Fresh { at_ms: 5 }
        );
        assert_eq!(
            events(&mut model),
            [Event::Changed(prop::MAC_REPEATER_ENABLED)]
        );

        // A table never read is not known whole: one item asks for the
        // rest.
        let peer = [7u8; 32];
        let mut buf = [0u8; 64];
        let len = frame::prop_inserted(&mut buf, 0, prop::DEV_PEERS, &peer).unwrap();
        script.publish(buf[..len].to_vec());
        model.pump(&mut script, 6);
        assert_eq!(model.peers().count(), 0);
        let (ticket, asked) = script.asked();
        assert_eq!(asked, [prop::DEV_PEERS]);
        script.answer(ticket, prop_is(prop::DEV_PEERS, &peer));
        model.pump(&mut script, 7);
        assert_eq!(model.peers().collect::<Vec<_>>(), [&peer]);

        // Once known, items come and go.
        let other = [9u8; 32];
        let len = frame::prop_inserted(&mut buf, 0, prop::DEV_PEERS, &other).unwrap();
        script.publish(buf[..len].to_vec());
        let len = frame::prop_removed(&mut buf, 0, prop::DEV_PEERS, &peer).unwrap();
        script.publish(buf[..len].to_vec());
        let sent = script.sent.len();
        model.pump(&mut script, 8);
        assert_eq!(script.sent.len(), sent);
        assert_eq!(model.peers().collect::<Vec<_>>(), [&other]);
    }

    #[test]
    fn a_reset_reads_everything_again_but_the_constants() {
        let (mut model, mut script) = with_caps(&[cap::DEV_NAME]);
        model.read(prop::DEV_NAME);
        model.pump(&mut script, 0);
        let (ticket, _) = script.last();
        script.answer(ticket, prop_is(prop::DEV_NAME, b"Pocket"));
        model.pump(&mut script, 1);
        events(&mut model);

        // A status that is not a reset says nothing about the cache.
        script.publish(status(Status::FAILURE));
        model.pump(&mut script, 2);
        assert!(events(&mut model).is_empty());

        script.publish(status(Status::RESET_SOFTWARE));
        model.pump(&mut script, 3);
        assert_eq!(events(&mut model), [Event::Resync]);
        assert_eq!(model.freshness(prop::DEV_NAME), Freshness::Stale);
        assert_eq!(model.device_name(), Some("Pocket"));
        let (_, asked) = script.asked();
        assert!(asked.contains(&prop::DEV_NAME));
        assert!(!asked.contains(&prop::CAPS));
        // What the device lacks is not asked for either.
        assert!(!asked.contains(&prop::MAC_REPEATER_ENABLED));
        assert!(asked.contains(&prop::PHY_TX_POWER));
    }

    #[test]
    fn a_write_answered_with_a_bare_success_is_read_back() {
        let (mut model, mut script) = with_caps(&[cap::DEV_NAME]);
        let id = model.set_device_name("Trail").unwrap();
        model.pump(&mut script, 0);
        let (ticket, _) = script.last();
        script.answer(ticket, status(Status::OK));
        model.pump(&mut script, 0);
        assert_eq!(
            events(&mut model),
            [Event::Written {
                id,
                key: prop::DEV_NAME,
                outcome: WriteOutcome::Unknown
            }]
        );
        let (_, asked) = script.asked();
        assert_eq!(asked, [prop::DEV_NAME]);
    }
}
