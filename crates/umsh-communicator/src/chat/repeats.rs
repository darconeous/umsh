//! The repeaters overheard carrying the device's own messages, kept in
//! memory for the messages sent most recently, and when a direct message's
//! word on them went quiet.

use umsh_node::RepeatTally;
use umsh_text::ConversationKey;
use umsh_text::chat::{Delivery, Repeats};
use umsh_text::engine::DeliveryState;
use umsh_ux_communicator::heapless::Vec;
use umsh_ux_communicator::model::{self, NodeEvent};

use super::Chats;
use crate::ids::MessageId;
use crate::store::ChatStore;

/// How many messages' repeaters are kept. Past it, the one whose word last
/// moved longest ago goes.
const HEARD_KEPT: usize = 16;

/// How long after its word last moved a direct message goes on naming its
/// repeaters, before it settles into waiting on its acknowledgment.
const SETTLE_MS: u64 = 2_000;

/// What became of one of the device's messages on its way.
pub(super) struct Heard {
    chat: model::ChatId,
    /// It went to a peer, who will acknowledge it.
    direct: bool,
    tally: RepeatTally,
    /// When it was last sent or a new repeater was heard carrying it.
    progress_ms: u64,
    /// Its acknowledgment came, or will not.
    answered: bool,
    /// Its repeaters went quiet with no acknowledgment yet.
    confirming: bool,
}

impl<S: ChatStore> Chats<S> {
    /// Takes in the repeaters heard so far carrying one of a message's
    /// fragments.
    pub(super) fn heard_repeats(
        &mut self,
        repeats: &Repeats,
        now_ms: u64,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        let Some(&id) = self.handles.get(&repeats.handle) else {
            return;
        };
        let Some(heard) = self.heard_entry(id, now_ms) else {
            return;
        };
        if !heard.tally.merge(&repeats.repeaters, repeats.anonymous) {
            return;
        }
        heard.progress_ms = now_ms;
        heard.confirming = false;
        let chat = heard.chat;
        events(NodeEvent::MessageChanged {
            chat,
            message: id.0,
        });
    }

    /// Takes in what became of one of a message's fragments. Sending one,
    /// again or for the first time, starts its wait over.
    pub(super) fn heard_delivery(&mut self, delivery: &Delivery, now_ms: u64) {
        let Some(&id) = self.handles.get(&delivery.handle) else {
            return;
        };
        match delivery.state {
            DeliveryState::Sent => {
                if let Some(heard) = self.heard_entry(id, now_ms) {
                    heard.progress_ms = now_ms;
                    heard.answered = false;
                    heard.confirming = false;
                }
            }
            DeliveryState::Acked | DeliveryState::Failed => {
                if let Some(heard) = self.heard.get_mut(&id) {
                    heard.answered = true;
                }
            }
        }
    }

    /// Settles each direct message whose repeaters went quiet for
    /// [`SETTLE_MS`] into waiting on its acknowledgment.
    pub(super) fn lapse_repeats(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) {
        for (id, heard) in &mut self.heard {
            if heard.direct
                && !heard.answered
                && !heard.confirming
                && now_ms.saturating_sub(heard.progress_ms) >= SETTLE_MS
            {
                heard.confirming = true;
                events(NodeEvent::MessageChanged {
                    chat: heard.chat,
                    message: id.0,
                });
            }
        }
    }

    /// Whether the direct message `id`, sent, waits on its acknowledgment
    /// with no repeater heard lately. One no longer kept here does too.
    pub(super) fn confirming(&self, id: MessageId) -> bool {
        self.heard.get(&id).is_none_or(|heard| heard.confirming)
    }

    /// The repeaters heard carrying `id`, as its caption names them.
    pub(super) fn via(&self, id: MessageId) -> Option<model::Via> {
        let tally = &self.heard.get(&id)?.tally;
        let count = u8::try_from(tally.count()).unwrap_or(u8::MAX);
        if count == 0 {
            return None;
        }
        let lead = tally
            .repeaters
            .first()
            .and_then(|&hint| self.repeater(hint))
            .map(|repeater| repeater.name);
        Some(model::Via { lead, count })
    }

    /// The repeaters heard carrying `id` that named themselves, as its
    /// details list them, and how many more did not.
    pub(super) fn repeaters(
        &self,
        id: MessageId,
    ) -> (Vec<model::Repeater, { model::MAX_REPEATERS }>, u16) {
        let Some(heard) = self.heard.get(&id) else {
            return Default::default();
        };
        let repeaters = heard
            .tally
            .repeaters
            .iter()
            .filter_map(|&hint| self.repeater(hint))
            .collect();
        (repeaters, heard.tally.anonymous)
    }

    /// What is kept of `id`, made when it is one of the device's messages
    /// and not kept yet.
    fn heard_entry(&mut self, id: MessageId, now_ms: u64) -> Option<&mut Heard> {
        if !self.heard.contains_key(&id) {
            let record = self.store.message(id).ok()??;
            let direct = matches!(
                self.conversation(record.chat.0)?,
                ConversationKey::Direct { .. }
            );
            if self.heard.len() >= HEARD_KEPT
                && let Some(oldest) = self
                    .heard
                    .iter()
                    .min_by_key(|(_, heard)| heard.progress_ms)
                    .map(|(id, _)| *id)
            {
                self.heard.remove(&oldest);
            }
            self.heard.insert(
                id,
                Heard {
                    chat: record.chat.0,
                    direct,
                    tally: RepeatTally::default(),
                    progress_ms: now_ms,
                    answered: false,
                    confirming: false,
                },
            );
        }
        self.heard.get_mut(&id)
    }
}
