use alloc::rc::{Rc, Weak};
use alloc::vec::Vec;
use core::cell::RefCell;

use umsh_mac::{LocalIdentityId, MacEventRef};

use crate::ticket::{SendToken, TicketState};

/// Tracks in-flight send tickets and updates their state from MAC callbacks.
pub(crate) struct EventDispatcher {
    ticket_states: Vec<(SendToken, Weak<RefCell<TicketState>>)>,
}

impl EventDispatcher {
    pub fn new() -> Self {
        Self {
            ticket_states: Vec::new(),
        }
    }

    pub fn register_ticket(&mut self, token: SendToken, non_ack: bool) -> Rc<RefCell<TicketState>> {
        let state = Rc::new(RefCell::new(TicketState {
            non_ack,
            ..TicketState::default()
        }));
        self.ticket_states.push((token, Rc::downgrade(&state)));
        state
    }

    pub fn dispatch_ticket_state(&mut self, identity_id: LocalIdentityId, event: &MacEventRef<'_>) {
        match *event {
            MacEventRef::Transmitted {
                identity_id: tx_id,
                receipt: Some(receipt),
                ..
            } => {
                let token = SendToken::new(tx_id, receipt);
                self.update_ticket(&token, |state| {
                    state.transmitted = true;
                    if state.non_ack {
                        state.finished = true;
                    }
                });
            }
            // Forwards go on arriving after a send that asked for no
            // acknowledgment is finished, and still count.
            MacEventRef::Forwarded {
                identity_id: fwd_id,
                receipt,
                repeater,
            } => {
                let token = SendToken::new(fwd_id, receipt);
                self.update_ticket(&token, |state| {
                    state.repeats.note(repeater);
                });
            }
            MacEventRef::AckReceived {
                receipt,
                via_route_retry,
                ..
            } => {
                let token = SendToken::new(identity_id, receipt);
                self.update_ticket(&token, |state| {
                    state.acked = true;
                    state.acked_via_route_retry = via_route_retry;
                    state.finished = true;
                });
            }
            MacEventRef::AckTimeout { receipt, .. } => {
                let token = SendToken::new(identity_id, receipt);
                self.update_ticket(&token, |state| {
                    state.failed = true;
                    state.finished = true;
                });
            }
            MacEventRef::TxAbandoned {
                identity_id: tx_id,
                receipt: Some(receipt),
            } => {
                let token = SendToken::new(tx_id, receipt);
                self.update_ticket(&token, |state| {
                    state.failed = true;
                    state.finished = true;
                });
            }
            _ => {}
        }
    }

    /// Fail every unfinished ticket of `identity_id`, whose identity is
    /// gone and its sends with it: the MAC reports nothing more for them.
    /// The tickets are forgotten too, so a later identity given the same
    /// slot, whose receipts start over, never updates them.
    pub fn fail_identity(&mut self, identity_id: LocalIdentityId) {
        self.ticket_states.retain(|(token, weak)| {
            if token.identity_id != identity_id {
                return weak.strong_count() > 0;
            }
            if let Some(rc) = weak.upgrade() {
                let mut state = rc.borrow_mut();
                if !state.finished {
                    state.failed = true;
                    state.finished = true;
                }
            }
            false
        });
    }

    fn update_ticket(&mut self, token: &SendToken, f: impl FnOnce(&mut TicketState)) {
        if let Some(pos) = self.ticket_states.iter().position(|(t, _)| t == token) {
            let (_, weak) = &self.ticket_states[pos];
            if let Some(rc) = weak.upgrade() {
                f(&mut rc.borrow_mut());
            } else {
                self.ticket_states.swap_remove(pos);
            }
        }

        self.ticket_states
            .retain(|(_, weak)| weak.strong_count() > 0);
    }
}
