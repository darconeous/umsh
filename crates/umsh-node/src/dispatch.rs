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

    pub fn register_ticket(
        &mut self,
        token: SendToken,
        non_ack: bool,
    ) -> Rc<RefCell<TicketState>> {
        let state = Rc::new(RefCell::new(TicketState {
            non_ack,
            ..TicketState::default()
        }));
        self.ticket_states.push((token, Rc::downgrade(&state)));
        state
    }

    pub fn dispatch_ticket_state(
        &mut self,
        identity_id: LocalIdentityId,
        event: &MacEventRef<'_>,
    ) {
        match *event {
            MacEventRef::Transmitted {
                identity_id: tx_id,
                receipt,
            } => {
                if let Some(receipt) = receipt {
                    let token = SendToken::new(tx_id, receipt);
                    self.update_ticket(&token, |state| {
                        state.transmitted = true;
                        if state.non_ack {
                            state.finished = true;
                        }
                    });
                }
            }
            MacEventRef::Forwarded {
                identity_id: fwd_id,
                receipt,
                ..
            } => {
                let token = SendToken::new(fwd_id, receipt);
                self.update_ticket(&token, |state| {
                    state.repeated = true;
                });
            }
            MacEventRef::AckReceived { receipt, .. } => {
                let token = SendToken::new(identity_id, receipt);
                self.update_ticket(&token, |state| {
                    state.acked = true;
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
            _ => {}
        }
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

        self.ticket_states.retain(|(_, weak)| weak.strong_count() > 0);
    }
}
