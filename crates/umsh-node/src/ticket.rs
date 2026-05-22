use alloc::rc::Rc;
use core::cell::RefCell;

use umsh_mac::{LocalIdentityId, SendReceipt};

/// Identity-scoped send token.
///
/// [`SendReceipt`] is only unique within a [`LocalIdentityId`] slot (it's allocated
/// from a per-identity `next_receipt` counter). `SendToken` combines the two into a
/// single value that is unique across all identity slots, suitable for use as a
/// dispatcher key, ticket identifier, or cancellation handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SendToken {
    pub identity_id: LocalIdentityId,
    pub receipt: SendReceipt,
}

impl SendToken {
    /// Create a new send token from an identity slot and receipt.
    pub fn new(identity_id: LocalIdentityId, receipt: SendReceipt) -> Self {
        Self {
            identity_id,
            receipt,
        }
    }
}

/// Internal shared state updated by the dispatcher.
#[derive(Clone, Debug, Default)]
pub(crate) struct TicketState {
    /// Frame was handed to the radio at least once.
    pub transmitted: bool,
    /// A repeater was overheard forwarding this frame.
    pub repeated: bool,
    /// Transport ACK received from the destination.
    pub acked: bool,
    /// ACK timeout — all retransmits exhausted without ACK.
    pub failed: bool,
    /// MAC is completely done with this send (no more events will fire).
    pub finished: bool,
    /// True for sends that don't request ACK (broadcast/multicast).
    /// The dispatcher marks these finished as soon as Transmitted fires.
    pub non_ack: bool,
}

/// Lightweight handle for observing the progress of an in-flight send.
///
/// The dispatcher updates the internal `TicketState` synchronously from the MAC
/// event callback. The application queries progress at its own pace via polling
/// methods (`was_transmitted`, `was_acked`, `is_finished`, etc.).
///
/// Dropping the ticket unregisters it from the dispatcher (via `Weak` reference
/// invalidation). The MAC continues the in-flight send — dropping only stops
/// *observation*, not the send itself.
pub struct SendProgressTicket {
    token: Option<SendToken>,
    state: Rc<RefCell<TicketState>>,
}

impl SendProgressTicket {
    /// Create a new ticket registered with the dispatcher for ACK-tracked sends.
    pub(crate) fn new(token: SendToken, state: Rc<RefCell<TicketState>>) -> Self {
        Self {
            token: Some(token),
            state,
        }
    }

    /// Create a ticket for a send that has no receipt (e.g. non-ACK unicast).
    ///
    /// Without a receipt, the MAC's `Transmitted` event cannot be correlated
    /// back to this ticket. The ticket is immediately marked as transmitted
    /// and finished since there is nothing to track.
    pub(crate) fn fire_and_forget() -> Self {
        let state = Rc::new(RefCell::new(TicketState {
            transmitted: true,
            finished: true,
            non_ack: true,
            ..TicketState::default()
        }));
        Self { token: None, state }
    }

    /// The identity-scoped send token, if this is an ACK-tracked send.
    pub fn token(&self) -> Option<SendToken> {
        self.token
    }

    /// The underlying receipt, if this is an ACK-tracked send.
    pub fn receipt(&self) -> Option<SendReceipt> {
        self.token.map(|t| t.receipt)
    }

    /// True after the frame was handed to the radio at least once.
    ///
    /// For all send types, this reflects actual radio transmission: it
    /// becomes `true` when the MAC fires the `Transmitted` event for this
    /// ticket's receipt.
    pub fn was_transmitted(&self) -> bool {
        self.state.borrow().transmitted
    }

    /// True after a repeater was overheard forwarding this frame.
    pub fn was_repeated(&self) -> bool {
        self.state.borrow().repeated
    }

    /// True after a transport ACK was received from the destination.
    pub fn was_acked(&self) -> bool {
        self.state.borrow().acked
    }

    /// True when the ACK timed out — all retransmits exhausted without ACK.
    pub fn has_failed(&self) -> bool {
        self.state.borrow().failed
    }

    /// True when the MAC is completely done — no more retransmissions,
    /// no more events will fire for this ticket.
    ///
    /// For non-ACK sends (broadcast/multicast), this becomes `true`
    /// immediately after the first radio transmission. For ACK-tracked
    /// sends, this becomes `true` after an ACK is received or all
    /// retransmits are exhausted.
    pub fn is_finished(&self) -> bool {
        self.state.borrow().finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_mac::{LocalIdentityId, SendReceipt};

    fn make_token() -> SendToken {
        SendToken::new(LocalIdentityId(0), SendReceipt(42))
    }

    fn make_ticket() -> (SendProgressTicket, Rc<RefCell<TicketState>>) {
        let state = Rc::new(RefCell::new(TicketState::default()));
        let ticket = SendProgressTicket::new(make_token(), state.clone());
        (ticket, state)
    }

    #[test]
    fn new_ticket_all_false() {
        let (ticket, _state) = make_ticket();
        assert!(!ticket.was_transmitted());
        assert!(!ticket.was_repeated());
        assert!(!ticket.was_acked());
        assert!(!ticket.has_failed());
        assert!(!ticket.is_finished());
    }

    #[test]
    fn new_ticket_token_and_receipt() {
        let (ticket, _state) = make_ticket();
        let token = ticket.token().unwrap();
        assert_eq!(token.identity_id, LocalIdentityId(0));
        assert_eq!(token.receipt, SendReceipt(42));
        assert_eq!(ticket.receipt(), Some(SendReceipt(42)));
    }

    #[test]
    fn fire_and_forget_initially_transmitted_and_finished() {
        let ticket = SendProgressTicket::fire_and_forget();
        assert!(ticket.was_transmitted());
        assert!(ticket.is_finished());
        assert!(!ticket.was_acked());
        assert!(!ticket.has_failed());
        assert!(ticket.token().is_none());
        assert!(ticket.receipt().is_none());
    }

    #[test]
    fn state_mutations_visible_through_ticket() {
        let (ticket, state) = make_ticket();

        state.borrow_mut().transmitted = true;
        assert!(ticket.was_transmitted());

        state.borrow_mut().repeated = true;
        assert!(ticket.was_repeated());

        state.borrow_mut().acked = true;
        assert!(ticket.was_acked());

        state.borrow_mut().failed = true;
        assert!(ticket.has_failed());

        state.borrow_mut().finished = true;
        assert!(ticket.is_finished());
    }

    #[test]
    fn cloned_state_reflects_same_updates() {
        let (ticket, state) = make_ticket();
        let ticket2 = SendProgressTicket::new(make_token(), state.clone());
        state.borrow_mut().acked = true;
        assert!(ticket.was_acked());
        assert!(ticket2.was_acked());
    }
}
