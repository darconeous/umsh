use alloc::rc::Rc;
use core::cell::RefCell;
use core::task::{Context, Poll, Waker};

use umsh_core::RouterHint;
use umsh_mac::{LocalIdentityId, SendReceipt, TxAbandonReason};

/// Distinct named repeaters a [`RepeatTally`] remembers. Past this, a newly
/// named repeater is counted as an anonymous one.
pub const MAX_TALLIED_REPEATERS: usize = 8;

/// The repeaters overheard carrying a send.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepeatTally {
    /// Repeaters the forwards named, each once, in the order first heard.
    pub repeaters: heapless::Vec<RouterHint, MAX_TALLIED_REPEATERS>,
    /// Forwards that named no repeater. One repeater may forward a frame
    /// more than once, so this counts repeats, not repeaters.
    pub anonymous: u16,
    /// Bumped whenever the tally changes, so a poller can tell.
    pub revision: u32,
}

impl RepeatTally {
    /// Named repeaters plus unnamed repeats.
    pub fn count(&self) -> usize {
        self.repeaters.len() + usize::from(self.anonymous)
    }

    pub(crate) fn note(&mut self, repeater: Option<RouterHint>) {
        match repeater {
            Some(hint) if self.repeaters.contains(&hint) => return,
            Some(hint) if self.repeaters.push(hint).is_ok() => {}
            _ => self.anonymous = self.anonymous.saturating_add(1),
        }
        self.revision = self.revision.wrapping_add(1);
    }

    /// Take in another tally of the same message: a fragment of it, or a
    /// send of it again. Named repeaters are added after those already
    /// here; the unnamed count is the larger of the two, since every send
    /// of a message is heard by the same repeaters. Returns whether a
    /// repeater was added.
    pub fn merge(&mut self, repeaters: &[RouterHint], anonymous: u16) -> bool {
        let mut added = false;
        for &hint in repeaters {
            if !self.repeaters.contains(&hint) && self.repeaters.push(hint).is_ok() {
                added = true;
            }
        }
        if anonymous > self.anonymous {
            self.anonymous = anonymous;
            added = true;
        }
        if added {
            self.revision = self.revision.wrapping_add(1);
        }
        added
    }
}

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
    /// Repeaters overheard forwarding this frame.
    pub repeats: RepeatTally,
    /// Transport ACK received from the destination.
    pub acked: bool,
    /// The ACK answered the route-retry flood that followed a missed route.
    pub acked_via_route_retry: bool,
    /// ACK timeout—all retransmits exhausted without ACK.
    pub failed: bool,
    /// Failed because the session it went under ended first.
    pub session_ended: bool,
    /// MAC is completely done with this send (no more events will fire).
    pub finished: bool,
    /// True for sends that don't request ACK (broadcast/multicast).
    /// The dispatcher marks these finished as soon as Transmitted fires.
    pub non_ack: bool,
    /// Why the MAC gave up on the frame without transmitting it, when it did.
    pub abandoned: Option<TxAbandonReason>,
    /// The task waiting for the send to finish.
    pub waker: Option<Waker>,
}

impl TicketState {
    /// Wake whoever waits on the send, once it is finished.
    pub(crate) fn wake_if_finished(&mut self) {
        if self.finished
            && let Some(waker) = self.waker.take()
        {
            waker.wake();
        }
    }
}

/// Lightweight handle for observing the progress of an in-flight send.
///
/// The dispatcher updates the internal `TicketState` synchronously from the MAC
/// event callback. The application queries progress at its own pace via polling
/// methods (`was_transmitted`, `was_acked`, `is_finished`, etc.).
///
/// Dropping the ticket unregisters it from the dispatcher (via `Weak` reference
/// invalidation). The MAC continues the in-flight send—dropping only stops
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
        self.state.borrow().repeats.count() > 0
    }

    /// The repeaters overheard forwarding this frame so far. Forwards keep
    /// arriving after the send is otherwise finished.
    pub fn repeats(&self) -> RepeatTally {
        self.state.borrow().repeats.clone()
    }

    /// True after a transport ACK was received from the destination.
    pub fn was_acked(&self) -> bool {
        self.state.borrow().acked
    }

    /// True when the ACK answered the route-retry flood that followed a miss
    /// on the cached route, rather than the original send.
    pub fn was_acked_via_route_retry(&self) -> bool {
        self.state.borrow().acked_via_route_retry
    }

    /// True when the ACK timed out—all retransmits exhausted without ACK.
    pub fn has_failed(&self) -> bool {
        self.state.borrow().failed
    }

    /// True when the send failed because the session with forward secrecy
    /// it went under ended before it was acknowledged. The frame may never
    /// have reached the peer, and nothing sealed under that session can
    /// go again.
    pub fn session_ended(&self) -> bool {
        self.state.borrow().session_ended
    }

    /// True when the MAC is completely done—no more retransmissions,
    /// no more events will fire for this ticket.
    ///
    /// For non-ACK sends (broadcast/multicast), this becomes `true`
    /// immediately after the first radio transmission. For ACK-tracked
    /// sends, this becomes `true` after an ACK is received or all
    /// retransmits are exhausted.
    pub fn is_finished(&self) -> bool {
        self.state.borrow().finished
    }

    /// Why the MAC gave up on the frame before it ever reached the air,
    /// when that is how the send finished.
    pub fn abandon_reason(&self) -> Option<TxAbandonReason> {
        self.state.borrow().abandoned
    }

    /// Ready once [`is_finished`](Self::is_finished); otherwise `cx` is
    /// woken when it becomes so. Only the latest waker is kept, so one
    /// task may wait on several tickets but two tasks may not wait on one.
    pub fn poll_finished(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.borrow_mut();
        if state.finished {
            return Poll::Ready(());
        }
        match &mut state.waker {
            Some(waker) => waker.clone_from(cx.waker()),
            none => *none = Some(cx.waker().clone()),
        }
        Poll::Pending
    }

    /// Wait until the MAC is done with the send.
    pub async fn finished(&self) {
        core::future::poll_fn(|cx| self.poll_finished(cx)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_mac::{LocalIdentityId, SendReceipt};

    fn make_token() -> SendToken {
        SendToken::new(LocalIdentityId(0), SendReceipt(42))
    }

    #[test]
    fn merging_tallies_adds_new_repeaters_and_keeps_the_larger_unnamed_count() {
        let mut tally = RepeatTally::default();
        assert!(tally.merge(&[RouterHint([1, 2])], 1));
        let revision = tally.revision;

        // The same word again changes nothing.
        assert!(!tally.merge(&[RouterHint([1, 2])], 1));
        assert_eq!(tally.revision, revision);

        // A smaller unnamed count is the same repeaters, heard less.
        assert!(tally.merge(&[RouterHint([3, 4]), RouterHint([1, 2])], 0));
        assert_eq!(tally.repeaters, [RouterHint([1, 2]), RouterHint([3, 4])]);
        assert_eq!(tally.anonymous, 1);

        assert!(tally.merge(&[], 2));
        assert_eq!(tally.count(), 4);
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

        state.borrow_mut().repeats.note(None);
        assert!(ticket.was_repeated());

        state.borrow_mut().acked = true;
        assert!(ticket.was_acked());

        state.borrow_mut().failed = true;
        assert!(ticket.has_failed());

        state.borrow_mut().finished = true;
        assert!(ticket.is_finished());
    }

    #[test]
    fn a_waiter_is_woken_when_the_send_finishes() {
        use alloc::sync::Arc;
        use alloc::task::Wake;
        use core::sync::atomic::{AtomicBool, Ordering};

        struct Flag(AtomicBool);
        impl Wake for Flag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut cx = Context::from_waker(&waker);
        let (ticket, state) = make_ticket();
        assert!(ticket.poll_finished(&mut cx).is_pending());
        state.borrow_mut().transmitted = true;
        state.borrow_mut().wake_if_finished();
        assert!(!flag.0.load(Ordering::Relaxed));
        state.borrow_mut().finished = true;
        state.borrow_mut().wake_if_finished();
        assert!(flag.0.load(Ordering::Relaxed));
        assert!(ticket.poll_finished(&mut cx).is_ready());
    }

    #[test]
    fn repeat_tally_names_each_repeater_once() {
        let mut tally = RepeatTally::default();
        let hint = RouterHint([1, 2]);
        tally.note(Some(hint));
        tally.note(Some(hint));
        tally.note(None);
        assert_eq!(tally.repeaters.as_slice(), &[hint]);
        assert_eq!(tally.anonymous, 1);
        assert_eq!(tally.count(), 2);
        assert_eq!(tally.revision, 2, "a repeater heard again is no change");
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
