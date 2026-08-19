//! Managing a device over the mesh, from a node.
//!
//! [`Exchange`] knows the binding and nothing else: it hands out payloads
//! to send and reads the ones that come back. This binds it to a
//! [`PeerConnection`], so an administrator's operation becomes a matter of
//! servicing it until it finishes.
//!
//! The node layer delivers packets from inside the coordinator's borrow,
//! so a response is queued where it arrives and read where it can be
//! acted on. The caller owns the clock and the pump: it services the
//! exchange, then drives its `Host` until the deadline the service call
//! named, whichever comes first.

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use umsh_core::{PayloadType, PublicKey};
use umsh_mac::SendOptions;
use umsh_node::{
    LocalNode, MacBackend, PeerConnection, ReceivedPacketRef, SendProgressTicket, Subscription,
    Transport,
};

use crate::admin::{Exchange, Outcome, Reassembly, Step};
use crate::{PAYLOAD_MAX, REQUEST_MAX};

/// Responses held between the subscription that takes them in and the
/// service call that reads them.
///
/// An administrator has one exchange outstanding at a time, so anything
/// beyond a couple of payloads is a duplicate or a stray; a short queue
/// keeps a talkative peer from growing this without bound.
const INBOX: usize = 4;

/// How large a reply this reassembles before giving up.
///
/// A continued read costs one exchange per fragment, so a reply of this
/// size is already a slow operation over LoRa; the ceiling is what keeps
/// a device that never stops issuing cursors from consuming the host.
pub const REPLY_MAX: usize = 8 * 1024;

/// Why an operation could not be started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginError {
    /// The request frame is larger than a Node Management payload holds.
    RequestTooLarge,
    /// An exchange is already outstanding. An administrator may have only
    /// one with a given device.
    Busy,
}

/// Why an outstanding exchange could not be carried further.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementError<E> {
    /// The node could not send.
    Transport(E),
    /// Nothing is outstanding to service.
    Idle,
}

/// What the caller should do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Nothing further until `deadline_ms`. Pump the host until then; a
    /// response arriving earlier makes the next service call productive
    /// sooner.
    Waiting { deadline_ms: u64 },
    /// The exchange is over.
    Done(Outcome),
}

/// One administrator's dealings with one device.
pub struct NodeManager<M: MacBackend> {
    peer: PeerConnection<LocalNode<M>>,
    inbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
    /// Payloads taken in that turned out to belong to nobody: another
    /// exchange's token, an unauthenticated sender, or more than the
    /// inbox holds.
    stray: Rc<Cell<u32>>,
    _subscription: Subscription,
    exchange: Option<Exchange<REQUEST_MAX>>,
    /// The reply being reassembled, and how much of it is assembled. Held
    /// apart from [`Reassembly`], whose borrow cannot outlive a service
    /// call.
    reply: Vec<u8>,
    assembled: usize,
    /// The most recent send, for a reset-class command whose completion
    /// is the acknowledgment rather than a response.
    ticket: Option<SendProgressTicket>,
    /// Distinguishes each exchange's token from the last.
    counter: u16,
    options: SendOptions,
}

impl<M: MacBackend> NodeManager<M> {
    /// Watch `peer` for Node Management responses.
    ///
    /// `seed` picks the first token; anything unpredictable will do.
    pub fn new(peer: PeerConnection<LocalNode<M>>, seed: u16) -> Self {
        let inbox = Rc::new(RefCell::new(VecDeque::with_capacity(INBOX)));
        let stray = Rc::new(Cell::new(0u32));
        let subscription = {
            let inbox = inbox.clone();
            let stray = stray.clone();
            peer.on_receive(move |packet: &ReceivedPacketRef<'_>| {
                if packet.payload_type() != PayloadType::NodeManagementResponse {
                    return false;
                }
                // The binding rests on what secure unicast guarantees, so
                // an unauthenticated packet claiming to be a response is
                // not one — and it is still this handler's to consume,
                // since nothing else wants it either.
                let room = inbox.borrow().len() < INBOX;
                if !packet.source_authenticated() || !room {
                    stray.set(stray.get().saturating_add(1));
                    return true;
                }
                inbox.borrow_mut().push_back(packet.payload().to_vec());
                true
            })
        };

        Self {
            peer,
            inbox,
            stray,
            _subscription: subscription,
            exchange: None,
            reply: vec![0u8; REPLY_MAX],
            assembled: 0,
            ticket: None,
            counter: seed,
            options: SendOptions::default().with_ack_requested(true),
        }
    }

    /// The device being managed.
    pub fn device(&self) -> &PublicKey {
        self.peer.peer()
    }

    /// How requests go out. An acknowledgment is requested by default: it
    /// is what completes a reset, and elsewhere it turns an unreachable
    /// path into an early answer rather than four silent retries.
    pub fn send_options_mut(&mut self) -> &mut SendOptions {
        &mut self.options
    }

    /// Payloads taken in that belonged to no outstanding exchange.
    pub fn stray(&self) -> u32 {
        self.stray.get()
    }

    /// The counter behind the last token any exchange here consumed,
    /// the outstanding one included.
    ///
    /// A caller that builds one manager per operation seeds the next one
    /// from this, so no token is ever issued twice against a device that
    /// holds answered tokens against retransmission.
    pub fn counter(&self) -> u16 {
        self.exchange
            .as_ref()
            .map_or(self.counter, Exchange::counter)
    }

    /// The device's most recent estimate of octets not yet returned,
    /// present only during a continued read.
    pub fn remaining(&self) -> Option<u32> {
        self.exchange.as_ref().and_then(Exchange::remaining)
    }

    /// Whether an exchange is outstanding.
    pub fn is_busy(&self) -> bool {
        self.exchange.is_some()
    }

    /// Begin an operation carrying `request`, one ULCP frame.
    ///
    /// The frame's TID is ignored over this binding; the envelope token
    /// is what correlates the response.
    pub fn begin(&mut self, request: &[u8], now_ms: u64) -> Result<(), BeginError> {
        if self.exchange.is_some() {
            return Err(BeginError::Busy);
        }
        self.counter = self.counter.wrapping_add(1);
        let exchange = Exchange::new(request, self.counter, now_ms)
            .map_err(|_| BeginError::RequestTooLarge)?;
        // Anything still queued belongs to an exchange that is over.
        self.inbox.borrow_mut().clear();
        self.exchange = Some(exchange);
        self.assembled = 0;
        self.ticket = None;
        Ok(())
    }

    /// Carry the outstanding exchange as far as it will go right now:
    /// take in whatever arrived, then send if an attempt is due.
    ///
    /// A `Done` clears the exchange, leaving [`Self::reply`] readable
    /// until the next [`Self::begin`].
    pub async fn service(
        &mut self,
        now_ms: u64,
    ) -> Result<Progress, ManagementError<<LocalNode<M> as Transport>::Error>> {
        let Some(exchange) = self.exchange.as_mut() else {
            return Err(ManagementError::Idle);
        };

        // A reset-class command is answered by no response payload, so
        // the acknowledgment is what ends it.
        if !exchange.expects_response()
            && self
                .ticket
                .as_ref()
                .is_some_and(SendProgressTicket::was_acked)
        {
            exchange.delivered();
            return Ok(self.settle(Outcome::NoResponse));
        }

        let mut payload = [0u8; 1 + PAYLOAD_MAX];
        payload[0] = PayloadType::NodeManagementRequest as u8;

        let mut step = None;
        while let Some(response) = pop(&self.inbox) {
            let mut reassembly = Reassembly::resume(&mut self.reply, self.assembled);
            let next = exchange.receive(&response, &mut reassembly, now_ms, &mut payload[1..]);
            self.assembled = reassembly.len();
            match next {
                Some(next) => {
                    step = Some(next);
                    break;
                }
                None => self.stray.set(self.stray.get().saturating_add(1)),
            }
        }

        let step = match step {
            Some(step) => step,
            None => exchange.poll(now_ms, &mut payload[1..]),
        };

        match step {
            Step::Send { len } => {
                // The exchange set its own deadline when it handed out
                // the attempt, so ask rather than recompute; a send that
                // fails outright leaves the exchange to time out.
                let deadline_ms = exchange.deadline_ms().unwrap_or(now_ms);
                let ticket = self
                    .peer
                    .send(&payload[..1 + len], &self.options)
                    .await
                    .map_err(ManagementError::Transport)?;
                self.ticket = Some(ticket);
                Ok(Progress::Waiting { deadline_ms })
            }
            Step::Wait { deadline_ms } => Ok(Progress::Waiting { deadline_ms }),
            Step::Done(outcome) => Ok(self.settle(outcome)),
        }
    }

    /// The reply frame of the exchange that just finished: one whole ULCP
    /// frame, its trailing content the concatenation of every fragment.
    pub fn reply(&self) -> &[u8] {
        &self.reply[..self.assembled]
    }

    fn settle(&mut self, outcome: Outcome) -> Progress {
        // A continued read rotated tokens the manager's own counter never
        // saw. Taking the exchange's final count back is what keeps the
        // next `begin` from reissuing one of them — which the device
        // would answer with the old exchange's retained response.
        if let Some(exchange) = &self.exchange {
            self.counter = exchange.counter();
        }
        self.exchange = None;
        self.ticket = None;
        if let Outcome::Replied { len } = outcome {
            self.assembled = len;
        }
        Progress::Done(outcome)
    }
}

/// Take the next queued response without holding the borrow across the
/// work that follows it.
fn pop(inbox: &Rc<RefCell<VecDeque<Vec<u8>>>>) -> Option<Vec<u8>> {
    inbox.borrow_mut().pop_front()
}
