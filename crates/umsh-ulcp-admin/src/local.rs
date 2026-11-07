//! The device's own session, reached in process.
//!
//! A local binding answers every request that carries a non-zero TID
//! exactly once, and at once, so an answer that has not come within
//! [`ANSWER_TIMEOUT_MS`] is not coming: a [`LocalExchange`] gives the
//! request up as [`Arrival::Lost`] and, after a second wait in which a
//! late answer is discarded, takes its TID back. What the device
//! publishes arrives on the same port, in order with the answers.
//!
//! The exchange is not an attach. It resets no session state and
//! displaces no host, and it reaches the device domain only.

use umsh_ulcp::Frame;
use umsh_ulcp::frame::{TID_MAX, TID_UNSOLICITED};

use crate::exchange::{Arrival, Busy, Exchange, Request, Ticket};

/// Largest frame a local binding carries: the most a session emits in one
/// frame, and what the firmware driver's frame buffers hold.
pub const FRAME_MAX: usize = 300;

/// How long a request waits for its answer before the exchange gives it
/// up, and then how long its TID stays out of use in case the answer was
/// only late.
pub const ANSWER_TIMEOUT_MS: u64 = 10_000;

/// The device's port into its own session: where requests go in and the
/// session's frames for the interface come out.
pub trait LocalPort {
    /// Hand one request frame to the device.
    fn send(&mut self, frame: &[u8]) -> Result<(), PortBusy>;

    /// The next frame the device emitted for its interface, copied into
    /// `out`.
    fn receive(&mut self, out: &mut [u8]) -> Option<PortFrame>;
}

/// The device cannot take a request right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortBusy;

/// What a [`LocalPort`] hands back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortFrame {
    /// A frame of this many octets: an answer, or a publication.
    Frame(usize),
    /// The port dropped publications because the interface fell behind.
    Overrun,
}

/// What a TID is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Free,
    /// A request waits under it for its answer until `deadline_ms`.
    Waiting {
        ticket: Ticket,
        deadline_ms: u64,
    },
    /// Its request went unanswered past its deadline, and is yet to be
    /// reported lost.
    Lost {
        ticket: Ticket,
        until_ms: u64,
    },
    /// Its request was given up on. An answer under it now is late and
    /// discarded; at `until_ms` it is free again.
    Expired {
        until_ms: u64,
    },
}

/// An [`Exchange`] over the device's own session.
///
/// Requests are told apart by TID, so at most seven are outstanding at
/// once; an eighth waits for an answer, or a timeout, to free one. TIDs
/// are handed out in rotation, so one is reused as late as possible.
pub struct LocalExchange<P> {
    port: P,
    /// What each TID is doing. TID 0 is never used.
    slots: [Slot; TID_MAX as usize + 1],
    next_tid: u8,
    next_ticket: u32,
    now_ms: u64,
    /// Answers discarded because their request had been given up on, or
    /// that came under a TID nothing asked under.
    late: u32,
}

impl<P: LocalPort> LocalExchange<P> {
    pub const fn new(port: P) -> Self {
        Self {
            port,
            slots: [Slot::Free; TID_MAX as usize + 1],
            next_tid: 1,
            next_ticket: 0,
            now_ms: 0,
            late: 0,
        }
    }

    pub fn port(&self) -> &P {
        &self.port
    }

    pub fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    /// Requests handed to the device and waiting on their answers.
    pub fn outstanding(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, Slot::Waiting { .. }))
            .count()
    }

    /// Answers discarded: late ones, and any under a TID nothing asked
    /// under.
    pub fn late_answers(&self) -> u32 {
        self.late
    }

    /// When [`Exchange::expire`] next has something to give up on or to
    /// free.
    pub fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter_map(|slot| match *slot {
                Slot::Waiting { deadline_ms, .. } => Some(deadline_ms),
                Slot::Expired { until_ms } => Some(until_ms),
                Slot::Free | Slot::Lost { .. } => None,
            })
            .min()
    }

    fn free_tid(&self) -> Option<u8> {
        (0..TID_MAX)
            .map(|offset| (self.next_tid - 1 + offset) % TID_MAX + 1)
            .find(|&tid| self.slots[usize::from(tid)] == Slot::Free)
    }
}

impl<P: LocalPort> Exchange for LocalExchange<P> {
    const ANSWER_MAX: usize = FRAME_MAX;

    fn submit(&mut self, request: &Request<'_>) -> Result<Ticket, Busy> {
        let tid = self.free_tid().ok_or(Busy::Full)?;
        let mut frame = [0u8; FRAME_MAX];
        let len = request
            .encode(tid, &mut frame)
            .map_err(|_| Busy::TooLarge)?;
        self.port
            .send(&frame[..len])
            .map_err(|PortBusy| Busy::Full)?;
        let ticket = Ticket(self.next_ticket);
        self.next_ticket = self.next_ticket.wrapping_add(1);
        self.slots[usize::from(tid)] = Slot::Waiting {
            ticket,
            deadline_ms: self.now_ms.saturating_add(ANSWER_TIMEOUT_MS),
        };
        self.next_tid = tid % TID_MAX + 1;
        Ok(ticket)
    }

    fn receive<'b>(&mut self, out: &'b mut [u8]) -> Option<Arrival<'b>> {
        loop {
            let len = match self.port.receive(out) {
                Some(PortFrame::Overrun) => return Some(Arrival::Overrun),
                Some(PortFrame::Frame(len)) => len,
                // Nothing came: report what was given up on, oldest first.
                None => {
                    let next = self.next_ticket;
                    let slot = self
                        .slots
                        .iter_mut()
                        .filter_map(|slot| match *slot {
                            Slot::Lost { ticket, until_ms } => Some((slot, ticket, until_ms)),
                            _ => None,
                        })
                        .max_by_key(|(_, ticket, _)| next.wrapping_sub(ticket.0));
                    let (slot, ticket, until_ms) = slot?;
                    *slot = Slot::Expired { until_ms };
                    return Some(Arrival::Lost { ticket });
                }
            };
            // A frame the session cannot have meant is dropped; whatever
            // it answered is given up on at its deadline.
            let Ok(parsed) = Frame::parse(&out[..len]) else {
                continue;
            };
            let tid = parsed.header.tid();
            if tid == TID_UNSOLICITED {
                return Some(Arrival::Publication { frame: &out[..len] });
            }
            let slot = &mut self.slots[usize::from(tid)];
            match core::mem::replace(slot, Slot::Free) {
                // An answer that beat the report of its loss still counts.
                Slot::Waiting { ticket, .. } | Slot::Lost { ticket, .. } => {
                    return Some(Arrival::Answer {
                        ticket,
                        frame: &out[..len],
                    });
                }
                // The answer to a request already given up on: the TID is
                // free at once, since nothing more can come under it.
                Slot::Expired { .. } | Slot::Free => self.late = self.late.wrapping_add(1),
            }
        }
    }

    fn expire(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        for slot in &mut self.slots {
            *slot = match *slot {
                Slot::Waiting {
                    ticket,
                    deadline_ms,
                } if deadline_ms <= now_ms => Slot::Lost {
                    ticket,
                    until_ms: now_ms.saturating_add(ANSWER_TIMEOUT_MS),
                },
                Slot::Expired { until_ms } if until_ms <= now_ms => Slot::Free,
                other => other,
            };
        }
    }
}

/// The port into the firmware ULCP driver: requests go in as
/// [`InEvent::Device`] on the driver's input channel, and the driver
/// answers on the board's [`DeviceLink`].
///
/// The port never waits. A full input channel is [`PortBusy`], and its
/// owner awaits [`DriverPort::ready`] to learn when the link has
/// something, which is also when a slot may have come free.
///
/// [`InEvent::Device`]: umsh_ulcp_runtime::driver::InEvent::Device
/// [`DeviceLink`]: umsh_ulcp_runtime::driver::DeviceLink
#[cfg(any(feature = "driver", test))]
pub mod driver {
    use embassy_sync::blocking_mutex::raw::RawMutex;
    use umsh_ulcp_runtime::driver::{DeviceFrame, DeviceLink, FrameBuf, InEvent, InputChannel};

    use super::{LocalPort, PortBusy, PortFrame};

    pub struct DriverPort<M: RawMutex + 'static> {
        input: &'static InputChannel<M>,
        link: &'static DeviceLink<M>,
    }

    impl<M: RawMutex + 'static> DriverPort<M> {
        pub const fn new(input: &'static InputChannel<M>, link: &'static DeviceLink<M>) -> Self {
            Self { input, link }
        }

        /// Wait until the link has something to receive.
        pub async fn ready(&self) {
            self.link.ready().await
        }
    }

    impl<M: RawMutex + 'static> LocalPort for DriverPort<M> {
        fn send(&mut self, frame: &[u8]) -> Result<(), PortBusy> {
            let frame = FrameBuf::from_slice(frame).map_err(|()| PortBusy)?;
            self.input
                .try_send(InEvent::Device(frame))
                .map_err(|_| PortBusy)
        }

        fn receive(&mut self, out: &mut [u8]) -> Option<PortFrame> {
            match self.link.try_receive()? {
                DeviceFrame::Frame(frame) => {
                    debug_assert!(frame.len() <= out.len(), "the receive buffer is too small");
                    let len = frame.len().min(out.len());
                    out[..len].copy_from_slice(&frame[..len]);
                    Some(PortFrame::Frame(len))
                }
                DeviceFrame::Overrun => Some(PortFrame::Overrun),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port that takes everything and answers whatever the test queues.
    #[derive(Default)]
    struct Script {
        sent: std::vec::Vec<std::vec::Vec<u8>>,
        replies: std::collections::VecDeque<Option<std::vec::Vec<u8>>>,
    }

    impl LocalPort for Script {
        fn send(&mut self, frame: &[u8]) -> Result<(), PortBusy> {
            self.sent.push(frame.to_vec());
            Ok(())
        }

        fn receive(&mut self, out: &mut [u8]) -> Option<PortFrame> {
            match self.replies.pop_front()? {
                Some(frame) => {
                    out[..frame.len()].copy_from_slice(&frame);
                    Some(PortFrame::Frame(frame.len()))
                }
                None => Some(PortFrame::Overrun),
            }
        }
    }

    fn tid_of(frame: &[u8]) -> u8 {
        Frame::parse(frame).unwrap().header.tid()
    }

    #[test]
    fn the_frame_ceiling_is_what_the_session_and_driver_carry() {
        assert_eq!(FRAME_MAX, umsh_ulcp_device::MULTI_MAX);
        assert_eq!(FRAME_MAX, umsh_ulcp_runtime::driver::FRAME_OUT_MAX);
        assert_eq!(FRAME_MAX, umsh_ulcp_runtime::driver::FRAME_IN_MAX);
    }

    /// Seven TIDs, never zero, handed out in rotation; an eighth request
    /// waits for an answer.
    #[test]
    fn requests_take_the_seven_tids_in_rotation() {
        let mut exchange = LocalExchange::new(Script::default());
        let tickets: std::vec::Vec<_> = (0..7)
            .map(|_| exchange.submit(&Request::Get(5)).unwrap())
            .collect();
        assert_eq!(exchange.submit(&Request::Get(5)), Err(Busy::Full));
        let tids: std::vec::Vec<_> = exchange.port().sent.iter().map(|f| tid_of(f)).collect();
        assert_eq!(tids, [1, 2, 3, 4, 5, 6, 7]);

        // TID 3 is answered and comes free, but the rotation goes on from
        // where it was before reusing it.
        let mut answer = [0u8; 16];
        let len = umsh_ulcp::frame::prop_is(&mut answer, 3, 5, &[]).unwrap();
        exchange
            .port_mut()
            .replies
            .push_back(Some(answer[..len].to_vec()));
        let mut out = [0u8; FRAME_MAX];
        assert_eq!(
            exchange.receive(&mut out),
            Some(Arrival::Answer {
                ticket: tickets[2],
                frame: &answer[..len]
            })
        );
        exchange.submit(&Request::Get(5)).unwrap();
        assert_eq!(tid_of(exchange.port().sent.last().unwrap()), 3);
        assert_eq!(exchange.outstanding(), 7);
    }

    /// The driver's side of the link—answers on it, publications and an
    /// overrun through it—is the runtime's to test. What is left is that
    /// the port hands requests to the driver's input and never waits.
    #[test]
    fn the_driver_port_hands_requests_in_and_never_waits() {
        use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
        use umsh_ulcp_runtime::driver::{DeviceLink, InEvent, InputChannel};

        static INPUT: InputChannel<CriticalSectionRawMutex> = InputChannel::new();
        static LINK: DeviceLink<CriticalSectionRawMutex> = DeviceLink::new();
        let mut exchange = LocalExchange::new(driver::DriverPort::new(&INPUT, &LINK));

        exchange.submit(&Request::Get(prop_key())).unwrap();
        let Ok(InEvent::Device(frame)) = INPUT.try_receive() else {
            panic!("the request reached the driver as a device request");
        };
        assert_eq!(tid_of(&frame), 1);

        // The board's other tasks fill the input. A full input is a link
        // busy for now: the request is not taken, and holds no TID.
        while INPUT.try_send(InEvent::Device(frame.clone())).is_ok() {}
        assert_eq!(exchange.submit(&Request::Get(prop_key())), Err(Busy::Full));
        assert_eq!(exchange.outstanding(), 1);
        INPUT.clear();
        exchange.submit(&Request::Get(prop_key())).unwrap();
        assert_eq!(exchange.outstanding(), 2);

        let mut out = [0u8; FRAME_MAX];
        assert_eq!(exchange.receive(&mut out), None);
    }

    fn prop_key() -> u32 {
        umsh_ulcp::ids::prop::PHY_TX_POWER
    }

    #[test]
    fn publications_and_overruns_pass_through_in_order() {
        let mut exchange = LocalExchange::new(Script::default());
        let mut publication = [0u8; 16];
        let len = umsh_ulcp::frame::prop_is(&mut publication, 0, 77, &[1]).unwrap();
        let port = exchange.port_mut();
        port.replies.push_back(Some(publication[..len].to_vec()));
        port.replies.push_back(None);
        let mut out = [0u8; FRAME_MAX];
        assert_eq!(
            exchange.receive(&mut out),
            Some(Arrival::Publication {
                frame: &publication[..len]
            })
        );
        assert_eq!(exchange.receive(&mut out), Some(Arrival::Overrun));
        assert_eq!(exchange.receive(&mut out), None);
    }
}
