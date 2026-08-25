//! ULCP carried over the Node Management binding.
//!
//! [`UlcpDevice`](crate::ulcp::UlcpDevice) speaks to whatever satisfies
//! [`FrameLink`]: send one frame, receive one frame. That is also the
//! whole of what an administrative exchange does, so a link made of the
//! two lets the ordinary host surface — properties, capabilities, the
//! synchronization procedure, every category command built on them —
//! reach a device across the mesh with nothing about it rewritten for
//! the occasion.
//!
//! The adapter is split in half. [`MeshFrameLink`] is what the device
//! handle holds; [`MeshEndpoint`] is what the driver that owns the radio
//! holds. Between them they reconcile the two differences between a wire
//! and the binding:
//!
//! - **Transaction identifiers.** A wire correlates a response to its
//!   request by TID. The binding requires TID 0 on every frame and
//!   correlates by envelope token instead, so requests go out with their
//!   TID cleared and replies come back wearing the one their request
//!   carried.
//! - **Reset-class commands.** `CMD_RST`, `CMD_RESTORE` and
//!   `CMD_FACTORY_RESET` are answered over the binding by no payload at
//!   all — delivery is the acknowledgment. A local device announces its
//!   new status instead, and callers wait for that announcement, so this
//!   synthesizes the announcement the device would have sent.
//!
//!   One consequence is worth knowing about. The exchange engine decides
//!   a command is reset-class by reading the *request*, and settles it as
//!   soon as the acknowledgment lands — before any reply is drained. A
//!   `CMD_RESTORE` that the device refuses for want of a snapshot does
//!   answer, with `STATUS_INVALID_STATE`, and that answer loses the race:
//!   the caller is told the restore completed. Reading
//!   `PROP_LAST_STATUS` in a later exchange is how the spec says to find
//!   out what actually happened, and it remains the way to tell these two
//!   apart over the mesh.
//!
//! Everything else the binding refuses — the host domain, session state,
//! the private key — it refuses as `STATUS_PROP_NOT_FOUND`, which is an
//! answer and needs no help from here.

use tokio::sync::mpsc;

use umsh_node_mgmt::admin::Failure;
use umsh_ulcp::Status;
use umsh_ulcp::frame::{self, Cmd, Frame, HEADER_FLG_PATTERN, HEADER_TID_MASK, TID_UNSOLICITED};

use crate::ulcp::{FrameLink, UlcpError};

/// Largest synthesized frame: a header, a command, and a status.
const SYNTHETIC_BUF: usize = 8;

/// Why an exchange produced no frame to hand back.
///
/// A fault is per-request, not terminal — the link stays usable for the
/// next command — except [`MeshFault::Radio`], which ends the session
/// because the radio underneath it is gone.
#[derive(Clone, Debug)]
pub enum MeshFault {
    /// The exchange failed, already rendered as prose for whoever is
    /// holding the tool.
    Exchange(String),
    /// The request is larger than one Node Management payload carries.
    RequestTooLarge(usize),
    /// The borrowed radio stopped answering; the session is over.
    Radio(String),
}

impl From<MeshFault> for UlcpError {
    fn from(fault: MeshFault) -> Self {
        match fault {
            // Not `Timeout`: the prose is the actionable part, and a
            // bare timeout would throw it away.
            MeshFault::Exchange(message) | MeshFault::Radio(message) => Self::Transport(message),
            MeshFault::RequestTooLarge(len) => Self::FrameTooLarge(len),
        }
    }
}

/// One request the driver is to carry, and the bookkeeping needed to
/// deliver its outcome.
#[derive(Clone, Debug)]
pub struct MeshRequest {
    /// The request frame, its TID already cleared for the binding.
    frame: Vec<u8>,
    /// The TID the caller used, and the one its reply must wear.
    tid: u8,
    /// The command, when it is one this crate defines. `None` is not an
    /// error — the binding carries whatever the caller encoded.
    cmd: Option<Cmd>,
}

impl MeshRequest {
    /// The frame to put on the air, with TID 0 as the binding requires.
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Whether the binding answers this command with no payload, so a
    /// caller can tell an expected silence from a lost exchange.
    pub fn is_reset_class(&self) -> bool {
        matches!(
            self.cmd,
            Some(Cmd::Reset | Cmd::Restore | Cmd::FactoryReset)
        )
    }
}

/// How an exchange ended.
#[derive(Clone, Copy, Debug)]
pub enum DeliveredOutcome<'a> {
    /// The device answered with this reply payload.
    Replied(&'a [u8]),
    /// The device answered nothing, its delivery acknowledged.
    NoResponse,
    /// The exchange failed.
    Failed(Failure),
}

/// Build a mesh link and the endpoint that serves it.
pub fn mesh_link() -> (MeshFrameLink, MeshEndpoint) {
    let (request_tx, request_rx) = mpsc::unbounded_channel();
    let (reply_tx, reply_rx) = mpsc::unbounded_channel();
    (
        MeshFrameLink {
            requests: request_tx,
            replies: reply_rx,
        },
        MeshEndpoint {
            requests: request_rx,
            replies: reply_tx,
        },
    )
}

/// The device handle's half: a [`FrameLink`] whose wire is an
/// administrative exchange.
pub struct MeshFrameLink {
    requests: mpsc::UnboundedSender<Vec<u8>>,
    replies: mpsc::UnboundedReceiver<Result<Vec<u8>, MeshFault>>,
}

impl FrameLink for MeshFrameLink {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), UlcpError> {
        self.requests
            .send(frame.to_vec())
            .map_err(|_| UlcpError::Disconnected)
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, UlcpError>> {
        self.replies.poll_recv(cx).map(|received| match received {
            Some(Ok(frame)) => Ok(frame),
            Some(Err(fault)) => Err(fault.into()),
            // The driver is gone, and with it the radio.
            None => Err(UlcpError::Disconnected),
        })
    }
}

/// The driver's half: requests to carry, and outcomes to report.
pub struct MeshEndpoint {
    requests: mpsc::UnboundedReceiver<Vec<u8>>,
    replies: mpsc::UnboundedSender<Result<Vec<u8>, MeshFault>>,
}

impl MeshEndpoint {
    /// The next request to carry, or `None` once the link is dropped and
    /// everything already queued has been handed over.
    ///
    /// A request too large for one payload is refused here rather than
    /// reaching the exchange engine, so the caller sees the size it
    /// asked for named in the error.
    pub async fn next(&mut self) -> Option<MeshRequest> {
        loop {
            let mut frame = self.requests.recv().await?;
            let Ok(parsed) = Frame::parse(&frame) else {
                // A frame the grammar does not recognize cannot be
                // classified, tokenized, or answered. Nothing built on
                // this link produces one.
                self.report(Err(MeshFault::Exchange(
                    "the request is not a well-formed ULCP frame".into(),
                )));
                continue;
            };
            let tid = parsed.header.tid();
            let cmd = parsed.command();
            if frame.len() > umsh_node_mgmt::REQUEST_MAX {
                let len = frame.len();
                self.report(Err(MeshFault::RequestTooLarge(len)));
                continue;
            }
            // The binding requires TID 0 and correlates by token; the
            // reply wears the caller's TID again on the way back.
            frame[0] = HEADER_FLG_PATTERN;
            return Some(MeshRequest { frame, tid, cmd });
        }
    }

    /// Hand one exchange's outcome back to the device handle.
    pub fn deliver(&mut self, request: &MeshRequest, outcome: DeliveredOutcome<'_>) {
        match outcome {
            DeliveredOutcome::Replied(reply) => {
                let mut reply = reply.to_vec();
                if reply.is_empty() {
                    self.report(Err(MeshFault::Exchange(
                        "the device answered with an empty frame".into(),
                    )));
                    return;
                }
                reply[0] = HEADER_FLG_PATTERN | (request.tid & HEADER_TID_MASK);
                self.report(Ok(reply));
            }
            DeliveredOutcome::NoResponse => self.synthesize(request),
            DeliveredOutcome::Failed(failure) => {
                self.report(Err(MeshFault::Exchange(describe(failure))))
            }
        }
    }

    /// Report that this request could not be carried, without ending the
    /// session.
    ///
    /// For the failures that belong to one command rather than to the
    /// link — a request that ran out of patience, an engine that would
    /// not take it — where the next command may well succeed.
    pub fn refuse(&mut self, message: String) {
        self.report(Err(MeshFault::Exchange(message)));
    }

    /// Report a terminal failure and close the link. The device handle
    /// sees this fault once, then `Disconnected`.
    pub fn fail(self, fault: MeshFault) {
        let _ = self.replies.send(Err(fault));
    }

    /// Stand in for the announcement a local device would have made.
    ///
    /// Delivery was the acknowledgment; the caller is waiting on the
    /// status that a wire-attached device would have volunteered. It is
    /// sent unsolicited (TID 0), which is what the waiting caller
    /// watches for.
    fn synthesize(&mut self, request: &MeshRequest) {
        let status = match request.cmd {
            Some(Cmd::Reset) => Status::RESET_SOFTWARE,
            Some(Cmd::Restore) => Status::RESET_RESTORED,
            // A factory reset is not waited on at all: the device wipes
            // itself and reboots, and the link dropping is the report.
            Some(Cmd::FactoryReset) => return,
            // Unreachable in practice — the exchange engine only reports
            // `NoResponse` for the three above — but silence here would
            // hang the caller until its own timeout, which is a worse
            // way to learn about a bug.
            _ => {
                self.report(Err(MeshFault::Exchange(
                    "the device answered nothing where a reply was due".into(),
                )));
                return;
            }
        };
        let mut buf = [0u8; SYNTHETIC_BUF];
        match frame::last_status(&mut buf, TID_UNSOLICITED, status) {
            Ok(len) => self.report(Ok(buf[..len].to_vec())),
            Err(_) => self.report(Err(MeshFault::Exchange(
                "could not report the device's completion".into(),
            ))),
        }
    }

    /// A closed channel means the caller gave up on this request; the
    /// exchange still ran, and the next `next()` will end the loop.
    fn report(&mut self, outcome: Result<Vec<u8>, MeshFault>) {
        let _ = self.replies.send(outcome);
    }
}

/// What a failed exchange means to somebody holding the tool.
pub fn describe(failure: Failure) -> String {
    match failure {
        Failure::TimedOut => {
            "no answer — the device may be out of range, or this host may not be one of its \
             administrators"
                .into()
        }
        Failure::CursorInvalid => {
            "the device's state changed mid-read; run the command again".into()
        }
        Failure::TooLarge => "the answer is larger than this host reassembles".into(),
        Failure::Malformed => "the device's answer could not be read".into(),
        Failure::UnknownCriticalOption(number) => {
            format!("the device's answer carries option {number}, which this host does not know")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_ulcp::ids::prop;

    /// Drive one request through the endpoint and collect what the link
    /// is handed back.
    async fn round_trip(
        request: Vec<u8>,
        answer: impl FnOnce(&MeshRequest) -> Option<Vec<u8>>,
    ) -> (MeshFrameLink, Option<MeshRequest>) {
        let (mut link, mut endpoint) = mesh_link();
        link.send_frame(&request).await.unwrap();
        let carried = endpoint.next().await;
        if let Some(carried) = &carried {
            match answer(carried) {
                Some(reply) => endpoint.deliver(carried, DeliveredOutcome::Replied(&reply)),
                None => endpoint.deliver(carried, DeliveredOutcome::NoResponse),
            }
        }
        // Keep the endpoint alive past the reads the test makes.
        core::mem::forget(endpoint);
        (link, carried)
    }

    #[tokio::test]
    async fn the_binding_sees_tid_zero_and_the_caller_sees_its_own() {
        let mut buf = [0u8; 8];
        let len = frame::prop_get(&mut buf, 5, prop::DEV_NAME).unwrap();

        let (mut link, carried) = round_trip(buf[..len].to_vec(), |carried| {
            // What goes on the air carries TID 0, as the binding requires.
            assert_eq!(carried.frame()[0] & HEADER_TID_MASK, 0);
            // The device answers with TID 0 too.
            let mut reply = [0u8; 32];
            let len =
                frame::prop_is(&mut reply, TID_UNSOLICITED, prop::DEV_NAME, b"node\0").unwrap();
            Some(reply[..len].to_vec())
        })
        .await;

        assert!(!carried.unwrap().is_reset_class());
        let reply = link.recv_frame().await.unwrap();
        let parsed = Frame::parse(&reply).unwrap();
        // ... and comes back wearing the TID the caller allocated, which
        // is the only thing that files it as a response.
        assert_eq!(parsed.header.tid(), 5);
        assert_eq!(parsed.command(), Some(Cmd::PropIs));
    }

    #[tokio::test]
    async fn a_reset_is_answered_by_the_announcement_a_wire_would_have_carried() {
        let mut buf = [0u8; 8];
        let len = frame::reset(&mut buf, TID_UNSOLICITED).unwrap();

        let (mut link, carried) = round_trip(buf[..len].to_vec(), |_| None).await;

        assert!(carried.unwrap().is_reset_class());
        let reply = link.recv_frame().await.unwrap();
        let parsed = Frame::parse(&reply).unwrap();
        assert_eq!(parsed.header.tid(), TID_UNSOLICITED);
        assert_eq!(parsed.command(), Some(Cmd::PropIs));
        // The caller is waiting on a reset announcement; this is one.
        assert_eq!(
            umsh_ulcp::reply::status_of(&reply),
            Some(Status::RESET_SOFTWARE)
        );
    }

    #[tokio::test]
    async fn a_restore_that_reset_announces_the_snapshot_it_came_up_on() {
        let mut buf = [0u8; 8];
        let len = frame::restore(&mut buf, 3).unwrap();

        let (mut link, _) = round_trip(buf[..len].to_vec(), |_| None).await;

        let reply = link.recv_frame().await.unwrap();
        assert_eq!(
            umsh_ulcp::reply::status_of(&reply),
            Some(Status::RESET_RESTORED)
        );
    }

    #[tokio::test]
    async fn a_factory_reset_is_answered_by_nothing_at_all() {
        let mut buf = [0u8; 8];
        let len = frame::factory_reset(&mut buf, TID_UNSOLICITED).unwrap();
        let (mut link, _) = round_trip(buf[..len].to_vec(), |_| None).await;

        // The device wipes itself and reboots; there is nothing to wait
        // for, and nothing is sent.
        assert!(
            tokio::time::timeout(core::time::Duration::from_millis(50), link.recv_frame())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_refused_command_costs_the_session_nothing() {
        let (mut link, mut endpoint) = mesh_link();
        let mut buf = [0u8; 8];
        let len = frame::prop_get(&mut buf, 2, prop::DEV_NAME).unwrap();
        link.send_frame(&buf[..len]).await.unwrap();
        let carried = endpoint.next().await.unwrap();
        assert_eq!(carried.frame()[0] & HEADER_TID_MASK, 0);
        endpoint.refuse("gave up after 180 s".into());

        match link.recv_frame().await {
            Err(UlcpError::Transport(message)) => assert!(message.contains("gave up")),
            other => panic!("expected a transport fault, got {other:?}"),
        }
        // One command ran out of patience; the session did not. A radio
        // that has actually died is reported by `fail`, not by this.
        link.send_frame(&buf[..len]).await.unwrap();
        assert!(endpoint.next().await.is_some());
    }

    #[tokio::test]
    async fn a_request_too_large_for_one_payload_names_its_size() {
        let (mut link, mut endpoint) = mesh_link();
        let mut buf = vec![0u8; umsh_node_mgmt::REQUEST_MAX + 64];
        let oversize = vec![0xAAu8; umsh_node_mgmt::REQUEST_MAX];
        let len = frame::prop_set(&mut buf, 1, prop::DEV_NAME, &oversize).unwrap();
        link.send_frame(&buf[..len]).await.unwrap();

        // The request never reaches the air.
        assert!(
            tokio::time::timeout(core::time::Duration::from_millis(50), endpoint.next())
                .await
                .is_err()
        );
        match link.recv_frame().await {
            Err(UlcpError::FrameTooLarge(reported)) => assert_eq!(reported, len),
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_failed_exchange_keeps_its_prose_and_leaves_the_link_usable() {
        let (mut link, mut endpoint) = mesh_link();
        let mut buf = [0u8; 8];
        let len = frame::prop_get(&mut buf, 1, prop::DEV_NAME).unwrap();
        link.send_frame(&buf[..len]).await.unwrap();
        let carried = endpoint.next().await.unwrap();
        endpoint.deliver(&carried, DeliveredOutcome::Failed(Failure::TimedOut));

        match link.recv_frame().await {
            Err(UlcpError::Transport(message)) => assert!(message.contains("administrators")),
            other => panic!("expected a transport fault, got {other:?}"),
        }
        // The fault was about the request, not the link: the next one
        // goes out as usual.
        link.send_frame(&buf[..len]).await.unwrap();
        assert!(endpoint.next().await.is_some());
    }

    #[tokio::test]
    async fn losing_the_driver_disconnects_the_handle() {
        let (mut link, endpoint) = mesh_link();
        drop(endpoint);
        assert!(matches!(
            link.recv_frame().await,
            Err(UlcpError::Disconnected)
        ));
    }

    #[tokio::test]
    async fn a_terminal_radio_failure_is_reported_before_the_disconnect() {
        let (mut link, endpoint) = mesh_link();
        endpoint.fail(MeshFault::Radio("the radio stopped answering".into()));
        match link.recv_frame().await {
            Err(UlcpError::Transport(message)) => assert!(message.contains("stopped answering")),
            other => panic!("expected a transport fault, got {other:?}"),
        }
        assert!(matches!(
            link.recv_frame().await,
            Err(UlcpError::Disconnected)
        ));
    }
}
