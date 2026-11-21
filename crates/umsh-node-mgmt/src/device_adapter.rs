//! Answering Node Management over the mesh, from a device.
//!
//! The device-side counterpart of `node_adapter` (with the `node` feature),
//! and like it free of any clock, transport, or task: the caller supplies
//! the time, hands each arriving packet to `admit`, and serves each
//! admitted frame through a closure, which is where its ULCP session is.
//!
//! `admit` (with the `receive` feature) is the binding's admission rule: a
//! Node Management Request, by unicast or blind unicast, from an
//! authenticated source that is a listed administrator or the host
//! identity. [`Responder`] runs the exchange around a [`DeviceEngine`]: a
//! retained answer needs no serving, a served reply is wrapped (a
//! reset-class command's into nothing at all), and a retained reply that
//! never went out is forgotten so a retransmission is served afresh.

#[cfg(feature = "receive")]
use umsh_core::{ChannelKey, PayloadType, PublicKey};
#[cfg(feature = "receive")]
use umsh_mac::{PacketFamily, ReceivedPacketRef};

use crate::device::{CACHE_ENTRIES, CompleteError, DeviceEngine, Dispatch, DropReason, Ingress};

/// Whether an authenticated request from `from` is heard: `Some(true)`
/// from a listed administrator, `Some(false)` from the host identity that
/// is not one, `None` from anyone else.
///
/// The host may revoke this radio over the mesh without being an
/// administrator; the session holds it to that one write.
pub fn authorize(from: &[u8; 32], admins: &[[u8; 32]], host: Option<&[u8; 32]>) -> Option<bool> {
    if admins.contains(from) {
        Some(true)
    } else if host == Some(from) {
        Some(false)
    } else {
        None
    }
}

/// Why an arriving packet is not served. Every refusal is silent on the
/// air: an unlisted sender learns nothing about whether the device is
/// manageable, not even that it declined to say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A Node Management Response, which a device never solicits.
    Response,
    /// A request by multicast or broadcast.
    NotUnicast,
    /// A request whose source is unauthenticated, or neither a listed
    /// administrator nor the host.
    Unauthorized,
    /// A request larger than the device can answer within. Dropped rather
    /// than truncated: a truncated envelope would be answered
    /// `STATUS_PARSE_ERROR`, which is a worse explanation than silence.
    Oversize,
}

/// A request the device will serve.
#[cfg(feature = "receive")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub from: [u8; 32],
    /// `from` is a listed administrator; otherwise it is the host.
    pub listed_admin: bool,
    /// The channel the request arrived on, when it came as a blind
    /// unicast. The response follows it back rather than naming both
    /// parties in the clear.
    pub channel: Option<ChannelKey>,
    /// The request's `ack_mic`, which the response carries back so the
    /// administrator's MAC can take the response as the acknowledgment
    /// should the standalone one be lost.
    pub ack_mic: Option<[u8; 4]>,
}

/// What the device does with an arriving packet.
#[cfg(feature = "receive")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Not Node Management; other observers have it.
    Ignored,
    Refused(Refusal),
    Admitted(Admitted),
}

/// Decide whether `packet` is a Node Management Request this device
/// serves. `authorize` answers for an authenticated source as [`authorize`]
/// does; it is asked only for a unicast request, so a caller whose lists
/// sit behind a lock takes it for those alone. A request is refused as
/// oversize past `payload_max` octets, the most the caller holds.
#[cfg(feature = "receive")]
pub fn admit(
    packet: &ReceivedPacketRef<'_>,
    authorize: impl FnOnce(&[u8; 32]) -> Option<bool>,
    payload_max: usize,
) -> Admission {
    match packet.payload_type() {
        PayloadType::NodeManagementRequest => {}
        // Misdirected, or an attempt to confuse the device.
        PayloadType::NodeManagementResponse => return Admission::Refused(Refusal::Response),
        _ => return Admission::Ignored,
    }
    if !matches!(
        packet.packet_family(),
        PacketFamily::Unicast | PacketFamily::BlindUnicast
    ) {
        return Admission::Refused(Refusal::NotUnicast);
    }
    // Both conditions matter and neither implies the other: an
    // unauthenticated source could claim any key, and an authenticated
    // one that is not listed is simply not an administrator here.
    let Some(PublicKey(from)) = packet.from_key().filter(|_| packet.source_authenticated()) else {
        return Admission::Refused(Refusal::Unauthorized);
    };
    let Some(listed_admin) = authorize(&from) else {
        return Admission::Refused(Refusal::Unauthorized);
    };
    if packet.payload().len() > payload_max {
        return Admission::Refused(Refusal::Oversize);
    }
    Admission::Admitted(Admitted {
        from,
        listed_admin,
        channel: packet.channel().map(|channel| *channel.key),
        ack_mic: packet.ack_mic(),
    })
}

/// What became of one admitted request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Nothing goes back, and nothing was served.
    Dropped(DropReason),
    /// `out[..len]` is the response payload, or nothing goes back where
    /// the length is `None`: a reset-class command, whose delivery the MAC
    /// acknowledgment of the request confirmed.
    Respond(Option<usize>),
    /// The session's reply cannot be carried: only a read this device
    /// cannot hold gets here. Nothing goes out, and the read runs again on
    /// the administrator's retransmission.
    Unanswerable(CompleteError),
}

/// A device's side of Node Management: the engine that correlates,
/// retains, and continues, around the caller's session.
pub struct Responder<const PAYLOAD: usize, const POOL: usize, const ENTRIES: usize = CACHE_ENTRIES>
{
    engine: DeviceEngine<PAYLOAD, POOL, ENTRIES>,
}

impl<const PAYLOAD: usize, const POOL: usize, const ENTRIES: usize>
    Responder<PAYLOAD, POOL, ENTRIES>
{
    /// `nonce` is drawn once per boot from a cryptographic source. It is
    /// what stops a cursor issued before a reboot from being honored after
    /// one, when the engine's serials have started over.
    pub fn new(nonce: u16) -> Self {
        Self {
            engine: DeviceEngine::new(nonce),
        }
    }

    /// Serve one admitted request from `from`, through `serve` when the
    /// session has to be reached. `serve` answers with the session's reply
    /// frame: empty for a reset-class command, and for anything the
    /// session declined to answer.
    pub fn exchange<R: AsRef<[u8]>>(
        &mut self,
        from: &[u8; 32],
        payload: &[u8],
        now_ms: u64,
        out: &mut [u8],
        serve: impl FnOnce(&Dispatch<'_>) -> R,
    ) -> Answer {
        match self.begin(from, payload, now_ms, out) {
            Ingress::Drop(reason) => Answer::Dropped(reason),
            Ingress::Respond { len } => Answer::Respond(Some(len)),
            Ingress::Dispatch(dispatch) => {
                let served = serve(&dispatch);
                match self.complete(served.as_ref(), out) {
                    Ok(len) => Answer::Respond(len),
                    Err(error) => Answer::Unanswerable(error),
                }
            }
        }
    }

    /// [`Self::exchange`] in two halves, for a caller that reaches its
    /// session by awaiting: on [`Ingress::Dispatch`], serve the frame and
    /// hand its reply to [`Self::complete`].
    ///
    /// The firmware's responder serves this way rather than through an
    /// async closure, which would nest a second state machine in its task
    /// at a flash cost the tightest images cannot spare.
    pub fn begin<'p>(
        &mut self,
        from: &[u8; 32],
        payload: &'p [u8],
        now_ms: u64,
        out: &mut [u8],
    ) -> Ingress<'p> {
        self.engine.begin(from, payload, now_ms, out)
    }

    /// Wrap the session's reply to the frame [`Self::begin`] dispatched:
    /// the response payload is `out[..len]`, or nothing goes back where
    /// `len` is `None`.
    pub fn complete(
        &mut self,
        reply: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, CompleteError> {
        self.engine.complete(reply, out)
    }

    /// The response to `payload` from `from` never went out. A reply
    /// retained for it is forgotten, so a retransmission is served afresh
    /// rather than answered with what nobody received.
    pub fn unsent(&mut self, from: &[u8; 32], payload: &[u8]) {
        if let [first, second, ..] = *payload {
            self.engine.fail_retained(from, [first, second]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMIN: [u8; 32] = [0xA1; 32];
    const HOST: [u8; 32] = [0xC4; 32];
    const STRANGER: [u8; 32] = [0x55; 32];

    #[test]
    fn the_host_is_heard_beside_the_administrators() {
        let admins = [ADMIN];
        assert_eq!(authorize(&ADMIN, &admins, Some(&HOST)), Some(true));
        assert_eq!(authorize(&HOST, &admins, Some(&HOST)), Some(false));
        assert_eq!(authorize(&STRANGER, &admins, Some(&HOST)), None);
        // With no host configured, only administrators are heard.
        assert_eq!(authorize(&HOST, &admins, None), None);
        assert_eq!(authorize(&ADMIN, &admins, None), Some(true));
        // A host that is also listed is heard as an administrator.
        assert_eq!(authorize(&HOST, &[HOST], Some(&HOST)), Some(true));
    }
}
