//! The device half of the Node Management binding, in front of the real
//! session: what firmware's responder does, in the order it does it.

use umsh_node_mgmt::device::{DeviceEngine, Ingress};
use umsh_node_mgmt::envelope::Envelope;
use umsh_ulcp::frame::Cmd;
use umsh_ulcp_device::MULTI_MAX;
use umsh_ulcp_simdev::soft::SoftDevice;

use crate::device::{self, FaultyPlatform};
use crate::fixup::cast;
use crate::script::{Fields, records};

/// What one Node Management payload carries, as on an nRF board.
pub const PAYLOAD: usize = 180;

pub const OP_REQUEST: u8 = 0;
pub const OP_FAIL: u8 = 1;
const OPS: u8 = 2;

pub type Engine = DeviceEngine<PAYLOAD, { 2 * MULTI_MAX }, 2>;

/// Serve one payload from a listed administrator, returning the response
/// payload, if there is one, and, if the session executed a frame, whether
/// that frame is one a retransmission may run again.
pub fn serve(
    engine: &mut Engine,
    device: &mut SoftDevice<FaultyPlatform>,
    from: &[u8; 32],
    payload: &[u8],
    now_ms: u64,
) -> (Option<Vec<u8>>, Option<bool>) {
    let mut out = [0u8; PAYLOAD];
    let dispatch = match engine.begin(from, payload, now_ms, &mut out) {
        Ingress::Drop(_) => return (None, None),
        Ingress::Respond { len } => {
            assert!(Envelope::parse(&out[..len]).is_ok(), "a retained reply");
            return (Some(out[..len].to_vec()), None);
        }
        Ingress::Dispatch(dispatch) => dispatch,
    };
    let frame = dispatch.frame.to_vec();
    let (budget, resets) = (dispatch.budget, dispatch.resets);
    // Running either of these again is harmless, and a reset forgets what
    // it would be answered from.
    let repeatable = resets || matches!(dispatch.command(), Some(Cmd::PropGet | Cmd::PropMultiGet));
    let answers = device.admin_request(&frame, budget, now_ms);
    assert!(
        answers.len() <= 1,
        "one exchange, one answer: {answers:02x?}"
    );
    if answers.is_empty() {
        assert!(resets, "only a reset goes unanswered: {frame:02x?}");
    }
    let reply = answers.first().map(Vec::as_slice).unwrap_or(&[]);
    match engine.complete(reply, &mut out) {
        Ok(Some(len)) => {
            assert!(Envelope::parse(&out[..len]).is_ok(), "a fresh reply");
            (Some(out[..len].to_vec()), Some(repeatable))
        }
        // A reply this device cannot carry goes out as nothing, and the
        // administrator retransmits.
        Ok(None) | Err(_) => (None, Some(repeatable)),
    }
}

pub fn run(data: &[u8]) {
    let (mut device, _) = device::soft_device();
    let mut engine = Engine::new(0x5A5A);
    let cast = cast();
    let mut now_ms = 1;
    for record in records(data) {
        let mut fields = Fields::new(record.body);
        let from = &cast.parties[usize::from(fields.u8()) % 2].key.0;
        now_ms += u64::from(fields.u16());
        match record.op % OPS {
            OP_REQUEST => {
                serve(&mut engine, &mut device, from, fields.rest(), now_ms);
            }
            _ => engine.fail_retained(from, [fields.u8(), fields.u8()]),
        }
    }
}
