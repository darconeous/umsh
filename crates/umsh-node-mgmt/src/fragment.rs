//! Where a response frame can be cut, and which requests may be
//! continued.
//!
//! A read whose answer does not fit one payload is carried across several
//! exchanges by fragmenting the response frame's **trailing content** —
//! the value of a `CMD_PROP_IS`, or the entry list of a `CMD_PROP_ARE`.
//! Every fragment repeats the frame's leading bytes, so each is a
//! well-formed frame on its own, and the administrator recovers the whole
//! by concatenating the trailing parts in order.
//!
//! Both halves of the binding need the same answer to "where does the
//! trailing content start", so it lives here rather than in either.

use umsh_ulcp::frame::{Cmd, Frame};
use umsh_ulcp::pui;

use crate::device::{Dispatch, Produced};

/// Whether a cursor may continue a request bearing this command.
///
/// Reads only. A write sequence cannot be continued — resuming one would
/// mean deciding whether to apply its entries again — so a
/// `CMD_PROP_MULTI_SET` whose reply does not fit stops instead, and the
/// administrator reissues the remainder as a new exchange.
pub const fn continuable(cmd: Cmd) -> bool {
    matches!(cmd, Cmd::PropGet | Cmd::PropMultiGet)
}

/// Where `frame`'s trailing content begins, or `None` for a frame that
/// has none and so cannot be fragmented.
///
/// A frame with no trailing content is one that either fits or does not:
/// a status, an insert or remove acknowledgment. None of them approach a
/// payload's size.
pub fn trailing_offset(frame: &[u8]) -> Option<usize> {
    let parsed = Frame::parse(frame).ok()?;
    let offset = frame.len().checked_sub(parsed.payload.len())?;
    match parsed.command()? {
        // header, command, and the property key.
        Cmd::PropIs => {
            let (_, consumed) = pui::decode(parsed.payload).ok()?;
            Some(offset + consumed)
        }
        // header and command; the entry list is the whole payload.
        Cmd::PropAre => Some(offset),
        _ => None,
    }
}

/// `frame`'s trailing content, empty for a frame that has none.
pub fn trailing(frame: &[u8]) -> &[u8] {
    match trailing_offset(frame) {
        Some(offset) => &frame[offset..],
        None => &[],
    }
}

/// Cut a whole reply down to the fragment one exchange carries.
///
/// `reply` is what the local dispatch produced, which for a continuable
/// read may be larger than a payload holds. The result is the frame's
/// leading bytes followed by the slice of its trailing content beginning
/// at `dispatch.resume`, sized to `dispatch.budget` and to `buf`.
///
/// A reply the caller cannot cut — one with no trailing content — is
/// copied through whole. If it does not fit, that is not this function's
/// to hide: [`DeviceEngine::complete`](crate::device::DeviceEngine::complete)
/// refuses it.
pub fn produce<'b>(reply: &[u8], dispatch: &Dispatch<'_>, buf: &'b mut [u8]) -> Produced<'b> {
    if reply.is_empty() {
        return Produced::no_response();
    }
    let Some(offset) = trailing_offset(reply) else {
        let len = reply.len().min(buf.len());
        buf[..len].copy_from_slice(&reply[..len]);
        return Produced::complete(&buf[..len]);
    };
    let (prefix, trailing) = reply.split_at(offset);
    let prefix_len = prefix.len().min(buf.len());
    // A cursor pointing past the end yields an empty last fragment, which
    // ends the read rather than failing it.
    let resume = (dispatch.resume as usize).min(trailing.len());
    let available = trailing.len() - resume;
    let room = dispatch
        .budget
        .saturating_sub(prefix_len)
        .min(buf.len() - prefix_len);
    let take = available.min(room);
    let end = prefix_len + take;
    buf[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
    buf[prefix_len..end].copy_from_slice(&trailing[resume..resume + take]);
    Produced::fragment(&buf[..end], take as u32, (available - take) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_ulcp::frame;
    use umsh_ulcp::ids::prop;

    /// A dispatch of the shape `produce` reads: only the cursor position
    /// and the budget matter to it.
    fn dispatch(resume: u32, budget: usize) -> Dispatch<'static> {
        Dispatch {
            frame: &[],
            resume,
            budget,
            resets: false,
        }
    }

    #[test]
    fn a_reply_that_fits_is_carried_whole() {
        let mut reply = [0u8; 64];
        let len = frame::prop_is(&mut reply, 0, prop::DEV_PEERS, &[7; 32]).unwrap();
        let mut buf = [0u8; 64];
        let produced = produce(&reply[..len], &dispatch(0, 64), &mut buf);
        assert_eq!(produced.frame, &reply[..len]);
        assert_eq!(produced.remaining, 0);
    }

    #[test]
    fn a_reply_that_does_not_fit_is_cut_at_the_budget() {
        let mut reply = [0u8; 64];
        let len = frame::prop_is(&mut reply, 0, prop::DEV_PEERS, &[7; 32]).unwrap();
        let prefix = trailing_offset(&reply[..len]).unwrap();

        let mut buf = [0u8; 64];
        let first = produce(&reply[..len], &dispatch(0, prefix + 20), &mut buf);
        assert_eq!(first.produced, 20);
        assert_eq!(first.remaining, 12);
        assert_eq!(&first.frame[..prefix], &reply[..prefix]);
        assert_eq!(&first.frame[prefix..], &[7; 20]);

        // The continuation resumes where the first left off, and this time
        // the rest fits.
        let mut buf = [0u8; 64];
        let rest = produce(&reply[..len], &dispatch(20, prefix + 20), &mut buf);
        assert_eq!(rest.produced, 12);
        assert_eq!(rest.remaining, 0);
        assert_eq!(&rest.frame[prefix..], &[7; 12]);
    }

    /// The buffer is a second ceiling, and the smaller of the two wins.
    #[test]
    fn the_buffer_bounds_the_cut_as_much_as_the_budget_does() {
        let mut reply = [0u8; 64];
        let len = frame::prop_is(&mut reply, 0, prop::DEV_PEERS, &[7; 32]).unwrap();
        let prefix = trailing_offset(&reply[..len]).unwrap();
        let mut buf = [0u8; 16];
        let produced = produce(&reply[..len], &dispatch(0, 1024), &mut buf);
        assert_eq!(produced.frame.len(), 16);
        assert_eq!(produced.produced as usize, 16 - prefix);
        assert_eq!(produced.remaining as usize, 32 - (16 - prefix));
    }

    /// A cursor at or past the end is answered by an empty last fragment,
    /// which ends the read rather than failing it.
    #[test]
    fn a_cursor_past_the_end_ends_the_read() {
        let mut reply = [0u8; 64];
        let len = frame::prop_is(&mut reply, 0, prop::DEV_PEERS, &[7; 32]).unwrap();
        let prefix = trailing_offset(&reply[..len]).unwrap();
        let mut buf = [0u8; 64];
        let produced = produce(&reply[..len], &dispatch(99, 64), &mut buf);
        assert_eq!(produced.frame.len(), prefix);
        assert_eq!(produced.produced, 0);
        assert_eq!(produced.remaining, 0);
    }

    #[test]
    fn an_empty_reply_is_a_reset() {
        let mut buf = [0u8; 8];
        assert_eq!(
            produce(&[], &dispatch(0, 64), &mut buf),
            Produced::no_response()
        );
    }

    #[test]
    fn a_prop_is_is_cut_after_its_key() {
        let mut buf = [0u8; 64];
        let len = frame::prop_is(&mut buf, 0, prop::DEV_PEERS, &[7; 32]).unwrap();
        assert_eq!(trailing(&buf[..len]), &[7; 32]);
    }

    #[test]
    fn a_prop_are_is_cut_after_its_command() {
        // Header and command only; the rest is the entry list.
        let entries = [0x03, 0x05, 0x01, 0x02];
        let mut buf = [0u8; 16];
        buf[0] = 0x80;
        buf[1] = Cmd::PropAre as u8;
        buf[2..2 + entries.len()].copy_from_slice(&entries);
        assert_eq!(trailing(&buf[..2 + entries.len()]), &entries);
    }

    #[test]
    fn everything_else_has_no_trailing_content() {
        let mut buf = [0u8; 32];
        let len = frame::last_status(&mut buf, 0, umsh_ulcp::status::Status::OK).unwrap();
        // A status is a CMD_PROP_IS, so it does have trailing content —
        // it is simply always short enough to fit.
        assert!(!trailing(&buf[..len]).is_empty());

        let len = frame::prop_inserted(&mut buf, 0, prop::DEV_PEERS, &[1, 2]).unwrap();
        assert!(trailing(&buf[..len]).is_empty());
        assert_eq!(trailing_offset(&buf[..len]), None);
    }

    #[test]
    fn only_reads_may_be_continued() {
        assert!(continuable(Cmd::PropGet));
        assert!(continuable(Cmd::PropMultiGet));
        assert!(!continuable(Cmd::PropMultiSet));
        assert!(!continuable(Cmd::PropSet));
        assert!(!continuable(Cmd::Save));
    }
}
