//! Where a response frame can be cut, and which requests may be
//! continued.
//!
//! A read whose answer does not fit one payload is carried across several
//! exchanges by fragmenting the response frame's **trailing content**—
//! the value of a `CMD_PROP_IS`, or the entry list of a `CMD_PROP_ARE`.
//! Every fragment repeats the frame's leading bytes, so each is a
//! well-formed frame on its own, and the administrator recovers the whole
//! by concatenating the trailing parts in order.
//!
//! Both halves of the binding need the same answer to "where does the
//! trailing content start", so it lives here rather than in either.

use umsh_ulcp::frame::{Cmd, Frame};
use umsh_ulcp::pui;

/// Whether a cursor may continue a request bearing this command.
///
/// Reads only. A write sequence cannot be continued—resuming one would
/// mean deciding whether to apply its entries again—so a
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

/// The share of a reply one response carries: the frame's leading
/// `prefix` octets, then `take` octets of its trailing content beginning
/// `resume` octets in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cut {
    pub prefix: usize,
    pub resume: usize,
    pub take: usize,
    /// Trailing octets after this fragment. Zero ends the read.
    pub remaining: usize,
}

/// Cut the fragment of `reply` that begins `resume` octets into its
/// trailing content and fills at most `room` octets of frame.
///
/// A reply with no trailing content is all prefix: it fits or it does
/// not. `None` when the fragment cannot be carried at all—the leading
/// bytes alone overflow `room`, `resume` lies past the end, or what is
/// left over could never make progress.
pub(crate) fn cut(reply: &[u8], resume: usize, room: usize) -> Option<Cut> {
    let prefix = trailing_offset(reply).unwrap_or(reply.len());
    let available = reply.len().checked_sub(prefix)?.checked_sub(resume)?;
    let take = available.min(room.checked_sub(prefix)?);
    if take == 0 && available > 0 {
        return None;
    }
    Some(Cut {
        prefix,
        resume,
        take,
        remaining: available - take,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_ulcp::frame;
    use umsh_ulcp::ids::prop;

    #[test]
    fn a_reply_that_fits_is_carried_whole() {
        let mut reply = [0u8; 64];
        let len = frame::prop_is(&mut reply, 0, prop::DEV_PEERS, &[7; 32]).unwrap();
        let cut = cut(&reply[..len], 0, 64).unwrap();
        assert_eq!(cut.prefix + cut.take, len);
        assert_eq!(cut.remaining, 0);
    }

    #[test]
    fn a_reply_that_does_not_fit_is_cut_at_the_room() {
        let mut reply = [0u8; 64];
        let len = frame::prop_is(&mut reply, 0, prop::DEV_PEERS, &[7; 32]).unwrap();
        let prefix = trailing_offset(&reply[..len]).unwrap();

        let first = cut(&reply[..len], 0, prefix + 20).unwrap();
        assert_eq!(first.prefix, prefix);
        assert_eq!(first.take, 20);
        assert_eq!(first.remaining, 12);

        // The continuation resumes where the first left off, and this time
        // the rest fits.
        let rest = cut(&reply[..len], 20, prefix + 20).unwrap();
        assert_eq!(rest.resume, 20);
        assert_eq!(rest.take, 12);
        assert_eq!(rest.remaining, 0);
    }

    #[test]
    fn a_reply_without_trailing_content_fits_whole_or_not_at_all() {
        let mut reply = [0u8; 32];
        let len = frame::prop_inserted(&mut reply, 0, prop::DEV_PEERS, &[1, 2]).unwrap();
        let whole = cut(&reply[..len], 0, len).unwrap();
        assert_eq!((whole.prefix, whole.take, whole.remaining), (len, 0, 0));
        assert_eq!(cut(&reply[..len], 0, len - 1), None);
    }

    /// Positions this binding never issues, and rooms that could only
    /// produce empty fragments forever, are refused rather than served.
    #[test]
    fn a_cut_that_cannot_make_progress_is_refused() {
        let mut reply = [0u8; 64];
        let len = frame::prop_is(&mut reply, 0, prop::DEV_PEERS, &[7; 32]).unwrap();
        let prefix = trailing_offset(&reply[..len]).unwrap();
        assert_eq!(cut(&reply[..len], 33, 64), None, "past the end");
        assert_eq!(
            cut(&reply[..len], 0, prefix),
            None,
            "no room past the prefix"
        );
        assert_eq!(
            cut(&reply[..len], 0, prefix - 1),
            None,
            "the prefix overflows"
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
        // A status is a CMD_PROP_IS, so it does have trailing content—
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
