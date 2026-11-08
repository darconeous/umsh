//! What the `EMERGENCY` channel asks of a receiver beyond any other
//! channel (`app-text-messages.md` §Test Messages).

/// The canonical name of the `EMERGENCY` channel, after case folding.
pub const CHANNEL_NAME: &str = umsh_core::EMERGENCY_CHANNEL_NAME;

/// What a test message's body begins with, in any letter case.
const TEST_PREFIX: &[u8] = b"test:";

/// Whether `body`, the text of a message on `EMERGENCY`, marks it as a
/// test message: after any leading whitespace, it begins with `TEST:` in
/// any letter case.
///
/// `body` may be a first fragment, cut partway through a character: only
/// its beginning decides.
pub fn is_test_body(body: &[u8]) -> bool {
    let text = match core::str::from_utf8(body) {
        Ok(text) => text,
        Err(error) => core::str::from_utf8(&body[..error.valid_up_to()]).unwrap_or_default(),
    };
    text.trim_start()
        .as_bytes()
        .get(..TEST_PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(TEST_PREFIX))
}

#[cfg(test)]
mod tests {
    use super::is_test_body;

    #[test]
    fn a_test_body_begins_with_test_in_any_case() {
        for body in [
            "TEST: radio check",
            "test:",
            "Test:x",
            "  \n\tTEST: indented",
            "\u{3000}TeSt:",
        ] {
            assert!(is_test_body(body.as_bytes()), "{body:?}");
        }
    }

    #[test]
    fn anything_else_is_not_a_test() {
        for body in [
            "",
            "TEST",
            "TESTING: one two",
            "TEST :",
            "x TEST:",
            "Fire at TEST: road",
            "TES",
        ] {
            assert!(!is_test_body(body.as_bytes()), "{body:?}");
        }
    }

    #[test]
    fn a_fragment_cut_mid_character_is_read_up_to_the_cut() {
        let body = "TEST: café".as_bytes();
        assert!(is_test_body(&body[..body.len() - 1]));
        let leading = "é TEST:".as_bytes();
        assert!(!is_test_body(&leading[..1]));
    }
}
