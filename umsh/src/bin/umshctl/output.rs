//! Shared presentation: the colour decision, the field-tinted styling
//! the capture decoder needs, and the key/value report layout every
//! command prints.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

/// When decoded output carries ANSI colour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    #[default]
    Auto,
    #[value(alias = "yes")]
    Always,
    #[value(alias = "no")]
    Never,
}

impl ColorChoice {
    /// Resolve to a concrete answer for this run. `auto` honours a
    /// non-terminal stdout (a pipe or a redirect to a log), `NO_COLOR`,
    /// and `TERM=dumb`.
    pub fn enabled(self) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => {
                std::io::stdout().is_terminal()
                    && std::env::var_os("NO_COLOR").is_none()
                    && std::env::var("TERM").is_ok_and(|term| term != "dumb")
            }
        }
    }
}

/// Resolved once at startup so every module can ask without threading a
/// flag through call after call. A tool this shape has exactly one
/// output stream and one answer for it.
static COLOR: AtomicBool = AtomicBool::new(false);

pub fn set_color(enabled: bool) {
    COLOR.store(enabled, Ordering::Relaxed);
}

pub fn color() -> bool {
    COLOR.load(Ordering::Relaxed)
}

/// Wrap `text` in the given SGR parameters, or return it unchanged when
/// the output is not colorized.
pub fn styled(text: &str, sgr: &str, color: bool) -> String {
    if color {
        format!("\x1b[{sgr}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// Column at which a report's values line up. Wide enough for the
/// longest label a report prints (`capabilities:`).
const LABEL_WIDTH: usize = 14;

/// One line of a key/value report: `label:` in the left column, value in
/// the right.
pub fn field(label: &str, value: impl std::fmt::Display) {
    println!("{:<LABEL_WIDTH$}{value}", format!("{label}:"));
}

/// A nested line of a key/value report, indented under its parent.
pub fn subfield(label: &str, value: impl std::fmt::Display) {
    println!("  {:<width$}{value}", format!("{label}:"), width = 14);
}

/// A note about what the tool just did, or declined to do. Stays on
/// stdout with the rest of the report; failures go through `Err`.
pub fn note(text: impl std::fmt::Display) {
    println!("note: {text}");
}

/// Something the user is likely to have gotten wrong, which did not stop
/// the command from succeeding.
pub fn warn(text: impl std::fmt::Display) {
    eprintln!("warning: {text}");
}

/// Lowercase hex, no separators — the form every digest, id, and key in
/// this tool's output uses.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_choice_resolves_the_unconditional_forms() {
        assert!(ColorChoice::Always.enabled());
        assert!(!ColorChoice::Never.enabled());
    }

    #[test]
    fn styling_is_inert_without_color() {
        assert_eq!(styled("x", "1;97", false), "x");
        assert_eq!(styled("x", "1;97", true), "\x1b[1;97mx\x1b[0m");
    }

    #[test]
    fn hex_has_no_separators() {
        assert_eq!(hex(&[0x0a, 0xff]), "0aff");
        assert_eq!(hex(&[]), "");
    }
}
