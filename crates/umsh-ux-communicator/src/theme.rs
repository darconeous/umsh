//! Colors and type sizes shared by every screen.
//!
//! The palette is the T-LoRa Pager mockup's: a near-black background, so
//! the emissive panel spends little on what is not content.

use embedded_graphics::pixelcolor::Rgb565;

/// A 24-bit `0xRRGGBB` color, truncated to the panel's format.
const fn rgb(hex: u32) -> Rgb565 {
    Rgb565::new(
        (hex >> 19) as u8 & 0x1f,
        (hex >> 10) as u8 & 0x3f,
        (hex >> 3) as u8 & 0x1f,
    )
}

pub const BACKGROUND: Rgb565 = rgb(0x0B0D10);
pub const CHROME: Rgb565 = rgb(0x0E1115);
pub const LINE: Rgb565 = rgb(0x20252C);
pub const TEXT: Rgb565 = rgb(0xEEF1F5);
pub const TEXT_SECONDARY: Rgb565 = rgb(0x9AA3AE);
pub const TEXT_TERTIARY: Rgb565 = rgb(0x7F8995);
/// The disc of an emoji the set lacks, and the badge of a flag's code.
pub const PLACEHOLDER: Rgb565 = rgb(0x6B7480);
pub const ACCENT: Rgb565 = rgb(0x4DA3FF);
/// The accent where anyone can read what is written: an open channel.
pub const ACCENT_OPEN: Rgb565 = GREEN;
/// The accent where what is written goes under forward secrecy.
pub const ACCENT_SECRET: Rgb565 = rgb(0xA585FF);
pub const FOCUS: Rgb565 = rgb(0x18304D);
/// My messages where only those holding the key can read them.
pub const OUTBOUND: Rgb565 = rgb(0x2A62C9);
/// My messages in an open channel, which anyone can read.
pub const OUTBOUND_OPEN: Rgb565 = rgb(0x1E7B45);
/// My messages sent under a session with forward secrecy.
pub const OUTBOUND_SECRET: Rgb565 = rgb(0x7045CC);
pub const INBOUND: Rgb565 = rgb(0x23272E);
/// A reply's quote inside one of my bubbles: its bar, whom it quotes, and
/// what.
pub const QUOTE_BAR_MINE: Rgb565 = rgb(0xCFE0FF);
pub const QUOTE_NAME_MINE: Rgb565 = rgb(0xE4EDFF);
pub const QUOTE_TEXT_MINE: Rgb565 = rgb(0xC9D8F5);
/// The same, in tints of [`OUTBOUND_SECRET`].
pub const QUOTE_BAR_SECRET: Rgb565 = rgb(0xDDD0FF);
pub const QUOTE_NAME_SECRET: Rgb565 = rgb(0xECE4FF);
pub const QUOTE_TEXT_SECRET: Rgb565 = rgb(0xD6CCF5);
/// The faintest of the dots in the place of a message on its way again.
pub const GAP_DOT: Rgb565 = rgb(0x4B535E);
pub const GREEN: Rgb565 = rgb(0x3DD68C);
pub const AMBER: Rgb565 = rgb(0xF5B544);
pub const RED: Rgb565 = rgb(0xFF6B5E);
pub const FIELD: Rgb565 = rgb(0x161A20);
/// A field while it is edited, while it is edited in an open channel, and
/// while what it sends goes under forward secrecy.
pub const ACTIVE_FIELD: Rgb565 = rgb(0x1A2333);
pub const ACTIVE_FIELD_OPEN: Rgb565 = rgb(0x152B1F);
pub const ACTIVE_FIELD_SECRET: Rgb565 = rgb(0x221A36);
/// A switch that is off, and its knob.
pub const SWITCH_OFF: Rgb565 = rgb(0x3A414B);
pub const KNOB_OFF: Rgb565 = rgb(0xC9CED6);
/// A card that is not focused.
pub const PANEL: Rgb565 = rgb(0x11151A);
pub const MENU: Rgb565 = rgb(0x1B2027);
/// The Alt key's orange, which its legends and its strip icon share.
pub const ALT: Rgb565 = rgb(0xF5A524);
/// A glance: a brief card for a setting changed from the keyboard.
pub const GLANCE: Rgb565 = rgb(0x1E2631);
pub const GLANCE_LINE: Rgb565 = rgb(0x34414F);
/// A level bar's unlit steps.
pub const LEVEL_OFF: Rgb565 = rgb(0x3A414B);
pub const MENU_LINE: Rgb565 = rgb(0x2E3540);
/// Behind each reaction in the actions menu's palette.
pub const REACTION_PAD: Rgb565 = rgb(0x2A313B);
/// A reaction chip of someone else's; mine is in [`OUTBOUND`], or
/// [`OUTBOUND_OPEN`] in an open channel.
pub const CHIP_THEIRS: Rgb565 = rgb(0x323A45);
/// A banner for a message that arrived elsewhere, and its edge.
pub const BANNER: Rgb565 = rgb(0x1E2631);
pub const BANNER_LINE: Rgb565 = rgb(0x34414F);

/// A nearness arc not lit.
pub const NEAR_UNLIT: Rgb565 = rgb(0x3A414B);

/// A contact-exchange session color, given as `0xRRGGBB`.
#[must_use]
pub const fn session(color: u32) -> Rgb565 {
    rgb(color)
}
