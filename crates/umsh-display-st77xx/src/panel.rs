//! What sets one board's panel apart from another's.

use crate::framebuffer::STRIPE_ROWS;

/// A board's panel, landscape, as the driver addresses it.
pub struct PanelSpec {
    pub width: u16,
    pub height: u16,
    /// Where the landscape window starts in the controller's memory, once
    /// the init list's MADCTL has rotated it.
    pub column_offset: u16,
    pub row_offset: u16,
    /// Sent after sleep out, in order: orientation, color format,
    /// voltages, gamma, inversion.
    pub init: &'static [(u8, &'static [u8])],
}

impl PanelSpec {
    /// A whole frame, RGB565.
    pub const fn frame_bytes(&self) -> usize {
        self.width as usize * self.height as usize * 2
    }
    /// Stripes in a frame; the last may be short.
    pub const fn stripes(&self) -> usize {
        (self.height as usize).div_ceil(STRIPE_ROWS)
    }
    /// The most one stripe can be.
    pub const fn stripe_bytes(&self) -> usize {
        self.width as usize * STRIPE_ROWS * 2
    }
}

/// The T-LoRa Pager's ST7796: a 222-row landscape window on a 320×480
/// panel. Board-specific settings from LilyGo's panel initialization.
pub const ST7796_PAGER: PanelSpec = PanelSpec {
    width: 480,
    height: 222,
    column_offset: 0,
    // Landscape rotation maps the portrait column offset to the Y address.
    row_offset: 49,
    init: &[
        (0xf0, &[0xc3]),
        (0xf0, &[0x96]),
        (0x36, &[0xe8]),
        (0x3a, &[0x55]),
        (0xb4, &[1]),
        (0xb6, &[0x80, 2, 0x3b]),
        (0xe8, &[0x40, 0x8a, 0, 0, 0x29, 0x19, 0xa5, 0x33]),
        (0xc1, &[6]),
        (0xc2, &[0xa7]),
        (0xc5, &[0x18]),
        (
            0xe0,
            &[
                0xf0, 9, 0x0b, 6, 4, 0x15, 0x2f, 0x54, 0x42, 0x3c, 0x17, 0x14, 0x18, 0x1b,
            ],
        ),
        (
            0xe1,
            &[
                0xe0, 9, 0x0b, 6, 4, 3, 0x2b, 0x43, 0x42, 0x3b, 0x16, 0x14, 0x17, 0x1b,
            ],
        ),
        (0xf0, &[0x3c]),
        (0xf0, &[0x69]),
        (0x21, &[]),
    ],
};

/// The T-Deck's ST7789, 240×320 run as 320×240. Settings from LilyGoLib's
/// list shared across T-Deck generations
/// (`docs/hardware/lilygo-t-deck-hardware.md` §5.3), with MADCTL for
/// landscape (MV | MX) in place of its portrait default.
pub const ST7789_TDECK: PanelSpec = PanelSpec {
    width: 320,
    height: 240,
    column_offset: 0,
    row_offset: 0,
    init: &[
        (0x13, &[]),
        (0x36, &[0x60]),
        (0x3a, &[0x55]),
        (0xb2, &[0x0c, 0x0c, 0, 0x33, 0x33]),
        (0xb7, &[0x75]),
        (0xbb, &[0x1a]),
        (0xc0, &[0x2c]),
        (0xc2, &[1]),
        (0xc3, &[0x13]),
        (0xc4, &[0x20]),
        (0xc6, &[0x0f]),
        (
            0xe0,
            &[
                0xd0, 0x0d, 0x14, 0x0d, 0x0d, 9, 0x38, 0x44, 0x4e, 0x3a, 0x17, 0x18, 0x2f, 0x30,
            ],
        ),
        (
            0xe1,
            &[
                0xd0, 9, 0x0f, 8, 7, 0x14, 0x37, 0x44, 0x4d, 0x38, 0x15, 0x16, 0x2c, 0x3e,
            ],
        ),
        (0x21, &[]),
    ],
};
