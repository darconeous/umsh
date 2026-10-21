//! What the interface knows of the board it runs on: its screen's size and
//! the type that reads well on it, and the controls it has.
//!
//! One build runs on any of these, so the host communicator can show
//! either and the tests can drive both.

use embedded_graphics::prelude::Size;

use crate::models;

/// A board the interface runs on.
#[derive(Debug, PartialEq, Eq)]
pub struct Board {
    /// Its model id (`boards.json`).
    pub model: u16,
    pub metrics: Metrics,
    pub controls: Controls,
}

impl Board {
    /// The LilyGO T-LoRa Pager: 480x222 at about 227 ppi, a wheel that
    /// presses, a lock button, and a keyboard with legends.
    pub const PAGER: Self = Self {
        model: models::LILYGO_T_LORA_PAGER,
        metrics: Metrics {
            width: 480,
            height: 222,
            strip: 22,
            rail: 66,
            body: 20,
            secondary: 17,
            small: 16,
            title: 26,
            header: 30,
            back: false,
            touch_target: None,
        },
        controls: Controls {
            unlock: Unlock::TurnThenPress,
            touch: false,
            keyboard: KeyboardKind::Legends,
        },
    };

    /// The LilyGO T-Deck and T-Deck Plus: 320x240 at about 143 ppi, a
    /// trackball that presses, a touchscreen, and a keyboard that types
    /// characters. No lock button.
    pub const TDECK: Self = Self {
        model: models::LILYGO_T_DECK,
        metrics: Metrics {
            width: 320,
            height: 240,
            strip: 20,
            rail: 52,
            body: 16,
            secondary: 14,
            small: 12,
            title: 20,
            header: 36,
            back: true,
            touch_target: Some(48),
        },
        controls: Controls {
            unlock: Unlock::Press,
            touch: true,
            keyboard: KeyboardKind::Characters,
        },
    };
}

/// The screen, and the sizes laid out on it.
#[derive(Debug, PartialEq, Eq)]
pub struct Metrics {
    pub width: u32,
    pub height: u32,
    /// The status strip's height.
    pub strip: u32,
    /// The rail's width, beside the top-level lists.
    pub rail: u32,
    /// Body text.
    pub body: u32,
    /// Secondary lines such as chat previews.
    pub secondary: u32,
    /// The smallest type anywhere: timestamps, labels, the status strip.
    pub small: u32,
    /// Figures set large, such as the parts of a date being set.
    pub title: u32,
    /// A screen's header, under the status strip.
    pub header: u32,
    /// Whether a header starts with an arrow to touch for Back, as on a
    /// board that has touch. Elsewhere the keys have Back, and no arrow
    /// stands for it.
    pub back: bool,
    /// The least a finger is taken to cover, on a board with touch: a
    /// smaller target takes a touch this near it, as though it were this
    /// size, with nothing drawn any larger.
    pub touch_target: Option<u32>,
}

impl Metrics {
    #[must_use]
    pub const fn size(&self) -> Size {
        Size::new(self.width, self.height)
    }

    /// Below the status strip.
    #[must_use]
    pub const fn below_strip(&self) -> u32 {
        self.height - self.strip
    }

    /// Beside the rail.
    #[must_use]
    pub const fn beside_rail(&self) -> u32 {
        self.width - self.rail
    }
}

/// The controls a board has, where they change what the interface asks.
#[derive(Debug, PartialEq, Eq)]
pub struct Controls {
    pub unlock: Unlock,
    /// A touchscreen.
    pub touch: bool,
    pub keyboard: KeyboardKind,
}

/// What unlocks the lock screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unlock {
    /// Steps of the wheel down, then a press.
    TurnThenPress,
    /// A press alone.
    Press,
}

/// What the keyboard reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyboardKind {
    /// Keys with their legends, and the modifiers going down and up: the
    /// interface applies the modifiers and typing aids.
    #[default]
    Legends,
    /// Characters, with its own modifiers already applied.
    Characters,
}
