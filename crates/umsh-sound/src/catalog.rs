//! The events that make a sound, the sounds there are, and which plays
//! for which.

use crate::{Level, Tone, Wave, melodies};

/// Something that happened that a sound tells of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cue {
    /// A direct message arrived.
    Direct,
    /// A message arrived in a channel.
    Channel,
    /// A message arrived in the conversation being read.
    InChat,
    /// A message was handed to the radio.
    Sent,
    /// A message was acknowledged by the peer it was sent to.
    Delivered,
    /// A message went unconfirmed.
    Unconfirmed,
}

impl Cue {
    pub const COUNT: usize = 6;
    pub const ALL: [Self; Self::COUNT] = [
        Self::Direct,
        Self::Channel,
        Self::InChat,
        Self::Sent,
        Self::Delivered,
        Self::Unconfirmed,
    ];

    /// Where the cue stands in a [`Theme`].
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// How much the cue matters beside another: only the one that
    /// matters most of several at once is played. Someone writing to you
    /// comes first, then a message of yours that did not get through.
    #[must_use]
    const fn rank(self) -> u8 {
        match self {
            Self::Direct => 5,
            Self::Unconfirmed => 4,
            Self::Channel => 3,
            Self::Delivered => 2,
            Self::Sent => 1,
            Self::InChat => 0,
        }
    }

    /// The one of `held` and `self` to play: the one that matters more,
    /// or the earlier of two that matter alike.
    #[must_use]
    pub fn over(self, held: Option<Self>) -> Self {
        match held {
            Some(held) if held.rank() >= self.rank() => held,
            _ => self,
        }
    }
}

/// Names a sound, built in or stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SoundId(pub u8);

/// What a sound is made of.
#[derive(Clone, Copy, Debug)]
pub enum Sound {
    /// A run of tones, in a wave.
    Tones(&'static [Tone], Wave),
    /// A recording, as [`Clip`](crate::Clip) plays it.
    Clip(&'static [u8]),
    /// A sound kept by the device rather than built in, such as a tune
    /// someone wrote, by where it is kept. None are kept yet, so none
    /// plays.
    Stored(u8),
}

/// A sound the device has, by name.
#[derive(Debug)]
pub struct Entry {
    pub id: SoundId,
    pub name: &'static str,
    pub sound: Sound,
}

impl SoundId {
    pub const RUN_UP: Self = Self(1);
    pub const KERPLOP: Self = Self(2);
    pub const PIP: Self = Self(3);
    pub const BLIP: Self = Self(4);
    pub const THUMP: Self = Self(5);
    pub const BUZZ: Self = Self(6);

    /// The built-in sound by this name, if it is one.
    #[must_use]
    pub fn entry(self) -> Option<&'static Entry> {
        CATALOG.iter().find(|entry| entry.id == self)
    }
}

/// Every built-in sound.
pub static CATALOG: &[Entry] = &[
    Entry {
        id: SoundId::RUN_UP,
        name: "Run up",
        sound: Sound::Tones(melodies::QUEUED_DIRECT.notes, Wave::Sine),
    },
    Entry {
        id: SoundId::KERPLOP,
        name: "Kerplop",
        sound: Sound::Tones(melodies::QUEUED_GROUP.notes, Wave::Sine),
    },
    Entry {
        id: SoundId::PIP,
        name: "Pip",
        sound: Sound::Tones(melodies::IN_CHAT.notes, Wave::Sine),
    },
    Entry {
        id: SoundId::BLIP,
        name: "Blip",
        sound: Sound::Tones(melodies::SENT.notes, Wave::Sine),
    },
    Entry {
        id: SoundId::THUMP,
        name: "Thump",
        sound: Sound::Tones(melodies::DELIVERED.notes, Wave::Sine),
    },
    Entry {
        id: SoundId::BUZZ,
        name: "Buzz",
        sound: Sound::Tones(melodies::UNCONFIRMED.notes, Wave::Square),
    },
];

/// The sound a cue plays, and how loud.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choice {
    pub sound: SoundId,
    pub level: Level,
}

/// Which sound each cue plays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Theme {
    pub cues: [Choice; Cue::COUNT],
}

impl Theme {
    pub const DEFAULT: Self = Self {
        cues: [
            Choice {
                sound: SoundId::RUN_UP,
                level: Level::Full,
            },
            Choice {
                sound: SoundId::KERPLOP,
                level: Level::Full,
            },
            Choice {
                sound: SoundId::PIP,
                level: Level::Soft,
            },
            Choice {
                sound: SoundId::BLIP,
                level: Level::Soft,
            },
            Choice {
                sound: SoundId::THUMP,
                level: Level::Soft,
            },
            Choice {
                sound: SoundId::BUZZ,
                level: Level::Full,
            },
        ],
    };

    #[must_use]
    pub const fn choice(&self, cue: Cue) -> Choice {
        self.cues[cue.index()]
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_theme_names_a_built_in_sound_for_every_cue() {
        for cue in Cue::ALL {
            assert_eq!(Cue::ALL[cue.index()], cue);
            let choice = Theme::DEFAULT.choice(cue);
            assert!(choice.sound.entry().is_some(), "{cue:?}");
        }
    }

    #[test]
    fn built_in_sounds_have_names_of_their_own() {
        for (i, a) in CATALOG.iter().enumerate() {
            assert!(!a.name.is_empty());
            for b in &CATALOG[i + 1..] {
                assert_ne!(a.id, b.id);
                assert_ne!(a.name, b.name);
            }
        }
    }

    #[test]
    fn the_cue_that_matters_most_is_kept() {
        assert_eq!(Cue::Channel.over(None), Cue::Channel);
        assert_eq!(Cue::Direct.over(Some(Cue::Channel)), Cue::Direct);
        assert_eq!(Cue::Channel.over(Some(Cue::Direct)), Cue::Direct);
        assert_eq!(Cue::Sent.over(Some(Cue::Unconfirmed)), Cue::Unconfirmed);
        assert_eq!(Cue::InChat.over(Some(Cue::Sent)), Cue::Sent);
        assert_eq!(Cue::Channel.over(Some(Cue::Channel)), Cue::Channel);
    }
}
