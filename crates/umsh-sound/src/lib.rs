//! Sounds of UMSH devices with a speaker.
//!
//! Three layers, each replaceable without the others:
//!
//! - **What a sound is.** Anything that fills 16 kHz mono samples is a
//!   [`Source`]: a run of [`Tones`], a recorded [`Clip`], or either
//!   [`Repeat`]ed on a period or played at a [`Level`].
//! - **Which sounds there are.** The [`CATALOG`] names every built-in
//!   [`Sound`], and a [`Theme`] says which one each [`Cue`] plays.
//! - **What is playing.** A [`Player`] holds the one sound under way,
//!   in storage of its own, so a sound read in at runtime plays as well
//!   as a built-in one.
//!
//! A board streams what the player fills to its output and knows nothing
//! else; the interface raises cues and knows nothing of samples.

#![no_std]

#[cfg(test)]
extern crate std;

mod catalog;
mod player;
mod source;
mod volume;

pub use catalog::{CATALOG, Choice, Cue, Entry, Sound, SoundId, Theme};
pub use player::{MAX_NOTES, Player};
pub use source::{Clip, Gain, Level, Repeat, Source, Tones, Wave};
pub use umsh_ux_tracker::buzzer::{Melody, Tone, melodies};
pub use volume::{MAX_VOLUME, scale as volume_scale};

/// The rate every source fills at, in samples per second.
pub const RATE_HZ: u32 = 16_000;

/// Samples in `ms` milliseconds.
#[must_use]
pub const fn samples(ms: u32) -> u32 {
    ms * (RATE_HZ / 1000)
}
