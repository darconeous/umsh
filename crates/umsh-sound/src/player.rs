//! The one sound under way.

use crate::source::{ToneCursor, note_of};
use crate::{
    Choice, Clip, Gain, Level, Repeat, Sound, Source, Tone, Tones, Wave, samples, volume_scale,
};

/// The most notes a tune held by the player may have.
pub const MAX_NOTES: usize = 64;

/// A note as the player holds it: frequency and length.
#[derive(Clone, Copy, Debug, Default)]
struct Note {
    hz: u16,
    ms: u16,
}

/// What is playing, in storage the player owns. Room for a held tune is
/// kept whatever plays, so that one read in at runtime always fits.
#[derive(Clone, Copy, Debug)]
#[allow(clippy::large_enum_variant)]
enum Live {
    Idle,
    Tones(Tones<'static>),
    /// A tune copied in, as one read at runtime is.
    Held {
        notes: [Note; MAX_NOTES],
        len: usize,
        cursor: ToneCursor,
    },
    Clip(Clip<'static>),
}

impl Source for Live {
    fn fill(&mut self, out: &mut [i16]) -> usize {
        match self {
            Self::Idle => 0,
            Self::Tones(tones) => tones.fill(out),
            Self::Held { notes, len, cursor } => {
                let notes = &notes[..*len];
                cursor.fill(
                    |i| notes.get(i).map(|n| (n.hz, samples(u32::from(n.ms)))),
                    out,
                )
            }
            Self::Clip(clip) => clip.fill(out),
        }
    }

    fn rewind(&mut self) {
        match self {
            Self::Idle => {}
            Self::Tones(tones) => tones.rewind(),
            Self::Held { cursor, .. } => cursor.rewind(),
            Self::Clip(clip) => clip.rewind(),
        }
    }
}

/// Plays one sound at a time: a new one takes the place of the last.
/// Itself a [`Source`], which finishes when its sound does.
#[derive(Debug)]
pub struct Player {
    live: Gain<Repeat<Live>>,
    playing: bool,
    /// The volume's multiplier, out of 4096.
    volume: i32,
}

impl Default for Player {
    fn default() -> Self {
        Self::new()
    }
}

impl Player {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            live: Gain::new(Repeat::once(Live::Idle), Level::Full),
            playing: false,
            volume: 4096,
        }
    }

    /// Plays at `volume`, [`MAX_VOLUME`](crate::MAX_VOLUME) the loudest,
    /// from the next sample on. A new player plays sounds as they are
    /// made.
    pub fn set_volume(&mut self, volume: u8) {
        self.volume = volume_scale(volume);
    }

    /// Plays `sound` once at `level`. Returns whether there was a sound
    /// to play; a stored one is not, as none is stored yet.
    pub fn play(&mut self, sound: &Sound, level: Level) -> bool {
        self.start(sound, level, None)
    }

    /// Plays `sound` at `level` again every `period_ms`, until it is
    /// stopped or replaced.
    pub fn play_every(&mut self, sound: &Sound, level: Level, period_ms: u32) -> bool {
        self.start(sound, level, Some(period_ms))
    }

    /// Plays what `choice` names once, as a [`Theme`](crate::Theme) has a
    /// cue play it.
    pub fn play_choice(&mut self, choice: Choice) -> bool {
        match choice.sound.entry() {
            Some(entry) => self.play(&entry.sound, choice.level),
            None => {
                self.stop();
                false
            }
        }
    }

    /// Plays `tones` once in `wave` at `level`, from a copy, so they need
    /// not outlive the call. Refused, playing nothing, when there are more
    /// than [`MAX_NOTES`] or a note is longer than a minute.
    pub fn play_tones(&mut self, tones: &[Tone], wave: Wave, level: Level) -> bool {
        let mut notes = [Note::default(); MAX_NOTES];
        if tones.len() > MAX_NOTES {
            self.stop();
            return false;
        }
        for (note, tone) in notes.iter_mut().zip(tones) {
            let (hz, len) = note_of(tone);
            let ms = len / samples(1);
            let Some(ms) = u16::try_from(ms).ok().filter(|&ms| ms <= 60_000) else {
                self.stop();
                return false;
            };
            *note = Note { hz, ms };
        }
        self.begin(
            Live::Held {
                notes,
                len: tones.len(),
                cursor: ToneCursor::new(wave),
            },
            level,
            None,
        );
        true
    }

    pub fn stop(&mut self) {
        self.live = Gain::new(Repeat::once(Live::Idle), Level::Full);
        self.playing = false;
    }

    #[must_use]
    pub fn is_playing(&self) -> bool {
        self.playing
    }

    fn start(&mut self, sound: &Sound, level: Level, period_ms: Option<u32>) -> bool {
        let live = match *sound {
            Sound::Tones(notes, wave) => Live::Tones(Tones::with_wave(notes, wave)),
            Sound::Clip(bytes) => Live::Clip(Clip::new(bytes)),
            Sound::Stored(_) => {
                self.stop();
                return false;
            }
        };
        self.begin(live, level, period_ms);
        true
    }

    fn begin(&mut self, live: Live, level: Level, period_ms: Option<u32>) {
        let repeat = match period_ms {
            Some(ms) => Repeat::every(live, ms),
            None => Repeat::once(live),
        };
        self.live = Gain::new(repeat, level);
        self.playing = true;
    }
}

impl Source for Player {
    fn fill(&mut self, out: &mut [i16]) -> usize {
        if !self.playing {
            return 0;
        }
        let n = self.live.fill(out);
        if n < out.len() {
            self.playing = false;
        }
        if self.volume != 4096 {
            for sample in &mut out[..n] {
                let scaled = i32::from(*sample) * self.volume / 4096;
                *sample = scaled.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
            }
        }
        n
    }

    fn rewind(&mut self) {
        self.live.rewind();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CATALOG, Cue, SoundId, Theme, melodies};
    use core::time::Duration;

    fn full(player: &mut Player) -> std::vec::Vec<i16> {
        let mut out = std::vec![0i16; 16_000];
        let n = player.fill(&mut out);
        out.truncate(n);
        out
    }

    #[test]
    fn a_sound_plays_once_and_the_player_falls_idle() {
        let mut player = Player::new();
        assert!(!player.is_playing());
        assert!(player.play(&Sound::Tones(melodies::SENT.notes, Wave::Sine), Level::Full));
        assert_eq!(full(&mut player).len(), samples(30) as usize);
        assert!(!player.is_playing());
        assert!(full(&mut player).is_empty());
    }

    #[test]
    fn a_stored_sound_plays_nothing_until_one_is_kept() {
        let mut player = Player::new();
        player.play(&Sound::Tones(melodies::SENT.notes, Wave::Sine), Level::Full);
        assert!(!player.play(&Sound::Stored(0), Level::Full));
        assert!(!player.is_playing());
    }

    #[test]
    fn a_tune_built_at_runtime_plays_from_the_players_copy() {
        let mut player = Player::new();
        let expected = {
            let mut tones = Tones::with_wave(melodies::UNCONFIRMED.notes, Wave::Square);
            let mut out = std::vec![0i16; samples(200) as usize];
            assert_eq!(tones.fill(&mut out), out.len());
            out
        };
        {
            let tune: std::vec::Vec<Tone> = melodies::UNCONFIRMED.notes.to_vec();
            assert!(player.play_tones(&tune, Wave::Square, Level::Full));
        }
        assert_eq!(full(&mut player), expected);
    }

    #[test]
    fn a_tune_too_long_to_hold_is_refused() {
        let note = Tone {
            frequency_hz: 1_000,
            duration: Duration::from_millis(10),
        };
        let mut player = Player::new();
        assert!(!player.play_tones(&[note; MAX_NOTES + 1], Wave::Sine, Level::Full));
        assert!(player.play_tones(&[note; MAX_NOTES], Wave::Sine, Level::Full));
    }

    #[test]
    fn a_clip_plays_through_the_player() {
        static BYTES: [u8; 6] = [1, 0, 2, 0, 3, 0];
        let mut player = Player::new();
        assert!(player.play(&Sound::Clip(&BYTES), Level::Full));
        assert_eq!(full(&mut player), [1, 2, 3]);
    }

    #[test]
    fn a_repeating_sound_plays_until_it_is_replaced() {
        let mut player = Player::new();
        player.play_every(
            &Sound::Tones(melodies::LOCATE.notes, Wave::Sine),
            Level::Full,
            3_000,
        );
        assert_eq!(full(&mut player).len(), 16_000);
        assert!(player.is_playing());
        player.play_choice(Theme::DEFAULT.choice(Cue::Sent));
        assert_eq!(full(&mut player).len(), samples(30) as usize);
        assert!(!player.is_playing());
    }

    #[test]
    fn the_volume_scales_what_plays() {
        let mut player = Player::new();
        player.play(&Sound::Tones(melodies::SENT.notes, Wave::Sine), Level::Full);
        let made = full(&mut player);
        player.set_volume(0);
        player.play(&Sound::Tones(melodies::SENT.notes, Wave::Sine), Level::Full);
        let quiet = full(&mut player);
        assert_eq!(made.len(), quiet.len());
        for (m, q) in made.iter().zip(&quiet) {
            assert_eq!(i32::from(*q), i32::from(*m) * 65 / 4096);
        }
        player.set_volume(crate::MAX_VOLUME);
        player.play(&Sound::Tones(melodies::SENT.notes, Wave::Sine), Level::Full);
        let peak = full(&mut player).iter().map(|v| v.unsigned_abs()).max();
        assert!(peak > Some(30_000));
    }

    #[test]
    fn an_unknown_sound_plays_nothing() {
        let mut player = Player::new();
        assert!(!CATALOG.iter().any(|e| e.id == SoundId(200)));
        assert!(!player.play_choice(Choice {
            sound: SoundId(200),
            level: Level::Full,
        }));
        assert!(!player.is_playing());
    }
}
