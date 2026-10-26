//! Sources of samples, and what can be done to one.

use crate::{Tone, samples};

/// Something that makes sound: it fills 16 kHz mono samples on demand.
pub trait Source {
    /// Fills `out` from where the sound stands, and returns how many
    /// samples it wrote. Fewer than `out.len()` means the sound has
    /// finished; it writes none after that until it is rewound.
    fn fill(&mut self, out: &mut [i16]) -> usize;

    /// Goes back to the start of the sound.
    fn rewind(&mut self);
}

/// How loud a sound plays.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Level {
    #[default]
    Full,
    /// A quarter of full amplitude, 12 dB down: for a sound that only
    /// confirms what the reader is already looking at.
    Soft,
}

impl Level {
    /// The multiplier this level applies, out of 256.
    const fn scale(self) -> i32 {
        match self {
            Self::Full => 256,
            Self::Soft => 64,
        }
    }
}

/// Samples over which a note fades in, and out again: 5 ms, short
/// enough not to be heard as a fade and long enough not to click.
const RAMP: u32 = 80;

/// The shape of a tone's oscillator.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Wave {
    /// Pure, for a tone that should sound like a note.
    #[default]
    Sine,
    /// Hard-edged, for a buzz: rich in overtones, so even a note below
    /// what a small speaker can move is heard through them.
    Square,
}

/// Height of a square tone: as loud, by RMS, as a sine at [`QUARTER`]'s
/// peak, so a wave's shape does not change how loud it plays.
const SQUARE: i32 = 5_793;

/// Peak amplitude of a sine tone, about −12 dBFS.
const QUARTER: [i32; 17] = [
    0, 803, 1598, 2378, 3135, 3862, 4551, 5197, 5793, 6333, 6811, 7225, 7568, 7839, 8035, 8153,
    8192,
];

/// Where a run of tones stands, apart from the tones themselves, so the
/// same cursor plays notes borrowed from flash or held in a buffer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ToneCursor {
    note: usize,
    /// Samples into the note.
    at: u32,
    /// Phase of the oscillator, a full turn being 2³².
    phase: u32,
    wave: Wave,
}

impl ToneCursor {
    pub(crate) const fn new(wave: Wave) -> Self {
        Self {
            note: 0,
            at: 0,
            phase: 0,
            wave,
        }
    }

    /// Back to the first note, in the same wave.
    pub(crate) fn rewind(&mut self) {
        *self = Self::new(self.wave);
    }

    /// Fills `out` from the notes `note(i)` gives, as frequency and
    /// length in samples, until it gives none.
    pub(crate) fn fill(
        &mut self,
        note: impl Fn(usize) -> Option<(u16, u32)>,
        out: &mut [i16],
    ) -> usize {
        let mut written = 0;
        while written < out.len() {
            let Some((hz, len)) = note(self.note) else {
                break;
            };
            if self.at >= len {
                self.note += 1;
                self.at = 0;
                continue;
            }
            out[written] = self.sample(hz, len);
            self.at += 1;
            written += 1;
        }
        written
    }

    /// One sample of the wave at `hz`, enveloped across a note `len`
    /// samples long. A rest is silence, and starts the next note's
    /// oscillator from zero.
    fn sample(&mut self, hz: u16, len: u32) -> i16 {
        if hz == 0 {
            self.phase = 0;
            return 0;
        }
        let v = match self.wave {
            Wave::Sine => {
                let i = (self.phase >> 26) as usize;
                match i / 16 {
                    0 => QUARTER[i],
                    1 => QUARTER[32 - i],
                    2 => -QUARTER[i - 32],
                    _ => -QUARTER[64 - i],
                }
            }
            Wave::Square if self.phase < 1 << 31 => SQUARE,
            Wave::Square => -SQUARE,
        };
        self.phase = self
            .phase
            .wrapping_add(((u64::from(hz) << 32) / u64::from(crate::RATE_HZ)) as u32);
        let envelope = self
            .at
            .min(len.saturating_sub(1).saturating_sub(self.at))
            .min(RAMP) as i32;
        (v * envelope / RAMP as i32) as i16
    }
}

/// A run of tones: each note a wave at its frequency, faded in and out
/// across its own length; a zero frequency is a rest.
#[derive(Clone, Copy, Debug)]
pub struct Tones<'a> {
    notes: &'a [Tone],
    cursor: ToneCursor,
}

impl<'a> Tones<'a> {
    /// `notes` as sines.
    #[must_use]
    pub fn new(notes: &'a [Tone]) -> Self {
        Self::with_wave(notes, Wave::Sine)
    }

    #[must_use]
    pub fn with_wave(notes: &'a [Tone], wave: Wave) -> Self {
        Self {
            notes,
            cursor: ToneCursor::new(wave),
        }
    }
}

/// A note's frequency and its length in samples.
pub(crate) fn note_of(tone: &Tone) -> (u16, u32) {
    let ms = u32::try_from(tone.duration.as_millis()).unwrap_or(u32::MAX / 16);
    (tone.frequency_hz, samples(ms))
}

impl Source for Tones<'_> {
    fn fill(&mut self, out: &mut [i16]) -> usize {
        let notes = self.notes;
        self.cursor.fill(|i| notes.get(i).map(note_of), out)
    }

    fn rewind(&mut self) {
        self.cursor.rewind();
    }
}

/// A recording: 16 kHz mono, signed 16-bit little-endian samples, played
/// as they are. An odd last byte is not a sample.
#[derive(Clone, Copy, Debug)]
pub struct Clip<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Clip<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
}

impl Source for Clip<'_> {
    fn fill(&mut self, out: &mut [i16]) -> usize {
        let left = self.bytes.len() / 2 - self.at;
        let n = left.min(out.len());
        for (sample, pair) in out[..n]
            .iter_mut()
            .zip(self.bytes[self.at * 2..].chunks_exact(2))
        {
            *sample = i16::from_le_bytes([pair[0], pair[1]]);
        }
        self.at += n;
        n
    }

    fn rewind(&mut self) {
        self.at = 0;
    }
}

/// A sound played again on a period, or once. Repeated, it never
/// finishes: what is left of each period after the sound is silence, and
/// a sound longer than the period is cut off at its end.
#[derive(Clone, Copy, Debug)]
pub struct Repeat<S> {
    inner: S,
    /// The period in samples, or `None` to play once.
    period: Option<u32>,
    /// Samples into the period.
    at: u32,
}

impl<S: Source> Repeat<S> {
    /// `inner` once: a repeat that passes it through.
    pub const fn once(inner: S) -> Self {
        Self {
            inner,
            period: None,
            at: 0,
        }
    }

    /// `inner` again every `period_ms` milliseconds.
    pub const fn every(inner: S, period_ms: u32) -> Self {
        Self {
            inner,
            period: Some(samples(period_ms)),
            at: 0,
        }
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: Source> Source for Repeat<S> {
    fn fill(&mut self, out: &mut [i16]) -> usize {
        let Some(period) = self.period.filter(|&p| p > 0) else {
            return self.inner.fill(out);
        };
        let mut written = 0;
        while written < out.len() {
            if self.at >= period {
                self.inner.rewind();
                self.at = 0;
            }
            let room = (out.len() - written).min((period - self.at) as usize);
            let span = &mut out[written..written + room];
            let got = self.inner.fill(span);
            span[got..].fill(0);
            self.at += room as u32;
            written += room;
        }
        written
    }

    fn rewind(&mut self) {
        self.inner.rewind();
        self.at = 0;
    }
}

/// A sound played at a [`Level`].
#[derive(Clone, Copy, Debug)]
pub struct Gain<S> {
    inner: S,
    level: Level,
}

impl<S: Source> Gain<S> {
    pub const fn new(inner: S, level: Level) -> Self {
        Self { inner, level }
    }

    pub fn set_level(&mut self, level: Level) {
        self.level = level;
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: Source> Source for Gain<S> {
    fn fill(&mut self, out: &mut [i16]) -> usize {
        let n = self.inner.fill(out);
        let scale = self.level.scale();
        if scale != 256 {
            for sample in &mut out[..n] {
                *sample = (i32::from(*sample) * scale / 256) as i16;
            }
        }
        n
    }

    fn rewind(&mut self) {
        self.inner.rewind();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Melody, melodies};
    use core::time::Duration;
    use umsh_ux_tracker::buzzer::{BuzzerDecision, BuzzerEngine};

    fn tone(hz: u16, ms: u64) -> Tone {
        Tone {
            frequency_hz: hz,
            duration: Duration::from_millis(ms),
        }
    }

    fn drain(source: &mut impl Source, buffer: &mut [i16]) -> usize {
        let mut total = 0;
        loop {
            let n = source.fill(&mut buffer[total..]);
            total += n;
            if total == buffer.len() || n == 0 {
                return total;
            }
        }
    }

    #[test]
    fn a_run_of_tones_lasts_as_long_as_its_notes_and_then_finishes() {
        let notes = [tone(1_000, 10), tone(0, 5), tone(2_000, 20)];
        let mut source = Tones::new(&notes);
        let mut out = [1i16; 1000];
        assert_eq!(drain(&mut source, &mut out), samples(35) as usize);
        assert_eq!(source.fill(&mut out), 0);
        source.rewind();
        assert_eq!(drain(&mut source, &mut out), samples(35) as usize);
    }

    #[test]
    fn a_short_note_fades_in_and_out_across_its_own_length() {
        // 38 ms, as in the direct-message run: no window of another
        // note's length may leave it starting or ending on a step.
        let notes = [tone(1_319, 38)];
        let mut out = [0i16; 608];
        assert_eq!(Tones::new(&notes).fill(&mut out), 608);
        assert_eq!(out[0], 0);
        assert!(out[607].abs() < 200, "ends at {}", out[607]);
        assert!(out[1..10].iter().all(|v| v.abs() < 1100));
        assert!(out[200..400].iter().any(|v| v.abs() > 7000));
    }

    #[test]
    fn tones_have_the_requested_fundamental_at_16khz() {
        for hz in [1900, 2600] {
            let notes = [tone(hz, 1000)];
            let mut out = [0i16; 16_000];
            assert_eq!(Tones::new(&notes).fill(&mut out), 16_000);
            let crossings = out
                .windows(2)
                .filter(|pair| pair[0] <= 0 && pair[1] > 0)
                .count() as u16;
            assert!(crossings.abs_diff(hz) <= 1, "{hz}: {crossings}");
            assert!(out.iter().all(|v| v.unsigned_abs() <= 8192));
        }
    }

    #[test]
    fn a_square_tone_holds_each_half_cycle_and_is_as_loud_as_a_sine() {
        let notes = [tone(100, 1000)];
        let mut square = [0i16; 16_000];
        let mut sine = [0i16; 16_000];
        Tones::with_wave(&notes, Wave::Square).fill(&mut square);
        Tones::new(&notes).fill(&mut sine);
        // Past the fade in: 80 samples low, then 80 high, each edge
        // within a sample of where it falls.
        assert!(square[82..158].iter().all(|&v| v == -SQUARE as i16));
        assert!(square[162..238].iter().all(|&v| v == SQUARE as i16));
        let crossings = square
            .windows(2)
            .filter(|pair| pair[0] <= 0 && pair[1] > 0)
            .count();
        assert!(crossings.abs_diff(100) <= 1, "{crossings}");
        let power = |out: &[i16]| out.iter().map(|&v| i64::from(v).pow(2)).sum::<i64>();
        let ratio = power(&square) as f64 / power(&sine) as f64;
        assert!((ratio - 1.0).abs() < 0.01, "{ratio}");
    }

    #[test]
    fn a_rest_is_silence() {
        let notes = [tone(0, 10)];
        let mut out = [5i16; 160];
        assert_eq!(Tones::new(&notes).fill(&mut out), 160);
        assert!(out.iter().all(|&v| v == 0));
    }

    #[test]
    fn soft_is_a_quarter_of_full() {
        let notes = [tone(1_500, 20)];
        let mut full = [0i16; 320];
        let mut soft = [0i16; 320];
        Gain::new(Tones::new(&notes), Level::Full).fill(&mut full);
        Gain::new(Tones::new(&notes), Level::Soft).fill(&mut soft);
        for (f, s) in full.iter().zip(soft) {
            assert_eq!(i32::from(s), i32::from(*f) * 64 / 256);
        }
    }

    #[test]
    fn a_clip_plays_its_samples_and_finishes() {
        let bytes = [0x01, 0x00, 0xff, 0xff, 0x00, 0x80, 0x7f];
        let mut clip = Clip::new(&bytes);
        let mut out = [9i16; 8];
        assert_eq!(clip.fill(&mut out[..2]), 2);
        assert_eq!(clip.fill(&mut out[2..]), 1);
        assert_eq!(&out[..3], &[1, -1, i16::MIN]);
        assert_eq!(clip.fill(&mut out), 0);
        clip.rewind();
        assert_eq!(clip.fill(&mut out), 3);
    }

    #[test]
    fn a_repeat_rests_out_each_period_and_never_finishes() {
        let notes = [tone(1_000, 10)];
        let mut source = Repeat::every(Tones::new(&notes), 25);
        let mut first = [0i16; 400];
        let mut second = [0i16; 400];
        assert_eq!(source.fill(&mut first), 400);
        assert_eq!(source.fill(&mut second), 400);
        assert!(first[160..].iter().all(|&v| v == 0));
        assert_eq!(first, second);
    }

    /// The locate alert as the Pager has played it: the buzzer engine's
    /// decision each millisecond, and a 150 ms envelope window.
    fn locate_as_played(frames: usize) -> std::vec::Vec<i16> {
        let mut engine = BuzzerEngine::new();
        engine.play_alert(&melodies::LOCATE, 0, 3_000);
        let mut phase = 0u32;
        (0..frames as u64)
            .map(|frame| {
                let hz = match engine.tick(frame / 16) {
                    BuzzerDecision::Tone { frequency_hz, .. } => frequency_hz,
                    _ => 0,
                };
                let note_sample = (frame % 2400) as u32;
                if hz == 0 {
                    phase = 0;
                    return 0;
                }
                let i = (phase >> 26) as usize;
                let v = match i / 16 {
                    0 => QUARTER[i],
                    1 => QUARTER[32 - i],
                    2 => -QUARTER[i - 32],
                    _ => -QUARTER[64 - i],
                };
                phase = phase.wrapping_add(((u64::from(hz) << 32) / 16_000) as u32);
                let envelope = note_sample.min(2399u32.saturating_sub(note_sample)).min(80) as i32;
                (v * envelope / 80) as i16
            })
            .collect()
    }

    #[test]
    fn the_locate_alert_sounds_as_it_did() {
        static LOCATE: &Melody = &melodies::LOCATE;
        let frames = samples(7_000) as usize;
        let mut source = Repeat::every(Tones::new(LOCATE.notes), 3_000);
        let mut out = std::vec![0i16; frames];
        // In uneven pieces, as a DMA buffer asks for them.
        let mut at = 0;
        for piece in [7, 2048, 1, 333].iter().cycle() {
            if at == frames {
                break;
            }
            let end = (at + piece).min(frames);
            assert_eq!(source.fill(&mut out[at..end]), end - at);
            at = end;
        }
        assert_eq!(out, locate_as_played(frames));
    }
}
