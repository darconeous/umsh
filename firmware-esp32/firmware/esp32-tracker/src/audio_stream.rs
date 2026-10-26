//! Streams a sound into an I2S transfer: what the boards with a speaker
//! share. A board brings its output up and down around this; what is
//! played comes from an `umsh_sound::Source`.
use esp_hal::{
    Async,
    dma::DmaTxStreamBuf,
    i2s::master::{I2sTx, I2sTxDmaTransfer},
};
use umsh_sound::{Choice, Source};

pub type Transfer<'a> = I2sTxDmaTransfer<'a, Async, DmaTxStreamBuf>;

/// A sound to play: which, and at what volume.
#[derive(Clone, Copy)]
pub struct Request {
    pub choice: Choice,
    pub volume: u8,
}

/// Four 32 ms descriptors in static internal RAM. The display's first
/// redraw can starve a 40 ms stream, so enough is queued for that CPU
/// work, while leaving room for a ramp and tail inside 250 ms.
macro_rules! stream_buffer {
    () => {
        esp_hal::dma_tx_stream_buffer!(8192, 2048)
    };
}
pub(crate) use stream_buffer;

/// Frames of silence after a sound before every frame of it has left the
/// buffer: the whole buffer, and the descriptor in flight.
const DRAIN_FRAMES: u32 = (8192 + 2048) / 4;

/// Frames over which a sound cut short falls to silence: 5 ms.
const TAIL_FRAMES: u32 = 80;

/// Frames rendered at a time.
const CHUNK: usize = 64;

/// Prefills `buffer` with silence and starts it out through `tx`. On a
/// refusal the buffer comes back, and `tx` is dropped.
pub fn start<'a>(
    tx: I2sTx<'a, Async>,
    mut buffer: DmaTxStreamBuf,
) -> Result<Transfer<'a>, DmaTxStreamBuf> {
    buffer.push_with(|bytes| {
        bytes.fill(0);
        bytes.len()
    });
    tx.write(buffer).map_err(|(_, tx, returned)| {
        drop(tx);
        rebuild(returned)
    })
}

/// Stops `transfer`, releasing the transmitter, and returns its buffer
/// ready to start again.
pub fn finish(transfer: Transfer<'_>) -> DmaTxStreamBuf {
    let (tx, returned) = transfer.stop();
    drop(tx);
    rebuild(returned)
}

/// A stopped streaming buffer retains its prefill cursor. Reconstruct it.
fn rebuild(buffer: DmaTxStreamBuf) -> DmaTxStreamBuf {
    let (descriptors, bytes) = buffer.split();
    DmaTxStreamBuf::new(descriptors, bytes).expect("same audio buffer")
}

/// A sound going out: the samples it has sent, and how it ends.
pub struct Stream {
    /// Frames of silence still to send before the sound starts.
    lead: u32,
    last: i16,
    /// Cut short: the sample it fell from, and the frames it has fallen.
    cut: Option<(i16, u32)>,
    /// Nothing but silence is sent from here on.
    ended: bool,
    /// Frames of silence sent since it ended.
    silence: u32,
}

impl Stream {
    /// A sound that starts `ms` milliseconds of silence from now, for an
    /// output that is not yet fit to be heard; 0 to start at once.
    pub const fn after(ms: u32) -> Self {
        Self {
            lead: umsh_sound::samples(ms),
            last: 0,
            cut: None,
            ended: false,
            silence: 0,
        }
    }

    /// Ends the sound where it is, falling to silence over a few
    /// milliseconds instead of stopping on a step.
    pub fn cut(&mut self) {
        self.lead = 0;
        if self.cut.is_none() && !self.ended {
            self.cut = Some((self.last, 0));
        }
    }

    /// The sound has ended, and all of it has left the buffer.
    pub fn drained(&self) -> bool {
        self.ended && self.silence >= DRAIN_FRAMES
    }

    /// Fills as much of `transfer` as it has room for from `source`, the
    /// same sample on both channels.
    pub fn fill(&mut self, transfer: &mut Transfer<'_>, source: &mut dyn Source) {
        while transfer.available_bytes() > 0 {
            let n = transfer.push_with(|bytes| {
                let usable = bytes.len() / 4 * 4;
                for out in bytes[..usable].chunks_mut(CHUNK * 4) {
                    let mut pcm = [0i16; CHUNK];
                    let pcm = &mut pcm[..out.len() / 4];
                    self.render(source, pcm);
                    for (frame, sample) in out.chunks_exact_mut(4).zip(pcm.iter()) {
                        let b = sample.to_le_bytes();
                        frame.copy_from_slice(&[b[0], b[1], b[0], b[1]]);
                    }
                }
                usable
            });
            if n == 0 {
                break;
            }
        }
    }

    fn render(&mut self, source: &mut dyn Source, pcm: &mut [i16]) {
        let lead = (self.lead as usize).min(pcm.len());
        pcm[..lead].fill(0);
        self.lead -= lead as u32;
        let pcm = &mut pcm[lead..];
        if pcm.is_empty() {
            return;
        }
        if let Some((from, fallen)) = &mut self.cut {
            for sample in pcm.iter_mut() {
                let gain = TAIL_FRAMES.saturating_sub(*fallen) as i32;
                *fallen = fallen.saturating_add(1);
                *sample = (i32::from(*from) * gain / TAIL_FRAMES as i32) as i16;
            }
            if *fallen >= TAIL_FRAMES {
                self.cut = None;
                self.ended = true;
            }
        } else if self.ended {
            pcm.fill(0);
        } else {
            let got = source.fill(pcm);
            pcm[got..].fill(0);
            // A sound ends on its own envelope, already at silence.
            self.ended = got < pcm.len();
        }
        if self.ended {
            self.silence = self.silence.saturating_add(pcm.len() as u32);
        }
        self.last = pcm.last().copied().unwrap_or(self.last);
    }
}
