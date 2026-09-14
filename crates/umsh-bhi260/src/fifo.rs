//! Streaming FIFO decoding. Each FIFO needs its own decoder and clock.
//! Only explicitly registered virtual sensors are accepted; an unknown event
//! makes framing uncertain and poisons the decoder until reset. Consumers must
//! invalidate motion candidates on overflow, initialization, reset, and sensor
//! error meta events, even if subsequent bytes contain plausible measurements.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Wake = 1,
    NonWake = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedEvent(u8),
    InvalidSize,
    Capacity,
    Discontinuity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub id: u8,
    /// Sensor ticks (1 / 64000 second), extended across the 40-bit rollover.
    /// Absent until a full timestamp follows a reset or FIFO discontinuity.
    pub ticks: Option<u64>,
    bytes: [u8; 23],
    size: u8,
}

impl Event {
    pub fn payload(&self) -> &[u8] {
        &self.bytes[1..usize::from(self.size)]
    }

    pub fn discontinuity(&self) -> bool {
        matches!(self.id, 248 | 254) && matches!(self.bytes[1], 11 | 12 | 16 | 19)
    }
}

pub struct Decoder {
    sizes: [(u8, u8); 8],
    bytes: [u8; 23],
    used: u8,
    needed: u8,
    ticks: Option<u64>,
    poisoned: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            sizes: [(0, 0); 8],
            bytes: [0; 23],
            used: 0,
            needed: 0,
            ticks: None,
            poisoned: false,
        }
    }

    /// Size includes the sensor ID byte, as returned by Virtual Sensor Info.
    pub fn register(&mut self, id: u8, size: u8) -> Result<(), Error> {
        if id == 0 || id >= 224 || size == 0 || usize::from(size) > self.bytes.len() {
            return Err(Error::InvalidSize);
        }
        let slot = self
            .sizes
            .iter_mut()
            .find(|(key, _)| *key == id || *key == 0)
            .ok_or(Error::Capacity)?;
        *slot = (id, size);
        Ok(())
    }

    /// Clear framing and timestamp state; preserve the registered sensor sizes.
    pub fn reset(&mut self) {
        self.used = 0;
        self.needed = 0;
        self.ticks = None;
        self.poisoned = false;
    }

    pub fn push(&mut self, byte: u8) -> Result<Option<Event>, Error> {
        if self.poisoned {
            return Err(Error::Discontinuity);
        }
        if self.used == 0 {
            self.needed = match byte {
                0 | 255 => return Ok(None),
                245 | 251 => 2,
                246 | 252 => 3,
                247 | 253 => 6,
                248 | 254 => 4,
                250 => 18,
                244 => 23,
                id => match self.sizes.iter().find(|(key, _)| *key == id) {
                    Some((_, size)) => *size,
                    None => {
                        self.poisoned = true;
                        self.ticks = None;
                        return Err(Error::UnsupportedEvent(id));
                    }
                },
            };
        }
        self.bytes[usize::from(self.used)] = byte;
        self.used += 1;
        if self.used != self.needed {
            return Ok(None);
        }
        self.used = 0;
        let id = self.bytes[0];
        match id {
            245 | 251 | 246 | 252 => {
                let delta = if matches!(id, 245 | 251) {
                    u64::from(self.bytes[1])
                } else {
                    u64::from(u16::from_le_bytes([self.bytes[1], self.bytes[2]]))
                };
                if let Some(ticks) = self.ticks {
                    self.ticks = Some(ticks.checked_add(delta).ok_or(Error::Discontinuity)?);
                }
                Ok(None)
            }
            247 | 253 => {
                let mut raw = [0; 8];
                raw[..5].copy_from_slice(&self.bytes[1..6]);
                let raw = u64::from_le_bytes(raw);
                let mask = (1u64 << 40) - 1;
                let previous = self.ticks.unwrap_or(0);
                let mut extended = (previous & !mask) | raw;
                if extended < previous {
                    // A small backwards jump is a reset/discontinuity, not
                    // the 198-day counter rollover. Never make it look fresh.
                    if previous - extended < 1u64 << 39 {
                        self.poisoned = true;
                        self.ticks = None;
                        return Err(Error::Discontinuity);
                    }
                    extended += 1u64 << 40;
                }
                self.ticks = Some(extended);
                Ok(None)
            }
            _ => {
                let mut event = Event {
                    id,
                    ticks: self.ticks,
                    bytes: self.bytes,
                    size: self.needed,
                };
                if event.discontinuity() {
                    self.ticks = None;
                    event.ticks = None;
                }
                Ok(Some(event))
            }
        }
    }
}
