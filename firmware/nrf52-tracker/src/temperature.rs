//! Temperature sources owned by the device environment for one physical boot.

use umsh_ulcp::{Status, temperature::UNKNOWN};
use umsh_ulcp_runtime::temperature::TemperatureInventory;

/// A driver instance, independent of its display label. Future battery and
/// external drivers add source variants and their acquisition branches here.
#[derive(Clone, Copy)]
pub(crate) enum Source {
    McuDie,
    #[cfg(feature = "t1000e")]
    BoardNtc,
    #[cfg(feature = "t1000e")]
    RadioDie,
}

pub(crate) trait Reader {
    /// Tenths of a kelvin; None means acquisition failed or is unavailable.
    async fn sample(&mut self, source: Source) -> Option<u16>;
}

pub(crate) struct Sensors<R> {
    inventory: TemperatureInventory<Source>,
    reader: R,
}

impl<R: Reader> Sensors<R> {
    pub(crate) fn new(reader: R) -> Self {
        let mut sensors = Self {
            inventory: TemperatureInventory::new(),
            reader,
        };
        sensors
            .register(Source::McuDie, "MCU die")
            .expect("initial die sensor fits");
        sensors
    }

    /// Add the board's fixed inventory once at boot, after the MCU slot.
    pub(crate) fn with_board_sensors(reader: R) -> Self {
        #[allow(unused_mut)]
        let mut sensors = Self::new(reader);
        #[cfg(feature = "t1000e")]
        {
            sensors
                .register(Source::BoardNtc, "Board NTC")
                .expect("NTC fits");
            sensors
                .register(Source::RadioDie, "LoRa die")
                .expect("radio fits");
        }
        sensors
    }

    /// Future discovery registers through this owner, retaining existing slots
    /// when a driver becomes unavailable. Never rebuild on a protocol reset.
    pub(crate) fn register(&mut self, source: Source, name: &str) -> Result<usize, Status> {
        self.inventory.register(source, name)
    }

    pub(crate) fn read_names(&self, out: &mut [u8]) -> Result<usize, Status> {
        self.inventory.read_names(out)
    }

    pub(crate) async fn sample(&mut self, out: &mut [u16]) -> Result<usize, Status> {
        let sources = self.inventory.snapshot();
        let slots = out.get_mut(..sources.len()).ok_or(Status::NOMEM)?;
        for (slot, source) in slots.iter_mut().zip(sources) {
            *slot = self.reader.sample(source).await.unwrap_or(UNKNOWN);
        }
        Ok(slots.len())
    }
}

/// Signed quarter-degrees Celsius to tenths of a kelvin, nearest with ties up.
/// Twice the output is exactly `raw * 5 + 5463`; widen before arithmetic.
/// Quantizing the wire value does not increase the sensor's resolution/accuracy.
fn quarter_celsius_to_tenths_kelvin(raw: i32) -> Option<u16> {
    let twice_tenths = i64::from(raw) * 5 + 5463;
    if twice_tenths < 0 {
        return None;
    }
    let rounded = (twice_tenths + 1) / 2;
    u16::try_from(rounded)
        .ok()
        .filter(|&value| value != UNKNOWN)
}

#[cfg(target_os = "none")]
impl Reader for &'static nrf_mpsl::MultiprotocolServiceLayer<'static> {
    async fn sample(&mut self, source: Source) -> Option<u16> {
        match source {
            Source::McuDie => {
                // MPSL owns TEMP. Its approximately 50 us synchronous acquisition
                // runs at the same thread-mode priority as mpsl_task's run loop.
                quarter_celsius_to_tenths_kelvin(self.get_temperature().raw())
            }
            #[cfg(feature = "t1000e")]
            Source::BoardNtc => umsh_bsp_t1000e::temperature::sample().await,
            #[cfg(feature = "t1000e")]
            Source::RadioDie => super::firmware::sample_radio_temperature().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_futures::block_on;

    #[test]
    fn temperature_conversion_is_signed_and_in_tenths_kelvin() {
        for (raw, expected) in [
            (100, 2982),
            (0, 2732),
            (-40, 2632),
            (-1, 2729),
            (1, 2734),
            (2, 2737),
            (-1092, 2),
            (25121, 65534),
        ] {
            assert_eq!(quarter_celsius_to_tenths_kelvin(raw), Some(expected));
        }
        for raw in [-1093, 25122, i32::MIN, i32::MAX] {
            assert_eq!(quarter_celsius_to_tenths_kelvin(raw), None);
        }
    }

    struct FakeReader {
        calls: usize,
        values: [Option<u16>; 3],
    }
    impl Reader for FakeReader {
        async fn sample(&mut self, _: Source) -> Option<u16> {
            let value = self.values[self.calls % self.values.len()];
            self.calls += 1;
            value
        }
    }

    #[test]
    fn temperature_names_and_short_buffers_do_not_sample() {
        let mut sensors = Sensors::new(FakeReader {
            calls: 0,
            values: [Some(2982); 3],
        });
        let mut names = [0; 32];
        let len = sensors.read_names(&mut names).unwrap();
        assert_eq!(&names[..len], b"\x07MCU die");
        assert_eq!(block_on(sensors.sample(&mut [])), Err(Status::NOMEM));
        assert_eq!(sensors.reader.calls, 0);
        let mut out = [0; 1];
        for expected_calls in 1..=2 {
            assert_eq!(block_on(sensors.sample(&mut out)), Ok(1));
            assert_eq!(out, [2982]);
            assert_eq!(sensors.reader.calls, expected_calls);
        }
    }

    #[test]
    fn temperature_failures_preserve_slots_and_names() {
        let mut sensors = Sensors::new(FakeReader {
            calls: 0,
            values: [Some(2982), None, Some(2800)],
        });
        assert_eq!(sensors.register(Source::McuDie, "Battery"), Ok(1));
        assert_eq!(sensors.register(Source::McuDie, "External"), Ok(2));
        let mut names = [0; 64];
        let len = sensors.read_names(&mut names).unwrap();
        let mut out = [0; 3];
        assert_eq!(block_on(sensors.sample(&mut out)), Ok(3));
        assert_eq!(out, [2982, UNKNOWN, 2800]);
        sensors.reader.values = [None; 3];
        assert_eq!(block_on(sensors.sample(&mut out)), Ok(3));
        assert_eq!(out, [UNKNOWN; 3]);
        let mut after = [0; 64];
        assert_eq!(sensors.read_names(&mut after), Ok(len));
        assert_eq!(names, after);
    }

    #[cfg(feature = "t1000e")]
    #[test]
    fn temperature_board_inventory_retains_unavailable_radio_slot() {
        let mut sensors = Sensors::with_board_sensors(FakeReader {
            calls: 0,
            values: [Some(3000), Some(2982), None],
        });
        let mut names = [0; 64];
        let len = sensors.read_names(&mut names).unwrap();
        assert_eq!(&names[..len], b"\x07MCU die\x09Board NTC\x08LoRa die");
        assert_eq!(sensors.reader.calls, 0);
        let mut out = [0; 3];
        assert_eq!(block_on(sensors.sample(&mut out)), Ok(3));
        assert_eq!(out, [3000, 2982, UNKNOWN]);
        sensors.reader.values[2] = Some(2990);
        assert_eq!(block_on(sensors.sample(&mut out)), Ok(3));
        assert_eq!(out, [3000, 2982, 2990]);
        assert_eq!(sensors.reader.calls, 6);
    }
}
