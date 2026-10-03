//! Append-only temperature inventory, independent of sensor drivers.

use heapless::Vec;
use umsh_ulcp::{Status, temperature};
use umsh_ulcp_device::{MAX_TEMPERATURE_SENSORS, TEMPERATURE_NAMES_MAX};

/// Owns labels and ordered source identifiers for one physical boot.
/// Session resets must retain this object. Sources identify driver instances,
/// while labels are opaque display text and may repeat.
pub struct TemperatureInventory<S: Copy> {
    sources: Vec<S, MAX_TEMPERATURE_SENSORS>,
    names: Vec<u8, TEMPERATURE_NAMES_MAX>,
}

impl<S: Copy> Default for TemperatureInventory<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Copy> TemperatureInventory<S> {
    pub const fn new() -> Self {
        Self {
            sources: Vec::new(),
            names: Vec::new(),
        }
    }

    /// Register atomically. Existing entries can never be changed or removed.
    pub fn register(&mut self, source: S, name: &str) -> Result<usize, Status> {
        let mut encoded = [0; temperature::NAME_MAX_BYTES + 1];
        let len = temperature::encode_names(&[name], &mut encoded)
            .map_err(|_| Status::INVALID_ARGUMENT)?;
        if self.sources.is_full() || self.names.len() + len > TEMPERATURE_NAMES_MAX {
            return Err(Status::NOMEM);
        }
        let index = self.sources.len();
        // Both capacities were checked before changing either array.
        let _ = self.sources.push(source);
        self.names
            .extend_from_slice(&encoded[..len])
            .expect("checked name capacity");
        Ok(index)
    }

    /// Capture before acquisition. Registrations made afterward belong to the
    /// next sample, even when individual sensor reads yield to other tasks.
    pub fn snapshot(&self) -> Vec<S, MAX_TEMPERATURE_SENSORS> {
        self.sources.clone()
    }

    /// Names are inventory data; this never accesses a sensor or driver.
    pub fn read_names(&self, out: &mut [u8]) -> Result<usize, Status> {
        let len = self.names.len();
        let dest = out.get_mut(..len).ok_or(Status::NOMEM)?;
        dest.copy_from_slice(&self.names);
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names<S: Copy>(inventory: &TemperatureInventory<S>) -> std::vec::Vec<u8> {
        let mut out = [0; TEMPERATURE_NAMES_MAX];
        let len = inventory.read_names(&mut out).unwrap();
        out[..len].to_vec()
    }

    #[test]
    fn temperature_inventory_owns_names_and_keeps_snapshot_indices() {
        let mut inventory = TemperatureInventory::new();
        assert!(inventory.snapshot().is_empty());
        assert_eq!(inventory.read_names(&mut []), Ok(0));
        let mut label = std::string::String::from("電池");
        assert_eq!(inventory.register(10, &label), Ok(0));
        label.clear();
        let captured = inventory.snapshot();
        assert_eq!(inventory.register(20, "電池"), Ok(1));
        assert_eq!(&captured[..], &[10]);
        assert_eq!(&inventory.snapshot()[..], &[10, 20]);
        assert_eq!(
            temperature::names(&names(&inventory))
                .unwrap()
                .collect::<std::vec::Vec<_>>(),
            ["電池", "電池"]
        );
        let mut too_short = [0xaa; 1];
        assert_eq!(inventory.read_names(&mut too_short), Err(Status::NOMEM));
        assert_eq!(too_short, [0xaa]);
    }

    #[test]
    fn temperature_inventory_registration_failures_are_atomic() {
        let mut inventory = TemperatureInventory::new();
        inventory.register(0, "MCU die").unwrap();
        let initial = names(&inventory);
        for label in ["", "a\0b", &"a".repeat(65)] {
            assert_eq!(inventory.register(1, label), Err(Status::INVALID_ARGUMENT));
            assert_eq!(names(&inventory), initial);
            assert_eq!(&inventory.snapshot()[..], &[0]);
        }
        for index in 1..MAX_TEMPERATURE_SENSORS {
            inventory.register(index, "a").unwrap();
        }
        let full = names(&inventory);
        assert_eq!(inventory.register(99, "b"), Err(Status::NOMEM));
        assert_eq!(names(&inventory), full);
        assert_eq!(inventory.snapshot().len(), MAX_TEMPERATURE_SENSORS);

        let mut inventory = TemperatureInventory::new();
        for index in 0..4 {
            inventory.register(index, &"a".repeat(64)).unwrap();
        }
        let before = names(&inventory);
        assert_eq!(inventory.register(4, "abcdefghijkl"), Err(Status::NOMEM));
        assert_eq!(inventory.snapshot().len(), 4);
        assert_eq!(names(&inventory), before);
        assert_eq!(inventory.register(4, "abcdefghijk"), Ok(4));
        assert_eq!(names(&inventory).len(), TEMPERATURE_NAMES_MAX);
    }
}
