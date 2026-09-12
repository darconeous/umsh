//! Bounded, secret-bearing station configuration. Never format credentials.
use heapless::Vec;
use umsh_ulcp::{Status, items, wifi};

pub const MAX_NETWORKS: usize = 4;

#[derive(Clone, PartialEq, Eq)]
pub struct KnownNetworks {
    entries: Vec<Vec<u8, { wifi::NETWORK_ENTRY_MAX_LEN }>, MAX_NETWORKS>,
}

impl Default for KnownNetworks {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl KnownNetworks {
    pub fn entries(&self) -> impl Iterator<Item = &[u8]> {
        self.entries.iter().map(|entry| entry.as_slice())
    }

    pub fn get(&self, ssid: &[u8]) -> Option<wifi::NetworkEntry<'_>> {
        self.entries()
            .filter_map(|bytes| wifi::NetworkEntry::decode(bytes).ok())
            .find(|entry| entry.ssid == ssid)
    }

    pub fn insert(&mut self, bytes: &[u8]) -> Result<(), Status> {
        let entry = wifi::NetworkEntry::decode(bytes).map_err(|_| Status::INVALID_ARGUMENT)?;
        entry.validate().map_err(|_| Status::INVALID_ARGUMENT)?;
        let index = self.entries.iter().position(|stored| {
            wifi::NetworkEntry::decode(stored).is_ok_and(|old| old.ssid == entry.ssid)
        });
        let next = Vec::from_slice(bytes).map_err(|_| Status::NOMEM)?;
        if let Some(index) = index {
            self.entries[index].fill(0);
            self.entries[index] = next;
        } else {
            self.entries.push(next).map_err(|_| Status::NOMEM)?;
        }
        Ok(())
    }

    pub fn remove(&mut self, ssid: &[u8]) -> Result<(), Status> {
        let index = self
            .entries
            .iter()
            .position(|stored| wifi::NetworkEntry::decode(stored).is_ok_and(|old| old.ssid == ssid))
            .ok_or(Status::ITEM_NOT_FOUND)?;
        self.entries[index].fill(0);
        self.entries.remove(index);
        Ok(())
    }

    /// Build the complete candidate before committing any mutation.
    pub fn replacement(
        bytes: &[u8],
        validate: impl Fn(&wifi::NetworkEntry<'_>) -> Result<(), Status>,
    ) -> Result<Self, Status> {
        let mut candidate = Self::default();
        for item in items::prefixed_items(bytes) {
            let item = item.map_err(|_| Status::INVALID_ARGUMENT)?;
            let entry = wifi::NetworkEntry::decode(item).map_err(|_| Status::INVALID_ARGUMENT)?;
            entry.validate().map_err(|_| Status::INVALID_ARGUMENT)?;
            if candidate.get(entry.ssid).is_some() {
                return Err(Status::INVALID_ARGUMENT);
            }
            validate(&entry)?;
            candidate.insert(item)?;
        }
        Ok(candidate)
    }

    pub fn encode_reported(&self, out: &mut [u8]) -> Result<usize, Status> {
        let mut len = 0;
        for bytes in self.entries() {
            let entry = wifi::NetworkEntry::decode(bytes).map_err(|_| Status::INTERNAL_ERROR)?;
            let mut item = [0; 3 + wifi::SSID_MAX_LEN];
            let n = entry
                .encode_reported(&mut item)
                .map_err(|_| Status::INTERNAL_ERROR)?;
            len +=
                items::encode_prefixed_item(&item[..n], out.get_mut(len..).ok_or(Status::NOMEM)?)
                    .map_err(|_| Status::NOMEM)?;
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ssid: &[u8], password: &[u8]) -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0, 2, ssid.len() as u8];
        bytes.extend_from_slice(ssid);
        bytes.extend_from_slice(password);
        bytes
    }

    #[test]
    fn replacement_rejects_duplicates_and_reads_redact_secrets() {
        let item = entry(b"office", b"password");
        let mut bytes = std::vec![item.len() as u8];
        bytes.extend_from_slice(&item);
        let table = KnownNetworks::replacement(&bytes, |_| Ok(())).unwrap();
        let mut out = [0; 144];
        let len = table.encode_reported(&mut out).unwrap();
        assert_eq!(&out[..len], b"\x09\x00\x02\x06office");
        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes);
        assert!(matches!(
            KnownNetworks::replacement(&duplicate, |_| Ok(())),
            Err(Status::INVALID_ARGUMENT)
        ));
        assert_eq!(table.get(b"office").unwrap().credential, b"password");
    }

    #[test]
    fn capacity_and_bytewise_names() {
        let mut table = KnownNetworks::default();
        for n in 0..4 {
            table.insert(&entry(&[0xff, n], b"password")).unwrap();
        }
        assert_eq!(
            table.insert(&entry(b"fifth", b"password")),
            Err(Status::NOMEM)
        );
        table.insert(&entry(&[0xff, 0], b"replaced")).unwrap();
        assert_eq!(table.get(&[0xff, 0]).unwrap().credential, b"replaced");
        table.remove(&[0xff, 0]).unwrap();
        assert!(table.get(&[0xff, 0]).is_none());
    }
}
