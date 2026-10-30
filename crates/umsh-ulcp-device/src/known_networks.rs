//! Bounded, secret-bearing station configuration. Never format credentials.
use heapless::Vec;
use umsh_ulcp::{Status, items, wifi};

pub const MAX_NETWORKS: usize = 4;

/// One encoded entry, credential included.
pub type EntryBytes = Vec<u8, { wifi::NETWORK_ENTRY_MAX_LEN }>;

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

/// Names only: a credential is never formatted.
impl core::fmt::Debug for KnownNetworks {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list()
            .entries(
                self.entries()
                    .filter_map(|bytes| wifi::NetworkEntry::decode(bytes).ok())
                    .map(|entry| entry.ssid),
            )
            .finish()
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

    /// The entry an insert of `bytes` stores. That is `bytes` itself,
    /// unless it is the form that keeps a stored credential: then the
    /// stored entry's credential and raw-key flag under the new flags.
    /// Answers `STATUS_ITEM_NOT_FOUND` when there is no entry to keep a
    /// credential from, and `STATUS_INVALID_ARGUMENT` when the mode
    /// changed, since a new mode needs a credential of its own.
    pub fn resolve(&self, bytes: &[u8]) -> Result<EntryBytes, Status> {
        let entry = wifi::NetworkEntry::decode(bytes).map_err(|_| Status::INVALID_ARGUMENT)?;
        entry
            .validate_insert()
            .map_err(|_| Status::INVALID_ARGUMENT)?;
        if !entry.keeps_credential() {
            return Vec::from_slice(bytes).map_err(|_| Status::INVALID_ARGUMENT);
        }
        let stored = self.get(entry.ssid).ok_or(Status::ITEM_NOT_FOUND)?;
        if stored.security != entry.security {
            return Err(Status::INVALID_ARGUMENT);
        }
        let merged = wifi::NetworkEntry {
            raw_key: stored.raw_key,
            credential: stored.credential,
            ..entry
        };
        let mut out = EntryBytes::new();
        out.resize_default(wifi::NETWORK_ENTRY_MAX_LEN)
            .map_err(|_| Status::INTERNAL_ERROR)?;
        let len = merged
            .encode(&mut out)
            .map_err(|_| Status::INTERNAL_ERROR)?;
        out.truncate(len);
        Ok(out)
    }

    /// Store a whole entry, replacing any with its SSID. The keep form
    /// goes through [`Self::resolve`] first.
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
    fn an_insert_without_a_credential_keeps_the_stored_one() {
        let mut table = KnownNetworks::default();
        table.insert(&entry(b"office", b"password")).unwrap();
        // Manual, same mode, no credential.
        let keep = [
            wifi::FLAG_MANUAL | wifi::FLAG_RAW_KEY,
            2,
            6,
            b'o',
            b'f',
            b'f',
            b'i',
            b'c',
            b'e',
        ];
        let merged = table.resolve(&keep).unwrap();
        let decoded = wifi::NetworkEntry::decode(&merged).unwrap();
        assert!(decoded.manual);
        // The stored credential was a passphrase, whatever bit 1 said.
        assert!(!decoded.raw_key);
        assert_eq!(decoded.credential, b"password");
        table.insert(&merged).unwrap();
        assert!(table.get(b"office").unwrap().manual);
        assert_eq!(table.get(b"office").unwrap().credential, b"password");
        // A new mode needs its own credential; an unknown name has none
        // to keep.
        let mut wpa3 = keep;
        wpa3[1] = 3;
        assert_eq!(table.resolve(&wpa3), Err(Status::INVALID_ARGUMENT));
        let unknown = [0, 2, 4, b'h', b'o', b'm', b'e'];
        assert_eq!(table.resolve(&unknown), Err(Status::ITEM_NOT_FOUND));
        // A whole entry resolves to itself, and a whole-table write
        // still needs every credential.
        let whole = entry(b"home", b"password");
        assert_eq!(table.resolve(&whole).unwrap().as_slice(), whole.as_slice());
        let mut set = std::vec![keep.len() as u8];
        set.extend_from_slice(&keep);
        assert!(matches!(
            KnownNetworks::replacement(&set, |_| Ok(())),
            Err(Status::INVALID_ARGUMENT)
        ));
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
