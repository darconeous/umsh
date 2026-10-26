//! A [`SoftPlatform`] for a real device with no hardware of its own.
//!
//! State lives in a directory: the saved configuration in `snapshot.bin`,
//! the identity secret in `identity.key`, and, on a device whose store
//! keeps them, the device lists in `lists.bin`. Identities come from the
//! operating system's generator, and the wall clock is the system's,
//! which a host may read but not set. The device makes its identity as it
//! first comes up, as firmware does.

use std::fs::{self, File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;

use umsh_ulcp_device::Effect;

use crate::soft::{DeviceSession, SoftPlatform};

const SNAPSHOT_FILE: &str = "snapshot.bin";
const IDENTITY_FILE: &str = "identity.key";
const LISTS_FILE: &str = "lists.bin";

/// Exclusive use of one device's state directory, for as long as it is
/// held.
///
/// Two devices sharing an identity would send under one key with two
/// frame counters, and each would see the other's frames as replays. The
/// lock is the operating system's, so it holds across processes—a tool
/// and its twin, or an app and its extension—and is released when its
/// holder exits, however it exits.
pub struct StateLock {
    _file: File,
}

impl StateLock {
    /// Take the lock on `dir`, or `None` if another holder has it.
    pub fn try_acquire(dir: &Path) -> io::Result<Option<Self>> {
        let file = File::create(dir.join("lock"))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error),
        }
    }
}

/// Files under one directory, the OS generator, and the system clock.
pub struct HostPlatform {
    dir: PathBuf,
    held_lists: Option<&'static [[u8; 32]]>,
}

impl HostPlatform {
    /// Keep state under `dir`, creating it if needed.
    pub fn new(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            held_lists: None,
        })
    }

    /// Keep the device lists in their own file rather than the snapshot,
    /// as a communicator's store does, with `defaults` the channel keys
    /// they hold after a reset with none kept.
    pub fn holding_lists(mut self, defaults: &'static [[u8; 32]]) -> Self {
        self.held_lists = Some(defaults);
        self
    }

    /// The directory state is kept in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn read(&self, name: &str) -> Option<Vec<u8>> {
        fs::read(self.dir.join(name)).ok()
    }

    /// Write by replacing, so a crash leaves the old file or the new one.
    fn write(&self, name: &str, contents: Option<&[u8]>) -> Result<(), ()> {
        let path = self.dir.join(name);
        match contents {
            None => match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(()),
            },
            Some(contents) => {
                let staged = self.dir.join(format!("{name}.new"));
                write_private(&staged, contents).map_err(|_| ())?;
                fs::rename(&staged, &path).map_err(|_| ())
            }
        }
    }
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    fs::write(path, contents)
}

impl SoftPlatform for HostPlatform {
    fn load_snapshot(&mut self) -> Option<Vec<u8>> {
        self.read(SNAPSHOT_FILE)
    }

    fn store_snapshot(&mut self, snapshot: Option<&[u8]>) -> Result<(), ()> {
        self.write(SNAPSHOT_FILE, snapshot)
    }

    fn load_identity(&mut self) -> Option<[u8; 32]> {
        self.read(IDENTITY_FILE)?.try_into().ok()
    }

    fn store_identity(&mut self, secret: Option<&[u8; 32]>) -> Result<(), ()> {
        self.write(IDENTITY_FILE, secret.map(|secret| &secret[..]))
    }

    fn held_lists(&self) -> Option<&'static [[u8; 32]]> {
        self.held_lists
    }

    fn load_lists(&mut self) -> Option<Vec<u8>> {
        self.read(LISTS_FILE)
    }

    fn store_lists(&mut self, record: Option<&[u8]>) -> Result<(), ()> {
        self.write(LISTS_FILE, record)
    }

    fn generate_secret(&mut self) -> [u8; 32] {
        let mut secret = [0; 32];
        rand::rng().fill_bytes(&mut secret);
        secret
    }

    fn generates_identity_at_boot(&self) -> bool {
        true
    }

    /// A soft device has no receiver to sample, so an RSSI read fails
    /// rather than going unanswered. Its configuration advertises nothing
    /// else a platform has to serve.
    fn peripheral(
        &mut self,
        effect: Effect,
        session: &mut DeviceSession,
        mut emit: &mut dyn FnMut(&[u8]),
    ) {
        if let Effect::SampleRssi { tid } = effect {
            session.respond_rssi(tid, Err(()), &mut emit);
        }
    }

    fn wall_clock(&mut self) -> Option<u32> {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        u32::try_from(seconds).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soft::SoftDevice;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("umsh-host-platform-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn one_holder_at_a_time() {
        let dir = scratch("lock");
        fs::create_dir_all(&dir).unwrap();
        let first = StateLock::try_acquire(&dir).unwrap();
        assert!(first.is_some());
        assert!(StateLock::try_acquire(&dir).unwrap().is_none());
        drop(first);
        assert!(StateLock::try_acquire(&dir).unwrap().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_identity_is_made_once_and_kept() {
        let dir = scratch("identity");
        let boot = || {
            SoftDevice::new(
                crate::tests::test_config(),
                HostPlatform::new(&dir).unwrap(),
            )
        };
        drop(boot());
        let secret = fs::read(dir.join(IDENTITY_FILE)).expect("made at first boot");
        assert_eq!(secret.len(), 32);
        drop(boot());
        assert_eq!(
            fs::read(dir.join(IDENTITY_FILE)).unwrap(),
            secret,
            "and kept"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A snapshot taken under the stored identity restores with the PHY
    /// as it was saved, which needs the identity installed first.
    #[test]
    fn a_saved_phy_comes_back_enabled() {
        use umsh_ulcp::{frame, hdlc, ids::prop};
        let dir = scratch("phy");
        let boot = || {
            SoftDevice::new(
                crate::tests::test_config(),
                HostPlatform::new(&dir).unwrap(),
            )
        };
        let send = |device: &mut SoftDevice<HostPlatform>, request: &[u8]| {
            let mut wire = vec![0; hdlc::max_encoded_len(request.len())];
            let len = hdlc::encode_frame(request, &mut wire).unwrap();
            device.ingest(&wire[..len], 0).unwrap();
            while device.take_outbound().is_some() {}
        };
        let mut device = boot();
        device.attach();
        while device.take_outbound().is_some() {}
        let mut request = [0u8; 32];
        let len = frame::prop_set(&mut request, 1, prop::PHY_ENABLED, &[1]).unwrap();
        send(&mut device, &request[..len]);
        let len = frame::save(&mut request, 2).unwrap();
        send(&mut device, &request[..len]);
        assert!(device.session().settings().enabled);
        drop(device);
        assert!(boot().session().settings().enabled);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn erasing_a_file_that_is_not_there_is_fine() {
        let dir = scratch("erase");
        let mut platform = HostPlatform::new(&dir).unwrap();
        assert_eq!(platform.store_snapshot(None), Ok(()));
        assert_eq!(platform.store_snapshot(Some(b"abc")), Ok(()));
        assert_eq!(platform.load_snapshot().as_deref(), Some(&b"abc"[..]));
        assert_eq!(platform.store_snapshot(None), Ok(()));
        assert_eq!(platform.load_snapshot(), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
