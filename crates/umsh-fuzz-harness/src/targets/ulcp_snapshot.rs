//! A saved snapshot is flash, and flash is an input: boot must survive any
//! bytes, and a snapshot it accepts must be one it can keep.

use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
use umsh_ulcp::Status;
use umsh_ulcp_device::{SNAPSHOT_MAX, Session};

use crate::device;

type DeviceSession = Session<SoftwareAes, SoftwareSha256>;

fn session() -> DeviceSession {
    Session::new(
        device::config(),
        Status::RESET_POWER_ON,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
    )
}

pub fn run(data: &[u8]) {
    let mut first = session();
    if first.restore_at_boot(data).is_err() {
        return;
    }
    let mut encoded = [0u8; SNAPSHOT_MAX];
    let Some(len) = first.encode_snapshot(&mut encoded) else {
        return;
    };

    let mut second = session();
    second
        .restore_at_boot(&encoded[..len])
        .expect("a snapshot the device wrote restores");
    let mut again = [0u8; SNAPSHOT_MAX];
    let again_len = second
        .encode_snapshot(&mut again)
        .expect("it fit a moment ago");
    assert_eq!(encoded[..len], again[..again_len], "not stable");
}
