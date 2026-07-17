//! RAM-budget measurement for the session object embedded firmwares
//! carry in a task future. Run with `--nocapture` to see the numbers.

use umsh_companion_ncp::Session;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};

#[test]
fn session_size_within_budget() {
    let size = core::mem::size_of::<Session<SoftwareAes, SoftwareSha256>>();
    println!("size_of::<Session> = {size} bytes");
    // The NCP images hold one Session inside a task-pool static; keep
    // growth deliberate. Raise this ceiling consciously, not by drift.
    assert!(size <= 32 * 1024, "Session grew past 32 KiB: {size}");
}
