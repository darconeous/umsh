//! Replay every committed seed and regression through its target.
//!
//! One test on purpose: targets reset process-wide ledgers, and parallel
//! tests would share them.

use std::fs;
use std::io::{self, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use umsh_fuzz_harness::mac::{
    self, Delivered, MAC_COMMAND_ECHO_REQUEST_ID, MAC_COMMAND_FRAME_VERIFIED_ID,
    MAC_COMMAND_VERIFY_FRAME_ID, Mode, Oracles, Outcome,
};
use umsh_fuzz_harness::targets;

fn inputs(root: &Path, target: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root.join(target)) else {
        return Vec::new();
    };
    let mut paths: Vec<_> = entries
        .map(|entry| entry.expect("readable directory").path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    paths
}

/// How long one input may run in a debug build. A hang cannot unwind to
/// `catch_unwind`: without a limit it would hold the CI job until the job is
/// killed, without ever naming the input.
const INPUT_LIMIT: Duration = Duration::from_secs(60);

type Running = Arc<Mutex<Option<(PathBuf, Instant)>>>;

/// End the process if an input outlives [`INPUT_LIMIT`].
fn watchdog() -> Running {
    let running: Running = Arc::default();
    let watched = running.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));
            if let Some((path, started)) = &*watched.lock().expect("never held across a run")
                && started.elapsed() > INPUT_LIMIT
            {
                // Not `eprintln!`: a spawned thread inherits the test's output
                // capture, and exiting here would discard what it captured.
                let message = format!("hung: {} passed {INPUT_LIMIT:?}\n", path.display());
                let _ = io::stderr().write_all(message.as_bytes());
                process::exit(101);
            }
        }
    });
    running
}

#[test]
fn seeds_and_regressions_replay() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let running = watchdog();
    let mut failures = Vec::new();
    for target in targets::ALL {
        for root in ["seeds", "regressions"] {
            for path in inputs(&manifest.join(root), target.name) {
                let data = fs::read(&path).expect("readable input");
                *running.lock().expect("never held across a run") =
                    Some((path.clone(), Instant::now()));
                let outcome = panic::catch_unwind(AssertUnwindSafe(|| (target.run)(&data)));
                *running.lock().expect("never held across a run") = None;
                if outcome.is_err() {
                    failures.push(path);
                }
            }
        }
    }
    assert!(failures.is_empty(), "inputs that fail: {failures:#?}");
}

/// A directory under `seeds/` or `regressions/` for a target that no longer
/// exists is an input nothing replays.
#[test]
fn every_input_directory_has_a_target() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for root in ["seeds", "regressions"] {
        let Ok(entries) = fs::read_dir(manifest.join(root)) else {
            continue;
        };
        for entry in entries {
            let name = entry.expect("readable directory").file_name();
            let name = name.to_string_lossy();
            assert!(
                targets::ALL.iter().any(|target| target.name == name),
                "{root}/{name} has no target"
            );
        }
    }
}

fn mac_seed(name: &str) -> Outcome {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("seeds/umsh_mac")
        .join(name);
    let data = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    mac::run(&data, Mode::Sealed, Oracles::All)
}

const OK: &[u8] = b"ok";

fn delivered_ok(outcome: &Outcome) -> usize {
    let hello = |delivered: &&Delivered| delivered.payload.ends_with(OK);
    outcome.received.iter().filter(hello).count()
}

/// A seed that stops reaching what it was written for fails here, not by a
/// quiet loss of coverage in a nightly run nobody compares.
#[test]
fn resync_seeds_reach_the_exchange_they_were_written_for() {
    for carriage in ["unicast", "blind"] {
        let held = mac_seed(&format!("resync-held-{carriage}"));
        assert!(
            held.commands_aired.contains(&MAC_COMMAND_VERIFY_FRAME_ID),
            "{carriage}: no Verify Frame: {held:?}"
        );
        assert_eq!(
            delivered_ok(&held),
            2,
            "{carriage}: the held frame was not released: {held:?}"
        );

        let echo = mac_seed(&format!("resync-echo-{carriage}"));
        assert!(
            echo.commands_aired.contains(&MAC_COMMAND_ECHO_REQUEST_ID),
            "{carriage}: no Echo Request: {echo:?}"
        );
        assert_eq!(
            delivered_ok(&echo),
            2,
            "{carriage}: the new baseline did not take: {echo:?}"
        );

        let vouch = mac_seed(&format!("vouch-{carriage}"));
        assert!(
            vouch
                .commands_aired
                .contains(&MAC_COMMAND_FRAME_VERIFIED_ID),
            "{carriage}: no Frame Verified: {vouch:?}"
        );
    }
}

#[test]
fn signed_seeds_verify() {
    for kind in ["broadcast", "multicast", "unicast", "blind"] {
        let outcome = mac_seed(&format!("signed-{kind}"));
        assert!(
            outcome.received.iter().any(|d| d.signature_verified),
            "{kind}: {outcome:?}"
        );
    }
}
