//! `replay`: put what the fuzzers found onto a real board.
//!
//! Host fuzzing cannot see stack overflow, flash wear, peripheral timing,
//! or a real driver's limits. This sends a corpus exported by the harness's
//! `export_replay` example at a board set aside for the purpose, probes it
//! as it goes, and on a miss keeps the frames that led there.
//!
//! The corpus scrambles whatever settings it reaches, so nothing runs until
//! the board attached is the one named. Frames that would end the run
//! without saying anything about the board, or wear its flash, are held back.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::time::{Instant, sleep, timeout};
use umsh::ulcp::{FrameLink, UlcpDevice};
use umsh::ulcp_wire::Status;
use umsh::ulcp_wire::frame::{self, Cmd, FRAME_IN_MAX, Frame, PropPayload};
use umsh::ulcp_wire::ids::{prop, stream};

use super::values::KeyArg;
use crate::App;
use crate::connection::{self, SessionLink, Target};
use crate::output::{field, note};

/// A frame for the board's host link.
const KIND_HOST: u8 = 1;
/// A frame for the air.
const KIND_RADIO: u8 = 2;

const PROBE_TID: u8 = 7;

#[derive(Debug, clap::Args)]
pub struct ReplayArgs {
    /// A file written by the harness's `export_replay` example.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// The bench board's device key. Any other board is refused.
    #[arg(long, value_name = "KEY")]
    pub bench: KeyArg,

    /// Put radio frames on the air from the attached board, and watch the
    /// bench board on this serial port.
    #[arg(long, value_name = "PORT")]
    pub watch: Option<String>,

    /// Frames between liveness probes.
    #[arg(long, value_name = "N", default_value_t = 16,
          value_parser = clap::value_parser!(u32).range(1..))]
    pub probe_every: u32,

    /// Seconds a probe may take.
    #[arg(long, value_name = "SECONDS", default_value_t = 5)]
    pub probe_timeout: u64,

    /// Milliseconds between frames. The air gets a floor of one second.
    #[arg(long, value_name = "MS", default_value_t = 0)]
    pub interval_ms: u64,

    /// Seconds between frames that write to flash.
    #[arg(long, value_name = "SECONDS", default_value_t = 60)]
    pub save_interval: u64,

    /// How many of the last frames a reproducer keeps.
    #[arg(long, value_name = "N", default_value_t = 256)]
    pub keep: usize,

    /// Where a reproducer goes.
    #[arg(long, value_name = "FILE", default_value = "replay-failure.bin")]
    pub reproducer: PathBuf,
}

/// One frame of an export.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    kind: u8,
    frame: Vec<u8>,
}

fn parse(bytes: &[u8]) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let [kind, hi, lo, tail @ ..] = rest else {
            bail!("the file ends inside a record header");
        };
        let len = usize::from(u16::from_be_bytes([*hi, *lo]));
        if len > tail.len() {
            bail!("the file ends inside a record");
        }
        if !matches!(*kind, KIND_HOST | KIND_RADIO) {
            bail!("a record of unknown kind {kind}");
        }
        records.push(Record {
            kind: *kind,
            frame: tail[..len].to_vec(),
        });
        rest = &tail[len..];
    }
    Ok(records)
}

fn encode<'a>(records: impl Iterator<Item = &'a Record>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        bytes.push(record.kind);
        bytes.extend_from_slice(&(record.frame.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&record.frame);
    }
    bytes
}

/// What to do with a host frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handling {
    Send,
    /// It writes to flash: at most one per `--save-interval`.
    RateLimited,
    /// Its session reset is the board doing as it was told.
    ExpectReset,
    Withhold,
}

/// Reboots and resets to factory would read as the crash this looks for, and
/// DFU leaves the board waiting for an image. A bus transfer can reach a
/// power manager, and a new identity would make this board stop being the
/// one named.
fn handling(bytes: &[u8]) -> Handling {
    let Ok(parsed) = Frame::parse(bytes) else {
        return Handling::Send;
    };
    match parsed.command() {
        Some(Cmd::Dfu | Cmd::Reboot | Cmd::FactoryReset | Cmd::I2cTransfer) => Handling::Withhold,
        Some(Cmd::Save | Cmd::Clear) => Handling::RateLimited,
        Some(Cmd::Reset | Cmd::Restore) => Handling::ExpectReset,
        Some(Cmd::PropSet)
            if PropPayload::parse(parsed.payload)
                .is_ok_and(|payload| payload.key == prop::DEV_PRIVATE_KEY) =>
        {
            Handling::Withhold
        }
        _ => Handling::Send,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Health {
    Alive,
    Silent,
    Reset,
    Lost,
}

/// Take what has arrived, reporting a session reset nobody asked for.
async fn drain(device: &mut UlcpDevice<SessionLink>, expect_reset: &mut bool) -> Health {
    loop {
        match timeout(Duration::from_millis(1), device.link_mut().recv_frame()).await {
            Err(_) => return Health::Alive,
            Ok(Err(_)) => return Health::Lost,
            Ok(Ok(bytes)) => {
                let reset = Frame::parse(&bytes)
                    .is_ok_and(|parsed| parsed.command() == Some(Cmd::SessionReset));
                if reset && !std::mem::take(expect_reset) {
                    return Health::Reset;
                }
            }
        }
    }
}

/// Ask the board something only a running session answers.
async fn probe(device: &mut UlcpDevice<SessionLink>, wait: Duration) -> Health {
    let mut request = [0u8; 8];
    let Ok(len) = frame::nop(&mut request, PROBE_TID) else {
        return Health::Lost;
    };
    if device.link_mut().send_frame(&request[..len]).await.is_err() {
        return Health::Lost;
    }
    let mut ok = [0u8; 16];
    let Ok(ok_len) = frame::last_status(&mut ok, PROBE_TID, Status::OK) else {
        return Health::Lost;
    };
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match timeout(left, device.link_mut().recv_frame()).await {
            Err(_) => return Health::Silent,
            Ok(Err(_)) => return Health::Lost,
            Ok(Ok(bytes)) if bytes == ok[..ok_len] => return Health::Alive,
            Ok(Ok(_)) => {}
        }
    }
}

async fn board_key<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<[u8; 32]> {
    let value = device.get_prop(prop::DEV_KEY).await?;
    value
        .as_slice()
        .try_into()
        .context("the board reports no device key")
}

pub async fn run(app: &mut App, args: ReplayArgs) -> Result<()> {
    let bytes =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let records = parse(&bytes)?;
    let mut watched = match &args.watch {
        Some(port) => Some(
            connection::connect(
                Target::Serial {
                    port: port.clone(),
                    baud: app.baud,
                },
                false,
            )
            .await?,
        ),
        None => None,
    };
    let bench = match watched.as_mut() {
        Some(session) => &mut session.device,
        None => app.device()?,
    };
    if board_key(bench).await? != args.bench.0 {
        bail!("the board attached is not the bench board named; nothing was sent");
    }

    let air_gap = Duration::from_millis(args.interval_ms.max(1_000));
    let host_gap = Duration::from_millis(args.interval_ms);
    let save_gap = Duration::from_secs(args.save_interval);
    let wait = Duration::from_secs(args.probe_timeout);

    let mut recent: VecDeque<Record> = VecDeque::with_capacity(args.keep);
    let (mut sent, mut withheld, mut since_probe) = (0u32, 0u32, 0u32);
    let mut last_save: Option<Instant> = None;
    let mut expect_reset = false;

    for record in records {
        let injector = app.device()?;
        let (wire, gap) = if record.kind == KIND_RADIO {
            if args.watch.is_none() {
                // With nothing to put it on the air from, a radio frame
                // says nothing about a board that never hears it.
                withheld += 1;
                continue;
            }
            let mut wire = [0u8; FRAME_IN_MAX];
            let Ok(len) = frame::str_send(&mut wire, 1, stream::PHY_RAW, &record.frame, &[]) else {
                withheld += 1;
                continue;
            };
            (wire[..len].to_vec(), air_gap)
        } else {
            match handling(&record.frame) {
                Handling::Withhold => {
                    withheld += 1;
                    continue;
                }
                Handling::RateLimited => {
                    if last_save.is_some_and(|last| last.elapsed() < save_gap) {
                        withheld += 1;
                        continue;
                    }
                    last_save = Some(Instant::now());
                }
                Handling::ExpectReset => expect_reset = true,
                Handling::Send => {}
            }
            (record.frame.clone(), host_gap)
        };

        if recent.len() == args.keep {
            recent.pop_front();
        }
        recent.push_back(record);

        let delivered = injector.link_mut().send_frame(&wire).await.is_ok();
        sent += 1;
        since_probe += 1;
        sleep(gap).await;

        let bench = match watched.as_mut() {
            Some(session) => &mut session.device,
            None => app.device()?,
        };
        let mut health = if delivered {
            drain(bench, &mut expect_reset).await
        } else {
            Health::Lost
        };
        if health == Health::Alive && since_probe >= args.probe_every {
            since_probe = 0;
            health = probe(bench, wait).await;
        }
        if health != Health::Alive {
            std::fs::write(&args.reproducer, encode(recent.iter()))
                .with_context(|| format!("writing {}", args.reproducer.display()))?;
            bail!(
                "the board stopped answering ({health:?}) after {sent} frames; the last {} are in {}",
                recent.len(),
                args.reproducer.display()
            );
        }
    }

    let bench = match watched.as_mut() {
        Some(session) => &mut session.device,
        None => app.device()?,
    };
    let health = probe(bench, wait).await;
    if health != Health::Alive {
        std::fs::write(&args.reproducer, encode(recent.iter()))
            .with_context(|| format!("writing {}", args.reproducer.display()))?;
        bail!(
            "the board stopped answering ({health:?}) at the end; the last {} frames are in {}",
            recent.len(),
            args.reproducer.display()
        );
    }
    field("Sent", sent);
    field("Withheld", withheld);
    note("the board answered every probe");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn built(build: impl Fn(&mut [u8]) -> usize) -> Vec<u8> {
        let mut buf = [0u8; 64];
        let len = build(&mut buf);
        buf[..len].to_vec()
    }

    #[test]
    fn an_export_reads_back() {
        let records = vec![
            Record {
                kind: KIND_HOST,
                frame: vec![1, 2, 3],
            },
            Record {
                kind: KIND_RADIO,
                frame: vec![],
            },
        ];
        assert_eq!(parse(&encode(records.iter())).unwrap(), records);
    }

    #[test]
    fn a_damaged_export_is_refused() {
        assert!(parse(&[KIND_HOST, 0]).is_err());
        assert!(parse(&[KIND_HOST, 0, 4, 1]).is_err());
        assert!(parse(&[9, 0, 0]).is_err());
    }

    #[test]
    fn what_would_end_the_run_is_withheld() {
        assert_eq!(
            handling(&built(|b| frame::reboot(b, 1).unwrap())),
            Handling::Withhold
        );
        assert_eq!(
            handling(&built(|b| frame::factory_reset(b, 1).unwrap())),
            Handling::Withhold
        );
        assert_eq!(
            handling(&built(|b| frame::dfu(b, 1, None).unwrap())),
            Handling::Withhold
        );
        assert_eq!(
            handling(&built(|b| {
                frame::prop_set(b, 1, prop::DEV_PRIVATE_KEY, &[0; 32]).unwrap()
            })),
            Handling::Withhold
        );
    }

    #[test]
    fn a_save_is_rate_limited_and_a_reset_expected() {
        assert_eq!(
            handling(&built(|b| frame::save(b, 1).unwrap())),
            Handling::RateLimited
        );
        assert_eq!(
            handling(&built(|b| frame::reset(b, 1).unwrap())),
            Handling::ExpectReset
        );
    }

    #[test]
    fn everything_else_goes_out() {
        assert_eq!(handling(&[0xFF, 0xFF, 0xFF]), Handling::Send);
        assert_eq!(
            handling(&built(|b| frame::prop_get(b, 1, prop::DEV_NAME).unwrap())),
            Handling::Send
        );
    }
}
