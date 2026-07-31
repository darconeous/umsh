//! `capture`: listen on the device's radio, decode what it hears, and
//! optionally write a Wireshark-compatible file.

pub mod decode;
pub mod pcap;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use umsh::hal::Radio as _;
use umsh::ulcp::{UlcpDevice, UlcpError};
use umsh::ulcp_wire::ids::prop;

use self::pcap::{CaptureLayers, PcapEncapsulation, PcapWriter, RfParams};
use super::values::HexU16Arg;
use super::{decode_u32, phy};
use crate::App;
use crate::connection::SessionLink;
use crate::output::{self, field, note, warn};

#[derive(Debug, clap::Args)]
pub struct CaptureArgs {
    /// Write a Wireshark-compatible capture here.
    #[arg(long, value_name = "PATH")]
    pub pcap: Option<PathBuf>,

    /// Which layers the capture file records.
    #[arg(long, value_enum, default_value_t = CaptureLayers::Radio)]
    pub layers: CaptureLayers,

    /// Store exact raw LoRa frames instead of the synthetic
    /// Ethernet/IPv4/UDP encapsulation (radio layer only).
    #[arg(long)]
    pub pcap_raw: bool,

    /// pcap LINKTYPE value required by --pcap-raw.
    #[arg(long, value_name = "N")]
    pub pcap_linktype: Option<u32>,

    /// Suppress raw/decoded output for frames that are not UMSH.
    #[arg(long)]
    pub umsh_only: bool,

    /// Verify link and radio health while the air is quiet.
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    pub idle_probe_secs: u64,

    /// Exit instead of recovering a failed BLE session.
    #[arg(long)]
    pub no_reconnect: bool,

    /// Seconds to wait before rediscovering after a failed session.
    #[arg(long, default_value_t = 2, value_name = "SECS")]
    pub reconnect_delay_secs: u64,

    /// Set the frequency in kHz for this session.
    #[arg(long, value_name = "KHZ", help_heading = "RF overrides")]
    pub freq_khz: Option<u32>,

    /// Set the LoRa bandwidth in Hz for this session.
    #[arg(long, value_name = "HZ", help_heading = "RF overrides")]
    pub bw_hz: Option<u32>,

    /// Set the LoRa spreading factor for this session.
    #[arg(long, value_parser = clap::value_parser!(u8).range(5..=12), help_heading = "RF overrides")]
    pub sf: Option<u8>,

    /// Set the LoRa coding-rate denominator for this session.
    #[arg(long, value_parser = clap::value_parser!(u8).range(5..=8), help_heading = "RF overrides")]
    pub cr: Option<u8>,

    /// Set the LoRa sync word for this session.
    #[arg(long, value_name = "N", help_heading = "RF overrides")]
    pub sync_word: Option<HexU16Arg>,

    /// Set the transmit power in dBm for this session.
    #[arg(
        long,
        value_name = "DBM",
        allow_hyphen_values = true,
        help_heading = "RF overrides"
    )]
    pub tx_power: Option<i8>,

    /// Decode nothing for a human: whatever reads the capture dissects
    /// it itself.
    ///
    /// Not a command-line flag — it belongs to the extcap interface,
    /// where Wireshark is the consumer. Narrating each frame there would
    /// decode every packet twice and fill Wireshark's log with output
    /// that reads like dissection but is not.
    #[arg(skip)]
    pub quiet: bool,
}

impl CaptureArgs {
    pub fn validate(&self) -> Result<()> {
        // `--layers` has a default, so "was it given?" is not visible
        // from the parsed value alone; anything other than the default
        // is an explicit choice, and an explicit default is harmless.
        let layers_given = self.layers != CaptureLayers::Radio;
        if layers_given && self.pcap.is_none() {
            bail!("--layers requires --pcap=PATH");
        }
        if self.pcap_raw {
            if self.pcap.is_none() {
                bail!("--pcap-raw requires --pcap=PATH");
            }
            if self.layers != CaptureLayers::Radio {
                bail!("--pcap-raw requires --layers=radio");
            }
            if self.pcap_linktype.is_none() {
                bail!("--pcap-raw requires --pcap-linktype=N");
            }
        } else if self.pcap_linktype.is_some() {
            bail!("--pcap-linktype requires --pcap-raw");
        }
        if self.idle_probe_secs == 0 {
            bail!("--idle-probe-secs must be greater than zero");
        }
        if self.reconnect_delay_secs == 0 {
            bail!("--reconnect-delay-secs must be greater than zero");
        }
        Ok(())
    }

    /// Whether the user asked for a specific RF configuration rather
    /// than accepting the one the device is already running.
    fn has_rf_overrides(&self) -> bool {
        self.freq_khz.is_some()
            || self.bw_hz.is_some()
            || self.sf.is_some()
            || self.cr.is_some()
            || self.sync_word.is_some()
            || self.tx_power.is_some()
    }

    fn encapsulation(&self) -> PcapEncapsulation {
        match self.pcap_linktype {
            Some(linktype) if self.pcap_raw => PcapEncapsulation::RawLoRa { linktype },
            _ => PcapEncapsulation::Ethernet,
        }
    }
}

/// Running totals, carried across BLE reconnects so one capture reads as
/// one capture.
struct Stats {
    started: Instant,
    last_progress: Instant,
    sequence: u64,
    displayed: u64,
    filtered: u64,
    sessions: u64,
}

impl Stats {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            last_progress: Instant::now(),
            sequence: 0,
            displayed: 0,
            filtered: 0,
            sessions: 0,
        }
    }
}

/// Why a capture stopped.
enum Stop {
    /// The capture was asked to stop; the tool is not in trouble.
    ///
    /// Either the user interrupted it, or whoever was reading the
    /// capture went away — Wireshark closing an extcap FIFO is a normal
    /// end to a capture, not a failure worth recovering from.
    Interrupted,
}

/// Whether an error is really "the reader hung up".
///
/// The tap writes through [`SessionLink`], so a closed sink can also
/// surface wrapped in a `UlcpError` that otherwise looks like the link
/// itself failed.
///
/// [`SessionLink`]: crate::connection::SessionLink
fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
    })
}

pub async fn run(app: &mut App, args: CaptureArgs) -> Result<()> {
    args.validate()?;

    let writer = match &args.pcap {
        Some(path) => {
            let writer = PcapWriter::create(path, args.layers, args.encapsulation())?;
            field(
                "capture",
                format!(
                    "{} layers={:?} encoding={}",
                    path.display(),
                    args.layers,
                    if args.pcap_raw {
                        "raw LoRa"
                    } else {
                        "Ethernet/IPv4/UDP"
                    },
                ),
            );
            Some(writer)
        }
        None => None,
    };

    run_with_writer(app, &args, writer).await
}

/// Capture into an already-built sink.
///
/// The extcap interface owns its own writer over Wireshark's FIFO, so
/// the two entry points differ only in where the sink came from.
pub(crate) async fn run_with_writer(
    app: &mut App,
    args: &CaptureArgs,
    writer: Option<PcapWriter>,
) -> Result<()> {
    let tapped = writer.is_some();
    if let Some(writer) = writer {
        *app.session()?.tap.borrow_mut() = Some(writer);
    }

    let outcome = capture_with_recovery(app, args).await;

    // Both cleanups run whatever happened: a half-written pcap and a
    // device left promiscuous are each worse than the original failure.
    if tapped
        && let Ok(session) = app.session()
    {
        session.tap.borrow_mut().take();
    }
    if app.interactive {
        clear_promiscuous(app).await;
    }
    outcome
}

/// Run the capture, recovering a dropped BLE link when asked to.
///
/// Reconnection belongs to one-shot mode, which owns the link and can
/// rediscover it. In the REPL the *session* owns the link: if it drops,
/// the REPL itself is unattached, and saying so beats silently
/// reconnecting underneath the user.
async fn capture_with_recovery(app: &mut App, args: &CaptureArgs) -> Result<()> {
    let mut stats = Stats::new();
    let reconnect = !args.no_reconnect && !app.interactive && app.target_is_ble();
    loop {
        stats.sessions += 1;
        let failure = match capture_once(app, args, &mut stats).await {
            Ok(Stop::Interrupted) => return Ok(()),
            Err(error) => error,
        };
        // Rediscovering the radio because the *capture reader* went away
        // would leave a process holding the link with nowhere to write.
        if is_broken_pipe(&failure) {
            return Ok(());
        }
        if !reconnect {
            return Err(failure);
        }
        eprintln!(
            "session failure +{:.3}s after {} packets: {failure}",
            stats.started.elapsed().as_secs_f64(),
            stats.sequence,
        );
        println!(
            "recovery: rediscovering in {} s (ctrl-c to exit) ...",
            args.reconnect_delay_secs,
        );
        tokio::time::sleep(Duration::from_secs(args.reconnect_delay_secs)).await;
        app.reconnect().await?;
    }
}

async fn capture_once(app: &mut App, args: &CaptureArgs, stats: &mut Stats) -> Result<Stop> {
    let interactive = app.interactive;
    let session = app.session()?;
    println!(
        "session #{}: device={} boot_status={:?}",
        stats.sessions,
        session.device.dev_version(),
        session.device.boot_status(),
    );

    if args.has_rf_overrides() {
        apply_rf(&mut session.device, args).await?;
        note("the radio's live RF configuration was changed for this session (never saved)");
    }
    report_rf(&mut session.device).await;
    // Read once per session: the radio holds these still for the whole
    // capture, but every LoRaTap record has to restate them.
    let rf = read_rf_params(&mut session.device).await;

    // A capture is a promiscuous listener. A device with a provisioned
    // (or saved-and-restored) host domain filters receptions, so the
    // factory deliver-everything rule cannot be relied on; bypass the
    // filtering for this session (`PROP_MAC_PROMISCUOUS` is
    // session-scoped and reverts on detach). A device that predates the
    // property refuses the set — capture then sees only frames matching
    // its receive filtering.
    match session.device.set_prop(prop::MAC_PROMISCUOUS, &[1]).await {
        Ok(_) => println!("promiscuous mode enabled"),
        Err(UlcpError::Status(status)) => warn(format!(
            "device refused promiscuous mode ({status:?}); capture is limited to the device's \
             receive filtering"
        )),
        Err(error) => return Err(error.into()),
    }

    let color = output::color();
    if !args.quiet {
        if color {
            decode::print_legend();
        }
        println!("dumping packets (ctrl-c to {}) ...", {
            if interactive { "stop" } else { "exit" }
        });
    }

    if interactive {
        // Ctrl-C is the way out of a capture that is going nowhere. In
        // the REPL that must return to the prompt, not kill the tool, so
        // the dump future is cancelled rather than the process.
        tokio::select! {
            result = dump(session, args, stats, color, &rf) => result,
            _ = tokio::signal::ctrl_c() => {
                println!();
                Ok(Stop::Interrupted)
            }
        }
    } else {
        dump(session, args, stats, color, &rf).await
    }
}

/// The receive loop. Only ever returns through an error or through the
/// caller cancelling it.
async fn dump(
    session: &mut crate::connection::Session,
    args: &CaptureArgs,
    stats: &mut Stats,
    color: bool,
    rf: &RfParams,
) -> Result<Stop> {
    use std::fmt::Write as _;

    let mut buf = [0u8; 256];
    let idle_probe_interval = Duration::from_secs(args.idle_probe_secs);
    loop {
        let receive = core::future::poll_fn(|cx| session.device.poll_receive(cx, &mut buf));
        let info = match tokio::time::timeout(idle_probe_interval, receive).await {
            Ok(result) => result?,
            Err(_) => {
                let value = session.device.get_prop(prop::PHY_RSSI).await?;
                let [rssi] = value.as_slice() else {
                    bail!("idle health probe returned malformed PHY_RSSI value: {value:02x?}");
                };
                // The probe itself is the point: it proves the link is
                // still answering. Only the narration is suppressed.
                if !args.quiet {
                    println!(
                        "idle +{:.3}s  received={}  displayed={}  filtered={}  session={}  \
                         link=ok  channel RSSI={} dBm",
                        stats.started.elapsed().as_secs_f64(),
                        stats.sequence,
                        stats.displayed,
                        stats.filtered,
                        stats.sessions,
                        *rssi as i8,
                    );
                }
                stats.last_progress = Instant::now();
                continue;
            }
        };
        stats.sequence += 1;
        let packet = &buf[..info.len];
        // `--umsh-only` gates the recording as well as the display: a
        // filtered capture that still carries every frame it claimed to
        // drop is not what the flag says it is.
        if !decode::should_display(packet, args.umsh_only) {
            stats.filtered += 1;
            if !args.quiet && stats.last_progress.elapsed() >= idle_probe_interval {
                println!(
                    "filter +{:.3}s  received={}  displayed={}  filtered={}  session={}  link=ok",
                    stats.started.elapsed().as_secs_f64(),
                    stats.sequence,
                    stats.displayed,
                    stats.filtered,
                    stats.sessions,
                );
                stats.last_progress = Instant::now();
            }
            continue;
        }
        if let Some(writer) = session.tap.borrow_mut().as_mut() {
            match writer.write_radio_with_info(rf, &info, packet) {
                Ok(()) => {}
                // Whoever was reading the capture closed it. That ends
                // the capture, but nothing about the radio is wrong.
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                    return Ok(Stop::Interrupted);
                }
                Err(error) => return Err(error.into()),
            }
        }
        stats.displayed += 1;
        if args.quiet {
            continue;
        }
        let mut meta = format!(
            "\n#{} +{:.3}s  {} B  RSSI {} dBm  SNR {}",
            stats.sequence,
            stats.started.elapsed().as_secs_f64(),
            info.len,
            info.rssi,
            info.snr,
        );
        // The attach counter only distinguishes anything once a link has
        // dropped and been re-established, which cannot happen over serial.
        if stats.sessions > 1 {
            let _ = write!(meta, "  s{}", stats.sessions);
        }
        if let Some(lqi) = info.lqi {
            let _ = write!(meta, "  LQI {}", lqi.get());
        }
        println!("{meta}");
        decode::print_frame(packet, color);
    }
}

/// Write the RF overrides the user asked for, as live-only state.
async fn apply_rf(device: &mut UlcpDevice<SessionLink>, args: &CaptureArgs) -> Result<()> {
    if let Some(khz) = args.freq_khz {
        device.set_prop(prop::PHY_FREQ, &khz.to_le_bytes()).await?;
    }
    if let Some(hz) = args.bw_hz {
        device
            .set_prop(prop::PHY_LORA_BW, &hz.to_le_bytes())
            .await?;
    }
    if let Some(sf) = args.sf {
        device.set_prop(prop::PHY_LORA_SF, &[sf]).await?;
    }
    if let Some(cr) = args.cr {
        device.set_prop(prop::PHY_LORA_CR, &[cr]).await?;
    }
    if let Some(sync) = args.sync_word {
        device
            .set_prop(prop::PHY_LORA_SW, &sync.0.to_le_bytes())
            .await?;
    }
    if let Some(dbm) = args.tx_power {
        device.set_prop(prop::PHY_TX_POWER, &[dbm as u8]).await?;
    }
    Ok(())
}

/// Say what the radio is actually listening on, read back from the
/// device rather than assumed.
async fn report_rf(device: &mut UlcpDevice<SessionLink>) {
    let mut parts = Vec::new();
    if let Some(freq) = device
        .get_prop(prop::PHY_FREQ)
        .await
        .ok()
        .and_then(|value| decode_u32(&value))
    {
        parts.push(format!("{freq} kHz"));
    }
    parts.extend(phy::lora_parts(device).await);
    parts.extend(phy::power_part(device).await);
    field("radio", parts.join(", "));
}

/// The same channel `report_rf` narrates, in a form a capture file can
/// carry.
///
/// A device that will not report a parameter leaves it zero: LoRaTap has
/// no way to say "unknown", and a wrong-looking zero is easier to spot
/// than a plausible invented value.
async fn read_rf_params(device: &mut UlcpDevice<SessionLink>) -> RfParams {
    let freq_khz = device
        .get_prop(prop::PHY_FREQ)
        .await
        .ok()
        .and_then(|value| decode_u32(&value))
        .unwrap_or(0);
    let bw_hz = device
        .get_prop(prop::PHY_LORA_BW)
        .await
        .ok()
        .and_then(|value| decode_u32(&value))
        .unwrap_or(0);
    let sf = device
        .get_prop(prop::PHY_LORA_SF)
        .await
        .ok()
        .and_then(|value| value.first().copied())
        .unwrap_or(0);
    // LoRa carries a 16-bit sync word whose nibbles interleave the
    // legacy 8-bit form (0x1424 is 0x12), which is all LoRaTap has room
    // for.
    let sync_word = device
        .get_prop(prop::PHY_LORA_SW)
        .await
        .ok()
        .and_then(|value| <[u8; 2]>::try_from(value.as_slice()).ok())
        .map(u16::from_le_bytes)
        .map(|sw| (((sw >> 8) as u8) & 0xf0) | (((sw >> 4) as u8) & 0x0f))
        .unwrap_or(0);

    RfParams {
        freq_hz: freq_khz.saturating_mul(1_000),
        bw_hz,
        sf,
        sync_word,
    }
}

/// Leave the device as it was found.
///
/// One-shot mode gets this for free: the session detaches when the
/// process exits and `PROP_MAC_PROMISCUOUS` is session-scoped. A REPL
/// session outlives the capture, so it has to say so explicitly.
async fn clear_promiscuous(app: &mut App) {
    let Ok(session) = app.session() else {
        return;
    };
    match session.device.set_prop(prop::MAC_PROMISCUOUS, &[0]).await {
        Ok(_) => println!("promiscuous mode disabled"),
        Err(UlcpError::Status(status)) => warn(format!(
            "device refused to leave promiscuous mode ({status:?})"
        )),
        Err(error) => warn(format!("could not leave promiscuous mode: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> CaptureArgs {
        CaptureArgs {
            pcap: None,
            layers: CaptureLayers::Radio,
            pcap_raw: false,
            pcap_linktype: None,
            umsh_only: false,
            idle_probe_secs: 10,
            no_reconnect: false,
            reconnect_delay_secs: 2,
            freq_khz: None,
            bw_hz: None,
            sf: None,
            cr: None,
            sync_word: None,
            tx_power: None,
            quiet: false,
        }
    }

    #[test]
    fn a_bare_capture_is_valid_and_disturbs_nothing() {
        let args = args();
        args.validate().unwrap();
        assert!(!args.has_rf_overrides());
    }

    #[test]
    fn pcap_options_require_the_file_they_describe() {
        let mut args = args();
        args.layers = CaptureLayers::Both;
        assert!(args.validate().is_err());
        args.pcap = Some(PathBuf::from("out.pcap"));
        args.validate().unwrap();
    }

    #[test]
    fn raw_pcap_needs_a_path_a_linktype_and_the_radio_layer() {
        let mut args = args();
        args.pcap_raw = true;
        assert!(args.validate().is_err(), "no path");
        args.pcap = Some(PathBuf::from("out.pcap"));
        assert!(args.validate().is_err(), "no linktype");
        args.pcap_linktype = Some(147);
        args.validate().unwrap();
        assert!(matches!(
            args.encapsulation(),
            PcapEncapsulation::RawLoRa { linktype: 147 }
        ));
        args.layers = CaptureLayers::Both;
        assert!(args.validate().is_err(), "raw is radio-only");
    }

    #[test]
    fn a_linktype_without_raw_frames_means_nothing() {
        let mut args = args();
        args.pcap = Some(PathBuf::from("out.pcap"));
        args.pcap_linktype = Some(147);
        assert!(args.validate().is_err());
    }

    #[test]
    fn zero_intervals_are_rejected() {
        let mut idle = args();
        idle.idle_probe_secs = 0;
        assert!(idle.validate().is_err());

        let mut delay = args();
        delay.reconnect_delay_secs = 0;
        assert!(delay.validate().is_err());
    }

    #[test]
    fn any_rf_flag_makes_the_capture_configure_the_radio() {
        let mut args = args();
        args.sf = Some(9);
        assert!(args.has_rf_overrides());
    }
}
