//! Wireshark extcap interface.
//!
//! Wireshark discovers capture interfaces by running every executable in
//! its `extcap` directory and asking each one what it offers. That makes
//! `umshctl` appear in Wireshark's interface list, so a live capture is a
//! double-click rather than a file written in one window and opened in
//! another.
//!
//! Wireshark identifies itself by its arguments, not by the name it
//! invokes us under, so nothing here depends on how the executable was
//! installed. The vocabulary is kept out of the tool's own argument
//! parser: these flags belong to Wireshark, and the two would otherwise
//! have to agree forever.

pub mod protocol;

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::Parser;

use crate::command::capture::CaptureArgs;
use crate::command::capture::pcap::{CaptureLayers, PcapEncapsulation, PcapWriter};
use crate::connection::{self, Prefs, Target};
use crate::{App, output};

/// How long a Reload in the configuration dialog spends scanning.
///
/// Longer than a plain `discover`, because the user pressed a button and
/// is watching a dropdown rather than waiting on a capture.
const RELOAD_SCAN: Duration = Duration::from_secs(3);

/// Whether Wireshark, rather than a person, is running this process.
///
/// Every phase carries at least one `--extcap-` flag — `--capture` always
/// arrives with `--extcap-interface` — so the arguments alone settle it.
/// Deliberately not a check on argv[0]: a copy and a symlink of the same
/// binary must behave identically.
pub fn is_extcap_invocation() -> bool {
    std::env::args_os()
        .skip(1)
        .any(|arg| arg.as_encoded_bytes().starts_with(b"--extcap-"))
}

/// The arguments Wireshark passes.
///
/// Unknown-but-harmless flags are accepted and ignored rather than
/// rejected: Wireshark passes `--extcap-version` and the logging flags
/// unconditionally, and a hard error on any one of them would make the
/// interface vanish from the list entirely.
#[derive(Debug, Parser)]
#[command(
    name = "umshctl",
    about = "Wireshark extcap interface",
    disable_help_flag = true
)]
pub struct ExtcapArgs {
    #[arg(long)]
    extcap_interfaces: bool,
    #[arg(long)]
    extcap_dlts: bool,
    #[arg(long)]
    extcap_config: bool,
    #[arg(long, value_name = "NAME")]
    extcap_interface: Option<String>,
    #[arg(long, value_name = "CALL")]
    extcap_reload_option: Option<String>,
    #[arg(long)]
    capture: bool,
    #[arg(long, value_name = "PATH")]
    fifo: Option<PathBuf>,

    // Accepted so Wireshark's unconditional flags cannot break a phase.
    #[arg(long, value_name = "VERSION")]
    extcap_version: Option<String>,
    #[arg(long, value_name = "FILTER")]
    extcap_capture_filter: Option<String>,
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,
    #[arg(long, value_name = "PATH")]
    log_file: Option<PathBuf>,

    // The capture options, mirroring `protocol::config`.
    #[arg(long, value_name = "ID")]
    radio: Option<String>,
    #[arg(long, value_name = "PORT")]
    serial_port: Option<String>,
    #[arg(long, default_value_t = 115_200, value_name = "N")]
    baud: u32,
    #[arg(long)]
    umsh_only: bool,
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    idle_probe_secs: u64,
    #[arg(long)]
    no_reconnect: bool,
    #[arg(long, value_name = "KHZ")]
    freq_khz: Option<String>,
    #[arg(long, value_name = "HZ")]
    bw_hz: Option<String>,
    #[arg(long, value_name = "N")]
    sf: Option<String>,
    #[arg(long, value_name = "N")]
    cr: Option<String>,
    #[arg(long, value_name = "N")]
    sync_word: Option<String>,
}

/// Parse an RF override that the dialog leaves empty when unset.
///
/// Wireshark sends the flag with an empty value for a string argument
/// the user did not fill in, which has to mean "leave the radio alone"
/// rather than "set it to zero".
fn rf_override<T>(
    value: Option<&String>,
    what: &str,
    range: std::ops::RangeInclusive<u64>,
) -> Result<Option<T>>
where
    T: TryFrom<u64>,
{
    let Some(text) = value
        .map(|text| text.trim())
        .filter(|text| !text.is_empty())
    else {
        return Ok(None);
    };
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse::<u64>(),
    }
    .with_context(|| format!("{what}: {text:?} is not a number"))?;
    if !range.contains(&parsed) {
        bail!(
            "{what}: {parsed} is outside {}..={}",
            range.start(),
            range.end(),
        );
    }
    T::try_from(parsed)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("{what}: {parsed} does not fit"))
}

pub async fn run() -> Result<()> {
    let args = ExtcapArgs::parse();

    // Order matters: a reload is a narrower case of `--extcap-config`.
    if args.extcap_reload_option.is_some() {
        return reload(&args).await;
    }
    if args.extcap_config {
        expect_interface(&args)?;
        print!("{}", protocol::config());
        return Ok(());
    }
    if args.extcap_dlts {
        expect_interface(&args)?;
        print!("{}", protocol::dlts());
        return Ok(());
    }
    if args.extcap_interfaces {
        print!(
            "{}",
            protocol::interfaces(Prefs::load().default_device.as_ref())
        );
        return Ok(());
    }
    if args.capture {
        return capture(args).await;
    }
    bail!("no extcap phase requested")
}

/// Reject an interface we did not advertise.
fn expect_interface(args: &ExtcapArgs) -> Result<()> {
    match args.extcap_interface.as_deref() {
        Some(protocol::INTERFACE) => Ok(()),
        Some(other) => bail!("unknown interface {other:?}"),
        None => bail!("--extcap-interface is required"),
    }
}

/// Re-populate the radio dropdown from a fresh scan.
async fn reload(args: &ExtcapArgs) -> Result<()> {
    expect_interface(args)?;
    if args.extcap_reload_option.as_deref() != Some(protocol::CALL_RADIO) {
        // Wireshark only reloads options we marked reloadable, but an
        // empty list is a better answer than a failed dialog.
        return Ok(());
    }
    // A build without BLE, or a machine without an adapter, still has to
    // render a usable dialog.
    let found = connection::scan(RELOAD_SCAN).await.unwrap_or_default();
    print!("{}", protocol::radio_values(&found));
    Ok(())
}

/// Stream a live capture into the FIFO Wireshark is reading.
async fn capture(args: ExtcapArgs) -> Result<()> {
    expect_interface(&args)?;
    let fifo = args
        .fifo
        .as_deref()
        .context("--capture requires --fifo=PATH")?;

    // Everything downstream narrates the capture on stdout, which here is
    // a pipe Wireshark does not promise to drain — a full pipe would park
    // the capture forever. Stderr is no place for it either: Wireshark
    // reads this process's stderr as a fault report and raises whatever
    // accumulated there when the capture ends, so a progress line becomes
    // an error dialog. Silence both.
    //
    // Declared before the radio so it is dropped after it: attaching,
    // recovering, and detaching all narrate too.
    let _silence = Silenced::install()?;
    output::set_color(false);

    // Before the radio: opening the FIFO and declaring the link type is
    // what lets Wireshark settle into a live capture, and BLE discovery
    // and attach can take seconds.
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open(fifo)
        .with_context(|| format!("opening capture FIFO {}", fifo.display()))?;
    let writer = PcapWriter::to_writer(
        Box::new(sink),
        CaptureLayers::Radio,
        PcapEncapsulation::LoRaTap,
    )?;

    let capture_args = capture_args(&args)?;
    capture_args.validate()?;

    let prefs = Prefs::load();
    let target = resolve_target(&args, &prefs).await?;
    let session = connection::connect(target, false).await?;
    let mut app = App::for_extcap(session, prefs, args.baud);

    // Wireshark stops a capture by closing the FIFO and signalling. The
    // signal is the one that also arrives when the air is quiet, where
    // there is no write to discover the closed FIFO through.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        tokio::select! {
            result = crate::command::capture::run_with_writer(&mut app, &capture_args, Some(writer)) => result,
            _ = terminate.recv() => Ok(()),
            _ = interrupt.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        crate::command::capture::run_with_writer(&mut app, &capture_args, Some(writer)).await
    }
}

/// Translate the dialog's answers into the capture command's own
/// arguments, so both entry points run exactly the same capture.
fn capture_args(args: &ExtcapArgs) -> Result<CaptureArgs> {
    Ok(CaptureArgs {
        pcap: None,
        layers: CaptureLayers::Radio,
        pcap_raw: false,
        pcap_linktype: None,
        umsh_only: args.umsh_only,
        quiet: true,
        idle_probe_secs: args.idle_probe_secs.max(1),
        no_reconnect: args.no_reconnect,
        reconnect_delay_secs: 2,
        freq_khz: rf_override(
            args.freq_khz.as_ref(),
            "--freq-khz",
            1..=u64::from(u32::MAX),
        )?,
        bw_hz: rf_override(args.bw_hz.as_ref(), "--bw-hz", 1..=u64::from(u32::MAX))?,
        sf: rf_override(args.sf.as_ref(), "--sf", 5..=12)?,
        cr: rf_override(args.cr.as_ref(), "--cr", 5..=8)?,
        sync_word: rf_override::<u16>(args.sync_word.as_ref(), "--sync-word", 0..=0xffff)?
            .map(crate::command::values::HexU16Arg),
        tx_power: None,
    })
}

/// Pick the radio to capture from.
///
/// A serial port is only ever used when named, the same rule the rest of
/// the tool follows: identifying one means opening it, and opening a port
/// can reset hardware that is not a radio at all.
async fn resolve_target(args: &ExtcapArgs, prefs: &Prefs) -> Result<Target> {
    if let Some(port) = &args.serial_port {
        return Ok(Target::Serial {
            port: port.clone(),
            baud: args.baud,
        });
    }
    if let Some(selector) = args
        .radio
        .as_deref()
        .map(str::trim)
        .filter(|selector| !selector.is_empty())
    {
        return Ok(Target::Ble {
            selector: selector.to_string(),
            name: None,
        });
    }
    // No person is watching, so an ambiguous scan has to fail rather
    // than ask which radio was meant. Naming the dialog is the actionable
    // part: that is where the choice can be made once and remembered.
    connection::discover(prefs, false, connection::Discovery::Auto)
        .await?
        .context(
            "no radio selected: pick one in the interface's capture options, or name a serial port",
        )
}

/// Both standard streams pointed at `/dev/null`, with the originals
/// restored when the value is dropped.
///
/// A blunt instrument on purpose: it catches every print in the capture
/// path, including ones added later, which auditing call sites would not.
/// Restoring on the way out is what keeps the one message Wireshark's
/// error dialog is good for — the fatal error `main` reports — from being
/// silenced along with the narration.
#[cfg(unix)]
struct Silenced {
    stdout: std::os::fd::OwnedFd,
    stderr: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl Silenced {
    fn install() -> Result<Self> {
        use std::os::fd::AsRawFd as _;

        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .context("opening /dev/null")?;
        let stdout = duplicate(libc::STDOUT_FILENO)?;
        let stderr = duplicate(libc::STDERR_FILENO)?;

        std::io::stdout().flush().ok();
        point_at(null.as_raw_fd(), libc::STDOUT_FILENO).context("silencing stdout")?;
        point_at(null.as_raw_fd(), libc::STDERR_FILENO).context("silencing stderr")?;
        Ok(Self { stdout, stderr })
    }
}

#[cfg(unix)]
impl Drop for Silenced {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;

        // Anything still buffered was written while silenced and belongs
        // to /dev/null, not to the stream being restored.
        std::io::stdout().flush().ok();
        let _ = point_at(self.stdout.as_raw_fd(), libc::STDOUT_FILENO);
        let _ = point_at(self.stderr.as_raw_fd(), libc::STDERR_FILENO);
    }
}

/// `dup`, as a descriptor that closes itself.
#[cfg(unix)]
fn duplicate(fd: std::os::fd::RawFd) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd as _;

    // SAFETY: `fd` is a standard stream, open for the life of the process.
    let copy = unsafe { libc::dup(fd) };
    if copy < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("duplicating descriptor {fd}"));
    }
    // SAFETY: dup returned a fresh descriptor that nothing else owns.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(copy) })
}

/// Make `target` refer to whatever `source` refers to.
#[cfg(unix)]
fn point_at(source: std::os::fd::RawFd, target: std::os::fd::RawFd) -> std::io::Result<()> {
    // SAFETY: both descriptors are valid, and dup2 is defined for any two
    // valid descriptors.
    if unsafe { libc::dup2(source, target) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
struct Silenced;

#[cfg(not(unix))]
impl Silenced {
    fn install() -> Result<Self> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> ExtcapArgs {
        let mut argv = vec!["umshctl"];
        argv.extend_from_slice(args);
        ExtcapArgs::try_parse_from(argv).expect("should parse")
    }

    /// Wireshark passes these unconditionally; rejecting one would make
    /// the interface disappear from the list.
    #[test]
    fn wiresharks_ambient_flags_are_tolerated() {
        let args = parse(&[
            "--extcap-interfaces",
            "--extcap-version=4.6",
            "--log-level=debug",
        ]);
        assert!(args.extcap_interfaces);
    }

    #[test]
    fn every_phase_parses() {
        assert!(parse(&["--extcap-interfaces"]).extcap_interfaces);
        assert!(parse(&["--extcap-dlts", "--extcap-interface=umsh"]).extcap_dlts);
        assert!(parse(&["--extcap-config", "--extcap-interface=umsh"]).extcap_config);
        let reload = parse(&[
            "--extcap-config",
            "--extcap-interface=umsh",
            "--extcap-reload-option=--radio",
        ]);
        assert_eq!(reload.extcap_reload_option.as_deref(), Some("--radio"));
        let capture = parse(&[
            "--capture",
            "--extcap-interface=umsh",
            "--fifo=/tmp/x",
            "--serial-port=/dev/null",
        ]);
        assert!(capture.capture);
        assert_eq!(
            capture.fifo.as_deref(),
            Some(std::path::Path::new("/tmp/x"))
        );
    }

    /// `--extcap-interface` and `--extcap-interfaces` differ by one
    /// character; clap must not infer one from the other.
    #[test]
    fn the_singular_and_plural_flags_stay_distinct() {
        let args = parse(&["--extcap-interface=umsh", "--extcap-dlts"]);
        assert!(!args.extcap_interfaces);
        assert_eq!(args.extcap_interface.as_deref(), Some("umsh"));
    }

    #[test]
    fn an_empty_rf_override_leaves_the_radio_alone() {
        let empty = String::new();
        assert_eq!(
            rf_override::<u8>(Some(&empty), "--sf", 5..=12).unwrap(),
            None
        );
        assert_eq!(rf_override::<u8>(None, "--sf", 5..=12).unwrap(), None);
        assert_eq!(
            rf_override::<u8>(Some(&"7".to_string()), "--sf", 5..=12).unwrap(),
            Some(7),
        );
    }

    #[test]
    fn an_out_of_range_rf_override_is_rejected() {
        assert!(rf_override::<u8>(Some(&"13".to_string()), "--sf", 5..=12).is_err());
        assert!(rf_override::<u8>(Some(&"nope".to_string()), "--sf", 5..=12).is_err());
    }

    #[test]
    fn a_hex_sync_word_is_accepted() {
        assert_eq!(
            rf_override::<u16>(Some(&"0x2b".to_string()), "--sync-word", 0..=0xffff).unwrap(),
            Some(0x2b),
        );
    }

    /// The capture command validates its own arguments, and extcap
    /// deliberately builds them with no `--pcap` path.
    #[test]
    fn the_translated_capture_arguments_are_valid() {
        let args = parse(&["--capture", "--extcap-interface=umsh", "--fifo=/tmp/x"]);
        capture_args(&args).unwrap().validate().unwrap();

        let filtered = parse(&[
            "--capture",
            "--extcap-interface=umsh",
            "--fifo=/tmp/x",
            "--umsh-only",
            "--sf=9",
        ]);
        let translated = capture_args(&filtered).unwrap();
        translated.validate().unwrap();
        assert!(translated.umsh_only);
        assert_eq!(translated.sf, Some(9));
    }
}
