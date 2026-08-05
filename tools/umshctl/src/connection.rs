//! Finding a device, opening a link to it, and holding the attached
//! session.
//!
//! Discovery is BLE-only on purpose. Identifying a ULCP device over
//! serial means opening the port and speaking to whatever is behind it,
//! and opening a port has side effects — DTR toggles reset some boards,
//! and a 1200-baud touch is this repository's own DFU trigger. A bench
//! is full of `usbmodem`/`usbserial` devices that are not ULCP radios,
//! so a serial port is used only when the user names one. BLE scanning
//! is passive and filtered to the ULCP GATT service, so it cannot land
//! on a foreign device.

use std::cell::RefCell;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};

use umsh::ulcp::{FrameLink, UlcpDevice, UlcpDeviceConfig, UlcpError};

use crate::command::capture::pcap::{PcapDirection, PcapWriter};
use crate::output;

/// How long general discovery listens before deciding what it found.
const DISCOVERY_WINDOW: Duration = Duration::from_secs(2);

/// How much longer discovery listens when the first window came up
/// empty (or missed the saved default). Power-conscious boards can
/// straddle a two-second advertising window.
const DISCOVERY_EXTENSION: Duration = Duration::from_secs(3);

/// The RF parameters here only size the driver's airtime-derived
/// timeouts; an administrative or tethered attach never writes PHY
/// configuration.
pub fn attach_config() -> UlcpDeviceConfig {
    UlcpDeviceConfig::new(910_525, 62_500, 7, 5)
}

/// A device this tool knows how to reach, in the form it would use to
/// reach it again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Serial {
        port: String,
        baud: u32,
    },
    /// `selector` is whatever identifies the radio to
    /// `BleFrameLink::connect`: a platform peripheral id when discovery
    /// chose it, or the user's own name fragment.
    Ble {
        selector: String,
        name: Option<String>,
    },
}

impl Target {
    /// Short transport tag for the prompt and for announcements.
    pub fn transport(&self) -> &'static str {
        match self {
            Self::Serial { .. } => "serial",
            Self::Ble { .. } => "ble",
        }
    }

    /// What to call this device before it has told us its own name.
    pub fn provisional_label(&self) -> String {
        match self {
            Self::Serial { port, .. } => {
                port.rsplit('/').next().unwrap_or(port.as_str()).to_string()
            }
            Self::Ble { selector, name } => name.clone().unwrap_or_else(|| selector.clone()),
        }
    }
}

// ---------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------

/// Every transport this tool can open, as one type, so a REPL can move
/// between them without the session being generic over the link.
pub enum AnyLink {
    #[cfg(feature = "serial-radio")]
    Serial(umsh::ulcp::SerialFrameLink<tokio_serial::SerialStream>),
    #[cfg(feature = "ble-radio")]
    Ble(umsh::ulcp::BleFrameLink),
    /// Keeps the type inhabited in a build with no transport feature.
    /// Never constructed.
    #[allow(dead_code)]
    Unavailable,
}

impl FrameLink for AnyLink {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), UlcpError> {
        match self {
            #[cfg(feature = "serial-radio")]
            Self::Serial(link) => link.send_frame(frame).await,
            #[cfg(feature = "ble-radio")]
            Self::Ble(link) => link.send_frame(frame).await,
            Self::Unavailable => Err(UlcpError::Disconnected),
        }
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, UlcpError>> {
        match self {
            #[cfg(feature = "serial-radio")]
            Self::Serial(link) => link.poll_recv_frame(cx),
            #[cfg(feature = "ble-radio")]
            Self::Ble(link) => link.poll_recv_frame(cx),
            Self::Unavailable => core::task::Poll::Ready(Err(UlcpError::Disconnected)),
        }
    }
}

/// The pcap sink shared by the link wrapper (ULCP frames) and the
/// capture loop (radio frames).
///
/// It is installed and removed at runtime rather than fixed at attach,
/// so a `capture --pcap` inside the REPL can record the session's own
/// control traffic without the session having been opened for capture.
pub type FrameTap = Rc<RefCell<Option<PcapWriter>>>;

pub fn new_tap() -> FrameTap {
    Rc::new(RefCell::new(None))
}

/// A link that copies every ULCP frame into the tap, when one is
/// installed.
pub struct SessionLink {
    inner: AnyLink,
    tap: FrameTap,
}

impl SessionLink {
    pub fn new(inner: AnyLink, tap: FrameTap) -> Self {
        Self { inner, tap }
    }

    fn record(&self, direction: PcapDirection, frame: &[u8]) -> std::io::Result<()> {
        if let Some(writer) = self.tap.borrow_mut().as_mut() {
            writer.write_ulcp(direction, frame)?;
        }
        Ok(())
    }
}

impl FrameLink for SessionLink {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), UlcpError> {
        self.record(PcapDirection::HostToDevice, frame)?;
        self.inner.send_frame(frame).await
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, UlcpError>> {
        match self.inner.poll_recv_frame(cx) {
            core::task::Poll::Ready(Ok(frame)) => {
                match self.record(PcapDirection::DeviceToHost, &frame) {
                    Ok(()) => core::task::Poll::Ready(Ok(frame)),
                    Err(error) => core::task::Poll::Ready(Err(error.into())),
                }
            }
            other => other,
        }
    }
}

// ---------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------

/// An attached device plus everything needed to describe it, tap it, and
/// re-attach it in the other mode.
pub struct Session {
    pub device: UlcpDevice<SessionLink>,
    pub target: Target,
    pub label: String,
    pub tap: FrameTap,
}

impl Session {
    /// True while this handle refuses host-domain writes.
    pub fn is_administrative(&self) -> bool {
        matches!(
            self.device.attach_mode(),
            umsh::ulcp::AttachMode::Administrative
        )
    }

    /// Re-attach the open link in the other mode.
    ///
    /// The device sees no detach — this replaces the host's own
    /// bookkeeping — so session-scoped state survives and the cost is
    /// four property reads rather than a reconnect.
    pub async fn reattach(self, tethered: bool, trace: bool) -> Result<Self> {
        let Self {
            device,
            target,
            label,
            tap,
        } = self;
        // The link keeps its tap: the wrapper is recovered whole, so a
        // capture in progress keeps recording.
        let link = device.into_link();
        let mut device = reattach_link(link, tethered).await?;
        if trace {
            install_trace(&mut device);
        }
        Ok(Self {
            device,
            target,
            label,
            tap,
        })
    }

    /// Open a fresh link to the same radio.
    ///
    /// Unlike [`Self::reattach`] this really does drop the connection —
    /// it exists for recovering a capture whose BLE link failed. The
    /// capture tap comes along so a recovered capture stays one file.
    pub async fn reconnect(self, trace: bool) -> Result<Self> {
        let Self {
            device,
            target,
            label,
            tap,
        } = self;
        drop(device);
        let link = open(&target).await?;
        let mut device = attach_tapped(link, tap.clone(), false).await?;
        if trace {
            install_trace(&mut device);
        }
        Ok(Self {
            device,
            target,
            label,
            tap,
        })
    }
}

/// Wire the frame-trace hook to stderr.
pub fn install_trace(device: &mut UlcpDevice<SessionLink>) {
    device.set_frame_trace(Some(Box::new(|direction, line| {
        eprintln!("trace {direction} {line}");
    })));
}

/// Open the transport named by `target`.
pub async fn open(target: &Target) -> Result<AnyLink> {
    match target {
        Target::Serial { port, baud } => open_serial(port, *baud).await,
        Target::Ble { selector, .. } => open_ble(selector).await,
    }
}

// Each transport comes in a working form and an explanatory one, chosen
// by feature. Two whole functions beat a `cfg` block inside one: the
// bodies stay ordinary code, and the build without the feature still
// produces a tool that says what it is missing.

#[cfg(feature = "serial-radio")]
async fn open_serial(port: &str, baud: u32) -> Result<AnyLink> {
    use tokio_serial::SerialPortBuilderExt as _;
    let stream = tokio_serial::new(port, baud)
        .open_native_async()
        .with_context(|| format!("opening {port}"))?;
    Ok(AnyLink::Serial(umsh::ulcp::SerialFrameLink::new(stream)))
}

#[cfg(not(feature = "serial-radio"))]
async fn open_serial(_port: &str, _baud: u32) -> Result<AnyLink> {
    bail!("this build has no serial support (build with the serial-radio feature)")
}

#[cfg(feature = "ble-radio")]
async fn open_ble(selector: &str) -> Result<AnyLink> {
    use umsh::ulcp::{BleFrameLink, BleFrameLinkConfig};
    let link = BleFrameLink::connect(Some(selector), BleFrameLinkConfig::default())
        .await
        .with_context(|| format!("connecting to BLE radio {selector:?}"))?;
    Ok(AnyLink::Ble(link))
}

#[cfg(not(feature = "ble-radio"))]
async fn open_ble(_selector: &str) -> Result<AnyLink> {
    bail!("this build has no BLE support (build with the ble-radio feature)")
}

async fn attach_tapped(
    link: AnyLink,
    tap: FrameTap,
    tethered: bool,
) -> Result<UlcpDevice<SessionLink>> {
    reattach_link(SessionLink::new(link, tap), tethered).await
}

/// Attach to an already-wrapped link.
///
/// Administrative is the default relationship: this tool administers
/// devices rather than tethering to them, so the handle refuses
/// host-domain writes. Only `provision` — which exists to establish a
/// host domain — asks for a tethered handle.
async fn reattach_link(link: SessionLink, tethered: bool) -> Result<UlcpDevice<SessionLink>> {
    let device = if tethered {
        UlcpDevice::attach_existing(link, attach_config()).await
    } else {
        UlcpDevice::attach_administrative(link, attach_config()).await
    }?;
    Ok(device)
}

/// Open, attach, and name a device in one step.
pub async fn connect(target: Target, tethered: bool, trace: bool) -> Result<Session> {
    let tap = new_tap();
    let link = open(&target).await?;
    let mut device = attach_tapped(link, tap.clone(), tethered).await?;
    if trace {
        install_trace(&mut device);
    }
    // A device without CAP_DEV_NAME still needs something to answer to.
    let label = match device.device_name().await {
        Ok(name) if !name.is_empty() => name,
        _ => target.provisional_label(),
    };
    Ok(Session {
        device,
        target,
        label,
        tap,
    })
}

// ---------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------

/// One radio seen during a scan, in the form the chooser and the saved
/// default both work with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub id: String,
    pub name: Option<String>,
    pub rssi: Option<i16>,
}

/// Scan for ULCP radios advertising the GATT service.
#[cfg(feature = "ble-radio")]
pub async fn scan(timeout: Duration) -> Result<Vec<Found>> {
    let results = umsh::ulcp::BleFrameLink::scan(timeout)
        .await
        .context("scanning for BLE radios")?;
    let mut found: Vec<Found> = results
        .into_iter()
        .map(|result| Found {
            id: result.id,
            name: result.name,
            rssi: result.rssi,
        })
        .collect();
    sort_found(&mut found);
    Ok(found)
}

/// Scan for ULCP radios advertising the GATT service.
#[cfg(not(feature = "ble-radio"))]
pub async fn scan(_timeout: Duration) -> Result<Vec<Found>> {
    bail!("this build has no BLE support (build with the ble-radio feature)")
}

/// Stable ordering: by name, then by id.
///
/// Deliberately **not** by signal strength. RSSI jitters between scans
/// and would reorder the list under the user's fingers between one
/// listing and the next.
pub fn sort_found(found: &mut [Found]) {
    found.sort_by(|left, right| {
        let key = |entry: &Found| {
            (
                entry.name.is_none(),
                entry.name.clone().unwrap_or_default(),
                entry.id.clone(),
            )
        };
        key(left).cmp(&key(right))
    });
}

/// Fold a later scan's results into an earlier one, keeping order stable
/// and preferring the fresher name and RSSI.
pub fn merge_found(into: &mut Vec<Found>, more: Vec<Found>) {
    for entry in more {
        match into.iter_mut().find(|existing| existing.id == entry.id) {
            Some(existing) => {
                existing.name = entry.name.or_else(|| existing.name.take());
                existing.rssi = entry.rssi.or(existing.rssi);
            }
            None => into.push(entry),
        }
    }
    sort_found(into);
}

/// Print a numbered listing of scan results.
pub fn render_found(found: &[Found]) {
    if found.is_empty() {
        println!("no ULCP radios found");
        return;
    }
    let width = found.len().to_string().len();
    for (index, entry) in found.iter().enumerate() {
        let name = entry.name.as_deref().unwrap_or("(no name)");
        match entry.rssi {
            Some(rssi) => println!(
                "{:>width$}) {name}  {}  rssi {rssi} dBm",
                index + 1,
                entry.id
            ),
            None => println!("{:>width$}) {name}  {}", index + 1, entry.id),
        }
    }
}

impl From<&Found> for Target {
    fn from(found: &Found) -> Self {
        Target::Ble {
            selector: found.id.clone(),
            name: found.name.clone(),
        }
    }
}

/// How a scan result set is resolved into one radio.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Discovery {
    /// Take the saved default when it answers, and ask only when the
    /// answer is genuinely ambiguous.
    #[default]
    Auto,
    /// Always show the listing and ask. The saved default is not
    /// consulted at all — the point of asking is to reach the radio the
    /// preference does not name.
    Ask,
}

/// Find the device to talk to when the command line named none.
///
/// Returns `None` when nothing was found, which the caller turns into an
/// unattached REPL or a one-shot error.
pub async fn discover(prefs: &Prefs, interactive: bool, how: Discovery) -> Result<Option<Target>> {
    let mut seen = scan(DISCOVERY_WINDOW).await?;
    let mut extended = false;

    if let (Discovery::Auto, Some(saved)) = (how, &prefs.default_device) {
        if let Some(found) = saved.find_in(&seen) {
            return Ok(Some(Target::from(found)));
        }
        merge_found(&mut seen, scan(DISCOVERY_EXTENSION).await?);
        extended = true;
        if let Some(found) = saved.find_in(&seen) {
            return Ok(Some(Target::from(found)));
        }
        // A stale preference costs one line of output, not a dead tool.
        output::warn(format!(
            "default radio {} not found; discovering instead",
            saved.display()
        ));
    }

    if seen.is_empty() && !extended {
        merge_found(&mut seen, scan(DISCOVERY_EXTENSION).await?);
    }

    choose(seen, interactive, how)
}

/// Turn a scan result set into a single target, asking the user when the
/// answer is ambiguous — or, under [`Discovery::Ask`], whenever there is
/// anything to ask about.
pub fn choose(found: Vec<Found>, interactive: bool, how: Discovery) -> Result<Option<Target>> {
    match found.len() {
        0 => Ok(None),
        // One radio is only an answer when nobody asked to be shown the
        // question.
        1 if how == Discovery::Auto => Ok(Some(Target::from(&found[0]))),
        _ => {
            render_found(&found);
            if !interactive {
                match how {
                    Discovery::Ask => bail!(
                        "choosing a radio needs a terminal; name one with --ble=SELECTOR instead"
                    ),
                    Discovery::Auto => bail!(
                        "{} ULCP radios are in range; name one with --ble=SELECTOR (or set a \
                         default with `default set`)",
                        found.len()
                    ),
                }
            }
            let index = prompt_index(found.len())?;
            Ok(index.map(|index| Target::from(&found[index])))
        }
    }
}

/// Read a 1-based choice from the terminal. `None` means the user
/// declined (empty line or EOF).
fn prompt_index(count: usize) -> Result<Option<usize>> {
    loop {
        print!("select radio [1-{count}, or blank to cancel]: ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            println!();
            return Ok(None);
        }
        let line = line.trim();
        if line.is_empty() {
            return Ok(None);
        }
        match line.parse::<usize>() {
            Ok(choice) if (1..=count).contains(&choice) => return Ok(Some(choice - 1)),
            _ => eprintln!("expected a number from 1 to {count}"),
        }
    }
}

/// Ask a yes/no question, defaulting to no.
pub fn confirm(question: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    print!("{question} [y/N]: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line)? == 0 {
        println!();
        return Ok(false);
    }
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

// ---------------------------------------------------------------------
// Preferences
// ---------------------------------------------------------------------

/// The device to reach for when the command line names none.
///
/// Both fields are kept: the platform id is the primary key, and the
/// name is a fallback for the day a Bluetooth cache reset churns the
/// ids — as well as what the user recognizes in a message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DefaultDevice {
    pub selector: String,
    pub name: Option<String>,
}

impl DefaultDevice {
    pub fn display(&self) -> String {
        match &self.name {
            Some(name) => format!("{name:?} ({})", self.selector),
            None => self.selector.clone(),
        }
    }

    fn find_in<'a>(&self, found: &'a [Found]) -> Option<&'a Found> {
        found
            .iter()
            .find(|entry| entry.id == self.selector)
            .or_else(|| {
                found.iter().find(|entry| {
                    entry
                        .name
                        .as_deref()
                        .is_some_and(|name| Some(name) == self.name.as_deref())
                })
            })
            .or_else(|| {
                found.iter().find(|entry| {
                    entry
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains(&self.selector))
                })
            })
    }
}

/// Persisted tool preferences. Deliberately tiny: `setting = value`
/// lines with `#` comments, the same vocabulary the provisioning file
/// uses, and no dependency to read it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prefs {
    pub default_device: Option<DefaultDevice>,
}

impl Prefs {
    pub fn parse(text: &str) -> Self {
        let mut prefs = Self::default();
        let mut selector = None;
        let mut name = None;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            let Some((setting, value)) = line.split_once('=') else {
                continue;
            };
            match setting.trim() {
                "default-selector" => selector = Some(value.trim().to_string()),
                "default-name" => name = Some(value.trim().to_string()),
                // Unknown settings are ignored rather than fatal: a
                // preferences file is not a command line.
                _ => {}
            }
        }
        if let Some(selector) = selector {
            prefs.default_device = Some(DefaultDevice { selector, name });
        }
        prefs
    }

    pub fn render(&self) -> String {
        let mut text = String::from("# umshctl preferences\n");
        if let Some(device) = &self.default_device {
            text.push_str(&format!("default-selector = {}\n", device.selector));
            if let Some(name) = &device.name {
                text.push_str(&format!("default-name = {name}\n"));
            }
        }
        text
    }

    pub fn load() -> Self {
        config_path()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .map(|text| Self::parse(&text))
            .unwrap_or_default()
    }

    pub fn store(&self) -> Result<PathBuf> {
        let path =
            config_path().ok_or_else(|| anyhow!("no HOME directory to store settings in"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&path, self.render())
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }
}

/// Where the preferences file and the REPL history live. One directory,
/// following `XDG_STATE_HOME` when it is set.
fn state_dir() -> Option<PathBuf> {
    if let Some(state) = std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(state).join("umsh"));
    }
    let home = std::env::var_os("HOME").filter(|value| !value.is_empty())?;
    Some(PathBuf::from(home).join(".local/state/umsh"))
}

pub fn config_path() -> Option<PathBuf> {
    state_dir().map(|dir| dir.join("umshctl.conf"))
}

pub fn history_path() -> Option<PathBuf> {
    state_dir().map(|dir| dir.join("umshctl-history"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(id: &str, name: Option<&str>, rssi: Option<i16>) -> Found {
        Found {
            id: id.to_string(),
            name: name.map(str::to_string),
            rssi,
        }
    }

    #[test]
    fn scan_results_sort_by_name_never_by_signal() {
        let mut list = vec![
            found("id-c", Some("T-Echo"), Some(-30)),
            found("id-a", Some("Solar"), Some(-90)),
            found("id-b", None, Some(-40)),
        ];
        sort_found(&mut list);
        assert_eq!(
            list.iter()
                .map(|entry| entry.id.as_str())
                .collect::<Vec<_>>(),
            ["id-a", "id-c", "id-b"],
        );

        // The strongest signal changing does not move anything.
        list[0].rssi = Some(-10);
        let before = list.clone();
        sort_found(&mut list);
        assert_eq!(list, before);
    }

    #[test]
    fn merging_a_second_scan_keeps_one_entry_per_radio() {
        let mut list = vec![found("id-a", None, None)];
        merge_found(&mut list, vec![found("id-a", Some("T-Echo"), Some(-55))]);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name.as_deref(), Some("T-Echo"));
        assert_eq!(list[0].rssi, Some(-55));
    }

    #[test]
    fn a_single_radio_needs_no_chooser() {
        let target = choose(
            vec![found("id-a", Some("T-Echo"), None)],
            false,
            Discovery::Auto,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            target,
            Target::Ble {
                selector: "id-a".into(),
                name: Some("T-Echo".into())
            }
        );
    }

    #[test]
    fn asking_explicitly_asks_even_about_a_single_radio() {
        // Without a terminal there is nobody to answer, which is the
        // observable half of "it asked" in a test.
        let error = choose(
            vec![found("id-a", Some("T-Echo"), None)],
            false,
            Discovery::Ask,
        )
        .unwrap_err();
        assert!(error.to_string().contains("terminal"), "{error}");
    }

    #[test]
    fn several_radios_fail_loudly_without_a_terminal() {
        let error = choose(
            vec![
                found("id-a", Some("T-Echo"), None),
                found("id-b", Some("Solar"), None),
            ],
            false,
            Discovery::Auto,
        )
        .unwrap_err();
        assert!(error.to_string().contains("--ble"), "{error}");
    }

    #[test]
    fn no_radios_is_not_an_error_here() {
        assert_eq!(choose(Vec::new(), false, Discovery::Auto).unwrap(), None);
        assert_eq!(choose(Vec::new(), false, Discovery::Ask).unwrap(), None);
    }

    #[test]
    fn preferences_round_trip() {
        let prefs = Prefs {
            default_device: Some(DefaultDevice {
                selector: "1234-ABCD".into(),
                name: Some("UMSH T-Echo".into()),
            }),
        };
        assert_eq!(Prefs::parse(&prefs.render()), prefs);
    }

    #[test]
    fn preferences_ignore_comments_and_unknown_settings() {
        let prefs = Prefs::parse(
            "# comment\n\
             default-selector = id-a  # trailing\n\
             mystery = 7\n",
        );
        assert_eq!(
            prefs.default_device,
            Some(DefaultDevice {
                selector: "id-a".into(),
                name: None
            })
        );
    }

    #[test]
    fn the_saved_default_matches_by_id_then_by_name() {
        let saved = DefaultDevice {
            selector: "id-a".into(),
            name: Some("UMSH T-Echo".into()),
        };
        let list = vec![
            found("id-z", Some("UMSH T-Echo"), None),
            found("id-a", Some("renamed"), None),
        ];
        // The id wins even when the name matches another radio.
        assert_eq!(saved.find_in(&list).unwrap().id, "id-a");

        // With the id gone, the name still finds it.
        assert_eq!(saved.find_in(&list[..1]).unwrap().id, "id-z");
        assert_eq!(saved.find_in(&[]), None);
    }
}
