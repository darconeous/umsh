//! Live inspection and pcap capture from a ULCP radio device.
//!
//! The default RF profile matches the T-Echo bringup profile:
//! 910.525 MHz, LoRa SF7 / BW62.5 kHz / CR4-5, sync word 0x1424.

#![cfg_attr(
    not(any(feature = "serial-radio", feature = "ble-radio")),
    allow(unused_variables, dead_code)
)]

use std::cell::RefCell;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufWriter, IsTerminal, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hamaddr::HamAddr;
use umsh::ulcp::{UlcpDevice, UlcpDeviceConfig, FrameLink};
use umsh::core::options::OptionDecoder;
use umsh::core::{
    OptionNumber, PacketHeader, PacketType, PayloadType, PublicKey, RegionCode, RouterHint,
    SourceAddrRef,
};
use umsh::hal::Radio;

const USAGE: &str = "\
usage: umsh-capture <serial-port> [options]\n\
       umsh-capture --ble [selector] [options]\n\
       umsh-capture --scan-ble\n\n\
--scan-ble lists nearby companion radios (id, name, RSSI) without\n\
connecting; the id works as a --ble selector.\n\n\
Options (RF defaults shown):\n\
  --freq-khz=910525\n\
  --bw-hz=62500\n\
  --sf=7\n\
  --cr=5                 coding-rate denominator (4/5)\n\
  --sync-word=0x1424\n\
  --tx-power=14\n\
  --idle-probe-secs=10    verify BLE/ULCP/radio health while RF is quiet\n\
  --umsh-only             suppress raw/decoded output for non-UMSH frames\n\
  --color=auto            colorize decoded fields: auto, always, or never\n\
  --pcap=PATH             write a Wireshark-compatible capture\n\
  --capture=radio         pcap layer: radio, ulcp, or both\n\
  --pcap-raw              store exact raw LoRa frames (radio layer only)\n\
  --pcap-linktype=N       pcap LINKTYPE value required by --pcap-raw\n\
  --reconnect-delay-secs=2\n\
  --no-reconnect          exit instead of recovering a failed BLE session\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureLayers {
    Radio,
    Ulcp,
    Both,
}

impl CaptureLayers {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "radio" => Ok(Self::Radio),
            "ulcp" | "companion" => Ok(Self::Ulcp),
            "both" => Ok(Self::Both),
            _ => Err(format!(
                "invalid capture layer {value:?}; expected radio, ulcp, or both"
            )),
        }
    }

    fn radio(self) -> bool {
        matches!(self, Self::Radio | Self::Both)
    }

    fn ulcp(self) -> bool {
        matches!(self, Self::Ulcp | Self::Both)
    }
}

/// When decoded output carries ANSI color.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl ColorChoice {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "always" | "yes" => Ok(Self::Always),
            "never" | "no" => Ok(Self::Never),
            _ => Err(format!(
                "invalid color choice {value:?}; expected auto, always, or never"
            )),
        }
    }

    /// Resolve to a concrete answer for this run. `auto` honours a
    /// non-terminal stdout (a pipe or a redirect to a log), `NO_COLOR`, and
    /// `TERM=dumb`.
    fn enabled(self) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => {
                std::io::stdout().is_terminal()
                    && std::env::var_os("NO_COLOR").is_none()
                    && std::env::var("TERM").is_ok_and(|term| term != "dumb")
            }
        }
    }
}

#[derive(Clone)]
struct RfArgs {
    freq_khz: u32,
    bandwidth_hz: u32,
    spreading_factor: u8,
    coding_rate_denom: u8,
    sync_word: u16,
    tx_power_dbm: i8,
    idle_probe_secs: u64,
    umsh_only: bool,
    color: ColorChoice,
    pcap_path: Option<PathBuf>,
    capture_layers: CaptureLayers,
    pcap_raw: bool,
    pcap_linktype: Option<u32>,
    reconnect: bool,
    reconnect_delay_secs: u64,
}

impl Default for RfArgs {
    fn default() -> Self {
        Self {
            freq_khz: 910_525,
            bandwidth_hz: 62_500,
            spreading_factor: 7,
            coding_rate_denom: 5,
            sync_word: 0x1424,
            tx_power_dbm: 14,
            idle_probe_secs: 10,
            umsh_only: false,
            color: ColorChoice::Auto,
            pcap_path: None,
            capture_layers: CaptureLayers::Radio,
            pcap_raw: false,
            pcap_linktype: None,
            reconnect: true,
            reconnect_delay_secs: 2,
        }
    }
}

impl RfArgs {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut rf = Self::default();
        let mut capture_selection_explicit = false;
        for arg in args {
            if let Some(value) = arg.strip_prefix("--freq-khz=") {
                rf.freq_khz = parse_u32(value)?;
            } else if let Some(value) = arg.strip_prefix("--bw-hz=") {
                rf.bandwidth_hz = parse_u32(value)?;
            } else if let Some(value) = arg.strip_prefix("--sf=") {
                rf.spreading_factor = parse_u32(value)?
                    .try_into()
                    .map_err(|_| format!("invalid spreading factor: {value}"))?;
            } else if let Some(value) = arg.strip_prefix("--cr=") {
                rf.coding_rate_denom = parse_u32(value)?
                    .try_into()
                    .map_err(|_| format!("invalid coding rate: {value}"))?;
            } else if let Some(value) = arg.strip_prefix("--sync-word=") {
                rf.sync_word = parse_u32(value)?
                    .try_into()
                    .map_err(|_| format!("invalid sync word: {value}"))?;
            } else if let Some(value) = arg.strip_prefix("--tx-power=") {
                rf.tx_power_dbm = value
                    .parse()
                    .map_err(|_| format!("invalid TX power: {value}"))?;
            } else if let Some(value) = arg.strip_prefix("--idle-probe-secs=") {
                rf.idle_probe_secs = value
                    .parse()
                    .map_err(|_| format!("invalid idle probe interval: {value}"))?;
                if rf.idle_probe_secs == 0 {
                    return Err("idle probe interval must be greater than zero".into());
                }
            } else if let Some(value) = arg.strip_prefix("--reconnect-delay-secs=") {
                rf.reconnect_delay_secs = value
                    .parse()
                    .map_err(|_| format!("invalid reconnect delay: {value}"))?;
                if rf.reconnect_delay_secs == 0 {
                    return Err("reconnect delay must be greater than zero".into());
                }
            } else if arg == "--no-reconnect" {
                rf.reconnect = false;
            } else if arg == "--umsh-only" {
                rf.umsh_only = true;
            } else if let Some(value) = arg.strip_prefix("--color=") {
                rf.color = ColorChoice::parse(value)?;
            } else if let Some(value) = arg.strip_prefix("--pcap=") {
                if value.is_empty() {
                    return Err("pcap path must not be empty".into());
                }
                rf.pcap_path = Some(PathBuf::from(value));
            } else if let Some(value) = arg.strip_prefix("--capture=") {
                rf.capture_layers = CaptureLayers::parse(value)?;
                capture_selection_explicit = true;
            } else if arg == "--pcap-raw" {
                rf.pcap_raw = true;
            } else if let Some(value) = arg.strip_prefix("--pcap-linktype=") {
                rf.pcap_linktype = Some(parse_u32(value)?);
            } else if arg.starts_with('-') {
                return Err(format!("unknown option: {arg}"));
            }
        }
        if capture_selection_explicit && rf.pcap_path.is_none() {
            return Err("--capture requires --pcap=PATH".into());
        }
        if rf.pcap_raw {
            if rf.pcap_path.is_none() {
                return Err("--pcap-raw requires --pcap=PATH".into());
            }
            if rf.capture_layers != CaptureLayers::Radio {
                return Err("--pcap-raw requires --capture=radio".into());
            }
            if rf.pcap_linktype.is_none() {
                return Err("--pcap-raw requires --pcap-linktype=N".into());
            }
        } else if rf.pcap_linktype.is_some() {
            return Err("--pcap-linktype requires --pcap-raw".into());
        }
        Ok(rf)
    }

    fn config(&self) -> UlcpDeviceConfig {
        let mut config = UlcpDeviceConfig::new(
            self.freq_khz,
            self.bandwidth_hz,
            self.spreading_factor,
            self.coding_rate_denom,
        );
        config.sync_word = self.sync_word;
        config.tx_power_dbm = self.tx_power_dbm;
        config
    }
}

fn parse_u32(value: &str) -> Result<u32, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|_| format!("invalid number: {value}"))
    } else {
        value
            .parse()
            .map_err(|_| format!("invalid number: {value}"))
    }
}

#[derive(Clone, Copy)]
enum CaptureDirection {
    HostToDevice,
    DeviceToHost,
}

/// Shared classic-pcap sink. Frames use the repository's established
/// synthetic Ethernet/IPv4/UDP encapsulation so stock Wireshark can open a
/// single file containing both capture layers.
type SharedCapture = Rc<RefCell<PcapWriter>>;

const PCAP_LINKTYPE_ETHERNET: u32 = 1;
const RADIO_UDP_PORT: u16 = 4242;
const ULCP_HOST_UDP_PORT: u16 = 4243;
const ULCP_DEVICE_UDP_PORT: u16 = 4244;

#[derive(Clone, Copy)]
enum PcapEncapsulation {
    Ethernet,
    RawLoRa { linktype: u32 },
}

struct PcapWriter {
    output: BufWriter<File>,
    layers: CaptureLayers,
    encapsulation: PcapEncapsulation,
    packet_id: u16,
}

impl PcapWriter {
    fn create(
        path: &PathBuf,
        layers: CaptureLayers,
        encapsulation: PcapEncapsulation,
    ) -> std::io::Result<Self> {
        let mut output = BufWriter::new(File::create(path)?);
        output.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
        output.write_all(&2u16.to_le_bytes())?;
        output.write_all(&4u16.to_le_bytes())?;
        output.write_all(&0i32.to_le_bytes())?;
        output.write_all(&0u32.to_le_bytes())?;
        output.write_all(&65_535u32.to_le_bytes())?;
        let linktype = match encapsulation {
            PcapEncapsulation::Ethernet => PCAP_LINKTYPE_ETHERNET,
            PcapEncapsulation::RawLoRa { linktype } => linktype,
        };
        output.write_all(&linktype.to_le_bytes())?;
        output.flush()?;
        Ok(Self {
            output,
            layers,
            encapsulation,
            packet_id: 0,
        })
    }

    fn write_radio(&mut self, frame: &[u8]) -> std::io::Result<()> {
        if self.layers.radio() {
            match self.encapsulation {
                PcapEncapsulation::Ethernet => self.write_udp(
                    CaptureDirection::DeviceToHost,
                    RADIO_UDP_PORT,
                    RADIO_UDP_PORT,
                    frame,
                )?,
                PcapEncapsulation::RawLoRa { .. } => self.write_record(frame)?,
            }
        }
        Ok(())
    }

    fn write_ulcp(
        &mut self,
        direction: CaptureDirection,
        frame: &[u8],
    ) -> std::io::Result<()> {
        if !self.layers.ulcp() {
            return Ok(());
        }
        debug_assert!(matches!(self.encapsulation, PcapEncapsulation::Ethernet));
        let (src_port, dst_port) = match direction {
            CaptureDirection::HostToDevice => (ULCP_HOST_UDP_PORT, ULCP_DEVICE_UDP_PORT),
            CaptureDirection::DeviceToHost => (ULCP_DEVICE_UDP_PORT, ULCP_HOST_UDP_PORT),
        };
        self.write_udp(direction, src_port, dst_port, frame)
    }

    fn write_udp(
        &mut self,
        direction: CaptureDirection,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let udp_len = 8usize
            .checked_add(payload.len())
            .and_then(|len| u16::try_from(len).ok())
            .ok_or_else(|| std::io::Error::other("capture payload exceeds IPv4 UDP size"))?;
        let ip_len = 20u16
            .checked_add(udp_len)
            .ok_or_else(|| std::io::Error::other("capture packet exceeds IPv4 size"))?;
        let frame_len = 14usize + usize::from(ip_len);
        let mut packet = Vec::with_capacity(frame_len);

        // Synthetic Ethernet and loopback IPv4 endpoints. Direction remains
        // visible in both endpoint addresses and ULCP UDP ports.
        packet.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        packet.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&0x0800u16.to_be_bytes());
        let (src_ip, dst_ip) = match direction {
            CaptureDirection::HostToDevice => ([127, 0, 0, 1], [127, 0, 0, 2]),
            CaptureDirection::DeviceToHost => ([127, 0, 0, 2], [127, 0, 0, 1]),
        };
        let ip_start = packet.len();
        packet.extend_from_slice(&[
            0x45,
            0,
            (ip_len >> 8) as u8,
            ip_len as u8,
            (self.packet_id >> 8) as u8,
            self.packet_id as u8,
            0,
            0,
            64,
            17,
            0,
            0,
            src_ip[0],
            src_ip[1],
            src_ip[2],
            src_ip[3],
            dst_ip[0],
            dst_ip[1],
            dst_ip[2],
            dst_ip[3],
        ]);
        let checksum = ipv4_checksum(&packet[ip_start..ip_start + 20]);
        packet[ip_start + 10..ip_start + 12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&udp_len.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(payload);
        self.packet_id = self.packet_id.wrapping_add(1);

        self.write_record(&packet)
    }

    fn write_record(&mut self, packet: &[u8]) -> std::io::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let seconds = u32::try_from(timestamp.as_secs()).unwrap_or(u32::MAX);
        let captured_len = u32::try_from(packet.len())
            .map_err(|_| std::io::Error::other("capture record exceeds pcap size"))?;
        self.output.write_all(&seconds.to_le_bytes())?;
        self.output
            .write_all(&timestamp.subsec_micros().to_le_bytes())?;
        self.output.write_all(&captured_len.to_le_bytes())?;
        self.output.write_all(&captured_len.to_le_bytes())?;
        self.output.write_all(&packet)?;
        // Keep the file usable by Wireshark during a long-running capture.
        self.output.flush()
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

struct CapturingFrameLink<L> {
    inner: L,
    capture: Option<SharedCapture>,
}

impl<L> CapturingFrameLink<L> {
    fn new(inner: L, capture: Option<SharedCapture>) -> Self {
        Self { inner, capture }
    }

    fn record(&self, direction: CaptureDirection, frame: &[u8]) -> std::io::Result<()> {
        if let Some(capture) = &self.capture {
            capture.borrow_mut().write_ulcp(direction, frame)?;
        }
        Ok(())
    }
}

impl<L: FrameLink> FrameLink for CapturingFrameLink<L> {
    async fn send_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<(), umsh::ulcp::UlcpError> {
        self.record(CaptureDirection::HostToDevice, frame)?;
        self.inner.send_frame(frame).await
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, umsh::ulcp::UlcpError>> {
        match self.inner.poll_recv_frame(cx) {
            core::task::Poll::Ready(Ok(frame)) => {
                match self.record(CaptureDirection::DeviceToHost, &frame) {
                    Ok(()) => core::task::Poll::Ready(Ok(frame)),
                    Err(error) => core::task::Poll::Ready(Err(error.into())),
                }
            }
            other => other,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(first) = args.next() else {
        return Err(USAGE.into());
    };
    if first == "--help" || first == "-h" {
        print!("{USAGE}");
        return Ok(());
    }

    if first == "--scan-ble" {
        if let Some(extra) = args.next() {
            return Err(format!("--scan-ble takes no arguments (got {extra:?})\n\n{USAGE}").into());
        }
        #[cfg(feature = "ble-radio")]
        {
            use umsh::ulcp::BleFrameLink;
            let timeout = std::time::Duration::from_secs(5);
            println!("scanning for companion radios ({timeout:?})...");
            let results = BleFrameLink::scan(timeout).await?;
            if results.is_empty() {
                println!("no companion radios found");
            } else {
                for result in results {
                    let name = result.name.as_deref().unwrap_or("(no name)");
                    match result.rssi {
                        Some(rssi) => println!("{}  {name}  rssi {rssi} dBm", result.id),
                        None => println!("{}  {name}", result.id),
                    }
                }
            }
            return Ok(());
        }
        #[cfg(not(feature = "ble-radio"))]
        return Err("the ble-radio feature is required for --scan-ble".into());
    }

    let mut rest: Vec<String> = args.collect();
    let selector = if first == "--ble" {
        rest.first().filter(|arg| !arg.starts_with('-')).cloned()
    } else {
        None
    };
    if selector.is_some() {
        rest.remove(0);
    }
    let rf = RfArgs::parse(&rest).map_err(|error| format!("{error}\n\n{USAGE}"))?;
    let config = rf.config();
    let capture = if let Some(path) = &rf.pcap_path {
        let encapsulation = if rf.pcap_raw {
            PcapEncapsulation::RawLoRa {
                linktype: rf.pcap_linktype.expect("validated raw pcap linktype"),
            }
        } else {
            PcapEncapsulation::Ethernet
        };
        let writer = PcapWriter::create(path, rf.capture_layers, encapsulation)?;
        println!(
            "capture: {} layer={:?} encoding={}",
            path.display(),
            rf.capture_layers,
            if rf.pcap_raw {
                "raw LoRa"
            } else {
                "Ethernet/IPv4/UDP"
            },
        );
        Some(Rc::new(RefCell::new(writer)))
    } else {
        None
    };

    if first == "--ble" {
        #[cfg(feature = "ble-radio")]
        {
            return run_ble_dump(selector.as_deref(), config, rf, capture).await;
        }
        #[cfg(not(feature = "ble-radio"))]
        return Err("the ble-radio feature is required for --ble".into());
    }

    #[cfg(feature = "serial-radio")]
    {
        use tokio_serial::SerialPortBuilderExt;
        use umsh::ulcp::SerialFrameLink;

        println!("attaching to {first} ...");
        let stream = tokio_serial::new(&first, 115_200).open_native_async()?;
        let link = CapturingFrameLink::new(SerialFrameLink::new(stream), capture.clone());
        let radio = UlcpDevice::new(link, config).await?;
        let mut stats = DumpStats::new();
        stats.sessions = 1;
        return run_dump(radio, &rf, &mut stats, capture.as_ref()).await;
    }
    #[cfg(not(feature = "serial-radio"))]
    Err("the serial-radio feature is required for a serial path".into())
}

struct DumpStats {
    started: Instant,
    last_progress: Instant,
    sequence: u64,
    displayed: u64,
    filtered: u64,
    sessions: u64,
}

impl DumpStats {
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

#[cfg(feature = "ble-radio")]
async fn run_ble_dump(
    selector: Option<&str>,
    config: UlcpDeviceConfig,
    rf: RfArgs,
    capture: Option<SharedCapture>,
) -> Result<(), Box<dyn std::error::Error>> {
    use umsh::ulcp::{BleFrameLink, BleFrameLinkConfig};

    let mut stats = DumpStats::new();
    loop {
        println!("discovering BLE companion radio ...");
        let failure: Box<dyn std::error::Error> =
            match BleFrameLink::connect(selector, BleFrameLinkConfig::default()).await {
                Ok(link) => match UlcpDevice::new(
                    CapturingFrameLink::new(link, capture.clone()),
                    config.clone(),
                )
                .await
                {
                    Ok(radio) => {
                        stats.sessions += 1;
                        match run_dump(radio, &rf, &mut stats, capture.as_ref()).await {
                            Ok(()) => return Ok(()),
                            Err(error) => error,
                        }
                    }
                    Err(error) => Box::new(error),
                },
                Err(error) => Box::new(error),
            };

        eprintln!(
            "BLE session failure +{:.3}s after {} packets: {failure}",
            stats.started.elapsed().as_secs_f64(),
            stats.sequence,
        );
        if !rf.reconnect {
            return Err(failure);
        }
        println!(
            "recovery: rediscovering in {} s (ctrl-c to exit) ...",
            rf.reconnect_delay_secs,
        );
        tokio::time::sleep(Duration::from_secs(rf.reconnect_delay_secs)).await;
    }
}

async fn run_dump<L: FrameLink>(
    mut radio: UlcpDevice<L>,
    rf: &RfArgs,
    stats: &mut DumpStats,
    capture: Option<&SharedCapture>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "session #{}: device={} boot_status={:?}",
        stats.sessions,
        radio.dev_version(),
        radio.boot_status(),
    );
    println!(
        "radio: {} kHz, BW {} Hz, SF{}, CR 4/{}, sync 0x{:04x}",
        rf.freq_khz, rf.bandwidth_hz, rf.spreading_factor, rf.coding_rate_denom, rf.sync_word,
    );
    // A capture is a promiscuous listener. A device with a provisioned
    // (or saved-and-restored) host domain filters receptions, so the
    // factory deliver-everything rule cannot be relied on; bypass the
    // filtering for this session (`PROP_MAC_PROMISCUOUS` is
    // session-scoped and reverts on detach). A device that predates the
    // property refuses the set — capture then sees only frames
    // matching its receive filtering.
    match radio
        .set_prop(umsh::ulcp_wire::ids::prop::MAC_PROMISCUOUS, &[1])
        .await
    {
        Ok(_) => println!("promiscuous mode enabled"),
        Err(umsh::ulcp::UlcpError::Status(status)) => eprintln!(
            "warning: device refused promiscuous mode ({status:?}); \
             capture is limited to the device's receive filtering"
        ),
        Err(error) => return Err(error.into()),
    }
    let color = rf.color.enabled();
    if color {
        print_legend();
    }
    println!("dumping packets (ctrl-c to exit) ...");

    let mut buf = [0u8; 256];
    let idle_probe_interval = Duration::from_secs(rf.idle_probe_secs);
    loop {
        let receive = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf));
        let info = match tokio::time::timeout(idle_probe_interval, receive).await {
            Ok(result) => result?,
            Err(_) => {
                let value = radio
                    .get_prop(umsh::ulcp_wire::ids::prop::PHY_RSSI)
                    .await
                    .map_err(|error| {
                        format!(
                            "idle health probe failed after {} packets: {error}",
                            stats.sequence,
                        )
                    })?;
                let [rssi] = value.as_slice() else {
                    return Err(format!(
                        "idle health probe returned malformed PHY_RSSI value: {value:02x?}"
                    )
                    .into());
                };
                println!(
                    "idle +{:.3}s  received={}  displayed={}  filtered={}  session={}  link=ok  channel RSSI={} dBm",
                    stats.started.elapsed().as_secs_f64(),
                    stats.sequence,
                    stats.displayed,
                    stats.filtered,
                    stats.sessions,
                    *rssi as i8,
                );
                stats.last_progress = Instant::now();
                continue;
            }
        };
        stats.sequence += 1;
        let packet = &buf[..info.len];
        if let Some(capture) = capture {
            capture.borrow_mut().write_radio(packet)?;
        }
        if !should_display(packet, rf.umsh_only) {
            stats.filtered += 1;
            if stats.last_progress.elapsed() >= idle_probe_interval {
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
        stats.displayed += 1;
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
        print_frame(packet, color);
    }
}

fn should_display(packet: &[u8], umsh_only: bool) -> bool {
    !umsh_only || PacketHeader::parse(packet).is_ok()
}

/// A header field, used both to color its bytes in the hex dump and to color
/// the decoded value that came out of those bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Fcf,
    FloodHops,
    Dst,
    Src,
    Channel,
    SecInfo,
    Options,
    /// Ciphertext covering the addresses of a blind unicast or an encrypted
    /// multicast, which cannot be attributed to `Dst`/`Src` without the key.
    EncAddr,
    Body,
    /// A MAC ack's correlation handle: the first four bytes of the acked
    /// packet's MIC. Public, and not an authenticator.
    AckMic,
    /// A MAC ack's keyed authenticator, which only the original sender can
    /// verify.
    AckTag,
    Mic,
}

impl Field {
    /// SGR parameters for this field. Deliberately limited to the 16 basic
    /// colors so the output survives minimal terminals.
    fn sgr(self) -> &'static str {
        match self {
            Self::Fcf => "1;97",
            Self::FloodHops => "93",
            Self::Dst => "91",
            Self::Src => "92",
            Self::Channel => "95",
            Self::SecInfo => "33",
            Self::Options => "96",
            Self::EncAddr => "94",
            Self::Body => "37",
            Self::AckMic => "36",
            Self::AckTag => "35",
            Self::Mic => "90",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Fcf => "fcf",
            Self::FloodHops => "hops",
            Self::Dst => "dst",
            Self::Src => "src",
            Self::Channel => "channel",
            Self::SecInfo => "secinfo",
            Self::Options => "options",
            Self::EncAddr => "enc-addr",
            Self::Body => "body",
            Self::AckMic => "ack-mic",
            Self::AckTag => "ack-tag",
            Self::Mic => "mic",
        }
    }
}

const LEGEND: [Field; 12] = [
    Field::Fcf,
    Field::FloodHops,
    Field::Dst,
    Field::Src,
    Field::Channel,
    Field::SecInfo,
    Field::Options,
    Field::EncAddr,
    Field::Body,
    Field::AckMic,
    Field::AckTag,
    Field::Mic,
];

/// Bold white on red. Encryption is the norm, so nothing marks it; it is
/// cleartext that has to be impossible to scroll past.
const UNENCRYPTED_SGR: &str = "1;97;41";

/// Wrap `text` in the given SGR parameters, or return it unchanged when the
/// output is not colorized.
fn styled(text: &str, sgr: &str, color: bool) -> String {
    if color {
        format!("\x1b[{sgr}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// Wrap `text` in this field's color, or return it unchanged when the output
/// is not colorized.
fn tint(text: &str, field: Field, color: bool) -> String {
    styled(text, field.sgr(), color)
}

fn print_legend() {
    let chips: Vec<String> = LEGEND
        .iter()
        .map(|field| tint(field.label(), *field, true))
        .collect();
    println!("fields: {}", chips.join("  "));
}

/// Attribute every byte of `packet` to the field it belongs to.
///
/// The layout is reconstructed from the landmarks `PacketHeader` already
/// computed (options, body, and MIC ranges plus the SECINFO length), so it
/// stays in step with the parser rather than re-deriving the wire format.
fn field_map(header: &PacketHeader, len: usize) -> Vec<Option<Field>> {
    fn paint(map: &mut [Option<Field>], range: Range<usize>, field: Field) {
        if let Some(slice) = map.get_mut(range) {
            slice.fill(Some(field));
        }
    }

    let mut map = vec![None; len];
    paint(&mut map, 0..1, Field::Fcf);
    let mut cursor = 1;
    if header.flood_hops.is_some() {
        paint(&mut map, 1..2, Field::FloodHops);
        cursor = 2;
    }

    let options = header.options_range.clone();
    // Painted before the addressing fields: an encrypted multicast places its
    // ciphertext source at the head of the body range, and must win.
    paint(&mut map, header.body_range.clone(), Field::Body);
    paint(&mut map, options.clone(), Field::Options);
    paint(&mut map, header.mic_range.clone(), Field::Mic);

    let sec_len = header.sec_info.map_or(0, |sec| sec.wire_len());
    let sec_start = options.start.saturating_sub(sec_len);
    match header.packet_type() {
        PacketType::Broadcast => paint(&mut map, cursor..options.start, Field::Src),
        // A MAC ack has no addressing, and no MIC of its own: its two fixed
        // fields are body. `PacketHeader` reports the same range as both
        // `body_range` and `mic_range`, so split it here.
        PacketType::MacAck => {
            let ack = header.body_range.start;
            paint(&mut map, ack..ack + 4, Field::AckMic);
            paint(&mut map, ack + 4..ack + 8, Field::AckTag);
        }
        PacketType::Reserved5 => {}
        PacketType::Unicast | PacketType::UnicastAckReq => {
            paint(&mut map, cursor..cursor + 3, Field::Dst);
            paint(&mut map, cursor + 3..sec_start, Field::Src);
            paint(&mut map, sec_start..options.start, Field::SecInfo);
        }
        PacketType::Multicast => {
            paint(&mut map, cursor..cursor + 2, Field::Channel);
            paint(&mut map, cursor + 2..options.start, Field::SecInfo);
            match header.source {
                SourceAddrRef::Encrypted { offset, len } => {
                    paint(&mut map, offset..offset + len, Field::EncAddr)
                }
                _ => paint(&mut map, options.end..header.body_range.start, Field::Src),
            }
        }
        PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {
            paint(&mut map, cursor..cursor + 2, Field::Channel);
            paint(&mut map, cursor + 2..options.start, Field::SecInfo);
            if matches!(header.source, SourceAddrRef::Encrypted { .. }) {
                paint(&mut map, options.end..header.body_range.start, Field::EncAddr);
            } else {
                paint(&mut map, options.end..options.end + 3, Field::Dst);
                paint(&mut map, options.end + 3..header.body_range.start, Field::Src);
            }
        }
    }
    map
}

/// Render the hex dump, grouped by field.
///
/// Colorized output needs no separators — the color change marks each field
/// boundary — so the bytes run together and stay compact. Without color the
/// same grouping is spelled with spaces between fields.
fn print_hex(packet: &[u8], map: &[Option<Field>], color: bool) {
    for line in hex_lines(packet, map, color) {
        println!("  {line}");
    }
}

/// Visible hex columns per line, chosen so a full-size LoRa frame wraps but a
/// typical one stays on a single line.
const HEX_WIDTH: usize = 96;

fn hex_lines(packet: &[u8], map: &[Option<Field>], color: bool) -> Vec<String> {
    let field_at = |index: usize| map.get(index).copied().flatten();

    // Split the frame into lines that fit the width budget. Each byte costs
    // two columns, plus one for the space that separates fields when the
    // output is not colorized.
    let mut spans: Vec<Range<usize>> = Vec::new();
    let mut start = 0;
    let mut col = 0;
    for index in 0..packet.len() {
        let separated = !color && index > start && field_at(index) != field_at(index - 1);
        let cost = 2 + usize::from(separated);
        if index > start && col + cost > HEX_WIDTH {
            spans.push(start..index);
            start = index;
            col = 2;
        } else {
            col += cost;
        }
    }
    if start < packet.len() {
        spans.push(start..packet.len());
    }

    spans
        .into_iter()
        .map(|span| {
            let mut line = String::new();
            let mut index = span.start;
            while index < span.end {
                let field = field_at(index);
                let mut run = index;
                while run < span.end && field_at(run) == field {
                    run += 1;
                }
                if !color && index != span.start {
                    line.push(' ');
                }
                let mut hex = String::new();
                for byte in &packet[index..run] {
                    let _ = write!(hex, "{byte:02x}");
                }
                match field {
                    Some(field) => line.push_str(&tint(&hex, field, color)),
                    None => line.push_str(&hex),
                }
                index = run;
            }
            line
        })
        .collect()
}

/// Print the decode summary, the present options, and the hex dump.
fn print_frame(packet: &[u8], color: bool) {
    let header = match PacketHeader::parse(packet) {
        Ok(header) => header,
        Err(error) => {
            println!("  not a UMSH packet ({error:?})");
            print_hex(packet, &vec![None; packet.len()], color);
            return;
        }
    };

    println!("  {}", summary_line(packet, &header, color));
    if let Some(line) = options_line(packet, &header, color) {
        println!("  {line}");
    }
    print_hex(packet, &field_map(&header, packet.len()), color);
}

/// Build the one-line decode summary: what it is, who it is between, and the
/// security and framing state that applies to it.
fn summary_line(packet: &[u8], header: &PacketHeader, color: bool) -> String {
    let mut chips: Vec<String> = Vec::new();
    let packet_type = header.packet_type();
    let type_text = format!("{packet_type:?}");
    chips.push(if color {
        format!("\x1b[1m{type_text}\x1b[0m")
    } else {
        type_text
    });

    // A destination hint names a node; a multicast or an encrypted blind
    // unicast is addressed by channel instead, so the channel stands in as
    // the destination and only appears separately when both are present.
    let dst = match (header.dst, header.channel) {
        (Some(hint), _) => Some(tint(&hint.to_string(), Field::Dst, color)),
        (None, Some(channel)) => Some(tint(
            &format!("ch:{:02x}{:02x}", channel.0[0], channel.0[1]),
            Field::Channel,
            color,
        )),
        (None, None) if packet_type == PacketType::Broadcast => Some("*".to_owned()),
        (None, None) => None,
    };
    let src = source_text(packet, header).map(|text| tint(&text, Field::Src, color));
    match (src, dst) {
        (Some(src), Some(dst)) => chips.push(format!("{src} → {dst}")),
        (Some(src), None) => chips.push(src),
        (None, Some(dst)) => chips.push(format!("→ {dst}")),
        (None, None) => {}
    }
    if header.dst.is_some()
        && let Some(channel) = header.channel
    {
        chips.push(tint(
            &format!("ch:{:02x}{:02x}", channel.0[0], channel.0[1]),
            Field::Channel,
            color,
        ));
    }

    // Rendered `remaining:accumulated`, matching the order of the two
    // nibbles in the FHOPS byte itself. `FHOPS_REM` is the flood-forwarding
    // budget still to spend and `FHOPS_ACC` the flood hops already
    // traversed; neither is a time-to-live nor a total hop count, since a
    // source-routed hop moves neither nibble.
    if let Some(hops) = header.flood_hops {
        chips.push(tint(
            &format!("fhops={}:{}", hops.remaining(), hops.accumulated()),
            Field::FloodHops,
            color,
        ));
    }

    let encrypted = header
        .sec_info
        .is_some_and(|security| security.scf.encrypted());
    if let Some(security) = header.sec_info {
        // Spelled `fcnt` rather than `ctr`, which would read as the AES-CTR
        // half of the packet's own encryption.
        chips.push(tint(
            &format!("fcnt={}", security.frame_counter),
            Field::SecInfo,
            color,
        ));
        if let Some(salt) = security.salt {
            chips.push(tint(&format!("salt={salt:#06x}"), Field::SecInfo, color));
        }
        // Encrypted is the expected case and says nothing; a secured packet
        // type carrying cleartext is the anomaly worth shouting about.
        if !encrypted {
            chips.push(styled("UNENC", UNENCRYPTED_SGR, color));
        }
    }
    // `ack_requested()` is derived purely from the packet type, which is
    // already the first chip on the line, so it gets no chip of its own.

    // A MAC ack's whole content is its two fixed fields, so show them rather
    // than a length: the ack MIC correlates the ack with the packet it
    // acknowledges, and the ack tag is what actually authenticates it.
    if packet_type == PacketType::MacAck {
        let ack = header.body_range.start;
        match packet.get(ack..ack + 8) {
            Some(fields) => {
                chips.push(tint(
                    &format!("ack_mic={}", hex_text(&fields[..4])),
                    Field::AckMic,
                    color,
                ));
                chips.push(tint(
                    &format!("ack_tag={}", hex_text(&fields[4..])),
                    Field::AckTag,
                    color,
                ));
            }
            None => chips.push("<truncated ack>".to_owned()),
        }
        return chips.join("  ");
    }

    // Lengths carry their unit so they cannot be read as the field's value.
    if header.is_beacon() {
        chips.push("beacon".to_owned());
    } else {
        chips.push(tint(
            &format!("body={}B", header.body_range.len()),
            Field::Body,
            color,
        ));
    }
    // The payload type is the first body byte, and is only readable in the
    // clear.
    if !encrypted
        && let Some(payload) = packet
            .get(header.body_range.start)
            .and_then(|byte| PayloadType::from_byte(*byte))
    {
        chips.push(tint(&format!("{payload:?}"), Field::Body, color));
    }
    if !header.mic_range.is_empty() {
        chips.push(tint(
            &format!("mic={}B", header.mic_range.len()),
            Field::Mic,
            color,
        ));
    }
    chips.join("  ")
}

/// Render the source address: a hint, a full key, or an acknowledgement that
/// it is sealed.
fn source_text(packet: &[u8], header: &PacketHeader) -> Option<String> {
    match header.source {
        SourceAddrRef::Hint(hint) => Some(hint.to_string()),
        SourceAddrRef::FullKeyAt { offset } => Some(
            packet
                .get(offset..offset + 32)
                .map_or_else(|| "<truncated>".to_owned(), |bytes| {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(bytes);
                    PublicKey(key).to_string()
                }),
        ),
        SourceAddrRef::Encrypted { .. } => Some("<enc>".to_owned()),
        SourceAddrRef::None => None,
    }
}

/// Render the options that are actually present, decoding each one's value.
///
/// This walks the option block directly rather than going through
/// `ParsedOptions`, so options that the MAC has no use for — callsigns, and
/// anything unrecognized — still show up in a capture.
fn options_line(packet: &[u8], header: &PacketHeader, color: bool) -> Option<String> {
    let range = header.options_range.clone();
    if range.is_empty() {
        return None;
    }

    let mut chips: Vec<String> = Vec::new();
    for entry in OptionDecoder::new(&packet[range]) {
        let (number, value) = match entry {
            Ok(entry) => entry,
            Err(error) => {
                chips.push(format!("<decode error: {error:?}>"));
                break;
            }
        };
        chips.push(option_chip(number, value));
    }
    if chips.is_empty() {
        return None;
    }
    Some(format!(
        "{}  {}",
        tint("opts", Field::Options, color),
        chips
            .iter()
            .map(|chip| tint(chip, Field::Options, color))
            .collect::<Vec<_>>()
            .join("  "),
    ))
}

fn option_chip(number: u16, value: &[u8]) -> String {
    match OptionNumber::from(number) {
        OptionNumber::TraceRoute => format!("trace=[{}]", route_text(value)),
        OptionNumber::SourceRoute => format!("route=[{}]", route_text(value)),
        OptionNumber::RegionCode if value.len() == 2 => {
            format!("region={}", RegionCode::from_bytes([value[0], value[1]]))
        }
        // A zero-length threshold selects the receiver's default, which the
        // frame itself does not name.
        OptionNumber::MinRssi if value.is_empty() => "min-rssi=default".to_owned(),
        OptionNumber::MinRssi if value.len() == 1 => format!("min-rssi={}", -i16::from(value[0])),
        OptionNumber::MinSnr if value.is_empty() => "min-snr=default".to_owned(),
        OptionNumber::MinSnr if value.len() == 1 => format!("min-snr={}", value[0] as i8),
        OptionNumber::RouteRetry if value.is_empty() => "retry".to_owned(),
        OptionNumber::OperatorCallsign => format!("op={}", callsign_text(value)),
        OptionNumber::StationCallsign => format!("via={}", callsign_text(value)),
        // Either an unknown option or a known one carrying a malformed value.
        // Critical options carry an odd number and are marked, since a
        // receiver that does not understand one has to drop the frame.
        other => format!(
            "{}opt{number}={}",
            if other.is_critical() { "!" } else { "" },
            hex_text(value),
        ),
    }
}

/// Render a route option as its list of router hints.
fn route_text(value: &[u8]) -> String {
    if !value.len().is_multiple_of(2) {
        return hex_text(value);
    }
    value
        .chunks_exact(2)
        .map(|hop| RouterHint([hop[0], hop[1]]).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn callsign_text(value: &[u8]) -> String {
    HamAddr::try_from_slice(value).map_or_else(|_| hex_text(value), |addr| addr.to_string())
}

fn hex_text(value: &[u8]) -> String {
    if value.is_empty() {
        return "-".to_owned();
    }
    let mut text = String::with_capacity(value.len() * 2);
    for byte in value {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_and_hex_rf_options() {
        let args = vec![
            "--freq-khz=915000".to_owned(),
            "--sync-word=0x1234".to_owned(),
            "--sf=9".to_owned(),
        ];
        let rf = RfArgs::parse(&args).unwrap();
        assert_eq!(rf.freq_khz, 915_000);
        assert_eq!(rf.sync_word, 0x1234);
        assert_eq!(rf.spreading_factor, 9);
        assert_eq!(rf.idle_probe_secs, 10);
        assert!(!rf.umsh_only);
        assert!(rf.pcap_path.is_none());
        assert_eq!(rf.capture_layers, CaptureLayers::Radio);
        assert!(!rf.pcap_raw);
        assert!(rf.pcap_linktype.is_none());
        assert!(rf.reconnect);
        assert_eq!(rf.reconnect_delay_secs, 2);
    }

    #[test]
    fn rejects_unknown_options() {
        assert!(RfArgs::parse(&["--mystery=1".to_owned()]).is_err());
    }

    #[test]
    fn parses_and_validates_idle_probe_interval() {
        let rf = RfArgs::parse(&["--idle-probe-secs=3".to_owned()]).unwrap();
        assert_eq!(rf.idle_probe_secs, 3);
        assert!(RfArgs::parse(&["--idle-probe-secs=0".to_owned()]).is_err());
    }

    #[test]
    fn parses_reconnect_options() {
        let rf = RfArgs::parse(&[
            "--no-reconnect".to_owned(),
            "--reconnect-delay-secs=7".to_owned(),
        ])
        .unwrap();
        assert!(!rf.reconnect);
        assert_eq!(rf.reconnect_delay_secs, 7);
        assert!(RfArgs::parse(&["--reconnect-delay-secs=0".to_owned()]).is_err());
    }

    #[test]
    fn parses_umsh_only_filter() {
        let rf = RfArgs::parse(&["--umsh-only".to_owned()]).unwrap();
        assert!(rf.umsh_only);
    }

    #[test]
    fn umsh_only_suppresses_foreign_frames_but_not_valid_umsh() {
        let valid_umsh_beacon = [0xc0, 0xa1, 0xb2, 0x03];
        let foreign_frame = [0x15, 0x02, 0x69, 0x26];
        assert!(should_display(&valid_umsh_beacon, true));
        assert!(!should_display(&foreign_frame, true));
        assert!(should_display(&foreign_frame, false));
    }

    #[test]
    fn parses_and_validates_capture_options() {
        let rf = RfArgs::parse(&[
            "--pcap=capture.pcap".to_owned(),
            "--capture=both".to_owned(),
        ])
        .unwrap();
        assert_eq!(rf.pcap_path, Some(PathBuf::from("capture.pcap")));
        assert_eq!(rf.capture_layers, CaptureLayers::Both);
        assert!(RfArgs::parse(&["--capture=both".to_owned()]).is_err());

        let raw = RfArgs::parse(&[
            "--pcap=raw.pcap".to_owned(),
            "--pcap-raw".to_owned(),
            "--pcap-linktype=147".to_owned(),
        ])
        .unwrap();
        assert!(raw.pcap_raw);
        assert_eq!(raw.pcap_linktype, Some(147));
        assert!(RfArgs::parse(&["--pcap-raw".to_owned()]).is_err());
        assert!(
            RfArgs::parse(&[
                "--pcap=raw.pcap".to_owned(),
                "--pcap-raw".to_owned(),
                "--pcap-linktype=147".to_owned(),
                "--capture=both".to_owned(),
            ])
            .is_err()
        );
    }

    #[test]
    fn raw_pcap_preserves_lora_bytes_and_requested_linktype() {
        let path = temp_capture_path("raw");
        let mut writer = PcapWriter::create(
            &path,
            CaptureLayers::Radio,
            PcapEncapsulation::RawLoRa { linktype: 147 },
        )
        .unwrap();
        writer.write_radio(&[0xc0, 0xa1, 0xb2, 0x03]).unwrap();
        drop(writer);

        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 147);
        assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 4);
        assert_eq!(&bytes[40..], &[0xc0, 0xa1, 0xb2, 0x03]);
    }

    #[test]
    fn ethernet_pcap_preserves_ulcp_direction_and_payload() {
        let path = temp_capture_path("ulcp");
        let mut writer =
            PcapWriter::create(&path, CaptureLayers::Ulcp, PcapEncapsulation::Ethernet)
                .unwrap();
        writer
            .write_ulcp(CaptureDirection::HostToDevice, &[0x81, 0x02, 0x26])
            .unwrap();
        drop(writer);

        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let packet = &bytes[40..];
        assert_eq!(&packet[12..14], &0x0800u16.to_be_bytes());
        assert_eq!(packet[23], 17);
        assert_eq!(
            u16::from_be_bytes(packet[34..36].try_into().unwrap()),
            ULCP_HOST_UDP_PORT,
        );
        assert_eq!(
            u16::from_be_bytes(packet[36..38].try_into().unwrap()),
            ULCP_DEVICE_UDP_PORT,
        );
        assert_eq!(&packet[42..], &[0x81, 0x02, 0x26]);
    }

    /// Packet #559 from a live capture: a source-routed encrypted unicast
    /// with an empty trace-route option, one source-route hop, and flood
    /// hops still to spend.
    const SOURCE_ROUTED_UNICAST: [u8; 44] = [
        0xd1, 0x50, 0xb7, 0xa6, 0x26, 0x45, 0xfe, 0xb2, 0xe0, 0xdf, 0x45, 0xb6, 0xa0, 0x20, 0x12,
        0xef, 0x24, 0xff, 0xa2, 0x41, 0x4a, 0x15, 0xf0, 0x7c, 0x55, 0x21, 0x51, 0xd6, 0x7d, 0xe6,
        0x29, 0xbb, 0xf3, 0xa0, 0xee, 0x37, 0x93, 0xa4, 0x22, 0x20, 0x9a, 0x49, 0x8f, 0x72,
    ];

    /// Packet #560: the same frame after a repeater consumed the source
    /// route and appended itself to the trace.
    const FORWARDED_UNICAST: [u8; 44] = [
        0xd1, 0x41, 0xb7, 0xa6, 0x26, 0x45, 0xfe, 0xb2, 0xe0, 0xdf, 0x45, 0xb6, 0xa0, 0x22, 0xef,
        0x24, 0x10, 0xff, 0xa2, 0x41, 0x4a, 0x15, 0xf0, 0x7c, 0x55, 0x21, 0x51, 0xd6, 0x7d, 0xe6,
        0x29, 0xbb, 0xf3, 0xa0, 0xee, 0x37, 0x93, 0xa4, 0x22, 0x20, 0x9a, 0x49, 0x8f, 0x72,
    ];

    #[test]
    fn summary_reports_addressing_security_and_framing() {
        let header = PacketHeader::parse(&SOURCE_ROUTED_UNICAST).unwrap();
        let summary = summary_line(&SOURCE_ROUTED_UNICAST, &header, false);
        assert_eq!(
            summary,
            "Unicast  5iEP → DMt*  fhops=5:0  fcnt=3745887904  body=10B  mic=16B",
        );
        // No `Some(..)`, and absent fields say nothing at all.
        assert!(!summary.contains("Some"));
        assert!(!summary.contains("None"));

        // One flood hop later: the repeater spent a hop from the remaining
        // budget and added it to the accumulated count. Neither nibble is a
        // total, so both are shown, in the order they appear in the byte.
        let forwarded = PacketHeader::parse(&FORWARDED_UNICAST).unwrap();
        assert!(
            summary_line(&FORWARDED_UNICAST, &forwarded, false).contains("fhops=4:1"),
        );
    }

    /// Packet #110 from a live capture: a MAC ack with a flood-hop field and
    /// an empty options block.
    const MAC_ACK: [u8; 10] = [
        0xc9, 0x10, 0x8c, 0xb6, 0x8f, 0x5d, 0x97, 0x00, 0xed, 0xe7,
    ];

    /// Packet #109 from a live capture: a forwarded ack-requested unicast
    /// whose source route was consumed by the repeater that carried it.
    const UNICAST_ACK_REQ: [u8; 40] = [
        0xd9, 0x41, 0x1e, 0x9d, 0xb8, 0x45, 0xfe, 0xb2, 0xe0, 0xdf, 0x45, 0xb6, 0xa7, 0x30, 0xff,
        0x94, 0x21, 0xd3, 0x18, 0x09, 0x2e, 0x78, 0xd6, 0x47, 0x8c, 0xb6, 0x8f, 0x5d, 0x0d, 0xcd,
        0xe2, 0x26, 0x8f, 0xf2, 0x9a, 0x60, 0x75, 0xbd, 0x1b, 0x41,
    ];

    #[test]
    fn ack_request_is_stated_once_by_the_packet_type() {
        let header = PacketHeader::parse(&UNICAST_ACK_REQ).unwrap();
        assert!(header.ack_requested());
        let summary = summary_line(&UNICAST_ACK_REQ, &header, false);
        assert_eq!(
            summary,
            "UnicastAckReq  5iEP → 34Wi  fhops=4:1  fcnt=3745887911  body=9B  mic=16B",
        );
        // The type name already carries it; nothing repeats it.
        assert_eq!(summary.matches("Ack").count(), 1);
        assert!(!summary.contains("ack-req"));

        // A repeater that consumed the final hint leaves the emptied option
        // behind for provenance, and the capture must still show it.
        assert_eq!(
            options_line(&UNICAST_ACK_REQ, &header, false).unwrap(),
            "opts  route=[]",
        );
    }

    #[test]
    fn mac_ack_reports_its_two_body_fields_not_a_trailer() {
        let header = PacketHeader::parse(&MAC_ACK).unwrap();
        assert_eq!(header.packet_type(), PacketType::MacAck);
        assert_eq!(
            summary_line(&MAC_ACK, &header, false),
            "MacAck  fhops=1:0  ack_mic=8cb68f5d  ack_tag=9700ede7",
        );

        // The two fields are body, and a MAC ack has no MIC of its own —
        // even though `PacketHeader` reports the same range as `mic_range`.
        let map = field_map(&header, MAC_ACK.len());
        assert_eq!(map[0], Some(Field::Fcf));
        assert_eq!(map[1], Some(Field::FloodHops));
        for index in 2..6 {
            assert_eq!(map[index], Some(Field::AckMic), "byte {index}");
        }
        for index in 6..10 {
            assert_eq!(map[index], Some(Field::AckTag), "byte {index}");
        }
        assert!(
            !map.contains(&Some(Field::Mic)),
            "a MAC ack carries no MIC of its own",
        );

        assert_eq!(
            hex_lines(&MAC_ACK, &map, false),
            vec!["c9 10 8cb68f5d 9700ede7"],
        );
    }

    #[test]
    fn cleartext_is_flagged_loudly_and_encryption_is_silent() {
        // Encryption is the expected case, so it adds nothing to the line.
        let header = PacketHeader::parse(&SOURCE_ROUTED_UNICAST).unwrap();
        assert!(!summary_line(&SOURCE_ROUTED_UNICAST, &header, false).contains("UNENC"));

        // Clearing the SCF encrypted bit leaves a secured packet type
        // carrying cleartext, which must be impossible to miss.
        let mut cleartext = SOURCE_ROUTED_UNICAST;
        cleartext[8] &= 0x7f;
        let header = PacketHeader::parse(&cleartext).unwrap();
        assert!(!header.sec_info.unwrap().scf.encrypted());

        let plain = summary_line(&cleartext, &header, false);
        assert!(plain.contains("UNENC"), "{plain}");

        // Colorized, it is bold white on a red background.
        let colored = summary_line(&cleartext, &header, true);
        assert!(colored.contains("\x1b[1;97;41mUNENC\x1b[0m"), "{colored}");
    }

    #[test]
    fn options_line_lists_only_present_options_with_decoded_routes() {
        let header = PacketHeader::parse(&SOURCE_ROUTED_UNICAST).unwrap();
        let line = options_line(&SOURCE_ROUTED_UNICAST, &header, false).unwrap();
        // Trace route is present but still empty; the source route names the
        // next hop rather than a byte range.
        assert_eq!(line, "opts  trace=[]  route=[H6*]");
        for absent in ["region", "min-rssi", "min-snr", "retry"] {
            assert!(!line.contains(absent), "{absent} should not be listed");
        }

        let forwarded = PacketHeader::parse(&FORWARDED_UNICAST).unwrap();
        let line = options_line(&FORWARDED_UNICAST, &forwarded, false).unwrap();
        assert_eq!(line, "opts  trace=[H6*]  route=[]");
    }

    #[test]
    fn option_chips_decode_each_known_option() {
        assert_eq!(option_chip(11, &[0x78, 0x53]), "region=SJC");
        assert_eq!(option_chip(5, &[130]), "min-rssi=-130");
        assert_eq!(option_chip(5, &[]), "min-rssi=default");
        assert_eq!(option_chip(9, &[0xfd]), "min-snr=-3");
        assert_eq!(option_chip(6, &[]), "retry");
        assert_eq!(
            option_chip(4, HamAddr::try_from_callsign("KJ6QOH").unwrap().as_trimmed_slice()),
            "op=KJ6QOH",
        );
        assert_eq!(
            option_chip(7, HamAddr::try_from_callsign("KZ2X").unwrap().as_trimmed_slice()),
            "via=KZ2X",
        );
        // Unknown options survive, and the critical ones are marked.
        assert_eq!(option_chip(20, &[0xaa, 0xbb]), "opt20=aabb");
        assert_eq!(option_chip(21, &[0xaa]), "!opt21=aa");
    }

    #[test]
    fn field_map_attributes_every_byte_of_a_unicast() {
        let header = PacketHeader::parse(&SOURCE_ROUTED_UNICAST).unwrap();
        let map = field_map(&header, SOURCE_ROUTED_UNICAST.len());
        let expected = [
            (0..1, Field::Fcf),
            (1..2, Field::FloodHops),
            (2..5, Field::Dst),
            (5..8, Field::Src),
            (8..13, Field::SecInfo),
            (13..18, Field::Options),
            (18..28, Field::Body),
            (28..44, Field::Mic),
        ];
        for (range, field) in expected {
            for index in range.clone() {
                assert_eq!(map[index], Some(field), "byte {index} of {range:?}");
            }
        }
        assert!(map.iter().all(Option::is_some), "every byte is attributed");
    }

    #[test]
    fn hex_dump_groups_by_field_and_drops_spaces_when_colorized() {
        let header = PacketHeader::parse(&SOURCE_ROUTED_UNICAST).unwrap();
        let map = field_map(&header, SOURCE_ROUTED_UNICAST.len());

        // Uncolored output separates fields with spaces.
        let plain = hex_lines(&SOURCE_ROUTED_UNICAST, &map, false);
        assert_eq!(
            plain,
            vec![
                "d1 50 b7a626 45feb2 e0df45b6a0 2012ef24ff \
                 a2414a15f07c552151d6 7de629bbf3a0ee3793a422209a498f72",
            ],
        );

        // Colorized output needs no separators: the color change is the
        // boundary. Stripping the escapes recovers a bare hex string.
        let colored = hex_lines(&SOURCE_ROUTED_UNICAST, &map, true);
        assert_eq!(colored.len(), 1);
        assert!(colored[0].contains("\x1b["));
        assert_eq!(
            strip_ansi(&colored[0]),
            SOURCE_ROUTED_UNICAST
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
    }

    #[test]
    fn hex_dump_wraps_a_full_size_frame_without_losing_bytes() {
        let packet = [0x5au8; 200];
        let map = vec![Some(Field::Body); packet.len()];
        let lines = hex_lines(&packet, &map, true);
        assert!(lines.len() > 1, "a 200-byte frame must wrap");
        for line in &lines {
            assert!(strip_ansi(line).len() <= HEX_WIDTH, "line exceeds budget");
        }
        let rejoined: String = lines.iter().map(|line| strip_ansi(line)).collect();
        assert_eq!(rejoined, "5a".repeat(packet.len()));
    }

    #[test]
    fn non_umsh_frames_still_dump_their_bytes() {
        let foreign = [0x15, 0x02, 0x69, 0x26];
        let map = vec![None; foreign.len()];
        assert_eq!(hex_lines(&foreign, &map, false), vec!["15026926"]);
    }

    fn strip_ansi(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                for skip in chars.by_ref() {
                    if skip == 'm' {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn beacons_and_foreign_frames_render_without_a_security_header() {
        let beacon = [0xc0, 0xa1, 0xb2, 0x03];
        let header = PacketHeader::parse(&beacon).unwrap();
        assert_eq!(
            summary_line(&beacon, &header, false),
            "Broadcast  BtC5 → *  beacon",
        );
        assert!(options_line(&beacon, &header, false).is_none());

        assert!(PacketHeader::parse(&[0x15, 0x02, 0x69, 0x26]).is_err());
    }

    #[test]
    fn parses_color_choice() {
        assert_eq!(ColorChoice::parse("always").unwrap(), ColorChoice::Always);
        assert_eq!(ColorChoice::parse("never").unwrap(), ColorChoice::Never);
        assert!(ColorChoice::parse("sometimes").is_err());
        assert!(ColorChoice::Always.enabled());
        assert!(!ColorChoice::Never.enabled());
        let rf = RfArgs::parse(&["--color=never".to_owned()]).unwrap();
        assert_eq!(rf.color, ColorChoice::Never);
    }

    fn temp_capture_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "umsh-capture-{label}-{}-{nonce}.pcap",
            std::process::id(),
        ))
    }
}
