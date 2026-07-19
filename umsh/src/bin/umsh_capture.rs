//! Live inspection and pcap capture from a companion-radio NCP.
//!
//! The default RF profile matches the T-Echo NCP bringup profile:
//! 910.525 MHz, LoRa SF7 / BW62.5 kHz / CR4-5, sync word 0x1424.

#![cfg_attr(
    not(any(feature = "serial-radio", feature = "ble-radio")),
    allow(unused_variables, dead_code)
)]

use std::cell::RefCell;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use umsh::companion_radio::{CompanionRadio, CompanionRadioConfig, FrameLink};
use umsh::core::{PacketHeader, PacketType, ParsedOptions, PayloadType, PublicKey, SourceAddrRef};
use umsh::hal::Radio;

const USAGE: &str = "\
usage: umsh-capture <serial-port> [options]\n\
       umsh-capture --ble [selector] [options]\n\n\
Options (RF defaults shown):\n\
  --freq-khz=910525\n\
  --bw-hz=62500\n\
  --sf=7\n\
  --cr=5                 coding-rate denominator (4/5)\n\
  --sync-word=0x1424\n\
  --tx-power=14\n\
  --idle-probe-secs=10    verify BLE/NCP/radio health while RF is quiet\n\
  --umsh-only             suppress raw/decoded output for non-UMSH frames\n\
  --pcap=PATH             write a Wireshark-compatible capture\n\
  --capture=radio         pcap layer: radio, companion, or both\n\
  --pcap-raw              store exact raw LoRa frames (radio layer only)\n\
  --pcap-linktype=N       pcap LINKTYPE value required by --pcap-raw\n\
  --reconnect-delay-secs=2\n\
  --no-reconnect          exit instead of recovering a failed BLE session\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureLayers {
    Radio,
    Companion,
    Both,
}

impl CaptureLayers {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "radio" => Ok(Self::Radio),
            "companion" => Ok(Self::Companion),
            "both" => Ok(Self::Both),
            _ => Err(format!(
                "invalid capture layer {value:?}; expected radio, companion, or both"
            )),
        }
    }

    fn radio(self) -> bool {
        matches!(self, Self::Radio | Self::Both)
    }

    fn companion(self) -> bool {
        matches!(self, Self::Companion | Self::Both)
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

    fn config(&self) -> CompanionRadioConfig {
        let mut config = CompanionRadioConfig::new(
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
    HostToNcp,
    NcpToHost,
}

/// Shared classic-pcap sink. Frames use the repository's established
/// synthetic Ethernet/IPv4/UDP encapsulation so stock Wireshark can open a
/// single file containing both capture layers.
type SharedCapture = Rc<RefCell<PcapWriter>>;

const PCAP_LINKTYPE_ETHERNET: u32 = 1;
const RADIO_UDP_PORT: u16 = 4242;
const COMPANION_HOST_UDP_PORT: u16 = 4243;
const COMPANION_NCP_UDP_PORT: u16 = 4244;

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
                    CaptureDirection::NcpToHost,
                    RADIO_UDP_PORT,
                    RADIO_UDP_PORT,
                    frame,
                )?,
                PcapEncapsulation::RawLoRa { .. } => self.write_record(frame)?,
            }
        }
        Ok(())
    }

    fn write_companion(
        &mut self,
        direction: CaptureDirection,
        frame: &[u8],
    ) -> std::io::Result<()> {
        if !self.layers.companion() {
            return Ok(());
        }
        debug_assert!(matches!(self.encapsulation, PcapEncapsulation::Ethernet));
        let (src_port, dst_port) = match direction {
            CaptureDirection::HostToNcp => (COMPANION_HOST_UDP_PORT, COMPANION_NCP_UDP_PORT),
            CaptureDirection::NcpToHost => (COMPANION_NCP_UDP_PORT, COMPANION_HOST_UDP_PORT),
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
        // visible in both endpoint addresses and companion UDP ports.
        packet.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        packet.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&0x0800u16.to_be_bytes());
        let (src_ip, dst_ip) = match direction {
            CaptureDirection::HostToNcp => ([127, 0, 0, 1], [127, 0, 0, 2]),
            CaptureDirection::NcpToHost => ([127, 0, 0, 2], [127, 0, 0, 1]),
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
            capture.borrow_mut().write_companion(direction, frame)?;
        }
        Ok(())
    }
}

impl<L: FrameLink> FrameLink for CapturingFrameLink<L> {
    async fn send_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<(), umsh::companion_radio::CompanionRadioError> {
        self.record(CaptureDirection::HostToNcp, frame)?;
        self.inner.send_frame(frame).await
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, umsh::companion_radio::CompanionRadioError>> {
        match self.inner.poll_recv_frame(cx) {
            core::task::Poll::Ready(Ok(frame)) => {
                match self.record(CaptureDirection::NcpToHost, &frame) {
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
        use umsh::companion_radio::SerialFrameLink;

        println!("attaching to {first} ...");
        let stream = tokio_serial::new(&first, 115_200).open_native_async()?;
        let link = CapturingFrameLink::new(SerialFrameLink::new(stream), capture.clone());
        let radio = CompanionRadio::new(link, config).await?;
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
    config: CompanionRadioConfig,
    rf: RfArgs,
    capture: Option<SharedCapture>,
) -> Result<(), Box<dyn std::error::Error>> {
    use umsh::companion_radio::{BleFrameLink, BleFrameLinkConfig};

    let mut stats = DumpStats::new();
    loop {
        println!("discovering BLE companion radio ...");
        let failure: Box<dyn std::error::Error> =
            match BleFrameLink::connect(selector, BleFrameLinkConfig::default()).await {
                Ok(link) => match CompanionRadio::new(
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
    mut radio: CompanionRadio<L>,
    rf: &RfArgs,
    stats: &mut DumpStats,
    capture: Option<&SharedCapture>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "session #{}: ncp={} boot_status={:?}",
        stats.sessions,
        radio.ncp_version(),
        radio.boot_status(),
    );
    println!(
        "radio: {} kHz, BW {} Hz, SF{}, CR 4/{}, sync 0x{:04x}",
        rf.freq_khz, rf.bandwidth_hz, rf.spreading_factor, rf.coding_rate_denom, rf.sync_word,
    );
    // A capture is a promiscuous listener. An NCP with a provisioned
    // (or saved-and-restored) host domain filters receptions, so the
    // factory deliver-everything rule cannot be relied on; bypass the
    // filtering for this session (`PROP_MAC_PROMISCUOUS` is
    // session-scoped and reverts on detach). An NCP that predates the
    // property refuses the set — capture then sees only frames
    // matching its receive filtering.
    match radio
        .set_prop(umsh::companion::ids::prop::MAC_PROMISCUOUS, &[1])
        .await
    {
        Ok(_) => println!("promiscuous mode enabled"),
        Err(umsh::companion_radio::CompanionRadioError::Status(status)) => eprintln!(
            "warning: NCP refused promiscuous mode ({status:?}); \
             capture is limited to the NCP's receive filtering"
        ),
        Err(error) => return Err(error.into()),
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
                    .get_prop(umsh::companion::ids::prop::PHY_RSSI)
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
        println!(
            "\n#{} +{:.3}s  session={}  len={}  RSSI={} dBm  SNR={}  LQI={}",
            stats.sequence,
            stats.started.elapsed().as_secs_f64(),
            stats.sessions,
            info.len,
            info.rssi,
            info.snr,
            info.lqi
                .map_or_else(|| "n/a".into(), |lqi| lqi.get().to_string()),
        );
        print!("raw:");
        for byte in packet {
            print!(" {byte:02x}");
        }
        println!();
        print_classification(packet);
    }
}

fn should_display(packet: &[u8], umsh_only: bool) -> bool {
    !umsh_only || PacketHeader::parse(packet).is_ok()
}

fn print_classification(packet: &[u8]) {
    let header = match PacketHeader::parse(packet) {
        Ok(header) => header,
        Err(error) => {
            println!("decode: not a valid UMSH packet ({error:?})");
            return;
        }
    };
    let options = ParsedOptions::extract(packet, header.options_range.clone());
    let encrypted = header
        .sec_info
        .is_some_and(|security| security.scf.encrypted());
    let frame_counter = header.sec_info.map(|security| security.frame_counter);
    let payload_type = (!encrypted && header.packet_type() != PacketType::MacAck)
        .then(|| {
            packet
                .get(header.body_range.start)
                .and_then(|byte| PayloadType::from_byte(*byte))
        })
        .flatten();

    let src = match header.source {
        SourceAddrRef::Hint(hint) => format!("hint:{hint}"),
        SourceAddrRef::FullKeyAt { offset } => packet.get(offset..offset + 32).map_or_else(
            || "<truncated>".to_owned(),
            |bytes| {
                let mut key = [0u8; 32];
                key.copy_from_slice(bytes);
                PublicKey(key).to_string()
            },
        ),
        SourceAddrRef::Encrypted { .. } => "<encrypted>".to_owned(),
        SourceAddrRef::None => "-".to_owned(),
    };
    let dst = header
        .dst
        .map_or_else(|| "-".to_owned(), |hint| hint.to_string());
    println!(
        "decode: UMSH {:?} src={} dst={} channel={:?}",
        header.packet_type(),
        src,
        dst,
        header.channel,
    );
    println!(
        "        encrypted={encrypted} frame_counter={frame_counter:?} ack_requested={} body={} mic={} payload={payload_type:?}",
        header.ack_requested(),
        header.body_range.len(),
        header.mic_range.len(),
    );
    match options {
        Ok(options) => println!("        options={options:?}"),
        Err(error) => println!("        options=<decode error: {error:?}>"),
    }
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
    fn ethernet_pcap_preserves_companion_direction_and_payload() {
        let path = temp_capture_path("companion");
        let mut writer =
            PcapWriter::create(&path, CaptureLayers::Companion, PcapEncapsulation::Ethernet)
                .unwrap();
        writer
            .write_companion(CaptureDirection::HostToNcp, &[0x81, 0x02, 0x26])
            .unwrap();
        drop(writer);

        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let packet = &bytes[40..];
        assert_eq!(&packet[12..14], &0x0800u16.to_be_bytes());
        assert_eq!(packet[23], 17);
        assert_eq!(
            u16::from_be_bytes(packet[34..36].try_into().unwrap()),
            COMPANION_HOST_UDP_PORT,
        );
        assert_eq!(
            u16::from_be_bytes(packet[36..38].try_into().unwrap()),
            COMPANION_NCP_UDP_PORT,
        );
        assert_eq!(&packet[42..], &[0x81, 0x02, 0x26]);
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
