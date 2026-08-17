//! Classic-pcap sink for captured frames.
//!
//! Radio frames and ULCP control frames land in one file using the
//! repository's established synthetic Ethernet/IPv4/UDP encapsulation,
//! so stock Wireshark opens a capture containing both layers. Raw LoRa
//! bytes are also available, at the cost of a link type the user has to
//! name.
//!
//! LoRaTap carries the radio frame under a header describing the
//! channel it arrived on, so the RSSI and SNR the receiver reported
//! survive into the capture instead of being dropped on the floor. It
//! is the encapsulation the Wireshark extcap interface uses, because it
//! invents none of the addressing the Ethernet form has to.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use umsh::hal::RxInfo;

/// Which layers a pcap file records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum CaptureLayers {
    /// Frames the radio heard over the air.
    #[default]
    Radio,
    /// Control traffic between this host and the device.
    #[value(alias = "companion")]
    Ulcp,
    Both,
}

impl CaptureLayers {
    pub fn radio(self) -> bool {
        matches!(self, Self::Radio | Self::Both)
    }

    pub fn ulcp(self) -> bool {
        matches!(self, Self::Ulcp | Self::Both)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcapDirection {
    HostToDevice,
    DeviceToHost,
}

const PCAP_LINKTYPE_ETHERNET: u32 = 1;
const PCAP_LINKTYPE_LORATAP: u32 = 270;
const RADIO_UDP_PORT: u16 = 4242;
const ULCP_HOST_UDP_PORT: u16 = 4243;
const ULCP_DEVICE_UDP_PORT: u16 = 4244;

/// Fixed part of a LoRaTap v0 header, in bytes.
const LORATAP_V0_LEN: u16 = 15;

/// LoRaTap reports signal strength as an unsigned byte biased by this
/// much, so -139 dBm is zero.
const LORATAP_RSSI_BIAS: i32 = 139;

#[derive(Clone, Copy, Debug)]
pub enum PcapEncapsulation {
    Ethernet,
    RawLoRa { linktype: u32 },
    LoRaTap,
}

/// The channel a capture is listening on, read back from the device.
///
/// LoRaTap describes every frame in terms of the channel it arrived on,
/// so these travel with each record even though the radio holds them
/// still for the whole capture.
#[derive(Clone, Copy, Debug, Default)]
pub struct RfParams {
    pub freq_hz: u32,
    pub bw_hz: u32,
    pub sf: u8,
    pub sync_word: u8,
}

pub struct PcapWriter {
    output: BufWriter<Box<dyn Write>>,
    layers: CaptureLayers,
    encapsulation: PcapEncapsulation,
    packet_id: u16,
}

impl PcapWriter {
    pub fn create(
        path: &Path,
        layers: CaptureLayers,
        encapsulation: PcapEncapsulation,
    ) -> std::io::Result<Self> {
        Self::to_writer(Box::new(File::create(path)?), layers, encapsulation)
    }

    /// Write the capture into an arbitrary sink.
    ///
    /// The extcap interface hands us the FIFO Wireshark is reading, which
    /// is opened for writing rather than created.
    pub fn to_writer(
        sink: Box<dyn Write>,
        layers: CaptureLayers,
        encapsulation: PcapEncapsulation,
    ) -> std::io::Result<Self> {
        let mut output = BufWriter::new(sink);
        output.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
        output.write_all(&2u16.to_le_bytes())?;
        output.write_all(&4u16.to_le_bytes())?;
        output.write_all(&0i32.to_le_bytes())?;
        output.write_all(&0u32.to_le_bytes())?;
        output.write_all(&65_535u32.to_le_bytes())?;
        let linktype = match encapsulation {
            PcapEncapsulation::Ethernet => PCAP_LINKTYPE_ETHERNET,
            PcapEncapsulation::RawLoRa { linktype } => linktype,
            PcapEncapsulation::LoRaTap => PCAP_LINKTYPE_LORATAP,
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

    pub fn write_radio(&mut self, frame: &[u8]) -> std::io::Result<()> {
        if self.layers.radio() {
            match self.encapsulation {
                PcapEncapsulation::Ethernet => self.write_udp(
                    PcapDirection::DeviceToHost,
                    RADIO_UDP_PORT,
                    RADIO_UDP_PORT,
                    frame,
                )?,
                PcapEncapsulation::RawLoRa { .. } => self.write_record(frame)?,
                // Without reception metadata the header would be all
                // zeroes, which reads as a real -139 dBm measurement.
                PcapEncapsulation::LoRaTap => {
                    return Err(std::io::Error::other(
                        "LoRaTap capture requires per-frame reception metadata",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Record a radio frame along with how the receiver heard it.
    ///
    /// Only LoRaTap has somewhere to put the metadata; the other
    /// encapsulations quietly ignore it and record the frame alone.
    pub fn write_radio_with_info(
        &mut self,
        rf: &RfParams,
        info: &RxInfo,
        frame: &[u8],
    ) -> std::io::Result<()> {
        if !self.layers.radio() {
            return Ok(());
        }
        if !matches!(self.encapsulation, PcapEncapsulation::LoRaTap) {
            return self.write_radio(frame);
        }

        let mut packet = Vec::with_capacity(usize::from(LORATAP_V0_LEN) + frame.len());
        packet.push(0); // version
        packet.push(0); // padding
        packet.extend_from_slice(&LORATAP_V0_LEN.to_be_bytes());
        packet.extend_from_slice(&rf.freq_hz.to_be_bytes());
        packet.push(loratap_bandwidth(rf.bw_hz));
        packet.push(rf.sf);
        // A frame the device transmitted itself was never received, and
        // LoRaTap v0 has no way to say so — its signal bytes are always
        // readings. The rails (-139 dBm, -32 dB) are at least values no
        // real link here produces, where the collapsed 0 dBm would chart
        // as the strongest signal in the capture.
        let (rssi, snr) = if info.origin.is_measured() {
            (
                loratap_rssi(i32::from(info.rssi)),
                loratap_snr(info.snr.as_centibels()),
            )
        } else {
            (0, loratap_snr(i16::MIN))
        };
        packet.push(rssi); // packet RSSI
        packet.push(rssi); // max RSSI
        packet.push(rssi); // current RSSI
        packet.push(snr);
        packet.push(rf.sync_word);
        packet.extend_from_slice(frame);

        self.write_record(&packet)
    }

    pub fn write_ulcp(&mut self, direction: PcapDirection, frame: &[u8]) -> std::io::Result<()> {
        if !self.layers.ulcp() {
            return Ok(());
        }
        debug_assert!(matches!(self.encapsulation, PcapEncapsulation::Ethernet));
        let (src_port, dst_port) = match direction {
            PcapDirection::HostToDevice => (ULCP_HOST_UDP_PORT, ULCP_DEVICE_UDP_PORT),
            PcapDirection::DeviceToHost => (ULCP_DEVICE_UDP_PORT, ULCP_HOST_UDP_PORT),
        };
        self.write_udp(direction, src_port, dst_port, frame)
    }

    fn write_udp(
        &mut self,
        direction: PcapDirection,
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
            PcapDirection::HostToDevice => ([127, 0, 0, 1], [127, 0, 0, 2]),
            PcapDirection::DeviceToHost => ([127, 0, 0, 2], [127, 0, 0, 1]),
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
        self.output.write_all(packet)?;
        // Keep the file usable by Wireshark during a long-running capture.
        self.output.flush()
    }
}

/// Map a bandwidth to LoRaTap's enumerated byte.
///
/// The field is an enumeration of the three classic LoRa bandwidths
/// rather than a scale factor, so it cannot express the 62.5 kHz UMSH
/// normally runs at. Anything it cannot name is reported as zero, which
/// Wireshark renders as "Unknown" — a narrower bandwidth silently
/// labeled as one of the three would misdescribe the radio.
fn loratap_bandwidth(bw_hz: u32) -> u8 {
    match bw_hz {
        125_000 => 1,
        250_000 => 2,
        500_000 => 4,
        _ => 0,
    }
}

/// Bias a dBm reading into LoRaTap's unsigned byte, saturating rather
/// than wrapping so an implausible reading stays at the rail.
fn loratap_rssi(dbm: i32) -> u8 {
    (dbm + LORATAP_RSSI_BIAS).clamp(0, u8::MAX as i32) as u8
}

/// Convert centibels to LoRaTap's signed quarter-dB byte, rounding to
/// nearest.
fn loratap_snr(centibels: i16) -> u8 {
    let scaled = i32::from(centibels) * 4;
    let quarters = if scaled >= 0 {
        (scaled + 5) / 10
    } else {
        (scaled - 5) / 10
    };
    quarters.clamp(i8::MIN as i32, i8::MAX as i32) as i8 as u8
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_capture_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "umshctl-capture-{label}-{}-{nonce}.pcap",
            std::process::id(),
        ))
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
            PcapWriter::create(&path, CaptureLayers::Ulcp, PcapEncapsulation::Ethernet).unwrap();
        writer
            .write_ulcp(PcapDirection::HostToDevice, &[0x81, 0x02, 0x26])
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

    /// A sink the test can read back after the writer has been dropped.
    #[derive(Clone, Default)]
    struct SharedSink(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn sample_rf() -> RfParams {
        RfParams {
            freq_hz: 910_525_000,
            bw_hz: 125_000,
            sf: 7,
            sync_word: 0x2b,
        }
    }

    fn sample_info(len: usize, rssi: i16, snr_centibels: i16) -> RxInfo {
        RxInfo {
            len,
            rssi,
            snr: umsh::hal::Snr::from_centibels(snr_centibels),
            lqi: None,
            origin: umsh::hal::RxOrigin::Air,
        }
    }

    /// The scalings here are the ones Wireshark's LoRaTap dissector
    /// actually applies: RSSI is biased by 139 and SNR is in quarter-dB
    /// steps, both verified against `tshark -V` output.
    #[test]
    fn loratap_records_channel_and_reception_metadata() {
        let sink = SharedSink::default();
        let bytes = sink.0.clone();
        let mut writer = PcapWriter::to_writer(
            Box::new(sink),
            CaptureLayers::Radio,
            PcapEncapsulation::LoRaTap,
        )
        .unwrap();
        let frame = [0xc0, 0xa1, 0xb2, 0x03, 0x11, 0x22];
        writer
            .write_radio_with_info(&sample_rf(), &sample_info(frame.len(), -52, 95), &frame)
            .unwrap();
        drop(writer);

        let bytes = bytes.borrow();
        assert_eq!(
            u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            PCAP_LINKTYPE_LORATAP,
        );
        let packet = &bytes[40..];
        assert_eq!(packet.len(), 15 + frame.len());
        assert_eq!(packet[0], 0, "version");
        assert_eq!(u16::from_be_bytes(packet[2..4].try_into().unwrap()), 15);
        assert_eq!(
            u32::from_be_bytes(packet[4..8].try_into().unwrap()),
            910_525_000,
        );
        assert_eq!(packet[8], 1, "125 kHz in 125 kHz steps");
        assert_eq!(packet[9], 7, "spreading factor");
        assert_eq!(packet[10], 87, "-52 dBm biased by 139");
        assert_eq!(packet[13], 38, "9.5 dB in quarter-dB steps");
        assert_eq!(packet[14], 0x2b, "sync word");
        assert_eq!(&packet[15..], &frame);
    }

    /// A self-transmitted frame carries no reading, and its collapsed
    /// 0 dBm placeholder must not chart as the strongest signal in the
    /// capture; the rails are the honest choice v0 leaves open.
    #[test]
    fn loratap_records_self_tx_at_the_rails() {
        let sink = SharedSink::default();
        let bytes = sink.0.clone();
        let mut writer = PcapWriter::to_writer(
            Box::new(sink),
            CaptureLayers::Radio,
            PcapEncapsulation::LoRaTap,
        )
        .unwrap();
        let frame = [0xc0, 0xa1];
        let mut info = sample_info(frame.len(), 0, 0);
        info.origin = umsh::hal::RxOrigin::Backhaul;
        writer
            .write_radio_with_info(&sample_rf(), &info, &frame)
            .unwrap();
        drop(writer);

        let bytes = bytes.borrow();
        let packet = &bytes[40..];
        assert_eq!(packet[10], 0, "RSSI at the -139 dBm floor");
        assert_eq!(packet[13] as i8, i8::MIN, "SNR at the -32 dB rail");
    }

    /// Wireshark reads this field as an enumeration, so a bandwidth it
    /// has no name for must not borrow the nearest one.
    #[test]
    fn loratap_bandwidth_is_an_enumeration_not_a_scale() {
        assert_eq!(loratap_bandwidth(125_000), 1);
        assert_eq!(loratap_bandwidth(250_000), 2);
        assert_eq!(loratap_bandwidth(500_000), 4);
        assert_eq!(loratap_bandwidth(62_500), 0, "UMSH's default is unnameable");
        assert_eq!(loratap_bandwidth(200_000), 0, "not rounded down to 125 kHz");
    }

    #[test]
    fn loratap_encodes_negative_snr_as_a_signed_byte() {
        assert_eq!(loratap_snr(-75) as i8, -30, "-7.5 dB");
        assert_eq!(loratap_snr(0), 0);
        assert_eq!(loratap_rssi(-52), 87);
        assert_eq!(loratap_rssi(-200), 0, "saturates rather than wrapping");
    }

    /// The metadata-free entry point cannot fabricate a LoRaTap header,
    /// so it must refuse rather than emit a plausible-looking -139 dBm.
    #[test]
    fn loratap_rejects_frames_without_metadata() {
        let mut writer = PcapWriter::to_writer(
            Box::new(SharedSink::default()),
            CaptureLayers::Radio,
            PcapEncapsulation::LoRaTap,
        )
        .unwrap();
        assert!(writer.write_radio(&[0xc0, 0xa1]).is_err());
    }

    #[test]
    fn a_radio_only_file_ignores_ulcp_frames() {
        let path = temp_capture_path("radio-only");
        let mut writer =
            PcapWriter::create(&path, CaptureLayers::Radio, PcapEncapsulation::Ethernet).unwrap();
        writer
            .write_ulcp(PcapDirection::HostToDevice, &[0x81, 0x02, 0x26])
            .unwrap();
        drop(writer);

        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(bytes.len(), 24, "header only, no records");
    }
}
