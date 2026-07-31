//! Classic-pcap sink for captured frames.
//!
//! Radio frames and ULCP control frames land in one file using the
//! repository's established synthetic Ethernet/IPv4/UDP encapsulation,
//! so stock Wireshark opens a capture containing both layers. Raw LoRa
//! bytes are also available, at the cost of a link type the user has to
//! name.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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
const RADIO_UDP_PORT: u16 = 4242;
const ULCP_HOST_UDP_PORT: u16 = 4243;
const ULCP_DEVICE_UDP_PORT: u16 = 4244;

#[derive(Clone, Copy, Debug)]
pub enum PcapEncapsulation {
    Ethernet,
    RawLoRa { linktype: u32 },
}

pub struct PcapWriter {
    output: BufWriter<File>,
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
            }
        }
        Ok(())
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
