const RADIO_UDP_PORT = 4242;
const PCAP_LINKTYPE_ETHERNET = 1;

/** DOM-free capture state reusable by debugger, chat, and management pages. */
export class PacketCapture {
  constructor(limit = 5000) {
    this.limit = limit;
    this.packets = [];
    this.recording = true;
    this.seen = 0;
    this.dropped = 0;
    this.nextId = 1;
  }

  add(event, capturedAtMs = Date.now()) {
    this.seen += 1;
    if (!this.recording) return undefined;
    const packet = { ...event, capture_id: this.nextId++, captured_at_ms: capturedAtMs };
    this.packets.push(packet);
    if (this.packets.length > this.limit) {
      this.packets.splice(0, this.packets.length - this.limit);
      this.dropped += 1;
    }
    return packet;
  }

  clear() {
    this.packets.length = 0;
    this.seen = 0;
    this.dropped = 0;
    this.nextId = 1;
  }

  stats() {
    const decoded = this.packets.filter((packet) => packet.packet).length;
    return {
      captured: this.packets.length,
      decoded,
      decode_errors: this.packets.length - decoded,
      bytes: this.packets.reduce((total, packet) => total + packet.data_hex.length / 2, 0),
      dropped: this.dropped,
    };
  }
}

export function filterPackets(packets, query, kind = "all") {
  const needle = query.trim().toLowerCase();
  return packets.filter((packet) => {
    if (kind === "umsh" && !packet.packet) return false;
    if (kind === "errors" && packet.packet) return false;
    if (!needle) return true;
    return packetSearchText(packet).includes(needle);
  });
}

export function captureJson(packets) {
  return JSON.stringify({
    format: "umsh-radio-capture",
    version: 1,
    exported_at: new Date().toISOString(),
    packets,
  }, null, 2);
}

/** Classic PCAP using the same synthetic Ethernet/IPv4/UDP radio framing as umsh-capture. */
export function capturePcap(packets) {
  const writer = new ByteWriter();
  writer.u32le(0xa1b2c3d4);
  writer.u16le(2);
  writer.u16le(4);
  writer.u32le(0);
  writer.u32le(0);
  writer.u32le(65535);
  writer.u32le(PCAP_LINKTYPE_ETHERNET);

  let packetId = 0;
  for (const packet of packets) {
    const payload = hexBytes(packet.data_hex);
    const frame = radioUdpFrame(payload, packetId++);
    const timestamp = Math.max(0, packet.captured_at_ms || 0);
    writer.u32le(Math.floor(timestamp / 1000));
    writer.u32le(Math.floor(timestamp % 1000) * 1000);
    writer.u32le(frame.length);
    writer.u32le(frame.length);
    writer.bytes(frame);
  }
  return Uint8Array.from(writer.output);
}

function packetSearchText(packet) {
  return [
    packet.capture_id,
    packet.packet?.packet_type,
    packet.packet?.source,
    packet.packet?.destination,
    packet.packet?.channel_hex,
    packet.packet?.frame_counter,
    packet.packet?.payload_type,
    packet.packet_error,
    packet.metadata_error,
    packet.data_hex,
  ].filter((value) => value != null).join(" ").toLowerCase();
}

function hexBytes(hex) {
  return Uint8Array.from(hex.match(/../g) || [], (octet) => Number.parseInt(octet, 16));
}

function radioUdpFrame(payload, packetId) {
  const udpLength = 8 + payload.length;
  const ipLength = 20 + udpLength;
  const frame = new Uint8Array(14 + ipLength);
  frame.set([0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
  const ip = 14;
  frame.set([
    0x45, 0, ipLength >> 8, ipLength & 0xff,
    packetId >> 8, packetId & 0xff, 0, 0, 64, 17, 0, 0,
    127, 0, 0, 2, 127, 0, 0, 1,
  ], ip);
  const checksum = ipv4Checksum(frame.subarray(ip, ip + 20));
  frame[ip + 10] = checksum >> 8;
  frame[ip + 11] = checksum & 0xff;
  const udp = ip + 20;
  frame.set([
    RADIO_UDP_PORT >> 8, RADIO_UDP_PORT & 0xff,
    RADIO_UDP_PORT >> 8, RADIO_UDP_PORT & 0xff,
    udpLength >> 8, udpLength & 0xff, 0, 0,
  ], udp);
  frame.set(payload, udp + 8);
  return frame;
}

function ipv4Checksum(header) {
  let sum = 0;
  for (let index = 0; index < header.length; index += 2) {
    sum += (header[index] << 8) | header[index + 1];
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

class ByteWriter {
  constructor() { this.output = []; }
  u16le(value) { this.output.push(value & 0xff, (value >>> 8) & 0xff); }
  u32le(value) {
    this.output.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
  }
  bytes(value) { this.output.push(...value); }
}
