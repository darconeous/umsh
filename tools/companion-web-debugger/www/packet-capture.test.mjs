import assert from "node:assert/strict";
import test from "node:test";

import { PacketCapture, captureJson, capturePcap, filterPackets } from "./packet-capture.js";

const decodedPacket = {
  type: "stream_rx",
  timestamp_ms: 1250,
  stream: 0,
  data_hex: "c0a1b203",
  metadata: { rssi_dbm: -91 },
  packet: { packet_type: "Broadcast", source: "a1b203" },
  packet_error: null,
};

test("capture can pause without losing receive accounting", () => {
  const capture = new PacketCapture(2);
  capture.add(decodedPacket, 1_700_000_000_123);
  capture.recording = false;
  capture.add({ ...decodedPacket, data_hex: "00" });
  assert.deepEqual(capture.stats(), {
    captured: 1,
    decoded: 1,
    decode_errors: 0,
    bytes: 4,
    dropped: 0,
  });
  assert.equal(capture.seen, 2);
});

test("capture is bounded and filters parsed fields and errors", () => {
  const capture = new PacketCapture(2);
  capture.add(decodedPacket);
  capture.add({ ...decodedPacket, packet: null, packet_error: "InvalidVersion" });
  capture.add({ ...decodedPacket, packet: { packet_type: "Unicast", source: "alice" } });
  assert.equal(capture.packets.length, 2);
  assert.equal(capture.dropped, 1);
  assert.equal(filterPackets(capture.packets, "alice", "all").length, 1);
  assert.equal(filterPackets(capture.packets, "", "errors").length, 1);
  assert.equal(filterPackets(capture.packets, "", "umsh").length, 1);
});

test("PCAP matches the native radio Ethernet and UDP encapsulation", () => {
  const capture = new PacketCapture();
  capture.add(decodedPacket, 1_700_000_000_123);
  const pcap = capturePcap(capture.packets);
  assert.deepEqual([...pcap.slice(0, 4)], [0xd4, 0xc3, 0xb2, 0xa1]);
  assert.equal(new DataView(pcap.buffer).getUint32(20, true), 1);
  const frame = 24 + 16;
  assert.deepEqual([...pcap.slice(frame, frame + 6)], [2, 0, 0, 0, 0, 2]);
  assert.deepEqual([...pcap.slice(frame + 26, frame + 34)], [127, 0, 0, 2, 127, 0, 0, 1]);
  assert.deepEqual([...pcap.slice(frame + 34, frame + 38)], [0x10, 0x92, 0x10, 0x92]);
  assert.deepEqual([...pcap.slice(-4)], [0xc0, 0xa1, 0xb2, 0x03]);
});

test("JSON retains parsed and raw packet data", () => {
  const capture = new PacketCapture();
  capture.add(decodedPacket, 1_700_000_000_123);
  const exported = JSON.parse(captureJson(capture.packets));
  assert.equal(exported.format, "umsh-radio-capture");
  assert.equal(exported.packets[0].packet.packet_type, "Broadcast");
  assert.equal(exported.packets[0].data_hex, "c0a1b203");
});
