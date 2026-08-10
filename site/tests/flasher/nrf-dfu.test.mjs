/**
 * Frame-level checks for the flasher's serial DFU implementation.
 *
 *     node --test site/tests/flasher/
 *
 * The golden frames come from an independent transcription of the framing
 * adafruit-nrfutil's `dfu_transport_serial.py` performs — the protocol `make
 * flash-<board>-serial` speaks — so a drift in the SLIP escaping, the CRC, the
 * sequence numbering, or the packet layout shows up here rather than on a
 * board. See `testdata/README.md` for how the fixtures are regenerated.
 *
 * These live outside `site/static/` because everything under that directory is
 * copied verbatim into the published site.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  NrfDfu,
  parseDfuPackage,
  DfuPackageError,
  DfuRejectedError,
  DfuTimeoutError,
} from "../../static/flasher/nrf-dfu.js";
import { SerialTimeoutError } from "../../static/flasher/serial.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(readFileSync(join(here, "testdata", "dfu-frames.json"), "utf8"));

const INIT_PACKET = Uint8Array.from({ length: 14 }, (_, i) => 0x10 + i);
const hex = (bytes) => Buffer.from(bytes).toString("hex");

/** The same 1 KiB pattern the fixtures were generated from: it contains both
 *  SLIP escape bytes, so the escaping is actually exercised. */
function firmwarePattern() {
  const bytes = new Uint8Array(1024);
  for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 7 + (i % 97 === 0 ? 0xc0 : 0)) & 0xff;
  bytes[10] = 0xc0;
  bytes[11] = 0xdb;
  bytes[600] = 0xc0;
  return bytes;
}

/** A SerialLink stand-in that records writes and acknowledges each one.
 *  `silentAfter` is how many acknowledgements to give before going quiet,
 *  the way a real bootloader refuses a package it will not take. */
class FakeLink {
  constructor({ ackFor = (n) => n % 8, replyChunks = null, silentAfter = Infinity } = {}) {
    this.written = [];
    this.ackFor = ackFor;
    this.replyChunks = replyChunks;
    this.silentAfter = silentAfter;
    this.acked = 0;
    this.pending = [];
  }

  flushInput() {}

  async write(bytes) {
    this.written.push(Uint8Array.from(bytes));
  }

  async read() {
    if (this.acked >= this.silentAfter) throw new SerialTimeoutError();
    if (this.pending.length) return this.pending.shift();

    this.acked += 1;
    const frame = Uint8Array.from([0xc0, (this.ackFor(this.acked) << 3) & 0xff, 0x00, 0xc0]);
    if (this.replyChunks) {
      this.pending = this.replyChunks(frame);
      return this.pending.shift();
    }
    return frame;
  }
}

test("frames match the adafruit-nrfutil reference byte for byte", async () => {
  const link = new FakeLink();
  await new NrfDfu(link).flash({ bin: firmwarePattern(), dat: INIT_PACKET });

  assert.equal(link.written.length, GOLDEN.frames.length, "frame count");
  for (const [index, frame] of link.written.entries()) {
    assert.equal(hex(frame), GOLDEN.frames[index], `frame ${index}`);
  }
});

test("a reply split across reads is still understood", async () => {
  // Web Serial hands over whatever arrived, so a frame can straddle two reads.
  const link = new FakeLink({
    replyChunks: (frame) => [frame.slice(0, 2), frame.slice(2)],
  });
  await new NrfDfu(link).flash({ bin: firmwarePattern(), dat: INIT_PACKET });
  assert.equal(link.written.length, GOLDEN.frames.length);
});

test("progress is reported per data packet and ends at the image size", async () => {
  const seen = [];
  const dfu = new NrfDfu(new FakeLink(), { onProgress: (done, total) => seen.push([done, total]) });
  await dfu.flash({ bin: firmwarePattern(), dat: INIT_PACKET });

  assert.deepEqual(seen, [
    [512, 1024],
    [1024, 1024],
  ]);
});

test("a broken acknowledgement after the init packet reads as a rejected package", async () => {
  // The bootloader turns down a package it will not take by dropping out of
  // the acknowledgement sequence rather than sending an error code.
  const link = new FakeLink({ ackFor: (n) => (n === 2 ? 5 : n % 8) });

  await assert.rejects(
    new NrfDfu(link).flash({ bin: firmwarePattern(), dat: INIT_PACKET }),
    (error) => error instanceof DfuRejectedError && /built for a different board/.test(error.message),
  );
});

test("silence from the port is reported as a timeout, not a hang", async () => {
  await assert.rejects(
    new NrfDfu(new FakeLink({ silentAfter: 0 })).flash({ bin: firmwarePattern(), dat: INIT_PACKET }),
    (error) => error instanceof DfuTimeoutError && /update mode/.test(error.message),
  );
});

test("silence right after the init packet reads as a refused package", async () => {
  // The rejection signature observed on a real T-Echo (2026-08-09): a package
  // with the wrong SoftDevice requirement is acknowledged through the init
  // packet, and the first data packet then goes unanswered.
  await assert.rejects(
    new NrfDfu(new FakeLink({ silentAfter: 2 })).flash({ bin: firmwarePattern(), dat: INIT_PACKET }),
    (error) => error instanceof DfuRejectedError && /refused this firmware/.test(error.message),
  );
});

test("a DFU package opens, and a file that is not one does not", () => {
  const pkg = parseDfuPackage(readFileSync(join(here, "testdata", "sample-dfu.zip")));
  assert.equal(pkg.binName, "firmware-t1000e.bin");
  assert.ok(pkg.bin.length > 1024, "firmware image is present");
  assert.equal(pkg.dat.length, 14, "init packet is the expected size");
  assert.deepEqual(pkg.softDeviceReq, [0x123], "S140 7.3.0");

  assert.throws(() => parseDfuPackage(Uint8Array.from([1, 2, 3, 4])), DfuPackageError);
});
