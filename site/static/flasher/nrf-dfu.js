/**
 * Legacy Nordic serial DFU, as spoken by the Adafruit nRF52 bootloader.
 *
 * Adapted from `lib/dfu.js` in meshcore-dev/flasher.meshcore.io:
 *
 *   MIT License — Copyright (c) 2025 Rastislav Vysoky
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a
 *   copy of this software and associated documentation files (the "Software"),
 *   to deal in the Software without restriction, including without limitation
 *   the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *   and/or sell copies of the Software, and to permit persons to whom the
 *   Software is furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. See
 *   `vendor/meshcore-flasher/LICENSE` for the full text.
 *
 * That implementation is itself a port of `dfu/dfu_transport_serial.py` from
 * adafruit-nrfutil (BSD-3-Clause, Copyright (c) 2015 Nordic Semiconductor),
 * which is where the framing and the nRF52840 flash timings come from — see
 * `vendor/adafruit-nrfutil/LICENSE`. `make flash-<board>-serial` drives the
 * same protocol from the command line.
 *
 * Changes here: framing runs over the flasher's SerialLink rather than raw
 * port streams, SLIP frames are reassembled across chunk boundaries, the
 * sequence counter is per-transfer instead of global, packages are opened with
 * fflate, and failures are typed so the UI can explain them.
 */

import { unzipSync } from "./vendor/fflate/fflate.js";
import { SerialTimeoutError, sleep } from "./serial.js";

const FLASH_PAGE_SIZE = 4096;
const FLASH_PAGE_ERASE_TIME_MS = 89.7; // nRF52840 maximum
const FLASH_WORD_WRITE_TIME_MS = 0.1; // nRF52840 maximum
const FLASH_PAGE_WRITE_TIME_MS = (FLASH_PAGE_SIZE / 4) * FLASH_WORD_WRITE_TIME_MS;
const DFU_PACKET_MAX_SIZE = 512;
const PACKETS_PER_PAGE = 8;

const DATA_INTEGRITY_CHECK_PRESENT = 1;
const RELIABLE_PACKET = 1;
const HCI_PACKET_TYPE = 14;

const DFU_INIT_PACKET = 1;
const DFU_START_PACKET = 3;
const DFU_DATA_PACKET = 4;
const DFU_STOP_DATA_PACKET = 5;

const DFU_UPDATE_MODE_APP = 4;

const SLIP_END = 0xc0;
const SLIP_ESC = 0xdb;
const SLIP_ESC_END = 0xdc;
const SLIP_ESC_ESC = 0xdd;

/** The bootloader did not answer at all. */
export class DfuTimeoutError extends Error {
  constructor(message = "the bootloader did not respond") {
    super(message);
    this.name = "DfuTimeoutError";
  }
}

/** The bootloader answered, but rejected what we sent. */
export class DfuRejectedError extends Error {
  constructor(message) {
    super(message);
    this.name = "DfuRejectedError";
  }
}

/** The file is not an adafruit-nrfutil DFU package. */
export class DfuPackageError extends Error {
  constructor(message) {
    super(message);
    this.name = "DfuPackageError";
  }
}

function int32le(value) {
  return [value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff];
}

function crc16(data, seed = 0xffff) {
  let crc = seed;
  for (const byte of data) {
    crc = ((crc >> 8) & 0x00ff) | ((crc << 8) & 0xff00);
    crc ^= byte;
    crc ^= (crc & 0x00ff) >> 4;
    crc ^= (crc << 8) << 4;
    crc ^= ((crc & 0x00ff) << 4) << 1;
  }
  return crc & 0xffff;
}

function slipEscape(data) {
  const out = [];
  for (const byte of data) {
    if (byte === SLIP_END) out.push(SLIP_ESC, SLIP_ESC_END);
    else if (byte === SLIP_ESC) out.push(SLIP_ESC, SLIP_ESC_ESC);
    else out.push(byte);
  }
  return out;
}

function slipUnescape(data) {
  const out = [];
  for (let i = 0; i < data.length; i++) {
    if (data[i] !== SLIP_ESC) {
      out.push(data[i]);
      continue;
    }
    i += 1;
    if (i >= data.length) throw new DfuRejectedError("truncated SLIP escape in the reply");
    if (data[i] === SLIP_ESC_END) out.push(SLIP_END);
    else if (data[i] === SLIP_ESC_ESC) out.push(SLIP_ESC);
    else throw new DfuRejectedError("invalid SLIP escape in the reply");
  }
  return out;
}

/** Wrap a DFU payload in the reliable-HCI framing the bootloader expects. */
function hciFrame(payload, sequenceNumber) {
  const header = new Uint8Array(4);
  header[0] =
    sequenceNumber |
    (((sequenceNumber + 1) % 8) << 3) |
    (DATA_INTEGRITY_CHECK_PRESENT << 6) |
    (RELIABLE_PACKET << 7);
  header[1] = HCI_PACKET_TYPE | ((payload.length & 0x000f) << 4);
  header[2] = (payload.length & 0x0ff0) >> 4;
  header[3] = (~(header[0] + header[1] + header[2]) + 1) & 0xff;

  const body = [...header, ...payload];
  const sum = crc16(new Uint8Array(body));
  body.push(sum & 0xff, (sum & 0xff00) >> 8);

  return new Uint8Array([SLIP_END, ...slipEscape(body), SLIP_END]);
}

/**
 * Open an adafruit-nrfutil DFU package.
 *
 * The archive is flat: `firmware-<board>.bin`, `firmware-<board>.dat`, and a
 * `manifest.json` naming both plus the SoftDevice requirement. `make
 * dfu-zip-<board>` produces exactly this.
 */
export function parseDfuPackage(bytes) {
  let files;
  try {
    files = unzipSync(new Uint8Array(bytes));
  } catch {
    throw new DfuPackageError("that file is not a zip archive.");
  }

  const manifestBytes = files["manifest.json"];
  if (!manifestBytes) {
    throw new DfuPackageError(
      "that zip has no manifest.json, so it is not a DFU package. Pick a file named umsh-<board>-<version>-dfu.zip.",
    );
  }

  let application;
  try {
    application = JSON.parse(new TextDecoder().decode(manifestBytes)).manifest.application;
  } catch {
    throw new DfuPackageError("the DFU package's manifest.json is unreadable.");
  }

  const bin = files[application?.bin_file];
  const dat = files[application?.dat_file];
  if (!bin || !dat) {
    throw new DfuPackageError("the DFU package is missing its firmware or init-packet file.");
  }

  return {
    bin,
    dat,
    binName: application.bin_file,
    softDeviceReq: application.init_packet_data?.softdevice_req ?? [],
  };
}

export class NrfDfu {
  #link;
  #onProgress;
  #onStage;
  #log;
  #sequenceNumber = 0;
  #lastAck = -1;

  /** @param link an open SerialLink at 115200 baud. */
  constructor(link, { onProgress = () => {}, onStage = () => {}, log = () => {} } = {}) {
    this.#link = link;
    this.#onProgress = onProgress;
    this.#onStage = onStage;
    this.#log = log;
  }

  /** Write `bin` to the application region, gated by the `dat` init packet. */
  async flash({ bin, dat }) {
    this.#sequenceNumber = 0;
    this.#lastAck = -1;
    this.#link.flushInput();

    const eraseMs = Math.max(500, (bin.length / FLASH_PAGE_SIZE + 1) * FLASH_PAGE_ERASE_TIME_MS);
    this.#onStage("erasing");
    this.#log(`Starting DFU: ${bin.length} bytes, allowing ${Math.round(eraseMs / 1000)}s to erase.`);
    await this.#send(
      [...int32le(DFU_START_PACKET), ...int32le(DFU_UPDATE_MODE_APP), ...int32le(0), ...int32le(0), ...int32le(bin.length)],
      "start",
    );
    await sleep(eraseMs);

    this.#onStage("verifying");
    this.#log("Sending the init packet.");
    await this.#send([...int32le(DFU_INIT_PACKET), ...dat, 0x00, 0x00], "init");

    this.#onStage("writing");
    await sleep(FLASH_PAGE_WRITE_TIME_MS);

    let sent = 0;
    let packetIndex = 0;
    for (let offset = 0; offset < bin.length; offset += DFU_PACKET_MAX_SIZE) {
      const chunk = bin.subarray(offset, offset + DFU_PACKET_MAX_SIZE);
      // Bench-observed rejection signature (T-Echo, 2026-08-09): a package
      // whose SoftDevice requirement does not match is acknowledged through
      // the init packet, and then the bootloader simply stops answering.
      await this.#send([...int32le(DFU_DATA_PACKET), ...chunk], offset === 0 ? "first-data" : "data");
      sent += chunk.length;
      this.#onProgress(sent, bin.length);

      packetIndex += 1;
      if (packetIndex % PACKETS_PER_PAGE === 0) await sleep(FLASH_PAGE_WRITE_TIME_MS);
    }

    await sleep(FLASH_PAGE_WRITE_TIME_MS);
    this.#onStage("finishing");
    this.#log("Sending the stop packet.");
    await this.#send(int32le(DFU_STOP_DATA_PACKET), "stop");
    this.#log("DFU complete.");
  }

  async #send(payload, what) {
    this.#sequenceNumber = (this.#sequenceNumber + 1) % 8;
    await this.#link.write(hciFrame(new Uint8Array(payload), this.#sequenceNumber));
    await this.#awaitAck(what);
  }

  async #awaitAck(what) {
    // The reply is one SLIP frame. Reassemble across chunk boundaries, and
    // discard anything before the opening delimiter — a bootloader that has
    // just been reset can have stray bytes in flight.
    const buffer = [];
    let start = -1;
    const deadline = what === "start" ? 20000 : 5000;

    while (true) {
      let chunk;
      try {
        chunk = await this.#link.read(deadline);
      } catch (error) {
        if (error instanceof SerialTimeoutError) {
          if (what === "start") {
            throw new DfuTimeoutError(
              "the radio did not answer. It may not be in update mode, or a different device was picked.",
            );
          }
          if (what === "first-data") {
            throw new DfuRejectedError(
              "the radio refused this firmware — it looks like it was built for a different board. Nothing was written.",
            );
          }
          throw new DfuTimeoutError(`the radio stopped answering partway through (${what} packet).`);
        }
        throw error;
      }

      for (const byte of chunk) {
        if (byte === SLIP_END && start === -1) {
          start = buffer.length;
          continue;
        }
        if (byte === SLIP_END && start !== -1) {
          return this.#decodeAck(buffer.slice(start), what);
        }
        if (start !== -1) buffer.push(byte);
      }
    }
  }

  #decodeAck(frame, what) {
    const decoded = slipUnescape(frame);
    if (decoded.length < 2) throw new DfuRejectedError("the radio sent a garbled reply.");

    const ack = (decoded[0] >> 3) & 0x07;
    const expected = (this.#lastAck + 1) % 8;
    if (this.#lastAck !== -1 && ack !== expected) {
      // The bootloader answers a package it will not accept by breaking the
      // acknowledgement sequence rather than by reporting an error code.
      throw new DfuRejectedError(
        what === "init"
          ? "the radio refused this firmware — it looks like it was built for a different board. Nothing was written."
          : `the radio rejected the ${what} packet.`,
      );
    }
    this.#lastAck = ack;
    return ack;
  }
}
