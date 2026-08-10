/**
 * ESP32-S3 flashing, over the ROM serial bootloader, via esptool-js.
 *
 * The release image is a single merged binary written at offset 0 — on the
 * ESP32-S3 the second-stage bootloader lives at 0x0, not at 0x1000 as on the
 * classic ESP32. `make merged-bin-heltec-v3` builds it with `--skip-padding`,
 * so it stops short of the `umsh` data partition at 0x300000 and a flash does
 * not wipe the device's stored identity. Everything below that mark is
 * rewritten, including the partition table.
 *
 * The CP2102 asserts DTR/RTS to drop the chip into its ROM bootloader, so
 * there is no button sequence, and the ROM is in mask ROM: this path cannot
 * brick the board.
 */

import { ESPLoader, Transport } from "./vendor/esptool-js/esptool.js";
import { sleep } from "./serial.js";

/** Offset of the merged image. See `scripts/release.py`'s `esp.offset`. */
export const MERGED_IMAGE_OFFSET = 0;

const FAST_BAUD = 921600;
const FALLBACK_BAUD = 115200;

export class EspFlashError extends Error {
  constructor(message) {
    super(message);
    this.name = "EspFlashError";
  }
}

function terminalShim(log) {
  return {
    clean() {},
    writeLine(data) {
      log(String(data));
    },
    write(data) {
      log(String(data));
    },
  };
}

/**
 * Write `image` to `port` and reset the board into it.
 *
 * Tries 921600 baud first and falls back to 115200, which some cables and USB
 * hubs need. `port` must not already be open — esptool-js opens it itself.
 */
export async function flashEsp(port, { image, onProgress = () => {}, onStage = () => {}, log = () => {} }) {
  let lastError;

  for (const baudrate of [FAST_BAUD, FALLBACK_BAUD]) {
    const transport = new Transport(port, false);
    try {
      onStage("connecting");
      log(`Connecting at ${baudrate} baud…`);
      const loader = new ESPLoader({ transport, baudrate, terminal: terminalShim(log) });
      const chip = await loader.main();
      log(`Found ${chip}.`);

      onStage("writing");
      await loader.writeFlash({
        fileArray: [{ data: image, address: MERGED_IMAGE_OFFSET }],
        flashMode: "keep",
        flashFreq: "keep",
        flashSize: "keep",
        eraseAll: false,
        compress: true,
        reportProgress: (_fileIndex, written, total) => onProgress(written, total),
      });

      onStage("finishing");
      // Not loader.after("hard_reset"): the vendored esptool-js 0.6.1 only
      // *releases* RTS there, assuming EN was still held low — which it is
      // not after flashing, so nothing happens and the board sits in the
      // flasher stub until someone pokes it. Pulse EN ourselves: DTR low
      // first so IO0 is high when EN rises, and the chip boots the new
      // firmware instead of re-entering the ROM downloader.
      await transport.setDTR(false);
      await transport.setRTS(true);
      await sleep(150);
      await transport.setRTS(false);
      log("Flash complete; the board has been reset.");
      return;
    } catch (error) {
      lastError = error;
      log(`Attempt at ${baudrate} baud failed: ${error?.message ?? error}`);
    } finally {
      await transport.disconnect().catch(() => {});
    }
  }

  throw new EspFlashError(
    `could not talk to the board (${lastError?.message ?? lastError}). Check that the USB cable carries data rather than power only, and that no serial monitor is holding the port.`,
  );
}
