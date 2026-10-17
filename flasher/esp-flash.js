/**
 * ESP32-S3 flashing, over the ROM serial bootloader, via esptool-js.
 *
 * The release image is a single merged binary written at offset 0—on the
 * ESP32-S3 the second-stage bootloader lives at 0x0, not at 0x1000 as on the
 * classic ESP32. `make merged-bin-<board>` builds it with `--skip-padding`,
 * so it stops short of the `umsh` data partition at 0x300000 and a flash does
 * not wipe the device's stored identity. Everything below that mark is
 * rewritten, including the partition table.
 *
 * DTR/RTS drops the chip into its ROM bootloader, so there is no button
 * sequence—whether those lines arrive over a CP2102 bridge, as on the
 * Heltec V3, or over the S3's own USB-Serial-JTAG peripheral, as on the
 * T-Beam Supreme. Either way the ROM is mask ROM: this path cannot brick
 * the board.
 *
 * Arduino firmware on TinyUSB—the XIAO ESP32S3's factory image, for one—is
 * the exception: it answers those signals by restarting into the ROM, which
 * comes up as a different USB device. `flashEsp` reports that as
 * `EspPortChangedError`, and the page has the user pick the new port.
 */

import { ESPLoader, Transport } from "./vendor/esptool-js/esptool.js";
import { sleep } from "./serial.js";

/** Offset of the merged image. See `scripts/release.py`'s `esp.offset`. */
export const MERGED_IMAGE_OFFSET = 0;

const FAST_BAUD = 921600;
const FALLBACK_BAUD = 115200;

/** The ESP32-S3's `RTC_CNTL_OPTION1_REG` and its `FORCE_DOWNLOAD_BOOT` bit.
 *  esptool-js 0.6.1 defines neither for this chip. */
const S3_RTC_CNTL_OPTION1_REG = 0x6000812c;
const S3_FORCE_DOWNLOAD_BOOT = 0x1;

/** The ESP32-S3's USB-Serial-JTAG peripheral, which the ROM downloader on a
 *  native-USB board enumerates as—and so does UMSH firmware. */
const USB_SERIAL_JTAG = { usbVendorId: 0x303a, usbProductId: 0x1001 };

/** Port-picker filter for a board that has restarted into its ROM: every
 *  Espressif device, since the ROM can also come up as USB-OTG. */
export const ESPRESSIF_PORT_FILTERS = [{ usbVendorId: USB_SERIAL_JTAG.usbVendorId }];

export class EspFlashError extends Error {
  constructor(message) {
    super(message);
    this.name = "EspFlashError";
  }
}

/**
 * The port vanished while connecting. Usually the board restarted into its
 * ROM as a different USB device, which has to be picked again; a cable
 * pulled at that moment looks the same.
 */
export class EspPortChangedError extends EspFlashError {
  constructor() {
    super("the board disconnected. Plug it back in and click Flash radio again.");
    this.name = "EspPortChangedError";
  }
}

export function isUsbSerialJtag(port) {
  const info = port?.getInfo?.() ?? {};
  return info.usbVendorId === USB_SERIAL_JTAG.usbVendorId && info.usbProductId === USB_SERIAL_JTAG.usbProductId;
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
 * hubs need. `port` must not already be open—esptool-js opens it itself.
 * Throws `EspPortChangedError` if the port disappears while connecting.
 */
export async function flashEsp(port, { image, onProgress = () => {}, onStage = () => {}, log = () => {} }) {
  let lastError;

  for (const baudrate of [FAST_BAUD, FALLBACK_BAUD]) {
    const transport = new Transport(port, false);
    let connected = false;
    try {
      onStage("connecting");
      log(`Connecting at ${baudrate} baud…`);
      const loader = new ESPLoader({ transport, baudrate, terminal: terminalShim(log) });
      const chip = await loader.main();
      connected = true;
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
      await resetIntoFirmware(loader, transport, log);
      log("Flash complete; the board has been reset.");
      return;
    } catch (error) {
      lastError = error;
      log(`Attempt at ${baudrate} baud failed: ${error?.message ?? error}`);
    } finally {
      await transport.disconnect().catch(() => {});
    }

    // Retrying a port that is gone can only fail to open it.
    if (!connected && (await portGone(port))) throw new EspPortChangedError();
  }

  throw new EspFlashError(
    `could not talk to the board (${lastError?.message ?? lastError}). Check that the USB cable carries data rather than power only, and that no serial monitor is holding the port.`,
  );
}

/**
 * Leave the flasher stub and start the firmware just written.
 *
 * Not loader.after("hard_reset"): the vendored esptool-js 0.6.1 only
 * *releases* RTS there, assuming EN was still held low—which it is not after
 * flashing, so nothing happens and the board sits in the flasher stub until
 * someone pokes it. Pulse EN ourselves: DTR low first so IO0 is high when EN
 * rises, and the chip boots the new firmware instead of re-entering the ROM
 * downloader.
 *
 * On an ESP32-S3, clear `FORCE_DOWNLOAD_BOOT` first. Arduino firmware on
 * TinyUSB—the XIAO ESP32S3's factory image, for one—answers the connect
 * sequence by setting that bit and restarting into the ROM, and the bit
 * survives every reset short of a power cycle: left set, the EN pulse lands
 * back in the downloader. esptool's ESP32-S3 `hard_reset` clears it the same
 * way (arduino-esp32#6762), and likewise resets regardless if the write fails.
 */
export async function resetIntoFirmware(loader, transport, log = () => {}) {
  if (loader.chip?.CHIP_NAME === "ESP32-S3") {
    try {
      await loader.writeReg(S3_RTC_CNTL_OPTION1_REG, 0, S3_FORCE_DOWNLOAD_BOOT);
    } catch (error) {
      log(`Could not clear the forced-download flag: ${error?.message ?? error}`);
    }
  }

  await transport.setDTR(false);
  await transport.setRTS(true);
  await sleep(150);
  await transport.setRTS(false);
}

/** The browser stops listing a port once its device leaves USB; a device
 *  that comes back is a new port. */
async function portGone(port) {
  try {
    return !(await navigator.serial.getPorts()).includes(port);
  } catch {
    return false;
  }
}
