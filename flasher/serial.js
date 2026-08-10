/**
 * Web Serial byte-stream link for the firmware flasher.
 *
 * Adapted from `tools/ulcp-web-debugger/www/transports/serial.js` in this
 * repository — same nested read-loop structure — with three changes the
 * flasher needs: the baud rate is a parameter (1200 for the DFU touch, 115200
 * for serial DFU), the caller supplies an already-chosen port so the user
 * gesture stays in the UI layer, and reads are pull-based so the DFU packet
 * loop can await a reply with a timeout.
 */

/** No bytes arrived within the deadline. */
export class SerialTimeoutError extends Error {
  constructor(message = "the device stopped responding") {
    super(message);
    this.name = "SerialTimeoutError";
  }
}

/** The port went away while we were using it. */
export class SerialLostError extends Error {
  constructor(message = "the serial port disconnected") {
    super(message);
    this.name = "SerialLostError";
  }
}

export class SerialLink {
  #port;
  #reader;
  #writer;
  #reading = false;
  #chunks = [];
  #waiter = null;
  #failure = null;

  /** Open `port` and start pumping received bytes into the read queue. */
  async open(port, { baudRate = 115200 } = {}) {
    this.#port = port;
    this.#chunks = [];
    this.#failure = null;
    await port.open({ baudRate, dataBits: 8, stopBits: 1, parity: "none", bufferSize: 8192 });
    this.#writer = port.writable.getWriter();
    this.#reading = true;
    this.#readLoop();
  }

  get isOpen() {
    return this.#reading;
  }

  async write(bytes) {
    if (!this.#writer) throw new SerialLostError("the serial port is not open");
    await this.#writer.write(bytes);
  }

  async setSignals(signals) {
    await this.#port?.setSignals(signals);
  }

  /**
   * Resolve with the next chunk of received bytes.
   * Throws SerialTimeoutError if nothing arrives in `timeoutMs`, or
   * SerialLostError if the port failed or was closed underneath us.
   */
  read(timeoutMs = 5000) {
    if (this.#chunks.length) return Promise.resolve(this.#chunks.shift());
    if (this.#failure) return Promise.reject(this.#failure);
    if (!this.#reading) return Promise.reject(new SerialLostError());

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#waiter = null;
        reject(new SerialTimeoutError());
      }, timeoutMs);
      this.#waiter = {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      };
    });
  }

  /** Drop anything already received. Call before a request/reply exchange. */
  flushInput() {
    this.#chunks = [];
  }

  async close() {
    this.#reading = false;
    this.#waiter?.reject(new SerialLostError("the serial port was closed"));
    this.#waiter = null;
    await this.#reader?.cancel().catch(() => {});
    this.#reader = undefined;
    try {
      this.#writer?.releaseLock();
    } catch {
      /* already released by a failed stream */
    }
    this.#writer = undefined;
    await this.#port?.close().catch(() => {});
    this.#port = undefined;
  }

  async #readLoop() {
    try {
      while (this.#reading && this.#port?.readable) {
        this.#reader = this.#port.readable.getReader();
        try {
          while (this.#reading) {
            const { value, done } = await this.#reader.read();
            if (done) break;
            if (value?.length) this.#deliver(value);
          }
        } finally {
          try {
            this.#reader?.releaseLock();
          } catch {
            /* the stream errored; the lock is already gone */
          }
          this.#reader = undefined;
        }
      }
    } catch (error) {
      if (this.#reading) {
        this.#failure = new SerialLostError(
          error instanceof Error ? error.message : String(error),
        );
        this.#reading = false;
        this.#waiter?.reject(this.#failure);
        this.#waiter = null;
      }
    }
  }

  #deliver(value) {
    if (this.#waiter) {
      const waiter = this.#waiter;
      this.#waiter = null;
      waiter.resolve(value);
    } else {
      this.#chunks.push(value);
    }
  }
}

export function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/** A human-readable label for a port, for the connected-device line. */
export function describePort(port) {
  const info = port?.getInfo?.() ?? {};
  if (info.usbVendorId === undefined) return "Serial device";
  const hex = (value = 0) => value.toString(16).padStart(4, "0");
  return `USB ${hex(info.usbVendorId)}:${hex(info.usbProductId)}`;
}

/**
 * The 1200-baud touch: reboot a running UMSH radio into its bootloader.
 *
 * `TouchlessResetWatcher` in `crates/umsh-bsp-nrf52840/src/rescue.rs` triggers
 * on a DTR *falling* edge while the line coding is 1200 baud, and DTR must have
 * been asserted first — so opening and closing the port is not enough on its
 * own, and the signals are driven explicitly here.
 *
 * Resolving does not prove the device rebooted: firmware that does not
 * implement the touch (a board still running its vendor image) simply ignores
 * it. The caller confirms by looking for a new port.
 */
export async function touch1200(port, { holdMs = 150, settleMs = 1500 } = {}) {
  await port.open({ baudRate: 1200, dataBits: 8, stopBits: 1, parity: "none" });
  try {
    await port.setSignals({ dataTerminalReady: true, requestToSend: false });
    await sleep(holdMs);
    await port.setSignals({ dataTerminalReady: false });
    await sleep(50);
  } finally {
    // The device resets as soon as it sees the edge, so the close often races
    // the disconnect. Either outcome is success.
    await port.close().catch(() => {});
  }
  await sleep(settleMs);
}
