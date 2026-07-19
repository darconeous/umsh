/** A Web Serial byte-stream link. Protocol framing belongs to the engine. */
export class SerialLink {
  #port;
  #reader;
  #writer;
  #reading = false;

  async connect(onBytes, onDisconnect) {
    this.#port = await navigator.serial.requestPort();
    await this.#port.open({ baudRate: 115200, dataBits: 8, stopBits: 1, parity: "none" });
    this.#writer = this.#port.writable.getWriter();
    this.#reading = true;
    this.#readLoop(onBytes, onDisconnect);
    return this.#port.getInfo().usbProductId
      ? `USB ${hex16(this.#port.getInfo().usbVendorId)}:${hex16(this.#port.getInfo().usbProductId)}`
      : "Serial device";
  }

  async write(bytes) {
    if (!this.#writer) throw new Error("serial port is not connected");
    await this.#writer.write(bytes);
  }

  async close() {
    this.#reading = false;
    await this.#reader?.cancel().catch(() => {});
    this.#reader?.releaseLock();
    this.#reader = undefined;
    this.#writer?.releaseLock();
    this.#writer = undefined;
    await this.#port?.close().catch(() => {});
    this.#port = undefined;
  }

  async #readLoop(onBytes, onDisconnect) {
    try {
      while (this.#reading && this.#port?.readable) {
        this.#reader = this.#port.readable.getReader();
        try {
          while (this.#reading) {
            const { value, done } = await this.#reader.read();
            if (done) break;
            if (value?.length) onBytes(value);
          }
        } finally {
          this.#reader.releaseLock();
          this.#reader = undefined;
        }
      }
    } catch (error) {
      if (this.#reading) onDisconnect(error instanceof Error ? error.message : String(error));
    }
  }
}

function hex16(value = 0) {
  return value.toString(16).padStart(4, "0");
}
