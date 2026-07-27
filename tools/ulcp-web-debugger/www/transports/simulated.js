/** A deterministic in-browser device backed by the production Rust Session. */
export class SimulatedLink {
  #device;
  #onBytes;

  constructor(SimulatedDevice) {
    this.#device = new SimulatedDevice();
  }

  async connect(onBytes) {
    this.#onBytes = onBytes;
    this.#device.attach();
    return "Browser simulated device";
  }

  async write(bytes) {
    this.#device.ingest(bytes, Math.round(performance.now()));
    this.#pump();
  }

  async close() {
    this.#device.detach();
    this.#onBytes = undefined;
  }

  injectRadioFrame(bytes) {
    this.#device.inject_radio_rx(bytes, Math.round(performance.now()));
    this.#pump();
  }

  injectDemoPacket() {
    this.#device.inject_demo_rx(Math.round(performance.now()));
    this.#pump();
  }

  #pump() {
    for (let bytes; (bytes = this.#device.take_outbound());) this.#onBytes?.(bytes);
  }
}
