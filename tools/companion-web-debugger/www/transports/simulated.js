/** A deterministic in-browser NCP backed by the production Rust Session. */
export class SimulatedLink {
  #ncp;
  #onBytes;

  constructor(SimulatedNcp) {
    this.#ncp = new SimulatedNcp();
  }

  async connect(onBytes) {
    this.#onBytes = onBytes;
    this.#ncp.attach();
    return "Browser simulated NCP";
  }

  async write(bytes) {
    this.#ncp.ingest(bytes, Math.round(performance.now()));
    this.#pump();
  }

  async close() {
    this.#ncp.detach();
    this.#onBytes = undefined;
  }

  injectRadioFrame(bytes) {
    this.#ncp.inject_radio_rx(bytes, Math.round(performance.now()));
    this.#pump();
  }

  injectDemoPacket() {
    this.#ncp.inject_demo_rx(Math.round(performance.now()));
    this.#pump();
  }

  #pump() {
    for (let bytes; (bytes = this.#ncp.take_outbound());) this.#onBytes?.(bytes);
  }
}
