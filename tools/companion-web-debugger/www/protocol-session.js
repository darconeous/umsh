/**
 * Reusable bridge between the sans-IO wasm engine and any byte-oriented link.
 * It has no DOM or debugger-specific policy, so other browser clients can own
 * presentation while retaining the same connection lifecycle.
 */
export class ProtocolSession extends EventTarget {
  #engine;
  #link;
  #writeChain = Promise.resolve();
  #ticker;

  constructor(Engine, transport) {
    super();
    this.#engine = new Engine(transport);
  }

  async connect(link, transport) {
    await this.disconnect();
    this.#link = link;
    this.#engine.set_transport(transport);
    this.#engine.tick(Math.round(performance.now()));
    const name = await link.connect(
      (bytes) => this.#receive(bytes),
      (reason) => this.#disconnected(reason),
    );
    this.#ticker = setInterval(() => {
      this.#engine.tick(Math.round(performance.now()));
      this.#drainEvents();
    }, 250);
    this.dispatchEvent(new CustomEvent("state", { detail: { connected: true, name } }));
    this.#engine.attach();
    await this.#flush();
  }

  async disconnect() {
    clearInterval(this.#ticker);
    this.#ticker = undefined;
    const link = this.#link;
    this.#link = undefined;
    if (link) await link.close();
    this.dispatchEvent(new CustomEvent("state", { detail: { connected: false } }));
  }

  async property(operation, key, value = new Uint8Array()) {
    const method = `prop_${operation}`;
    if (operation === "get") this.#engine[method](key);
    else this.#engine[method](key, value);
    await this.#flush();
  }

  async setPropertyText(key, value) {
    this.#engine.prop_set_text(key, value);
    await this.#flush();
  }

  async refreshKnownProperties() {
    this.#engine.refresh_known_properties();
    await this.#flush();
  }

  async command(command) {
    this.#engine.command(command);
    await this.#flush();
  }

  async #receive(bytes) {
    this.#engine.tick(Math.round(performance.now()));
    this.#engine.ingest(bytes);
    this.#drainEvents();
    await this.#flush();
  }

  async #flush() {
    const writes = [];
    for (let bytes; (bytes = this.#engine.take_outbound());) writes.push(bytes);
    this.#drainEvents();
    if (!this.#link) return;
    this.#writeChain = this.#writeChain.then(async () => {
      for (const bytes of writes) await this.#link.write(bytes);
    });
    try {
      await this.#writeChain;
    } catch (error) {
      this.#writeChain = Promise.resolve();
      this.#disconnected(error instanceof Error ? error.message : String(error));
      throw error;
    }
  }

  #drainEvents() {
    for (let json; (json = this.#engine.take_event());) {
      this.dispatchEvent(new CustomEvent("engine-event", { detail: JSON.parse(json) }));
    }
  }

  #disconnected(reason) {
    clearInterval(this.#ticker);
    this.#ticker = undefined;
    this.#engine.disconnected(reason);
    this.#drainEvents();
    this.#link = undefined;
    this.dispatchEvent(new CustomEvent("state", { detail: { connected: false } }));
  }
}
