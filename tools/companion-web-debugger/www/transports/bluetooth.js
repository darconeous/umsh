const SERVICE = "21eb6b15-0001-4ccf-92e4-a079171bec97";
const FRAME_IN = "21eb6b15-0002-4ccf-92e4-a079171bec97";
const FRAME_OUT = "21eb6b15-0003-4ccf-92e4-a079171bec97";

/** A Web Bluetooth ATT-value link. SAR framing belongs to the engine. */
export class BluetoothLink {
  #device;
  #frameIn;
  #frameOut;
  #onValue;
  #onGattDisconnect;

  async connect(onBytes, onDisconnect) {
    this.#device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [SERVICE] }],
    });
    this.#onGattDisconnect = () => onDisconnect("Bluetooth device disconnected");
    this.#device.addEventListener("gattserverdisconnected", this.#onGattDisconnect);
    const server = await this.#device.gatt.connect();
    const service = await server.getPrimaryService(SERVICE);
    [this.#frameIn, this.#frameOut] = await Promise.all([
      service.getCharacteristic(FRAME_IN),
      service.getCharacteristic(FRAME_OUT),
    ]);
    this.#onValue = (event) => {
      const view = event.target.value;
      onBytes(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
    };
    this.#frameOut.addEventListener("characteristicvaluechanged", this.#onValue);
    await this.#frameOut.startNotifications();
    return this.#device.name || "Bluetooth companion radio";
  }

  async write(bytes) {
    if (!this.#frameIn) throw new Error("Bluetooth device is not connected");
    await this.#frameIn.writeValueWithResponse(bytes);
  }

  async close() {
    if (this.#frameOut && this.#onValue) {
      this.#frameOut.removeEventListener("characteristicvaluechanged", this.#onValue);
      await this.#frameOut.stopNotifications().catch(() => {});
    }
    if (this.#device && this.#onGattDisconnect) {
      this.#device.removeEventListener("gattserverdisconnected", this.#onGattDisconnect);
    }
    this.#device?.gatt?.disconnect();
    this.#frameIn = undefined;
    this.#frameOut = undefined;
    this.#device = undefined;
  }
}
