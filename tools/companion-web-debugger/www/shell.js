import { ProtocolSession } from "./protocol-session.js";
import { SerialLink } from "./transports/serial.js";
import { BluetoothLink } from "./transports/bluetooth.js";
import { SimulatedLink } from "./transports/simulated.js";
import { PacketCapture, captureJson, capturePcap, filterPackets } from "./packet-capture.js";

const elements = Object.fromEntries(
  [...document.querySelectorAll("[id]")].map((element) => [element.id, element]),
);
const trace = [];
const packetCapture = new PacketCapture();
let session;
let SimulatedNcp;
let requestedPropertyKey;
let activeSimulatedLink;
let propertySpecs = [];
let activeCapabilities = new Set();
let capabilitiesKnown = false;
let isConnected = false;
let commandBusy = false;
let selectedPacketId;
const propertyRowByKey = new Map();

start();

async function start() {
  showPlatformSupport();
  bindUi();
  try {
    const wasm = await import("./pkg/umsh_companion_web_engine.js");
    await wasm.default();
    SimulatedNcp = wasm.SimulatedNcp;
    propertySpecs = JSON.parse(wasm.propertySpecs());
    renderPropertyTable();
    session = new ProtocolSession(wasm.DebuggerEngine, "serial_hdlc");
    session.addEventListener("engine-event", ({ detail }) => handleEvent(detail));
    session.addEventListener("state", ({ detail }) => setConnectionState(detail));
    setStatus("Ready to connect", "ready");
  } catch (error) {
    setStatus("Engine not built", "error");
    elements.connectSerial.disabled = true;
    elements.connectBluetooth.disabled = true;
    elements.connectSimulator.disabled = true;
    elements.notice.textContent =
      "Build the WebAssembly engine with ‘make web-debugger’ before serving this directory.";
    elements.propertyRows.innerHTML = '<tr><td colspan="4" class="decode-warning">The WebAssembly engine did not load.</td></tr>';
    console.error(error);
  }
}

function bindUi() {
  elements.connectSerial.addEventListener("click", () => connect(new SerialLink(), "serial_hdlc"));
  elements.connectBluetooth.addEventListener("click", () => connect(new BluetoothLink(), "ble_sar"));
  elements.connectSimulator.addEventListener("click", () => connect(new SimulatedLink(SimulatedNcp), "serial_hdlc", false));
  elements.disconnect.addEventListener("click", async () => {
    await session?.disconnect();
    activeSimulatedLink = undefined;
    elements.injectDemo.disabled = true;
  });
  elements.clearTrace.addEventListener("click", () => {
    trace.length = 0;
    renderTrace();
  });
  elements.clearRx.addEventListener("click", () => {
    packetCapture.clear();
    selectedPacketId = undefined;
    renderCapture();
  });
  elements.captureToggle.addEventListener("click", toggleCapture);
  elements.captureFilter.addEventListener("input", renderCapture);
  elements.captureKind.addEventListener("change", renderCapture);
  elements.exportCaptureJson.addEventListener("click", exportCaptureJson);
  elements.exportCapturePcap.addEventListener("click", exportCapturePcap);
  elements.injectDemo.addEventListener("click", injectDemoPacket);
  elements.exportTrace.addEventListener("click", exportTrace);
  elements.traceFilter.addEventListener("input", renderTrace);
  elements.propertyFilter.addEventListener("input", filterProperties);
  elements.refreshProperties.addEventListener("click", () => session?.refreshKnownProperties());
  elements.propertyForm.addEventListener("submit", submitProperty);
  for (const button of document.querySelectorAll(".command-button")) button.addEventListener("click", issueCommand);
}

async function connect(link, transport, displacesHost = true) {
  if (!session) return;
  if (displacesHost && !confirm("Attaching resets the NCP protocol session and displaces any host already using this radio. Continue?")) return;
  setStatus("Opening device chooser…", "busy");
  activeSimulatedLink = link instanceof SimulatedLink ? link : undefined;
  elements.injectDemo.disabled = true;
  try {
    await session.connect(link, transport);
    elements.injectDemo.disabled = !activeSimulatedLink;
  } catch (error) {
    activeSimulatedLink = undefined;
    const message = error instanceof Error ? error.message : String(error);
    setStatus("Connection failed", "error");
    elements.notice.textContent = pairingHint(message);
  }
}

async function injectDemoPacket() {
  if (!activeSimulatedLink) return;
  try {
    await session.property("set", 32, Uint8Array.of(1));
    activeSimulatedLink.injectDemoPacket();
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), "error");
  }
}

function handleEvent(event) {
  switch (event.type) {
    case "trace":
      trace.push(event);
      renderTrace();
      break;
    case "attached":
      activeCapabilities = new Set(event.capabilities.map(({ code }) => code));
      capabilitiesKnown = true;
      updatePropertyAvailability();
      updateCommandAvailability();
      elements.protocolVersion.textContent = `${event.protocol_major}.${event.protocol_minor}`;
      elements.ncpVersion.textContent = event.ncp_version || "(empty)";
      elements.bootStatus.textContent = event.boot_status;
      elements.capabilities.textContent = event.capabilities.length
        ? event.capabilities.map(({ code, name }) => name ? `${name} (${code})` : String(code)).join(", ")
        : "None advertised";
      setStatus("Attached", "ready");
      break;
    case "property":
      updateKnownProperty(event);
      if (event.unsolicited || event.key === requestedPropertyKey || (requestedPropertyKey !== undefined && event.key === 0)) {
        renderPropertyResult(event);
        if (!event.unsolicited) requestedPropertyKey = undefined;
      }
      break;
    case "property_error":
      showPropertyError(event.key, event.status);
      if (event.key === requestedPropertyKey) {
        elements.propertyResult.textContent = `${event.name || `Property ${event.key}`}: ${event.status}`;
        requestedPropertyKey = undefined;
      }
      break;
    case "command_result":
      commandBusy = false;
      updateCommandAvailability();
      elements.commandResult.textContent = `${commandLabel(event.command)}: ${event.status.replace(/^Status::/, "")}`;
      elements.commandResult.classList.toggle("has-error", !event.success);
      break;
    case "stream_rx":
      {
        const captured = packetCapture.add(event);
        if (captured && selectedPacketId == null) selectedPacketId = captured.capture_id;
        renderCapture();
      }
      break;
    case "protocol_error":
      setStatus(event.message, "error");
      break;
    case "detached":
      setStatus(event.reason, "error");
      break;
  }
}

const commandConfirmations = {
  restore: "Discard unsaved live configuration changes and restore the saved snapshot?",
  reset: "Reset the NCP protocol state and reload its saved configuration? The active session will be resynchronized.",
  clear: "Erase the saved snapshot and all persisted protocol provisioning, including the device identity? Live RAM remains unchanged until reset.",
};

async function issueCommand(event) {
  const command = event.currentTarget.dataset.command;
  const warning = commandConfirmations[command];
  if (warning && !confirm(warning)) return;
  commandBusy = true;
  updateCommandAvailability();
  elements.commandResult.classList.remove("has-error");
  elements.commandResult.textContent = `${commandLabel(command)}…`;
  try {
    await session.command(command);
  } catch (error) {
    commandBusy = false;
    updateCommandAvailability();
    elements.commandResult.classList.add("has-error");
    elements.commandResult.textContent = error instanceof Error ? error.message : String(error);
  }
}

function commandLabel(command) {
  return ({
    queue_drain: "Drain queue",
    save: "Save state",
    restore: "Restore saved state",
    reset: "Reset NCP",
    clear: "Clear persisted state",
    nop: "No-op",
  })[command] || command;
}

function renderPropertyTable() {
  propertyRowByKey.clear();
  const rows = [];
  let previousGroup;
  for (const spec of propertySpecs) {
    if (spec.group !== previousGroup) {
      const group = document.createElement("tr");
      group.className = "property-group";
      group.dataset.group = spec.group;
      const heading = document.createElement("th");
      heading.colSpan = 4;
      heading.textContent = spec.group;
      group.append(heading);
      rows.push(group);
      previousGroup = spec.group;
    }
    const row = document.createElement("tr");
    row.className = "property-row";
    row.dataset.key = String(spec.key);
    row.dataset.group = spec.group;
    row.dataset.search = `${spec.name} ${spec.key} ${spec.description} ${spec.group}`.toLowerCase();

    const identity = document.createElement("th");
    identity.scope = "row";
    const name = document.createElement("code");
    name.textContent = spec.name.replace(/^PROP_/, "");
    const number = document.createElement("small");
    number.textContent = `Property ${spec.key}`;
    identity.append(name, number);

    const description = document.createElement("td");
    description.textContent = spec.description;
    const value = document.createElement("td");
    value.className = "property-value";
    value.textContent = spec.readable ? "Waiting for connection" : "Write-only";
    const change = document.createElement("td");
    change.className = "property-change";
    if (spec.readable) change.append(propertyFetchButton(spec));
    if (spec.writable) change.append(propertyEditor(spec));
    if (!spec.readable && !spec.writable) change.textContent = "—";

    row.append(identity, description, value, change);
    propertyRowByKey.set(spec.key, { row, spec, value, change });
    rows.push(row);
  }
  elements.propertyRows.replaceChildren(...rows);
  updatePropertyAvailability();
}

function propertyFetchButton(spec) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "secondary small property-fetch";
  button.dataset.key = String(spec.key);
  button.textContent = "Fetch";
  button.setAttribute("aria-label", `Fetch ${spec.name}`);
  button.addEventListener("click", fetchKnownProperty);
  return button;
}

async function fetchKnownProperty(event) {
  const key = Number(event.currentTarget.dataset.key);
  const entry = propertyRowByKey.get(key);
  try {
    entry.row.classList.remove("has-error");
    entry.row.classList.add("is-fetching");
    await session.property("get", key);
  } catch (error) {
    entry.row.classList.remove("is-fetching");
    showPropertyError(key, error instanceof Error ? error.message : String(error));
  }
}

function propertyEditor(spec) {
  const form = document.createElement("form");
  form.className = "property-editor";
  form.dataset.key = String(spec.key);
  let input;
  if (spec.choices.length) {
    input = document.createElement("select");
    for (const choice of spec.choices) input.append(new Option(choice.label, choice.value));
  } else if (spec.editor === "boolean") {
    input = document.createElement("select");
    input.append(new Option("False", "false"), new Option("True", "true"));
  } else {
    input = document.createElement("input");
    input.type = spec.editor === "integer" ? "number" : "text";
    if (spec.editor === "hex_integer") input.placeholder = "0x1424";
  }
  input.name = "value";
  input.setAttribute("aria-label", `New value for ${spec.name}`);
  const button = document.createElement("button");
  button.type = "submit";
  button.className = "small";
  button.textContent = "Apply";
  form.append(input);
  if (spec.unit) {
    const unit = document.createElement("span");
    unit.className = "property-unit";
    unit.textContent = spec.unit;
    form.append(unit);
  }
  form.append(button);
  form.addEventListener("submit", applyKnownProperty);
  return form;
}

async function applyKnownProperty(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const key = Number(form.dataset.key);
  const entry = propertyRowByKey.get(key);
  const input = form.elements.value;
  try {
    entry.row.classList.remove("has-error");
    entry.row.classList.add("is-saving");
    await session.setPropertyText(key, input.value);
  } catch (error) {
    entry.row.classList.remove("is-saving");
    showPropertyError(key, error instanceof Error ? error.message : String(error));
  }
}

function updateKnownProperty(event) {
  const entry = propertyRowByKey.get(event.key);
  if (!entry) return;
  entry.row.classList.remove("has-error", "is-saving", "is-fetching");
  entry.row.classList.add("has-value");
  entry.value.textContent = event.decoded?.display || spacedHex(event.value_hex) || "(empty)";
  entry.value.title = `Raw: ${spacedHex(event.value_hex) || "(empty)"}`;
  const input = entry.change.querySelector("[name=value]");
  if (input && event.decoded?.edit != null && document.activeElement !== input) input.value = event.decoded.edit;
  if (event.unsolicited) {
    entry.row.classList.remove("was-updated");
    requestAnimationFrame(() => entry.row.classList.add("was-updated"));
    setTimeout(() => entry.row.classList.remove("was-updated"), 1800);
  }
}

function showPropertyError(key, message) {
  const entry = propertyRowByKey.get(key);
  if (!entry) return;
  entry.row.classList.remove("is-saving", "is-fetching");
  entry.row.classList.add("has-error");
  entry.value.textContent = message.replace(/^Status::/, "");
}

function updatePropertyAvailability() {
  for (const { row, spec, value, change } of propertyRowByKey.values()) {
    const supported = !capabilitiesKnown || spec.capability == null || activeCapabilities.has(spec.capability);
    row.classList.toggle("is-unsupported", !supported);
    if (!supported) value.textContent = "Not supported by this NCP";
    else if (!isConnected && spec.readable) value.textContent = "Waiting for connection";
    for (const control of change.querySelectorAll("input, select, button")) control.disabled = !isConnected || !supported;
  }
  elements.refreshProperties.disabled = !isConnected;
}

function updateCommandAvailability() {
  for (const button of document.querySelectorAll(".command-button")) {
    const capability = button.dataset.capability ? Number(button.dataset.capability) : undefined;
    const supported = capability == null || (capabilitiesKnown && activeCapabilities.has(capability));
    button.disabled = !isConnected || commandBusy || !supported;
  }
}

function filterProperties() {
  const needle = elements.propertyFilter.value.trim().toLowerCase();
  for (const { row } of propertyRowByKey.values()) row.hidden = Boolean(needle && !row.dataset.search.includes(needle));
  for (const group of elements.propertyRows.querySelectorAll(".property-group")) {
    group.hidden = ![...elements.propertyRows.querySelectorAll(`.property-row[data-group="${group.dataset.group}"]`)].some((row) => !row.hidden);
  }
}

function renderPropertyResult(event) {
  const heading = document.createElement("strong");
  heading.textContent = `${event.name || `Property ${event.key}`}${event.unsolicited ? " · unsolicited" : ""}`;
  const decoded = document.createElement("span");
  decoded.className = "decoded-value";
  decoded.textContent = event.decoded?.display || "No typed decoder for this property";
  const raw = document.createElement("small");
  raw.textContent = `Raw: ${spacedHex(event.value_hex) || "(empty)"}`;
  elements.propertyResult.replaceChildren(heading, decoded, raw);
}

function toggleCapture() {
  packetCapture.recording = !packetCapture.recording;
  renderCapture();
}

function renderCapture() {
  const packets = filterPackets(packetCapture.packets, elements.captureFilter.value, elements.captureKind.value);
  elements.captureRows.replaceChildren(...packets.slice(-500).reverse().map(captureTableRow));
  elements.captureEmpty.hidden = packets.length !== 0;

  const stats = packetCapture.stats();
  const parts = [
    `${stats.captured} packet${stats.captured === 1 ? "" : "s"}`,
    formatBytes(stats.bytes),
    stats.decoded && `${stats.decoded} decoded`,
    stats.decode_errors && `${stats.decode_errors} decode error${stats.decode_errors === 1 ? "" : "s"}`,
    stats.dropped && `${stats.dropped} dropped from view`,
  ].filter(Boolean);
  elements.captureStats.textContent = parts.join(" · ");
  elements.captureState.textContent = packetCapture.recording ? "Capturing" : "Paused";
  elements.captureState.classList.toggle("is-recording", packetCapture.recording);
  elements.captureToggle.textContent = packetCapture.recording ? "Pause capture" : "Resume capture";
  elements.exportCaptureJson.disabled = stats.captured === 0;
  elements.exportCapturePcap.disabled = stats.captured === 0;

  const selected = packetCapture.packets.find((packet) => packet.capture_id === selectedPacketId);
  renderCaptureDetail(selected);
}

function captureTableRow(event) {
  const row = document.createElement("tr");
  row.dataset.captureId = String(event.capture_id);
  row.classList.toggle("is-selected", event.capture_id === selectedPacketId);
  row.tabIndex = 0;
  const select = () => {
    selectedPacketId = event.capture_id;
    renderCapture();
  };
  row.addEventListener("click", select);
  row.addEventListener("keydown", (keyboardEvent) => {
    if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") {
      keyboardEvent.preventDefault();
      select();
    }
  });
  const meta = event.metadata;
  for (const [value, className] of [
    [event.capture_id],
    [formatTime(event.timestamp_ms), "capture-nowrap"],
    [event.packet?.packet_type || "Unparsed", event.packet ? "capture-type" : "decode-warning"],
    [event.packet?.source || "—", "capture-address"],
    [event.packet?.destination || event.packet?.channel_hex || "—", "capture-address"],
    [meta?.rssi_dbm != null ? `${meta.rssi_dbm} dBm` : "—", "capture-nowrap"],
    [`${event.data_hex.length / 2} B`, "capture-nowrap"],
  ]) {
    const cell = document.createElement("td");
    cell.textContent = String(value);
    if (className) cell.className = className;
    row.append(cell);
  }
  return row;
}

function renderCaptureDetail(event) {
  if (!event) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "Select a packet to inspect its parsed fields and raw bytes.";
    elements.captureDetail.replaceChildren(empty);
    return;
  }

  const heading = document.createElement("div");
  heading.className = "capture-detail-heading";
  const title = document.createElement("h3");
  title.textContent = `#${event.capture_id} · ${event.packet?.packet_type || "Unparsed packet"}`;
  const metrics = document.createElement("div");
  metrics.className = "rx-metrics";
  for (const label of captureMetricLabels(event)) {
    const chip = document.createElement("span");
    chip.textContent = label;
    metrics.append(chip);
  }
  heading.append(title, metrics);

  const fields = document.createElement("dl");
  for (const [name, value] of captureFields(event)) {
    if (value == null) continue;
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = name;
    detail.textContent = String(value);
    fields.append(term, detail);
  }

  const children = [heading, fields];
  const warnings = [
    event.packet_error && `Packet: ${event.packet_error}`,
    event.metadata_error && `Metadata: ${event.metadata_error}`,
    event.packet?.options_error && `Options: ${event.packet.options_error}`,
  ].filter(Boolean);
  if (warnings.length) {
    const warning = document.createElement("p");
    warning.className = "decode-warning";
    warning.textContent = warnings.join(" · ");
    children.push(warning);
  }
  if (event.packet?.body_hex) children.push(hexSection("MAC body", event.packet.body_hex));
  children.push(hexSection(`Raw packet · ${event.data_hex.length / 2} bytes`, event.data_hex));
  elements.captureDetail.replaceChildren(...children);
}

function captureMetricLabels(event) {
  const meta = event.metadata;
  return [
    formatTime(event.timestamp_ms),
    meta?.rssi_dbm != null && `${meta.rssi_dbm} dBm`,
    meta?.lqi != null && `LQI ${meta.lqi}`,
    meta?.snr_cb != null && `${(meta.snr_cb / 10).toFixed(1)} dB SNR`,
    meta?.buffered && `Buffered · ${meta.age_s}s`,
    meta?.acknowledged && "NCP acknowledged",
  ].filter(Boolean);
}

function captureFields(event) {
  const packet = event.packet;
  if (!packet) return [["Stream", event.stream], ["Decode", "Not a valid UMSH MAC packet"]];
  const options = packet.options;
  return [
    ["Source", packet.source],
    ["Destination", packet.destination],
    ["Channel", packet.channel_hex],
    ["Frame counter", packet.frame_counter],
    ["Security", packet.encrypted ? "Encrypted" : "Plaintext"],
    ["Payload type", packet.payload_type],
    ["ACK requested", packet.ack_requested ? "Yes" : "No"],
    ["Frame layout", `${packet.header_len} B header · ${packet.body_len} B body · ${packet.mic_len} B MIC/tag`],
    ["Flood hops", packet.flood_remaining != null ? `${packet.flood_remaining} remaining · ${packet.flood_accumulated} accumulated` : null],
    ["Region", options?.region_code],
    ["Source route", options?.source_route_len != null ? `${options.source_route_len} bytes` : null],
    ["Trace route", options?.trace_route_len != null ? `${options.trace_route_len} bytes` : null],
    ["Minimum RSSI", options?.min_rssi_dbm != null ? `${options.min_rssi_dbm} dBm` : null],
    ["Minimum SNR", options?.min_snr_db != null ? `${options.min_snr_db} dB` : null],
    ["Route retry", options?.route_retry ? "Requested" : null],
    ["Unknown critical option", options?.unknown_critical ? "Present" : null],
  ];
}

function hexSection(label, value) {
  const details = document.createElement("details");
  details.open = label.startsWith("Raw");
  const summary = document.createElement("summary");
  summary.textContent = label;
  const raw = document.createElement("code");
  raw.textContent = spacedHex(value);
  details.append(summary, raw);
  return details;
}

function setConnectionState({ connected, name }) {
  isConnected = connected;
  elements.disconnect.disabled = !connected;
  elements.propertyFieldset.disabled = !connected;
  if (connected) {
    elements.deviceName.textContent = name;
    if (elements.status.textContent !== "Attached") setStatus("Synchronizing…", "busy");
  } else {
    capabilitiesKnown = false;
    activeCapabilities = new Set();
    commandBusy = false;
    elements.deviceName.textContent = "No device";
    elements.commandResult.textContent = "Connect to issue a command.";
  }
  updatePropertyAvailability();
  updateCommandAvailability();
}

async function submitProperty(event) {
  event.preventDefault();
  const key = Number(elements.propertyKey.value);
  const operation = elements.propertyOperation.value;
  try {
    const value = operation === "get" ? new Uint8Array() : parseHex(elements.propertyValue.value);
    requestedPropertyKey = key;
    await session.property(operation, key, value);
  } catch (error) {
    requestedPropertyKey = undefined;
    elements.propertyResult.textContent = error instanceof Error ? error.message : String(error);
  }
}

function renderTrace() {
  const needle = elements.traceFilter.value.trim().toLowerCase();
  const rows = trace.filter((entry) => !needle || entry.summary.toLowerCase().includes(needle));
  elements.traceRows.replaceChildren(...rows.slice(-500).reverse().map(traceRow));
  elements.traceEmpty.hidden = rows.length !== 0;
}

function traceRow(entry) {
  const row = document.createElement("li");
  const heading = document.createElement("div");
  heading.className = "trace-heading";
  const direction = entry.direction === "host_to_ncp" ? "HOST → NCP" : "NCP → HOST";
  heading.innerHTML = `<span class="direction ${entry.direction}">${direction}</span><time>${formatTime(entry.timestamp_ms)}</time>`;
  const summary = document.createElement("code");
  summary.textContent = entry.summary;
  row.append(heading, summary);
  if (entry.redacted) {
    const raw = document.createElement("small");
    raw.textContent = "Raw bytes hidden: secret-bearing write";
    row.append(raw);
  } else if (entry.raw_hex) {
    const details = document.createElement("details");
    details.innerHTML = "<summary>Raw frame</summary>";
    const raw = document.createElement("code");
    raw.textContent = spacedHex(entry.raw_hex);
    details.append(raw);
    row.append(details);
  }
  return row;
}

function exportTrace() {
  const blob = new Blob([JSON.stringify({ format: "umsh-companion-trace", version: 1, trace }, null, 2)], { type: "application/json" });
  downloadBlob(blob, `umsh-companion-${captureTimestamp()}.json`);
}

function exportCaptureJson() {
  const blob = new Blob([captureJson(packetCapture.packets)], { type: "application/json" });
  downloadBlob(blob, `umsh-radio-${captureTimestamp()}.json`);
}

function exportCapturePcap() {
  const blob = new Blob([capturePcap(packetCapture.packets)], { type: "application/vnd.tcpdump.pcap" });
  downloadBlob(blob, `umsh-radio-${captureTimestamp()}.pcap`);
}

function downloadBlob(blob, filename) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 0);
}

function captureTimestamp() {
  return new Date().toISOString().replaceAll(":", "-");
}

function showPlatformSupport() {
  const secure = window.isSecureContext;
  elements.connectSerial.disabled = !secure || !("serial" in navigator);
  elements.connectBluetooth.disabled = !secure || !("bluetooth" in navigator);
  const supported = [];
  if ("serial" in navigator) supported.push("Web Serial");
  if ("bluetooth" in navigator) supported.push("Web Bluetooth");
  elements.platform.textContent = secure
    ? supported.length ? `${supported.join(" and ")} available` : "Hardware APIs unavailable; use desktop or Android Chrome"
    : "HTTPS or localhost is required for hardware access";
}

function setStatus(message, state) {
  elements.status.textContent = message;
  elements.status.dataset.state = state;
}

function parseHex(value) {
  const compact = value.replaceAll(/\s|_/g, "");
  if (compact.length % 2 || !/^[0-9a-f]*$/i.test(compact)) throw new Error("Value must contain complete hexadecimal octets");
  return Uint8Array.from(compact.match(/../g) || [], (octet) => Number.parseInt(octet, 16));
}

function spacedHex(value) {
  return value.match(/../g)?.join(" ") || "";
}

function formatTime(milliseconds) {
  return `${(milliseconds / 1000).toFixed(3)}s`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KiB`;
}

function pairingHint(message) {
  return /auth|security|gatt|network/i.test(message)
    ? `${message}. If the radio requires pairing, enable pairing mode and complete the operating-system passkey prompt.`
    : message;
}
