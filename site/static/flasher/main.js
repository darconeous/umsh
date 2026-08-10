/**
 * The web flasher: pick a board, pick firmware, flash it over USB.
 *
 * Two paths, chosen by what the board is:
 *   nRF52840 — reboot into the Adafruit bootloader (or let the user do it by
 *              hand), then speak legacy Nordic serial DFU at 115200.
 *   ESP32-S3 — hand the port to esptool-js, which drives the ROM bootloader
 *              itself over DTR/RTS.
 *
 * Everything the page fetches is same-origin, which is what lets the template
 * keep a strict Content-Security-Policy.
 */

import { loadBoards, boardFromQuery, isNrf, isEsp, warningsFor, updateModeFor } from "./boards.js";
import { SerialLink, SerialLostError, describePort, touch1200, sleep } from "./serial.js";
import { NrfDfu, parseDfuPackage, DfuPackageError } from "./nrf-dfu.js";
import { flashEsp } from "./esp-flash.js";
import {
  fetchLatestManifest,
  manifestBoard,
  flashableFile,
  fileByRole,
  fetchArtifact,
  ManifestUnavailableError,
} from "./releases.js";

const elements = Object.fromEntries(
  [...document.querySelectorAll("#flasher [id]")].map((element) => [element.id, element]),
);

const state = {
  boards: loadBoards(),
  board: null,
  source: "latest",
  /** Set once the user picks a source, so we stop moving it for them. */
  sourcePinned: false,
  manifest: null,
  /** The manifest fetch has finished, successfully or not. */
  manifestSettled: false,
  /** Bytes ready to flash: {bin, dat} for nRF, {image} for ESP. */
  artifact: null,
  artifactLabel: "",
  busy: false,
  /** Set once a 1200-baud touch has been done and we need the new port. */
  awaitingBootloader: false,
};

// `?flasher-test=unsupported` forces the no-WebSerial rendering, so the
// fallback can be checked from a browser that does support it.
const supported =
  "serial" in navigator &&
  window.isSecureContext &&
  new URLSearchParams(location.search).get("flasher-test") !== "unsupported";

function main() {
  if (!elements["flasher-board"]) return;

  if (!supported) {
    elements["flasher-unsupported"].hidden = false;
    // Without WebSerial the only useful firmware source is a download, so
    // the pick-a-file option would be a dead end.
    document.querySelector("input[name='flasher-source'][value='custom']").closest("label").hidden = true;
  }

  elements["flasher-board"].addEventListener("change", (event) => {
    selectBoard(state.boards.find((board) => board.id === event.target.value) ?? null);
  });

  for (const input of document.querySelectorAll("input[name='flasher-source']")) {
    input.addEventListener("change", () => {
      state.source = input.value;
      state.sourcePinned = true;
      state.artifact = null;
      renderFirmwareStep();
      renderFlashStep();
    });
  }

  elements["flasher-file"].addEventListener("change", onFileChosen);

  const preselected = boardFromQuery(state.boards);
  if (preselected) {
    elements["flasher-board"].value = preselected.id;
    selectBoard(preselected);
  }

  loadManifest();
}

async function loadManifest() {
  try {
    state.manifest = await fetchLatestManifest();
  } catch (error) {
    state.manifest = null;
    if (!(error instanceof ManifestUnavailableError)) throw error;
  }
  state.manifestSettled = true;
  renderFirmwareStep();
  renderFlashStep();
}

function selectBoard(board) {
  state.board = board;
  state.artifact = null;
  state.awaitingBootloader = false;
  setStatus("");
  setLog("");

  const url = new URL(location.href);
  if (board) url.searchParams.set("board", board.id);
  else url.searchParams.delete("board");
  history.replaceState(null, "", `${url.pathname}${url.search}`);

  elements["flasher-step-firmware"].hidden = !board;
  renderFirmwareStep();
  renderFlashStep();
}

/* ── Step 2: which firmware ─────────────────────────────────────────────── */

function renderFirmwareStep() {
  const board = state.board;
  if (!board) return;

  const entry = state.manifest ? manifestBoard(state.manifest, board.id) : null;
  const file = entry ? flashableFile(entry) : null;
  const latestInput = document.querySelector("input[name='flasher-source'][value='latest']");

  if (file) {
    const megabytes = (file.size / 1024 / 1024).toFixed(1);
    elements["flasher-release-meta"].textContent =
      `version ${state.manifest.release.version}, released ${state.manifest.release.date} · ${megabytes} MB`;
    latestInput.disabled = false;
    // A board switched to before the manifest arrived, or one that has no
    // published build, leaves the choice on "custom"; put it back.
    if (!state.sourcePinned) chooseSource("latest");
  } else if (!state.manifestSettled) {
    elements["flasher-release-meta"].textContent = "checking…";
    latestInput.disabled = true;
  } else {
    elements["flasher-release-meta"].textContent = state.manifest
      ? "no published build for this board yet"
      : "unavailable right now";
    latestInput.disabled = true;
    // Without WebSerial the custom-file option is hidden, so there is
    // nothing to fall back to.
    if (supported && state.source === "latest") chooseSource("custom");
  }

  const custom = state.source === "custom";
  elements["flasher-file"].hidden = !custom;
  elements["flasher-file"].accept = isEsp(board) ? ".bin" : ".zip";
  elements["flasher-file-hint"].hidden = !custom;
  elements["flasher-file-hint"].innerHTML = isEsp(board)
    ? "For developers: a merged image, as <code>make merged-bin-heltec-v3</code> writes it — <code>umsh-heltec-v3-&lt;version&gt;.bin</code>."
    : "For developers: a DFU package, as <code>make dfu-zip-" +
      board.id +
      "</code> writes it — <code>umsh-" +
      board.id +
      "-&lt;version&gt;-dfu.zip</code>.";
}

function chooseSource(source) {
  if (state.source !== source) state.artifact = null;
  state.source = source;
  document.querySelector(`input[name='flasher-source'][value='${source}']`).checked = true;
}

async function onFileChosen(event) {
  const file = event.target.files?.[0];
  state.artifact = null;
  if (!file) {
    renderFlashStep();
    return;
  }

  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    state.artifact = isEsp(state.board) ? { image: bytes } : parseDfuPackage(bytes);
    state.artifactLabel = file.name;
    setStatus(`Ready to flash ${file.name}.`);
  } catch (error) {
    state.artifact = null;
    setStatus(
      error instanceof DfuPackageError ? `That file will not do: ${error.message}` : String(error?.message ?? error),
      "error",
    );
  }
  renderFlashStep();
}

/* ── Step 3: flash ──────────────────────────────────────────────────────── */

function renderFlashStep() {
  const board = state.board;
  elements["flasher-step-flash"].hidden = !board;
  if (!board) return;

  const warnings = warningsFor(board);
  elements["flasher-warnings"].innerHTML = warnings.length
    ? `<div class="notice notice--compact"><ul>${warnings.map((w) => `<li>${w}</li>`).join("")}</ul></div>`
    : "";

  const packageNote = mismatchNote();
  if (packageNote) {
    elements["flasher-warnings"].insertAdjacentHTML(
      "beforeend",
      `<div class="notice notice--warn"><p>${packageNote}</p></div>`,
    );
  }

  const actions = elements["flasher-actions"];
  actions.innerHTML = "";
  if (state.busy) return;

  if (!supported) {
    // The banner at the top already says why; this step's job is to hand
    // over the file and say what to do with it.
    appendDownloadLinks(actions, { primary: true });
    elements["flasher-entry"].textContent = !actions.children.length
      ? "Firmware downloads are unavailable right now."
      : isEsp(board)
        ? "To flash by hand, write the downloaded image to the board at address 0x0 with esptool or espflash."
        : `To flash by hand: put the radio in update mode (${updateModeFor(board)}) — a small USB drive named ${board.flash.volume} appears. Copy the downloaded UF2 onto it, and the radio restarts with the new firmware.`;
    return;
  }

  if (state.awaitingBootloader) {
    actions.append(
      button("Continue", "btn btn--primary", () => run(flashOverSerial)),
      button("Start over", "btn btn--ghost", () => {
        state.awaitingBootloader = false;
        setStatus("");
        renderFlashStep();
      }),
    );
    elements["flasher-entry"].textContent = "";
    return;
  }

  actions.append(
    button("Flash radio", "btn btn--primary", () => run(isEsp(board) ? flashEspBoard : flashNrf)),
  );
  appendDownloadLinks(actions);

  // For a radio already running UMSH, clicking Flash is the whole job — the
  // page restarts it into update mode itself. This line covers the boards
  // that can't do that yet, without asking anyone to decode "bootloader".
  elements["flasher-entry"].textContent = isEsp(board)
    ? ""
    : `Brand-new board, or not running UMSH yet? Put it in update mode first — ${updateModeFor(board)} — then click Flash radio.`;
}

/**
 * Warn when a hand-picked package looks like it belongs to another board.
 *
 * The bootloader refuses a package whose SoftDevice requirement does not
 * match, which catches a T-Echo image on any other board and vice versa. It
 * cannot catch a mix-up between the four boards that share S140 7.3.0, so say
 * something.
 */
function mismatchNote() {
  const name = state.artifact?.binName;
  if (!name || !state.board) return "";
  if (name.includes(state.board.id)) return "";
  return `This package contains <code>${name}</code>, which does not look like firmware for the ${state.board.name}. Flashing it will leave the board running software built for different hardware.`;
}

function appendDownloadLinks(container, { primary = false } = {}) {
  const entry = state.manifest ? manifestBoard(state.manifest, state.board.id) : null;
  if (!entry) return;

  const uf2 = fileByRole(entry, "uf2");
  const file = uf2 ?? fileByRole(entry, "merged-bin");
  const href = file?.url ?? file?.path;
  if (!href) return;

  const link = document.createElement("a");
  link.className = primary ? "btn btn--primary" : "btn btn--ghost";
  const what = uf2 ? "the UF2" : "the firmware image";
  link.textContent = primary ? `Download ${what}` : `Download ${what} instead`;
  link.href = href;
  container.append(link);
}

/* ── The three flashing routines ────────────────────────────────────────── */

/** A port belonging to a radio that is running UMSH firmware right now. */
function isUmshAppPort(port) {
  const info = port.getInfo?.() ?? {};
  return info.usbVendorId === 0x16c0 && info.usbProductId === 0x27dd;
}

async function flashNrf() {
  await ensureArtifact();

  setStatus("Pick your radio in the list the browser just opened, then press Connect.");
  const port = await requestPort();
  if (!port) return;

  // Anything that is not a running UMSH radio is either already in update
  // mode — flash it right here, on the port the user just picked — or still
  // on factory firmware, in which case the attempt times out and the error
  // explains the button gesture. A second picker helps neither case.
  if (!isUmshAppPort(port)) {
    log(`${describePort(port)} is not a running UMSH radio; treating it as already in update mode.`);
    await flashPort(port);
    return;
  }

  setStatus("Restarting the radio into update mode…");
  log(`Touching ${describePort(port)} at 1200 baud.`);
  await touch1200(port);

  // If this browser has flashed the radio before, its update-mode port is
  // already granted and there is nothing to ask the user for.
  const successor = await findReenumeratedPort(port);
  if (successor) {
    log(`Found the radio's update-mode port (${describePort(successor)}) without asking.`);
    await flashPort(successor);
    return;
  }

  state.awaitingBootloader = true;
  setStatus(
    "The radio restarted into update mode, so it shows up as a new entry in the port list. Click Continue and pick it again — same radio, possibly a different name. If a small USB drive popped up too, just ignore it.",
  );
}

/**
 * After the touch, the radio drops off USB and returns as a different device.
 * If the browser already trusts that device from an earlier flash, use it
 * directly; if anything is ambiguous, fall back to asking.
 */
async function findReenumeratedPort(oldPort) {
  for (let poll = 0; poll < 8; poll++) {
    await sleep(500);
    const ports = await navigator.serial.getPorts();
    if (ports.includes(oldPort)) continue; // still re-enumerating, or the touch did nothing
    const candidates = ports.filter((candidate) => !isUmshAppPort(candidate));
    if (candidates.length === 1) return candidates[0];
    if (candidates.length > 1) return null;
  }
  return null;
}

async function flashOverSerial() {
  setStatus("Pick your radio in the list the browser just opened, then press Connect.");
  const port = await requestPort();
  if (!port) return;
  await flashPort(port);
}

async function flashPort(port) {
  await ensureArtifact();

  // A radio that has just re-enumerated into update mode reliably drops the
  // very first connection on some machines (macOS is still probing the new
  // device and mounting its little USB drive). Nothing durable has happened
  // when that occurs — update mode only applies a complete image — so retry
  // quietly instead of asking the user to press the button again. The
  // permission survives re-enumeration, so no second picker is needed.
  const ATTEMPTS = 3;
  for (let attempt = 1; ; attempt++) {
    const link = new SerialLink();
    try {
      await link.open(port, { baudRate: 115200 });
      log(`Opened ${describePort(port)} at 115200 baud.`);

      const dfu = new NrfDfu(link, { onProgress: showProgress, onStage: showStage, log });
      await dfu.flash(state.artifact);

      state.awaitingBootloader = false;
      finish("Done. Your radio is restarting with the new firmware.");
      return;
    } catch (error) {
      // NetworkError is the browser's own face for the same thing, thrown
      // when open() itself hits the half-settled device.
      const retriable = error instanceof SerialLostError || error?.name === "NetworkError";
      if (!retriable || attempt >= ATTEMPTS) throw error;
      log(`Connection dropped (${error.message}); waiting for the radio to settle, then retrying.`);
      setStatus("The radio is still settling into update mode — trying again…");
      hideProgress();
      await sleep(2000);
      port = (await reacquirePort(port)) ?? port;
    } finally {
      await link.close();
    }
  }
}

/** Find the granted port again after the device re-enumerated under us. */
async function reacquirePort(oldPort) {
  try {
    const wanted = oldPort.getInfo?.() ?? {};
    const ports = await navigator.serial.getPorts();
    return (
      ports.find((candidate) => {
        const info = candidate.getInfo();
        return info.usbVendorId === wanted.usbVendorId && info.usbProductId === wanted.usbProductId;
      }) ??
      ports[0] ??
      null
    );
  } catch {
    return null;
  }
}

async function flashEspBoard() {
  await ensureArtifact();

  setStatus("Pick your board in the list the browser just opened, then press Connect.");
  const port = await requestPort();
  if (!port) return;

  await flashEsp(port, {
    image: state.artifact.image,
    onProgress: showProgress,
    onStage: showStage,
    log,
  });
  finish("Done. The board has restarted with the new firmware.");
}

/** Make sure bytes are in hand, downloading and verifying them if need be. */
async function ensureArtifact() {
  if (state.artifact) return;

  if (state.source === "custom") {
    throw new Error("choose a firmware file first.");
  }

  const entry = manifestBoard(state.manifest, state.board.id);
  const file = flashableFile(entry);
  showStage("downloading");
  const bytes = await fetchArtifact(file, { onProgress: showProgress });
  log(`Downloaded ${file.name} (${bytes.length} bytes) and verified its checksum.`);

  state.artifact = isEsp(state.board) ? { image: bytes } : parseDfuPackage(bytes);
  state.artifactLabel = file.name;
  hideProgress();
}

/* ── Plumbing ───────────────────────────────────────────────────────────── */

/** Returns null when the user dismisses the port picker, which is not an error. */
async function requestPort() {
  try {
    return await navigator.serial.requestPort();
  } catch (error) {
    if (error?.name === "NotFoundError" || error?.name === "AbortError") {
      setStatus("Nothing was flashed — the picker was closed. Click the button again and choose your radio from the list.");
      return null;
    }
    throw error;
  }
}

async function run(action) {
  state.busy = true;
  renderFlashStep();
  try {
    await action();
  } catch (error) {
    fail(error);
  } finally {
    state.busy = false;
    hideProgress();
    renderFlashStep();
  }
}

function fail(error) {
  log(`Failed: ${error?.message ?? error}`);

  // Browser serial errors read like kernel logs ("The device has been
  // lost."); never show them to the user. The raw text is in the log above.
  let message = error?.message ?? String(error);
  let guidance = "";
  if (error instanceof SerialLostError) {
    message = "the connection to the radio dropped partway through.";
    guidance = isEsp(state.board)
      ? " The board is not damaged—an interrupted flash just has to be redone. Plug it back in and click Flash radio again."
      : ` The radio is not damaged—it just didn't get the whole update, so it may not start until it does. Put it back in update mode — ${updateModeFor(state.board)} — and click Flash radio again.`;
  } else if (error?.name === "DfuTimeoutError") {
    guidance = ` Try putting it in update mode yourself — ${updateModeFor(state.board)} — then click Flash radio again.`;
  } else if (error?.name === "NetworkError" || /already open|failed to open/i.test(message)) {
    guidance = " Another program on this computer is probably using the port—close any serial monitor or flashing tool and try again.";
  }

  setStatus(`That did not work: ${message}${guidance}`, "error");
}

function finish(message) {
  hideProgress();
  setStatus(message, "ok");
}

function showStage(stage) {
  const messages = {
    downloading: "Downloading firmware…",
    connecting: "Connecting to the board…",
    erasing: "Erasing the old firmware. This takes a few seconds.",
    verifying: "Checking that this firmware fits this board…",
    writing: "Writing firmware…",
    finishing: "Finishing up…",
  };
  setStatus(messages[stage] ?? stage);
  if (stage === "erasing" || stage === "verifying" || stage === "connecting") {
    elements["flasher-progress"].hidden = false;
    elements["flasher-progress"].removeAttribute("value");
  }
}

function showProgress(done, total) {
  const bar = elements["flasher-progress"];
  bar.hidden = false;
  if (total) bar.value = Math.min(100, Math.round((done / total) * 100));
  else bar.removeAttribute("value");
}

function hideProgress() {
  elements["flasher-progress"].hidden = true;
  elements["flasher-progress"].value = 0;
}

function setStatus(message, kind = "") {
  const node = elements["flasher-status"];
  node.innerHTML = message;
  node.dataset.kind = kind;
}

function setLog(text) {
  elements["flasher-log"].textContent = text;
}

function log(line) {
  elements["flasher-log"].textContent += `${line}\n`;
  elements["flasher-log"].scrollTop = elements["flasher-log"].scrollHeight;
}

function button(label, className, onClick) {
  const element = document.createElement("button");
  element.type = "button";
  element.className = className;
  element.textContent = label;
  element.addEventListener("click", onClick);
  return element;
}

main();
