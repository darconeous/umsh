/**
 * Published firmware, read from the release manifest.
 *
 * `make release-mirror` copies the newest release's `manifest.json` to
 * `/firmware/manifest.json` and mirrors the artifacts a browser can actually
 * fetch — the nRF52 DFU packages and the merged ESP32 image — alongside it.
 * GitHub's release assets send no CORS headers, so a file's `url` is only ever
 * a download link for the user; `path` is the same-origin copy we may fetch.
 * A file with a null `path` (the UF2s) is download-only.
 *
 * Manifest shape is `schema_version: 1`, written by `scripts/release.py`.
 */

export class ManifestUnavailableError extends Error {
  constructor(message = "no published firmware is available right now") {
    super(message);
    this.name = "ManifestUnavailableError";
  }
}

export class ArtifactError extends Error {
  constructor(message) {
    super(message);
    this.name = "ArtifactError";
  }
}

const MANIFEST_URL = "/firmware/manifest.json";
const SUPPORTED_SCHEMA = 1;

export async function fetchLatestManifest() {
  let response;
  try {
    response = await fetch(MANIFEST_URL, { cache: "no-cache" });
  } catch (error) {
    throw new ManifestUnavailableError(`could not reach ${MANIFEST_URL}: ${error.message}`);
  }
  if (!response.ok) {
    throw new ManifestUnavailableError(`${MANIFEST_URL} returned ${response.status}`);
  }

  const manifest = await response.json();
  if (manifest.schema_version !== SUPPORTED_SCHEMA) {
    throw new ManifestUnavailableError(
      `this page understands manifest schema ${SUPPORTED_SCHEMA}, but the published one is ${manifest.schema_version}. Reload the page to pick up a newer flasher.`,
    );
  }
  return manifest;
}

export function manifestBoard(manifest, boardId) {
  return manifest?.boards?.find((board) => board.id === boardId) ?? null;
}

export function fileByRole(boardEntry, role) {
  return boardEntry?.files?.find((file) => file.role === role) ?? null;
}

/** The artifact this page flashes for a board: a DFU package, or a merged image. */
export function flashableFile(boardEntry) {
  return fileByRole(boardEntry, "dfu-zip") ?? fileByRole(boardEntry, "merged-bin");
}

export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Download a manifest file and prove it is the one the manifest describes.
 *
 * Verification happens here, before the bytes are handed to a flashing
 * routine — never after, when a corrupted image would already be on the board.
 */
export async function fetchArtifact(file, { onProgress = () => {} } = {}) {
  if (!file?.path) {
    throw new ArtifactError(`${file?.name ?? "that file"} is not mirrored for download from this page.`);
  }

  const response = await fetch(file.path, { cache: "no-cache" });
  if (!response.ok) {
    throw new ArtifactError(`could not download ${file.name} (HTTP ${response.status}).`);
  }

  const total = Number(response.headers.get("content-length")) || file.size || 0;
  const bytes = await readAll(response, total, onProgress);

  if (file.size && bytes.length !== file.size) {
    throw new ArtifactError(
      `${file.name} downloaded as ${bytes.length} bytes but should be ${file.size}. Reload and try again.`,
    );
  }
  if (file.sha256) {
    const digest = await sha256Hex(bytes);
    if (digest !== file.sha256.toLowerCase()) {
      throw new ArtifactError(
        `${file.name} failed its checksum. Nothing has been written to the board. Reload and try again.`,
      );
    }
  }
  return bytes;
}

async function readAll(response, total, onProgress) {
  if (!response.body) return new Uint8Array(await response.arrayBuffer());

  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    onProgress(received, total);
  }

  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}
