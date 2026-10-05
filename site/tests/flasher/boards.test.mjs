/**
 * One board, more than one firmware image.
 *
 *     node --test site/tests/flasher/
 *
 * A board that can take several images is still a single entry in
 * `hardware.toml`; the images hang off its flash table. These check that the
 * flasher resolves each image to its own release entry, and that a board with
 * one image behaves as it did before images existed.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { imagesFor, warningsFor } from "../../static/flasher/boards.js";
import { manifestBoard, flashableFile } from "../../static/flasher/releases.js";

const here = dirname(fileURLToPath(import.meta.url));
const HARDWARE = readFileSync(join(here, "..", "..", "data", "hardware.toml"), "utf8");
const RELEASE = readFileSync(join(here, "..", "..", "..", "scripts", "release.py"), "utf8");

const single = { id: "techo", flash: { methods: ["uf2", "serial-dfu"] } };
const dual = {
  id: "heltec-v3",
  flash: {
    methods: ["esp-serial"],
    images: [
      { id: "heltec-v3", name: "Standard" },
      { id: "heltec-v3-bridge", name: "Internet bridge" },
    ],
  },
};

const manifest = {
  boards: [
    { id: "heltec-v3", files: [{ role: "merged-bin", name: "umsh-heltec-v3-1.bin" }] },
    { id: "heltec-v3-bridge", files: [{ role: "merged-bin", name: "umsh-heltec-v3-bridge-1.bin" }] },
  ],
};

test("a board with one image is its own image", () => {
  assert.deepEqual(imagesFor(single), [{ id: "techo", name: "" }]);
  assert.deepEqual(imagesFor(null), []);
});

test("a board's listed images come back in order, default first", () => {
  assert.deepEqual(
    imagesFor(dual).map((image) => image.id),
    ["heltec-v3", "heltec-v3-bridge"],
  );
});

test("each image resolves to its own release file", () => {
  const names = imagesFor(dual).map((image) => flashableFile(manifestBoard(manifest, image.id)).name);
  assert.deepEqual(names, ["umsh-heltec-v3-1.bin", "umsh-heltec-v3-bridge-1.bin"]);
});

test("an image the release does not carry has no entry", () => {
  const older = { boards: [manifest.boards[0]] };
  assert.equal(manifestBoard(older, "heltec-v3-bridge"), null);
});

test("an image's cautions come before its board's, which still apply", () => {
  const standard = warningsFor(dual, "heltec-v3");
  const bridge = warningsFor(dual, "heltec-v3-bridge");
  assert.deepEqual(standard, warningsFor(dual));
  assert.equal(bridge.length, standard.length + 1);
  assert.match(bridge[0], /Bluetooth/);
  assert.deepEqual(bridge.slice(1), standard);
});

test("every image the site lists is one the release script builds", () => {
  // The two files are joined by id and nothing else. An image listed here
  // and missing there would offer a download that no release contains.
  const listed = [...HARDWARE.matchAll(/\[\[boards\.flash\.images\]\]\s*\nid = "([^"]+)"/g)].map(
    (match) => match[1],
  );
  assert.ok(listed.includes("heltec-v3-bridge"));
  for (const id of listed) {
    assert.ok(RELEASE.includes(`"${id}": {`), `${id} is not in scripts/release.py`);
  }
});
