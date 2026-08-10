/**
 * Board facts for the flasher, read from the data island the Zola template
 * emits from `site/data/hardware.toml`. That file is the single source of
 * truth the hardware page, the manual instructions, and the release manifest
 * all key off, so the ids here match `scripts/firmware_image.py`'s presets and
 * the manifest's board ids exactly.
 */

/** Boards that have firmware to flash, in the order the data file lists them. */
export function loadBoards() {
  const island = document.getElementById("flasher-data");
  if (!island) return [];
  try {
    return JSON.parse(island.textContent).filter((board) => board.flash);
  } catch {
    return [];
  }
}

/** The board named by `?board=<id>`, as the hardware page's buttons link to. */
export function boardFromQuery(boards) {
  const wanted = new URLSearchParams(location.search).get("board");
  return boards.find((board) => board.id === wanted) ?? null;
}

export function isNrf(board) {
  return board?.flash?.methods?.includes("serial-dfu") ?? false;
}

export function isEsp(board) {
  return board?.flash?.methods?.includes("esp-serial") ?? false;
}

/**
 * How a person puts each board into update mode by hand, written for someone
 * who has never heard the word "bootloader".
 *
 * `hardware.toml`'s `dfu_entry` strings serve the developer docs and mention
 * things like the 1200-baud touch — which is not an instruction a user can
 * follow, it is the trick the Flash button performs for them. These are the
 * human versions, and only of the part a human can do.
 */
const UPDATE_MODE = {
  t1000e:
    "hold its button down and unplug-replug the USB cable twice while still holding it, until the green LED stays solidly lit",
  techo: "quickly press its reset button twice in a row",
  "wio-tracker-l1": "quickly press its reset button twice in a row",
  "sensecap-solar": "quickly press its reset button twice in a row",
  "xiao-nrf52": "quickly press the small reset button on the module twice in a row",
};

export function updateModeFor(board) {
  return UPDATE_MODE[board?.id] ?? "quickly press its reset button twice in a row";
}

/**
 * Extra cautions the wizard shows before flashing.
 *
 * These are about the act of flashing from a browser, which is why they live
 * here rather than in `hardware.toml`'s `quirks` — those serve the developer
 * docs and say different things.
 */
const WARNINGS = {
  t1000e: [
    // Flashing only ever writes the application area, so an interrupted
    // update is an inconvenience, not damage — say so, and teach the way out.
    `If an update gets interrupted, nothing is lost—the tracker just sits without working firmware until it gets a complete one. Put it back in update mode by hand (${UPDATE_MODE.t1000e}) and click Flash radio again.`,
  ],
  "sensecap-solar": [
    "When the node is off, any press of the PWR button—however brief—puts it in update mode instead of turning it on. USR is the power button.",
  ],
  "heltec-v3": [
    "If this board previously ran different firmware, flashing clears whatever settings that firmware had stored on it.",
  ],
  "xiao-nrf52": [
    "Only if you flash with a downloaded UF2 file instead of this page: a UF2 built for a different board is silently ignored—the copy looks like it worked, and nothing changes. Flashing from this page rejects a mismatched image with an error.",
  ],
};

export function warningsFor(board) {
  return WARNINGS[board?.id] ?? [];
}
