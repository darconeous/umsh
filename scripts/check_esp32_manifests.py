#!/usr/bin/env python3
"""Hold the ESP32 device images' feature tables in step.

Every device image under firmware-esp32/firmware/ is a thin manifest over
the shared sources in esp32-tracker/. Cargo cannot share a `[features]`
table between packages, so each manifest carries its own copy, and a
feature added to one and forgotten in another goes unnoticed until
someone builds that board. This compares the copies.

What may differ between two images:

- `default`, which is what selects the image;
- the name of the board's BSP crate wherever a feature forwards to it;
- a `dep:` entry for a dependency only one chip has (CHIP_ONLY_DEPS).

Two images of one board must also agree on `[dependencies]`.

Standard library only (tomllib, so Python 3.11 or newer).
"""

import pathlib
import sys
import tomllib

FIRMWARE = pathlib.Path(__file__).resolve().parent.parent / "firmware-esp32" / "firmware"
SHARED_ENTRY = "../esp32-tracker/src/main.rs"
COMMON_BSP = "umsh-bsp-esp32"
BSP_PLACEHOLDER = "<board-bsp>"

# Dependencies that exist for one chip only. A feature may name one of
# these in the manifests that have it and omit it in those that do not.
CHIP_ONLY_DEPS = {"esp-wifi-sys-esp32s3"}


def is_device_image(manifest):
    return any(binary.get("path") == SHARED_ENTRY for binary in manifest.get("bin", []))


def board_bsp(manifest):
    """The one board-support crate this image links, besides the common one."""
    crates = [
        name
        for name in manifest.get("dependencies", {})
        if name.startswith("umsh-bsp-") and name != COMMON_BSP
    ]
    if len(crates) != 1:
        raise ValueError(f"expected one board BSP dependency, found {crates or 'none'}")
    return crates[0]


def board_of(manifest):
    """The `board-*` feature `default` turns on."""
    boards = [
        feature
        for feature in manifest.get("features", {}).get("default", [])
        if feature.startswith("board-")
    ]
    if len(boards) != 1:
        raise ValueError(f"`default` must select one board, found {boards or 'none'}")
    return boards[0]


def normalized_features(manifest):
    """The feature table with everything an image may vary taken out."""
    bsp = board_bsp(manifest)
    table = {}
    for name, entries in manifest.get("features", {}).items():
        if name == "default":
            continue
        kept = set()
        for entry in entries:
            if entry.removeprefix("dep:") in CHIP_ONLY_DEPS:
                continue
            if entry.split("/")[0].rstrip("?") == bsp:
                entry = BSP_PLACEHOLDER + entry[len(bsp) :]
            kept.add(entry)
        table[name] = tuple(sorted(kept))
    return table


def feature_disagreements(tables):
    """Messages for every feature the images do not define alike."""
    problems = []
    for feature in sorted({name for table in tables.values() for name in table}):
        definitions = {}
        for image, table in tables.items():
            definitions.setdefault(table.get(feature), []).append(image)
        if len(definitions) == 1:
            continue
        problems.append(f"feature `{feature}` differs:")
        for definition, images in sorted(definitions.items(), key=lambda item: item[1]):
            shown = "not declared" if definition is None else f"[{', '.join(definition)}]"
            problems.append(f"    {', '.join(images)}: {shown}")
    return problems


def dependency_disagreements(manifests):
    """Messages for images of one board whose dependency tables differ."""
    problems = []
    by_board = {}
    for image, manifest in manifests.items():
        by_board.setdefault(board_of(manifest), []).append(image)
    for board, images in sorted(by_board.items()):
        first = manifests[images[0]].get("dependencies", {})
        for other in images[1:]:
            theirs = manifests[other].get("dependencies", {})
            for name in sorted(first.keys() | theirs.keys()):
                if first.get(name) != theirs.get(name):
                    problems.append(
                        f"dependency `{name}` differs between {images[0]} and {other} "
                        f"(both {board})"
                    )
    return problems


def load(root):
    manifests = {}
    for path in sorted(root.glob("*/Cargo.toml")):
        with path.open("rb") as file:
            manifest = tomllib.load(file)
        if is_device_image(manifest):
            manifests[path.parent.name] = manifest
    return manifests


def check(manifests):
    try:
        tables = {image: normalized_features(m) for image, m in manifests.items()}
        return feature_disagreements(tables) + dependency_disagreements(manifests)
    except ValueError as error:
        return [str(error)]


def main():
    manifests = load(FIRMWARE)
    if len(manifests) < 2:
        print(f"found {len(manifests)} device manifests under {FIRMWARE}", file=sys.stderr)
        return 1
    problems = check(manifests)
    if problems:
        print("ESP32 device manifests have drifted apart:", file=sys.stderr)
        for line in problems:
            print(f"  {line}", file=sys.stderr)
        return 1
    features = len(next(iter(manifests.values()))["features"]) - 1
    print(f"{len(manifests)} ESP32 device manifests agree on {features} features")
    return 0


if __name__ == "__main__":
    sys.exit(main())
