#!/usr/bin/env python3
"""
Index a staged firmware release: write `manifest.json` and `SHA256SUMS`.

This converts nothing and builds nothing. `make release-artifacts` has
already put every artifact in one directory under its release name; this
describes what is there, so the web flasher can find and verify it.

The manifest is the flasher's entry point. It carries only what is needed
to put bytes on a board — board ids, the hardware model string a device
reports over ULCP, the chip, UF2 family and app base, the ESP32 write
offset, and per file a size, a SHA-256, and where to get it. Everything
presentational (photos, specs, prose about entering DFU) lives in
site/data/hardware.toml, keyed by the same board ids, so the two join
without either one duplicating the other.

Board facts come from scripts/firmware_image.py rather than being repeated
here, and the SoftDevice requirement is read back out of each DFU package
rather than being asserted — so the manifest describes the artifacts that
exist, not the ones we meant to build.

  # Index a staged release:
  scripts/release.py --version 2026.08.01

  # Rebuild the published mirror's index and prune old versions:
  scripts/release.py --index-mirror /tmp/umsh-gh-pages/firmware --keep 3

The first writes into target/firmware-release/<version>/ unless --dir says
otherwise. The second is what `make release-mirror` runs after copying a
version directory into the published tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile

from firmware_image import BOARDS

DEFAULT_REPO = "darconeous/umsh"

SCHEMA_VERSION = 1

# Which roles get copied into the same-origin mirror on the website.
#
# Mirroring exists to satisfy `fetch()`, and only these are ever fetched: a
# browser cannot write to a mass-storage volume, so a UF2 reaches a board as
# a download the user drags across, which works straight off the GitHub
# release URL and needs no CORS. Adding "uf2" here is all it would take if a
# File System Access flow ever makes the bytes worth having in the page.
MIRRORED_ROLES = frozenset({"dfu-zip", "merged-bin"})

# Per-board release facts that BOARDS cannot carry: which ELF the build
# produces, what the chip is, and — for boards outside the UF2 world — the
# whole flashing story. `uf2` boards inherit family/base/volume/model from
# the BOARDS preset, keyed by the same id.
RELEASE_BOARDS = {
    "techo": {"chip": "nrf52840", "elf": "firmware-techo"},
    "t1000e": {"chip": "nrf52840", "elf": "firmware-t1000e"},
    "sensecap-solar": {"chip": "nrf52840", "elf": "firmware-sensecap-solar"},
    "wio-tracker-l1": {"chip": "nrf52840", "elf": "firmware-wio-tracker-l1"},
    "xiao-nrf52": {"chip": "nrf52840", "elf": "firmware-xiao-nrf52"},
    "heltec-v3": {
        "chip": "esp32s3",
        "elf": "firmware-heltec-v3",
        # No BOARDS entry: this board has no UF2 bootloader, so it has no
        # family id or app base to record there.
        "name": "Heltec WiFi LoRa 32 V3",
        "flash_methods": ["esp-serial"],
        "esp": {
            "chip": "esp32s3",
            "offset": "0x0",
            "flash_size": "4MB",
            "partition_table": "partitions-umsh.csv",
        },
    },
}


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dfu_sd_req(zip_path: str) -> str | None:
    """Read the SoftDevice requirement back out of a DFU package.

    adafruit-nrfutil records `--sd-req` in the package's own manifest, so
    reading it here reports what the artifact actually demands instead of
    repeating the Makefile's value and hoping the two agree.
    """
    try:
        with zipfile.ZipFile(zip_path) as archive:
            manifest = json.loads(archive.read("manifest.json"))
        required = manifest["manifest"]["application"]["init_packet_data"][
            "softdevice_req"
        ]
    except (KeyError, ValueError, zipfile.BadZipFile) as exc:
        print(f"release.py: cannot read sd-req from {zip_path}: {exc}",
              file=sys.stderr)
        return None
    return ", ".join(f"0x{value:04X}" for value in required)


def git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args], capture_output=True, text=True, check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return result.stdout.strip()


def tool_version(*command: str) -> str | None:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return result.stdout.strip() or None


def board_files(board_id: str, spec: dict, version: str, directory: str) -> list[dict]:
    """Every artifact this board is expected to have contributed."""
    names = []
    if spec["chip"] == "nrf52840":
        names.append(("uf2", f"umsh-{board_id}-{version}.uf2"))
        names.append(("dfu-zip", f"umsh-{board_id}-{version}-dfu.zip"))
    else:
        names.append(("merged-bin", f"umsh-{board_id}-{version}.bin"))

    files = []
    for role, name in names:
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        entry = {
            "role": role,
            "name": name,
            "size": os.path.getsize(path),
            "sha256": sha256_of(path),
        }
        if role == "dfu-zip":
            sd_req = dfu_sd_req(path)
            if sd_req:
                entry["sd_req"] = sd_req
        files.append(entry)
    return files


def board_entry(board_id: str, spec: dict, version: str, directory: str) -> dict:
    preset = BOARDS.get(board_id)
    entry = {
        "id": board_id,
        "name": spec.get("name") or preset["description"],
        "chip": spec["chip"],
    }
    # The string this board's firmware reports as PROP_DEV_MODEL, so a host
    # that has a device attached can find its entry without guessing.
    entry["model"] = entry["name"]

    if preset is not None:
        entry["flash_methods"] = ["uf2", "serial-dfu"]
        entry["uf2"] = {
            "family_id": f"0x{preset['family']:08X}",
            "app_base": f"0x{preset['base']:08X}",
            "volume": os.path.basename(preset["mount"]),
        }
    else:
        entry["flash_methods"] = spec["flash_methods"]
        entry["esp"] = spec["esp"]

    entry["files"] = board_files(board_id, spec, version, directory)
    return entry


def version_key(version: str):
    """Sort key that orders 2026.08.09 before 2026.08.10.

    Zero-padded date versions already sort correctly as strings, but this
    keeps working if the scheme moves to semver, where 1.10.0 must come
    after 1.9.0.
    """
    parts = version.split(".")
    if all(part.isdigit() for part in parts):
        return (0, [int(part) for part in parts])
    return (1, version)


def index_mirror(root: str, keep: int) -> int:
    """Rebuild `releases.json`, refresh `manifest.json`, prune old versions.

    The published tree holds one directory per mirrored release. This reads
    each one's own manifest for the index, points the top-level manifest at
    the newest, and deletes the oldest beyond `keep` — the artifacts stay
    on GitHub Releases forever, so pruning here costs nothing but a click.
    """
    if not os.path.isdir(root):
        print(f"release.py: no such mirror directory: {root}", file=sys.stderr)
        return 1

    releases = []
    for name in os.listdir(root):
        manifest_path = os.path.join(root, name, "manifest.json")
        if not os.path.isfile(manifest_path):
            continue
        with open(manifest_path) as fh:
            release = json.load(fh)["release"]
        releases.append({
            "version": release["version"],
            "tag": release["tag"],
            "date": release["date"],
            "channel": release["channel"],
            "manifest": f"/firmware/{release['version']}/manifest.json",
        })

    if not releases:
        print(f"release.py: no version directories under {root}",
              file=sys.stderr)
        return 1

    releases.sort(key=lambda entry: version_key(entry["version"]), reverse=True)

    for stale in releases[keep:]:
        victim = os.path.join(root, stale["version"])
        shutil.rmtree(victim)
        print(f"release.py: pruned {victim} (kept {keep})")
    releases = releases[:keep]

    with open(os.path.join(root, "releases.json"), "w") as fh:
        json.dump(releases, fh, indent=2)
        fh.write("\n")

    # The flasher's one-fetch entry point: a copy of the newest release's
    # manifest, so the common case needs no indirection through the index.
    current = releases[0]["version"]
    shutil.copyfile(
        os.path.join(root, current, "manifest.json"),
        os.path.join(root, "manifest.json"),
    )
    print(f"release.py: mirror indexed, current = {current}, "
          f"{len(releases)} version(s) published")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Write manifest.json and SHA256SUMS for a staged release.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", metavar="X.Y.Z",
                        help="release version, e.g. 2026.08.01 (no `fw-`)")
    parser.add_argument("--dir", metavar="PATH",
                        help="staging directory (default: "
                             "target/firmware-release/<version>)")
    parser.add_argument("--repo", default=DEFAULT_REPO, metavar="OWNER/NAME",
                        help=f"GitHub repository (default: {DEFAULT_REPO})")
    parser.add_argument("--channel", default="preview", metavar="NAME",
                        help="release channel (default: preview)")
    parser.add_argument("--index-mirror", metavar="PATH",
                        help="instead of indexing a staged release, rebuild "
                             "the published mirror's releases.json and "
                             "manifest.json under PATH, pruning old versions")
    parser.add_argument("--keep", type=int, default=3, metavar="N",
                        help="versions to keep with --index-mirror (default: 3)")
    args = parser.parse_args(argv)

    if args.index_mirror:
        return index_mirror(args.index_mirror, args.keep)
    if not args.version:
        parser.error("--version is required unless --index-mirror is given")

    version = args.version
    tag = f"fw-{version}"
    directory = args.dir or os.path.join("target", "firmware-release", version)

    if not os.path.isdir(directory):
        print(f"release.py: no such staging directory: {directory}",
              file=sys.stderr)
        print("release.py: run `make release-artifacts VERSION=…` first",
              file=sys.stderr)
        return 1

    download = f"https://github.com/{args.repo}/releases/download/{tag}"

    boards = []
    for board_id, spec in RELEASE_BOARDS.items():
        try:
            entry = board_entry(board_id, spec, version, directory)
        except FileNotFoundError as missing:
            # A board that failed to build must not ship a release that
            # silently omits it.
            print(f"release.py: missing artifact: {missing}", file=sys.stderr)
            print(f"release.py: {board_id} did not produce every expected "
                  f"file; the release is incomplete.", file=sys.stderr)
            return 1
        for entry_file in entry["files"]:
            entry_file["url"] = f"{download}/{entry_file['name']}"
            entry_file["path"] = (
                f"/firmware/{version}/{entry_file['name']}"
                if entry_file["role"] in MIRRORED_ROLES
                else None
            )
        boards.append(entry)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "release": {
            "version": version,
            "tag": tag,
            "date": (git("log", "-1", "--format=%cs", tag) or ""),
            "commit": (git("rev-parse", tag + "^{commit}") or ""),
            "channel": args.channel,
            "release_url": f"https://github.com/{args.repo}/releases/tag/{tag}",
        },
        "build": {
            "rustc": tool_version("rustc", "--version"),
            "rustc_xtensa": tool_version("rustup", "run", "esp", "rustc",
                                         "--version"),
            "host": (tool_version("uname", "-sm") or "").replace(" ", "-"),
        },
        "boards": boards,
    }

    manifest_path = os.path.join(directory, "manifest.json")
    with open(manifest_path, "w") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    print(f"release.py: wrote {manifest_path}")

    # `shasum -c SHA256SUMS` format: digest, two spaces, name. Sorted so a
    # rebuild of the same release produces an identical file.
    sums_path = os.path.join(directory, "SHA256SUMS")
    lines = sorted(
        f"{entry_file['sha256']}  {entry_file['name']}"
        for board in boards
        for entry_file in board["files"]
    )
    with open(sums_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"release.py: wrote {sums_path} ({len(lines)} artifacts)")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
