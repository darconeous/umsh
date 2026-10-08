#!/usr/bin/env python3
"""Upload an application to an already active Nordic legacy BLE DFU service.

Uses the unmodified nrf_dfu_py library; see README.md for the tested revision
and isolated Python environment. No bootloader-entry command is sent.
"""

import argparse
import asyncio
import hashlib
import importlib
import json
import logging
from pathlib import Path
import re
import sys
import time
import uuid
import zipfile


DFU_SERVICE_UUID = "00001530-1212-efde-1523-785feabcd123"


def address(value):
    """Accept a CoreBluetooth UUID or a Bluetooth MAC, never a shared name."""
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        return value.upper()
    try:
        return str(uuid.UUID(value)).upper()
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a bootloader UUID or MAC address") from error


def validate_package(path):
    """Reject other image types and SoftDevice layouts before connecting."""
    with zipfile.ZipFile(path) as package:
        manifest = json.loads(package.read("manifest.json"))["manifest"]
        if set(manifest) - {"dfu_version"} != {"application"}:
            raise ValueError("An application-only DFU package is required")
        application = manifest["application"]
        if application["init_packet_data"]["softdevice_req"] != [0x0123]:
            raise ValueError("BLE DFU upload requires S140 7.3.0 (0x0123)")
        firmware = package.read(application["bin_file"])
        if not firmware or not package.read(application["dat_file"]):
            raise ValueError("The application or init packet is empty")
        return len(firmware), hashlib.sha256(firmware).hexdigest()


def load_backend(upstream):
    if not (upstream / "dfu_lib.py").is_file():
        raise ValueError("nrf_dfu_py was not found; run make install-ble-dfu-setup")
    sys.path.insert(0, str(upstream.resolve()))
    try:
        return importlib.import_module("dfu_lib")
    except ImportError as error:
        raise ValueError(
            "BLE uploader dependencies are missing; run make install-ble-dfu-setup"
        ) from error


async def discover(backend):
    discoveries = await backend.BleakScanner.discover(
        timeout=10, return_adv=True, service_uuids=[DFU_SERVICE_UUID]
    )
    # Check the advertisement too: some backends may return cached entries.
    return [
        device for device, advertisement in discoveries.values()
        if DFU_SERVICE_UUID in [value.lower() for value in advertisement.service_uuids]
    ]


async def upload(backend, package, target):
    size, digest = validate_package(package)
    print(f"Application: {size} bytes, SHA-256 {digest}", flush=True)
    devices = await discover(backend)
    device = next((item for item in devices if item.address.upper() == target.upper()), None)
    if device is None:
        raise ValueError(f"BLE DFU bootloader {target} was not found; no update sent")
    print(f"Uploading to {device.address} ({device.name or 'unnamed'})", flush=True)
    started = time.monotonic()

    def progress(percent):
        if percent % 5 == 0:
            print(f"Upload {percent}% ({time.monotonic() - started:.1f}s)", flush=True)

    updater = backend.NordicLegacyDFU(
        str(package), prn=8, packet_delay=0.4, high_mtu=False,
        progress_callback=progress,
    )
    updater.parse_zip()
    if updater.upload_mode != backend.UPLOAD_MODE_APPLICATION:
        raise ValueError("The uploader did not select an application-only update")
    # Use the already identified bootloader. The upstream CLI's buttonless
    # jump and broad bootloader search do not apply to this operation.
    await updater.perform_update(device, max_retries=1)
    print(
        f"Transfer and validation completed in {time.monotonic() - started:.1f}s; "
        "activation requested. Verify the application version after reboot.",
        flush=True,
    )


async def run(args, backend):
    if args.command == "check":
        return
    if args.command == "scan":
        devices = await discover(backend)
        for device in devices:
            print(f"{device.address}  {device.name or '(no name)'}")
        if not devices:
            print("No BLE DFU bootloaders found")
        return
    await upload(backend, args.package, args.address)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, type=Path, help="nrf_dfu_py checkout")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="check uploader dependencies without Bluetooth access")
    commands.add_parser("scan", help="list nearby legacy DFU bootloader UUIDs/addresses")
    flash = commands.add_parser("flash", help="upload an application to its bootloader")
    flash.add_argument("package", type=Path)
    flash.add_argument("--address", required=True, type=address)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        asyncio.run(run(args, load_backend(args.upstream)))
    except KeyboardInterrupt:
        print("BLE DFU interrupted", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"BLE DFU failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
