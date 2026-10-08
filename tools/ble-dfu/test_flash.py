"""Exercise package and target selection without sending anything to hardware."""

import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
import zipfile

import flash


TARGET = "2AD68D62-CE25-1C16-2E62-D2161305B683"
OTHER = "12345678-1234-1234-1234-123456789ABC"


class UploadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.package = Path(self.directory.name) / "application.zip"
        self.write_package()
        self.device = SimpleNamespace(address=TARGET, name="AdaDFU")
        advertisement = SimpleNamespace(service_uuids=[flash.DFU_SERVICE_UUID.upper()])
        self.discover = AsyncMock(return_value={TARGET: (self.device, advertisement)})
        self.updater = SimpleNamespace(
            parse_zip=Mock(), upload_mode=4, perform_update=AsyncMock(),
        )
        self.backend = SimpleNamespace(
            BleakScanner=SimpleNamespace(discover=self.discover),
            NordicLegacyDFU=Mock(return_value=self.updater),
            UPLOAD_MODE_APPLICATION=4,
        )
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def write_package(self, sd_req=0x0123, extra=None):
        manifest = {
            "dfu_version": 0.5,
            "application": {
                "bin_file": "application.bin", "dat_file": "application.dat",
                "init_packet_data": {"softdevice_req": [sd_req]},
            },
        }
        if extra:
            manifest[extra] = {}
        with zipfile.ZipFile(self.package, "w") as package:
            package.writestr("manifest.json", json.dumps({"manifest": manifest}))
            package.writestr("application.bin", b"application fixture")
            package.writestr("application.dat", b"init fixture")

    async def test_upload_selects_exact_bootloader_with_no_jump_or_retry(self):
        self.discover.return_value[OTHER] = (
            SimpleNamespace(address=OTHER, name="AdaDFU"),
            SimpleNamespace(service_uuids=[flash.DFU_SERVICE_UUID]),
        )
        await flash.upload(self.backend, self.package, TARGET.lower())
        self.updater.perform_update.assert_awaited_once_with(self.device, max_retries=1)

    async def test_missing_target_never_falls_back_to_another_bootloader(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            await flash.upload(self.backend, self.package, OTHER)
        self.backend.NordicLegacyDFU.assert_not_called()

    async def test_matching_address_without_dfu_service_is_rejected(self):
        self.discover.return_value[TARGET][1].service_uuids = []
        with self.assertRaisesRegex(ValueError, "not found"):
            await flash.upload(self.backend, self.package, TARGET)
        self.backend.NordicLegacyDFU.assert_not_called()

    async def test_wrong_package_is_rejected_before_bluetooth_access(self):
        for options in [{"sd_req": 0x00B6}, {"extra": "bootloader"}, {"extra": "softdevice"}]:
            with self.subTest(options=options):
                self.write_package(**options)
                with self.assertRaises(ValueError):
                    await flash.upload(self.backend, self.package, TARGET)
        self.discover.assert_not_awaited()

    async def test_failed_transfer_propagates_without_another_attempt(self):
        self.updater.perform_update.side_effect = RuntimeError("Validation failed")
        with self.assertRaisesRegex(RuntimeError, "Validation failed"):
            await flash.upload(self.backend, self.package, TARGET)
        self.updater.perform_update.assert_awaited_once()


class CommandTests(unittest.TestCase):
    def test_device_names_are_not_identifiers(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            flash.address("AdaDFU")
        self.assertEqual(flash.address(TARGET.lower()), TARGET)
        self.assertEqual(flash.address("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")

    def test_cli_reports_failure_with_nonzero_exit(self):
        with patch.object(flash, "load_backend", return_value=object()):
            with patch.object(flash, "run", new=AsyncMock(side_effect=RuntimeError("lost link"))):
                with contextlib.redirect_stderr(io.StringIO()) as error:
                    result = flash.main(["--upstream", ".", "flash", "app.zip", "--address", TARGET])
        self.assertEqual(result, 1)
        self.assertIn("lost link", error.getvalue())


if __name__ == "__main__":
    unittest.main()
