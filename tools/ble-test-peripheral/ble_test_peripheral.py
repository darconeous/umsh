"""A UMSH radio's BLE side, for the Android emulator.

Serves the ULCP GATT service (`docs/protocol-legacy/src/ulcp-ble.md`) from the
emulator's shared virtual Bluetooth (netsim), and carries its frames to a
`umsh-bridge` host interface over TCP, so an app on an AVD scans, pairs,
attaches and talks to a real device session. It mirrors the radios' BLE
behavior, not more: encryption (not authentication) on Frame In and on Frame
Out's CCCD, LE Secure Connections with bonding, Just Works or a fixed passkey,
one central at a time, resolvable private addresses from a persisted IRK, and
the pairing-mode advertising payloads.

Commands on stdin drive the faults the app must survive; `help` lists them.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import secrets
import sys
import unicodedata
from collections.abc import Iterable
from pathlib import Path

# ---------------------------------------------------------------------------
# Codecs. Checked against the Rust implementations through the committed
# vectors in tests/vectors.json (`make ble-test-vectors` regenerates them).

SAR_COMPLETE, SAR_FIRST, SAR_CONT, SAR_LAST = 0, 1, 2, 3
MAX_FRAME = 512

HDLC_FLAG, HDLC_ESCAPE, HDLC_XOR = 0x7E, 0x7D, 0x20
HDLC_XON, HDLC_XOFF, HDLC_TEXT, HDLC_FILL = 0x11, 0x13, 0x23, 0xFF


def gatt_segments(frame: bytes, max_value_length: int) -> list[bytes]:
    """Split a frame into ATT values of at most `max_value_length` octets,
    each led by its SAR header octet."""
    size = max_value_length - 1
    if size <= 0:
        raise ValueError("ATT value too small for a segment")
    if len(frame) > MAX_FRAME:
        raise ValueError("frame too long")
    if len(frame) <= size:
        return [bytes([SAR_COMPLETE << 6]) + frame]
    out = []
    for start in range(0, len(frame), size):
        end = min(start + size, len(frame))
        sar = SAR_FIRST if start == 0 else SAR_LAST if end == len(frame) else SAR_CONT
        out.append(bytes([sar << 6]) + frame[start:end])
    return out


class Reassembler:
    """Frame In reassembly, as `umsh_ulcp::gatt::Reassembler`."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.buf = bytearray()
        self.in_progress = False
        self.discarding = False

    def push(self, value: bytes) -> bytes | str | None:
        """A complete frame, an error name, or None while a frame is pending."""
        if not value:
            self.reset()
            return "runt"
        header, payload = value[0], value[1:]
        if header & 0x3F:
            self.reset()
            return "reserved"
        sar = header >> 6
        if sar in (SAR_COMPLETE, SAR_FIRST):
            self.reset()
        elif self.discarding:
            return None
        elif not self.in_progress:
            return "orphan"
        if len(payload) > MAX_FRAME - len(self.buf):
            self.buf = bytearray()
            self.in_progress = False
            self.discarding = True
            return "too_long"
        self.buf += payload
        if sar in (SAR_FIRST, SAR_CONT):
            self.in_progress = True
            return None
        self.in_progress = False
        return bytes(self.buf)


def crc16_x25(data: bytes) -> int:
    fcs = 0xFFFF
    for byte in data:
        fcs ^= byte
        for _ in range(8):
            fcs = (fcs >> 1) ^ 0x8408 if fcs & 1 else fcs >> 1
    return fcs ^ 0xFFFF


def hdlc_encode(frame: bytes) -> bytes:
    out = bytearray([HDLC_FLAG])
    for byte in frame + crc16_x25(frame).to_bytes(2, "little"):
        if byte in (HDLC_FLAG, HDLC_ESCAPE, HDLC_XON, HDLC_XOFF):
            out += bytes([HDLC_ESCAPE, byte ^ HDLC_XOR])
        else:
            out.append(byte)
    out.append(HDLC_FLAG)
    return bytes(out)


class HdlcDecoder:
    """HDLC-Lite stream decoder with ULCP's rules: bare XON/XOFF skipped,
    marked text and fill skipped to the next flag, bad frames dropped."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.buf = bytearray()
        self.escaped = False
        self.skipping = False
        self.overflow = False

    def push(self, data: Iterable[int]) -> list[bytes]:
        """Every valid frame `data` completes; corrupt ones are dropped.
        A line-for-line port of `umsh_ulcp::hdlc::Decoder::push`."""
        frames = []
        for byte in data:
            if byte in (HDLC_XON, HDLC_XOFF):
                continue
            if self.skipping:
                if byte == HDLC_FLAG:
                    self.skipping = False
                continue
            if byte == HDLC_FLAG:
                escaped, overflow, buf = self.escaped, self.overflow, self.buf
                self.escaped, self.overflow, self.buf = False, False, bytearray()
                if escaped or overflow or len(buf) < 2:
                    continue
                body, fcs = bytes(buf[:-2]), buf[-2:]
                if crc16_x25(body) == int.from_bytes(fcs, "little"):
                    frames.append(body)
                continue
            if (
                byte in (HDLC_TEXT, HDLC_FILL)
                and not self.buf
                and not self.escaped
                and not self.overflow
            ):
                self.skipping = True
                continue
            if byte == HDLC_ESCAPE:
                self.escaped = True
                continue
            if self.escaped:
                byte ^= HDLC_XOR
                self.escaped = False
            if len(self.buf) < MAX_FRAME + 2:
                self.buf.append(byte)
            else:
                self.overflow = True
        return frames


# ---------------------------------------------------------------------------
# The peripheral. Bumble is imported here so the codec tests need none of it.

SERVICE_UUID = "21EB6B15-0001-4CCF-92E4-A079171BEC97"
FRAME_IN_UUID = "21EB6B15-0002-4CCF-92E4-A079171BEC97"
FRAME_OUT_UUID = "21EB6B15-0003-4CCF-92E4-A079171BEC97"
COMPANY_ID = 0xFFFF
DEFAULT_TRANSPORT = "android-netsim:name=umsh-radio"
FALLBACK_TRANSPORT = "tcp-client:127.0.0.1:6402"

log = logging.getLogger("ble-test-peripheral")


def _regional_indicator(char: str) -> bool:
    return 0x1F1E6 <= ord(char) <= 0x1F1FF


def _joined(before: str, after: str) -> bool:
    """No cluster boundary between two code points, for what a radio's name holds.

    A stand-in for UAX #29, which the firmware applies (`umsh_grapheme`):
    marks, variation selectors, skin tones, emoji tags and zero-width
    joiners stay with what they follow, and a joiner with what comes after
    it. Hangul syllable sequences and Indic conjuncts are not modeled.
    """
    code = ord(after)
    return (
        unicodedata.category(after) in ("Mn", "Mc", "Me")
        or code == 0x200D
        or 0xFE00 <= code <= 0xFE0F
        or 0x1F3FB <= code <= 0x1F3FF
        or 0xE0020 <= code <= 0xE007F
        or ord(before) == 0x200D
    )


def cut_name(name: str, limit: int) -> str:
    """The longest prefix of `name` within `limit` octets of UTF-8 that ends between clusters."""
    end = 0
    size = 0
    for char in name:
        width = len(char.encode())
        if size + width > limit:
            break
        size += width
        end += 1
    while 0 < end < len(name):
        before, after = name[end - 1], name[end]
        if _joined(before, after):
            end -= 1
            continue
        if _regional_indicator(before) and _regional_indicator(after):
            run = 0
            while run < end and _regional_indicator(name[end - 1 - run]):
                run += 1
            # An odd run ends in the first half of a flag.
            if run % 2:
                end -= 1
                continue
        break
    return name[:end]


def advertising_payloads(pairing: bool, name: str, model_id: int) -> tuple[bytes, bytes]:
    """Primary and scan-response data, as `umsh_ulcp_runtime::ble_privacy`."""
    import uuid

    service_le = uuid.UUID(SERVICE_UUID).bytes[::-1]
    adv = bytes([2, 0x01, 0x06 if pairing else 0x04, 17, 0x07]) + service_le
    if not pairing:
        return adv, b""
    adv += bytes([5, 0xFF]) + COMPANY_ID.to_bytes(2, "little") + model_id.to_bytes(2, "big")
    raw = name.encode()
    cut = cut_name(name, 29).encode()
    scan = bytes([len(cut) + 1, 0x09 if cut == raw else 0x08]) + cut if cut else b""
    return adv, scan


class Radio:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.state_dir = Path(args.state).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.pairing_window = args.pairing_window
        self.advertising_wanted = True
        self.refuse_cccd = False
        self.write_delay = 0.0
        self.connection = None
        self.subscribed = False
        self.reassembler = Reassembler()
        self.decoder = HdlcDecoder()
        self.bridge_writer: asyncio.StreamWriter | None = None
        self.bridge_task: asyncio.Task | None = None
        self.notify_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.loop_tasks: list[asyncio.Task] = []

    # -- persisted identity ------------------------------------------------

    def load_identity(self) -> tuple[str, bytes]:
        path = self.state_dir / "identity.json"
        if path.exists():
            data = json.loads(path.read_text())
            return data["address"], bytes.fromhex(data["irk"])
        return self.new_identity()

    def new_identity(self) -> tuple[str, bytes]:
        raw = bytearray(secrets.token_bytes(6))
        raw[0] |= 0xC0  # static random: the two top bits set
        address = ":".join(f"{b:02X}" for b in raw)
        irk = secrets.token_bytes(16)
        (self.state_dir / "identity.json").write_text(
            json.dumps({"address": address, "irk": irk.hex()}, indent=2) + "\n"
        )
        return address, irk

    async def adopt_identity(self, address: str, irk: bytes) -> None:
        """The identity address and IRK a bond is given (and RPAs come from)."""
        from bumble import hci

        self.irk = irk
        self.device.irk = irk
        self.device.static_address = hci.Address(address, hci.Address.RANDOM_DEVICE_ADDRESS)

    # -- setup -------------------------------------------------------------

    async def run(self) -> None:
        from bumble import hci
        from bumble.device import Device, DeviceConfiguration
        from bumble.gatt import Characteristic, CharacteristicValue, Service
        from bumble.keys import JsonKeyStore
        from bumble.pairing import PairingConfig, PairingDelegate
        from bumble.transport import open_transport

        address, irk = self.load_identity()
        transport_spec = self.args.transport
        log.info("opening %s", transport_spec)
        try:
            transport = await open_transport(transport_spec)
        except Exception as error:  # noqa: BLE001 - any failure falls back
            if transport_spec != DEFAULT_TRANSPORT:
                raise
            log.warning("%s failed (%s); trying %s", transport_spec, error, FALLBACK_TRANSPORT)
            transport = await open_transport(FALLBACK_TRANSPORT)

        async with transport:
            config = DeviceConfiguration()
            config.name = self.args.name
            config.address = hci.Address(address, hci.Address.RANDOM_DEVICE_ADDRESS)
            config.irk = irk
            config.le_privacy_enabled = False  # addresses are managed here
            config.keystore = "JsonKeyStore"
            device = Device.from_config_with_hci(config, transport.source, transport.sink)
            device.keystore = JsonKeyStore(
                namespace="umsh-radio", filename=str(self.state_dir / "bonds.json")
            )
            self.device = device
            await self.adopt_identity(address, irk)
            device.gatt_server.max_mtu = self.args.mtu

            self.frame_in = Characteristic(
                FRAME_IN_UUID,
                Characteristic.Properties.WRITE | Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
                Characteristic.Permissions.WRITEABLE
                | Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
                CharacteristicValue(write=self.on_frame_in),
            )
            self.frame_out = Characteristic(
                FRAME_OUT_UUID,
                Characteristic.Properties.NOTIFY,
                Characteristic.Permissions(0),
                b"",
            )
            device.add_service(Service(SERVICE_UUID, [self.frame_in, self.frame_out]))
            self.protect_cccd()
            self.frame_out.on("subscription", self.on_subscription)

            io = (
                PairingDelegate.IoCapability.DISPLAY_OUTPUT_ONLY
                if self.args.passkey is not None
                else PairingDelegate.IoCapability.NO_OUTPUT_NO_INPUT
            )
            passkey = self.args.passkey

            class Delegate(PairingDelegate):
                async def generate_passkey(self) -> int:
                    return passkey if passkey is not None else 0

                async def display_number(self, number: int, digits: int) -> None:
                    log.info("passkey %0*d", digits, number)

            device.pairing_config_factory = lambda _connection: PairingConfig(
                sc=True,
                mitm=passkey is not None,
                bonding=True,
                delegate=Delegate(io_capability=io),
                identity_address_type=PairingConfig.AddressType.RANDOM,
            )

            device.on("connection", self.on_connection)
            await device.power_on()
            log.info(
                "identity %s, pairing %s, window %s",
                address,
                f"passkey {passkey:06d}" if passkey is not None else "just works",
                "open" if self.pairing_window else "closed",
            )
            await self.new_rpa()
            await self.advertise()
            self.loop_tasks.append(asyncio.create_task(self.notify_pump()))
            if self.args.rpa_seconds > 0:
                self.loop_tasks.append(asyncio.create_task(self.rotate_periodically()))
            await self.repl()

    def protect_cccd(self) -> None:
        """The radios protect Frame Out's CCCD: encryption required to
        subscribe. Bumble makes the descriptor itself, so mark it here."""
        from bumble import att, gatt

        found = False
        for attribute in self.device.gatt_server.attributes:
            if (
                attribute.handle > self.frame_out.handle
                and attribute.type == gatt.GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
            ):
                attribute.permissions |= att.Attribute.WRITE_REQUIRES_ENCRYPTION
                found = True
                break
        if not found:
            raise RuntimeError("Frame Out has no CCCD")

    # -- advertising and addresses ----------------------------------------

    async def advertise(self) -> None:
        from bumble.device import AdvertisingType

        if self.connection is not None or not self.advertising_wanted:
            return
        adv, scan = advertising_payloads(self.pairing_window, self.args.name, self.args.model_id)
        await self.device.start_advertising(
            advertising_type=AdvertisingType.UNDIRECTED_CONNECTABLE_SCANNABLE,
            advertising_data=adv,
            scan_response_data=scan,
            advertising_interval_min=100,
            advertising_interval_max=100,
        )
        log.info(
            "advertising from %s (%s)",
            self.device.random_address,
            "pairing window" if self.pairing_window else "service UUID only",
        )

    async def new_rpa(self) -> None:
        from bumble import hci

        was_advertising = self.device.is_advertising
        if was_advertising:
            await self.device.stop_advertising()
        rpa = hci.Address.generate_private_address(self.irk)
        await self.device.send_command(hci.HCI_LE_Set_Random_Address_Command(random_address=rpa))
        self.device.random_address = rpa
        log.info("address now %s", rpa)
        if was_advertising:
            await self.advertise()

    async def rotate_periodically(self) -> None:
        while True:
            await asyncio.sleep(self.args.rpa_seconds)
            if self.connection is None:
                await self.new_rpa()

    async def set_window(self, open_: bool) -> None:
        if self.pairing_window == open_:
            return
        self.pairing_window = open_
        if self.connection is None:
            await self.new_rpa()
            await self.advertise()

    # -- connection --------------------------------------------------------

    def on_connection(self, connection) -> None:
        if self.connection is not None:
            log.warning("second central %s refused", connection.peer_address)
            asyncio.create_task(connection.disconnect())
            return
        log.info("connected: %s", connection.peer_address)
        self.connection = connection
        self.reassembler.reset()
        connection.on("disconnection", lambda reason: self.on_disconnection(connection, reason))
        connection.on("pairing", lambda keys: self.on_pairing(connection))
        connection.on("pairing_failure", lambda reason: log.info("pairing failed: %s", reason))
        connection.on(
            "connection_encryption_change",
            lambda *_: log.info("encryption %s", "on" if connection.is_encrypted else "off"),
        )
        connection.on(
            "connection_att_mtu_update", lambda *_: log.info("ATT MTU %d", connection.att_mtu)
        )

    def on_pairing(self, connection) -> None:
        log.info("bonded with %s", connection.peer_address)
        # A new bond closes the pairing window, as the radios do.
        if self.pairing_window:
            self.pairing_window = False
            log.info("pairing window closed")

    def on_disconnection(self, connection, reason) -> None:
        log.info("disconnected: %s", reason)
        if self.connection is connection:
            self.connection = None
            self.detach()
            asyncio.create_task(self.after_disconnection())

    async def after_disconnection(self) -> None:
        # Leaving a window refreshes the address, deferred until now.
        await self.new_rpa()
        await self.advertise()

    def on_subscription(self, bearer, notify: bool, _indicate: bool) -> None:
        if notify and not self.subscribed:
            self.subscribed = True
            log.info("attached: notifications on")
            self.attach()
        elif not notify and self.subscribed:
            log.info("detached: notifications off")
            self.detach()

    async def on_frame_in(self, connection, value: bytes) -> None:
        if self.write_delay:
            await asyncio.sleep(self.write_delay)
        result = self.reassembler.push(bytes(value))
        if result is None:
            return
        if isinstance(result, str):
            log.warning("Frame In segment dropped: %s", result)
            return
        if self.args.loopback:
            await self.send_frame(result)
        elif self.bridge_writer is not None:
            self.bridge_writer.write(hdlc_encode(result))
        else:
            log.info("frame of %d octets dropped: not attached", len(result))

    # -- bridge ------------------------------------------------------------

    def attach(self) -> None:
        self.decoder.reset()
        if self.args.loopback:
            return
        if self.bridge_task is None:
            self.bridge_task = asyncio.create_task(self.bridge())

    def detach(self) -> None:
        self.subscribed = False
        if self.bridge_task is not None:
            self.bridge_task.cancel()
            self.bridge_task = None
        if self.bridge_writer is not None:
            self.bridge_writer.close()
            self.bridge_writer = None
        while not self.notify_queue.empty():
            self.notify_queue.get_nowait()

    async def bridge(self) -> None:
        """One TCP session to the bridge per attachment: the host interface
        starts a fresh device session, as a radio resets its own on attach."""
        host, port = self.args.bridge.rsplit(":", 1)
        while True:
            try:
                reader, writer = await asyncio.open_connection(host, int(port))
            except OSError as error:
                log.warning("bridge %s: %s; retrying", self.args.bridge, error)
                await asyncio.sleep(2)
                continue
            log.info("bridge %s connected", self.args.bridge)
            self.bridge_writer = writer
            try:
                while chunk := await reader.read(4096):
                    for frame in self.decoder.push(chunk):
                        await self.send_frame(frame)
            finally:
                self.bridge_writer = None
                writer.close()
            log.warning("bridge closed; the link goes down with it")
            if self.connection is not None:
                await self.connection.disconnect()
            return

    async def send_frame(self, frame: bytes) -> None:
        if self.connection is None:
            return
        for value in gatt_segments(frame, self.connection.att_mtu - 3):
            self.notify_queue.put_nowait(value)

    async def notify_pump(self) -> None:
        while True:
            value = await self.notify_queue.get()
            if self.connection is None or not self.subscribed:
                continue
            await self.device.notify_subscribers(self.frame_out, value)

    # -- faults ------------------------------------------------------------

    async def repl(self) -> None:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
        print(HELP, flush=True)
        while line := await reader.readline():
            words = line.decode().split()
            if not words:
                continue
            try:
                await self.command(words)
            except Exception as error:  # noqa: BLE001 - report and carry on
                log.error("%s: %s", " ".join(words), error)
            if words[0] == "quit":
                break
        for task in self.loop_tasks:
            task.cancel()

    async def command(self, words: list[str]) -> None:
        verb, rest = words[0], words[1:]
        if verb == "help":
            print(HELP, flush=True)
        elif verb == "drop":
            if self.connection is not None:
                await self.connection.disconnect()
        elif verb == "adv":
            self.advertising_wanted = rest == ["on"]
            if self.advertising_wanted:
                await self.advertise()
            else:
                await self.device.stop_advertising()
                log.info("advertising off")
        elif verb == "window":
            await self.set_window(rest == ["on"])
        elif verb == "refuse-cccd":
            self.refuse_cccd = rest != ["off"]
            self.apply_cccd_refusal()
        elif verb == "forget-bond":
            await self.device.keystore.delete_all()
            log.info("every bond forgotten (this radio no longer knows the phone)")
        elif verb == "factory-reset":
            await self.device.keystore.delete_all()
            await self.adopt_identity(*self.new_identity())
            log.info("factory reset: every bond forgotten, new identity and IRK")
            if self.connection is not None:
                await self.connection.disconnect()
            self.pairing_window = True
            await self.new_rpa()
            await self.advertise()
        elif verb == "slow-writes":
            self.write_delay = int(rest[0]) / 1000
            log.info("each Frame In write takes %d ms", int(rest[0]))
        elif verb == "mtu":
            self.device.gatt_server.max_mtu = int(rest[0])
            log.info("ATT MTU offered on the next exchange: %d", int(rest[0]))
        elif verb == "rotate":
            await self.new_rpa()
        elif verb == "service-changed":
            await self.service_changed()
        elif verb == "status":
            log.info(
                "connected %s, attached %s, address %s, window %s",
                self.connection.peer_address if self.connection else "no",
                self.subscribed,
                self.device.random_address,
                self.pairing_window,
            )
        elif verb == "quit":
            pass
        else:
            print(f"unknown command {verb!r}", flush=True)

    def apply_cccd_refusal(self) -> None:
        """Refuse the phone's write to Frame Out's CCCD with Insufficient
        Authentication, as a radio that lost its keys does (the API 31–35
        bond-loss path). Bumble counts every encrypted LE link as
        authenticated, so the attribute's permission flags never refuse
        it: the write itself is answered here."""
        from bumble import att, gatt

        for attribute in self.device.gatt_server.attributes:
            if (
                attribute.handle > self.frame_out.handle
                and attribute.type == gatt.GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
            ):
                if not getattr(attribute, "umsh_refusable", False):
                    accept = attribute.write_value

                    async def write_value(bearer, value, accept=accept, handle=attribute.handle):
                        if self.refuse_cccd:
                            log.info("CCCD write refused")
                            raise att.ATT_Error(
                                error_code=att.ATT_INSUFFICIENT_AUTHENTICATION_ERROR,
                                att_handle=handle,
                            )
                        await accept(bearer, value)

                    attribute.write_value = write_value
                    attribute.umsh_refusable = True
                log.info("CCCD writes %s", "refused" if self.refuse_cccd else "accepted")
                return

    async def service_changed(self) -> None:
        from bumble import gatt

        service = self.device.gatt_service
        if service is None or service.service_changed_characteristic is None:
            log.warning("no Service Changed characteristic")
            return
        value = (1).to_bytes(2, "little") + (0xFFFF).to_bytes(2, "little")
        del gatt
        await self.device.indicate_subscribers(service.service_changed_characteristic, value)
        log.info("Service Changed indicated")


HELP = """commands:
  drop                 disconnect the central
  adv on|off           advertise or go silent (presence; the CDM dialog's closed window)
  window on|off        open or close the pairing window (new address either way)
  refuse-cccd [off]    refuse Frame Out's CCCD write (bond lost, API 31-35 path)
  forget-bond          forget every bond (the phone sees its keys missing)
  factory-reset        forget every bond, new IRK, pairing window open
  slow-writes MS       delay each Frame In write
  mtu N                ATT MTU offered on the next exchange
  rotate               new resolvable private address now
  service-changed      indicate Service Changed
  status | help | quit"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--transport", default=DEFAULT_TRANSPORT)
    parser.add_argument("--bridge", default="127.0.0.1:21838", help="umsh-bridge host interface")
    parser.add_argument(
        "--loopback", action="store_true", help="echo each Frame In frame back on Frame Out"
    )
    parser.add_argument(
        "--pairing",
        nargs="+",
        default=["just-works"],
        metavar="MODE",
        help="just-works (NoInputNoOutput) or passkey NNNNNN (DisplayOnly, fixed)",
    )
    parser.add_argument("--pairing-window", action="store_true", help="start in pairing mode")
    parser.add_argument("--name", default="T1000-E 4F2A")
    parser.add_argument("--model-id", type=int, default=2, help="boards.json model_id")
    parser.add_argument("--rpa-seconds", type=int, default=900, help="0: rotate only on command")
    parser.add_argument("--mtu", type=int, default=255, help="ATT MTU offered (nRF radios: 255)")
    parser.add_argument("--state", default="build/ble-test-peripheral", help="IRK and bonds")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    if args.pairing == ["just-works"]:
        args.passkey = None
    elif len(args.pairing) == 2 and args.pairing[0] == "passkey" and args.pairing[1].isdigit():
        args.passkey = int(args.pairing[1])
        if not 0 <= args.passkey <= 999_999:
            parser.error("a passkey has six digits")
    else:
        parser.error("--pairing just-works | --pairing passkey NNNNNN")
    return args


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    if not args.verbose:
        logging.getLogger("bumble").setLevel(logging.WARNING)
    try:
        asyncio.run(Radio(args).run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
