#!/usr/bin/env python3
"""Read a BME280 over ULCP I2C and turn the raw registers into a reading.

Called with no arguments, it prints the `umshctl i2c` commands that wake the
sensor and dump its calibration and data registers. Paste the hex those
commands print back as arguments and it applies Bosch's compensation and
shows temperature, pressure, and humidity.

Standard library only. The sensor sits at 0x77 unless `--addr` says
otherwise; `--bus` and `--node` are passed through to the printed commands.
"""

import argparse
import math
import sys

CHIP_ID_REG = 0xD0
CALIB_LOW_REG = 0x88  # dig_T1..dig_P9, then dig_H1 at 0xa1
CALIB_LOW_LEN = 26
CALIB_HIGH_REG = 0xE1  # dig_H2..dig_H6
CALIB_HIGH_LEN = 7
DATA_REG = 0xF7  # press, temp, hum
DATA_LEN = 8

# ctrl_hum = x1 oversampling, then ctrl_meas = temp x1, press x1, forced.
# ctrl_hum only takes effect on the following ctrl_meas write, which is why
# the pair goes out in that order in one transaction.
WAKE_WRITE = "f201f425"

CHIP_IDS = {0x60: "BME280", 0x58: "BMP280 (no humidity)"}

# Blob lengths are distinct, so pasted reads identify themselves.
BLOB_KINDS = {1: "chip", CALIB_LOW_LEN: "calib_low", CALIB_HIGH_LEN: "calib_high", DATA_LEN: "data"}
COMBINED = ("chip", "calib_low", "calib_high", "data")
COMBINED_LEN = 1 + CALIB_LOW_LEN + CALIB_HIGH_LEN + DATA_LEN


def usage(bus, addr, prefix):
    """The two commands that produce everything this script needs."""
    ctl = " ".join(["umshctl", *prefix, "i2c"])
    xfer = (
        f"w:{CHIP_ID_REG:02x} r:1 "
        f"w:{CALIB_LOW_REG:02x} r:{CALIB_LOW_LEN} "
        f"w:{CALIB_HIGH_REG:02x} r:{CALIB_HIGH_LEN} "
        f"w:{DATA_REG:02x} r:{DATA_LEN}"
    )
    return f"""\
Take one forced measurement, then read the sensor out:

  1. Trigger a measurement (the sensor is in sleep until told otherwise):

       {ctl} write {bus} 0x{addr:02x} {WAKE_WRITE}

     0x{addr:02x} is in the firmware's peripheral table, so umshctl warns
     before the write. Nothing on the board drives this sensor, so the
     warning is expected. The measurement takes about 10 ms; the command
     round trip is longer than that, so no wait is needed.

  2. Read the chip id, both calibration blocks, and the data registers in
     one transaction:

       {ctl} xfer {bus} 0x{addr:02x} {xfer}

  3. Paste what step 2 printed back here:

       {sys.argv[0]} <{COMBINED_LEN * 2} hex characters>

Repeat steps 1-3 for each new reading; the calibration comes back every
time, which keeps the paste self-contained. Separate reads pasted as
several arguments work too—each blob is recognized by its length."""


def parse_hex(text):
    cleaned = "".join(text.lower().split()).replace("0x", "").replace(":", "").replace(",", "")
    if not cleaned or len(cleaned) % 2 or any(c not in "0123456789abcdef" for c in cleaned):
        raise SystemExit(f"not a hex octet string: {text!r}")
    return bytes.fromhex(cleaned)


def collect(args):
    """Sort pasted blobs into the four reads, however they were split up."""
    blobs = [parse_hex(arg) for arg in args]
    if len(blobs) == 1 and len(blobs[0]) == COMBINED_LEN:
        blob = blobs[0]
        lengths = (1, CALIB_LOW_LEN, CALIB_HIGH_LEN, DATA_LEN)
        parts, at = {}, 0
        for kind, length in zip(COMBINED, lengths):
            parts[kind] = blob[at : at + length]
            at += length
        return parts
    parts = {}
    for blob in blobs:
        kind = BLOB_KINDS.get(len(blob))
        if kind is None:
            raise SystemExit(
                f"{len(blob)} octets matches none of the reads "
                f"(1, {CALIB_LOW_LEN}, {CALIB_HIGH_LEN}, {DATA_LEN}, or {COMBINED_LEN} combined)"
            )
        if kind in parts:
            raise SystemExit(f"two blobs of {len(blob)} octets; expected one {kind} read")
        parts[kind] = blob
    for required in ("calib_low", "calib_high", "data"):
        if required not in parts and not (required == "calib_high" and parts.get("chip") == b"\x58"):
            raise SystemExit(f"missing the {required} read")
    return parts


def u16(data, at):
    return int.from_bytes(data[at : at + 2], "little")


def s16(data, at):
    return int.from_bytes(data[at : at + 2], "little", signed=True)


def s12(value):
    return value - 4096 if value & 0x800 else value


def calibration(low, high):
    cal = {
        "T1": u16(low, 0),
        "T2": s16(low, 2),
        "T3": s16(low, 4),
        "P1": u16(low, 6),
        "P2": s16(low, 8),
        "P3": s16(low, 10),
        "P4": s16(low, 12),
        "P5": s16(low, 14),
        "P6": s16(low, 16),
        "P7": s16(low, 18),
        "P8": s16(low, 20),
        "P9": s16(low, 22),
        "H1": low[25],
    }
    if high is not None:
        cal.update(
            {
                "H2": s16(high, 0),
                "H3": high[2],
                "H4": s12(((high[3] << 4) | (high[4] & 0x0F)) & 0xFFF),
                "H5": s12(((high[5] << 4) | (high[4] >> 4)) & 0xFFF),
                "H6": int.from_bytes(high[6:7], "little", signed=True),
            }
        )
    return cal


def raw_readings(data):
    adc_p = (data[0] << 12) | (data[1] << 4) | (data[2] >> 4)
    adc_t = (data[3] << 12) | (data[4] << 4) | (data[5] >> 4)
    adc_h = (data[6] << 8) | data[7]
    return adc_t, adc_p, adc_h


def compensate_temperature(adc_t, cal):
    var1 = (adc_t / 16384.0 - cal["T1"] / 1024.0) * cal["T2"]
    var2 = (adc_t / 131072.0 - cal["T1"] / 8192.0) ** 2 * cal["T3"]
    t_fine = var1 + var2
    return t_fine / 5120.0, t_fine


def compensate_pressure(adc_p, t_fine, cal):
    var1 = t_fine / 2.0 - 64000.0
    var2 = var1 * var1 * cal["P6"] / 32768.0
    var2 = var2 + var1 * cal["P5"] * 2.0
    var2 = var2 / 4.0 + cal["P4"] * 65536.0
    var1 = (cal["P3"] * var1 * var1 / 524288.0 + cal["P2"] * var1) / 524288.0
    var1 = (1.0 + var1 / 32768.0) * cal["P1"]
    if var1 == 0.0:
        return None
    pressure = 1048576.0 - adc_p
    pressure = (pressure - var2 / 4096.0) * 6250.0 / var1
    var1 = cal["P9"] * pressure * pressure / 2147483648.0
    var2 = pressure * cal["P8"] / 32768.0
    return pressure + (var1 + var2 + cal["P7"]) / 16.0


def compensate_humidity(adc_h, t_fine, cal):
    humidity = t_fine - 76800.0
    humidity = (adc_h - (cal["H4"] * 64.0 + cal["H5"] / 16384.0 * humidity)) * (
        cal["H2"]
        / 65536.0
        * (1.0 + cal["H6"] / 67108864.0 * humidity * (1.0 + cal["H3"] / 67108864.0 * humidity))
    )
    humidity = humidity * (1.0 - cal["H1"] * humidity / 524288.0)
    return min(max(humidity, 0.0), 100.0)


def dew_point(celsius, humidity):
    """Magnus-Tetens, good to a few hundredths of a degree above freezing."""
    if humidity <= 0.0:
        return None
    gamma = (17.62 * celsius) / (243.12 + celsius) + math.log(humidity / 100.0)
    return (243.12 * gamma) / (17.62 - gamma)


def pressure_altitude(pascals):
    """ISA altitude for the measured pressure, not a corrected elevation."""
    return 44330.0 * (1.0 - (pascals / 101325.0) ** (1.0 / 5.255))


def report(parts):
    lines = []
    chip = parts.get("chip")
    chip_id = chip[0] if chip else None
    if chip_id is not None:
        name = CHIP_IDS.get(chip_id, "unknown part")
        lines.append(f"chip id      0x{chip_id:02x}  {name}")
        if chip_id not in CHIP_IDS:
            lines.append("             the rest of this reading is probably meaningless")

    has_humidity = chip_id != 0x58 and "calib_high" in parts
    cal = calibration(parts["calib_low"], parts.get("calib_high") if has_humidity else None)
    adc_t, adc_p, adc_h = raw_readings(parts["data"])

    if adc_t == 0x80000:
        lines.append("")
        lines.append("The data registers hold their reset value: no measurement has been")
        lines.append("taken since power-up. Run the write in step 1 and read again.")
        return "\n".join(lines)

    celsius, t_fine = compensate_temperature(adc_t, cal)
    pascals = compensate_pressure(adc_p, t_fine, cal) if adc_p != 0x80000 else None
    humidity = compensate_humidity(adc_h, t_fine, cal) if has_humidity and adc_h != 0x8000 else None

    lines.append("")
    lines.append(f"temperature  {celsius:7.2f} C   {celsius * 9 / 5 + 32:7.2f} F")
    if pascals is not None:
        lines.append(f"pressure     {pascals / 100.0:7.2f} hPa {pascals / 3386.389:7.2f} inHg")
    if humidity is not None:
        lines.append(f"humidity     {humidity:7.2f} %RH")
        point = dew_point(celsius, humidity)
        if point is not None:
            lines.append(f"dew point    {point:7.2f} C   {point * 9 / 5 + 32:7.2f} F")
    if pascals is not None:
        meters = pressure_altitude(pascals)
        lines.append(f"ISA altitude {meters:7.0f} m   {meters * 3.28084:7.0f} ft")

    lines.append("")
    raw = f"raw adc      T {adc_t}  P {adc_p}"
    if has_humidity:
        raw += f"  H {adc_h}"
    lines.append(raw)
    trim = " ".join(f"{key}={value}" for key, value in cal.items())
    lines.append(f"calibration  {trim}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--bus", type=lambda text: int(text, 0), default=0, help="ULCP bus number")
    parser.add_argument(
        "--addr", type=lambda text: int(text, 0), default=0x77, help="sensor address (default 0x77)"
    )
    parser.add_argument("--node", help="administrator key, for reading a sensor across the mesh")
    parser.add_argument("--port", help="serial port, when more than one radio is attached")
    parser.add_argument("hex", nargs="*", help="what the read command printed")
    args = parser.parse_args()

    if not args.hex:
        prefix = []
        if args.port:
            prefix += ["-p", args.port]
        if args.node:
            prefix += ["--node", args.node]
        print(usage(args.bus, args.addr, prefix))
        return

    print(report(collect(args.hex)))


if __name__ == "__main__":
    main()
