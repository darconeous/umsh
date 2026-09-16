#!/usr/bin/env python3
"""Read a PCF8563 over ULCP I2C and turn the raw registers into a reading.

Called with no arguments, it prints the `umshctl i2c` command that dumps the
clock's whole register file. Paste the hex it prints back as arguments and
this decodes the time, the voltage-low and alarm flags, both alarms, CLKOUT,
and the countdown timer.

Standard library only. The clock sits at 0x51 unless `--addr` says
otherwise; `--bus` and `--node` are passed through to the printed command.

Nothing here writes: the firmware's own driver reads this chip at boot and
writes it back after a GNSS fix, so a host read is safe at any time.
"""

import argparse
import datetime
import sys

STATUS_REG = 0x00
STATUS_LEN = 2
TIME_REG = 0x02
TIME_LEN = 7
ALL_REG = 0x00
ALL_LEN = 16

WEEKDAYS = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")
CLKOUT_FREQUENCIES = ("32.768 kHz", "1.024 kHz", "32 Hz", "1 Hz")
TIMER_FREQUENCIES = ((4096.0, "4.096 kHz"), (64.0, "64 Hz"), (1.0, "1 Hz"), (1 / 60.0, "1/60 Hz"))

# Blob lengths are distinct, so pasted reads identify themselves.
BLOB_KINDS = {ALL_LEN: "all", TIME_LEN: "time", STATUS_LEN: "status"}


def usage(bus, addr, prefix):
    """The one command that produces everything this script needs."""
    ctl = " ".join(["umshctl", *prefix, "i2c"])
    return f"""\
Dump the clock's registers and paste them back:

  1. Read all {ALL_LEN} registers in one transaction:

       {ctl} read {bus} 0x{addr:02x} {ALL_LEN} --reg {ALL_REG:02x}

     The part has no identity register, so nothing here proves it is a
     PCF8563 rather than something else strapped to 0x{addr:02x}. Reading the
     whole file in one auto-incrementing transfer is what keeps the time
     fields consistent with each other; if a reading lands on a rollover
     the seconds can still be off by one, so read twice and compare when
     the seconds matter.

  2. Paste what step 1 printed back here:

       {sys.argv[0]} <{ALL_LEN * 2} hex characters>

The time block alone ({TIME_LEN} octets from 0x{TIME_REG:02x}) and the two status
registers also decode on their own—each blob is recognized by its length."""


def parse_hex(text):
    cleaned = "".join(text.lower().split()).replace("0x", "").replace(":", "").replace(",", "")
    if not cleaned or len(cleaned) % 2 or any(c not in "0123456789abcdef" for c in cleaned):
        raise SystemExit(f"not a hex octet string: {text!r}")
    return bytes.fromhex(cleaned)


def collect(args):
    """Sort pasted blobs into the register file, however they were split up."""
    registers = {}
    for arg in args:
        blob = parse_hex(arg)
        kind = BLOB_KINDS.get(len(blob))
        if kind is None:
            raise SystemExit(
                f"{len(blob)} octets matches none of the reads "
                f"({ALL_LEN} for the whole file, {TIME_LEN} for the time block, "
                f"{STATUS_LEN} for the status registers)"
            )
        base = {"all": ALL_REG, "time": TIME_REG, "status": STATUS_REG}[kind]
        for offset, value in enumerate(blob):
            registers[base + offset] = value
    if not registers:
        raise SystemExit("nothing was pasted")
    return registers


def from_bcd(value, mask):
    """Decode a masked packed-BCD field, or None when a nibble is not a digit."""
    value &= mask
    tens, ones = value >> 4, value & 0x0F
    if tens > 9 or ones > 9:
        return None
    return tens * 10 + ones


def flags(value, names):
    """The set bits of a register, high bit first, as names."""
    return [name for bit, name in names if value & (1 << bit)]


def decode_time(registers):
    """The seven time registers as a datetime, plus what was wrong with them."""
    fields = {
        "second": from_bcd(registers[0x02], 0x7F),
        "minute": from_bcd(registers[0x03], 0x7F),
        "hour": from_bcd(registers[0x04], 0x3F),
        "day": from_bcd(registers[0x05], 0x3F),
        "month": from_bcd(registers[0x07], 0x1F),
        "year": from_bcd(registers[0x08], 0xFF),
    }
    bad = [name for name, value in fields.items() if value is None]
    if bad:
        return None, f"not BCD: {', '.join(bad)}"
    # The firmware writes the century bit as zero and reads 2000-2099 only,
    # because upstream drivers disagree about which polarity means 19xx.
    # This follows it, and reports the raw bit either way.
    try:
        stamp = datetime.datetime(
            2000 + fields["year"],
            fields["month"],
            fields["day"],
            fields["hour"],
            fields["minute"],
            fields["second"],
            tzinfo=datetime.timezone.utc,
        )
    except ValueError as error:
        return None, str(error)
    return stamp, None


def interval(seconds):
    """A drift in whatever unit keeps it readable."""
    if seconds < 90:
        return f"{seconds:.0f} s"
    if seconds < 5400:
        return f"{seconds / 60:.1f} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} days"


def alarm(value, mask, render):
    """One alarm register: enabled when bit 7 is clear, as the part has it."""
    if value & 0x80:
        return "off"
    field = from_bcd(value, mask) if mask != 0x07 else value & 0x07
    if field is None:
        return "on, but not BCD"
    return f"on, {render(field)}"


def report(registers, compare):
    lines = []
    have = registers.keys()

    if STATUS_REG in have:
        status1, status2 = registers[0x00], registers[0x01]
        set1 = flags(status1, ((7, "TEST1"), (5, "STOP"), (3, "TESTC")))
        set2 = flags(status2, ((4, "TI_TP"), (3, "AF"), (2, "TF"), (1, "AIE"), (0, "TIE")))
        named = " ".join(set1 + set2) or "no flags set"
        lines.append(f"status       0x{status1:02x} 0x{status2:02x}  {named}")
        if status1 & 0x20:
            lines.append("             STOP is set: the clock is not counting")
        if status2 & 0x08:
            lines.append("             AF is set: the alarm has matched since it was last cleared")
        if status2 & 0x04:
            lines.append("             TF is set: the countdown timer has expired")

    if TIME_REG in have:
        if registers[0x02] & 0x80:
            lines.append("integrity    VL is set: the oscillator has stopped, so the time below")
            lines.append("             is whatever the registers held, not a trustworthy reading")
        else:
            lines.append("integrity    VL clear: the oscillator has run continuously")

        stamp, problem = decode_time(registers)
        century = "19xx" if registers[0x07] & 0x80 else "20xx"
        weekday = registers[0x06] & 0x07
        if stamp is None:
            lines.append(f"time         undecodable ({problem})")
        else:
            lines.append(f"time         {stamp:%Y-%m-%d %H:%M:%S} UTC")
            lines.append(f"weekday      {WEEKDAYS[weekday]} (register {weekday})")
            counted = WEEKDAYS[(stamp.weekday() + 1) % 7]
            if counted != WEEKDAYS[weekday]:
                lines.append(
                    f"             the date falls on a {counted}; the part never derives this"
                )
            if compare is not None:
                drift = (stamp - compare).total_seconds()
                if abs(drift) < 1.0:
                    lines.append("versus host  agrees with this machine to the second")
                else:
                    sense = "ahead of" if drift > 0 else "behind"
                    lines.append(
                        f"versus host  {interval(abs(drift))} {sense} this machine, including"
                    )
                    lines.append("             however long the read sat before it was pasted")
        lines.append(f"century bit  {registers[0x07] >> 7} ({century}); the firmware writes it clear")

    if 0x09 in have:
        lines.append("")
        lines.append(f"minute alarm {alarm(registers[0x09], 0x7F, lambda v: f'at :{v:02d}')}")
        lines.append(f"hour alarm   {alarm(registers[0x0A], 0x3F, lambda v: f'at {v:02d}:xx')}")
        lines.append(f"day alarm    {alarm(registers[0x0B], 0x3F, lambda v: f'on day {v}')}")
        lines.append(f"weekday alrm {alarm(registers[0x0C], 0x07, lambda v: f'on {WEEKDAYS[v]}')}")

    if 0x0D in have:
        clkout = registers[0x0D]
        which = CLKOUT_FREQUENCIES[clkout & 0x03]
        lines.append(f"CLKOUT       {'on, ' + which if clkout & 0x80 else 'off (' + which + ' selected)'}")

    if 0x0F in have:
        control, countdown = registers[0x0E], registers[0x0F]
        hertz, label = TIMER_FREQUENCIES[control & 0x03]
        state = "running" if control & 0x80 else "stopped"
        period = f", {countdown / hertz:g} s from reload" if countdown else ""
        lines.append(f"timer        {state}, source {label}, counter {countdown}{period}")

    lines.append("")
    dump = " ".join(f"{registers[reg]:02x}" if reg in have else "--" for reg in range(ALL_LEN))
    lines.append(f"registers    {dump}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--bus", type=lambda text: int(text, 0), default=0, help="ULCP bus number")
    parser.add_argument(
        "--addr", type=lambda text: int(text, 0), default=0x51, help="clock address (default 0x51)"
    )
    parser.add_argument("--node", help="administrator key, for reading a clock across the mesh")
    parser.add_argument("--port", help="serial port, when more than one radio is attached")
    parser.add_argument(
        "--no-compare", action="store_true", help="skip the comparison against this machine's clock"
    )
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

    now = None if args.no_compare else datetime.datetime.now(datetime.timezone.utc)
    print(report(collect(args.hex), now))


if __name__ == "__main__":
    main()
