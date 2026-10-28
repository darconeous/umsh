# T-Deck keyboard firmware

The T-Deck's keyboard is scanned by its own ESP32-C3, which answers the S3 on
I²C. `firmware-esp32/firmware/tdeck/tkeyboard` is firmware for that C3: a
drop-in replacement for LilyGO's `Keyboard_ESP32C3.ino` (2025-06-12), so every
existing host keeps working, written to grow low-power modes and, later, key
custody. The hardware is §8 of
[`hardware/lilygo-t-deck-hardware.md`](hardware/lilygo-t-deck-hardware.md).

## Structure

The library (`src/lib.rs`) is the whole behavior as synchronous, pure logic,
tested on the host against a transliteration of the stock sketch
(`make test-tdeck-keyboard`). The binary (`src/firmware/`) is three Embassy
tasks around it:

| Task | Does |
|---|---|
| `scan` | Waits with every column driven low for any row to fall, then scans every 5 ms until every key is up and settled. Two agreeing scans debounce a key. |
| `host` | The I²C target at `0x55`. A read is answered while the host's clock is held. |
| `light` | Drives the key light (GPIO9, LEDC, 1 kHz, 8-bit) at the duty the controller asks for. |

The chip light-sleeps whenever every task is waiting and no wake lock is held.
A task that needs the chip awake holds a lock for exactly as long as it does:
the I²C target while it serves, `scan` while the keyboard is awake, and `light`
while it is on, since its PWM stops in sleep. So the chip sleeps only when the
host has sent it to sleep (`src/firmware/power.rs`).

The three share one `Controller` behind a blocking mutex. Every key change
passes through `Controller::route`, the one place to send keys somewhere other
than the host.

Differences from stock that no host can see: the light is set up before the
I²C target starts (on stock firmware an early `01` could be undone by setup),
nothing is scanned while no key is down, keys are debounced, and raw mode
reports the debounced matrix.

## Protocol

I²C target at `0x55`, 100 kHz on stock hosts. A write and a read are separate
transactions; a write followed by a read with a repeated start loses the
write.

### Writes

Each byte is a command, taken in order. An unknown byte is skipped, and a
command missing its operand does nothing.

| Write | Effect |
|---|---|
| `01 d` | Key light duty `d` (0 off, 255 fully on), now. The light counts as on when `d > 0`. Then, as on stock firmware, a following byte is taken as `02`'s operand. |
| `02 d` | Alt+B's duty, used when the duty set by `01` is 0. Taken only when `d > 30`. Default 127. |
| `03` | Raw mode. |
| `04` | Key mode (the power-on mode). |
| `50` | Sleep, in a write of its own (after `01 d` it would be taken as Alt+B's duty). |
| `A0` | Identify: the next read returns the identify reply. |

### Reads

| Mode | Reply |
|---|---|
| Key | One byte: the last key pressed, or `00`. Reading clears it. |
| Raw | Five bytes, one per column; bit *r* is set while row *r* is down. |
| After `A0` | The identify reply, once. |

A read longer than the reply gets `FF` for the rest.

### Key mode

One byte is held; a newer key replaces an unread one. For each newly pressed
key, in row-major matrix order, that has a legend on either layer: the Sym
legend while Sym is held, else the base legend (a missing legend is `00`);
either Shift subtracts 32, wrapping. Then:

- Enter sends `0D`, Backspace `08`.
- Alt+B toggles the key light and clears the held byte.
- Alt+C sends `0C`.

So Shift on a symbol gives a control code, Shift+Space and Mic alone give
`00`, and Shift+Mic gives `E0`. Every byte key mode can send is `00`–`7A` or
`E0`. The legends and modifier positions are in `src/keymap.rs`.

### Identify

`A5 5A <major> <minor> <capabilities: u16, big-endian> <PEC>`, where PEC is
CRC-8 with the SMBus polynomial over the six bytes before it. This is protocol
1.1. Capability bit 0 is set when `50` is understood.

`A5` is never a key-mode byte, so the probe is safe on a stock keyboard: a
host that reads anything else has stock firmware and treats the first byte as
an ordinary key-mode read, so no key is lost. Until identify succeeds, a host
sends nothing but `01`–`04` and `A0`: stock firmware would take the operand
bytes of any other command as commands.

### Sleep

`50` takes the keyboard off the bus until the bus is next used. Meanwhile the
matrix is not scanned, keys are not wake sources, and the key light is off; the
C3 is in light sleep.

Any traffic on the bus wakes it, including traffic for other devices. The
transaction that wakes it goes unanswered (NAK), and the host retries it until
it is answered, a few milliseconds at most. The keyboard then answers as before,
with the light back at the duty last set. A key that was down when it went to
sleep counts as pressed again if it is still down on waking.

Stock firmware ignores `50`, so only identify tells a host whether the keyboard
will sleep.

### Reserved

| Bytes | For |
|---|---|
| `05`–`3F` | Modes and key events |
| `40`–`7F` | Power |
| `A0`–`AF` | Identity and firmware update |
| `B0`–`BF` | Key custody |

The `C3_INT` line (C3 GPIO8 to S3 GPIO46) is never driven unless a host asks
for it: Meshtastic treats GPIO46 as an output.

## Flashing

The S3 cannot reach the C3. A 3.3 V USB-UART adapter goes on the 6-pin header
beside the keyboard's reset button: TX, RX, BOOT, RST, GND, and VCC from the
top. Hold BOOT to ground while the C3 powers up or resets to enter its ROM
bootloader.

1. Once per keyboard, save what is on it: `make backup-tdeck-keyboard`
   (`TKEYBOARD_BACKUP=<file>`, default `tdeck-keyboard-backup.bin`). This is
   the whole 4 MiB flash; keep it. It reads at 460800 baud
   (`TKEYBOARD_BACKUP_BAUD`), and an adapter that cannot reset the C3 leaves
   it at that rate, so enter the bootloader again before the next step.
2. `make flash-tdeck-keyboard` (`ESPFLASH_PORT=...` to choose the adapter).
   It writes `partitions.csv`, puts the image in `ota_0`, and stays attached to
   the C3's log at 115200.
3. To go back: `espflash write-bin --chip esp32c3 0 <backup file>`.

The partition table holds two app slots and a reserved `keystore` partition,
so a later update over I²C or keys kept on the C3 need no repartition through
the header.
