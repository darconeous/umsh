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
| `light` | Drives the key light (GPIO9, LEDC, 1 kHz, 8-bit), fading to each duty the controller asks for. |

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
reports the debounced matrix. Differences a host can see are the light's
fades and its return after a sleep, and in key mode the queue, the latches,
the status byte, and Shift and Sym leaving alone the keys they do not change.

## Protocol

I²C target at `0x55`, 100 kHz on stock hosts. A write and a read are separate
transactions; a write followed by a read with a repeated start loses the
write.

### Writes

Each byte is a command, taken in order. An unknown byte is skipped, and a
command missing its operand does nothing.

| Write | Effect |
|---|---|
| `01 d` | Key light duty `d` (0 off, 255 fully on). The light counts as on when `d > 0`. Then, as on stock firmware, a following byte is taken as `02`'s operand. |
| `02 d` | Alt+B's duty, used when the duty set by `01` is 0. Taken only when `d > 30`. Default 127. |
| `03` | Raw mode. |
| `04` | Key mode (the power-on mode). |
| `50` | Sleep, in a write of its own (after `01 d` it would be taken as Alt+B's duty). |
| `A0` | Identify: the next read returns the identify reply. |

The light fades to each new duty over 250 ms, evenly in the duty's square
root, from wherever it is, including partway through another fade. Alt+B fades
the same way.

### Reads

| Mode | Reply |
|---|---|
| Key | The next character typed, or `00`; then the status byte; then `00`. A stock host reads the first byte alone. |
| Raw | Five bytes, one per column; bit *r* is set while row *r* is down. |
| After `A0` | The identify reply, once. |

A raw or identify read longer than the reply gets `FF` for the rest. In key
mode, bytes 2–6 are `00`, reserved for later fields, and bytes past those are
`FF`.

### Key mode

Characters wait in a queue of 16, oldest first; one typed into a full queue is
dropped. Reading takes one. Each newly pressed key, in row-major matrix order,
sends its base legend, or:

- With Sym, its Sym legend, or the base legend where it has none.
- With Shift, the capital of a letter, and `04` for `$` (the speaker key).
  Other keys send their base legend.
- With Caps Lock, the capital of a letter. Other keys send their base legend.

Sym and Shift never combine: of the two, the one pressed last applies. A key
with no legend, such as Mic without Sym, sends nothing. Then:

- Enter sends `0D`, Backspace `08`.
- Alt+B toggles the key light and sends nothing.
- Alt+C sends `0C`.

Every byte key mode sends is `01`–`7A`. The legends and modifier positions are
in `src/keymap.rs`.

Sym and Shift latch, sending what holding them would. The latch is one state
at a time:

- One press applies to the next key, held or not.
- A second press within 500 ms of the first locks it on (Caps Lock, Sym Lock)
  until the next press.
- A second press after that lets it go.
- A press of the other modifier replaces the state with its own.

#### Status byte

Read fresh, except bit 7, which belongs to the character beside it.

| Bits | Meaning |
|---|---|
| 0–2 | Latch: 0 none, 1 Shift next, 2 Sym next, 3 Alt next (reserved), 4 Caps Lock, 5 Sym Lock, 6–7 reserved |
| 3 | Key light on |
| 4 | Left Shift held |
| 5 | Right Shift held |
| 6 | Alt held |
| 7 | The character is a held key's repeat; never set beside `00` (reserved, not yet sent) |

Hosts read the status byte only once identify reports it.

### Identify

`A5 5A <major> <minor> <capabilities: u16, big-endian> <PEC>`, where PEC is
CRC-8 with the SMBus polynomial over the six bytes before it. This is protocol
1.2.

| Capability bit | Set when |
|---|---|
| 0 | `50` is understood. |
| 1 | A key-mode read's second byte is the status byte. |

`A5` is never a key-mode byte, so the probe is safe on a stock keyboard: a
host that reads anything else has stock firmware and treats the first byte as
an ordinary key-mode read, so no key is lost. Until identify succeeds, a host
sends nothing but `01`–`04` and `A0`: stock firmware would take the operand
bytes of any other command as commands.

### Sleep

`50` takes the keyboard off the bus until the bus is next used. Meanwhile the
matrix is not scanned, keys are not wake sources, and the key light is off; the
C3 is in light sleep. A lit light fades out first, from wherever it is.

Any traffic on the bus wakes it, including traffic for other devices, and
including traffic while the light is still fading out. The transaction that
wakes it goes unanswered (NAK), and the host retries it until it is answered, a
few milliseconds at most. The keyboard then answers as before. A key that was
down when it went to sleep counts as pressed again if it is still down on
waking.

The light stays dark for 100 ms after waking, then fades back to the duty last
set. A `01` in that time sets the light instead. The status byte reports the
light as on or off as it was set, dark or not.

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
