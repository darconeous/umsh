# LilyGO T-Deck / T-Deck Plus Hardware Reference

This document describes the **LilyGO T-Deck** and **T-Deck Plus** at the level
needed to port and maintain UMSH firmware. It combines:

- LilyGO's T-Deck schematic (`schematic/schematic.pdf`, read at 600 dpi) and the
  two GPS-module schematics in the same repository
- LilyGO's `Xinyuan-LilyGO/T-Deck` examples: `utilities.h`, the factory
  `UnitTest`, the ESP32-C3 keyboard firmware, and the keyboard master example
- LilyGO's newer `LilyGoLib` T-Deck support (`LilyGo_T_Deck.cpp`,
  `TDeckDisplayConfig.h`, `TDeckKeyboard.cpp`, its Arduino variant, and its
  T-Deck hardware page)
- Meshtastic's `variants/esp32s3/t-deck` variant and `boards/t-deck.json`, and
  the Meshtastic device-ui T-Deck display/touch driver (`LGFX_T_DECK.h`)
- MeshCore's `variants/lilygo_tdeck` variant
- The Awinic AW9364 backlight driver datasheet and RadioLib's SX126x defaults

Where sources disagree, the disagreement is stated and the schematic wins on
wiring questions. Facts that need a physical board are collected in §17.

> **Identification warning**
>
> This covers the original T-Deck and the T-Deck Plus, which share one pin map.
> It does **not** cover the **T-Deck Pro** (e-paper, different pinout) or the
> **T-Deck V2**, which LilyGoLib treats as a separate product that its T-Deck
> page "does not apply to".

---

## 1. Summary

- ESP32-S3-WROOM-1 module (ESP32-S3R8 die): 16 MiB QIO flash, 8 MiB **octal**
  PSRAM
- 2.8" ST7789 IPS LCD, 240×320 native, used as **320×240 landscape**, on SPI
- GT911 capacitive touch on I²C (original T-Deck and Plus)
- 35-key QWERTY keyboard run by a dedicated **ESP32-C3** that answers on I²C at
  `0x55`
- Trackball: four Hall-effect sensors (one per direction) plus a center
  push switch on **GPIO0 (BOOT)**
- SX1262 in an "HPD16A" module, **optional** on the original T-Deck
- MAX98357A I²S speaker amplifier; ES7210 microphone ADC
- MicroSD slot on the shared SPI bus
- TP4065B linear charger (500 mA), SY8089 3.3 V buck, a slide power switch, and
  a reset button; **no PMIC, no fuel gauge, no RTC, no haptics**
- Battery voltage through a 2:1 divider on GPIO4 (§4.5)
- One switched peripheral rail, enabled by **GPIO10**
- Native USB-Serial-JTAG only (USB-C); no USB-UART bridge
- T-Deck Plus adds a GNSS module (u-blox MIA-M10Q or Quectel L76K) on
  GPIO43/44 and a 2000 mAh cell, and gives up the Grove UART

## 2. Variants

| | T-Deck | T-Deck Plus |
|---|---|---|
| LoRa | Optional SX1262 (433 or 868/915 MHz builds) | SX1262 |
| GNSS | None; Grove UART on GPIO43/44 can take one | Onboard, on GPIO43/44; Grove not available |
| Battery | Bring your own LiPo | 2000 mAh in the case |
| LCD panel | Earlier panel batch | Different panel batch (§5.3) |
| Touch INT polarity | Low on touch | High on touch, as shipped (§7.3) |

LilyGO states that "only the shell and screen are different" (T-Deck
issue #61). Meshtastic and MeshCore each build one image for both. There is no
documented way to tell them apart in firmware; a GNSS probe on GPIO43/44 is the
practical test, and it cannot distinguish a Plus from a T-Deck with an external
GPS on the Grove port.

## 3. MCU and memory

### 3.1 ESP32-S3R8

The WROOM-1 carries an ESP32-S3R8, whose 8 MiB PSRAM is wired **octal** (OPI).
The schematic notes that GPIO35, 36, and 37 (and module pin IO26) belong to the
PSRAM and must not be used. Meshtastic's `boards/t-deck.json` sets
`memory_type: qio_opi`; LilyGO's UnitTest refuses to build without
"OPI PSRAM". In UMSH terms this is `PSRAM_MODE = OctalSpi`, as on the XIAO
ESP32S3, not the T-LoRa Pager's `QuadSpi`.

LilyGoLib's hardware page names the SoC "ESP32-S3FN16R8". The schematic shows
the WROOM-1 module; the difference does not matter to firmware.

### 3.2 Flash

16 MiB, QIO at 80 MHz (`flash_mode: qio`, `f_flash: 80MHz`). Meshtastic uses
`default_16MB.csv`; the communicator's `chat` partition needs a 16 MiB table
like the T-LoRa Pager's.

## 4. Power

### 4.1 Power path

From the schematic:

- **VBUS** (USB-C, 5.1 kΩ CC pull-downs) feeds the **TP4065B** charger and,
  through a 1N5819 Schottky, the system input node.
- **VBAT** reaches the same node through an SI2307 P-FET (Q5) whose gate is
  VBUS (100 kΩ to ground): the cell powers the system only while USB is absent.
- The **slide switch** (SW1, K3-1391D) sits between that node and the `+5V`
  system rail. Off means everything except the charger is unpowered.
- An **SY8089AAC** buck makes **VDD3V3** from `+5V` (100 kΩ/22 kΩ feedback,
  3.33 V).
- **V3V** is a switched copy of VDD3V3 through an SI2301 P-FET (Q6).

There is no PMIC and no software power-off: the slide switch is the only hard
off. The charger works with the switch in either position.

### 4.2 Peripheral rail (GPIO10)

GPIO10 (`PWR_EN`, `BOARD_POWERON`, `KB_POWERON`, `PIN_PERF_POWERON`) drives an
NPN (Q7, PMBT3904) through a 1N4148 and 10 kΩ, with a 100 kΩ base pull-down.
Q7 pulls the gates of Q6 and Q4 low, which:

- connects **V3V** to VDD3V3, and
- connects the battery-sense divider to `+5V` (§4.5).

A second diode into the same base, from `VBUS`, is marked **NC** (not fitted),
and a third from a `TP_EN` net sits in a dashed box with no matching MCU pin. So
on the reviewed schematic, USB power alone does not light the peripheral rail.
LilyGO's wiki claims GPIO10 is unnecessary on USB power; do not rely on that.
GPIO10 low (including in deep sleep without a pad hold, because of the base
pull-down) turns the rail off.

| Rail | Loads (schematic unless noted) |
|---|---|
| **VDD3V3** (on while the switch is on) | ESP32-S3; ST7789 logic supply (`VDD`); GT911 (`VCC`); the GPS connector's 3.3 V on the Plus (GPS-module sheet) |
| **V3V** (GPIO10) | SX1262 module `VCC`; ESP32-C3 keyboard controller; AW9364 backlight driver and LED anode; four trackball Hall sensors; MicroSD `VDD`; MAX98357A and ES7210 (per Meshtastic's `variant.cpp`, not traced) |

Consequences:

- The radio, the keyboard, and the trackball cannot be powered separately.
  Keeping the radio listening keeps the ESP32-C3 running too, and its stock
  firmware has no low-power mode (§8.8). Meshtastic learned this in practice:
  it drove GPIO10 low while the screen was dark to power the keyboard down
  ("saves 20mA", PR #2786), then reverted it (PR #2847) when the next transmit
  after blanking failed with `busyTx` and rebooted the device.
- The LCD controller and the touch controller stay powered while V3V is off.
  Put them to sleep by command (§5.5, §7.5).
- The I²C pull-ups are on V3V, and the unpowered ESP32-C3 sits on SDA/SCL.
  With V3V off the bus is unusable, touch included.

Meshtastic raises GPIO10 in `earlyInitVariant()`, before anything else,
because "if some boards are turned on late, ESP32 will reset due to low
voltage", and then waits 100 ms. LilyGO's keyboard example waits **500 ms**
before the first keyboard read ("give LILYGO-KEYBOARD some startup time"), and
so does LilyGoLib. The SX1262 and the backlight driver are dead until the rail
is up, so GPIO10 comes first in bring-up.

### 4.3 Charger

TP4065B with a 2 kΩ PROG resistor; LilyGoLib gives the charge current as 500 mA
(fixed) and the input as 4.7–6 V. `CHRG` drives a blue LED only (on while
charging). **No charge status reaches a GPIO.**

### 4.4 Battery

The Plus ships a 2000 mAh cell. LilyGoLib quotes 3.7 V / 2000 mAh and a 0–60 °C
charge range. The original T-Deck takes a user-supplied LiPo on a JST
connector (P3).

### 4.5 Battery and USB sense (GPIO4)

GPIO4 (ADC1 channel 3) reads a 100 kΩ/100 kΩ divider (with 10 nF). On the
schematic the divider's top is the net `BAT`, which Q4 connects to the `+5V`
system rail when GPIO10 is high. It is not the cell itself:

- **On battery:** `+5V` is the cell through Q5, so the reading is the cell
  voltage (less Q5's drop).
- **On USB:** `+5V` is VBUS less the Schottky drop, about 4.4–4.7 V, regardless
  of the cell. **The cell cannot be measured while USB is connected.**
- **GPIO10 low:** Q4 is off and the divider reads near 0 V.

This matches LilyGoLib, which treats a reading above **4200 mV** as "USB
connected" and has no other charge or presence signal. The divider's ~21 µA
load is switched with the rail.

| Source | Conversion |
|---|---|
| LilyGoLib | Median of 7 `analogReadMilliVolts` × 2; percent from a piecewise curve (3300 mV = 0 %, 3700 = 20 %, 3800 = 40 %, 3900 = 60 %, 4000 = 80 %, 4100 = 90 %, 4200 = 100 %) |
| Meshtastic | `ADC_MULTIPLIER 2.11` ("2.0 + 10% for correction of display undervoltage") |
| MeshCore | Mean of 8 raw reads, `2 × 3.3 V × raw / 4096` (no calibration) |

Use calibrated millivolts at 11 dB attenuation and ×2. Meshtastic's 10 % fudge
is a symptom of uncalibrated reads, not a property of the board.

USB host presence can also come from the bus: the T-Deck's native
USB-Serial-JTAG is the same arrangement the XIAO ESP32S3 uses for
`usb-presence-sof`
([`seeed-xiao-esp32s3-wio-sx1262-kit-hardware.md`](seeed-xiao-esp32s3-wio-sx1262-kit-hardware.md),
§6.1). A charger without data lines shows up only on the ADC.

### 4.6 Sleep

- **Deep sleep:** LilyGO's UnitTest puts touch and LCD to sleep, ends SPI and
  I²C, and arms ext1 wake on GPIO0 low (the trackball center), noting
  "approximately 240 µA". GPIO10 is not held, so V3V drops. Its comment says to
  hold GPIO10 with `gpio_hold_en` if peripherals must stay powered.
- **Light sleep:** LilyGoLib sleeps the LCD, radio, keyboard backlight, and
  touch, then wakes on GPIO0 low level. It skips sleep if GPIO0 is already held
  low. ESP32-S3 light sleep keeps digital pads driven, so GPIO10 and the rail
  hold through it.
- GPIO0 has an external 100 kΩ pull-up and is an RTC GPIO, so it works as a
  deep-sleep wake source with the rail off. The trackball direction pins (§9)
  are also RTC GPIOs, but their sensors are on V3V.

## 5. Display

### 5.1 Interface

| Signal | GPIO | Notes |
|---|---:|---|
| SCK | 40 | Shared SPI bus (§6) |
| MOSI | 41 | |
| MISO | 38 | Wired; the panel is readable. Pull up (§6) |
| CS | 12 | |
| DC | 11 | |
| RESET | — | RC power-on reset on the panel's `RESET` (10 kΩ, 100 nF); no GPIO |
| Backlight | 42 | AW9364 `EN` (§5.4) |

Every source agrees on these pins. Panel supply: logic `VDD` on VDD3V3, LED
anode on V3V.

### 5.2 Orientation, color, and clock

- Native 240×320 portrait; every source runs it as 320×240 landscape.
  TFT_eSPI `setRotation(1)` and LilyGoLib's landscape entry both come to
  **MADCTL `0x60`** (MV | MX), RGB order.
- **Inversion on** (`INVON`, `0x21`): LilyGoLib's init list, LilyGO's UnitTest
  override list, Meshtastic device-ui (`cfg.invert = true`), and the only Rust
  project found. LilyGO's TFT_eSPI setup file leaves both inversion defines
  commented out, with a note that the first T-Deck sample needed inversion on.
- RGB565, sent big-endian (LilyGoLib `needSwapColors() = true` for its
  little-endian buffers).
- **SPI write clock: 40 MHz** in Meshtastic's variant, LilyGO's TFT_eSPI setup,
  and the Rust project; reads at 16–20 MHz. Device-ui's driver defaults to
  80 MHz, but Meshtastic's variant overrides it. The ST7789V datasheet's
  minimum serial write cycle is 16 ns (62.5 MHz). At 40 MHz a full
  153,600-byte frame takes about 31 ms.

### 5.3 Initialization

LilyGoLib's current list (`TDeckDisplayConfig.h`, dated 2026-09-28, "shared ...
for T-Deck generations"):

| Command | Data | Meaning |
|---|---|---|
| `11` | — | Sleep out, then 120 ms |
| `13` | — | Normal display mode |
| `36` | `00` | MADCTL (rotation sets it later) |
| `3A` | `55` | 16-bit color |
| `B2` | `0C 0C 00 33 33` | Porch control |
| `B7` | `75` | Gate control |
| `BB` | `1A` | VCOM |
| `C0` | `2C` | LCM control |
| `C2` | `01` | VDV/VRH enable |
| `C3` | `13` | VRH |
| `C4` | `20` | VDV |
| `C6` | `0F` | Frame rate (60 Hz) |
| `E0` | `D0 0D 14 0D 0D 09 38 44 4E 3A 17 18 2F 30` | Positive gamma |
| `E1` | `D0 09 0F 08 07 14 37 44 4D 38 15 16 2C 3E` | Negative gamma |
| `21` | — | Inversion on |
| `2A` | `00 00 00 EF` | Columns 0–239 |
| `2B` | `00 00 01 3F` | Rows 0–319 |
| `29` | — | Display on |

The same values appear in LilyGO's UnitTest as a disabled override with the
comment that "T-Deck-Plus and T-Deck display panels are different", and the
T-Deck README records an updated init and gamma sequence from 2024-07-26.
Device-ui instead keeps LovyanGFX's ST7789 defaults and sets only gamma curve 1
(`26 01`). Start from LilyGoLib's list and check colors and gamma on both panel
batches.

### 5.4 Backlight (AW9364)

GPIO42 drives the `EN` pin of an **AW9364DNR** 4-channel LED driver, the same
part and GPIO as the T-LoRa Pager's panel backlight. It is pulse-count dimmed,
not PWM:

- The first rising edge after shutdown gives full current (16/16, 20 mA per
  channel); each further low-to-high pulse steps down one level, wrapping from
  1/16 back to 16/16.
- Datasheet timing: T_ON > 20 µs after the first rise; 0.5 µs < T_LO < 500 µs
  and T_HI > 0.5 µs per pulse; `EN` low for more than 2.5 ms shuts it down
  (T_OFF 0.8–2.5 ms). `EN` has an internal 150 kΩ pull-down.
- LilyGO's UnitTest algorithm: level 0 = hold low 3 ms; from off, raise and
  wait 30 µs (level 16); to go from level *a* to *b*, send
  `(16 + (16 − b) − (16 − a)) % 16` pulses. LilyGoLib exposes 0–16.

Meshtastic's device-ui drives GPIO42 with LovyanGFX PWM at 44.1 kHz, capped at
253/255 ("T-Deck PWM doesn't like 100%"), and the Rust experiment uses 24 kHz
PWM. Under the datasheet every PWM low period under 500 µs is a dimming pulse,
so PWM brightness is accidental; a T-Deck issue (#61) reports PWM working on the
original but not the Plus. LilyGoLib's hardware page states "not controlled by
PWM". Use the pulse protocol, as UMSH's T-LoRa Pager BSP already does.

The driver's `VIN` and the LED anode are on V3V, so the backlight is dark while
GPIO10 is low, and the driver restarts at full brightness when the rail returns.

### 5.5 Sleep

The panel stays powered on VDD3V3. Blanking means backlight off (`EN` low)
plus `SLPIN` (`0x10`); waking means `SLPOUT` (`0x11`), 120 ms, then the
backlight. There is no hardware reset after power-up; use `SWRESET` (`0x01`) if
needed.

## 6. Shared SPI bus

SCK 40, MOSI 41, MISO 38 serve three devices:

| Device | CS | Clock used upstream |
|---|---:|---|
| ST7789 | 12 | 40 MHz write |
| SX1262 | 9 | RadioLib default (the SX1262 allows up to 16 MHz) |
| MicroSD | 39 | 800 kHz (LilyGO, LilyGoLib); Meshtastic's 75 MHz define is not credible |

Drive all three chip selects high before using any device on the bus. Both
LilyGO's UnitTest and Meshtastic's `earlyInitVariant()` do this, the latter
because otherwise "there will be SPI communication issues e.g. when detecting
the SD card". Meshtastic, LilyGO, LilyGoLib, and MeshCore all enable the
internal pull-up on MISO (GPIO38).

## 7. Touch (GT911)

### 7.1 Interface

| Signal | GPIO | Notes |
|---|---:|---|
| SDA / SCL | 18 / 8 | Shared I²C bus (§11) |
| INT | 16 | Polarity varies (§7.3) |
| RST | — | RC power-on reset (10 kΩ to VDD3V3, 100 nF); no GPIO |

The controller is on VDD3V3 and keeps power when V3V is off.

### 7.2 Address

The GT911 latches its address (`0x5D` or `0x14`) from the INT level at the end
of reset. With RC reset and no firmware control of the timing, either may
appear. Meshtastic configures `0x5D`; device-ui retries every transaction at
the other address; LilyGoLib's SensorLib probes both. Probe both and keep the
one that answers.

### 7.3 Interrupt

INT polarity differs between panels. T-Deck issue #42 is the reference:

- Original T-Deck panels pull INT **low** on touch; Plus panels pull it
  **high**. LilyGO traced this to the old panels triggering on a falling edge
  and the new ones on a rising edge.
- The reported symptom on the Plus, touch data "for about ten seconds" after
  one touch, is what a driver sees when it watches for the wrong polarity:
  the line looks asserted while the finger is up.
- The GT911's trigger mode is the low two bits of `Module_Switch1` (`0x804D`):
  `0` rising edge, `1` falling edge, `2` low while touched, `3` high while
  touched. LilyGO found that setting it "does not seem to have any effect after
  installing on T-Deck", so the register is not a reliable description of the
  pin.

**Determine the polarity from the pin at boot.** This is the approach
Meshtastic settled on in issue #42:

1. Read the status register (`0x814E`) and confirm no point is reported.
2. Sample GPIO16. That is the idle level; the opposite level is active.
3. If a finger is down at boot, wait for the status register to report no
   points and sample again.

This leaves the panel's stored configuration untouched. Two alternatives
change it persistently, because the GT911 keeps its configuration:

- LilyGO rewrote the trigger mode on affected boards from a factory test image
  (`T-Deck_UnitTest_240913.bin`).
- Device-ui reads `0x804D` at boot and, if the mode is not `2`, rewrites the
  184-byte config block at `0x8047`, bumps the version byte, writes the
  checksum to `0x80FF`, and sets `0x8100 = 1`.

An original T-Deck panel (at `0x5D`) idles INT high and pulses it low once per
report, about every 10 ms while a finger is down, the release report included.
Whether a Plus panel pulses the same way or holds the line through a drag
(a level mode) is still to be checked (§17). In a level mode the line stays
asserted with no further edges, so reports are read on a timer while it does.

### 7.4 Registers and coordinates

- Product ID at `0x8140` (4 ASCII bytes), firmware version `0x8144`.
- Status at `0x814E`: bit 7 = buffer ready, low nibble = point count. Points
  follow from `0x814F`, 8 bytes each (track ID, X, Y, size). Write `0` to
  `0x814E` after reading.
- Raw coordinates are portrait. LilyGO (UnitTest and LilyGoLib) maps them to
  the 320×240 landscape frame with max coordinates (320, 240), **swap X/Y**,
  then **mirror Y**. Confirm with a corner test on each panel batch; device-ui's
  alternate path subtracts 90 from Y, which looks like a calibration hack.

### 7.5 Sleep and wake

Writing `0x05` to the command register `0x8040` puts the GT911 to sleep;
driving INT high for a few milliseconds wakes it. LilyGoLib drives INT high for
8 ms before probing, then returns it to an input.

Only the RC power-on resets the controller, and it stays powered while the
switch is on. A controller put to sleep before a deep-sleep wake, a reset, or a
flash is still asleep when the S3 boots again, and answers no probe until INT
wakes it.

### 7.6 Presence

LilyGO's wiki says the original T-Deck has no touchscreen; its schematic,
LilyGoLib's capability table, and Meshtastic all include one. Detect it at
runtime.

## 8. Keyboard (ESP32-C3)

### 8.1 Interface

The keyboard matrix is scanned by an ESP32-C3 that acts as an I²C target at
**`0x55`** on the S3's SDA 18 / SCL 8, configured for 100 kHz on its side
(C3 SDA = GPIO2, SCL = GPIO10). The C3 is on V3V and needs about 500 ms after
GPIO10 rises before it answers.

The schematic routes a `C3_INT` line from C3 GPIO8 to S3 **GPIO46** (4.7 kΩ
pull-up to V3V). **The stock firmware never drives it** (issue #9); a reader must
poll. Meshtastic's `KB_BL_PIN 46` label is wrong. GPIO46 is also a boot strap
(§15).

### 8.2 The ESP32-C3

| | |
|---|---|
| Core | Single-core RISC-V, rated to 160 MHz; the stock firmware sets 80 MHz |
| Memory | 400 KiB SRAM on chip |
| Flash | External W25Q32FV, **4 MiB**, DIO (WP and HOLD tied high) |
| Clock | External 40 MHz crystal, 10 ppm |
| Radio | **Unusable:** `LNA_IN` is not connected and there is no antenna |
| USB | Unusable: GPIO18/19 are matrix rows and reach no connector |
| JTAG | Unusable: GPIO4–7 are matrix lines |
| Supply | V3V, with its flash |

Every C3 GPIO is assigned:

| C3 GPIO | Use |
|---|---|
| 0, 3, 19, 12, 18, 6, 7 | Matrix rows 0–6 |
| 1, 4, 5, 11, 13 | Matrix columns 0–4 |
| 2 / 10 | I²C SDA / SCL to the S3 |
| 8 | `C3_INT` to S3 GPIO46 (unused by stock firmware) |
| 9 | `BL_CTRL`: gate of a BSS138 switching the key LEDs' cathodes; also the C3's boot strap |
| 14–17 | Flash |
| 20 / 21 | UART RX / TX, header only |

GPIO11 is the C3's flash-supply pin by default and works as a GPIO only once
the `VDD_SPI_AS_GPIO` eFuse is burned. Its use as a matrix column implies that
fuse is set on shipped keyboards, which the flash's supply on V3V allows.

The 4.7 kΩ pull-ups on `BL_CTRL`, `C3_INT`, SDA, and SCL go to V3V.

### 8.3 Programming

The C3's 6-pin header beside the reset button carries, from the top, TX, RX,
BOOT (`BL_CTRL`, C3 GPIO9), RST (`CHIP_EN`, 10 kΩ / 1 µF), GND, and VCC (V3V).
Reflashing needs a USB-UART adapter with BOOT shorted to ground at power on.
LilyGO publishes prebuilt keyboard images
`T-Keyboard_Keyboard_ESP32C3_241225.bin` and `..._250620.bin`.

**The S3 cannot reflash the C3.** Its UART, `CHIP_EN`, and GPIO9 reach only
the header; the only S3–C3 connections are I²C and `C3_INT`. The S3 can
power-cycle the C3 through GPIO10, but GPIO9's pull-up to the same rail makes it
boot normally every time. In-field updates from the S3 would need C3 firmware
that accepts an image over I²C, installed once through the header.

UMSH has its own C3 firmware, compatible with every host of the stock one:
see [`../tdeck-keyboard-firmware.md`](../tdeck-keyboard-firmware.md).

### 8.4 Key mode (default)

A 1-byte read returns the last key pressed, or `0x00` for none.

- The C3 keeps **one** pending byte. A new key replaces an unread one, and two
  keys pressed within one scan yield only the last. Each scan spends 1 ms per
  matrix cell, about 35 ms in all, so poll at least that often.
- Press edges only: no release, no auto-repeat, no modifier events.
- `Enter` sends `0x0D` and `Backspace` sends `0x08`, unaffected by modifiers.
- **Sym** (held) selects the symbol layer.
- **Shift** (either, held) subtracts 32 from the resulting byte, symbols
  included: Shift+Space gives `0x00` (lost), Shift+`$` gives `0x04`,
  Shift+Sym+W (`1`) gives `0x11`, and Shift+Mic gives `0xE0` from the
  published source (a Meshtastic comment says `0xEA`; shipped firmware may
  differ).
- **Alt** sends nothing by itself, and Alt+letter sends the plain letter,
  except **Alt+C**, which sends `0x0C` (Meshtastic's modifier toggle), and
  **Alt+B**, which toggles the keyboard backlight and sends nothing (since the
  2024-12-16 fix for issue #69).
- No arrow, Escape, or Tab codes exist. The `0xB4`–`0xB7` arrow codes in
  Meshtastic's `kbI2cBase.cpp` belong to other keyboards.

### 8.5 Raw mode

Firmware from 2025-06-12 accepts mode commands. After `0x03`, each read returns
**5 bytes, one per column**, with bit *r* set while row *r* is pressed (the
C3's last scan, undebounced). `0x04` returns to key mode. LilyGoLib sends `0x04`
on attach. Raw mode is the only way to see modifiers, releases, and holds. How
older firmware answers a 5-byte read is untested.

### 8.6 Matrix and legends

Columns are C3 GPIO 1, 4, 5, 11, 13; rows are C3 GPIO 0, 3, 19, 12, 18, 6, 7.
Raw-mode bit positions, with the key-mode output for the base and Sym layers:

| | Row 0 | Row 1 | Row 2 | Row 3 | Row 4 | Row 5 | Row 6 |
|---|---|---|---|---|---|---|---|
| **Col 0** | `q` / `#` | `w` / `1` | **Sym** | `a` / `*` | **Alt** | Space / — | **Mic** — / `0` |
| **Col 1** | `e` / `2` | `s` / `4` | `d` / `5` | `p` / `@` | `x` / `8` | `z` / `7` | **Left Shift** |
| **Col 2** | `r` / `3` | `g` / `/` | `t` / `(` | **Right Shift** | `v` / `?` | `c` / `9` | `f` / `6` |
| **Col 3** | `u` / `_` | `h` / `:` | `y` / `)` | **Enter** | `b` / `!` | `n` / `,` | `j` / `;` |
| **Col 4** | `o` / `+` | `l` / `"` | `i` / `-` | **Backspace** | `$` / — | `m` / `.` | `k` / `'` |

Mic sends nothing on the base layer and `0` with Sym; `$` (the speaker legend)
sends nothing with Sym.

Physically the layout is BlackBerry-style: Q–P, then A–L with Backspace, then
Z–M with `$` and Enter, with Alt, the two Shifts, Mic, Space, and Sym around
them. The exact placement of the modifier keys should be recorded from a unit.

### 8.7 Backlight commands

Firmware from 2024-12-25 accepts two-byte writes:

| Write | Effect |
|---|---|
| `01 dd` | Backlight duty 0–255 now (C3 GPIO9, LEDC 1 kHz, 8-bit). Boot duty is 0 (off) |
| `02 dd` | Duty used by Alt+B when the set duty is 0; accepted only above 30; default 127 |

The firmware's `0x01` case falls through into the `0x02` handler (no `break`);
with a two-byte write the second read finds no data and nothing changes.
`setup()` starts the I²C target before it sets up the light and writes the
boot duty, so a `01` that arrives as soon as the C3 first answers can be undone.
Keyboards shipped earlier (issue #32) ignore both commands unless reflashed.

### 8.8 Power

The stock firmware sets 80 MHz and never sleeps. Its loop scans the matrix
with `delay(1)` per cell, so the CPU spends most of its time idle in FreeRTOS's
idle task, with the I²C target and LEDC running. The ESP32-C3 datasheet
(Table 5-8, modem-sleep, typical) gives at 80 MHz:

| CPU | Peripheral clocks off | Peripheral clocks on |
|---|---|---|
| Idle | 13 mA | 18 mA |
| Running | 17 mA | 22 mA |

Flash access can add more. For comparison, the radio module's own figure for
receive is at most 8.2 mA (§10.1). The C3 shares V3V with the radio (§4.2), so
with stock firmware it draws whenever the radio is powered. The only ways to
lower it are C3 firmware that sleeps between scans (the C3's light-sleep and
GPIO-wake support allow it) or turning V3V off, which also powers off the
radio (§4.2).

The one board-level figure found is Meshtastic's 20 mA (PR #2786), the saving
from turning V3V off with the screen already dark. It covers the whole rail
(the C3, the trackball sensors, the audio parts, and the idle radio), not the
C3 alone. No measurement of the C3 by itself was found, and none of the
community keyboard firmwares (hasn0life, rgrizzell, hreikin) sleep; hasn0life's
build instructions set the CPU to 40 MHz.

## 9. Trackball

Four Panasonic **AN48841B** Hall-effect sensors (UZ1–UZ4) sit around the ball
and pulse their outputs as its magnets pass. The center press is a separate
tact switch (TS-1187AB) on GPIO0.

| Direction | Sensor net | GPIO |
|---|---|---:|
| Up | `G_S1` | 3 |
| Right | `G_S2` | 2 |
| Down | `G_S3` | 15 |
| Left | `G_S4` | 1 |
| Press | `GPIO_0` (100 kΩ pull-up) | 0 |

The schematic, LilyGO, LilyGoLib, Meshtastic, and the Rust project agree on
these pins, except that the Rust project's `hardware.rs` puts Down on GPIO5
(the speaker's I²S word select); its own trackball example uses 15.

Every source enables internal pull-ups on the four direction pins (LilyGoLib
calls them "active-low"). How they count motion differs:

| Source | Method |
|---|---|
| LilyGO UnitTest | Polls; every level change, either edge, is one step (24 px) |
| LilyGoLib | Falling-edge interrupts; one event per edge, ignoring edges within 5 ms of the last in the same direction |
| Meshtastic | Falling-edge interrupts; a move needs 3 edges (`TB_THRESHOLD`), counters reset after 1 s idle; a held direction repeats |

Edges per revolution, bounce, and whether diagonal rolls produce interleaved
edges on two pins need measuring on hardware. The sensors are on V3V, so the
direction pins float with GPIO10 low.

GPIO0 is the ROM download strap: holding the trackball while resetting enters
download mode. LilyGO's README notes that the GPIO0 button cannot be used while
the microphone is in use.

## 10. LoRa radio

### 10.1 Module and interface

The radio is an "HPD16A" SX1262 module (LilyGO's schematic name), optional on
the original T-Deck.

| Module pin | Signal | GPIO / net |
|---|---|---|
| 1 | ANT | 0 Ω to the antenna connector |
| 3 | DIO3 | Not connected on the board |
| 5 | VCC | **V3V** (GPIO10) |
| 7 | DIO1 | 45 |
| 8 | BUSY | 13 |
| 10–12 | MISO / MOSI / SCK | 38 / 41 / 40 (shared bus) |
| 13 | NSS | 9 |
| 14 | NRESET | 17 |

All sources agree on these. The module exposes no DIO2 and no RF-switch pins:
any TX/RX switch is inside it. The schematic's notes give the module's needs as
a 200 mA supply, a 30 mV ripple limit, and draws of at most 114 mA transmitting,
8.2 mA receiving, and 1.5 µA asleep. Pin 6 (NC) carries a dangling net label
`Lora_P1.01_GPIO2`; S3 GPIO2 is the trackball's `G_S2`.

### 10.2 TCXO, RF switch, and settings

| Setting | Meshtastic | MeshCore | LilyGO / LilyGoLib |
|---|---|---|---|
| DIO3 TCXO | 1.8 V | 1.8 V (retries at 0 V on SPI command error) | RadioLib default, **1.6 V** |
| DIO2 as RF switch | **On** | **Off** (`SX126X_DIO2_AS_RF_SWITCH=false`) | RadioLib default, **on** |
| Current limit | — | 140 mA | 140 mA (UnitTest) |
| RX boosted gain | — | On | — |
| TX power | — | 22 dBm | 22 dBm (7 dBm for Japan) |

Meshtastic's comments say the module "hooks the SX1262-DIO2 in to control the
TX/RX switch" and that DIO3 is "internally ... if DIO3 is high the TXCO is
enabled". Both mesh projects that ship T-Deck images agree on 1.8 V. The DIO2
disagreement cannot be settled from documents (no HPD16A datasheet was found);
compare receive RSSI and transmit range with DIO2 on and off. UMSH's other
LilyGO ESP32 boards use DIO2 on, DC-DC, and RX boost, with the TCXO voltage as a
board constant.

Antenna datasheets are in the T-Deck repository's `datasheet/` folder (433 MHz,
868–915 MHz, and the Plus antenna).

## 11. I²C bus

SDA GPIO18, SCL GPIO8 (Arduino `SDA`/`SCL` in Meshtastic's `pins_arduino.h`),
with 4.7 kΩ pull-ups to **V3V** (the GPIO10 rail).

| Device | Address | Rail |
|---|---|---|
| GT911 touch | `0x5D` or `0x14` | VDD3V3 |
| ES7210 microphone ADC | `0x40` | V3V |
| ESP32-C3 keyboard | `0x55` | V3V |

No IMU, RTC, PMIC, or fuel gauge. Bus speeds in use: 100 kHz on the C3's side
and in LilyGoLib and the Rust project, 400 kHz for touch in device-ui. MeshCore
probes the bus for an external RTC. Meshtastic's `BQ27220_ADDR 0x55 // same
address as TDECK_KB` concerns other boards.

## 12. GNSS (T-Deck Plus)

| Signal | GPIO |
|---|---:|
| ESP32 TX → GNSS RX | 43 (U0TXD) |
| ESP32 RX ← GNSS TX | 44 (U0RXD) |

These are the S3's UART0 pins, which carry the ROM boot log on GPIO43, and the
original T-Deck's Grove (HY2.0-4P) connector. MeshCore's `PIN_GPS_RX=43` /
`PIN_GPS_TX=44` names them from the module's side; its `setPins` call agrees.

Two module builds exist, each with its own LilyGO schematic:

| Module | Baud | Notes |
|---|---|---|
| u-blox **MIA-M10Q** (2024-03-29 sheet) | 38400, falling back to 9600 (LilyGO GPSShield; MeshCore 38400) | UBX protocol |
| Quectel **L76K** (2024-08-12 sheet) | 9600 | Configured with `$PCAS` sentences |

Meshtastic sets `GPS_DEFAULT_NOT_PRESENT` and autodetects; LilyGoLib probes
for both at 9600.

Both module sheets power the module from the connector's 3.3 V with no enable
line and keep its backup domain on a rechargeable MS412FE coin cell through a
1N4148. Their 5-pin connector carries PPS, but no source maps PPS to an S3
GPIO. With no enable line, the module draws power whenever the slide switch is
on; only its own backup or standby commands reduce that.

The coin cell keeps the module's RTC running with the switch off, and nothing
else on the board keeps time. The firmware reads that clock back at boot,
waking the module briefly if it is parked.

| Module | UART standby | Wake |
|---|---|---|
| MIA-M10Q | UBX-RXM-PMREQ, backup with `force`, no duration, `wakeupSources` = UART RX | Any edge at its RX; the byte is lost |
| L76K | None found: `$PCAS12` timed standby is reported unsupported on this part, and its standby is the STANDBY pin, which no source routes to an S3 GPIO | — |

A module woken by an RX edge makes the MCU's TX line part of its power state:
while it is parked, TX idles high rather than floating.

## 13. Audio

| Function | Part | Pins |
|---|---|---|
| Speaker | MAX98357A I²S amplifier (no control interface) | BCLK 7, WS 5, DOUT 6 |
| Microphone | ES7210 4-channel ADC (I²C `0x40`); MIC1 and MIC3 fitted | MCLK 48, LRCK 21, SCLK 47, SDOUT→S3 14 |

Meshtastic's `DAC_I2S_MCLK 21 // GPIO lrck mic` collides with the ES7210's
LRCK and is not used by the amplifier. The speaker key on the keyboard is just
the `$` key.

The firmware plays the communicator's sounds on I2S0 and DMA channel 1, at
16 kHz, 16-bit stereo, with no MCLK. With no control line, the amplifier is
silenced by stopping the I2S clocks: the transmitter is dropped between
sounds. Its level is the amplifier's fixed gain applied to tones at about
−12 dBFS; how loud that is on the fitted speaker has not been measured.

## 14. MicroSD

CS GPIO39 on the shared bus (§6), card supply on V3V, 22 Ω series resistors on
the data lines. No card-detect line reaches the S3.

## 15. Strapping pins, boot, and flashing

| GPIO | Strap role | T-Deck use | Note |
|---:|---|---|---|
| 0 | Boot mode | Trackball press | Held at reset enters download mode |
| 3 | JTAG source (only if the eFuse selects strapping) | Trackball up | Harmless with default eFuses |
| 45 | VDD_SPI voltage | SX1262 DIO1 | The radio is unpowered at reset (V3V off), so DIO1 cannot pull it high |
| 46 | Boot mode / ROM log | `C3_INT` (4.7 kΩ pull-up to V3V) | See below |

The schematic notes that GPIO46 high with GPIO0 low is invalid. LilyGO
attributes failed USB download-mode entry to the ESP32-C3 pulling GPIO46 high
(issue #62). The pull-up is on V3V, which should be off at reset, so the
mechanism is probably a rail that has not yet discharged after a reset-button
press; it is not confirmed. LilyGO's fix is to remove that resistor; users
report that grounding GPIO46 while entering download mode also works.

Manual download mode (LilyGoLib): switch off, connect USB, switch on, hold the
trackball, press and release the reset button on the left side, release the
trackball, flash.

USB is native USB-Serial-JTAG on GPIO19/20, `303a:1001` (Meshtastic's board
definition, which also requests a 1200-baud touch on upload). LilyGoLib's
Arduino variant enumerates as `303a:81b5` "T-Deck", so a factory or
Arduino-built image may not answer espflash's reset request, as on the XIAO
ESP32S3 (§6.3 of its reference); use the manual sequence then.

## 16. Comparison with the T-LoRa Pager

| | T-LoRa Pager | T-Deck |
|---|---|---|
| Panel | ST7796, 480×222 visible | ST7789, 320×240 |
| SPI write clock | 80 MHz | 40 MHz |
| Backlight | AW9364 on GPIO42 | AW9364 on GPIO42 (same protocol) |
| PSRAM | 8 MiB quad | 8 MiB **octal** |
| Navigation | Rotary encoder and press | Four-direction trackball and press (GPIO0) |
| Touch | None | GT911 |
| Keyboard | TCA8418 matrix on the host's I²C, key up/down events | ESP32-C3 sending finished characters (raw matrix optional) |
| Keyboard light | GPIO46 | I²C command to the C3 |
| Lock / power button | BOOT (GPIO0) | None; GPIO0 is the trackball press |
| Haptics | DRV2605 | None |
| Audio | ES8311 codec | MAX98357A amplifier only |
| Power | XL9555 expander, BQ25896 charger, BQ27220 gauge | GPIO10 rail, TP4065B, voltage divider |
| Power-off | Charger ship mode | Slide switch only |
| RTC | PCF85063 | None |
| Motion | BHI260AP | None |
| GNSS | MIA-M10Q, always fitted | Plus only (MIA-M10Q or L76K) |

## 17. Open questions for hardware

1. Display colors, inversion, and gamma with LilyGoLib's init list, on an
   original and a Plus panel.
2. Whether the panel runs reliably above 40 MHz.
3. Touch address on each unit; on a Plus panel, the INT idle level, whether
   INT is driven while idle, edge versus level mode; and the corner mapping.
4. Keyboard firmware date on each unit: whether `0x01` backlight and `0x03`
   raw mode are answered, and what an old image returns for a 5-byte read.
5. Physical position of Alt, Sym, the Shifts, and Mic.
6. Trackball edges per revolution, bounce, and diagonal behavior.
7. SX1262 DIO2 on versus off, and TCXO 1.8 V versus 1.6 V.
8. Whether USB power alone lights V3V on any unit (the NC diode in §4.2).
9. ADC reading on USB versus battery, against a meter.
10. Current with V3V on and the radio asleep (the C3, the trackball sensors,
    and the audio parts' quiescent draw) versus V3V off; light- and deep-sleep current; GNSS
    module standby on the Plus.

## 18. Sources

- LilyGO T-Deck repository: https://github.com/Xinyuan-LilyGO/T-Deck
  - Schematic: `schematic/schematic.pdf`; GPS modules:
    `schematic/T-Deck-GPS V1.0  24-03-29.pdf`,
    `schematic/T-Deck-L76K V1.0  24-08-12.pdf`
  - Pins: `examples/UnitTest/utilities.h`; factory test:
    `examples/UnitTest/UnitTest.ino`
  - Keyboard: `examples/Keyboard_ESP32C3/Keyboard_ESP32C3.ino`,
    `examples/Keyboard_T_Deck_Master/Keyboard_T_Deck_Master.ino`, prebuilt
    images in `firmware/`
  - `examples/GPSShield/GPSShield.ino`,
    `lib/TFT_eSPI/User_Setups/Setup210_LilyGo_T_Deck.h`, `README.MD`
  - Issues #9 (keyboard interrupt), #32 (keyboard backlight), #42 (touch INT),
    #61 (backlight PWM), #62 (download mode and GPIO46), #69 (Alt+B)
- LilyGoLib: https://github.com/Xinyuan-LilyGO/LilyGoLib
  - `src/LilyGo_T_Deck.cpp`, `src/LilyGo_T_Deck.h`,
    `src/display/TDeckDisplayConfig.h`, `src/input/TDeckKeyboard.cpp`
  - `arduino/temporary_tdeck/variants/lilygo_tdeck/pins_arduino.h`
  - `docs/hardware/lilygo-t-deck.md`, `docs/lilygo-t-deck.md`
- Meshtastic PRs #2786 (keyboard power-down while dark) and #2847 (its
  revert): https://github.com/meshtastic/firmware/pull/2786,
  https://github.com/meshtastic/firmware/pull/2847
- Community keyboard firmware: https://github.com/hasn0life/t-deck-keyboard-ex,
  https://github.com/rgrizzell/lilygo-t-deck-keyboard,
  https://github.com/hreikin/tdeck-keyboard
- Meshtastic: https://github.com/meshtastic/firmware/tree/develop/variants/esp32s3/t-deck
  (`variant.h`, `variant.cpp`, `platformio.ini`, `pins_arduino.h`),
  `boards/t-deck.json`, `src/input/kbI2cBase.cpp`,
  `src/input/TrackballInterruptBase.cpp`
- Meshtastic device-ui:
  https://github.com/meshtastic/device-ui/blob/master/include/graphics/LGFX/LGFX_T_DECK.h
- MeshCore: https://github.com/meshcore-dev/MeshCore/tree/main/variants/lilygo_tdeck
  (`platformio.ini`, `TDeckBoard.cpp/.h`, `target.cpp`),
  `src/helpers/radiolib/CustomSX1262.h`
- Rust (esp-hal) experiment: https://github.com/joshmarinacci/rust-tdeck-experiments
- ESP32-C3 datasheet v2.4 (Table 5-8, modem-sleep current):
  https://www.espressif.com/sites/default/files/documentation/esp32-c3_datasheet_en.pdf
- AW9364 datasheet (Awinic, V2.4):
  https://doc.awinic.com/doc/202402/d1a46d65-a45d-494f-bfc9-3d6a6a93a860.pdf
- RadioLib SX126x defaults: https://github.com/jgromes/RadioLib/tree/master/src/modules/SX126x
- LilyGO T-Deck Plus wiki: https://wiki.lilygo.cc/products/t-deck-series/t-deck-plus/
