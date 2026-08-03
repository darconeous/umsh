#![no_std]

//! Board support for the Seeed Studio **XIAO nRF52840 & Wio-SX1262 Kit**
//! (SKU 102010710) — a XIAO nRF52840 controller mated to a Wio-SX1262 for
//! XIAO radio carrier through the standard 2×7 header.
//!
//! Composes [`umsh-bsp-nrf52840`](../umsh_bsp_nrf52840/index.html) with
//! this board's pinout. Both halves of the kit have published Seeed
//! schematics, so unlike most boards in this directory the pin map is
//! schematic-confirmed rather than reconstructed from vendor firmware.
//!
//! See `docs/hardware/seeed-xiao-nrf52840-wio-sx1262-kit-hardware.md`.
//!
//! # Relationship to the SenseCAP Solar Node
//!
//! Both are XIAO-pinout carriers around the same Wio SX1262 module, so
//! the radio wiring and the battery-sense topology are shared *pin for
//! pin* — the firmware's SX1262 bring-up block is literally the same code
//! for both boards. The [`Platform`](umsh_mac::Platform) bundle is a
//! verbatim copy. What differs is LED polarity, the charger, the divider
//! gating rule, and the complete absence of buttons.
//!
//! # Pin map (nRF52840; schematic-confirmed)
//!
//! The BSP and firmware name the `P0_xx` / `P1_xx` embassy-nrf pins
//! directly. The Arduino logical column exists only for cross-referencing
//! the Meshtastic and MeshCore variant files, whose `g_ADigitalPinMap`
//! arrays are byte-for-byte identical to each other.
//!
//! | Function                       | Logical | nRF pin      | Notes |
//! |--------------------------------|--------:|--------------|-------|
//! | GNSS standby (optional L76K)   | 0       | `P0.02`      | also the unpopulated button footprint — see below |
//! | Radio DIO1                     | 1       | `P0.03`      | |
//! | Radio RESET                    | 2       | `P0.28`      | **10 kΩ pull-up on the carrier** — idles released |
//! | Radio BUSY                     | 3       | `P0.29`      | |
//! | Radio CS                       | 4       | `P0.04`      | 22 Ω series |
//! | Radio RXEN (`RF_SW1`)          | 5       | `P0.05`      | **no pull** — drive deterministically and early |
//! | GNSS UART TX (MCU→L76K)        | 6       | `P1.11`      | unconnected on the carrier |
//! | GNSS UART RX (L76K→MCU)        | 7       | `P1.12`      | unconnected on the carrier |
//! | Radio SPI SCK                  | 8       | `P1.13`      | 22 Ω series |
//! | Radio SPI MISO                 | 9       | `P1.14`      | 22 Ω series |
//! | Radio SPI MOSI                 | 10      | `P1.15`      | 22 Ω series |
//! | RGB LED red                    | 11      | `P0.26`      | common anode, **active low**, 2.2 kΩ |
//! | RGB LED blue                   | 12      | `P0.06`      | common anode, **active low**, 2.2 kΩ |
//! | RGB LED green                  | 13      | `P0.30`      | common anode, **active low**, 10 kΩ — visibly dimmer |
//! | Battery divider low side       | 14      | `P0.14`      | **drive LOW always** — see [`power`] |
//! | Charge-current select (HICHG)  | 22      | `P0.13`      | LOW → 100 mA, HIGH/input → 50 mA |
//! | Charge status (`~CHG`)         | 23      | `P0.17`      | BQ25100 open drain, LOW = charging. **Read only** |
//! | QSPI flash (P25Q16H, 2 MB)     | 24–29   | see below    | reserved; NV store is internal NVMC |
//! | NFC pads                       | 30–31   | `P0.09/0.10` | GPIO use needs UICR `NFCPINS` cleared |
//! | Battery ADC                    | 32      | `P0.31`/AIN7 | |
//! | RESET                          | —       | `P0.18`      | `nRESET` via UICR `PSELRESET`; not readable as GPIO |
//! | LF crystal                     | —       | `P0.00/0.01` | 32.768 kHz fitted — `lfclk-xtal`, no RC fallback |
//!
//! QSPI, for the record: SCK `P0.21`, CSN `P0.25`, IO0 `P0.20`, IO1
//! `P0.24`, IO2 `P0.22`, IO3 `P0.23`. The part **is** fitted despite the
//! schematic's stale `DNP` annotation. Nothing here uses it, but the pins
//! must not be repurposed.
//!
//! # This board is headless
//!
//! A stock kit has exactly one button: the XIAO's RESET, which is
//! `nRESET` and unreadable from the application. The radio carrier's K1
//! footprint — the one place a user button would go — **ships bare, and
//! so does its R2 pull-up**.
//!
//! Every gesture UX the other UMSH boards rely on is therefore
//! unavailable: no hold-to-power-off, no press-to-wake, no
//! hold-at-boot force-pairing ceremony. Configuration and control come
//! over USB-CDC (ULCP) or BLE. System OFF is reached only by the
//! protective low-battery cutoff, and its only exits are the reset
//! button, a USB attach, or a future LPCOMP battery-recovery wake. See
//! [`shutdown`].
//!
//! ## Pairing without a button
//!
//! The missing force-pairing gesture is the one absence that would
//! otherwise be fatal rather than merely inconvenient: with pairing mode
//! normally opening only when no bonds exist, the first host to bond
//! would own the radio permanently, and nothing short of a full security
//! wipe over that host's own link could ever let a second one in.
//!
//! So the firmware for this board builds with `boot-pairing-window`: a
//! **20-second BLE pairing window opens on every boot**, bonded or not.
//! Pressing RESET is the physical-presence ceremony here, standing in for
//! the button hold the other boards use. A configured PIN still gates the
//! pairing itself and the repeated-failure lockout still applies, so the
//! window enables attempts rather than granting access.
//!
//! This is an interim measure, not a designed answer — it trades a
//! recurring 20 s exposure on every reset for not locking users out, and
//! a board whose reset button is reachable by anyone is a board whose
//! pairing window is reachable by anyone. Revisit alongside the
//! retrofitted-button profile.
//!
//! `P0.02` is left as a **disconnected** input in this configuration. It
//! has no external pull of any kind, and a floating pin with the input
//! buffer connected sits near mid-rail and burns current through it —
//! which on a board chasing a < 5 µA standby figure is not a rounding
//! error.
//!
//! ## If K1 is retrofitted
//!
//! Soldering a switch into K1 is the intended way to add a button, and
//! it is a supported thing to want — but it is not what this crate
//! builds today, and the requirements are sharp enough to record here
//! for whoever adds it:
//!
//! - **The internal pull-up is mandatory**, not belt-and-braces: R2 is
//!   absent, so nothing else holds `P0.02` high.
//! - Active low, and debounce generously — a bare mechanical switch with
//!   no hardware RC bounces freely.
//! - Arming System OFF wake means `SENSE_LOW` **with the pull-up
//!   retained**. MeshCore's `XiaoNrf52Board::powerOff()` passes
//!   `NRF_GPIO_PIN_NOPULL` here, which is correct only where an external
//!   pull-up exists; on this carrier it leaves the pin floating into a
//!   low detector, and the board wakes spuriously or immediately.
//! - `P0.02` is mutually exclusive with the L76K's standby line, so a
//!   button build and a GNSS build cannot be the same build.

#[cfg(target_os = "none")]
pub mod platform;

#[cfg(target_os = "none")]
pub mod power;

#[cfg(target_os = "none")]
pub mod shutdown;

#[cfg(target_os = "none")]
pub use platform::{XiaoNrf52Mac, XiaoNrf52Platform};
#[cfg(target_os = "none")]
pub use power::PowerSignaler;
