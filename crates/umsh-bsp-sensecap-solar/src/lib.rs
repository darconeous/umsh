#![no_std]

//! Board support for the SenseCAP Solar Node P1 / P1-Pro (nRF52840 +
//! SX1262).
//!
//! Composes [`umsh-bsp-nrf52840`](../umsh_bsp_nrf52840/index.html) with
//! the Solar Node's pinout and on-board peripherals. This is the fourth
//! `nRF52840 + SX1262`-class board, after the T-Echo, Wio Tracker L1,
//! and T1000-E; the radio path is byte-for-byte the Wio Tracker L1
//! configuration (external RXEN, DIO2-as-RF-switch, DIO3 TCXO at 1.8 V)
//! on a different pin map. The [`Platform`](umsh_mac::Platform) bundle is
//! therefore a verbatim copy of the Wio Tracker's.
//!
//! The same crate is intended to cover both the P1 and the P1-Pro, which
//! are believed to differ only in GNSS module and battery pack.
//!
//! Initial scope is *bringup only* (see
//! `docs/firmware-plan-sensecap-solar-node-p1-pro.md`):
//!
//! - USB-CDC handles (over the nRF native USB peripheral, chip BSP)
//! - two user LEDs and two buttons for identification (Phase 1)
//! - calibrated battery measurement (Phase 2)
//! - SX1262 LoRa radio + external RXEN pin (Phase 3)
//!
//! Future expansion (companion-NCP device-node behavior, low-battery
//! System OFF + LPCOMP solar recovery, GNSS) is welcome but is not yet
//! implemented.
//!
//! See `docs/sensecap-solar-node-p1-pro-hardware.md` for the
//! firmware-derived hardware reference.
//!
//! # Pin map (nRF52840, from the Meshtastic `seeed_solar_node` variant)
//!
//! The BSP and firmware hard-code the `P0_xx` / `P1_xx` embassy-nrf pins
//! directly; the Arduino logical numbers below appear only for
//! cross-referencing the vendor sources.
//!
//! | Function                     | Logical | nRF pin      | Notes |
//! |------------------------------|--------:|--------------|-------|
//! | GNSS standby/wake            | 0       | `P0.02`      | polarity unverified |
//! | Radio DIO1                   | 1       | `P0.03`      | |
//! | Radio RESET                  | 2       | `P0.28`      | |
//! | Radio BUSY                   | 3       | `P0.29`      | |
//! | Radio CS                     | 4       | `P0.04`      | |
//! | Radio RXEN                   | 5       | `P0.05`      | drive LOW at boot, then `rf_switch_rx` |
//! | GNSS UART TX (MCU→L76K)       | 6       | `P1.11`      | NMEA 9600 |
//! | GNSS UART RX (L76K→MCU)       | 7       | `P1.12`      | |
//! | Radio SPI SCK                | 8       | `P1.13`      | |
//! | Radio SPI MISO               | 9       | `P1.14`      | |
//! | Radio SPI MOSI               | 10      | `P1.15`      | |
//! | LED_A ("User LED")           | 11      | `P0.15`      | **white, active-high** (confirmed 2026-07-23) |
//! | LED_B ("Breathing"/TX LED)   | 12      | `P0.19`      | **blue, active-high** (confirmed); heartbeat LED |
//! | USER_BUTTON                  | 13      | `P1.01`      | active-low, internal pull-up (confirmed) |
//! | Grove SDA                    | 14      | `P0.09`      | NFC pin — NFCT off / UICR NFCPINS cleared for GPIO |
//! | Grove SCL                    | 15      | `P0.10`      | NFC pin, ditto |
//! | Battery ADC                  | 16      | `P0.31`/AIN7 | Phase 2 |
//! | GNSS RESET (candidate)       | 17      | `P1.03`      | never driven — input only until characterized |
//! | GNSS ENABLE                  | 18      | `P1.05`      | likely active-high; held inactive in bringup |
//! | Battery divider enable (n)   | 19      | `P0.14`      | active-low per MeshCore, verify (Phase 2) |
//! | PWR button (USER_BUTTON_2)   | 20      | `P1.07`      | **labeled "PWR"**, active-low, pull-up (confirmed); soft — pressing it does NOT cut the MCU rail |
//! | QSPI flash (P25Q16H)         | 21–26   | see hw doc   | reserved, unused (NV store is internal NVMC) |

#[cfg(target_os = "none")]
pub mod platform;

#[cfg(target_os = "none")]
pub mod power;

#[cfg(target_os = "none")]
pub mod shutdown;

#[cfg(target_os = "none")]
pub use platform::{SensecapSolarMac, SensecapSolarPlatform};
#[cfg(target_os = "none")]
pub use power::PowerSignaler;

// TODO (see docs/firmware-plan-sensecap-solar-node-p1-pro.md):
//   Phase 2: pub mod power  — port the T1000-E battery monitor
//            (SAADC AIN7/P0.31, gated divider P0.14) with calibrated
//            slope/offset constants.
//   Phase 6: low-battery System OFF + LPCOMP solar-recovery wake.
//   Phase 7: pub mod gnss   — L76K UART/NMEA (P1.11/P1.12).
