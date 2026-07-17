#![no_std]

//! UX mechanism for tracker-class UMSH boards.
//!
//! This crate is the user-experience layer for boards whose physical
//! UX is: one button, one status LED, one piezo buzzer, battery
//! power, no display, no speaker, no keyboard. Both Seeed Studio
//! SenseCap T1000-E and SenseCap Solar P1 fall in this class.
//!
//! The crate provides only **mechanism**, not policy:
//!
//! - [`button`] — recognize Single / Double / Triple / Long button
//!   events from raw debounced edges + a monotonic-millisecond clock.
//! - [`led`] — drive a single-LED heartbeat with one-shot sequences
//!   layered on top (power-on, power-off, location-advert, …).
//! - [`buzzer`] — play short tone melodies on a piezo buzzer with
//!   silence-mode support.
//! - [`power`] — vocabulary ([`PowerIntent`](power::PowerIntent),
//!   [`PowerIntentSource`](power::PowerIntentSource)) shared by every
//!   source that wants to take the device out of normal operation,
//!   plus a [`LowBatteryDetector`](power::LowBatteryDetector) that
//!   protects the Li-ion cell when no hardware undervoltage cutoff
//!   exists.
//!
//! Policy (which event maps to which action, which CLI commands
//! exist, how the MAC integrates) belongs in the consuming app
//! crate, e.g. `umsh-app-companion-cli`.
//!
//! Devices in a different class (handheld with screen + speaker +
//! keyboard, headless mesh nodes) need their own `umsh-ux-<class>`
//! crate because the abstractions here — single-LED heartbeat,
//! piezo-tone melodies, gesture-on-one-button — do not generalize
//! meaningfully across classes.
//!
//! See `docs/firmware-architecture.md` for the broader BSP / UX / App
//! / Binary layering.

pub mod battery;
pub mod button;
pub mod buzzer;
pub mod led;
pub mod power;
pub mod state;
