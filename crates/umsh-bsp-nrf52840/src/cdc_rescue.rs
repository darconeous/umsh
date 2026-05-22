//! Rescue-protected wrapper around `embassy_usb::class::cdc_acm`.
//!
//! Hides the raw [`Receiver`] and [`ControlChanged`] halves behind a
//! single type whose `read_packet` always runs the firmware's two
//! recovery paths:
//!
//! 1. **1200-baud touchless reset.** When the host opens the CDC port
//!    at 1200 baud and drops DTR, this enters UF2 DFU mode. Matches the
//!    Adafruit / Arduino convention; what `flasher.meshcore.co.uk`,
//!    `adafruit-nrfutil --touch 1200`, and `arduino-cli` all expect.
//!
//! 2. **Magic escape sequence.** Receiving `Ctrl-C Ctrl-C Ctrl-C dfu\r`
//!    in the inbound byte stream also enters UF2 DFU mode. Lets a human
//!    at a terminal force DFU when a CLI is wedged.
//!
//! ## Why a wrapper instead of a free-standing rescue task?
//!
//! Both rescue paths fundamentally need access to the CDC's received
//! bytes (for the escape sequence) and to the CDC's `LineCoding`
//! (for the 1200-baud baud-rate check at the moment DTR drops). Both
//! of those live behind `&mut Receiver` in embassy-usb 0.6, so a
//! separately-spawned task can't read them while the application is
//! also reading. Hiding the `Receiver` inside this wrapper is the
//! straightforward way to keep both checks always-active.
//!
//! ## Defensive design
//!
//! Application code is given only this wrapper (for reads) and the
//! `Sender` (for writes). There is no constructor that exposes the
//! inner `Receiver` or `ControlChanged`. So a future refactor that
//! adds a CLI on top of this cannot accidentally bypass the rescue
//! checks — they happen on every byte the application sees, by
//! construction.
//!
//! The one contract the application owes: keep calling
//! [`CdcAcmRescue::read_packet`] in a loop. If the application stops
//! reading entirely, the 1200-baud and escape checks stop firing too.
//! For typical CLI / echo / line-protocol code this is satisfied
//! naturally.

use embassy_futures::select::{Either, select};
use embassy_usb::class::cdc_acm::{ControlChanged, Receiver};
use embassy_usb::driver::{Driver, EndpointError};

use crate::gpregret;
use crate::rescue::{EscapeWatcher, RescueAction};

/// A `Receiver` + `ControlChanged` pair wrapped to run rescue checks
/// transparently on every read.
///
/// Construct with [`CdcAcmRescue::new`] from the output of
/// `CdcAcmClass::split_with_control()`:
///
/// ```ignore
/// let (mut tx, rx, ctrl) = class.split_with_control();
/// let mut rx = CdcAcmRescue::new(rx, ctrl);
/// loop {
///     rx.wait_connection().await;
///     // ... use `tx` for writes, `rx.read_packet(...)` for reads ...
/// }
/// ```
pub struct CdcAcmRescue<'d, D: Driver<'d>> {
    rx: Receiver<'d, D>,
    ctrl: ControlChanged<'d>,
    escape: EscapeWatcher,
}

impl<'d, D: Driver<'d>> CdcAcmRescue<'d, D> {
    pub fn new(rx: Receiver<'d, D>, ctrl: ControlChanged<'d>) -> Self {
        Self { rx, ctrl, escape: EscapeWatcher::new() }
    }

    /// Wait until the host asserts DTR (opens the port).
    pub async fn wait_connection(&self) {
        while !self.ctrl.dtr() {
            self.ctrl.control_changed().await;
        }
    }

    /// Read up to one USB packet into `buf` and return the byte count.
    ///
    /// Runs both rescue paths before returning:
    /// - If the magic escape sequence appears in the received bytes,
    ///   diverges into [`gpregret::enter_dfu_uf2`].
    /// - If DTR drops while the line coding is at 1200 baud, diverges
    ///   into [`gpregret::enter_dfu_uf2`].
    ///
    /// Returns `Ok(0)` when DTR drops at any other baud rate (port
    /// closed normally — caller should loop back to `wait_connection`).
    /// Returns `Err` on USB endpoint errors.
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, EndpointError> {
        loop {
            match select(self.rx.read_packet(buf), self.ctrl.control_changed()).await {
                Either::First(result) => {
                    let n = result?;
                    if n > 0
                        && self.escape.observe_slice(&buf[..n]) == RescueAction::TriggerDfu
                    {
                        gpregret::enter_dfu_uf2();
                    }
                    return Ok(n);
                }
                Either::Second(()) => {
                    if !self.ctrl.dtr() {
                        if self.rx.line_coding().data_rate() == 1_200 {
                            gpregret::enter_dfu_uf2();
                        }
                        // Port closed at a different baud — surface as EOF.
                        return Ok(0);
                    }
                    // DTR still high (baud/RTS change). Loop and retry the read.
                }
            }
        }
    }
}
