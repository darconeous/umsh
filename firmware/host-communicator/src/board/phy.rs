//! The device's radio: an IP multicast group, as a LoRa board's is its
//! modem. It serves the multiplexer's real radio bundle and the session's
//! radio control, as `umsh_radio_loraphy::device_runner` does for a chip,
//! so the session and the device node above it are the Pager's own.
//!
//! The group is the session's `PROP_LAN_BEARER_GROUP`, joined while the
//! PHY is on, and `PROP_LAN_BEARER_STATE` says how that went. A group that
//! cannot be joined, as on a host with no network yet, is tried again
//! every couple of seconds. What the group carries is received unmeasured
//! (`RxOrigin::Bearer`), and the device's own echoes are dropped.

use std::future::poll_fn;
use std::net::SocketAddrV4;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;
use umsh::hal::{BearerId, Radio as _, TxOptions};
use umsh::tokio_support::{LanConfig, RxMode, UdpMulticastRadio};
use umsh_radio_loraphy::{ControlRequest, MAX_PAYLOAD, RxFrame};
use umsh_ulcp::lan::State;

use super::{DEVICE_CTL, REAL_CH};

/// How long to wait before trying the group again.
const REJOIN_DELAY: Duration = Duration::from_secs(2);

/// What the device asks of its radio, and what it is told back.
pub struct Phy {
    /// The interface and loopback every group is joined with.
    pub base: LanConfig,
    /// The session's group.
    pub group: watch::Receiver<SocketAddrV4>,
    /// How joining it went.
    pub state: watch::Sender<State>,
    /// Never join: a script's device shows only what the script did.
    pub offline: bool,
}

/// The group joined, or being tried.
struct Membership {
    group: SocketAddrV4,
    radio: Option<UdpMulticastRadio>,
    retry_at: Option<Instant>,
}

impl Phy {
    pub async fn run(mut self) {
        let mut enabled = false;
        let mut membership: Option<Membership> = None;
        let mut buf = [0u8; MAX_PAYLOAD];
        loop {
            self.follow(enabled, &mut membership);
            let retry_at = membership.as_ref().and_then(|joined| joined.retry_at);
            let mut joined = membership.as_mut().and_then(|joined| joined.radio.as_mut());
            let listening = joined.is_some();
            tokio::select! {
                request = DEVICE_CTL.next_request() => match request {
                    ControlRequest::Settings(settings) => {
                        if DEVICE_CTL.shutdown_requested() {
                            DEVICE_CTL.shutdown_complete();
                            return;
                        }
                        enabled = settings.enabled;
                    }
                    // Nothing measures the group.
                    ControlRequest::Rssi => DEVICE_CTL.answer_rssi(Err(())),
                    ControlRequest::Temperature(id) => DEVICE_CTL.answer_temperature(id, None),
                },
                Ok(()) = self.group.changed() => {}
                // A radio takes frames only while it is on, as a chip does.
                request = REAL_CH.tx.receive(), if enabled => {
                    // A send that fails, or finds no group, is a frame lost
                    // on the medium, which the protocol above tolerates.
                    if let Some(radio) = membership.as_mut().and_then(|joined| joined.radio.as_mut()) {
                        let _ = radio.transmit(&request.data, TxOptions::default()).await;
                    }
                    REAL_CH.tx_done.signal(Ok(()));
                }
                Some(received) = poll_fn(|cx| match joined {
                    Some(ref mut radio) => radio.poll_receive(cx, &mut buf).map(Result::ok),
                    None => std::task::Poll::Pending,
                }), if listening => {
                    let mut frame = RxFrame { data: Default::default(), info: received };
                    if frame.data.extend_from_slice(&buf[..received.len]).is_ok()
                        && REAL_CH.rx.try_send(frame).is_ok()
                    {
                        REAL_CH.rx_waker.wake();
                    }
                }
                () = tokio::time::sleep_until(retry_at.unwrap_or_else(Instant::now)),
                    if retry_at.is_some() =>
                {
                    if let Some(joined) = &mut membership {
                        joined.retry_at = None;
                    }
                    let group = membership.take().map(|joined| joined.group);
                    self.join(group, &mut membership);
                }
            }
        }
    }

    /// Joins the group the session asks for, if it is not the one
    /// joined, and leaves it while the PHY is off.
    fn follow(&mut self, enabled: bool, membership: &mut Option<Membership>) {
        let wanted = (enabled && !self.offline).then(|| *self.group.borrow());
        if wanted == membership.as_ref().map(|joined| joined.group) {
            return;
        }
        *membership = None;
        self.join(wanted, membership);
    }

    fn join(&mut self, group: Option<SocketAddrV4>, membership: &mut Option<Membership>) {
        let state = match group {
            None => State::Disabled,
            Some(group) => {
                let radio = UdpMulticastRadio::bind(
                    LanConfig { group, ..self.base },
                    RxMode::Bearer(BearerId::LAN),
                    UdpMulticastRadio::SIMULATED_T_FRAME_MS,
                )
                .ok();
                let state = if radio.is_some() {
                    State::Active
                } else {
                    State::NoNetwork
                };
                let retry_at = radio.is_none().then(|| Instant::now() + REJOIN_DELAY);
                *membership = Some(Membership {
                    group,
                    radio,
                    retry_at,
                });
                state
            }
        };
        self.state.send_replace(state);
    }
}
