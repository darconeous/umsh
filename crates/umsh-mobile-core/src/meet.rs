//! Add Peer's contact exchange (`app-meet.md`) as the phone runs it: the
//! shared [`Meeting`], and the records the platform reads of it.

use umsh_core::PublicKey;
use umsh_node::meet::{EndReason, Exchange, Exchanged, Meeting, Nearby};

/// A device listed on Nearby: what kind of device it is and its color for
/// this visit, and nothing of whose it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeetDeviceRecord {
    /// Its place on Nearby, stable while it stays listed; what
    /// `ask_to_exchange` names.
    pub id: u32,
    /// Its model id (`boards.json`, `platforms.json`); 0 when unspecified.
    pub model: u16,
    /// Its session color, as `0xRRGGBB`.
    pub color_rgb: u32,
    /// How near it seems, 0 (far) to 3 (close), once a Hello's signal is
    /// known.
    pub nearness: Option<u8>,
}

/// Why an exchange ended without contacts crossing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileMeetEnd {
    /// The other holder declined.
    NotNow,
    /// The other device is in another exchange.
    Busy,
    /// A holder found the codes different.
    Different,
    /// The other holder backed out or closed Add Peer.
    Left,
    /// A step took too long.
    TimedOut,
    /// Something did not check out.
    Failed,
}

/// Who the other device says its holder is, once contacts have crossed.
/// Nothing is saved.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeetContactRecord {
    pub peer_address: String,
    /// Their node identity bundle, ROLE through any signature, as received.
    pub identity_bundle: Vec<u8>,
    /// A valid signature by the peer's key covers the bundle. Without one,
    /// the name and the rest are not linked to the key.
    pub signed: bool,
}

/// Where the exchange stands.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileMeetExchange {
    /// Add Peer's exchange is not open.
    Closed,
    /// The session is being set up.
    Opening,
    /// Listed on Nearby, nothing in progress.
    Idle,
    /// This phone asked; waiting for an answer.
    Asking {
        device: MobileMeetDeviceRecord,
    },
    /// This phone was asked; waiting for its holder.
    Asked {
        device: MobileMeetDeviceRecord,
    },
    /// This phone agreed; waiting for the other device.
    Accepted {
        device: MobileMeetDeviceRecord,
    },
    /// Both show `code`. `sent` once this phone's holder pressed Same.
    Comparing {
        device: MobileMeetDeviceRecord,
        code: u32,
        sent: bool,
    },
    Ended {
        reason: MobileMeetEnd,
    },
    Exchanged {
        contact: MobileMeetContactRecord,
    },
}

/// What Add Peer shows of the exchange.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeetStateRecord {
    /// This phone's color for this visit, once its session is up.
    pub own_color_rgb: Option<u32>,
    /// The devices heard, oldest first.
    pub devices: Vec<MobileMeetDeviceRecord>,
    /// The device the exchange is with, or was until it ended.
    pub device: Option<MobileMeetDeviceRecord>,
    pub exchange: MobileMeetExchange,
}

/// What the platform asks of the exchange.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MeetRequest {
    /// Open Add Peer's exchange under a fresh session key, ending any
    /// attempt in progress. `model` is this phone's platform id.
    Open {
        model: u16,
    },
    Close,
    Ask {
        device: u32,
    },
    Answer {
        accept: bool,
    },
    /// The holder pressed Same (`true`) or Different.
    Confirm {
        same: bool,
    },
    Cancel,
}

/// The phone's contact exchange, and whether what the platform shows of it
/// has changed since it was last published.
pub(crate) struct PhoneMeeting {
    pub meeting: Meeting<MobileMeetContactRecord>,
    changed: bool,
}

impl PhoneMeeting {
    pub fn new() -> Self {
        Self {
            meeting: Meeting::new(),
            changed: false,
        }
    }

    /// Runs `f` on the meeting, noting any change, and keeps what crossed.
    pub fn with(
        &mut self,
        f: impl FnOnce(&mut Meeting<MobileMeetContactRecord>, &mut dyn FnMut()) -> Option<Exchanged>,
    ) {
        let mut changed = false;
        let theirs = f(&mut self.meeting, &mut || changed = true);
        if let Some(theirs) = theirs {
            let contact = MobileMeetContactRecord {
                peer_address: crate::mobile_mesh::encode_peer_address(&theirs.key),
                identity_bundle: theirs.payload,
                signed: theirs.signed,
            };
            self.meeting.exchanged_with(contact, &mut || changed = true);
        }
        self.changed |= changed;
    }

    /// Opens Add Peer's exchange for an attempt under a fresh key.
    pub fn open(&mut self, now_ms: u64, model: u16, own: PublicKey, frame_ms: u32) {
        self.meeting.set_model(model);
        let frame_ms = (frame_ms > 0).then_some(frame_ms);
        self.with(|meeting, changed| {
            meeting.open(now_ms, own, frame_ms, changed);
            None
        });
    }

    /// The state to publish, when it changed since the last.
    pub fn take_state(&mut self) -> Option<MobileMeetStateRecord> {
        if !core::mem::take(&mut self.changed) {
            return None;
        }
        let meeting = &self.meeting;
        Some(MobileMeetStateRecord {
            own_color_rgb: meeting.own_color(),
            devices: meeting.devices().map(device).collect(),
            device: meeting.with().map(device),
            exchange: match meeting.exchange() {
                Exchange::Closed => MobileMeetExchange::Closed,
                Exchange::Opening => MobileMeetExchange::Opening,
                Exchange::Idle => MobileMeetExchange::Idle,
                Exchange::Asking(with) => MobileMeetExchange::Asking {
                    device: device(with),
                },
                Exchange::Asked(with) => MobileMeetExchange::Asked {
                    device: device(with),
                },
                Exchange::Accepted(with) => MobileMeetExchange::Accepted {
                    device: device(with),
                },
                Exchange::Comparing { with, code, sent } => MobileMeetExchange::Comparing {
                    device: device(with),
                    code,
                    sent,
                },
                Exchange::Ended(reason) => MobileMeetExchange::Ended {
                    reason: ending(reason),
                },
                Exchange::Exchanged(contact) => MobileMeetExchange::Exchanged { contact },
            },
        })
    }
}

const fn device(nearby: Nearby) -> MobileMeetDeviceRecord {
    MobileMeetDeviceRecord {
        id: nearby.id,
        model: nearby.model,
        color_rgb: nearby.color,
        nearness: nearby.nearness,
    }
}

const fn ending(reason: EndReason) -> MobileMeetEnd {
    match reason {
        EndReason::NotNow => MobileMeetEnd::NotNow,
        EndReason::Busy => MobileMeetEnd::Busy,
        EndReason::Different => MobileMeetEnd::Different,
        EndReason::Left => MobileMeetEnd::Left,
        EndReason::TimedOut => MobileMeetEnd::TimedOut,
        EndReason::Failed | EndReason::Unknown(_) => MobileMeetEnd::Failed,
    }
}
