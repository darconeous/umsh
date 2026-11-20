//! The radio driver: everything a companion radio session does above its
//! transport.
//!
//! The driver runs the ULCP session over a link that native code owns,
//! carries the mesh session's frames to and from the radio, paces raw
//! transmits, keeps the deadlines a silent radio would otherwise strand
//! callers behind, and owns the radio's whole published state, transport
//! phases included. Native code owns discovery, connecting, bonding, the
//! framing its medium needs, and what it persists; it reports the
//! transport's state here and carries out the link calls the driver makes.
//!
//! [`core`] is the logic, a synchronous state machine with an explicit
//! clock. [`runner`] is the one thread that feeds it events and timer
//! expiries in order and carries out what it decides.

mod core;
mod runner;
#[cfg(test)]
mod tests;

use std::fmt;

use crate::{
    MobileError, UlcpAlertState, UlcpBatteryRecord, UlcpGnssRecord, UlcpHostOwnership,
    UlcpReceivedFrameRecord, UlcpSyncRecord, ulcp::UlcpPropertyPushRecord,
};

pub use runner::{MobileRadioDriver, MobileRadioDriverListener, RadioLink};

/// Where the transport stands while it carries no frames. Once the link
/// carries frames (`MobileRadioDriver::link_ready`) the ULCP session's
/// phase takes over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileRadioTransportPhase {
    Idle,
    /// The medium itself is unavailable: Bluetooth off or not permitted.
    Unavailable,
    Scanning,
    Discovered,
    Connecting,
    Pairing,
    /// Connected, and finding the radio's ULCP endpoint.
    Attaching,
    /// The link was lost and the transport is bringing it back.
    Reconnecting,
    /// The transport waits for the radio to appear.
    WaitingForRadio,
    Disconnecting,
    Failed,
}

/// The transport's state, as native code reports it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileRadioTransportStateRecord {
    pub phase: MobileRadioTransportPhase,
    /// What to call the radio until it reports its own name.
    pub name: Option<String>,
    /// The transport's identifier for the radio. Opaque to the driver,
    /// which only hands it back in the state it publishes.
    pub link_id: Option<String>,
    pub problem: Option<MobileRadioProblem>,
}

/// The phase a radio is in, transport and protocol together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileRadioPhase {
    Idle,
    Unavailable,
    Scanning,
    Discovered,
    Connecting,
    Pairing,
    Attaching,
    Reconnecting,
    WaitingForRadio,
    Synchronizing,
    AwaitingHost,
    /// Writing this phone's host key into the radio.
    Provisioning,
    Configuring,
    Attached,
    Disconnecting,
    Failed,
}

impl From<MobileRadioTransportPhase> for MobileRadioPhase {
    fn from(phase: MobileRadioTransportPhase) -> Self {
        use MobileRadioTransportPhase as Transport;
        match phase {
            Transport::Idle => Self::Idle,
            Transport::Unavailable => Self::Unavailable,
            Transport::Scanning => Self::Scanning,
            Transport::Discovered => Self::Discovered,
            Transport::Connecting => Self::Connecting,
            Transport::Pairing => Self::Pairing,
            Transport::Attaching => Self::Attaching,
            Transport::Reconnecting => Self::Reconnecting,
            Transport::WaitingForRadio => Self::WaitingForRadio,
            Transport::Disconnecting => Self::Disconnecting,
            Transport::Failed => Self::Failed,
        }
    }
}

/// Why the radio is not doing what it should, or what went wrong with the
/// last thing it was asked. Codes, never text: native code words them.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileRadioProblem {
    /// The link went away on its own.
    Disconnected,
    /// The radio sent a frame the ULCP session could not read.
    InvalidFrame,
    /// The radio sent a value the session could not use.
    UnusableValue,
    /// The ULCP session could not start.
    SessionStartFailed,
    /// A control exchange went unanswered past its deadline.
    SynchronizationStalled,
    /// The radio could not take this phone's host key.
    ClaimFailed,
    /// The radio refused an operation. The names are diagnostic labels.
    OperationRejected {
        operation: String,
        status_code: u32,
        status_name: String,
    },
    /// The radio answered in a form the session did not expect.
    UnrecognizedAnswer,
    /// The radio stayed busy through every retry of a transmission.
    RadioBusy,
    /// The radio refused a transmission.
    TransmissionRejected {
        status_code: u32,
        status_name: String,
    },
    /// The radio took a transmission and never said what became of it.
    TransmissionUnreported,
    /// The ULCP session could not start a transmission.
    TransmissionUnsendable,
    /// The radio's transmitter could not be turned on automatically.
    AutoEnableFailed,
    /// A problem the transport reported in its own terms, which native
    /// code names and words: an operating-system error's domain and code,
    /// or a code of the transport's own.
    Transport { domain: String, code: i64 },
}

/// A reading of the radio's clock and when it was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileRadioClockRecord {
    /// Seconds since the Unix epoch, or `None` when the radio does not
    /// know the time.
    pub epoch_seconds: Option<u32>,
    /// When the reading arrived, in milliseconds since the Unix epoch.
    pub read_at_ms: u64,
}

/// Everything the app shows about a radio. Not `Eq`: a position is
/// degrees.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileRadioStateRecord {
    pub phase: MobileRadioPhase,
    /// The radio's own name once it reports one, the transport's until
    /// then.
    pub name: Option<String>,
    /// The transport's identifier for the radio, as it last reported it.
    pub link_id: Option<String>,
    pub host: UlcpHostOwnership,
    /// The radio's own public key, when it has a device identity.
    pub device_key: Option<Vec<u8>>,
    /// The latest battery reading, kept until a newer one arrives.
    pub battery: Option<UlcpBatteryRecord>,
    /// When `battery` arrived, in milliseconds since the Unix epoch.
    pub battery_read_at_ms: Option<u64>,
    /// What the radio is doing to make itself findable, as it reports it
    /// now.
    pub alert: Option<UlcpAlertState>,
    /// The latest clock reading, kept until a newer one arrives.
    pub clock: Option<MobileRadioClockRecord>,
    /// Where the radio's receiver puts it, as it reports it now.
    pub position: Option<UlcpGnssRecord>,
    pub provisioning: Option<UlcpSyncRecord>,
    /// What to tell the user, until the radio next answers.
    pub problem: Option<MobileRadioProblem>,
}

impl MobileRadioStateRecord {
    /// A radio the driver has heard nothing about.
    pub(crate) fn idle() -> Self {
        Self::transport(&MobileRadioTransportStateRecord {
            phase: MobileRadioTransportPhase::Idle,
            name: None,
            link_id: None,
            problem: None,
        })
    }

    /// The state of a transport carrying no frames: what it reports, and
    /// nothing from the radio.
    pub(crate) fn transport(report: &MobileRadioTransportStateRecord) -> Self {
        Self {
            phase: report.phase.into(),
            name: report.name.clone(),
            link_id: report.link_id.clone(),
            host: UlcpHostOwnership::Unknown,
            device_key: None,
            battery: None,
            battery_read_at_ms: None,
            alert: None,
            clock: None,
            position: None,
            provisioning: None,
            problem: report.problem.clone(),
        }
    }
}

/// What changed since the last `MobileRadioDriver::poll_update`.
#[derive(Clone, Debug, Default, PartialEq, uniffi::Record)]
pub struct MobileRadioDriverUpdateRecord {
    /// The radio's state, when it changed.
    pub state: Option<MobileRadioStateRecord>,
    /// Mesh frames the radio received, newest kept when the platform falls
    /// behind. They have already gone to the mesh session.
    pub received_frames: Vec<UlcpReceivedFrameRecord>,
    /// Values the radio announced on its own, verbatim.
    pub pushed_properties: Vec<UlcpPropertyPushRecord>,
    /// The device keys of radios that confirmed they let go of this phone.
    pub host_releases: Vec<Vec<u8>>,
    /// Lines for the log: faults, late answers, frames ignored. Never
    /// shown to the user.
    pub diagnostics: Vec<String>,
}

/// Why a driver operation did not complete.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileRadioError {
    /// No radio is attached, or it is not in a state to take this.
    RadioUnavailable,
    /// Another operation of this kind is still running.
    OperationInProgress,
    /// This phone's identity is not known to the driver yet.
    IdentityUnavailable,
    /// The radio's host is not one this phone may replace.
    TakeoverNotAllowed,
    /// The radio and this app disagree about the protocol.
    IncompatibleProtocol,
    /// The radio lacks the capability this needs.
    Unsupported,
    /// The radio's table is full.
    DeviceFull,
    /// The radio refused. The names are diagnostic labels.
    OperationRejected {
        operation: String,
        status_code: u32,
        status_name: String,
    },
    /// The radio answered in a form the session did not expect.
    UnrecognizedAnswer,
    /// The radio did not answer in time. It may or may not have acted.
    TimedOut,
    /// The ULCP session would not start the operation.
    Refused { error: MobileError },
    /// An argument was malformed: a key of the wrong length.
    InvalidArgument,
    /// The driver has stopped.
    Stopped,
    /// The link came to rest or failed before the attach finished, with
    /// the problem the state shows, if any.
    LinkFailed { problem: Option<MobileRadioProblem> },
}

impl fmt::Display for MobileRadioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RadioUnavailable => formatter.write_str("RADIO_UNAVAILABLE"),
            Self::OperationInProgress => formatter.write_str("RADIO_OPERATION_IN_PROGRESS"),
            Self::IdentityUnavailable => formatter.write_str("RADIO_IDENTITY_UNAVAILABLE"),
            Self::TakeoverNotAllowed => formatter.write_str("RADIO_TAKEOVER_NOT_ALLOWED"),
            Self::IncompatibleProtocol => formatter.write_str("RADIO_INCOMPATIBLE_PROTOCOL"),
            Self::Unsupported => formatter.write_str("RADIO_UNSUPPORTED"),
            Self::DeviceFull => formatter.write_str("RADIO_DEVICE_FULL"),
            Self::OperationRejected {
                operation,
                status_code,
                status_name,
            } => write!(
                formatter,
                "RADIO_OPERATION_REJECTED: {operation} {status_name} ({status_code})"
            ),
            Self::UnrecognizedAnswer => formatter.write_str("RADIO_UNRECOGNIZED_ANSWER"),
            Self::TimedOut => formatter.write_str("RADIO_TIMED_OUT"),
            Self::Refused { error } => write!(formatter, "RADIO_REFUSED: {error}"),
            Self::InvalidArgument => formatter.write_str("RADIO_INVALID_ARGUMENT"),
            Self::Stopped => formatter.write_str("RADIO_DRIVER_STOPPED"),
            Self::LinkFailed { problem } => write!(formatter, "RADIO_LINK_FAILED: {problem:?}"),
        }
    }
}

impl std::error::Error for MobileRadioError {}
