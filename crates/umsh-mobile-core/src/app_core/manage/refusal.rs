//! One table from what each link reports to what a screen shows: device
//! statuses to refusal reasons, and every carrier's failures to one
//! problem each, so a condition reads the same on every link.

use umsh_ulcp::Status;

use super::records::{MobileManagementProblem, MobileRefusal, MobileRefusalReason};
use crate::app_core::MobileAppError;
use crate::radio_driver::MobileRadioError;

/// Why an operation on a device ended without its result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Stop {
    /// The operator canceled it.
    Cancelled,
    /// It never ran: the device entered firmware update, or nobody is
    /// left to show a read to.
    Skipped,
    Problem(MobileManagementProblem),
}

impl From<MobileManagementProblem> for Stop {
    fn from(problem: MobileManagementProblem) -> Self {
        Self::Problem(problem)
    }
}

/// What a device's status means. `None` is a value missing with no status
/// in its place.
pub(super) fn classify(status: Option<u32>) -> MobileRefusal {
    let reason = match status.map(Status) {
        None => MobileRefusalReason::NoStatus,
        Some(Status::UNIMPLEMENTED) => MobileRefusalReason::NotImplemented,
        Some(Status::PROP_NOT_FOUND) => MobileRefusalReason::NoSuchProperty,
        Some(Status::INVALID_ARGUMENT) => MobileRefusalReason::OutOfRange,
        Some(Status::INVALID_STATE) => MobileRefusalReason::NotNow,
        Some(Status::NOMEM) => MobileRefusalReason::TooLarge,
        Some(Status::IN_PROGRESS | Status::BUSY) => MobileRefusalReason::Busy,
        Some(Status::NOT_PERMITTED) => MobileRefusalReason::NotPermitted,
        Some(_) => MobileRefusalReason::Other,
    };
    MobileRefusal { reason, status }
}

/// A device's refusal of a whole request, as a problem.
pub(super) fn refused(status: u32) -> MobileManagementProblem {
    MobileManagementProblem::Refused {
        refusal: classify(Some(status)),
    }
}

/// Whether a firmware-update entry took, by the status the device
/// answered: `OK` took, `UNIMPLEMENTED` and `INVALID_COMMAND` say it
/// cannot, any other status refused, and no status is unconfirmed.
pub(super) fn dfu_outcome(status: Option<u32>) -> Result<(), MobileAppError> {
    match status.map(Status) {
        Some(Status::OK) => Ok(()),
        Some(Status::UNIMPLEMENTED | Status::INVALID_COMMAND) => {
            Err(MobileAppError::DfuUnsupported)
        }
        Some(Status(status)) => Err(MobileAppError::DfuRefused { status }),
        None => Err(MobileAppError::DfuUnconfirmed),
    }
}

/// A mesh command's error, as what a screen shows.
pub(super) fn mesh_stop(error: MobileAppError) -> Stop {
    use MobileManagementProblem as Problem;
    Stop::Problem(match error {
        MobileAppError::Cancelled => return Stop::Cancelled,
        MobileAppError::NoAnswer => Problem::NoAnswer,
        MobileAppError::Unreachable => Problem::Unreachable,
        MobileAppError::Unreadable => Problem::Unreadable,
        MobileAppError::DfuUnsupported => Problem::DfuUnsupported,
        MobileAppError::DfuRefused { status } => Problem::DfuRefused { status },
        MobileAppError::DfuUnconfirmed => Problem::DfuUnconfirmed,
        MobileAppError::NoRadio => Problem::NoRadio,
        MobileAppError::NotRunning => Problem::NotRunning,
        MobileAppError::NoOwner => Problem::NoOwner,
        MobileAppError::NotThisPhone => Problem::NotThisPhone,
        MobileAppError::NotFound => Problem::NotFound,
        MobileAppError::InvalidRequest => Problem::InvalidRequest,
        MobileAppError::SendFailed => Problem::SendFailed,
        MobileAppError::Busy => Problem::Busy,
        MobileAppError::Stopped => Problem::Stopped,
        MobileAppError::Store { .. }
        | MobileAppError::InvalidInput { .. }
        | MobileAppError::ChannelTableFull
        | MobileAppError::StartFailed { .. }
        | MobileAppError::Vault { .. }
        | MobileAppError::CountersNotRemoved
        | MobileAppError::EmergencyNotCertified
        | MobileAppError::MessageNotQueued { .. } => Problem::Other,
    })
}

/// A local link's error, as what a screen shows.
pub(super) fn driver_problem(error: MobileRadioError) -> MobileManagementProblem {
    use MobileManagementProblem as Problem;
    match error {
        MobileRadioError::TimedOut => Problem::NoAnswer,
        // The session refuses a local exchange when the radio is not
        // attached or one is already outstanding: a radio not ready to
        // send through, as the other three say.
        MobileRadioError::RadioUnavailable
        | MobileRadioError::Stopped
        | MobileRadioError::LinkFailed { .. }
        | MobileRadioError::Refused { .. } => Problem::NoRadio,
        MobileRadioError::OperationInProgress => Problem::RadioBusy,
        MobileRadioError::DeviceFull => Problem::TableFull,
        MobileRadioError::Unsupported => Problem::Unsupported,
        MobileRadioError::OperationRejected { status_code, .. } => refused(status_code),
        MobileRadioError::UnrecognizedAnswer => Problem::Unreadable,
        MobileRadioError::InvalidArgument
        | MobileRadioError::IncompatibleProtocol
        | MobileRadioError::IdentityUnavailable
        | MobileRadioError::TakeoverNotAllowed => Problem::NotBuilt,
    }
}

/// The device's refusal, if it refused.
pub(super) fn require(refusal: Option<u32>) -> Result<(), Stop> {
    refusal.map_or(Ok(()), |status| Err(Stop::Problem(refused(status))))
}
