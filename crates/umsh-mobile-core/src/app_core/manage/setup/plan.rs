//! What each goal decides: which devices it refuses, the values it
//! assumes on the operator's behalf, the sections it asks about, and what
//! it says it cannot do.

use super::records::{MobileSetupGoal, MobileSetupNote, MobileSetupRefusal, MobileSetupSection};
use crate::ulcp::UlcpSyncRecord;

/// Why `goal` cannot use a device that reported `sync`, or `None` when it
/// can. A device is refused only when it cannot do what the goal asks of
/// it; everything else degrades and a note says so.
pub(in crate::app_core::manage) fn refusal(
    goal: MobileSetupGoal,
    sync: Option<&UlcpSyncRecord>,
) -> Option<MobileSetupRefusal> {
    let Some(sync) = sync else {
        return Some(MobileSetupRefusal::NotReported);
    };
    match goal {
        // The identity first: the protocol makes the schedule imply it,
        // but a device can carry the capability without the schedule.
        MobileSetupGoal::Tracker if !sync.supports_device_identity => {
            Some(MobileSetupRefusal::NoDeviceIdentity)
        }
        MobileSetupGoal::Tracker if !sync.supports_advert => {
            Some(MobileSetupRefusal::NoAdvertSchedule)
        }
        // Not gated on announcing: a repeater that cannot announce itself
        // is a worse repeater, not a non-repeater.
        MobileSetupGoal::Repeater if !sync.supports_repeater => {
            Some(MobileSetupRefusal::CannotForward)
        }
        MobileSetupGoal::Repeater if sync.repeater.is_none() => {
            Some(MobileSetupRefusal::ForwardingUnreported)
        }
        MobileSetupGoal::Tracker | MobileSetupGoal::Repeater => None,
    }
}

/// A value a goal decides on the operator's behalf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::app_core::manage) enum Assumption {
    ForwardingOff,
    ForwardingOn,
    RadioEnabled,
    AdvertisesTracker,
    /// The role left empty, so the device derives it from forwarding.
    RoleDerivedFromForwarding,
    Mobile,
    Stationary,
    /// This phone on the administrator list, so the device can be managed
    /// once it is out of Bluetooth range.
    PhoneAdministers,
    PhoneTimeZone,
    /// The clock set from the phone's on Apply. Forces nothing on the
    /// draft.
    ClockFromPhone,
}

impl Assumption {
    /// Whether a device that reported `sync` can be told it. One it
    /// cannot is skipped, never a failure.
    pub(in crate::app_core::manage) fn applies(self, sync: &UlcpSyncRecord) -> bool {
        match self {
            // A policy the device would not report is not decided blind.
            Self::ForwardingOff | Self::ForwardingOn => {
                sync.supports_repeater && sync.repeater.is_some()
            }
            Self::RadioEnabled => true,
            Self::AdvertisesTracker
            | Self::RoleDerivedFromForwarding
            | Self::Mobile
            | Self::Stationary => sync.supports_ident,
            // Nor is a list the device would not report added to.
            Self::PhoneAdministers => sync.supports_admin && sync.dev_admin_keys.is_some(),
            Self::PhoneTimeZone | Self::ClockFromPhone => sync.supports_time,
        }
    }
}

/// What `goal` assumes, in the order it is applied.
pub(in crate::app_core::manage) fn assumptions(goal: MobileSetupGoal) -> &'static [Assumption] {
    match goal {
        MobileSetupGoal::Tracker => &[
            Assumption::ForwardingOff,
            Assumption::RadioEnabled,
            Assumption::AdvertisesTracker,
            Assumption::Mobile,
            Assumption::PhoneTimeZone,
            Assumption::ClockFromPhone,
        ],
        MobileSetupGoal::Repeater => &[
            Assumption::ForwardingOn,
            Assumption::RadioEnabled,
            Assumption::RoleDerivedFromForwarding,
            Assumption::Stationary,
            Assumption::PhoneAdministers,
            Assumption::PhoneTimeZone,
            Assumption::ClockFromPhone,
        ],
    }
}

/// Whether Apply sets the device's clock from the phone's.
pub(in crate::app_core::manage) fn sets_clock(
    goal: MobileSetupGoal,
    sync: &UlcpSyncRecord,
) -> bool {
    assumptions(goal).contains(&Assumption::ClockFromPhone)
        && Assumption::ClockFromPhone.applies(sync)
}

/// Every section `goal` asks about, before readability drops any.
fn all_sections(goal: MobileSetupGoal) -> &'static [MobileSetupSection] {
    use MobileSetupSection::{
        Administrators, Announcements, Discoverability, Forwarding, Name, Positioning, RadioProfile,
    };
    match goal {
        MobileSetupGoal::Tracker => &[
            Name,
            Discoverability,
            Positioning,
            Announcements,
            RadioProfile,
        ],
        MobileSetupGoal::Repeater => &[
            Name,
            Forwarding,
            Discoverability,
            Positioning,
            Announcements,
            RadioProfile,
            Administrators,
        ],
    }
}

/// The sections `goal` shows for a device that reported `sync`: each one
/// the device reported the settings of. The radio profile always stays,
/// since every setup resolves one.
pub(in crate::app_core::manage) fn sections(
    goal: MobileSetupGoal,
    sync: &UlcpSyncRecord,
    gates: &super::draft::Gates,
) -> Vec<MobileSetupSection> {
    all_sections(goal)
        .iter()
        .copied()
        .filter(|section| match section {
            MobileSetupSection::Name => sync.supports_device_name,
            MobileSetupSection::Forwarding => gates.shows_forwarding,
            MobileSetupSection::Discoverability => gates.shows_discoverable,
            MobileSetupSection::Positioning => gates.shows_positioning,
            MobileSetupSection::Announcements => gates.shows_announcements,
            MobileSetupSection::RadioProfile => true,
            MobileSetupSection::Administrators => gates.shows_administrators,
        })
        .collect()
}

/// What either goal cannot do on a device that reported `sync`.
pub(in crate::app_core::manage) fn notes(sync: &UlcpSyncRecord) -> Vec<MobileSetupNote> {
    [
        (!sync.supports_gnss).then_some(MobileSetupNote::NoPositioning),
        (!sync.supports_ident).then_some(MobileSetupNote::NoRole),
        (!sync.supports_time).then_some(MobileSetupNote::NoClock),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The forwarding section proposes regions from the phone's position.
pub(in crate::app_core::manage) fn suggests_regions_from_phone(goal: MobileSetupGoal) -> bool {
    goal == MobileSetupGoal::Repeater
}
