//! The rules of the Wi-Fi sheets: which security modes to offer, what an
//! entry needs before it can be sent, and what a device's refusal of a
//! network means. One statement of each, read against
//! `umsh_ulcp::wifi`, which the device applies to what arrives.

use umsh_ulcp::Status;
use umsh_ulcp::wifi::{SSID_MAX_LEN, SecurityMode};

use super::records::{
    MobileRefusal, MobileWifiEntryCheckRecord, MobileWifiEntryProblem, MobileWifiJoinPlanRecord,
    MobileWifiRefusal, MobileWifiStep,
};
use crate::ulcp::{UlcpWifiNetworkRecord, ulcp_wifi_network_item};

/// The modes this app can build an entry for, strongest first: the order
/// a sheet offers them in and a step-down walks.
const BUILDABLE: [SecurityMode; 5] = [
    SecurityMode::Wpa3,
    SecurityMode::Wpa2,
    SecurityMode::Wpa,
    SecurityMode::Owe,
    SecurityMode::Open,
];

/// The modes a network may offer that this app cannot set up.
const UNSUPPORTED: [SecurityMode; 4] = [
    SecurityMode::Wep,
    SecurityMode::Wpa2Ent,
    SecurityMode::Wpa3Ent,
    SecurityMode::Wpa3Ent192,
];

/// Every mode a scan may report, strongest first.
const OFFERED_ORDER: [SecurityMode; 8] = [
    SecurityMode::Wpa3Ent192,
    SecurityMode::Wpa3Ent,
    SecurityMode::Wpa2Ent,
    SecurityMode::Wpa3,
    SecurityMode::Wpa2,
    SecurityMode::Wpa,
    SecurityMode::Owe,
    SecurityMode::Wep,
];

fn codes(modes: impl IntoIterator<Item = SecurityMode>) -> Vec<u8> {
    modes.into_iter().map(SecurityMode::code).collect()
}

/// The modes to offer for joining a network that advertised `offered`
/// (bit *n* for mode *n*). Nothing heard, or a device that could not
/// tell (zero), offers every mode this app can build; so does a network
/// offering none of them.
#[uniffi::export]
pub fn wifi_join_plan(offered: Option<u16>) -> MobileWifiJoinPlanRecord {
    let offered = offered.filter(|offered| *offered != 0);
    let matching: Vec<SecurityMode> = BUILDABLE
        .into_iter()
        .filter(|mode| offered.is_some_and(|offered| offered & mode.bit() != 0))
        .collect();
    let choices = if matching.is_empty() {
        codes(BUILDABLE)
    } else {
        codes(matching)
    };
    let unsupported = offered.map_or_else(Vec::new, |offered| {
        codes(
            UNSUPPORTED
                .into_iter()
                .filter(|mode| offered & mode.bit() != 0),
        )
    });
    MobileWifiJoinPlanRecord {
        initial: choices[0],
        choices,
        unsupported,
    }
}

/// The modes to offer for a network the device already knows: every mode
/// this app can build, with the stored one first when it is not one of
/// them, so the choice always shows the truth.
#[uniffi::export]
pub fn wifi_edit_plan(network: UlcpWifiNetworkRecord) -> MobileWifiJoinPlanRecord {
    let mut choices = codes(BUILDABLE);
    if !choices.contains(&network.security) {
        choices.insert(0, network.security);
    }
    MobileWifiJoinPlanRecord {
        choices,
        unsupported: Vec::new(),
        initial: network.security,
    }
}

/// Whether `security` takes a credential at all.
fn takes_credential(security: u8) -> bool {
    SecurityMode::from_code(security).is_some_and(|mode| mode.passphrase_len_bounds().is_some())
}

/// Judge a sheet's entry: a network being joined (`stored` `None`) or one
/// the device knows being edited. Nothing here is logged: `credential` is
/// the one secret the app ever holds.
#[uniffi::export]
pub fn wifi_entry_check(
    ssid: Vec<u8>,
    security: u8,
    hidden: bool,
    auto_join: bool,
    credential: Vec<u8>,
    stored: Option<UlcpWifiNetworkRecord>,
) -> MobileWifiEntryCheckRecord {
    let takes_credential = takes_credential(security);
    let keeps_credential = takes_credential
        && stored
            .as_ref()
            .is_some_and(|stored| stored.security == security);
    let changed = stored.as_ref().is_none_or(|stored| {
        stored.security != security
            || stored.hidden != hidden
            || stored.auto_join != auto_join
            || !credential.is_empty()
    });
    let problem = if ssid.is_empty() {
        Some(MobileWifiEntryProblem::SsidEmpty)
    } else if ssid.len() > SSID_MAX_LEN {
        Some(MobileWifiEntryProblem::SsidTooLong)
    } else if takes_credential && !keeps_credential && credential.is_empty() {
        Some(MobileWifiEntryProblem::CredentialRequired)
    } else if ulcp_wifi_network_item(ssid, security, hidden, auto_join, credential).is_err() {
        Some(MobileWifiEntryProblem::CredentialInvalid)
    } else {
        None
    };
    MobileWifiEntryCheckRecord {
        takes_credential,
        keeps_credential,
        changed,
        problem,
    }
}

/// The modes in a scan result's `offered` set, strongest first.
#[uniffi::export]
pub fn wifi_offered_modes(offered: u16) -> Vec<u8> {
    codes(
        OFFERED_ORDER
            .into_iter()
            .filter(|mode| offered & mode.bit() != 0),
    )
}

/// What a device's refusal of a join means, at `step`. Only the store
/// step says something particular: no room, a credential that does not
/// fit, or a mode the device cannot use, which names the next mode the
/// network offers.
pub(super) fn classify_join(
    step: MobileWifiStep,
    refusal: MobileRefusal,
    security: u8,
    offered: Option<u16>,
) -> MobileWifiRefusal {
    if step != MobileWifiStep::Store {
        return MobileWifiRefusal::Other { step, refusal };
    }
    match refusal.status.map(Status) {
        Some(Status::NOMEM) => MobileWifiRefusal::NoRoom,
        Some(Status::UNIMPLEMENTED) => {
            let choices = wifi_join_plan(offered).choices;
            let weaker = choices
                .iter()
                .position(|mode| *mode == security)
                .and_then(|position| choices.get(position + 1))
                .copied();
            MobileWifiRefusal::SecurityUnsupported {
                tried: security,
                weaker,
            }
        }
        _ => classify_store(refusal),
    }
}

/// What a device's refusal of a changed network means. Nothing weaker is
/// offered: the operator chose the mode on purpose.
pub(super) fn classify_update(refusal: MobileRefusal, security: u8) -> MobileWifiRefusal {
    match refusal.status.map(Status) {
        Some(Status::UNIMPLEMENTED) => MobileWifiRefusal::SecurityUnsupported {
            tried: security,
            weaker: None,
        },
        _ => classify_store(refusal),
    }
}

fn classify_store(refusal: MobileRefusal) -> MobileWifiRefusal {
    match refusal.status.map(Status) {
        Some(Status::INVALID_ARGUMENT) => MobileWifiRefusal::CredentialRejected,
        _ => MobileWifiRefusal::Other {
            step: MobileWifiStep::Store,
            refusal,
        },
    }
}
