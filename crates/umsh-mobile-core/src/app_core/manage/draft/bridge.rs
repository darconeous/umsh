//! Both ways a device carries the mesh over IP: a tunnel to a server, and
//! a multicast group on its own network.

use umsh_ulcp::ids::prop;

use super::{
    Field, Fold, Source, fold_group, group_field, integer, optional_integer, rebased, text, toggle,
};
use crate::app_core::manage::records::{MobileBridgeDraft, MobileFieldProblem};
use crate::ulcp::ulcp_bridge_server_key;

pub(super) fn build(source: &Source<'_>) -> MobileBridgeDraft {
    let held = source.held();
    let server_key = held.bridge_server_key.as_ref().map(|key| {
        if key.is_empty() {
            String::new()
        } else {
            crate::inspect_public_identity_bytes(key.clone())
                .map(|identity| identity.canonical_address)
                .unwrap_or_default()
        }
    });
    MobileBridgeDraft {
        reading_revision: source.revision(),
        enabled: toggle(prop::BRIDGE_ENABLED, held.bridge_enabled),
        host: text(prop::BRIDGE_HOST, held.bridge_host.clone()),
        port: integer(prop::BRIDGE_PORT, held.bridge_port),
        server_key: text(prop::BRIDGE_SERVER_KEY, server_key),
        local_enabled: toggle(prop::LAN_BEARER_ENABLED, held.lan_bearer_enabled),
        group: group_field(source),
        ingress_limit: optional_integer(
            prop::LAN_BEARER_INGRESS_LIMIT,
            held.lan_bearer_ingress_limit.is_some(),
            held.lan_bearer_ingress_limit,
        ),
    }
}

pub(super) fn rebase(fresh: MobileBridgeDraft, old: &MobileBridgeDraft) -> MobileBridgeDraft {
    MobileBridgeDraft {
        reading_revision: fresh.reading_revision,
        enabled: rebased(fresh.enabled, &old.enabled),
        host: rebased(fresh.host, &old.host),
        port: rebased(fresh.port, &old.port),
        server_key: rebased(fresh.server_key, &old.server_key),
        local_enabled: rebased(fresh.local_enabled, &old.local_enabled),
        group: rebased(fresh.group, &old.group),
        ingress_limit: rebased(fresh.ingress_limit, &old.ingress_limit),
    }
}

pub(super) fn fold(draft: &MobileBridgeDraft, fold: &mut Fold) {
    fold.toggle(&draft.enabled, |desired, value| {
        desired.bridge_enabled = Some(value);
    });
    let host = &draft.host;
    if host.dirty() {
        if umsh_ulcp::bridge::valid_host(&host.text) {
            let text = host.text.clone();
            fold.edit(host.property_id, |desired| desired.bridge_host = Some(text));
        } else {
            fold.problem(host.property_id, MobileFieldProblem::HostInvalid);
        }
    }
    fold.integer(
        &draft.port,
        MobileFieldProblem::PortInvalid,
        |port: u16| port > 0,
        |desired, port| desired.bridge_port = Some(port),
    );
    let key = &draft.server_key;
    if key.dirty() {
        // Empty clears the server.
        match ulcp_bridge_server_key(key.text.clone()) {
            Ok(bytes)
                if ulcp_bridge_server_key(key.reported.clone()).ok() == Some(bytes.clone()) => {}
            Ok(bytes) => fold.edit(key.property_id, |desired| {
                desired.bridge_server_key = Some(bytes);
            }),
            Err(_) => fold.problem(key.property_id, MobileFieldProblem::ServerKeyInvalid),
        }
    }
    fold.toggle(&draft.local_enabled, |desired, value| {
        desired.lan_bearer_enabled = Some(value);
    });
    fold_group(&draft.group, fold);
    fold.optional_integer(
        &draft.ingress_limit,
        MobileFieldProblem::LimitInvalid,
        |limit: u16| limit > 0,
        |desired, limit| desired.lan_bearer_ingress_limit = limit,
    );
}
