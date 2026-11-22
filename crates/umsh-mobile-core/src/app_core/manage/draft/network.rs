//! Addressing per family, the resolvers both families share, and the LAN
//! group a device whose medium is the group joins.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use umsh_ulcp::ids::prop;

use super::{
    Field, Fold, Record, Source, choice, fold_group, group_field, list, rebased, text_known,
    trim_horizontal as trim,
};
use crate::app_core::manage::records::{
    MobileApplyWarning, MobileChoiceField, MobileFieldProblem, MobileManagedDeviceRecord,
    MobileManagementLink, MobileNetworkDraft, MobileOptionalIntegerField, MobileTextField,
};
use crate::ulcp::UlcpIpConfigRecord;

/// `IP_METHOD_STATIC`: the one method that carries an address.
const STATIC: u8 = 2;

/// An address as `std::net` writes it.
fn address_text(octets: &[u8]) -> String {
    if let Ok(octets) = <[u8; 4]>::try_from(octets) {
        return Ipv4Addr::from(octets).to_string();
    }
    if let Ok(octets) = <[u8; 16]>::try_from(octets) {
        return Ipv6Addr::from(octets).to_string();
    }
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

/// An address typed for a family `width` octets wide.
fn family_address(text: &str, width: usize) -> Option<Vec<u8>> {
    let text = trim(text);
    match width {
        4 => text.parse::<Ipv4Addr>().ok().map(|a| a.octets().to_vec()),
        _ => text.parse::<Ipv6Addr>().ok().map(|a| a.octets().to_vec()),
    }
}

/// A resolver, of either family.
fn resolver(text: &str) -> Option<Vec<u8>> {
    match text.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) => Some(address.octets().to_vec()),
        IpAddr::V6(address) => Some(address.octets().to_vec()),
    }
}

/// One family's fields: under a configuration with no address, all three
/// are empty, and a gateway of all zeros (no default route) is too.
struct Family {
    method: MobileChoiceField,
    address: MobileTextField,
    prefix: MobileOptionalIntegerField,
    gateway: MobileTextField,
}

fn family(property: u32, config: Option<&UlcpIpConfigRecord>) -> Family {
    let known = config.is_some();
    let addressed = config.filter(|config| !config.address.is_empty());
    let gateway = config
        .map(|config| &config.gateway)
        .filter(|gateway| gateway.iter().any(|octet| *octet != 0));
    Family {
        method: choice(property, config.map(|config| config.method)),
        address: text_known(
            property,
            known,
            addressed.map_or_else(String::new, |config| address_text(&config.address)),
        ),
        prefix: MobileOptionalIntegerField {
            property_id: property,
            known,
            reported: addressed.map(|config| config.prefix.into()),
            value: addressed.map(|config| config.prefix.into()),
        },
        gateway: text_known(
            property,
            known,
            gateway.map_or_else(String::new, |gateway| address_text(gateway)),
        ),
    }
}

pub(super) fn build(source: &Source<'_>) -> MobileNetworkDraft {
    let held = source.held();
    let v4 = family(prop::IPV4_CONFIG, held.ipv4_config.as_ref());
    let v6 = family(prop::IPV6_CONFIG, held.ipv6_config.as_ref());
    MobileNetworkDraft {
        reading_revision: source.revision(),
        v4_method: v4.method,
        v4_address: v4.address,
        v4_prefix: v4.prefix,
        v4_gateway: v4.gateway,
        v6_method: v6.method,
        v6_address: v6.address,
        v6_prefix: v6.prefix,
        v6_gateway: v6.gateway,
        dns: list(
            prop::IP_DNS,
            held.ip_dns.as_ref().map(|resolvers| {
                resolvers
                    .iter()
                    .map(|octets| address_text(octets))
                    .collect()
            }),
        ),
        group: group_field(source),
    }
}

/// One family's fields as a draft holds them, and its address width in
/// octets.
#[derive(Clone, Copy)]
struct FamilyRef<'a> {
    method: &'a MobileChoiceField,
    address: &'a MobileTextField,
    prefix: &'a MobileOptionalIntegerField,
    gateway: &'a MobileTextField,
    width: usize,
}

fn v4(draft: &MobileNetworkDraft) -> FamilyRef<'_> {
    FamilyRef {
        method: &draft.v4_method,
        address: &draft.v4_address,
        prefix: &draft.v4_prefix,
        gateway: &draft.v4_gateway,
        width: 4,
    }
}

fn v6(draft: &MobileNetworkDraft) -> FamilyRef<'_> {
    FamilyRef {
        method: &draft.v6_method,
        address: &draft.v6_address,
        prefix: &draft.v6_prefix,
        gateway: &draft.v6_gateway,
        width: 16,
    }
}

/// Whether a family's address, prefix or gateway differs from its own
/// baseline: the three travel together.
fn addressing_edited(family: FamilyRef<'_>) -> bool {
    family.address.dirty() || family.prefix.dirty() || family.gateway.dirty()
}

pub(super) fn rebase(fresh: MobileNetworkDraft, old: &MobileNetworkDraft) -> MobileNetworkDraft {
    let mut draft = MobileNetworkDraft {
        reading_revision: fresh.reading_revision,
        v4_method: rebased(fresh.v4_method, &old.v4_method),
        v6_method: rebased(fresh.v6_method, &old.v6_method),
        dns: rebased(fresh.dns, &old.dns),
        group: rebased(fresh.group, &old.group),
        ..fresh
    };
    // Judged against the old draft's own baseline, never the new one: a
    // clean family follows the device.
    if addressing_edited(v4(old)) && draft.v4_address.known {
        draft.v4_address.text.clone_from(&old.v4_address.text);
        draft.v4_prefix.value = old.v4_prefix.value;
        draft.v4_gateway.text.clone_from(&old.v4_gateway.text);
    }
    if addressing_edited(v6(old)) && draft.v6_address.known {
        draft.v6_address.text.clone_from(&old.v6_address.text);
        draft.v6_prefix.value = old.v6_prefix.value;
        draft.v6_gateway.text.clone_from(&old.v6_gateway.text);
    }
    draft
}

/// The configuration one family's fields amount to, or the problems that
/// keep it from being one.
fn configuration(family: FamilyRef<'_>) -> Result<UlcpIpConfigRecord, Vec<MobileFieldProblem>> {
    let FamilyRef {
        method,
        address,
        prefix,
        gateway,
        width,
    } = family;
    let Some(chosen) = method.value.and_then(|method| u8::try_from(method).ok()) else {
        return Err(vec![MobileFieldProblem::OutOfRange]);
    };
    if chosen != STATIC {
        return Ok(UlcpIpConfigRecord {
            method: chosen,
            address: Vec::new(),
            prefix: 0,
            gateway: Vec::new(),
        });
    }
    let mut problems = Vec::new();
    let parsed = family_address(&address.text, width);
    if parsed.is_none() {
        problems.push(MobileFieldProblem::AddressInvalid);
    }
    // An empty prefix is never read as zero: it is one not yet typed.
    let bits = prefix
        .value
        .and_then(|bits| u8::try_from(bits).ok())
        .filter(|bits| usize::from(*bits) <= width * 8);
    if bits.is_none() {
        problems.push(MobileFieldProblem::PrefixInvalid);
    }
    let router = if trim(&gateway.text).is_empty() {
        Some(vec![0; width])
    } else {
        family_address(&gateway.text, width)
    };
    if router.is_none() {
        problems.push(MobileFieldProblem::GatewayInvalid);
    }
    match (parsed, bits, router) {
        (Some(address), Some(prefix), Some(gateway)) => Ok(UlcpIpConfigRecord {
            method: chosen,
            address,
            prefix,
            gateway,
        }),
        _ => Err(problems),
    }
}

fn fold_family(
    fold: &mut Fold,
    family: FamilyRef<'_>,
    write: impl FnOnce(&mut Record, UlcpIpConfigRecord),
) {
    let method = family.method;
    // Only an edit is judged: a family nobody touched has nothing to say.
    if !method.known || !(method.dirty() || addressing_edited(family)) {
        return;
    }
    match configuration(family) {
        Ok(config) if Some(&config) == reported_configuration(family).as_ref() => {}
        Ok(config) => fold.edit(method.property_id, |desired| write(desired, config)),
        Err(problems) => {
            for problem in problems {
                fold.problem(method.property_id, problem);
            }
        }
    }
}

/// The configuration a family's own baseline spells out.
fn reported_configuration(family: FamilyRef<'_>) -> Option<UlcpIpConfigRecord> {
    let method = MobileChoiceField {
        value: family.method.reported,
        ..family.method.clone()
    };
    let address = MobileTextField {
        text: family.address.reported.clone(),
        ..family.address.clone()
    };
    let prefix = MobileOptionalIntegerField {
        value: family.prefix.reported,
        ..family.prefix.clone()
    };
    let gateway = MobileTextField {
        text: family.gateway.reported.clone(),
        ..family.gateway.clone()
    };
    configuration(FamilyRef {
        method: &method,
        address: &address,
        prefix: &prefix,
        gateway: &gateway,
        width: family.width,
    })
    .ok()
}

pub(super) fn fold(draft: &MobileNetworkDraft, fold: &mut Fold) {
    fold_family(fold, v4(draft), |desired, config| {
        desired.ipv4_config = Some(config);
    });
    fold_family(fold, v6(draft), |desired, config| {
        desired.ipv6_config = Some(config);
    });
    let dns = &draft.dns;
    if dns.dirty() {
        // The blank row an operator is still filling in is dropped.
        let parsed: Option<Vec<Vec<u8>>> = dns
            .value
            .iter()
            .map(|row| trim(row))
            .filter(|row| !row.is_empty())
            .map(resolver)
            .collect();
        let reported: Option<Vec<Vec<u8>>> = dns.reported.iter().map(|row| resolver(row)).collect();
        match parsed {
            None => fold.problem(dns.property_id, MobileFieldProblem::ResolverInvalid),
            Some(resolvers) if Some(&resolvers) == reported.as_ref() => {}
            Some(resolvers) => fold.edit(dns.property_id, |desired| {
                desired.ip_dns = Some(resolvers);
            }),
        }
    }
    fold_group(&draft.group, fold);
}

/// Across the mesh, a family moved onto a static address it is not
/// already on can leave the device somewhere nothing reaches it.
pub(super) fn warning(
    device: &MobileManagedDeviceRecord,
    fold: &Fold,
) -> Option<MobileApplyWarning> {
    let moves = |property, config: &Option<UlcpIpConfigRecord>| {
        fold.is_dirty(property)
            && config
                .as_ref()
                .is_some_and(|config| config.method == STATIC)
    };
    (device.link == MobileManagementLink::Mesh
        && (moves(prop::IPV4_CONFIG, &fold.desired.ipv4_config)
            || moves(prop::IPV6_CONFIG, &fold.desired.ipv6_config)))
    .then_some(MobileApplyWarning::ChangesStaticAddressing)
}
