//! Drafts: what an editor holds, as typed values beside the values they
//! were built on, and the rules that judge them.
//!
//! A draft is a value native code keeps as view state and edits field by
//! field; everything here is a pure function of a draft and the device as
//! last published. Three rules run through all of it:
//!
//! - A field is dirty when it is known and its value differs from its own
//!   `reported`, the baseline the draft was built on, never a newer one.
//! - `rebase` builds a fresh draft from the current reading and keeps each
//!   dirty field's value where the new field is known; a clean field
//!   follows the device, and a value that lands on the edit is clean.
//! - `review` and `apply` rebase first, then fold: a value that cannot be
//!   written is a problem on its row and stays out of `dirty`, and only
//!   an edit is ever judged.

use std::collections::BTreeSet;

use umsh_ulcp::ids::prop;

use super::records::{
    MobileApplyWarning, MobileCategoryReadingRecord, MobileChoiceField, MobileChoiceList,
    MobileDraftDetails, MobileDraftKind, MobileDraftReviewRecord, MobileFieldProblem,
    MobileFieldProblemRecord, MobileIntegerField, MobileManagedDeviceRecord, MobileManagementDraft,
    MobileOptionalIntegerField, MobilePositionField, MobileTextField, MobileTextListField,
    MobileToggleField,
};
use crate::app_core::MobileAppError;
use crate::ulcp::{UlcpDevicePropertiesRecord, UlcpManageCategory, ulcp_dirty_writes};

mod bluetooth;
mod bridge;
mod gnss;
mod identity;
mod meshcore;
mod network;
mod radio;
mod repeater;
mod time;
mod wifi;

pub use identity::{
    draft_clear_position, draft_place, draft_place_from_phone, draft_set_precision,
};
pub use meshcore::draft_add_meshcore_region;
pub use radio::draft_adopt_preset;
pub(in crate::app_core::manage) use radio::matches as matches_preset;
pub use repeater::{draft_add_repeater_region, draft_adopt_regions};
pub(in crate::app_core::manage) use repeater::{region_code, spelled, taggable_regions};

#[cfg(test)]
pub(super) use identity::cell_decimals;

/// The category a draft's kind reads, applies and is refused under.
fn category(kind: MobileDraftKind) -> UlcpManageCategory {
    match kind {
        MobileDraftKind::Radio => UlcpManageCategory::Radio,
        MobileDraftKind::Identity => UlcpManageCategory::Identity,
        MobileDraftKind::Repeater | MobileDraftKind::MeshCore => UlcpManageCategory::Repeater,
        MobileDraftKind::Wifi => UlcpManageCategory::Wifi,
        MobileDraftKind::Network => UlcpManageCategory::Network,
        MobileDraftKind::Bridge => UlcpManageCategory::Bridge,
        MobileDraftKind::Bluetooth => UlcpManageCategory::Bluetooth,
        MobileDraftKind::Gnss => UlcpManageCategory::Gnss,
        MobileDraftKind::Time => UlcpManageCategory::Time,
    }
}

pub(super) fn kind(draft: &MobileManagementDraft) -> MobileDraftKind {
    match draft {
        MobileManagementDraft::Radio { .. } => MobileDraftKind::Radio,
        MobileManagementDraft::Identity { .. } => MobileDraftKind::Identity,
        MobileManagementDraft::Repeater { .. } => MobileDraftKind::Repeater,
        MobileManagementDraft::MeshCore { .. } => MobileDraftKind::MeshCore,
        MobileManagementDraft::Wifi { .. } => MobileDraftKind::Wifi,
        MobileManagementDraft::Network { .. } => MobileDraftKind::Network,
        MobileManagementDraft::Bridge { .. } => MobileDraftKind::Bridge,
        MobileManagementDraft::Bluetooth { .. } => MobileDraftKind::Bluetooth,
        MobileManagementDraft::Gnss { .. } => MobileDraftKind::Gnss,
        MobileManagementDraft::Time { .. } => MobileDraftKind::Time,
    }
}

fn reading_revision(draft: &MobileManagementDraft) -> u64 {
    match draft {
        MobileManagementDraft::Radio { draft } => draft.reading_revision,
        MobileManagementDraft::Identity { draft } => draft.reading_revision,
        MobileManagementDraft::Repeater { draft } => draft.reading_revision,
        MobileManagementDraft::MeshCore { draft } => draft.reading_revision,
        MobileManagementDraft::Wifi { draft } => draft.reading_revision,
        MobileManagementDraft::Network { draft } => draft.reading_revision,
        MobileManagementDraft::Bridge { draft } => draft.reading_revision,
        MobileManagementDraft::Bluetooth { draft } => draft.reading_revision,
        MobileManagementDraft::Gnss { draft } => draft.reading_revision,
        MobileManagementDraft::Time { draft } => draft.reading_revision,
    }
}

fn reading(
    device: &MobileManagedDeviceRecord,
    category: UlcpManageCategory,
) -> Option<&MobileCategoryReadingRecord> {
    device
        .readings
        .iter()
        .find(|reading| reading.category == category)
}

/// Whether the device's card leaves `category` out. Without a card
/// nothing is known either way, so nothing is refused.
fn not_offered(device: &MobileManagedDeviceRecord, category: UlcpManageCategory) -> bool {
    device.card.is_some()
        && !device
            .categories
            .iter()
            .any(|offered| offered.category == category)
}

/// `InvalidRequest` for a draft whose category the device's card leaves
/// out.
pub(super) fn refuse_unoffered(
    device: &MobileManagedDeviceRecord,
    draft: &MobileManagementDraft,
) -> Result<(), MobileAppError> {
    if not_offered(device, category(kind(draft))) {
        return Err(MobileAppError::InvalidRequest);
    }
    Ok(())
}

/// A draft of `kind` built from the device's reading, or `None` while
/// there is no reading or the device does not offer the category.
pub(super) fn build(
    device: &MobileManagedDeviceRecord,
    kind: MobileDraftKind,
) -> Option<MobileManagementDraft> {
    let category = category(kind);
    if not_offered(device, category) {
        return None;
    }
    let source = Source::new(reading(device, category)?);
    Some(match kind {
        MobileDraftKind::Radio => MobileManagementDraft::Radio {
            draft: radio::build(&source),
        },
        MobileDraftKind::Identity => MobileManagementDraft::Identity {
            draft: identity::build(&source),
        },
        MobileDraftKind::Repeater => MobileManagementDraft::Repeater {
            draft: repeater::build(&source),
        },
        MobileDraftKind::MeshCore => MobileManagementDraft::MeshCore {
            draft: meshcore::build(&source),
        },
        MobileDraftKind::Wifi => MobileManagementDraft::Wifi {
            draft: wifi::build(&source),
        },
        MobileDraftKind::Network => MobileManagementDraft::Network {
            draft: network::build(&source),
        },
        MobileDraftKind::Bridge => MobileManagementDraft::Bridge {
            draft: bridge::build(&source),
        },
        MobileDraftKind::Bluetooth => MobileManagementDraft::Bluetooth {
            draft: bluetooth::build(&source),
        },
        MobileDraftKind::Gnss => MobileManagementDraft::Gnss {
            draft: gnss::build(&source),
        },
        MobileDraftKind::Time => MobileManagementDraft::Time {
            draft: time::build(&source),
        },
    })
}

/// `draft` on the device's current reading, keeping the operator's
/// standing edits. The same variant comes back; `InvalidRequest` for one
/// whose category the device's card leaves out. Unchanged while there is
/// no reading, or when it was built on the current one.
pub(super) fn rebase(
    device: &MobileManagedDeviceRecord,
    draft: MobileManagementDraft,
) -> Result<MobileManagementDraft, MobileAppError> {
    refuse_unoffered(device, &draft)?;
    let category = category(kind(&draft));
    let Some(reading) = reading(device, category) else {
        return Ok(draft);
    };
    if reading.revision == reading_revision(&draft) {
        return Ok(draft);
    }
    let source = Source::new(reading);
    Ok(match draft {
        MobileManagementDraft::Radio { draft } => MobileManagementDraft::Radio {
            draft: radio::rebase(radio::build(&source), &draft),
        },
        MobileManagementDraft::Identity { draft } => MobileManagementDraft::Identity {
            draft: identity::rebase(identity::build(&source), &draft),
        },
        MobileManagementDraft::Repeater { draft } => MobileManagementDraft::Repeater {
            draft: repeater::rebase(repeater::build(&source), &draft),
        },
        MobileManagementDraft::MeshCore { draft } => MobileManagementDraft::MeshCore {
            draft: meshcore::rebase(meshcore::build(&source), &draft),
        },
        MobileManagementDraft::Wifi { draft } => MobileManagementDraft::Wifi {
            draft: wifi::rebase(wifi::build(&source), &draft),
        },
        MobileManagementDraft::Network { draft } => MobileManagementDraft::Network {
            draft: network::rebase(network::build(&source), &draft),
        },
        MobileManagementDraft::Bridge { draft } => MobileManagementDraft::Bridge {
            draft: bridge::rebase(bridge::build(&source), &draft),
        },
        MobileManagementDraft::Bluetooth { draft } => MobileManagementDraft::Bluetooth {
            draft: bluetooth::rebase(bluetooth::build(&source), &draft),
        },
        MobileManagementDraft::Gnss { draft } => MobileManagementDraft::Gnss {
            draft: gnss::rebase(gnss::build(&source), &draft),
        },
        MobileManagementDraft::Time { draft } => MobileManagementDraft::Time {
            draft: time::rebase(time::build(&source), &draft),
        },
    })
}

/// A draft folded for writing: what Apply would send, and what it cannot.
pub(super) struct Prepared {
    pub(super) category: UlcpManageCategory,
    pub(super) desired: UlcpDevicePropertiesRecord,
    pub(super) dirty: Vec<u32>,
    pub(super) problems: Vec<MobileFieldProblemRecord>,
    pub(super) warning: Option<MobileApplyWarning>,
    pub(super) details: MobileDraftDetails,
}

/// Rebase `draft`, then fold it against the device as published.
pub(super) fn prepare(
    device: &MobileManagedDeviceRecord,
    draft: MobileManagementDraft,
) -> Result<Prepared, MobileAppError> {
    let draft = rebase(device, draft)?;
    let category = category(kind(&draft));
    let reading = reading(device, category);
    let held = reading
        .map(|reading| reading.properties.clone())
        .unwrap_or_default();
    let mut fold = Fold::new(held);
    match &draft {
        MobileManagementDraft::Radio { draft } => radio::fold(draft, &mut fold),
        MobileManagementDraft::Identity { draft } => identity::fold(draft, &mut fold),
        MobileManagementDraft::Repeater { draft } => repeater::fold(draft, &mut fold),
        MobileManagementDraft::MeshCore { draft } => meshcore::fold(draft, &mut fold),
        MobileManagementDraft::Wifi { draft } => wifi::fold(draft, &mut fold),
        MobileManagementDraft::Network { draft } => network::fold(draft, &mut fold),
        MobileManagementDraft::Bridge { draft } => bridge::fold(draft, &mut fold),
        MobileManagementDraft::Bluetooth { draft } => bluetooth::fold(draft, &mut fold),
        MobileManagementDraft::Gnss { draft } => gnss::fold(draft, &mut fold),
        MobileManagementDraft::Time { draft } => time::fold(draft, &mut fold),
    }
    fold.check_encoding();
    // Warnings and details read what would be written, after the check.
    let (warning, details) = match &draft {
        MobileManagementDraft::Radio { draft } => radio::assess(draft, device, &fold),
        MobileManagementDraft::Identity { draft } => identity::assess(draft, &fold),
        MobileManagementDraft::Repeater { draft } => (None, repeater::details(draft)),
        MobileManagementDraft::MeshCore { draft } => (None, meshcore::details(draft, reading)),
        MobileManagementDraft::Wifi { .. } => {
            (wifi::warning(device, &fold), MobileDraftDetails::None)
        }
        MobileManagementDraft::Network { .. } => {
            (network::warning(device, &fold), MobileDraftDetails::None)
        }
        MobileManagementDraft::Bridge { .. }
        | MobileManagementDraft::Gnss { .. }
        | MobileManagementDraft::Time { .. } => (None, MobileDraftDetails::None),
        MobileManagementDraft::Bluetooth { .. } => bluetooth::assess(device, &fold),
    };
    let Fold {
        desired,
        dirty,
        problems,
    } = fold;
    let dirty = dirty.into_iter().collect();
    Ok(Prepared {
        category,
        desired,
        dirty,
        problems,
        warning,
        details,
    })
}

pub(super) fn review(
    device: &MobileManagedDeviceRecord,
    draft: MobileManagementDraft,
) -> Result<MobileDraftReviewRecord, MobileAppError> {
    let prepared = prepare(device, draft)?;
    Ok(MobileDraftReviewRecord {
        has_edits: !prepared.dirty.is_empty(),
        dirty: prepared.dirty,
        problems: prepared.problems,
        warning: prepared.warning,
        details: prepared.details,
    })
}

// MARK: Building fields

/// A reading, read as a draft's baseline.
pub(super) struct Source<'a> {
    pub(super) reading: &'a MobileCategoryReadingRecord,
}

impl<'a> Source<'a> {
    fn new(reading: &'a MobileCategoryReadingRecord) -> Self {
        Self { reading }
    }

    pub(super) fn held(&self) -> &'a UlcpDevicePropertiesRecord {
        &self.reading.properties
    }

    pub(super) fn revision(&self) -> u64 {
        self.reading.revision
    }

    /// Whether the device answered for `property`: where an empty value
    /// is a value, that is what makes the field known. A reading that
    /// holds nothing for it, such as one built from an empty cache, has
    /// not heard it, whatever it covers.
    pub(super) fn answered(&self, property: u32) -> bool {
        self.reading.answered.contains(&property)
            && self
                .reading
                .values
                .iter()
                .any(|value| value.property_id == property)
    }
}

pub(super) fn toggle(property_id: u32, reported: Option<bool>) -> MobileToggleField {
    let value = reported.unwrap_or(false);
    MobileToggleField {
        property_id,
        known: reported.is_some(),
        reported: value,
        value,
    }
}

/// A picker known when the device reported a value.
pub(super) fn choice<T: Into<i64>>(property_id: u32, reported: Option<T>) -> MobileChoiceField {
    let reported = reported.map(Into::into);
    MobileChoiceField {
        property_id,
        known: reported.is_some(),
        reported,
        value: reported,
    }
}

/// A picker whose `None` is a value, known when the device answered.
pub(super) fn optional_choice<T: Into<i64>>(
    property_id: u32,
    known: bool,
    reported: Option<T>,
) -> MobileChoiceField {
    let reported = reported.map(Into::into).filter(|_| known);
    MobileChoiceField {
        property_id,
        known,
        reported,
        value: reported,
    }
}

pub(super) fn integer<T: Into<i64>>(property_id: u32, reported: Option<T>) -> MobileIntegerField {
    let known = reported.is_some();
    let value = reported.map_or(0, Into::into);
    MobileIntegerField {
        property_id,
        known,
        reported: value,
        value,
    }
}

pub(super) fn optional_integer<T: Into<i64>>(
    property_id: u32,
    known: bool,
    reported: Option<T>,
) -> MobileOptionalIntegerField {
    let reported = reported.map(Into::into).filter(|_| known);
    MobileOptionalIntegerField {
        property_id,
        known,
        reported,
        value: reported,
    }
}

pub(super) fn text(property_id: u32, reported: Option<String>) -> MobileTextField {
    text_known(
        property_id,
        reported.is_some(),
        reported.unwrap_or_default(),
    )
}

pub(super) fn text_known(property_id: u32, known: bool, reported: String) -> MobileTextField {
    let reported = if known { reported } else { String::new() };
    MobileTextField {
        property_id,
        known,
        text: reported.clone(),
        reported,
    }
}

pub(super) fn list(property_id: u32, reported: Option<Vec<String>>) -> MobileTextListField {
    let known = reported.is_some();
    let reported = reported.unwrap_or_default();
    MobileTextListField {
        property_id,
        known,
        value: reported.clone(),
        reported,
    }
}

// MARK: Picker lists

/// `offered`, and the field's own value when it is known and not one of
/// them: a picker missing the value it holds shows no selection, and the
/// next pick silently rewrites the setting.
pub(in crate::app_core::manage) fn choice_list(
    offered: &[i64],
    field: &MobileChoiceField,
) -> MobileChoiceList {
    listed(offered, field.known, field.value)
}

/// `choice_list` for a picker whose `None` is a value of its own, never
/// an off-list one.
pub(in crate::app_core::manage) fn optional_choice_list(
    offered: &[i64],
    field: &MobileOptionalIntegerField,
) -> MobileChoiceList {
    listed(offered, field.known, field.value)
}

fn listed(offered: &[i64], known: bool, value: Option<i64>) -> MobileChoiceList {
    MobileChoiceList {
        offered: offered.to_vec(),
        other: value.filter(|value| known && !offered.contains(value)),
    }
}

// MARK: Rebasing fields

/// One field's dirtiness against its own baseline, and how an edit is
/// carried onto a fresh field.
pub(super) trait Field {
    fn known(&self) -> bool;
    fn dirty(&self) -> bool;
    /// Take `old`'s edit.
    fn keep(&mut self, old: &Self);
}

/// `fresh`, keeping `old`'s edit where one stands and `fresh` is known.
pub(super) fn rebased<F: Field>(mut fresh: F, old: &F) -> F {
    if old.dirty() && fresh.known() {
        fresh.keep(old);
    }
    fresh
}

impl Field for MobileToggleField {
    fn known(&self) -> bool {
        self.known
    }
    fn dirty(&self) -> bool {
        self.known && self.value != self.reported
    }
    fn keep(&mut self, old: &Self) {
        self.value = old.value;
    }
}

impl Field for MobileChoiceField {
    fn known(&self) -> bool {
        self.known
    }
    fn dirty(&self) -> bool {
        self.known && self.value != self.reported
    }
    fn keep(&mut self, old: &Self) {
        self.value = old.value;
    }
}

impl Field for MobileIntegerField {
    fn known(&self) -> bool {
        self.known
    }
    fn dirty(&self) -> bool {
        self.known && self.value != self.reported
    }
    fn keep(&mut self, old: &Self) {
        self.value = old.value;
    }
}

impl Field for MobileOptionalIntegerField {
    fn known(&self) -> bool {
        self.known
    }
    fn dirty(&self) -> bool {
        self.known && self.value != self.reported
    }
    fn keep(&mut self, old: &Self) {
        self.value = old.value;
    }
}

impl Field for MobileTextField {
    fn known(&self) -> bool {
        self.known
    }
    fn dirty(&self) -> bool {
        self.known && self.text != self.reported
    }
    fn keep(&mut self, old: &Self) {
        self.text.clone_from(&old.text);
    }
}

impl Field for MobileTextListField {
    fn known(&self) -> bool {
        self.known
    }
    fn dirty(&self) -> bool {
        self.known && self.value != self.reported
    }
    fn keep(&mut self, old: &Self) {
        self.value.clone_from(&old.value);
    }
}

/// The position is one field: both coordinates are kept or replaced
/// together, a half-typed pair included.
impl Field for MobilePositionField {
    fn known(&self) -> bool {
        self.known
    }
    fn dirty(&self) -> bool {
        self.known
            && (self.latitude, self.longitude) != (self.reported_latitude, self.reported_longitude)
    }
    fn keep(&mut self, old: &Self) {
        self.latitude = old.latitude;
        self.longitude = old.longitude;
    }
}

// MARK: Folding

/// What a draft folds into: the reading's record with the edits written
/// in, the properties they touch, and the edits that cannot be written.
pub(super) struct Fold {
    pub(super) desired: UlcpDevicePropertiesRecord,
    dirty: BTreeSet<u32>,
    problems: Vec<MobileFieldProblemRecord>,
}

type Record = UlcpDevicePropertiesRecord;

impl Fold {
    fn new(held: UlcpDevicePropertiesRecord) -> Self {
        Self {
            desired: held,
            dirty: BTreeSet::new(),
            problems: Vec::new(),
        }
    }

    pub(super) fn is_dirty(&self, property: u32) -> bool {
        self.dirty.contains(&property)
    }

    /// Write an edit to `property`.
    pub(super) fn edit(&mut self, property: u32, write: impl FnOnce(&mut Record)) {
        write(&mut self.desired);
        self.dirty.insert(property);
    }

    pub(super) fn problem(&mut self, property_id: u32, problem: MobileFieldProblem) {
        let record = MobileFieldProblemRecord {
            property_id,
            problem,
        };
        if !self.problems.contains(&record) {
            self.problems.push(record);
        }
    }

    pub(super) fn toggle(
        &mut self,
        field: &MobileToggleField,
        write: impl FnOnce(&mut Record, bool),
    ) {
        if field.dirty() {
            let value = field.value;
            self.edit(field.property_id, |desired| write(desired, value));
        }
    }

    /// A picker with no empty choice: `None` is out of range.
    pub(super) fn choice<T: TryFrom<i64>>(
        &mut self,
        field: &MobileChoiceField,
        write: impl FnOnce(&mut Record, T),
    ) {
        if !field.dirty() {
            return;
        }
        match field.value.map(T::try_from) {
            Some(Ok(value)) => self.edit(field.property_id, |desired| write(desired, value)),
            _ => self.problem(field.property_id, MobileFieldProblem::OutOfRange),
        }
    }

    /// A picker whose `None` is a value.
    pub(super) fn optional_choice<T: TryFrom<i64>>(
        &mut self,
        field: &MobileChoiceField,
        write: impl FnOnce(&mut Record, Option<T>),
    ) {
        if !field.dirty() {
            return;
        }
        match field.value.map(T::try_from).transpose() {
            Ok(value) => self.edit(field.property_id, |desired| write(desired, value)),
            Err(_) => self.problem(field.property_id, MobileFieldProblem::OutOfRange),
        }
    }

    /// A typed number; outside its wire type, or failing `valid`, it is
    /// `invalid`.
    pub(super) fn integer<T: TryFrom<i64> + Copy>(
        &mut self,
        field: &MobileIntegerField,
        invalid: MobileFieldProblem,
        valid: impl FnOnce(T) -> bool,
        write: impl FnOnce(&mut Record, T),
    ) {
        if !field.dirty() {
            return;
        }
        match T::try_from(field.value) {
            Ok(value) if valid(value) => {
                self.edit(field.property_id, |desired| write(desired, value));
            }
            _ => self.problem(field.property_id, invalid),
        }
    }

    /// A typed number where `None` is a value.
    pub(super) fn optional_integer<T: TryFrom<i64> + Copy>(
        &mut self,
        field: &MobileOptionalIntegerField,
        invalid: MobileFieldProblem,
        valid: impl FnOnce(T) -> bool,
        write: impl FnOnce(&mut Record, Option<T>),
    ) {
        if !field.dirty() {
            return;
        }
        match field.value.map(T::try_from) {
            None => self.edit(field.property_id, |desired| write(desired, None)),
            Some(Ok(value)) if valid(value) => {
                self.edit(field.property_id, |desired| write(desired, Some(value)));
            }
            Some(_) => self.problem(field.property_id, invalid),
        }
    }

    pub(super) fn text(
        &mut self,
        field: &MobileTextField,
        write: impl FnOnce(&mut Record, String),
    ) {
        if field.dirty() {
            let text = field.text.clone();
            self.edit(field.property_id, |desired| write(desired, text));
        }
    }

    pub(super) fn list(
        &mut self,
        field: &MobileTextListField,
        write: impl FnOnce(&mut Record, Vec<String>),
    ) {
        if field.dirty() {
            let value = field.value.clone();
            self.edit(field.property_id, |desired| write(desired, value));
        }
    }

    /// Check every edit the way the write encodes it: a value the encoder
    /// refuses is its field's problem rather than a failed Apply.
    fn check_encoding(&mut self) {
        let refused: Vec<u32> = self
            .dirty
            .iter()
            .copied()
            .filter(|property| ulcp_dirty_writes(self.desired.clone(), vec![*property]).is_err())
            .collect();
        for property in refused {
            self.dirty.remove(&property);
            self.problem(property, encoding_problem(property));
        }
    }
}

/// The problem a property's value is when its encoder refuses it.
fn encoding_problem(property: u32) -> MobileFieldProblem {
    match property {
        prop::BRIDGE_HOST => MobileFieldProblem::HostInvalid,
        prop::BRIDGE_PORT => MobileFieldProblem::PortInvalid,
        prop::BRIDGE_SERVER_KEY => MobileFieldProblem::ServerKeyInvalid,
        prop::LAN_BEARER_GROUP => MobileFieldProblem::GroupInvalid,
        prop::LAN_BEARER_INGRESS_LIMIT => MobileFieldProblem::LimitInvalid,
        prop::IPV4_CONFIG | prop::IPV6_CONFIG => MobileFieldProblem::AddressInvalid,
        prop::IP_DNS => MobileFieldProblem::ResolverInvalid,
        _ => MobileFieldProblem::OutOfRange,
    }
}

/// `text` less the horizontal white space at either end: Unicode `Zs` and
/// the tab, never a line break.
pub(in crate::app_core::manage) fn trim_horizontal(text: &str) -> &str {
    text.trim_matches(|character: char| {
        matches!(
            character,
            '\t' | ' ' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
        )
    })
}

/// The LAN group as written: empty text returns it to the device's
/// default, shared by Network and Bridge.
pub(super) fn fold_group(field: &MobileTextField, fold: &mut Fold) {
    if !field.dirty() {
        return;
    }
    let text = trim_horizontal(&field.text);
    if text.is_empty() {
        fold.edit(field.property_id, |desired| desired.lan_bearer_group = None);
        return;
    }
    match crate::ulcp::ulcp_lan_group(text.to_owned()) {
        // The same group spelled another way is not an edit.
        Ok(group) if group == field.reported => {}
        Ok(group) => fold.edit(field.property_id, |desired| {
            desired.lan_bearer_group = Some(group);
        }),
        Err(_) => fold.problem(field.property_id, MobileFieldProblem::GroupInvalid),
    }
}

pub(super) fn group_field(source: &Source<'_>) -> MobileTextField {
    text(
        prop::LAN_BEARER_GROUP,
        source.held().lan_bearer_group.clone(),
    )
}
