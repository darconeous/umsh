//! Where the device's clock is meant to be and how it shows it. The clock
//! itself is set by its own action, never by Apply.

use umsh_ulcp::ids::prop;

use super::{Fold, Source, rebased, text, toggle};
use crate::app_core::manage::records::MobileTimeDraft;

pub(super) fn build(source: &Source<'_>) -> MobileTimeDraft {
    let held = source.held();
    MobileTimeDraft {
        reading_revision: source.revision(),
        tz_rule: text(prop::TZ_RULE, held.tz_rule.clone()),
        time_24h: toggle(prop::TIME_24H, held.time_24h),
        time_trust: toggle(prop::GNSS_TIME_TRUST, held.gnss_time_trust),
    }
}

pub(super) fn rebase(fresh: MobileTimeDraft, old: &MobileTimeDraft) -> MobileTimeDraft {
    MobileTimeDraft {
        reading_revision: fresh.reading_revision,
        tz_rule: rebased(fresh.tz_rule, &old.tz_rule),
        time_24h: rebased(fresh.time_24h, &old.time_24h),
        time_trust: rebased(fresh.time_trust, &old.time_trust),
    }
}

pub(super) fn fold(draft: &MobileTimeDraft, fold: &mut Fold) {
    fold.text(&draft.tz_rule, |desired, rule| desired.tz_rule = Some(rule));
    fold.toggle(&draft.time_24h, |desired, value| {
        desired.time_24h = Some(value);
    });
    fold.toggle(&draft.time_trust, |desired, value| {
        desired.gnss_time_trust = Some(value);
    });
}
