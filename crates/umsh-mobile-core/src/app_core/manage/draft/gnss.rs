//! The receiver switch. The fix is what the receiver reports, not a
//! setting.

use umsh_ulcp::ids::prop;

use super::{Fold, Source, rebased, toggle};
use crate::app_core::manage::records::MobileGnssDraft;

pub(super) fn build(source: &Source<'_>) -> MobileGnssDraft {
    MobileGnssDraft {
        reading_revision: source.revision(),
        enabled: toggle(prop::GNSS_ENABLED, source.held().gnss_enabled),
    }
}

pub(super) fn rebase(fresh: MobileGnssDraft, old: &MobileGnssDraft) -> MobileGnssDraft {
    MobileGnssDraft {
        reading_revision: fresh.reading_revision,
        enabled: rebased(fresh.enabled, &old.enabled),
    }
}

pub(super) fn fold(draft: &MobileGnssDraft, fold: &mut Fold) {
    fold.toggle(&draft.enabled, |desired, value| {
        desired.gnss_enabled = Some(value);
    });
}
