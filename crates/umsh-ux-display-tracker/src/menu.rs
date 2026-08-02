//! On-screen menu policy shared by every display tracker.
//!
//! The model is a flat, wrapping list of [`MenuItem`]s with a
//! confirmation page in front of the destructive ones. Each board
//! enables the subset it can actually perform via [`MenuItems`];
//! navigation skips whatever is not enabled, so the same code drives a
//! two-item Heltec menu and a four-item T-Echo menu without either
//! firmware knowing the other exists.
//!
//! [`MenuItem::Status`] is the home item and is always enabled: it is
//! where boot starts, where an activated item returns to, and where the
//! display-attention lapse sends the user back to (see
//! [`crate::attention`]).

/// One resolved navigation gesture.
///
/// Boards with a single button map click / double-click / hold-release
/// onto these; boards with a D-pad map up / down, press, and a back
/// button onto the same three. The model never learns which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiInput {
    Forward,
    Select,
    Backward,
}

/// An entry in the menu.
///
/// The enum is the union across all display trackers; a board narrows it
/// with [`MenuItems`]. Declaration order is navigation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuItem {
    /// Home. Shows the battery, and whatever else is not nominal.
    Status,
    /// Radio activity since boot: frame counts, power, duty cycle. A
    /// page, not an action.
    Stats,
    /// Advertise this device's identity now.
    CheckIn,
    /// Open a time-limited pairing window for a new companion.
    StartPairing,
    /// Forget every bonded companion. Confirmed before it runs.
    ClearBonds,
}

impl MenuItem {
    /// Every item, in navigation order.
    pub const ALL: [MenuItem; 5] = [
        MenuItem::Status,
        MenuItem::Stats,
        MenuItem::CheckIn,
        MenuItem::StartPairing,
        MenuItem::ClearBonds,
    ];

    const fn bit(self) -> u8 {
        1 << self as u8
    }

    const fn index(self) -> usize {
        self as usize
    }

    /// Whether selecting this item opens a confirmation page rather than
    /// acting immediately.
    ///
    /// Destructive items confirm; everything else is either harmless or
    /// trivially reversible.
    pub const fn requires_confirmation(self) -> bool {
        matches!(self, MenuItem::ClearBonds)
    }

    /// What activating this item asks the firmware to do. `Status` and
    /// `Stats` are inert — they are pages, not actions.
    pub const fn effect(self) -> Option<UiEffect> {
        match self {
            MenuItem::Status | MenuItem::Stats => None,
            MenuItem::CheckIn => Some(UiEffect::CheckIn),
            MenuItem::StartPairing => Some(UiEffect::StartPairing),
            MenuItem::ClearBonds => Some(UiEffect::ClearBonds),
        }
    }
}

/// The set of menu items a board enables.
///
/// [`MenuItem::Status`] is always present regardless of how the set was
/// built: a menu with no home item has nowhere to return to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuItems(u8);

impl MenuItems {
    /// Just [`MenuItem::Status`].
    pub const fn new() -> Self {
        Self(MenuItem::Status.bit())
    }

    /// Every item this crate defines.
    pub const fn all() -> Self {
        Self(
            MenuItem::Status.bit()
                | MenuItem::Stats.bit()
                | MenuItem::CheckIn.bit()
                | MenuItem::StartPairing.bit()
                | MenuItem::ClearBonds.bit(),
        )
    }

    /// Enable one more item.
    pub const fn with(self, item: MenuItem) -> Self {
        Self(self.0 | item.bit())
    }

    pub const fn contains(self, item: MenuItem) -> bool {
        self.0 & item.bit() != 0
    }

    /// Number of enabled items. Always at least one.
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    pub const fn is_empty(self) -> bool {
        false
    }

    /// Step `from` by `step` positions through the enabled items,
    /// wrapping. `step` is +1 for forward and -1 for backward.
    fn step(self, from: MenuItem, step: isize) -> MenuItem {
        let n = MenuItem::ALL.len();
        let mut index = from.index();
        // At worst this visits every item once; `Status` is always
        // enabled, so it always terminates on something.
        for _ in 0..n {
            index = (index as isize + step).rem_euclid(n as isize) as usize;
            let candidate = MenuItem::ALL[index];
            if self.contains(candidate) {
                return candidate;
            }
        }
        MenuItem::Status
    }
}

impl Default for MenuItems {
    fn default() -> Self {
        Self::new()
    }
}

/// The screen currently being shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    /// The menu, with `.0` highlighted.
    Menu(MenuItem),
    /// A confirmation for a destructive `item`. `confirm_selected` is
    /// false while Cancel is the visible choice.
    Confirm {
        item: MenuItem,
        confirm_selected: bool,
    },
}

/// Something the firmware should do as a result of a selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiEffect {
    CheckIn,
    StartPairing,
    ClearBonds,
}

/// A transient result message shown on the status page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiNotice {
    CheckInRequested,
    PairingStarted,
    PairingUnavailable,
    BondsCleared,
    ClearFailed,
}

/// The menu state machine.
///
/// Pure logic: no clock, no I/O. The owning task feeds it resolved
/// gestures and renders whatever [`page`](Self::page) and
/// [`notice`](Self::notice) report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiModel {
    items: MenuItems,
    page: Page,
    notice: Option<UiNotice>,
}

impl UiModel {
    pub const fn new(items: MenuItems) -> Self {
        Self {
            items,
            page: Page::Menu(MenuItem::Status),
            notice: None,
        }
    }

    pub const fn page(&self) -> Page {
        self.page
    }

    pub const fn notice(&self) -> Option<UiNotice> {
        self.notice
    }

    pub const fn items(&self) -> MenuItems {
        self.items
    }

    /// Whether the model is showing its home page with nothing pending.
    ///
    /// The attention lapse uses this to skip a pointless redraw.
    pub const fn is_home(&self) -> bool {
        matches!(self.page, Page::Menu(MenuItem::Status)) && self.notice.is_none()
    }

    /// Report a result and return to the status page.
    pub fn set_notice(&mut self, notice: UiNotice) {
        self.page = Page::Menu(MenuItem::Status);
        self.notice = Some(notice);
    }

    pub fn clear_notice(&mut self) {
        self.notice = None;
    }

    /// Drop everything transient and return to the home page.
    ///
    /// Called when display attention lapses, so the next press always
    /// starts from a page whose meaning the user can see rather than
    /// from a confirmation they walked away from.
    pub fn go_home(&mut self) {
        self.page = Page::Menu(MenuItem::Status);
        self.notice = None;
    }

    /// Apply one resolved gesture.
    ///
    /// A destructive confirmation defaults to Cancel; Forward and
    /// Backward both toggle its two choices, and Select activates the
    /// visible one.
    pub fn apply(&mut self, input: UiInput) -> Option<UiEffect> {
        self.notice = None;
        match (self.page, input) {
            (Page::Menu(item), UiInput::Forward) => {
                self.page = Page::Menu(self.items.step(item, 1));
                None
            }
            (Page::Menu(item), UiInput::Backward) => {
                self.page = Page::Menu(self.items.step(item, -1));
                None
            }
            (Page::Menu(item), UiInput::Select) => {
                if item.requires_confirmation() {
                    self.page = Page::Confirm {
                        item,
                        confirm_selected: false,
                    };
                    return None;
                }
                let effect = item.effect();
                if effect.is_some() {
                    self.page = Page::Menu(MenuItem::Status);
                }
                effect
            }
            (
                Page::Confirm {
                    item,
                    confirm_selected,
                },
                UiInput::Forward | UiInput::Backward,
            ) => {
                self.page = Page::Confirm {
                    item,
                    confirm_selected: !confirm_selected,
                };
                None
            }
            (
                Page::Confirm {
                    item,
                    confirm_selected: false,
                },
                UiInput::Select,
            ) => {
                self.page = Page::Menu(item);
                None
            }
            (
                Page::Confirm {
                    item,
                    confirm_selected: true,
                },
                UiInput::Select,
            ) => {
                self.page = Page::Menu(MenuItem::Status);
                item.effect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> UiModel {
        UiModel::new(MenuItems::all())
    }

    #[test]
    fn forward_and_backward_wrap_menu_items() {
        let mut ui = full();
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Stats));
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::CheckIn));
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::StartPairing));
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::ClearBonds));
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        ui.apply(UiInput::Backward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::ClearBonds));
    }

    #[test]
    fn navigation_skips_items_the_board_does_not_enable() {
        // A board with no bond storage to clear and no beacon.
        let items = MenuItems::new().with(MenuItem::StartPairing);
        let mut ui = UiModel::new(items);
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::StartPairing));
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        ui.apply(UiInput::Backward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::StartPairing));
    }

    #[test]
    fn status_only_menu_stays_put() {
        let mut ui = UiModel::new(MenuItems::new());
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        assert_eq!(ui.apply(UiInput::Select), None);
    }

    #[test]
    fn safe_items_activate_without_confirmation() {
        let mut ui = full();
        ui.apply(UiInput::Forward);
        ui.apply(UiInput::Forward);
        assert_eq!(ui.apply(UiInput::Select), Some(UiEffect::CheckIn));
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));

        ui.apply(UiInput::Forward);
        ui.apply(UiInput::Forward);
        ui.apply(UiInput::Forward);
        assert_eq!(ui.apply(UiInput::Select), Some(UiEffect::StartPairing));
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
    }

    #[test]
    fn status_select_is_inert() {
        let mut ui = full();
        assert_eq!(ui.apply(UiInput::Select), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
    }

    #[test]
    fn clear_defaults_to_cancel_and_requires_visible_confirmation() {
        let mut ui = full();
        ui.apply(UiInput::Backward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::ClearBonds));
        assert_eq!(ui.apply(UiInput::Select), None);
        assert_eq!(
            ui.page(),
            Page::Confirm {
                item: MenuItem::ClearBonds,
                confirm_selected: false,
            }
        );

        // Selecting the default choice cancels, returning to the item.
        assert_eq!(ui.apply(UiInput::Select), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::ClearBonds));

        // Re-enter, visibly choose Clear, then confirm it.
        ui.apply(UiInput::Select);
        ui.apply(UiInput::Forward);
        assert_eq!(
            ui.page(),
            Page::Confirm {
                item: MenuItem::ClearBonds,
                confirm_selected: true,
            }
        );
        assert_eq!(ui.apply(UiInput::Select), Some(UiEffect::ClearBonds));
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
    }

    #[test]
    fn backward_also_toggles_the_confirmation() {
        let mut ui = full();
        ui.apply(UiInput::Backward);
        ui.apply(UiInput::Select);
        ui.apply(UiInput::Backward);
        assert_eq!(
            ui.page(),
            Page::Confirm {
                item: MenuItem::ClearBonds,
                confirm_selected: true,
            }
        );
    }

    #[test]
    fn notice_returns_to_status_and_clears_on_input() {
        let mut ui = full();
        ui.apply(UiInput::Backward);
        ui.set_notice(UiNotice::BondsCleared);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        assert_eq!(ui.notice(), Some(UiNotice::BondsCleared));

        ui.apply(UiInput::Forward);
        assert_eq!(ui.notice(), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Stats));
    }

    #[test]
    fn go_home_drops_a_pending_confirmation() {
        let mut ui = full();
        ui.apply(UiInput::Backward);
        ui.apply(UiInput::Select);
        assert!(!ui.is_home());

        ui.go_home();
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        assert_eq!(ui.notice(), None);
        assert!(ui.is_home());
    }

    #[test]
    fn go_home_drops_a_stale_notice() {
        let mut ui = full();
        ui.set_notice(UiNotice::PairingStarted);
        assert!(!ui.is_home());
        ui.go_home();
        assert!(ui.is_home());
    }

    #[test]
    fn status_is_always_enabled() {
        assert!(MenuItems::new().contains(MenuItem::Status));
        assert!(MenuItems::all().contains(MenuItem::Status));
        assert_eq!(MenuItems::new().len(), 1);
        assert_eq!(MenuItems::all().len(), 5);
    }
}
