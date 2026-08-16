//! On-screen menu policy shared by every display tracker.
//!
//! The model is a tree three levels deep: a top level that reads, a
//! [`Level::Settings`] list that groups the subsystems, and one list per
//! subsystem holding the settings that change something. Each level is a
//! wrapping list of [`MenuItem`]s with a confirmation page in front of
//! the destructive entries. Each board enables the subset it can actually
//! perform via [`MenuItems`]; navigation skips whatever is not enabled,
//! so the same code drives a two-item Heltec menu and a full T-Echo tree
//! without either firmware knowing the other exists.
//!
//! Depth is fixed and known here rather than discovered at runtime, so
//! the cursor is one [`MenuItem`] and nothing else: an item knows its own
//! [`level`](MenuItem::level), and a level knows the entry that opens it.
//! That keeps [`UiModel`] `Copy`, which the display tasks rely on.
//!
//! Highlighting an entry is how you read it. An entry that has content
//! shows it in place, so walking the list never changes anything and
//! Select is reserved for the entries that act.
//!
//! [`MenuItem::Status`] is the home item and is always enabled: it is
//! where boot starts, where an activated item returns to, and where the
//! display-attention lapse sends the user back to (see
//! [`crate::attention`]).

/// One resolved navigation gesture.
///
/// Boards with a single button map click / double-click / hold-release
/// onto the first three; boards with a D-pad map down / up / press onto
/// the same three and have a real [`Back`](UiInput::Back) besides. The
/// model never learns which.
///
/// [`Back`](UiInput::Back) leaves the current screen, where
/// [`Backward`](UiInput::Backward) only moves the cursor within it. A
/// board without a back button never sends it and reaches the same place
/// through the Back entry every level carries; a board with one can also
/// still use that entry, so the two never need to be told apart
/// downstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiInput {
    Forward,
    Select,
    Backward,
    Back,
}

/// One list in the tree.
///
/// A level is a wrapping list of the [`MenuItem`]s that report it from
/// [`MenuItem::level`]. Every level below the top opens from exactly one
/// entry in its parent, which is what lets Back return without a stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Top,
    Settings,
    Bluetooth,
    Gnss,
    Radio,
}

impl Level {
    /// Every level, outermost first.
    pub const ALL: [Level; 5] = [
        Level::Top,
        Level::Settings,
        Level::Bluetooth,
        Level::Gnss,
        Level::Radio,
    ];

    /// The entry in the parent level that opens this one. `None` for the
    /// top level, which nothing opens.
    pub const fn opened_by(self) -> Option<MenuItem> {
        match self {
            Level::Top => None,
            Level::Settings => Some(MenuItem::Settings),
            Level::Bluetooth => Some(MenuItem::Bluetooth),
            Level::Gnss => Some(MenuItem::Gnss),
            Level::Radio => Some(MenuItem::Radio),
        }
    }

    /// This level's own Back entry. `None` for the top level, which has
    /// nowhere to go back to.
    pub const fn back(self) -> Option<MenuItem> {
        match self {
            Level::Top => None,
            Level::Settings => Some(MenuItem::SettingsBack),
            Level::Bluetooth => Some(MenuItem::BluetoothBack),
            Level::Gnss => Some(MenuItem::GnssBack),
            Level::Radio => Some(MenuItem::RadioBack),
        }
    }
}

/// Which setting a [`EntryKind::Toggle`] entry flips.
///
/// The model never learns a toggle's value — that is device state the
/// firmware owns and the renderer is handed separately. All the model
/// does is say which one the user asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToggleId {
    Bluetooth,
    Gnss,
    ShareLocation,
    Forwarding,
}

/// What an entry does when it is selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// Reads in place. Select does nothing, or the one extra action the
    /// entry defines — home's check-in is the only one today.
    Reading(Option<UiEffect>),
    /// Opens the named level.
    Submenu(Level),
    /// Flips a setting and stays put, so the new state is on the screen
    /// the user is already looking at.
    Toggle(ToggleId),
    /// Acts, returns home, and reports the outcome as a notice.
    Action(UiEffect),
    /// Acts only after a confirmation that defaults to Cancel.
    Destructive(UiEffect),
    /// Leaves this level for its parent.
    Back,
}

/// An entry in the menu.
///
/// The enum is the union across all display trackers; a board narrows it
/// with [`MenuItems`]. Declaration order is navigation order, and every
/// level's entries are contiguous so stepping stays an index walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuItem {
    // ─── Top ───
    /// Home. Shows the battery, and whatever else is not nominal.
    Status,
    /// This device's own address, for another device to take down.
    Identity,
    /// The settings that change something.
    Settings,

    // ─── Settings ───
    SettingsBack,
    /// The Bluetooth submenu.
    Bluetooth,
    /// The GNSS submenu.
    Gnss,
    /// The radio submenu.
    Radio,

    // ─── Bluetooth ───
    BluetoothBack,
    /// Turn the Bluetooth radio on and off.
    BluetoothToggle,
    /// Open a time-limited pairing window for a new companion.
    StartPairing,
    /// Forget every bonded companion. Confirmed before it runs.
    ClearBonds,

    // ─── GNSS ───
    GnssBack,
    /// Turn the GNSS receiver on and off.
    GnssToggle,
    /// Whether position goes out in what the device advertises. A
    /// separate decision from whether the device knows where it is.
    ShareLocation,

    // ─── Radio ───
    RadioBack,
    /// Whether other nodes' frames are relayed onward.
    Forwarding,
    /// Radio activity since boot: frame counts, power, duty cycle. A
    /// page, not an action.
    Stats,
}

impl MenuItem {
    /// Every item, in navigation order.
    pub const ALL: [MenuItem; 17] = [
        MenuItem::Status,
        MenuItem::Identity,
        MenuItem::Settings,
        MenuItem::SettingsBack,
        MenuItem::Bluetooth,
        MenuItem::Gnss,
        MenuItem::Radio,
        MenuItem::BluetoothBack,
        MenuItem::BluetoothToggle,
        MenuItem::StartPairing,
        MenuItem::ClearBonds,
        MenuItem::GnssBack,
        MenuItem::GnssToggle,
        MenuItem::ShareLocation,
        MenuItem::RadioBack,
        MenuItem::Forwarding,
        MenuItem::Stats,
    ];

    const fn bit(self) -> u32 {
        1 << self as u32
    }

    const fn index(self) -> usize {
        self as usize
    }

    /// Which list this entry belongs to.
    pub const fn level(self) -> Level {
        match self {
            MenuItem::Status | MenuItem::Identity | MenuItem::Settings => Level::Top,
            MenuItem::SettingsBack | MenuItem::Bluetooth | MenuItem::Gnss | MenuItem::Radio => {
                Level::Settings
            }
            MenuItem::BluetoothBack
            | MenuItem::BluetoothToggle
            | MenuItem::StartPairing
            | MenuItem::ClearBonds => Level::Bluetooth,
            MenuItem::GnssBack | MenuItem::GnssToggle | MenuItem::ShareLocation => Level::Gnss,
            MenuItem::RadioBack | MenuItem::Forwarding | MenuItem::Stats => Level::Radio,
        }
    }

    /// What selecting this entry does.
    pub const fn kind(self) -> EntryKind {
        match self {
            // Home's Select is the device's frequent, non-destructive
            // action; the cost of firing it by accident is one frame of
            // airtime.
            MenuItem::Status => EntryKind::Reading(Some(UiEffect::CheckIn)),
            MenuItem::Identity | MenuItem::Stats => EntryKind::Reading(None),
            MenuItem::Settings => EntryKind::Submenu(Level::Settings),
            MenuItem::Bluetooth => EntryKind::Submenu(Level::Bluetooth),
            MenuItem::Gnss => EntryKind::Submenu(Level::Gnss),
            MenuItem::Radio => EntryKind::Submenu(Level::Radio),
            MenuItem::SettingsBack
            | MenuItem::BluetoothBack
            | MenuItem::GnssBack
            | MenuItem::RadioBack => EntryKind::Back,
            MenuItem::BluetoothToggle => EntryKind::Toggle(ToggleId::Bluetooth),
            MenuItem::GnssToggle => EntryKind::Toggle(ToggleId::Gnss),
            MenuItem::ShareLocation => EntryKind::Toggle(ToggleId::ShareLocation),
            MenuItem::Forwarding => EntryKind::Toggle(ToggleId::Forwarding),
            MenuItem::StartPairing => EntryKind::Action(UiEffect::StartPairing),
            MenuItem::ClearBonds => EntryKind::Destructive(UiEffect::ClearBonds),
        }
    }

    /// Entries a board never has to ask for.
    ///
    /// Home has to exist or there is nowhere to return to, and a Back
    /// entry has to exist or a level the user entered has no exit — on a
    /// one-button board the entry *is* the way out.
    const fn always_enabled(self) -> bool {
        matches!(
            self,
            MenuItem::Status
                | MenuItem::SettingsBack
                | MenuItem::BluetoothBack
                | MenuItem::GnssBack
                | MenuItem::RadioBack
        )
    }

    /// Whether selecting this item opens a confirmation page rather than
    /// acting immediately.
    ///
    /// Destructive items confirm; everything else is either harmless or
    /// trivially reversible.
    pub const fn requires_confirmation(self) -> bool {
        matches!(self.kind(), EntryKind::Destructive(_))
    }

    /// What activating this item asks the firmware to do. Reading
    /// entries, submenus, and Back are inert — they move the user
    /// around rather than changing anything.
    pub const fn effect(self) -> Option<UiEffect> {
        match self.kind() {
            EntryKind::Action(effect) | EntryKind::Destructive(effect) => Some(effect),
            EntryKind::Reading(effect) => effect,
            EntryKind::Toggle(id) => Some(UiEffect::Toggle(id)),
            EntryKind::Submenu(_) | EntryKind::Back => None,
        }
    }
}

/// The set of menu items a board enables.
///
/// [`MenuItem::Status`] and every Back entry are always present
/// regardless of how the set was built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuItems(u32);

impl MenuItems {
    /// Just the entries no board can do without.
    pub const fn new() -> Self {
        Self(
            MenuItem::Status.bit()
                | MenuItem::SettingsBack.bit()
                | MenuItem::BluetoothBack.bit()
                | MenuItem::GnssBack.bit()
                | MenuItem::RadioBack.bit(),
        )
    }

    /// Every item this crate defines.
    pub const fn all() -> Self {
        let mut bits = 0u32;
        let mut i = 0;
        while i < MenuItem::ALL.len() {
            bits |= MenuItem::ALL[i].bit();
            i += 1;
        }
        Self(bits)
    }

    /// Enable one more item.
    pub const fn with(self, item: MenuItem) -> Self {
        Self(self.0 | item.bit())
    }

    /// Disable one item.
    ///
    /// The counterpart to [`with`](Self::with) for boards that start from
    /// [`all`](Self::all) and name what they cannot do, which is the
    /// shorter list on most hardware. Removing every entry of a level
    /// removes the way into it too — see
    /// [`level_is_empty`](Self::level_is_empty) — so a board need not
    /// also remember to disable the submenu that led there.
    pub const fn without(self, item: MenuItem) -> Self {
        Self(self.0 & !item.bit())
    }

    pub const fn contains(self, item: MenuItem) -> bool {
        item.always_enabled() || self.0 & item.bit() != 0
    }

    /// Number of enabled items across the whole tree. Always at least
    /// one.
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    pub const fn is_empty(self) -> bool {
        false
    }

    /// Whether a level has anything worth entering: any enabled entry
    /// that is not its own Back.
    ///
    /// A submenu whose entries are all disabled is not shown at all,
    /// rather than opening onto a list containing only Back.
    pub fn level_is_empty(self, level: Level) -> bool {
        !MenuItem::ALL
            .iter()
            .any(|&item| item.level() == level && !item.is_back() && self.reachable(item))
    }

    /// Whether an entry can be navigated to: enabled, and not a doorway
    /// into a level with nothing in it.
    fn reachable(self, item: MenuItem) -> bool {
        if !self.contains(item) {
            return false;
        }
        match item.kind() {
            EntryKind::Submenu(level) => !self.level_is_empty(level),
            _ => true,
        }
    }

    /// The enabled entries of one level, in navigation order.
    ///
    /// This is what a renderer draws a list from, so it and
    /// [`step`](Self::step) must agree about what is on screen.
    pub fn entries(self, level: Level) -> impl Iterator<Item = MenuItem> {
        MenuItem::ALL
            .into_iter()
            .filter(move |&item| item.level() == level && self.reachable(item))
    }

    /// The entry a freshly entered level should highlight: the first one
    /// after Back.
    ///
    /// Highlighting the exit of a screen the user just asked to enter
    /// would waste the press that got them there. A level with nothing
    /// but Back falls back to it, though [`level_is_empty`](Self::level_is_empty)
    /// means such a level is never entered.
    pub fn first_after_back(self, level: Level) -> MenuItem {
        MenuItem::ALL
            .iter()
            .copied()
            .find(|&item| item.level() == level && !item.is_back() && self.reachable(item))
            .or_else(|| level.back())
            .unwrap_or(MenuItem::Status)
    }

    /// Step `from` by `step` positions through the enabled items of its
    /// own level, wrapping. `step` is +1 for forward and -1 for
    /// backward.
    fn step(self, from: MenuItem, step: isize) -> MenuItem {
        let level = from.level();
        let n = MenuItem::ALL.len();
        let mut index = from.index();
        // At worst this visits every item once. Every level holds at
        // least one always-enabled entry — Status at the top, Back
        // below it — so it always terminates on something.
        for _ in 0..n {
            index = (index as isize + step).rem_euclid(n as isize) as usize;
            let candidate = MenuItem::ALL[index];
            if candidate.level() == level && self.reachable(candidate) {
                return candidate;
            }
        }
        from
    }
}

impl MenuItem {
    const fn is_back(self) -> bool {
        matches!(self.kind(), EntryKind::Back)
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
    /// The menu, with `.0` highlighted. The item's own
    /// [`level`](MenuItem::level) is the list being shown.
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
    /// Flip a setting. The firmware applies it and publishes the new
    /// value; the menu does not track it.
    Toggle(ToggleId),
}

/// A transient result message shown on the status page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiNotice {
    CheckInRequested,
    PairingStarted,
    PairingUnavailable,
    BondsCleared,
    ClearFailed,
    /// A toggle the board could not carry out.
    ToggleUnavailable,
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

    /// The list currently on screen.
    pub const fn level(&self) -> Level {
        match self.page {
            Page::Menu(item) => item.level(),
            Page::Confirm { item, .. } => item.level(),
        }
    }

    /// Whether the model is showing its home page with nothing pending.
    ///
    /// The attention lapse uses this to skip a pointless redraw, so it
    /// must be false anywhere below the top level — a bistable panel
    /// that skips the refresh keeps showing a submenu the user walked
    /// away from.
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
    /// from a confirmation they walked away from — or from a settings
    /// list three levels down.
    pub fn go_home(&mut self) {
        self.page = Page::Menu(MenuItem::Status);
        self.notice = None;
    }

    /// Apply one resolved gesture.
    ///
    /// A destructive confirmation defaults to Cancel; Forward and
    /// Backward both toggle its two choices, and Select activates the
    /// visible one.
    /// Leave `level` for the entry that opened it.
    ///
    /// The entry that opened a level is what the user is returning to, so
    /// the way back in is under the cursor rather than a list-length
    /// away. Leaving the top level — which nothing opened — goes home
    /// instead, so Back is never a press that does nothing.
    fn leave(&mut self, level: Level) {
        self.page = Page::Menu(level.opened_by().unwrap_or(MenuItem::Status));
    }

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
            (Page::Menu(item), UiInput::Select) => match item.kind() {
                // A reading entry stays where it is: the user is looking
                // at it, and its action — where it has one — returns
                // nothing to look at instead.
                EntryKind::Reading(effect) => effect,
                EntryKind::Submenu(level) => {
                    self.page = Page::Menu(self.items.first_after_back(level));
                    None
                }
                EntryKind::Back => {
                    self.leave(item.level());
                    None
                }
                // A toggle stays put: its whole result is a state the
                // user is looking at, and returning home would hide the
                // evidence that the press worked.
                EntryKind::Toggle(id) => Some(UiEffect::Toggle(id)),
                EntryKind::Action(effect) => {
                    self.page = Page::Menu(MenuItem::Status);
                    Some(effect)
                }
                EntryKind::Destructive(_) => {
                    self.page = Page::Confirm {
                        item,
                        confirm_selected: false,
                    };
                    None
                }
            },
            (Page::Menu(item), UiInput::Back) => {
                self.leave(item.level());
                None
            }
            // Backing out of a question is answering it with no, which
            // is the answer a confirmation defaults to anyway.
            (Page::Confirm { item, .. }, UiInput::Back) => {
                self.page = Page::Menu(item);
                None
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

    /// Walk to `item` from wherever the model is, by Forward presses
    /// within one level. Panics rather than looping forever.
    fn walk_to(ui: &mut UiModel, item: MenuItem) {
        for _ in 0..MenuItem::ALL.len() + 1 {
            if ui.page() == Page::Menu(item) {
                return;
            }
            ui.apply(UiInput::Forward);
        }
        panic!("never reached {item:?}");
    }

    #[test]
    fn forward_and_backward_wrap_the_top_level() {
        let mut ui = full();
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Identity));
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Settings));
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        ui.apply(UiInput::Backward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Settings));
    }

    #[test]
    fn navigation_never_leaves_the_current_level() {
        let mut ui = full();
        walk_to(&mut ui, MenuItem::Settings);
        ui.apply(UiInput::Select);
        // Every entry reachable by walking is a Settings entry.
        for _ in 0..8 {
            let Page::Menu(item) = ui.page() else {
                panic!("left the menu");
            };
            assert_eq!(item.level(), Level::Settings);
            ui.apply(UiInput::Forward);
        }
    }

    #[test]
    fn entering_a_submenu_highlights_the_entry_after_back() {
        let mut ui = full();
        walk_to(&mut ui, MenuItem::Settings);
        assert_eq!(ui.apply(UiInput::Select), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Bluetooth));
        assert_eq!(ui.level(), Level::Settings);

        // One Previous reaches the way out.
        ui.apply(UiInput::Backward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::SettingsBack));
    }

    #[test]
    fn back_returns_to_the_entry_that_opened_the_level() {
        let mut ui = full();
        walk_to(&mut ui, MenuItem::Settings);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::Gnss);
        ui.apply(UiInput::Select);
        assert_eq!(ui.page(), Page::Menu(MenuItem::GnssToggle));

        walk_to(&mut ui, MenuItem::GnssBack);
        assert_eq!(ui.apply(UiInput::Select), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Gnss));

        walk_to(&mut ui, MenuItem::SettingsBack);
        assert_eq!(ui.apply(UiInput::Select), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Settings));
        assert_eq!(ui.level(), Level::Top);
    }

    /// A board with a back button reaches the same places without ever
    /// walking to the Back entry.
    #[test]
    fn a_back_press_leaves_the_level_from_any_entry() {
        let mut ui = full();
        walk_to(&mut ui, MenuItem::Settings);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::Bluetooth);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::ClearBonds);

        assert_eq!(ui.apply(UiInput::Back), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Bluetooth));
        assert_eq!(ui.apply(UiInput::Back), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Settings));
        assert_eq!(ui.level(), Level::Top);
    }

    /// Back at the top level is still a press that does something.
    #[test]
    fn a_back_press_at_the_top_goes_home() {
        let mut ui = full();
        walk_to(&mut ui, MenuItem::Identity);
        assert_eq!(ui.apply(UiInput::Back), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        // And from home it is a no-op rather than a wrap into the tree.
        assert_eq!(ui.apply(UiInput::Back), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
    }

    #[test]
    fn a_back_press_answers_a_confirmation_with_no() {
        let mut ui = full();
        walk_to(&mut ui, MenuItem::Settings);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::Bluetooth);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::ClearBonds);
        ui.apply(UiInput::Select);
        // Even with the destructive choice under the cursor.
        ui.apply(UiInput::Forward);
        assert_eq!(
            ui.page(),
            Page::Confirm {
                item: MenuItem::ClearBonds,
                confirm_selected: true,
            }
        );
        assert_eq!(ui.apply(UiInput::Back), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::ClearBonds));
    }

    #[test]
    fn a_submenu_with_nothing_in_it_is_not_shown() {
        // A board with no GNSS and no bond storage: Bluetooth keeps its
        // pairing entry, GNSS has nothing at all.
        let items = MenuItems::new()
            .with(MenuItem::Settings)
            .with(MenuItem::Bluetooth)
            .with(MenuItem::StartPairing)
            .with(MenuItem::Gnss);
        assert!(items.level_is_empty(Level::Gnss));
        assert!(!items.level_is_empty(Level::Bluetooth));

        let mut ui = UiModel::new(items);
        walk_to(&mut ui, MenuItem::Settings);
        ui.apply(UiInput::Select);
        // Bluetooth is reachable, GNSS is skipped even though its own
        // entry was enabled.
        for _ in 0..6 {
            assert_ne!(ui.page(), Page::Menu(MenuItem::Gnss));
            ui.apply(UiInput::Forward);
        }
    }

    #[test]
    fn a_toggle_stays_on_its_entry() {
        let mut ui = full();
        walk_to(&mut ui, MenuItem::Settings);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::Radio);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::Forwarding);

        assert_eq!(
            ui.apply(UiInput::Select),
            Some(UiEffect::Toggle(ToggleId::Forwarding))
        );
        assert_eq!(ui.page(), Page::Menu(MenuItem::Forwarding));
    }

    #[test]
    fn navigation_skips_items_the_board_does_not_enable() {
        // A board with no bond storage to clear.
        let items = MenuItems::new()
            .with(MenuItem::Bluetooth)
            .with(MenuItem::BluetoothToggle)
            .with(MenuItem::StartPairing);
        let mut ui = UiModel::new(items);
        ui.page = Page::Menu(MenuItem::BluetoothToggle);
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::StartPairing));
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::BluetoothBack));
        ui.apply(UiInput::Backward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::StartPairing));
    }

    #[test]
    fn status_only_menu_stays_put() {
        let mut ui = UiModel::new(MenuItems::new());
        ui.apply(UiInput::Forward);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        assert_eq!(ui.apply(UiInput::Select), Some(UiEffect::CheckIn));
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
    }

    #[test]
    fn safe_items_activate_and_return_home() {
        let mut ui = full();
        walk_to(&mut ui, MenuItem::Settings);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::Bluetooth);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::StartPairing);
        assert_eq!(ui.apply(UiInput::Select), Some(UiEffect::StartPairing));
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        assert_eq!(ui.level(), Level::Top);
    }

    #[test]
    fn reading_entries_stay_put_and_only_home_acts() {
        let mut ui = full();
        // Home carries the device's frequent, non-destructive action.
        assert_eq!(ui.apply(UiInput::Select), Some(UiEffect::CheckIn));
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));

        walk_to(&mut ui, MenuItem::Identity);
        assert_eq!(ui.apply(UiInput::Select), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Identity));

        walk_to(&mut ui, MenuItem::Settings);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::Radio);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::Stats);
        assert_eq!(ui.apply(UiInput::Select), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Stats));
    }

    /// Walk to Clear bonds, which lives two levels down.
    fn at_clear_bonds() -> UiModel {
        let mut ui = full();
        walk_to(&mut ui, MenuItem::Settings);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::Bluetooth);
        ui.apply(UiInput::Select);
        walk_to(&mut ui, MenuItem::ClearBonds);
        ui
    }

    #[test]
    fn clear_defaults_to_cancel_and_requires_visible_confirmation() {
        let mut ui = at_clear_bonds();
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
        let mut ui = at_clear_bonds();
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
        walk_to(&mut ui, MenuItem::Settings);
        ui.set_notice(UiNotice::BondsCleared);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        assert_eq!(ui.notice(), Some(UiNotice::BondsCleared));

        ui.apply(UiInput::Forward);
        assert_eq!(ui.notice(), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Identity));
    }

    #[test]
    fn go_home_unwinds_from_the_deepest_level() {
        let mut ui = at_clear_bonds();
        ui.apply(UiInput::Select);
        assert!(!ui.is_home());

        ui.go_home();
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        assert_eq!(ui.notice(), None);
        assert_eq!(ui.level(), Level::Top);
        assert!(ui.is_home());
    }

    #[test]
    fn a_submenu_is_never_home() {
        let mut ui = full();
        walk_to(&mut ui, MenuItem::Settings);
        ui.apply(UiInput::Select);
        assert!(!ui.is_home());
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
    fn home_and_every_exit_are_always_enabled() {
        let bare = MenuItems::new();
        assert!(bare.contains(MenuItem::Status));
        for level in Level::ALL {
            if let Some(back) = level.back() {
                assert!(bare.contains(back), "{level:?} has no way out");
            }
        }
    }

    #[test]
    fn every_level_below_the_top_has_a_back_and_an_opener() {
        for level in Level::ALL {
            let has_back = MenuItem::ALL
                .iter()
                .any(|i| i.level() == level && i.is_back());
            assert_eq!(has_back, level != Level::Top, "{level:?}");
            assert_eq!(
                level.opened_by().is_some(),
                level != Level::Top,
                "{level:?}"
            );
            assert_eq!(level.back().is_some(), level != Level::Top, "{level:?}");
        }
    }

    #[test]
    fn a_levels_opener_and_back_agree_about_where_they_sit() {
        for level in Level::ALL {
            if let (Some(opener), Some(back)) = (level.opened_by(), level.back()) {
                // The opener lives in the parent; Back lives in the level
                // it leaves.
                assert_eq!(opener.kind(), EntryKind::Submenu(level));
                assert_eq!(back.level(), level);
            }
        }
    }

    #[test]
    fn every_item_is_listed_exactly_once() {
        for item in MenuItem::ALL {
            let count = MenuItem::ALL.iter().filter(|&&i| i == item).count();
            assert_eq!(count, 1, "{item:?}");
        }
        assert_eq!(MenuItems::all().len(), MenuItem::ALL.len() as u32);
    }

    #[test]
    fn each_levels_entries_are_contiguous() {
        // `step` walks the flat index, so a level whose entries are
        // interleaved with another's would wrap through the wrong list.
        for level in Level::ALL {
            let mut first = None;
            let mut offset = 0;
            for (position, item) in MenuItem::ALL.iter().enumerate() {
                if item.level() != level {
                    continue;
                }
                let start = *first.get_or_insert(position);
                assert_eq!(position, start + offset, "{level:?} is not contiguous");
                offset += 1;
            }
            assert!(first.is_some(), "{level:?} has no entries");
        }
    }
}
