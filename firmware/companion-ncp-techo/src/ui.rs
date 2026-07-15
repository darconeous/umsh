//! Pure T-Echo on-screen BLE menu policy.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiInput {
    Forward,
    Select,
    Backward,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuItem {
    Status,
    StartPairing,
    ClearBonds,
}

impl MenuItem {
    const fn forward(self) -> Self {
        match self {
            Self::Status => Self::StartPairing,
            Self::StartPairing => Self::ClearBonds,
            Self::ClearBonds => Self::Status,
        }
    }

    const fn backward(self) -> Self {
        match self {
            Self::Status => Self::ClearBonds,
            Self::StartPairing => Self::Status,
            Self::ClearBonds => Self::StartPairing,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Menu(MenuItem),
    ConfirmClear { clear_selected: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiEffect {
    StartPairing,
    ClearBonds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiNotice {
    PairingStarted,
    PairingUnavailable,
    BondsCleared,
    ClearFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiModel {
    page: Page,
    notice: Option<UiNotice>,
}

impl UiModel {
    pub const fn new() -> Self {
        Self {
            page: Page::Menu(MenuItem::Status),
            notice: None,
        }
    }

    pub const fn page(self) -> Page {
        self.page
    }

    pub const fn notice(self) -> Option<UiNotice> {
        self.notice
    }

    pub fn set_notice(&mut self, notice: UiNotice) {
        self.page = Page::Menu(MenuItem::Status);
        self.notice = Some(notice);
    }

    pub fn clear_notice(&mut self) {
        self.notice = None;
    }

    /// Apply one resolved button gesture.
    ///
    /// The destructive confirmation defaults to Cancel. Forward and backward
    /// both toggle the two choices, while Select activates the visible choice.
    pub fn apply(&mut self, input: UiInput) -> Option<UiEffect> {
        self.notice = None;
        match (self.page, input) {
            (Page::Menu(item), UiInput::Forward) => {
                self.page = Page::Menu(item.forward());
                None
            }
            (Page::Menu(item), UiInput::Backward) => {
                self.page = Page::Menu(item.backward());
                None
            }
            (Page::Menu(MenuItem::Status), UiInput::Select) => None,
            (Page::Menu(MenuItem::StartPairing), UiInput::Select) => {
                self.page = Page::Menu(MenuItem::Status);
                Some(UiEffect::StartPairing)
            }
            (Page::Menu(MenuItem::ClearBonds), UiInput::Select) => {
                self.page = Page::ConfirmClear {
                    clear_selected: false,
                };
                None
            }
            (Page::ConfirmClear { clear_selected }, UiInput::Forward | UiInput::Backward) => {
                self.page = Page::ConfirmClear {
                    clear_selected: !clear_selected,
                };
                None
            }
            (
                Page::ConfirmClear {
                    clear_selected: false,
                },
                UiInput::Select,
            ) => {
                self.page = Page::Menu(MenuItem::ClearBonds);
                None
            }
            (
                Page::ConfirmClear {
                    clear_selected: true,
                },
                UiInput::Select,
            ) => {
                self.page = Page::Menu(MenuItem::Status);
                Some(UiEffect::ClearBonds)
            }
        }
    }
}

impl Default for UiModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_and_backward_wrap_menu_items() {
        let mut ui = UiModel::new();
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
    fn pairing_is_an_explicit_selection() {
        let mut ui = UiModel::new();
        assert_eq!(ui.apply(UiInput::Select), None);
        ui.apply(UiInput::Forward);
        assert_eq!(ui.apply(UiInput::Select), Some(UiEffect::StartPairing));
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
    }

    #[test]
    fn notice_returns_to_status_and_clears_on_input() {
        let mut ui = UiModel::new();
        ui.apply(UiInput::Backward);
        ui.set_notice(UiNotice::BondsCleared);
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
        assert_eq!(ui.notice(), Some(UiNotice::BondsCleared));

        ui.apply(UiInput::Forward);
        assert_eq!(ui.notice(), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::StartPairing));
    }

    #[test]
    fn clear_defaults_to_cancel_and_requires_visible_confirmation() {
        let mut ui = UiModel::new();
        ui.apply(UiInput::Backward);
        assert_eq!(ui.apply(UiInput::Select), None);
        assert_eq!(
            ui.page(),
            Page::ConfirmClear {
                clear_selected: false
            }
        );

        // Selecting the default choice cancels without an effect.
        assert_eq!(ui.apply(UiInput::Select), None);
        assert_eq!(ui.page(), Page::Menu(MenuItem::ClearBonds));

        // Re-enter, visibly choose Clear, then confirm it.
        ui.apply(UiInput::Select);
        ui.apply(UiInput::Forward);
        assert_eq!(ui.apply(UiInput::Select), Some(UiEffect::ClearBonds));
        assert_eq!(ui.page(), Page::Menu(MenuItem::Status));
    }
}
