//! The character picker: what it offers, in the order the wheel walks it,
//! and what typing a name finds.
//!
//! It offers every emoji the board draws, by CLDR group, then the
//! characters the fonts draw beyond what the keys type: symbols, currency
//! signs, and accented letters. Recently picked characters come first.

use heapless::{String, Vec};
use umsh_emoji::{COUNT, GROUP_COUNT, GROUPS, Id, Match, find, matching, sequence, words};

/// Recently picked characters kept, newest first.
pub const RECENT: usize = 20;
/// The most a name finds.
pub const FOUND: usize = 120;
/// The longest name typed, in bytes.
pub const FILTER: usize = 16;
/// The most rows shown at once: the last is cut by the picker's edge.
pub const ROWS: usize = 3;
/// The most cells a row holds, on any board.
pub const COLUMNS: usize = 12;

/// Recent picks as the node keeps them: each one's text, newest first, a
/// line each.
pub type RecentText = String<{ RECENT * 32 }>;

/// Something the picker offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    Emoji(Id),
    /// One of [`CHARACTERS`].
    Character(u8),
}

impl Pick {
    /// What picking it types.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::Emoji(id) => sequence(id),
            Self::Character(i) => CHARACTERS.get(usize::from(i)).map_or("", |c| c.0),
        }
    }

    /// The pick that types `text`, if the picker offers one.
    #[must_use]
    pub fn of(text: &str) -> Option<Self> {
        if let Some(i) = CHARACTERS.iter().position(|c| c.0 == text) {
            return Some(Self::Character(i as u8));
        }
        let bare: String<64> = text.chars().filter(|&c| c != '\u{FE0F}').collect();
        umsh_emoji::find(&bare).map(Self::Emoji)
    }

    fn words(self) -> &'static str {
        match self {
            Self::Emoji(id) => words(id),
            Self::Character(i) => CHARACTERS.get(usize::from(i)).map_or("", |c| c.1),
        }
    }
}

/// A run of the picker, named by a tab while no name is typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Recent,
    /// One of [`GROUPS`].
    Group(u8),
    Symbols,
    Currency,
    Letters,
}

/// Every tab, in order.
pub static TABS: [Tab; GROUP_COUNT + 4] = {
    let mut tabs = [Tab::Recent; GROUP_COUNT + 4];
    let mut g = 0;
    while g < GROUP_COUNT {
        tabs[1 + g] = Tab::Group(g as u8);
        g += 1;
    }
    tabs[GROUP_COUNT + 1] = Tab::Symbols;
    tabs[GROUP_COUNT + 2] = Tab::Currency;
    tabs[GROUP_COUNT + 3] = Tab::Letters;
    tabs
};

impl Tab {
    /// Every tab but [`Tab::Recent`], in order.
    pub fn all() -> impl Iterator<Item = Self> {
        TABS[1..].iter().copied()
    }

    /// What the tab shows, but for [`Tab::Recent`], which is an icon.
    #[must_use]
    pub fn face(self) -> &'static str {
        match self {
            Self::Recent => "",
            Self::Group(g) => {
                let Some(group) = GROUPS.get(usize::from(g)) else {
                    return "";
                };
                // A group not named here shows its first emoji.
                find(group_face(group.name)).map_or(sequence(group.start), sequence)
            }
            Self::Symbols => "&",
            Self::Currency => "\u{20AC}",
            Self::Letters => "\u{E9}",
        }
    }

    /// How many it offers.
    fn len(self, recents: &[Pick]) -> u16 {
        match self {
            Self::Recent => recents.len() as u16,
            Self::Group(g) => GROUPS.get(usize::from(g)).map_or(0, |g| g.end - g.start),
            Self::Symbols => SYMBOLS as u16,
            Self::Currency => CURRENCY as u16,
            Self::Letters => LETTERS as u16,
        }
    }
}

/// The emoji a group's tab shows, written without U+FE0F.
fn group_face(group: &str) -> &'static str {
    match group {
        "Smileys & Emotion" => "\u{1F600}",
        "People & Body" => "\u{1F44B}",
        "Animals & Nature" => "\u{1F436}",
        "Food & Drink" => "\u{1F354}",
        "Travel & Places" => "\u{1F697}",
        "Activities" => "\u{26BD}",
        "Objects" => "\u{1F4A1}",
        "Symbols" => "\u{267B}",
        "Flags" => "\u{1F3C1}",
        _ => "",
    }
}

/// Characters the fonts draw beyond what the keys type, each with the
/// words it is found by: its Unicode name, shortened, and after a `|` any
/// aliases. Symbols, then currency signs, then letters.
pub static CHARACTERS: [(&str, &str); SYMBOLS + CURRENCY + LETTERS] = [
    // Symbols.
    ("#", "number sign|hash"),
    ("&", "ampersand|and"),
    ("%", "percent sign"),
    ("~", "tilde"),
    ("(", "left parenthesis|paren"),
    (")", "right parenthesis|paren"),
    ("[", "left square bracket"),
    ("]", "right square bracket"),
    ("{", "left curly bracket|brace"),
    ("}", "right curly bracket|brace"),
    ("<", "less-than sign"),
    (">", "greater-than sign"),
    ("|", "vertical line|pipe bar"),
    ("\\", "reverse solidus|backslash"),
    ("^", "circumflex accent|caret"),
    ("`", "grave accent|backtick"),
    ("–", "en dash|dash"),
    ("—", "em dash|dash"),
    ("―", "horizontal bar|dash"),
    ("‘", "left single quotation mark|quote apostrophe"),
    ("’", "right single quotation mark|quote apostrophe"),
    ("‚", "single low-9 quotation mark|quote"),
    ("“", "left double quotation mark|quote"),
    ("”", "right double quotation mark|quote"),
    ("„", "double low-9 quotation mark|quote"),
    (
        "«",
        "left-pointing double angle quotation mark|guillemet quote",
    ),
    (
        "»",
        "right-pointing double angle quotation mark|guillemet quote",
    ),
    (
        "‹",
        "single left-pointing angle quotation mark|guillemet quote",
    ),
    (
        "›",
        "single right-pointing angle quotation mark|guillemet quote",
    ),
    ("…", "horizontal ellipsis|dots"),
    ("•", "bullet|dot"),
    ("·", "middle dot|dot"),
    ("¡", "inverted exclamation mark"),
    ("¿", "inverted question mark"),
    ("§", "section sign"),
    ("¶", "pilcrow sign|paragraph"),
    ("†", "dagger"),
    ("‡", "double dagger"),
    ("©", "copyright sign"),
    ("®", "registered sign"),
    ("™", "trade mark sign|tm"),
    ("°", "degree sign|degrees"),
    ("±", "plus-minus sign"),
    ("×", "multiplication sign|times multiply"),
    ("÷", "division sign|divide"),
    ("−", "minus sign|subtract"),
    ("¬", "not sign"),
    ("‰", "per mille sign"),
    ("µ", "micro sign|mu"),
    ("¹", "superscript one"),
    ("²", "superscript two"),
    ("³", "superscript three"),
    ("¼", "vulgar fraction one quarter"),
    ("½", "vulgar fraction one half"),
    ("¾", "vulgar fraction three quarters"),
    ("ª", "feminine ordinal indicator"),
    ("º", "masculine ordinal indicator"),
    ("¦", "broken bar"),
    // Currency.
    ("$", "dollar sign"),
    ("¢", "cent sign"),
    ("£", "pound sign"),
    ("¥", "yen sign"),
    ("€", "euro sign"),
    // Letters.
    ("à", "a grave"),
    ("á", "a acute"),
    ("â", "a circumflex"),
    ("ã", "a tilde"),
    ("ä", "a diaeresis|umlaut"),
    ("å", "a ring above"),
    ("æ", "ae"),
    ("ā", "a macron"),
    ("ă", "a breve"),
    ("ą", "a ogonek"),
    ("À", "a grave"),
    ("Á", "a acute"),
    ("Â", "a circumflex"),
    ("Ã", "a tilde"),
    ("Ä", "a diaeresis|umlaut"),
    ("Å", "a ring above"),
    ("Æ", "ae"),
    ("Ā", "a macron"),
    ("Ă", "a breve"),
    ("Ą", "a ogonek"),
    ("ç", "c cedilla"),
    ("ć", "c acute"),
    ("ĉ", "c circumflex"),
    ("ċ", "c dot above"),
    ("č", "c caron"),
    ("Ç", "c cedilla"),
    ("Ć", "c acute"),
    ("Ĉ", "c circumflex"),
    ("Ċ", "c dot above"),
    ("Č", "c caron"),
    ("ð", "eth"),
    ("ď", "d caron"),
    ("đ", "d stroke"),
    ("Ð", "eth"),
    ("Ď", "d caron"),
    ("Đ", "d stroke"),
    ("è", "e grave"),
    ("é", "e acute"),
    ("ê", "e circumflex"),
    ("ë", "e diaeresis|umlaut"),
    ("ē", "e macron"),
    ("ĕ", "e breve"),
    ("ė", "e dot above"),
    ("ę", "e ogonek"),
    ("ě", "e caron"),
    ("È", "e grave"),
    ("É", "e acute"),
    ("Ê", "e circumflex"),
    ("Ë", "e diaeresis|umlaut"),
    ("Ē", "e macron"),
    ("Ĕ", "e breve"),
    ("Ė", "e dot above"),
    ("Ę", "e ogonek"),
    ("Ě", "e caron"),
    ("ĝ", "g circumflex"),
    ("ğ", "g breve"),
    ("ġ", "g dot above"),
    ("ģ", "g cedilla"),
    ("Ĝ", "g circumflex"),
    ("Ğ", "g breve"),
    ("Ġ", "g dot above"),
    ("Ģ", "g cedilla"),
    ("ĥ", "h circumflex"),
    ("ħ", "h stroke"),
    ("Ĥ", "h circumflex"),
    ("Ħ", "h stroke"),
    ("ì", "i grave"),
    ("í", "i acute"),
    ("î", "i circumflex"),
    ("ï", "i diaeresis|umlaut"),
    ("ĩ", "i tilde"),
    ("ī", "i macron"),
    ("ĭ", "i breve"),
    ("į", "i ogonek"),
    ("ı", "dotless i"),
    ("ĳ", "ij"),
    ("Ì", "i grave"),
    ("Í", "i acute"),
    ("Î", "i circumflex"),
    ("Ï", "i diaeresis|umlaut"),
    ("Ĩ", "i tilde"),
    ("Ī", "i macron"),
    ("Ĭ", "i breve"),
    ("Į", "i ogonek"),
    ("İ", "i dot above"),
    ("Ĳ", "ij"),
    ("ĵ", "j circumflex"),
    ("Ĵ", "j circumflex"),
    ("ķ", "k cedilla"),
    ("ĸ", "kra"),
    ("Ķ", "k cedilla"),
    ("ĺ", "l acute"),
    ("ļ", "l cedilla"),
    ("ľ", "l caron"),
    ("ŀ", "l middle dot"),
    ("ł", "l stroke"),
    ("Ĺ", "l acute"),
    ("Ļ", "l cedilla"),
    ("Ľ", "l caron"),
    ("Ŀ", "l middle dot"),
    ("Ł", "l stroke"),
    ("ñ", "n tilde"),
    ("ń", "n acute"),
    ("ņ", "n cedilla"),
    ("ň", "n caron"),
    ("ŋ", "eng"),
    ("Ñ", "n tilde"),
    ("Ń", "n acute"),
    ("Ņ", "n cedilla"),
    ("Ň", "n caron"),
    ("Ŋ", "eng"),
    ("ò", "o grave"),
    ("ó", "o acute"),
    ("ô", "o circumflex"),
    ("õ", "o tilde"),
    ("ö", "o diaeresis|umlaut"),
    ("ø", "o stroke"),
    ("ō", "o macron"),
    ("ŏ", "o breve"),
    ("ő", "o double acute"),
    ("œ", "oe"),
    ("Ò", "o grave"),
    ("Ó", "o acute"),
    ("Ô", "o circumflex"),
    ("Õ", "o tilde"),
    ("Ö", "o diaeresis|umlaut"),
    ("Ø", "o stroke"),
    ("Ō", "o macron"),
    ("Ŏ", "o breve"),
    ("Ő", "o double acute"),
    ("Œ", "oe"),
    ("ŕ", "r acute"),
    ("ŗ", "r cedilla"),
    ("ř", "r caron"),
    ("Ŕ", "r acute"),
    ("Ŗ", "r cedilla"),
    ("Ř", "r caron"),
    ("ß", "sharp s|eszett"),
    ("ś", "s acute"),
    ("ŝ", "s circumflex"),
    ("ş", "s cedilla"),
    ("š", "s caron"),
    ("Ś", "s acute"),
    ("Ŝ", "s circumflex"),
    ("Ş", "s cedilla"),
    ("Š", "s caron"),
    ("þ", "thorn"),
    ("ţ", "t cedilla"),
    ("ť", "t caron"),
    ("ŧ", "t stroke"),
    ("Þ", "thorn"),
    ("Ţ", "t cedilla"),
    ("Ť", "t caron"),
    ("Ŧ", "t stroke"),
    ("ù", "u grave"),
    ("ú", "u acute"),
    ("û", "u circumflex"),
    ("ü", "u diaeresis|umlaut"),
    ("ũ", "u tilde"),
    ("ū", "u macron"),
    ("ŭ", "u breve"),
    ("ů", "u ring above"),
    ("ű", "u double acute"),
    ("ų", "u ogonek"),
    ("Ù", "u grave"),
    ("Ú", "u acute"),
    ("Û", "u circumflex"),
    ("Ü", "u diaeresis|umlaut"),
    ("Ũ", "u tilde"),
    ("Ū", "u macron"),
    ("Ŭ", "u breve"),
    ("Ů", "u ring above"),
    ("Ű", "u double acute"),
    ("Ų", "u ogonek"),
    ("ŵ", "w circumflex"),
    ("Ŵ", "w circumflex"),
    ("ý", "y acute"),
    ("ÿ", "y diaeresis|umlaut"),
    ("ŷ", "y circumflex"),
    ("Ý", "y acute"),
    ("Ŷ", "y circumflex"),
    ("Ÿ", "y diaeresis|umlaut"),
    ("ź", "z acute"),
    ("ż", "z dot above"),
    ("ž", "z caron"),
    ("Ź", "z acute"),
    ("Ż", "z dot above"),
    ("Ž", "z caron"),
];
const SYMBOLS: usize = 58;
const CURRENCY: usize = 5;
const LETTERS: usize = 188;

/// The characters last picked, newest first, and when they are next kept.
#[derive(Debug, Default)]
pub struct Recents {
    picks: Vec<Pick, RECENT>,
    /// Read from the node yet.
    loaded: bool,
    /// When to hand them to the node, if they changed since.
    pub(crate) save_at: Option<u64>,
}

impl Recents {
    #[must_use]
    pub fn picks(&self) -> &[Pick] {
        &self.picks
    }

    /// Takes in what the node kept, once.
    pub(crate) fn load(&mut self, kept: impl FnOnce() -> RecentText) {
        if core::mem::replace(&mut self.loaded, true) {
            return;
        }
        for pick in kept().lines().filter_map(Pick::of) {
            if !self.picks.contains(&pick) {
                _ = self.picks.push(pick);
            }
        }
    }

    /// `pick` was picked at `now`: it comes first, and is kept a little
    /// later, so picks in a row are kept at once.
    pub(crate) fn picked(&mut self, pick: Pick, now: u64) {
        self.picks.retain(|&p| p != pick);
        if self.picks.is_full() {
            self.picks.pop();
        }
        _ = self.picks.insert(0, pick);
        self.save_at = Some(now + SAVE_MS);
    }

    /// The picks as the node keeps them.
    #[must_use]
    pub fn text(&self) -> RecentText {
        let mut text = RecentText::new();
        for pick in &self.picks {
            if text.len() + pick.text().len() + 1 > text.capacity() {
                break;
            }
            _ = text.push_str(pick.text());
            _ = text.push('\n');
        }
        text
    }
}

/// How long after a pick the recents are kept, in milliseconds.
const SAVE_MS: u64 = 5000;

/// The picker, open.
#[derive(Debug, Default)]
pub struct Picker {
    /// The focused pick, counted through everything offered, in order.
    at: u16,
    /// The first row shown.
    top: u16,
    /// The name typed, if any.
    filter: String<FILTER>,
    /// What the name finds, best first.
    found: Vec<Pick, FOUND>,
}

/// What the picker shows: its tab or name, and the rows in view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shown {
    /// The tab the focused pick is under, while no name is typed.
    pub tab: Option<Tab>,
    pub filter: String<FILTER>,
    pub rows: Vec<Vec<Pick, COLUMNS>, ROWS>,
    /// The focused pick: its row in view, and its cell.
    pub focus: Option<(usize, usize)>,
}

impl Picker {
    #[must_use]
    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// The runs offered, in order, each with how many it has: one without a
    /// tab while a name is typed.
    fn runs<'a>(&'a self, recents: &'a [Pick]) -> impl Iterator<Item = (Option<Tab>, u16)> + 'a {
        let filtered = !self.filter.is_empty();
        let found = filtered.then_some((None, self.found.len() as u16));
        let tabs = (!filtered).then(|| {
            core::iter::once(Tab::Recent)
                .chain(Tab::all())
                .map(|tab| (Some(tab), tab.len(recents)))
                .filter(|&(_, len)| len > 0)
        });
        found.into_iter().chain(tabs.into_iter().flatten())
    }

    fn total(&self, recents: &[Pick]) -> u16 {
        self.runs(recents).map(|(_, len)| len).sum()
    }

    /// The pick at `index`.
    fn pick(&self, recents: &[Pick], index: u16) -> Option<Pick> {
        if !self.filter.is_empty() {
            return self.found.get(usize::from(index)).copied();
        }
        let mut i = usize::from(index);
        if let Some(&pick) = recents.get(i) {
            return Some(pick);
        }
        i -= recents.len();
        if i < usize::from(COUNT) {
            return Some(Pick::Emoji(i as Id));
        }
        i -= usize::from(COUNT);
        (i < CHARACTERS.len()).then_some(Pick::Character(i as u8))
    }

    /// The rows, each its first pick's index, its length, and its run's
    /// tab. Every run starts a row.
    fn rows<'a>(
        &'a self,
        recents: &'a [Pick],
        columns: u16,
    ) -> impl Iterator<Item = (u16, u16, Option<Tab>)> + 'a {
        let columns = columns.max(1);
        let mut start = 0;
        self.runs(recents).flat_map(move |(tab, len)| {
            let first = start;
            start += len;
            (0..len.div_ceil(columns)).map(move |r| {
                let at = first + r * columns;
                (at, columns.min(first + len - at), tab)
            })
        })
    }

    /// The row and cell of `index`.
    fn locate(&self, recents: &[Pick], columns: u16, index: u16) -> (u16, u16) {
        self.rows(recents, columns)
            .enumerate()
            .find(|(_, (start, len, _))| (*start..start + len).contains(&index))
            .map_or((0, 0), |(row, (start, _, _))| (row as u16, index - start))
    }

    /// Turns the focus `steps` picks on, or back.
    pub fn turn(&mut self, recents: &[Pick], columns: u16, steps: i16) {
        let last = self.total(recents).saturating_sub(1);
        self.at = (i32::from(self.at) + i32::from(steps)).clamp(0, i32::from(last)) as u16;
        self.scroll(recents, columns);
    }

    /// Moves the focus `rows` rows down, or up, to the same cell or the
    /// last of a shorter row.
    pub fn rows_down(&mut self, recents: &[Pick], columns: u16, rows: i16) {
        let (row, cell) = self.locate(recents, columns, self.at);
        let Ok(to) = u16::try_from(i32::from(row) + i32::from(rows)) else {
            return;
        };
        let row = self.rows(recents, columns).nth(usize::from(to));
        if let Some((start, len, _)) = row {
            self.at = start + cell.min(len - 1);
            self.scroll(recents, columns);
        }
    }

    /// Keeps the focused row in view, with the row before it where it can.
    fn scroll(&mut self, recents: &[Pick], columns: u16) {
        let (row, _) = self.locate(recents, columns, self.at);
        if row < self.top {
            self.top = row;
        } else if row > self.top + 1 {
            self.top = row - 1;
        }
    }

    /// The focused pick.
    #[must_use]
    pub fn focused(&self, recents: &[Pick]) -> Option<Pick> {
        self.pick(recents, self.at)
    }

    /// Adds `c` to the name typed, if there is room.
    pub fn type_letter(&mut self, c: char) {
        if c.is_control() || (c.is_whitespace() && self.filter.is_empty()) {
            return;
        }
        if self.filter.push(c).is_ok() {
            self.find();
        }
    }

    /// Takes the last letter off the name typed. Returns `false` when there
    /// was none.
    pub fn erase_letter(&mut self) -> bool {
        if self.filter.pop().is_none() {
            return false;
        }
        self.find();
        true
    }

    /// What the name finds, best first, starting over at the first.
    fn find(&mut self) {
        self.found.clear();
        self.at = 0;
        self.top = 0;
        if self.filter.trim().is_empty() {
            return;
        }
        let emoji = (0..COUNT).map(Pick::Emoji);
        let characters = (0..CHARACTERS.len() as u8).map(Pick::Character);
        for rank in [Match::Head, Match::Word] {
            for pick in emoji.clone().chain(characters.clone()) {
                if matching(pick.words(), &self.filter) == Some(rank)
                    && self.found.push(pick).is_err()
                {
                    return;
                }
            }
        }
    }

    /// What is in view, `columns` cells to a row.
    #[must_use]
    pub fn shown(&self, recents: &[Pick], columns: u16) -> Shown {
        let mut shown = Shown {
            tab: None,
            filter: self.filter.clone(),
            rows: Vec::new(),
            focus: None,
        };
        let columns = columns.clamp(1, COLUMNS as u16);
        for (i, (start, len, tab)) in self
            .rows(recents, columns)
            .skip(usize::from(self.top))
            .take(ROWS)
            .enumerate()
        {
            let row: Vec<Pick, COLUMNS> = (start..start + len)
                .filter_map(|index| self.pick(recents, index))
                .collect();
            if (start..start + len).contains(&self.at) {
                shown.focus = Some((i, usize::from(self.at - start)));
            }
            _ = shown.rows.push(row);
            _ = tab;
        }
        shown.tab = self
            .rows(recents, columns)
            .find(|(start, len, _)| (*start..start + len).contains(&self.at))
            .and_then(|(_, _, tab)| tab);
        shown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recents() -> Vec<Pick, RECENT> {
        let mut v = Vec::new();
        _ = v.push(Pick::of("\u{1F44D}").unwrap());
        _ = v.push(Pick::of("\u{20AC}").unwrap());
        v
    }

    #[test]
    fn every_group_has_a_face_the_board_draws() {
        for tab in Tab::all() {
            assert!(!tab.face().is_empty(), "{tab:?}");
            if let Tab::Group(g) = tab {
                // Its own face, not the first emoji in its stead.
                let face = group_face(GROUPS[usize::from(g)].name);
                assert!(find(face).is_some(), "{tab:?}");
            }
        }
    }

    #[test]
    fn a_pick_types_what_it_was_kept_as() {
        let heart = Pick::of("\u{2764}\u{FE0F}").unwrap();
        assert_eq!(Pick::of("\u{2764}"), Some(heart));
        assert_eq!(heart.text(), "\u{2764}\u{FE0F}");
        assert_eq!(Pick::of("\u{E9}").unwrap().text(), "\u{E9}");
        assert_eq!(Pick::of("x"), None);
    }

    #[test]
    fn the_character_runs_are_what_they_say() {
        assert_eq!(CHARACTERS[0].0, "#");
        assert_eq!(CHARACTERS[SYMBOLS].0, "$");
        assert_eq!(CHARACTERS[SYMBOLS + CURRENCY].0, "\u{E0}");
    }

    #[test]
    fn recents_come_first_then_every_group_each_on_its_own_rows() {
        let recents = recents();
        let mut picker = Picker::default();
        let shown = picker.shown(&recents, 10);
        assert_eq!(shown.tab, Some(Tab::Recent));
        assert_eq!(shown.rows[0].len(), 2);
        assert_eq!(shown.rows[1][0], Pick::Emoji(0));
        assert_eq!(shown.focus, Some((0, 0)));
        // Past the recents, into the first group.
        picker.turn(&recents, 10, 2);
        let shown = picker.shown(&recents, 10);
        assert_eq!(shown.tab, Some(Tab::Group(0)));
        assert_eq!(shown.focus, Some((1, 0)));
        // Down a row keeps the cell; the row before stays in view.
        picker.turn(&recents, 10, 3);
        picker.rows_down(&recents, 10, 1);
        let shown = picker.shown(&recents, 10);
        assert_eq!(picker.focused(&recents), Some(Pick::Emoji(13)));
        assert_eq!(shown.focus, Some((1, 3)));
        // Up from a short row's end to a longer row.
        picker.rows_down(&recents, 10, -2);
        assert_eq!(picker.focused(&recents), Some(recents[1]));
        // The last of all is the last letter.
        picker.turn(&recents, 10, i16::MAX);
        assert_eq!(
            picker.focused(&recents),
            Some(Pick::Character(CHARACTERS.len() as u8 - 1))
        );
        assert_eq!(picker.shown(&recents, 10).tab, Some(Tab::Letters));
    }

    #[test]
    fn a_name_finds_what_it_names_first() {
        let mut picker = Picker::default();
        for c in "hea".chars() {
            picker.type_letter(c);
        }
        let shown = picker.shown(&[], 10);
        assert_eq!(shown.tab, None);
        assert_eq!(shown.filter, "hea");
        let heart = Pick::of("\u{2764}").unwrap();
        let eyes = Pick::of("\u{1F60D}").unwrap();
        let first = shown.rows.iter().flatten().position(|&p| p == heart);
        let found: Vec<Pick, FOUND> = picker.found.clone();
        assert!(first.is_some());
        assert!(found.iter().position(|&p| p == heart) < found.iter().position(|&p| p == eyes));
        assert!(picker.erase_letter());
        assert!(picker.erase_letter());
        assert!(picker.erase_letter());
        assert!(!picker.erase_letter());
        assert_eq!(picker.shown(&[], 10).tab, Some(Tab::Group(0)));
    }

    #[test]
    fn recents_move_to_the_front_and_are_kept_later() {
        let mut recents = Recents::default();
        recents.load(|| RecentText::try_from("\u{1F44D}\nnot offered\n\u{20AC}\n").unwrap());
        recents.load(|| unreachable!());
        assert_eq!(recents.picks().len(), 2);
        let euro = Pick::of("\u{20AC}").unwrap();
        recents.picked(euro, 100);
        assert_eq!(recents.picks()[0], euro);
        assert_eq!(recents.picks().len(), 2);
        assert_eq!(recents.save_at, Some(100 + SAVE_MS));
        assert_eq!(recents.text(), "\u{20AC}\n\u{1F44D}\n");
    }
}
