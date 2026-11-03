//! The character picker: what it offers, in the order the wheel walks it,
//! where it is scrolled to, and what typing a name finds.
//!
//! It offers every symbol a keyboard types and those the fonts draw
//! beyond them, then every emoji the board draws, by CLDR group, then
//! accented letters. Recently picked characters come first.
//!
//! Focus is on a cell of the grid, or on the row of tabs above it, where
//! turning moves from tab to tab: the way to jump far, on a board with no
//! touchscreen.

use heapless::{String, Vec};

use crate::model::MessageId;
use umsh_emoji::{COUNT, GROUP_COUNT, GROUPS, Id, Match, find, matching, name, sequence, words};

/// Recently picked characters kept, newest first.
pub const RECENT: usize = 20;
/// The most a name finds.
pub const FOUND: usize = 120;
/// The longest name typed, in bytes.
pub const FILTER: usize = 16;
/// The most rows in view at once, counting those cut at either edge.
pub const ROWS: usize = 5;
/// The most cells a row holds, on any board.
pub const COLUMNS: usize = 10;

/// The picker's grid as a board lays it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Cells to a row.
    pub columns: u16,
    /// A row's height, in pixels.
    pub row: u16,
    /// The height of the rows in view, in pixels.
    pub height: u16,
}

impl Geometry {
    /// How many rows the view shows whole.
    fn whole(self) -> u16 {
        (self.height / self.row.max(1)).max(1)
    }
}

/// Where on the screen a touch landed, as the picker sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spot {
    /// Off the picker.
    Outside,
    /// On the picker, but on nothing in it.
    Card,
    /// On the tab at this place in [`Shown::tabs`].
    Tab(u8),
    /// In the grid: this cell across, this far below the top of the rows
    /// in view.
    Grid { column: u16, y: u16 },
}

/// Recent picks as the node keeps them: each one's text, newest first, a
/// line each.
pub type RecentText = String<{ RECENT * 32 }>;

/// Something the picker offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    Emoji(Id),
    /// One of [`CHARACTERS`].
    Character(u16),
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
            return Some(Self::Character(i as u16));
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

    /// What it is called: an emoji's name as a title shows it, and a
    /// character's Unicode name, shortened, in lowercase.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Emoji(id) => name(id),
            Self::Character(_) => {
                let words = self.words();
                words.split_once('|').map_or(words, |(name, _)| name)
            }
        }
    }
}

/// A run of the picker, named by a tab while no name is typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Recent,
    Symbols,
    /// One of [`GROUPS`].
    Group(u8),
    Letters,
}

/// Every tab, in order.
pub static TABS: [Tab; GROUP_COUNT + 3] = {
    let mut tabs = [Tab::Recent; GROUP_COUNT + 3];
    tabs[1] = Tab::Symbols;
    let mut g = 0;
    while g < GROUP_COUNT {
        tabs[2 + g] = Tab::Group(g as u8);
        g += 1;
    }
    tabs[GROUP_COUNT + 2] = Tab::Letters;
    tabs
};

/// The tabs while reacting, which offers only emoji.
static REACTING: [Tab; GROUP_COUNT + 1] = {
    let mut tabs = [Tab::Recent; GROUP_COUNT + 1];
    let mut g = 0;
    while g < GROUP_COUNT {
        tabs[1 + g] = Tab::Group(g as u8);
        g += 1;
    }
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
            Self::Symbols => "&%",
            Self::Letters => "\u{E9}",
        }
    }

    /// How many it offers, but for [`Tab::Recent`].
    fn len(self) -> u16 {
        match self {
            Self::Recent => 0,
            Self::Group(g) => GROUPS.get(usize::from(g)).map_or(0, |g| g.end - g.start),
            Self::Symbols => SYMBOLS as u16,
            Self::Letters => LETTERS as u16,
        }
    }

    /// Its `i`th pick, but for [`Tab::Recent`].
    fn pick(self, i: u16) -> Option<Pick> {
        if i >= self.len() {
            return None;
        }
        match self {
            Self::Recent => None,
            Self::Group(g) => GROUPS.get(usize::from(g)).map(|g| Pick::Emoji(g.start + i)),
            Self::Symbols => Some(Pick::Character(i)),
            Self::Letters => Some(Pick::Character(SYMBOLS as u16 + i)),
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

/// The characters offered besides emoji, each with the words it is found
/// by: its Unicode name, shortened, and after a `|` any aliases. Symbols,
/// then letters.
///
/// The symbols start with every one a US keyboard types, as its keys
/// have them, so that whatever a board's keys lack is near at hand.
pub static CHARACTERS: [(&str, &str); SYMBOLS + LETTERS] = [
    // Symbols, a keyboard's first.
    ("!", "exclamation mark|bang"),
    ("@", "commercial at|at"),
    ("#", "number sign|hash hashtag pound"),
    ("$", "dollar sign"),
    ("%", "percent sign"),
    ("^", "circumflex accent|caret"),
    ("&", "ampersand|and"),
    ("*", "asterisk|star"),
    ("(", "left parenthesis|paren"),
    (")", "right parenthesis|paren"),
    ("-", "hyphen-minus|dash"),
    ("_", "low line|underscore"),
    ("=", "equals sign"),
    ("+", "plus sign"),
    ("[", "left square bracket"),
    ("]", "right square bracket"),
    ("{", "left curly bracket|brace"),
    ("}", "right curly bracket|brace"),
    ("\\", "reverse solidus|backslash"),
    ("|", "vertical line|pipe bar"),
    (";", "semicolon"),
    (":", "colon"),
    ("'", "apostrophe|quote"),
    ("\"", "quotation mark|quote"),
    (",", "comma"),
    (".", "full stop|period dot"),
    ("<", "less-than sign"),
    (">", "greater-than sign"),
    ("/", "solidus|slash"),
    ("?", "question mark"),
    ("`", "grave accent|backtick"),
    ("~", "tilde"),
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
const SYMBOLS: usize = 78;
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
    /// The message a pick reacts to, rather than being typed. It offers
    /// only emoji.
    reacting: Option<MessageId>,
    /// The focused pick, counted through everything offered, in order.
    /// While focus is on the tabs, its tab is the one focused.
    at: u16,
    /// Focus is on the tabs.
    on_tabs: bool,
    /// How far the rows are scrolled, in pixels.
    scroll: u16,
    /// The name typed, if any.
    filter: String<FILTER>,
    /// What the name finds, best first.
    found: Vec<Pick, FOUND>,
    /// The finger on the picker, if there is one.
    grab: Option<Grab>,
    /// The rows coasting on after a flick.
    glide: Option<Glide>,
}

/// A finger on the picker: where it came down, and where the rows were
/// scrolled then.
#[derive(Clone, Copy, Debug)]
struct Grab {
    spot: Spot,
    y: i16,
    scroll: u16,
    /// Where focus was before the finger took it, for a scroll to put it
    /// back: the focused pick, and whether focus was on the tabs.
    was: (u16, bool),
    /// It has moved far enough to scroll, or caught the rows coasting, so
    /// lifting it picks nothing.
    moved: bool,
    /// Where it was last, and a little before, with when: how fast it was
    /// going as it lifted.
    last: (i16, u64),
    before: (i16, u64),
}

/// How far a finger moves before it scrolls rather than taps.
const SLOP: i16 = 6;

/// The rows coasting on: where they are, in sixteenths of a pixel, how
/// fast they go, in pixels a second, and when they were moved last.
#[derive(Clone, Copy, Debug)]
struct Glide {
    at: i32,
    speed: i32,
    when: u64,
}

/// A flick slower than this, in pixels a second, stops where it lifts.
const FLICK: i32 = 300;
/// How long a glide's speed takes to fall by about two thirds, in
/// milliseconds.
const COAST_MS: i32 = 325;
/// A glide slower than this, in pixels a second, has stopped.
const STOPPED: i32 = 30;
/// How often a glide moves the rows, in milliseconds.
const GLIDE_FRAME_MS: u64 = 16;
/// How long a finger's speed is measured over, in milliseconds.
const SPEED_MS: u64 = 60;

/// What choosing the focused pick did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chosen {
    /// This is to be typed, or reacted with.
    Pick(Pick),
    /// Focus went from the tabs down into the grid.
    Entered,
    /// Nothing was found to choose.
    Nothing,
}

/// What the picker shows: its tabs or the name typed, and the rows in
/// view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shown {
    /// The tabs offered.
    pub tabs: &'static [Tab],
    /// The tab the focused pick is under, while no name is typed.
    pub tab: Option<Tab>,
    /// Focus is on that tab, rather than on a pick.
    pub on_tabs: bool,
    pub filter: String<FILTER>,
    /// The focused pick's name, while a name is typed.
    pub name: &'static str,
    /// The rows in view, the first `offset` pixels above the top.
    pub rows: Vec<Vec<Pick, COLUMNS>, ROWS>,
    pub offset: u16,
    /// The focused pick: its row in view, and its cell.
    pub focus: Option<(usize, usize)>,
}

impl Picker {
    /// The picker, to react to `message`.
    #[must_use]
    pub fn to_react(message: MessageId) -> Self {
        Self {
            reacting: Some(message),
            ..Self::default()
        }
    }

    /// The message a pick reacts to, if it is not to be typed.
    #[must_use]
    pub fn reacting(&self) -> Option<MessageId> {
        self.reacting
    }

    #[must_use]
    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// Whether focus is on the tabs.
    #[must_use]
    pub fn on_tabs(&self) -> bool {
        self.on_tabs
    }

    /// Whether `pick` is offered at all.
    fn offers(&self, pick: Pick) -> bool {
        self.reacting.is_none() || matches!(pick, Pick::Emoji(_))
    }

    /// The recent picks offered.
    fn recents<'a>(&'a self, recents: &'a [Pick]) -> impl Iterator<Item = Pick> + 'a {
        recents.iter().copied().filter(|&p| self.offers(p))
    }

    /// The tabs offered, [`Tab::Recent`] first where there are recent
    /// picks.
    #[must_use]
    pub fn tabs(&self, recents: &[Pick]) -> &'static [Tab] {
        let all: &'static [Tab] = if self.reacting.is_some() {
            &REACTING
        } else {
            &TABS
        };
        let recent = self.recents(recents).next().is_some();
        &all[usize::from(!recent)..]
    }

    /// The runs offered, in order, each with how many it has: one without a
    /// tab while a name is typed.
    fn runs<'a>(&'a self, recents: &'a [Pick]) -> impl Iterator<Item = (Option<Tab>, u16)> + 'a {
        let filtered = !self.filter.is_empty();
        let found = filtered.then_some((None, self.found.len() as u16));
        let tabs = (!filtered).then(|| {
            self.tabs(recents).iter().map(move |&tab| {
                let len = match tab {
                    Tab::Recent => self.recents(recents).count() as u16,
                    tab => tab.len(),
                };
                (Some(tab), len)
            })
        });
        found.into_iter().chain(tabs.into_iter().flatten())
    }

    fn total(&self, recents: &[Pick]) -> u16 {
        self.runs(recents).map(|(_, len)| len).sum()
    }

    /// The pick at `index`.
    fn pick(&self, recents: &[Pick], index: u16) -> Option<Pick> {
        let mut i = index;
        for (tab, len) in self.runs(recents) {
            if i < len {
                return match tab {
                    None => self.found.get(usize::from(i)).copied(),
                    Some(Tab::Recent) => self.recents(recents).nth(usize::from(i)),
                    Some(tab) => tab.pick(i),
                };
            }
            i -= len;
        }
        None
    }

    /// Where `tab`'s run starts.
    fn start_of(&self, recents: &[Pick], tab: Tab) -> Option<u16> {
        let mut start = 0;
        for (t, len) in self.runs(recents) {
            if t == Some(tab) {
                return Some(start);
            }
            start += len;
        }
        None
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

    /// The row and cell of `index`, and its run's tab.
    fn locate(&self, recents: &[Pick], columns: u16, index: u16) -> (u16, u16, Option<Tab>) {
        self.rows(recents, columns)
            .enumerate()
            .find(|(_, (start, len, _))| (*start..start + len).contains(&index))
            .map_or((0, 0, None), |(row, (start, _, tab))| {
                (row as u16, index - start, tab)
            })
    }

    /// The farthest the rows scroll: the last row at the bottom.
    fn most_scroll(&self, recents: &[Pick], g: Geometry) -> u16 {
        let rows = self.rows(recents, g.columns).count() as u16;
        (rows * g.row).saturating_sub(g.height)
    }

    /// Turns the focus `steps` picks on, or back; or, on the tabs, `steps`
    /// tabs. Turning back from the first pick goes up to the tabs.
    pub fn turn(&mut self, recents: &[Pick], g: Geometry, steps: i16) {
        if self.on_tabs {
            self.step_tab(recents, g, steps);
        } else if steps < 0 && self.at == 0 && self.filter.is_empty() {
            self.on_tabs = true;
        } else {
            self.across(recents, g, steps);
        }
    }

    /// Moves the focus `steps` picks on, or back, stopping at either end;
    /// or, on the tabs, `steps` tabs.
    pub fn across(&mut self, recents: &[Pick], g: Geometry, steps: i16) {
        if self.on_tabs {
            self.step_tab(recents, g, steps);
            return;
        }
        let last = self.total(recents).saturating_sub(1);
        self.at = (i32::from(self.at) + i32::from(steps)).clamp(0, i32::from(last)) as u16;
        self.keep_in_view(recents, g);
    }

    /// Moves the focus `rows` rows down, or up, to the same cell or the
    /// last of a shorter row. Up from the first row goes to the tabs, and
    /// down from the tabs into the rows.
    pub fn rows_down(&mut self, recents: &[Pick], g: Geometry, rows: i16) {
        if self.on_tabs {
            self.on_tabs = rows <= 0;
            return;
        }
        let (row, cell, _) = self.locate(recents, g.columns, self.at);
        let Ok(to) = u16::try_from(i32::from(row) + i32::from(rows)) else {
            self.on_tabs = self.filter.is_empty();
            return;
        };
        let row = self.rows(recents, g.columns).nth(usize::from(to));
        if let Some((start, len, _)) = row {
            self.at = start + cell.min(len - 1);
            self.keep_in_view(recents, g);
        }
    }

    /// Moves focus `steps` tabs on, or back, onto each tab's first pick,
    /// with its first row at the top.
    fn step_tab(&mut self, recents: &[Pick], g: Geometry, steps: i16) {
        let tabs = self.tabs(recents);
        let (_, _, tab) = self.locate(recents, g.columns, self.at);
        let i = tab.and_then(|tab| tabs.iter().position(|&t| t == tab));
        let i = i.unwrap_or_default() as i32 + i32::from(steps);
        let last = tabs.len().saturating_sub(1) as i32;
        self.show_tab(recents, g, i.clamp(0, last) as usize);
    }

    /// Shows the tab at `i` in [`Shown::tabs`]: its first pick focused,
    /// and its first row at the top.
    fn show_tab(&mut self, recents: &[Pick], g: Geometry, i: usize) {
        self.glide = None;
        let Some(&tab) = self.tabs(recents).get(i) else {
            return;
        };
        let Some(start) = self.start_of(recents, tab) else {
            return;
        };
        self.at = start;
        let (row, _, _) = self.locate(recents, g.columns, start);
        self.scroll = (row * g.row).min(self.most_scroll(recents, g));
    }

    /// Scrolls the focused row into view, whole: up to the top, or down
    /// to the last row shown whole.
    fn keep_in_view(&mut self, recents: &[Pick], g: Geometry) {
        self.glide = None;
        let (row, _, _) = self.locate(recents, g.columns, self.at);
        let top = row * g.row;
        if top < self.scroll {
            self.scroll = top;
        } else if top + g.row > self.scroll + g.height {
            self.scroll = (row + 1).saturating_sub(g.whole()) * g.row;
        }
        self.scroll = self.scroll.min(self.most_scroll(recents, g));
    }

    /// The focused pick, even while focus is on its tab.
    #[must_use]
    pub fn focused(&self, recents: &[Pick]) -> Option<Pick> {
        self.pick(recents, self.at)
    }

    /// Chooses what is focused: the focused pick, or, on the tabs, the
    /// rows below them.
    pub fn choose(&mut self, recents: &[Pick]) -> Chosen {
        if core::mem::take(&mut self.on_tabs) {
            return Chosen::Entered;
        }
        self.focused(recents).map_or(Chosen::Nothing, Chosen::Pick)
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

    /// Back, a step: a letter off the name typed, or from the rows up to
    /// the tabs. Returns `false` when there is nowhere further back but
    /// closed.
    pub fn back(&mut self) -> bool {
        if self.filter.pop().is_some() {
            self.find();
            return true;
        }
        !core::mem::replace(&mut self.on_tabs, true)
    }

    /// What the name finds, best first, starting over at the first.
    fn find(&mut self) {
        self.found.clear();
        self.at = 0;
        self.scroll = 0;
        self.glide = None;
        self.on_tabs = false;
        if self.filter.trim().is_empty() {
            return;
        }
        let emoji = (0..COUNT).map(Pick::Emoji);
        let characters = (0..CHARACTERS.len() as u16).map(Pick::Character);
        for rank in [Match::Name, Match::Head, Match::Word] {
            for pick in emoji.clone().chain(characters.clone()) {
                if self.offers(pick)
                    && matching(pick.words(), &self.filter) == Some(rank)
                    && self.found.push(pick).is_err()
                {
                    return;
                }
            }
        }
    }

    /// A finger came down on `spot`, at `y` on the screen, at `now`. On a
    /// pick, it focuses it, for as long as it is held in place; on rows
    /// coasting, it stops them.
    pub fn touch_down(&mut self, recents: &[Pick], g: Geometry, spot: Spot, y: i16, now: u64) {
        let was = (self.at, self.on_tabs);
        let caught = self.glide.take().is_some();
        if let Spot::Grid { column, y } = spot
            && !caught
            && let Some(index) = self.index_at(recents, g, column, y)
        {
            self.at = index;
            self.on_tabs = false;
        }
        self.grab = Some(Grab {
            spot,
            y,
            scroll: self.scroll,
            was,
            moved: caught,
            last: (y, now),
            before: (y, now),
        });
    }

    /// The finger moved to `y` on the screen, at `now`: on the rows, past
    /// a little slop, it scrolls them, and focus goes back where it was.
    /// Returns whether that changed what is shown.
    pub fn touch_move(&mut self, recents: &[Pick], g: Geometry, y: i16, now: u64) -> bool {
        let most = self.most_scroll(recents, g);
        let Some(grab) = self.grab.as_mut() else {
            return false;
        };
        if now.saturating_sub(grab.before.1) > SPEED_MS {
            grab.before = grab.last;
        }
        grab.last = (y, now);
        let moved = y.saturating_sub(grab.y);
        if !matches!(grab.spot, Spot::Grid { .. }) || (!grab.moved && moved.abs() <= SLOP) {
            return false;
        }
        let started = !core::mem::replace(&mut grab.moved, true);
        let scroll = (i32::from(grab.scroll) - i32::from(moved)).clamp(0, i32::from(most)) as u16;
        if started {
            (self.at, self.on_tabs) = grab.was;
        }
        core::mem::replace(&mut self.scroll, scroll) != scroll || started
    }

    /// The finger lifted at `now`. Held in place, it tapped: a tab shows
    /// its picks, and a pick is returned, to be chosen. Flicked, the rows
    /// coast on.
    pub fn touch_up(&mut self, recents: &[Pick], g: Geometry, now: u64) -> Option<Pick> {
        let grab = self.grab.take()?;
        if grab.moved {
            self.flicked(&grab, now);
            return None;
        }
        match grab.spot {
            Spot::Tab(i) => {
                self.on_tabs = false;
                self.show_tab(recents, g, usize::from(i));
                None
            }
            Spot::Grid { column, y } => {
                self.at = self.index_at(recents, g, column, y)?;
                self.focused(recents)
            }
            Spot::Outside | Spot::Card => None,
        }
    }

    /// The finger's touch ended without meaning anything.
    pub fn touch_cancel(&mut self) {
        self.grab = None;
    }

    /// A finger lifted from scrolling at `now`: still moving fast enough,
    /// it leaves the rows to coast on.
    fn flicked(&mut self, grab: &Grab, now: u64) {
        let ((y, then), (last_y, last)) = (grab.before, grab.last);
        // Held still before lifting, it stops where it is.
        if now.saturating_sub(last) > SPEED_MS || last <= then {
            return;
        }
        let speed = i32::from(y - last_y) * 1000 / (last - then) as i32;
        if speed.abs() >= FLICK {
            self.glide = Some(Glide {
                at: i32::from(self.scroll) * 16,
                speed,
                when: now,
            });
        }
    }

    /// When the coasting rows next move, if they are coasting.
    #[must_use]
    pub fn coasting_until(&self) -> Option<u64> {
        self.glide.map(|glide| glide.when + GLIDE_FRAME_MS)
    }

    /// Moves the coasting rows on to `now`, slowing them, until they stop
    /// or reach either end.
    pub fn coast(&mut self, recents: &[Pick], g: Geometry, now: u64) {
        let most = i32::from(self.most_scroll(recents, g)) * 16;
        let Some(glide) = self.glide.as_mut() else {
            return;
        };
        let mut left = now.saturating_sub(glide.when).min(2000) as i32;
        while left > 0 && glide.speed.abs() >= STOPPED {
            let dt = left.min(GLIDE_FRAME_MS as i32);
            glide.at += glide.speed * dt * 16 / 1000;
            glide.speed -= glide.speed * dt / COAST_MS;
            left -= dt;
        }
        glide.when = now;
        let at = glide.at.clamp(0, most);
        self.scroll = (at / 16) as u16;
        if at != glide.at || glide.speed.abs() < STOPPED {
            self.glide = None;
        }
    }

    /// The pick at `column` across, `y` below the top of the rows in view.
    fn index_at(&self, recents: &[Pick], g: Geometry, column: u16, y: u16) -> Option<u16> {
        let row = (self.scroll + y) / g.row.max(1);
        let (start, len, _) = self.rows(recents, g.columns).nth(usize::from(row))?;
        (column < len).then_some(start + column)
    }

    /// What is in view.
    #[must_use]
    pub fn shown(&self, recents: &[Pick], g: Geometry) -> Shown {
        let columns = g.columns.clamp(1, COLUMNS as u16);
        let row_height = g.row.max(1);
        let first = self.scroll / row_height;
        let mut shown = Shown {
            tabs: self.tabs(recents),
            tab: None,
            on_tabs: self.on_tabs,
            filter: self.filter.clone(),
            name: "",
            rows: Vec::new(),
            offset: self.scroll % row_height,
            focus: None,
        };
        let rows = self.rows(recents, columns).skip(usize::from(first));
        for (i, (start, len, _)) in rows.take(ROWS).enumerate() {
            // Below the bottom.
            if i as u16 * row_height >= shown.offset + g.height {
                break;
            }
            let row: Vec<Pick, COLUMNS> = (start..start + len)
                .filter_map(|index| self.pick(recents, index))
                .collect();
            if !self.on_tabs && (start..start + len).contains(&self.at) {
                shown.focus = Some((i, usize::from(self.at - start)));
            }
            _ = shown.rows.push(row);
        }
        let (_, _, tab) = self.locate(recents, columns, self.at);
        shown.tab = tab;
        if !self.filter.is_empty() {
            shown.name = self.focused(recents).map_or("", Pick::name);
        }
        shown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ten to a row, 40 pixels each, two and a half rows in view.
    const G: Geometry = Geometry {
        columns: 10,
        row: 40,
        height: 100,
    };

    fn recents() -> Vec<Pick, RECENT> {
        let mut v = Vec::new();
        _ = v.push(Pick::of("\u{1F44D}").unwrap());
        _ = v.push(Pick::of("\u{20AC}").unwrap());
        v
    }

    fn character(c: &str) -> Pick {
        Pick::of(c).unwrap()
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
        assert_eq!(heart.name(), "Red heart");
        assert_eq!(character("#").name(), "number sign");
    }

    #[test]
    fn the_symbols_start_with_every_one_a_keyboard_types() {
        let ascii: Vec<char, 32> = (' '..='~').filter(char::is_ascii_punctuation).collect();
        assert_eq!(ascii.len(), 32);
        for c in &ascii {
            let mut text = String::<4>::new();
            _ = text.push(*c);
            let Some(Pick::Character(i)) = Pick::of(&text) else {
                panic!("{c:?} is not offered");
            };
            assert!(usize::from(i) < ascii.len(), "{c:?} is not among the first");
        }
        assert_eq!(CHARACTERS[SYMBOLS - 1].0, "\u{20AC}");
        assert_eq!(CHARACTERS[SYMBOLS].0, "\u{E0}");
        // Nothing offered twice.
        for (i, (c, _)) in CHARACTERS.iter().enumerate() {
            assert!(!CHARACTERS[..i].iter().any(|(d, _)| d == c), "{c}");
        }
    }

    #[test]
    fn recents_come_first_then_the_symbols_then_every_group() {
        let recents = recents();
        let mut picker = Picker::default();
        let shown = picker.shown(&recents, G);
        assert_eq!(shown.tabs[0], Tab::Recent);
        assert_eq!(shown.tab, Some(Tab::Recent));
        assert_eq!(shown.rows[0].as_slice(), recents.as_slice());
        assert_eq!(shown.rows[1][0], character("!"));
        assert_eq!(shown.focus, Some((0, 0)));
        // Past the recents, into the symbols.
        picker.turn(&recents, G, 4);
        assert_eq!(picker.focused(&recents), Some(character("#")));
        let shown = picker.shown(&recents, G);
        assert_eq!(shown.tab, Some(Tab::Symbols));
        assert_eq!(shown.focus, Some((1, 2)));
        // Down a row keeps the cell, and scrolls it into view, whole.
        picker.rows_down(&recents, G, 1);
        let shown = picker.shown(&recents, G);
        assert_eq!(picker.focused(&recents), Some(character("=")));
        assert_eq!((shown.rows[0][0], shown.offset), (character("!"), 0));
        assert_eq!(shown.focus, Some((1, 2)));
        // Up from a longer row to the end of a shorter one.
        picker.rows_down(&recents, G, -2);
        assert_eq!(picker.focused(&recents), Some(recents[1]));
        // The last of all is the last letter.
        picker.turn(&recents, G, i16::MAX);
        assert_eq!(
            picker.focused(&recents),
            Some(Pick::Character(CHARACTERS.len() as u16 - 1))
        );
        let shown = picker.shown(&recents, G);
        assert_eq!(shown.tab, Some(Tab::Letters));
        // The last row at the bottom, the one before cut by the top.
        assert_eq!(shown.offset, 20);
        assert_eq!(shown.focus, Some((2, (LETTERS - 1) % 10)));
    }

    #[test]
    fn up_from_the_first_row_the_wheel_moves_from_tab_to_tab() {
        let recents = recents();
        let mut picker = Picker::default();
        // Turning back from the first pick.
        picker.turn(&recents, G, -1);
        assert!(picker.on_tabs());
        let shown = picker.shown(&recents, G);
        assert!(shown.on_tabs);
        assert_eq!(shown.focus, None);
        // Two tabs on: the first emoji, its row at the top.
        picker.turn(&recents, G, 2);
        let shown = picker.shown(&recents, G);
        assert_eq!(shown.tab, Some(Tab::Group(0)));
        assert_eq!((shown.rows[0][0], shown.offset), (Pick::Emoji(0), 0));
        // Down into them.
        assert_eq!(picker.choose(&recents), Chosen::Entered);
        assert_eq!(picker.choose(&recents), Chosen::Pick(Pick::Emoji(0)));
        // Back goes up to the tabs, and then closes.
        picker.across(&recents, G, 25);
        assert!(picker.back());
        assert!(picker.on_tabs());
        assert_eq!(picker.focused(&recents), Some(Pick::Emoji(25)));
        assert!(!picker.back());
        // The last tab is as far as it goes.
        picker.turn(&recents, G, 50);
        assert_eq!(picker.shown(&recents, G).tab, Some(Tab::Letters));
        picker.rows_down(&recents, G, -1);
        assert!(picker.on_tabs());
        picker.rows_down(&recents, G, 1);
        assert!(!picker.on_tabs());
    }

    #[test]
    fn a_finger_taps_a_tab_or_a_pick_and_drawn_over_the_rows_scrolls_them() {
        let recents = recents();
        let mut picker = Picker::default();
        // The symbols' tab.
        picker.touch_down(&recents, G, Spot::Tab(1), 10, 0);
        assert_eq!(picker.touch_up(&recents, G, 50), None);
        let shown = picker.shown(&recents, G);
        assert_eq!(shown.tab, Some(Tab::Symbols));
        assert_eq!((shown.rows[0][0], shown.offset), (character("!"), 0));
        // A pick, in the second row.
        let spot = Spot::Grid { column: 1, y: 50 };
        picker.touch_down(&recents, G, spot, 100, 1000);
        assert_eq!(picker.focused(&recents), Some(character("_")));
        assert_eq!(picker.touch_up(&recents, G, 1050), Some(character("_")));
        // Drawn up, the rows follow the finger, and focus stays put.
        picker.touch_down(&recents, G, Spot::Grid { column: 5, y: 10 }, 100, 2000);
        assert!(!picker.touch_move(&recents, G, 97, 2100));
        assert!(picker.touch_move(&recents, G, 50, 2200));
        assert_eq!(picker.focused(&recents), Some(character("_")));
        assert_eq!(picker.shown(&recents, G).offset, 10);
        assert!(picker.touch_move(&recents, G, 40, 2300));
        // Held still, then lifted: it stays where it is.
        assert_eq!(picker.touch_up(&recents, G, 2500), None);
        assert_eq!(picker.coasting_until(), None);
        let shown = picker.shown(&recents, G);
        assert_eq!((shown.rows[0][0], shown.offset), (character("-"), 20));
        // Not past the top.
        picker.touch_down(&recents, G, Spot::Grid { column: 0, y: 0 }, 0, 3000);
        assert!(picker.touch_move(&recents, G, 1000, 3100));
        picker.touch_cancel();
        assert_eq!(picker.shown(&recents, G).offset, 0);
        assert_eq!(picker.shown(&recents, G).tab, Some(Tab::Symbols));
    }

    #[test]
    fn a_flick_coasts_on_slowing_and_a_finger_stops_it() {
        let recents = recents();
        let mut picker = Picker::default();
        let stroke = |picker: &mut Picker| {
            picker.touch_down(&recents, G, Spot::Grid { column: 0, y: 60 }, 100, 0);
            for (i, y) in [90, 80, 70, 60].into_iter().enumerate() {
                picker.touch_move(&recents, G, y, 10 * (i as u64 + 1));
            }
            assert_eq!(picker.touch_up(&recents, G, 45), None);
        };
        // 40 pixels in 30 ms.
        stroke(&mut picker);
        let lifted = picker.scroll;
        assert_eq!(picker.coasting_until(), Some(45 + GLIDE_FRAME_MS));
        let mut was = lifted;
        let mut went = Vec::<u16, 8>::new();
        for now in [145, 245, 345, 445] {
            picker.coast(&recents, G, now);
            _ = went.push(picker.scroll - was);
            was = picker.scroll;
        }
        assert!(went.windows(2).all(|w| w[0] > w[1]), "{went:?}");
        assert!(picker.scroll - lifted > 200, "{}", picker.scroll - lifted);
        picker.coast(&recents, G, 5000);
        assert_eq!(picker.coasting_until(), None);
        // Caught coasting, a finger stops it, and picks nothing.
        stroke(&mut picker);
        picker.coast(&recents, G, 100);
        let at = picker.scroll;
        let focused = picker.focused(&recents);
        picker.touch_down(&recents, G, Spot::Grid { column: 3, y: 10 }, 100, 120);
        assert_eq!(picker.touch_up(&recents, G, 150), None);
        assert_eq!((picker.scroll, picker.focused(&recents)), (at, focused));
        assert_eq!(picker.coasting_until(), None);
    }

    #[test]
    fn a_name_finds_what_it_names_first() {
        let mut picker = Picker::default();
        for c in "hea".chars() {
            picker.type_letter(c);
        }
        let shown = picker.shown(&[], G);
        assert_eq!(shown.tab, None);
        assert_eq!(shown.filter, "hea");
        let heart = Pick::of("\u{2764}").unwrap();
        let eyes = Pick::of("\u{1F60D}").unwrap();
        let found: Vec<Pick, FOUND> = picker.found.clone();
        assert!(found.iter().position(|&p| p == heart) < found.iter().position(|&p| p == eyes));
        assert_eq!(shown.name, picker.focused(&[]).unwrap().name());
        // Turning back from the first stays among them.
        picker.turn(&[], G, -1);
        assert!(!picker.on_tabs());
        // A space in a name.
        for c in " #".chars() {
            picker.type_letter(c);
        }
        assert_eq!(picker.filter(), "hea #");
        picker.back();
        picker.back();
        picker.filter = String::try_from("hash").unwrap();
        picker.find();
        assert_eq!(picker.focused(&[]), Some(character("#")));
        for _ in 0..4 {
            assert!(picker.back());
        }
        assert!(!picker.on_tabs());
        assert_eq!(picker.shown(&[], G).tab, Some(Tab::Symbols));
    }

    #[test]
    fn reacting_it_offers_only_emoji() {
        let recents = recents();
        let mut picker = Picker::to_react(7);
        assert_eq!(picker.reacting(), Some(7));
        let shown = picker.shown(&recents, G);
        // The thumb, but not the euro.
        assert_eq!(shown.rows[0].as_slice(), &recents[..1]);
        assert_eq!(shown.tabs.first(), Some(&Tab::Recent));
        assert_eq!(shown.tabs[1], Tab::Group(0));
        assert_eq!(shown.tabs.last(), Some(&Tab::Group(GROUP_COUNT as u8 - 1)));
        picker.turn(&recents, G, i16::MAX);
        assert!(matches!(picker.focused(&recents), Some(Pick::Emoji(_))));
        // Only letters are named so.
        for c in "cedilla".chars() {
            picker.type_letter(c);
        }
        assert_eq!(picker.focused(&recents), None);
        assert_eq!(picker.choose(&recents), Chosen::Nothing);
        // Without recents, no tab for them.
        assert_eq!(Picker::default().shown(&[], G).tabs[0], Tab::Symbols);
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
