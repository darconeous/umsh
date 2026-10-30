//! Device › Wi-Fi: the switch; while on, the network in use, the other
//! saved networks, what the last scan heard, Other network, and Scan
//! again. A network's sheet, a password, and Other network open from it.
//! Backspace goes back.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::{BoundaryBehavior, FocusKey};
use buoyant::match_view;
use buoyant::view::lazy_foreach::{Extent, Natural};
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use buoyant::view::{Lazy, LazyForEach};
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::conversation::titled_with;
use super::details::spinner;
use super::enter_address::field_look;
use super::setting::{End, card, choice, page, readout, row};
use super::{label, line};
use crate::board::Metrics;
use crate::model::{
    MAX_NEARBY_NETWORKS, MAX_SAVED_NETWORKS, State, WifiReading, WifiSecurity, WifiStatus,
    wifi_bars,
};
use crate::nav::{WifiPage, keys};
use crate::wifi_settings::{OTHER_SECURITY, PasswordText, ssid_text};
use crate::{font, icon, theme};

const ROW: u32 = 36;
/// The network in use: its name over what it is doing.
const CURRENT: u32 = 50;
/// A section's label.
const LABEL: u32 = 26;
const INSET: u32 = 12;
/// A field's place, and its label's.
const FIELD_INSET: u32 = 8;
const CARET: u32 = 3;
/// Forget's confirmation, and the security choices.
const CARD_WIDTH: u32 = 220;

/// A screen under Device › Wi-Fi.
///
/// This and each page's builder are kept out of line so that their
/// temporaries take a frame of their own while a Wi-Fi page is built,
/// rather than enlarging the frame every Device page is built in.
#[inline(never)]
pub fn view(state: &State, page: &WifiPage) -> impl View<Rgb565, State> + use<> {
    match_view!(page, {
        WifiPage::Main => main(state),
        WifiPage::Sheet { ssid, confirm } => sheet(state, ssid, *confirm),
        WifiPage::Password { ssid, change, text, .. } => password(state, ssid, *change, text),
        WifiPage::Other { .. } => other(state, page),
    })
}

/// What a network's row shows.
#[derive(Clone)]
struct Network {
    name: String<32>,
    /// Signal bars, 1 to 3, when it was heard.
    bars: Option<u8>,
    secured: bool,
}

/// The status line of the network in use, and its color.
fn status(reading: &WifiReading) -> (&'static str, Rgb565) {
    let color = match reading.status {
        WifiStatus::Connected => theme::GREEN,
        WifiStatus::WrongPassword | WifiStatus::Refused => theme::RED,
        WifiStatus::NotInRange => theme::AMBER,
        WifiStatus::Joining | WifiStatus::GettingAddress => theme::TEXT_SECONDARY,
    };
    (reading.status.label(), color)
}

/// One row of the main page.
#[derive(Clone, Copy)]
enum Entry {
    Switch,
    /// The network in use.
    Current,
    /// The device's IP address on it.
    Address,
    /// Searching or Disconnected, with no network in use.
    Idle,
    SavedLabel,
    /// A saved network: its place among the rows' networks, and in the
    /// reading.
    Saved {
        slot: u8,
        index: u8,
    },
    NearbyLabel,
    /// The nearby network at this place in the reading.
    Nearby(u8),
    Other,
    Scan,
    IpMulticast,
}

impl Entry {
    fn key(self) -> FocusKey {
        match self {
            Self::Switch => keys::WIFI_ENABLED,
            Self::Current => keys::WIFI_CURRENT,
            Self::Address => keys::WIFI_ADDRESS,
            Self::Idle => keys::WIFI_IDLE,
            Self::SavedLabel => keys::WIFI_SAVED_LABEL,
            Self::Saved { index, .. } => keys::wifi_saved(usize::from(index)),
            Self::NearbyLabel => keys::WIFI_NEARBY_LABEL,
            Self::Nearby(i) => keys::wifi_nearby(usize::from(i)),
            Self::Other => keys::WIFI_OTHER,
            Self::Scan => keys::WIFI_SCAN,
            Self::IpMulticast => keys::WIFI_IP_MULTICAST,
        }
    }
}

/// The switch, the network in use and its address or the idle line, two
/// labels, every network, Other network, Scan again, and IP multicast.
const ENTRIES: usize = 9 + MAX_SAVED_NETWORKS + MAX_NEARBY_NETWORKS;
/// Rows built at once: as many 26-pixel labels as the taller board's list
/// shows, both partly shown ends, and two the list keeps in hand.
const BUILT: usize = 12;
/// Row heights remembered once a row is dropped.
const REMEMBERED: usize = 8;

/// What the main page's rows are built from.
#[derive(Clone)]
struct Rows {
    m: &'static Metrics,
    entries: Vec<Entry, ENTRIES>,
    on: bool,
    phase: u8,
    searching: bool,
    scanning: bool,
    /// The network in use: its name, its status line and color, and its
    /// signal bars.
    current: Option<(String<32>, &'static str, Rgb565, u8)>,
    address: String<16>,
    ip_multicast: bool,
    saved: Vec<Network, MAX_SAVED_NETWORKS>,
    nearby: Vec<Network, MAX_NEARBY_NETWORKS>,
}

/// The switch; while on, the network in use and its address, the saved
/// and nearby networks, Other network, and Scan again; and IP multicast,
/// where the device has it.
///
/// One lazy list, so that only the rows near what is shown are built, and
/// the view holds the networks as data rather than as rows.
#[inline(never)]
fn main(state: &State) -> impl View<Rgb565, State> + use<> {
    let reading = &state.wifi;
    let on = reading.enabled == Some(true);
    let mut entries: Vec<Entry, ENTRIES> = Vec::new();
    _ = entries.push(Entry::Switch);
    let mut saved: Vec<Network, MAX_SAVED_NETWORKS> = Vec::new();
    let mut nearby: Vec<Network, MAX_NEARBY_NETWORKS> = Vec::new();
    if on {
        _ = entries.push(if reading.current.is_empty() {
            Entry::Idle
        } else {
            Entry::Current
        });
        if reading.address.is_some() && !reading.current.is_empty() {
            _ = entries.push(Entry::Address);
        }
        // The other saved networks, by their place in the reading.
        for (i, network) in reading.saved.iter().enumerate() {
            if network.ssid == reading.current {
                continue;
            }
            if saved.is_empty() {
                _ = entries.push(Entry::SavedLabel);
            }
            _ = entries.push(Entry::Saved {
                slot: saved.len() as u8,
                index: i as u8,
            });
            _ = saved.push(Network {
                name: ssid_text(&network.ssid),
                bars: network.rssi.map(wifi_bars),
                secured: network.security.takes_password(),
            });
        }
        _ = entries.push(Entry::NearbyLabel);
        for (i, network) in reading.nearby.iter().enumerate() {
            _ = entries.push(Entry::Nearby(i as u8));
            _ = nearby.push(Network {
                name: ssid_text(&network.ssid),
                bars: Some(wifi_bars(network.rssi)),
                secured: network.security.takes_password(),
            });
        }
        _ = entries.push(Entry::Other);
        _ = entries.push(Entry::Scan);
    }
    if reading.ip_multicast.is_some() {
        _ = entries.push(Entry::IpMulticast);
    }
    let mut address: String<16> = String::new();
    if let Some([a, b, c, d]) = reading.address {
        _ = core::fmt::write(&mut address, format_args!("{a}.{b}.{c}.{d}"));
    }
    let current = (!reading.current.is_empty()).then(|| {
        let (text, color) = status(reading);
        (
            ssid_text(&reading.current),
            text,
            color,
            reading.rssi.map_or(3, wifi_bars),
        )
    });
    let keyed = entries.clone();
    let rows = Rows {
        m: state.metrics(),
        entries,
        on,
        phase: state.spinner_phase(),
        searching: reading.searching,
        scanning: reading.scanning,
        current,
        address,
        ip_multicast: reading.ip_multicast == Some(true),
        saved,
        nearby,
    };
    page(
        rows.m,
        "Wi-Fi",
        LazyForEach::<BUILT>::new_natural(
            rows.entries.len(),
            Natural::<REMEMBERED>::new(ROW),
            move |i| entry(&rows, i),
        )
        .keyed(move |i| keyed[i].key()),
    )
}

/// The main page's row at `i`.
fn entry(rows: &Rows, i: usize) -> impl View<Rgb565, State> + use<> {
    let m = rows.m;
    let phase = rows.phase;
    match_view!(rows.entries[i], {
        Entry::Switch | Entry::Other | Entry::Scan | Entry::IpMulticast => {
            let (name, act, end): (_, fn(&mut State), _) = match rows.entries[i] {
                Entry::Switch => ("Wi-Fi", State::toggle_wifi, End::Switch(rows.on)),
                Entry::Other => ("Other network", State::open_other_wifi, End::Chevron),
                Entry::IpMulticast => (
                    "IP multicast",
                    State::toggle_ip_multicast,
                    End::Switch(rows.ip_multicast),
                ),
                _ => ("Scan again", State::scan_wifi, End::Nothing),
            };
            row(m, name, rows.entries[i].key(), act, end, false, ROW)
        },
        Entry::Address => readout(m, "IP address", &rows.address, ROW),
        Entry::Current => rows
            .current
            .clone()
            .map(|(name, text, color, bars)| current_row(m, name, text, color, bars)),
        Entry::Idle => if rows.searching {
            state_line(m, "Searching", Some(phase))
        } else {
            state_line(m, "Disconnected", None)
        },
        Entry::SavedLabel | Entry::NearbyLabel => if matches!(rows.entries[i], Entry::SavedLabel) {
            section(m, "Saved", None)
        } else {
            section(m, "Nearby", rows.scanning.then_some(phase))
        },
        Entry::Saved { slot, index } => {
            let index = usize::from(index);
            network_row(
                m,
                rows.saved[usize::from(slot)].clone(),
                keys::wifi_saved(index),
                Pick::Saved(index),
                false,
            )
        },
        Entry::Nearby(index) => {
            let index = usize::from(index);
            network_row(
                m,
                rows.nearby[index].clone(),
                keys::wifi_nearby(index),
                Pick::Nearby(index),
                true,
            )
        },
    })
}

/// What pressing a network's row does.
#[derive(Clone, Copy)]
enum Pick {
    /// Opens the saved network's sheet.
    Saved(usize),
    /// Joins the nearby network, asking for its password where it takes one.
    Nearby(usize),
}

impl Pick {
    fn act(self, state: &mut State) {
        match self {
            Self::Saved(i) => state.open_saved_wifi(i),
            Self::Nearby(i) => state.join_nearby_wifi(i),
        }
    }
}

/// A fan of `bars` lit arcs in `lit`, over the whole fan in the dim.
fn fan<C>(bars: u8, lit: Rgb565) -> impl View<Rgb565, C> + use<C> {
    let arcs = match bars {
        0 | 1 => &icon::FAN_1,
        2 => &icon::FAN_2,
        _ => &icon::FAN,
    };
    ZStack::new((
        Image::new(&icon::FAN)
            .as_template()
            .foreground_color(theme::LEVEL_OFF),
        Image::new(arcs).as_template().foreground_color(lit),
    ))
}

/// The look of a row that takes focus, as a settings row has it.
fn focus_look<C, V: View<Rgb565, C>>(
    content: V,
    focused: bool,
    height: u32,
) -> impl View<Rgb565, C> + use<C, V> {
    content
        .hint_background_color(if focused {
            theme::FOCUS
        } else {
            theme::BACKGROUND
        })
        .padding(Edges::Leading, INSET - 4)
        .padding(Edges::Trailing, 10)
        .frame()
        .with_height(height - 2)
        .background(
            Alignment::Center,
            focused.then(|| {
                ZStack::new((
                    RoundedRectangle::new(8).foreground_color(theme::FOCUS),
                    RoundedRectangle::new(8)
                        .stroked(2)
                        .foreground_color(theme::ACCENT),
                ))
            }),
        )
        .padding(Edges::Horizontal, 4)
        .padding(Edges::Vertical, 1)
        .overlay(
            Alignment::Bottom,
            (!focused).then(|| {
                Rectangle
                    .foreground_color(theme::LINE)
                    .frame()
                    .with_height(1)
                    .padding(Edges::Leading, INSET)
            }),
        )
}

/// A saved or nearby network: its name, then a padlock when it takes a
/// password and its signal. A saved one not heard is dim and has none.
// Out of line, as `setting::row` is, against the Xtensa back end's failure.
#[inline(never)]
fn network_row(
    m: &'static Metrics,
    network: Network,
    key: FocusKey,
    pick: Pick,
    nearby: bool,
) -> impl View<Rgb565, State> + use<> {
    let look = Row {
        network,
        nearby,
        focused: false,
        m,
    };
    Button::new(
        move |s: &mut State| pick.act(s),
        move |button: ButtonState| {
            let mut look = look.clone();
            look.focused = button.is_focused();
            Lazy::new(look, row_look)
        },
    )
    .focus_key(key)
}

/// What a network's row draws.
#[derive(Clone)]
struct Row {
    network: Network,
    nearby: bool,
    focused: bool,
    m: &'static Metrics,
}

/// A network's row.
///
/// Built from its data each time it is drawn ([`Lazy`]): kept in the
/// render trees, every built row's would outweigh the rest of the screen.
fn row_look(row: &Row) -> impl View<Rgb565, ()> + use<> {
    let network = &row.network;
    let face = if row.focused {
        &font::BOLD
    } else {
        &font::REGULAR
    };
    let color = if network.bars.is_some() {
        theme::TEXT
    } else {
        theme::TEXT_TERTIARY
    };
    focus_look(
        HStack::new((
            line(network.name.clone(), face, row.m.body, color),
            Spacer::default(),
            (row.nearby && network.secured).then(|| {
                Image::new(&icon::LOCK_SMALL)
                    .as_template()
                    .foreground_color(theme::TEXT_SECONDARY)
            }),
            network.bars.map(|bars| fan(bars, theme::TEXT)),
            (!row.nearby).then(|| {
                Image::new(&icon::CHEVRON)
                    .as_template()
                    .foreground_color(theme::TEXT_TERTIARY)
            }),
        ))
        .with_spacing(8),
        row.focused,
        ROW,
    )
}

/// The network in use: its fan, its name, and what it is doing.
#[inline(never)]
fn current_row(
    m: &'static Metrics,
    name: String<32>,
    status: &'static str,
    color: Rgb565,
    bars: u8,
) -> impl View<Rgb565, State> + use<> {
    Button::new(State::open_current_wifi, move |button: ButtonState| {
        let focused = button.is_focused();
        let lit = if color == theme::GREEN {
            theme::TEXT
        } else {
            color
        };
        focus_look(
            HStack::new((
                fan(bars, lit),
                VStack::new((
                    label::<32>(&name, &font::BOLD, m.body, theme::TEXT),
                    label::<16>(status, &font::SEMIBOLD, m.small, color),
                ))
                .with_spacing(1)
                .with_alignment(HorizontalAlignment::Leading),
                Spacer::default(),
                Image::new(&icon::CHEVRON)
                    .as_template()
                    .foreground_color(theme::TEXT_TERTIARY),
            ))
            .with_spacing(10),
            focused,
            CURRENT,
        )
    })
    .focus_key(keys::WIFI_CURRENT)
}

/// What the station does with no network in use, with a spinner while it
/// looks.
fn state_line(
    m: &'static Metrics,
    text: &'static str,
    phase: Option<u8>,
) -> impl View<Rgb565, State> + use<> {
    HStack::new((
        label::<16>(text, &font::SEMIBOLD, m.body, theme::TEXT_SECONDARY),
        phase.map(|phase| spinner::<State>(phase)),
        Spacer::default(),
    ))
    .with_spacing(10)
    .padding(Edges::Leading, INSET)
    .frame()
    .with_height(ROW)
}

/// A section's label, with a spinner while it fills.
fn section(
    m: &'static Metrics,
    text: &'static str,
    phase: Option<u8>,
) -> impl View<Rgb565, State> + use<> {
    HStack::new((
        label::<16>(text, &font::BOLD, m.small, theme::TEXT_SECONDARY),
        phase.map(|phase| spinner::<State>(phase)),
        Spacer::default(),
    ))
    .with_spacing(8)
    .padding(Edges::Leading, INSET)
    .padding(Edges::Top, 6)
    .frame()
    .with_height(LABEL)
}

/// A screen with a header of `name` and what it is doing, and `rows` in a
/// list. Backspace goes back.
fn titled_page<V: View<Rgb565, State>>(
    m: &'static Metrics,
    name: &str,
    about: &str,
    about_color: Rgb565,
    rows: V,
) -> impl View<Rgb565, State> + use<V> {
    VStack::new((
        titled_with(m, name, theme::TEXT, None, about, about_color),
        super::list(rows)
            .with_scroll_step(ROW)
            .with_self_focus(true)
            .focus_key(keys::READING),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
}

/// One row of a network's sheet.
#[derive(Clone, Copy)]
enum SheetEntry {
    ChangePassword,
    /// Join, or Disconnect from the network in use.
    Act,
    AutoJoin,
    Signal,
    Address,
    Channel,
    Security,
    Forget,
}

impl SheetEntry {
    fn key(self) -> FocusKey {
        match self {
            Self::ChangePassword => keys::WIFI_CHANGE_PASSWORD,
            Self::Act => keys::WIFI_ACT,
            Self::AutoJoin => keys::WIFI_AUTO_JOIN,
            Self::Signal => keys::wifi_readout(0),
            Self::Address => keys::wifi_readout(1),
            Self::Channel => keys::wifi_readout(2),
            Self::Security => keys::wifi_readout(3),
            Self::Forget => keys::WIFI_FORGET,
        }
    }
}

/// Every row a sheet can have, each once.
const SHEET_ROWS: usize = 8;

/// What a sheet's rows are built from.
#[derive(Clone)]
struct SheetRows {
    m: &'static Metrics,
    entries: Vec<SheetEntry, SHEET_ROWS>,
    in_use: bool,
    auto_join: bool,
    signal: String<16>,
    address: String<16>,
    channel: String<8>,
    security: &'static str,
}

/// A network's sheet: Join or Disconnect, Join automatically, Change
/// password, what is known of it, and Forget.
///
/// One lazy list, as the main page is, so that the view holds what the
/// rows say rather than the rows.
#[inline(never)]
fn sheet(state: &State, ssid: &[u8], confirm: bool) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let reading = &state.wifi;
    let name = ssid_text(ssid);
    let in_use = reading.current == ssid;
    let saved = reading.saved(ssid).cloned().unwrap_or_default();
    let (about, color) = if in_use {
        status(reading)
    } else {
        ("Saved", theme::TEXT_TERTIARY)
    };
    let failing = in_use && reading.status == WifiStatus::WrongPassword;
    let mut signal: String<16> = String::new();
    let mut address: String<16> = String::new();
    let mut channel: String<8> = String::new();
    if in_use {
        if let Some(rssi) = reading.rssi {
            _ = core::fmt::write(&mut signal, format_args!("{rssi} dBm"));
        }
        if let Some([a, b, c, d]) = reading.address {
            _ = core::fmt::write(&mut address, format_args!("{a}.{b}.{c}.{d}"));
        }
        if let Some(number) = reading.channel {
            _ = core::fmt::write(&mut channel, format_args!("{number}"));
        }
    }
    let takes_password = saved.security.takes_password();
    let mut entries: Vec<SheetEntry, SHEET_ROWS> = Vec::new();
    // Change password leads while the password is what is wrong.
    if failing && takes_password {
        _ = entries.push(SheetEntry::ChangePassword);
    }
    _ = entries.push(SheetEntry::Act);
    _ = entries.push(SheetEntry::AutoJoin);
    if !failing && takes_password {
        _ = entries.push(SheetEntry::ChangePassword);
    }
    for (entry, shown) in [
        (SheetEntry::Signal, &signal[..]),
        (SheetEntry::Address, &address[..]),
        (SheetEntry::Channel, &channel[..]),
    ] {
        if !shown.is_empty() {
            _ = entries.push(entry);
        }
    }
    _ = entries.push(SheetEntry::Security);
    _ = entries.push(SheetEntry::Forget);
    let keyed = entries.clone();
    let rows = SheetRows {
        m,
        entries,
        in_use,
        auto_join: saved.auto_join,
        signal,
        address,
        channel,
        security: saved.security.label(),
    };
    titled_page(
        m,
        &name,
        about,
        color,
        LazyForEach::<SHEET_ROWS>::new_vertical(rows.entries.len(), Extent::Fixed(ROW), move |i| {
            sheet_entry(&rows, i)
        })
        .keyed(move |i| keyed[i].key()),
    )
    .popover(confirm.then_some(()).as_ref(), move |()| {
        forget_confirmation(m)
    })
    // A tap outside is Cancel.
    .on_blur(|s: &mut State| {
        s.cancel_forget_wifi();
        Dismissal::Dismiss
    })
}

/// What a row of a sheet is: something to press, or something to read.
enum SheetRow<'a> {
    Action(&'static str, FocusKey, fn(&mut State), End, bool),
    Readout(&'static str, &'a str),
}

/// A sheet's row at `i`.
fn sheet_entry(rows: &SheetRows, i: usize) -> impl View<Rgb565, State> + use<> {
    let m = rows.m;
    let entry = rows.entries[i];
    let shown = match entry {
        SheetEntry::ChangePassword => SheetRow::Action(
            "Change password",
            entry.key(),
            State::open_wifi_change_password,
            End::Chevron,
            false,
        ),
        SheetEntry::Act => SheetRow::Action(
            if rows.in_use { "Disconnect" } else { "Join" },
            entry.key(),
            State::wifi_sheet_act,
            End::Nothing,
            false,
        ),
        SheetEntry::AutoJoin => SheetRow::Action(
            "Join automatically",
            entry.key(),
            State::toggle_wifi_auto_join,
            End::Switch(rows.auto_join),
            false,
        ),
        SheetEntry::Forget => SheetRow::Action(
            "Forget",
            entry.key(),
            State::ask_forget_wifi,
            End::Nothing,
            true,
        ),
        SheetEntry::Signal => SheetRow::Readout("Signal", &rows.signal),
        SheetEntry::Address => SheetRow::Readout("Address", &rows.address),
        SheetEntry::Channel => SheetRow::Readout("Channel", &rows.channel),
        SheetEntry::Security => SheetRow::Readout("Security", rows.security),
    };
    match_view!(shown, {
        SheetRow::Action(name, key, act, end, danger) => row(m, name, key, act, end, danger, ROW),
        SheetRow::Readout(name, value) => readout(m, name, value, ROW),
    })
}

/// Forget, confirmed, or Cancel, which is focused.
#[inline(never)]
fn forget_confirmation(m: &'static Metrics) -> impl View<Rgb565, State> + use<> {
    let text = |text: &str| String::try_from(text).unwrap_or_default();
    card(
        m,
        VStack::new((
            choice(
                m,
                text("Forget"),
                keys::WIFI_FORGET_CONFIRM,
                State::forget_wifi,
                theme::RED,
                None,
            ),
            choice(
                m,
                text("Cancel"),
                keys::WIFI_FORGET_CANCEL,
                State::cancel_forget_wifi,
                theme::TEXT,
                None,
            ),
        ))
        .with_spacing(0),
        CARD_WIDTH,
        HorizontalAlignment::Center,
        State::cancel_forget_wifi,
    )
}

/// A field's label.
fn field_label(m: &'static Metrics, text: &'static str) -> impl View<Rgb565, State> + use<> {
    label::<24>(text, &font::BOLD, m.small, theme::TEXT_SECONDARY)
        .padding(Edges::Leading, 10)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(LABEL)
}

/// The password field, in the clear.
fn password_field(
    m: &'static Metrics,
    text: &PasswordText,
    submit: fn(&mut State),
) -> impl View<Rgb565, State> + use<> {
    TextField::new(&text.0, &font::MONO, State::wifi_password_mut)
        .on_submit(submit)
        .with_font_size(m.body)
        .with_max_lines(2)
        .with_caret_width(CARET)
        .on_active(State::field_active)
        .with_label(move |status, area| field_look(status, area, m.width - 2 * FIELD_INSET - 24))
        .focus_key(keys::WIFI_PASSWORD_FIELD)
        .padding(Edges::Horizontal, FIELD_INSET)
}

/// The row that submits, dim until there is something to submit.
fn submit(
    m: &'static Metrics,
    text: &'static str,
    ready: bool,
    act: fn(&mut State),
) -> impl View<Rgb565, State> + use<> {
    match_view!(ready, {
        true => row(m, text, keys::WIFI_SUBMIT, act, End::Nothing, false, ROW),
        false => label::<8>(text, &font::REGULAR, m.body, theme::TEXT_TERTIARY)
            .padding(Edges::Leading, INSET)
            .flex_infinite_width(HorizontalAlignment::Leading)
            .frame()
            .with_height(ROW),
    })
}

/// A network's password: to join it, or with `change`, its new one.
#[inline(never)]
fn password(
    state: &State,
    ssid: &[u8],
    change: bool,
    text: &PasswordText,
) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let name = ssid_text(ssid);
    let ready = text.valid();
    titled_page(
        m,
        &name,
        "",
        theme::TEXT_TERTIARY,
        VStack::new((
            field_label(m, if change { "New password" } else { "Password" }),
            password_field(m, text, State::submit_wifi_password),
            submit(
                m,
                if change { "Save" } else { "Join" },
                ready,
                State::submit_wifi_password,
            ),
        ))
        .with_spacing(0),
    )
}

/// A network that hides its name: its name, its security, and a password
/// where it takes one.
#[inline(never)]
fn other(state: &State, page: &WifiPage) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let WifiPage::Other {
        name,
        security,
        password,
        choosing,
    } = page
    else {
        unreachable!("only Other network is drawn here")
    };
    let ready = State::other_wifi_ready(page);
    let security = *security;
    let choosing = *choosing;
    let name_field = TextField::new(name, &font::MONO, State::wifi_name_mut)
        .with_font_size(m.body)
        .with_max_lines(1)
        .with_caret_width(CARET)
        .on_active(State::field_active)
        .with_label(move |status, area| field_look(status, area, m.width - 2 * FIELD_INSET - 24))
        .focus_key(keys::WIFI_NAME_FIELD)
        .padding(Edges::Horizontal, FIELD_INSET);
    titled_page(
        m,
        "Other network",
        "",
        theme::TEXT_TERTIARY,
        VStack::new((
            field_label(m, "Network name"),
            name_field,
            row(
                m,
                "Security",
                keys::WIFI_SECURITY,
                State::choose_wifi_security,
                End::value_chevron(security.label()),
                false,
                ROW,
            ),
            security.takes_password().then(|| {
                VStack::new((
                    field_label(m, "Password"),
                    password_field(m, password, State::submit_other_wifi),
                ))
                .with_spacing(0)
            }),
            submit(m, "Join", ready, State::submit_other_wifi),
        ))
        .with_spacing(0),
    )
    .popover(choosing.then_some(()).as_ref(), move |()| {
        security_choices(m, security)
    })
    .on_blur(|s: &mut State| {
        s.cancel_wifi_security();
        Dismissal::Dismiss
    })
}

/// The security a hidden network can be joined with, `current` checked.
#[inline(never)]
fn security_choices(
    m: &'static Metrics,
    current: WifiSecurity,
) -> impl View<Rgb565, State> + use<> {
    let option = |index: usize, act: fn(&mut State)| {
        let security = OTHER_SECURITY[index];
        choice(
            m,
            String::try_from(security.label()).unwrap_or_default(),
            keys::wifi_security(index),
            act,
            theme::TEXT,
            Some(security == current),
        )
    };
    card(
        m,
        VStack::new((
            option(0, |s| s.set_wifi_security(0)),
            option(1, |s| s.set_wifi_security(1)),
            option(2, |s| s.set_wifi_security(2)),
        ))
        .with_spacing(0),
        CARD_WIDTH,
        HorizontalAlignment::Center,
        State::cancel_wifi_security,
    )
}
