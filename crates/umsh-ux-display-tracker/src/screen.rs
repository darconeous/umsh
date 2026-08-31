//! Frame rendering shared by every display tracker.
//!
//! One renderer draws every board in the class. A board contributes its
//! panel driver, its frame buffer, and a [`Layout`] describing the
//! geometry it can offer; what actually appears on the glass — which
//! rows exist, what they say, where the battery sits — is decided here,
//! so a T-Echo and a Heltec V3 disagree about pixels and about nothing
//! else.
//!
//! Every frame carries a header: the device name on the left and a
//! battery indicator on the right. That includes the message frames
//! ([`render_message`]) shown while pairing starts or the board shuts
//! down — a panel that blanks its status to say "Clearing bonds..." is a
//! panel the user has to wait on to learn anything.
//!
//! # Coordinates and color
//!
//! The renderer draws `BinaryColor::On` as foreground and clears with
//! `Off`, which is what all three panels in this class already mean by
//! those values: the e-paper's frame buffer maps `On` to ink, both OLEDs
//! map it to a lit pixel. Boards hand over a `DrawTarget` in natural
//! screen coordinates and keep rotation, packing, and flushing to
//! themselves.
//!
//! # Layout model
//!
//! A frame is a stack of `rows` text lines of one font. Row 0 is the
//! header, row 1 is the menu cursor or the confirmation question, and the
//! rows after that belong to the page. Gesture hints sit at the bottom of
//! the panel and are dropped, last one first, when the page needs the
//! room — which is how a five-row OLED and a seven-row e-paper run the
//! same code without either one wasting a line.
//!
//! Errors are swallowed throughout: a panel that fails mid-frame leaves a
//! stale image, which is a display problem and never a protocol one.

use core::fmt::Write as _;

use embedded_graphics::mono_font::ascii::{FONT_6X10, FONT_10X20};
use embedded_graphics::mono_font::{MonoFont, MonoTextStyle, MonoTextStyleBuilder};
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{
    PrimitiveStyle, PrimitiveStyleBuilder, Rectangle, StrokeAlignment, Triangle,
};
use embedded_graphics::text::{Baseline, Text};
use heapless::String;

use crate::menu::{EntryKind, MenuItem, Page, ToggleId, UiEffect, UiModel, UiNotice};
use umsh_ux_tracker::battery::ChargeClass;

/// Scratch buffer for a composed line. No panel in the class shows more
/// than 21 characters — the 200 px e-paper manages only 19, since its
/// font is proportionally much larger than the OLEDs' — so this is slack
/// rather than a constraint. Rows are clipped to the panel on the way
/// out regardless.
const LINE: usize = 32;

// ─── Board geometry ──────────────────────────────────────────────────────────

/// How many fill segments the battery body is divided into.
///
/// Four is a deliberate coarseness. The e-paper diffs frames to decide
/// how small a partial refresh it can get away with, so an indicator that
/// moved on every sample would keep re-inking the panel; quantizing to
/// quarters means the icon changes four times across a discharge.
pub const BATTERY_SEGMENTS: u8 = 4;

/// Number of lit segments for a *known* charge level, from 0 to
/// [`BATTERY_SEGMENTS`].
///
/// The bands center each bar count on the level it depicts: two of four
/// bars covers 37–63 %, so a half-full pack draws half a body. The two
/// end bands are deliberately narrower than the middle ones — full and
/// empty are absolute claims, and a body should not look full at 80 %
/// nor empty at 20 %.
pub const fn battery_segments(level_percent: u8) -> u8 {
    match level_percent {
        0..=14 => 0,
        15..=36 => 1,
        37..=62 => 2,
        63..=84 => 3,
        _ => BATTERY_SEGMENTS,
    }
}

/// Battery indicator geometry, in pixels.
///
/// The bolt slot is reserved whether or not a bolt is drawn, so plugging
/// in a charger never moves the battery body. On a partial-refresh panel
/// that keeps the changed region down to the bolt itself.
#[derive(Clone, Copy, Debug)]
pub struct BatteryIconMetrics {
    /// Outline of the battery body, border included.
    pub body: Size,
    /// Terminal nub, drawn flush against the body's right edge.
    pub nub: Size,
    /// Width reserved to the left of the body for the charging bolt.
    pub bolt_width: u32,
    /// Size of the bolt drawn when it stands in for the whole indicator,
    /// which is bigger than [`Self::bolt_width`] because it is then the
    /// only thing in the zone rather than an adornment beside a body.
    pub solo_bolt: Size,
    /// Gap between the bolt slot and the body.
    pub spacing: u32,
    /// Body outline stroke width, drawn inside [`Self::body`].
    pub border: u32,
    /// Clearance between the outline and the fill segments.
    pub pad: u32,
    /// Gap between adjacent fill segments.
    pub gap: u32,
    /// Clearance between the indicator and the right edge of the panel.
    pub margin: u32,
}

impl BatteryIconMetrics {
    /// Sized against `FONT_6X10`'s ten-pixel row on a 128×64 panel.
    pub const OLED: Self = Self {
        body: Size::new(16, 9),
        nub: Size::new(2, 3),
        bolt_width: 5,
        solo_bolt: Size::new(7, 9),
        spacing: 2,
        border: 1,
        pad: 1,
        gap: 1,
        margin: 1,
    };

    /// Sized against `FONT_10X20`'s twenty-pixel row on a 200×200 panel.
    pub const EPD: Self = Self {
        body: Size::new(32, 17),
        nub: Size::new(4, 7),
        bolt_width: 10,
        solo_bolt: Size::new(13, 17),
        spacing: 3,
        border: 2,
        pad: 2,
        gap: 2,
        margin: 3,
    };

    /// Total width the indicator occupies, bolt slot included.
    pub const fn zone_width(&self) -> u32 {
        self.bolt_width + self.spacing + self.body.width + self.nub.width
    }
}

/// What the board gives the user to drive the menu with.
///
/// The hints at the bottom of every page name gestures the hardware
/// actually has, so the renderer has to know which set it is looking at.
/// Nothing else about a frame changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Controls {
    /// One button carrying the whole vocabulary: click advances,
    /// double-click selects, a released hold goes back one entry.
    OneButton,
    /// A four-way pad with a center press, beside a button the case
    /// labels Back. Up and down move, the center selects, and Back
    /// leaves the screen — no gesture means two things.
    Dpad,
}

/// A board's panel and controls.
///
/// Everything the renderer needs to place a row of text and the battery
/// indicator, plus which gestures to name in the hints. A board picks one
/// of the constants — or writes its own if its panel is neither of the
/// two shapes in the class today — and overrides the fields its hardware
/// disagrees about:
///
/// ```
/// # use umsh_ux_display_tracker::screen::{Controls, Layout};
/// const LAYOUT: Layout = Layout {
///     controls: Controls::Dpad,
///     ..Layout::OLED_128X64
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub font: &'static MonoFont<'static>,
    /// Left margin for row text.
    pub left: i32,
    /// Top of row 0's glyph band.
    pub top: i32,
    /// Distance between the tops of consecutive rows.
    pub row_pitch: i32,
    /// How many rows fit on the panel.
    pub rows: usize,
    pub size: Size,
    pub battery: BatteryIconMetrics,
    /// How this panel says a list continues past what it can draw.
    pub overflow: Overflow,
    /// What the user drives it with.
    pub controls: Controls,
}

/// How a board shows that a list has more entries than fit.
///
/// One per board, used on every list. Two overflow idioms in one product
/// teach the user to read neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overflow {
    /// Cut the row past the last complete one off half-way, so a partial
    /// row hangs over the bottom. Costs nothing horizontally, which is
    /// what recommends it on a panel already short of characters.
    ClipRow,
    /// A track down the right edge with a thumb sized to the visible
    /// fraction. Takes a column from every row to say how much list there
    /// is and how far through it you are.
    ScrollBar,
}

impl Layout {
    /// 128×64 OLED: five rows of `FONT_6X10`. Shared by the Wio Tracker
    /// L1's SH1106 and the Heltec V3's SSD1306.
    pub const OLED_128X64: Self = Self {
        font: &FONT_6X10,
        left: 0,
        top: 3,
        row_pitch: 12,
        rows: 5,
        size: Size::new(128, 64),
        battery: BatteryIconMetrics::OLED,
        // 21 characters to a row already; a bar would take one of them
        // from every row on the screen.
        overflow: Overflow::ClipRow,
        // The narrower assumption: a board with more controls says so,
        // and one with fewer than a single button has no menu at all.
        controls: Controls::OneButton,
    };

    /// 200×200 e-paper: seven rows of `FONT_10X20`. The T-Echo's SSD1681.
    pub const EPD_200X200: Self = Self {
        font: &FONT_10X20,
        left: 5,
        top: 8,
        row_pitch: 27,
        rows: 7,
        size: Size::new(200, 200),
        battery: BatteryIconMetrics::EPD,
        // 200 px across can spare the column, and a bistable panel is
        // read at leisure, which is when extent is worth knowing.
        overflow: Overflow::ScrollBar,
        controls: Controls::OneButton,
    };

    /// Top of `row`'s glyph band.
    pub const fn row_top(&self, row: usize) -> i32 {
        self.top + row as i32 * self.row_pitch
    }

    /// The full-width band `row` occupies.
    ///
    /// A highlight fills this rather than the glyph cells, so it reads as
    /// a solid bar rather than as emphasized text.
    pub fn row_rect(&self, row: usize) -> Rectangle {
        let top = self.row_top(row);
        let height = self.row_pitch.max(self.font.character_size.height as i32);
        let bottom = (top + height).min(self.size.height as i32);
        Rectangle::new(
            Point::new(0, top),
            Size::new(self.size.width, (bottom - top).max(0) as u32),
        )
    }

    /// The rectangle the battery indicator owns, right-aligned on row 0.
    pub fn battery_zone(&self) -> Rectangle {
        let width = self.battery.zone_width();
        let height = self.battery.body.height;
        let x = self.size.width as i32 - self.battery.margin as i32 - width as i32;
        let y = self.row_top(0) + (self.font.character_size.height as i32 - height as i32) / 2;
        Rectangle::new(Point::new(x, y), Size::new(width, height))
    }
}

// ─── What the frame says ─────────────────────────────────────────────────────

/// How the board's local link is currently reachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// A companion is connected and has a live session.
    Attached,
    /// A companion is connected but has not attached a session.
    Connected,
    /// Nothing is connected; the board is discoverable.
    Advertising,
    /// Advertising is suppressed, typically because a wired host owns the
    /// device.
    OffWired,
    /// The operator turned Bluetooth off. Distinct from `OffWired`: this
    /// device is unreachable because it was told to be, not because a
    /// cable outranks the radio.
    Disabled,
}

/// Whether a companion can pair right now, and with what secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingState {
    /// Too many failed attempts; pairing cannot be opened.
    LockedOut,
    /// A pairing window is open. The panel is the only place the PIN is
    /// ever shown, which is why an open window holds the display awake.
    Open { pin: Option<u32> },
    /// No pairing window is open.
    Closed,
}

/// Charge level and charging state, as far as the board can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatteryIndicator {
    /// `None` when there is no level to show — before the estimator has
    /// had a resting sample, or while charging on a board whose charger
    /// reports no completion. Nothing is drawn in its place.
    pub level_percent: Option<u8>,
    /// `None` on a board whose charger reports nothing to the MCU, which
    /// is different from knowing the pack is discharging.
    pub charge: Option<ChargeClass>,
}

impl BatteryIndicator {
    /// Nothing known yet: no body, no bolt.
    pub const UNKNOWN: Self = Self {
        level_percent: None,
        charge: None,
    };

    /// Whether the indicator should carry a charging bolt.
    ///
    /// `Charged` draws one too, which is a deliberate degradation. The
    /// full vocabulary is a bolt for "charging" and a plug for "charging
    /// complete"; no board in this class can tell the two apart — only
    /// the T-1000E reads a real charge-status line, and it has no panel
    /// — so a board that sees external power flies the bolt for as long
    /// as it is plugged in rather than asserting a completion it never
    /// learns. Add the plug when a display board can substantiate it.
    const fn shows_bolt(&self) -> bool {
        matches!(
            self.charge,
            Some(ChargeClass::Charging) | Some(ChargeClass::Charged)
        )
    }
}

/// Radio activity, for the stats page.
///
/// Counts are cumulative since boot. They saturate rather than wrap: a
/// counter that rolled over would make a long-quiet node look busy, and
/// pinning at the maximum is at least monotone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatsModel {
    pub tx_frames: u32,
    /// Every frame the radio handed up, whoever it was for.
    pub rx_frames: u32,
    /// Receptions that produced an event — addressed to this node, or
    /// forwarded. The shortfall against [`Self::rx_frames`] is other
    /// people's traffic and undecodable noise, shown as "drop".
    pub rx_accepted: u32,
    pub forwarded: u32,
    /// Configured transmit power; `None` until the radio is configured.
    pub tx_power_dbm: Option<i8>,
    /// Duty-cycle usage in tenths of a percent. Trackers normally sit
    /// well under one percent, so whole percent would read zero forever.
    pub duty_permille: u16,
}

impl StatsModel {
    /// Receptions that went nowhere.
    pub const fn rx_dropped(&self) -> u32 {
        self.rx_frames.saturating_sub(self.rx_accepted)
    }
}

/// Everything drawn that is not menu state.
///
/// The firmware assembles this immediately before rendering — the device
/// name in particular comes from an async read, which is why it arrives
/// as a borrowed string rather than being fetched here.
#[derive(Clone, Copy, Debug)]
pub struct StatusModel<'a> {
    pub device_name: &'a str,
    pub battery: BatteryIndicator,
    /// Pack voltage for the status page's diagnostic row. The header icon
    /// is the glanceable reading; this is the one to quote in a bug
    /// report.
    pub battery_mv: Option<u16>,
    pub link: LinkState,
    /// How many companions are bonded. Shown only on the clear-bonds
    /// confirmation, where it says what is about to be destroyed; on the
    /// status page it was a number nobody was deciding anything with.
    /// Running out of slots surfaces as a pairing failure, which is the
    /// moment the capacity matters.
    pub bonds: u8,
    pub pairing: PairingState,
    pub stats: StatsModel,
    /// The local time to show in the header, or `None` when the device
    /// does not know what time it is.
    ///
    /// `None` draws nothing at all — not a placeholder, not dashes, not a
    /// zeroed clock. A device that does not know the time **must not**
    /// indicate one, and enforcing that here rather than in each panel is
    /// what keeps it true: there is no way to render a clock without a
    /// reading to render.
    pub clock: Option<ClockModel>,
    /// The values behind the toggle entries.
    pub settings: SettingsModel,
    /// This device's own address, for the Status and Identity screens.
    pub identity: Option<IdentityModel<'a>>,
}

/// What the toggle entries currently read.
///
/// Every field is an `Option` for the same reason [`StatusModel::clock`]
/// is: a board that cannot say which way a setting is set draws no state
/// rather than a plausible guess. `None` is also what a board without the
/// subsystem reports, and such a board does not enable the entry anyway.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SettingsModel {
    pub bluetooth: Option<bool>,
    pub gnss: Option<bool>,
    pub share_location: Option<bool>,
    pub forwarding: Option<bool>,
}

/// This device's own address, rendered by the firmware.
///
/// Both forms arrive pre-formatted because base58 lives in `umsh-core`,
/// which this crate does not depend on — and because the hint's
/// star-truncated rendering is canonical elsewhere and must not be
/// reinvented here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityModel<'a> {
    /// The four-character node hint, `*` and all. What a person compares
    /// by eye.
    pub hint: &'a str,
    /// The complete 44-character Base58 address. What a machine reads —
    /// and what Identity falls back to on a panel with no room for a
    /// scannable symbol, which today is every panel in the class.
    pub address: &'a str,
}

/// A local wall-clock reading for the header.
///
/// Hours and minutes only. A seconds field would commit every panel to
/// redrawing once a second, which an e-paper cannot do and a
/// battery-powered OLED should not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockModel {
    /// Local hour, 0–23.
    pub hour: u8,
    /// Local minute, 0–59.
    pub minute: u8,
}

impl ClockModel {
    /// Render the status-page row, labeled to match the battery row
    /// beside it — a bare `14:30` on a line of its own reads as a
    /// measurement without a name.
    fn write(&self, out: &mut String<LINE>) {
        let _ = write!(out, "time {:02}:{:02}", self.hour, self.minute);
    }
}

// ─── Entry points ────────────────────────────────────────────────────────────

/// Draw the menu or the confirmation page.
pub fn render_frame<D>(target: &mut D, layout: &Layout, model: &UiModel, status: &StatusModel<'_>)
where
    D: DrawTarget<Color = BinaryColor>,
{
    let _ = target.clear(BinaryColor::Off);
    draw_header(target, layout, status);

    let mut line: String<LINE> = String::new();
    let content_end = match model.page() {
        // The top level is three pages the user walks between, each of
        // them the whole panel: the highlight names what is being read
        // and the rows below are the reading. Everything below the top is
        // only meaningful beside its neighbors, so the list it belongs to
        // is the screen and a Select is what opens one of its entries.
        Page::Menu(MenuItem::Status) => {
            draw_row_inverted(target, layout, 1, menu_label(MenuItem::Status));
            draw_status_page(target, layout, model, status, &mut line)
        }
        Page::Menu(MenuItem::Identity) => {
            draw_row_inverted(target, layout, 1, menu_label(MenuItem::Identity));
            draw_identity_page(target, layout, status)
        }
        // Settings is a doorway and has nothing of its own to say. A page
        // that listed what was behind it read as the list one Select
        // away rather than as the way to it — rows of labels and states,
        // under a bar that looked like a highlight on the first of them.
        // So: its name, centered, and the hint saying what opens it.
        Page::Menu(MenuItem::Settings) => {
            draw_row_centered(target, layout, 1, menu_label(MenuItem::Settings));
            2
        }
        Page::Detail(MenuItem::Stats) => {
            draw_row_inverted(target, layout, 1, menu_label(MenuItem::Stats));
            draw_stats_page(target, layout, status, &mut line)
        }
        // No other entry opens a page yet. Naming it is still better than
        // a blank panel, and better than a list the Select just left.
        Page::Detail(item) => {
            draw_row_inverted(target, layout, 1, menu_label(item));
            2
        }
        Page::Menu(item) => draw_level_list(target, layout, model, status, item),
        Page::Confirm {
            confirm_selected, ..
        } => {
            // The question names the object and its size, which is the
            // only place the bond count changes a decision — and is why
            // the status page no longer spends a row carrying it around.
            write_clear_question(&mut line, status.bonds);
            draw_row(target, layout, 1, &line);
            // The two choices carry the same inversion the menu uses, so
            // "which one is under the cursor" is one question everywhere.
            draw_row_selectable(target, layout, 2, "Cancel", !confirm_selected);
            draw_row_selectable(target, layout, 3, "CLEAR", confirm_selected);
            4
        }
    };

    // The second hint names what Select would actually do here, so it is
    // built rather than picked from a table of literals.
    let mut menu_hints = [move_hint(layout.controls), ""];
    let hints: &[&str] = match model.page() {
        Page::Menu(item) => match select_hint(layout.controls, item) {
            Some(hint) => {
                menu_hints[1] = hint;
                &menu_hints[..]
            }
            None => &menu_hints[..1],
        },
        // A reading page has one question left, so it gets one hint —
        // and it names the gesture that is quickest rather than the only
        // one that works, since every press dismisses it.
        Page::Detail(_) => match layout.controls {
            Controls::OneButton => &["2x: back"],
            Controls::Dpad => &["OK: back"],
        },
        Page::Confirm { .. } => match layout.controls {
            Controls::OneButton => &["1x/hold: toggle", "2x: confirm"],
            Controls::Dpad => &["up/dn: pick", "OK: confirm"],
        },
    };
    draw_hints(target, layout, content_end, hints);
}

/// Draw a short centered message — a pairing window opening, a wipe
/// running, an alert, a farewell.
///
/// The header stays, so the battery is readable even while the board is
/// busy saying something else.
pub fn render_message<D>(
    target: &mut D,
    layout: &Layout,
    status: &StatusModel<'_>,
    title: &str,
    detail: &str,
) where
    D: DrawTarget<Color = BinaryColor>,
{
    let _ = target.clear(BinaryColor::Off);
    draw_header(target, layout, status);
    let title_row = layout.rows / 2;
    draw_row_centered(target, layout, title_row, title);
    draw_row_centered(target, layout, title_row + 1, detail);
}

/// Draw the battery indicator with its zone's top-left corner at
/// `top_left`.
///
/// Public because it is the one piece of this module a richer, more
/// graphical UI would want to keep and reuse verbatim.
pub fn draw_battery_icon<D>(
    target: &mut D,
    top_left: Point,
    metrics: &BatteryIconMetrics,
    indicator: &BatteryIndicator,
) where
    D: DrawTarget<Color = BinaryColor>,
{
    let outline = PrimitiveStyleBuilder::new()
        .stroke_color(BinaryColor::On)
        .stroke_width(metrics.border)
        .stroke_alignment(StrokeAlignment::Inside)
        .build();
    let solid = PrimitiveStyle::with_fill(BinaryColor::On);

    // Two independent facts, drawn independently: whether there is a
    // level to show, and whether the pack is charging. Either, both, or
    // neither.
    //
    // The bolt takes its reserved column beside a body when there is one
    // to sit beside, and the whole zone when there is not. It keeps the
    // zone's right edge either way, so the indicator stays anchored to
    // the same corner whatever it is currently drawing.
    if indicator.shows_bolt() {
        if indicator.level_percent.is_some() {
            draw_bolt(
                target,
                top_left,
                Size::new(metrics.bolt_width, metrics.body.height),
                solid,
            );
        } else {
            let bolt = metrics.solo_bolt;
            let at = Point::new(
                top_left.x + metrics.zone_width().saturating_sub(bolt.width) as i32,
                top_left.y + (metrics.body.height.saturating_sub(bolt.height) / 2) as i32,
            );
            draw_bolt(target, at, bolt, solid);
        }
    }

    // No level, no body. An empty body means a pack down to its last
    // sixth; a level the device has not established is drawn as nothing
    // at all.
    let Some(level) = indicator.level_percent else {
        return;
    };

    let body_left = top_left.x + (metrics.bolt_width + metrics.spacing) as i32;
    let _ = Rectangle::new(Point::new(body_left, top_left.y), metrics.body)
        .into_styled(outline)
        .draw(target);

    let nub_y = top_left.y + (metrics.body.height as i32 - metrics.nub.height as i32) / 2;
    let _ = Rectangle::new(
        Point::new(body_left + metrics.body.width as i32, nub_y),
        metrics.nub,
    )
    .into_styled(solid)
    .draw(target);

    let inset = metrics.border + metrics.pad;
    let inner = Size::new(
        metrics.body.width.saturating_sub(2 * inset),
        metrics.body.height.saturating_sub(2 * inset),
    );
    let lit = u32::from(battery_segments(level));
    let count = u32::from(BATTERY_SEGMENTS);
    let seg_width = inner
        .width
        .saturating_sub(metrics.gap * (count - 1))
        .checked_div(count)
        .unwrap_or(0);
    if seg_width == 0 || inner.height == 0 {
        return;
    }
    for index in 0..lit {
        let x = body_left + inset as i32 + (index * (seg_width + metrics.gap)) as i32;
        let _ = Rectangle::new(
            Point::new(x, top_left.y + inset as i32),
            Size::new(seg_width, inner.height),
        )
        .into_styled(solid)
        .draw(target);
    }
}

// ─── Pages ───────────────────────────────────────────────────────────────────

/// The status page's content rows, packed upward from row 2.
///
/// Only state that departs from nominal earns a row. A closed pairing
/// window and plain advertising are what every tracker does when nothing
/// is happening, and a line that appears on almost every frame trains the
/// user to stop reading it — so neither is drawn, and what is left on a
/// resting device is a single battery line. That is also what gives the
/// five-row panels enough room to show their gesture hints on the page
/// users actually sit on.
///
/// The order is falling importance, so the line a short panel runs out of
/// room for is always the one it can most afford to lose: the battery row
/// duplicates a header icon that is already on screen.
fn draw_status_page<D>(
    target: &mut D,
    layout: &Layout,
    model: &UiModel,
    status: &StatusModel<'_>,
    line: &mut String<LINE>,
) -> usize
where
    D: DrawTarget<Color = BinaryColor>,
{
    let mut row = 2;

    if let Some(notice) = model.notice() {
        draw_row(target, layout, row, notice_label(notice));
        row += 1;
    }

    line.clear();
    if write_pairing(line, status.pairing) {
        draw_row(target, layout, row, line);
        row += 1;
    }

    if let Some(label) = link_label(status.link) {
        draw_row(target, layout, row, label);
        row += 1;
    }

    line.clear();
    write_battery(line, status);
    draw_row(target, layout, row, line);
    row += 1;

    // Last, so that on a panel whose rows have run out the clock is what
    // falls off rather than the battery: how much charge is left is a
    // fact somebody is deciding something with, and what time it is is
    // not. Absent entirely when the device does not know the time —
    // there is no placeholder row, because a row that says the time is
    // unknown is still an indication about the time.
    if let Some(clock) = status.clock {
        line.clear();
        clock.write(line);
        draw_row(target, layout, row, line);
        row += 1;
    }

    row
}

/// Radio activity: what the node has actually done on the air.
///
/// Enough to tell a working node from a deaf one without reaching for a
/// capture — a node whose `rx` never moves is not hearing anybody, and one
/// whose `tx` never moves is not being heard.
fn draw_stats_page<D>(
    target: &mut D,
    layout: &Layout,
    status: &StatusModel<'_>,
    line: &mut String<LINE>,
) -> usize
where
    D: DrawTarget<Color = BinaryColor>,
{
    let stats = status.stats;

    line.clear();
    let _ = write!(line, "tx {}  rx {}", stats.tx_frames, stats.rx_frames);
    draw_row(target, layout, 2, line);

    line.clear();
    let _ = write!(line, "fwd {}  drop {}", stats.forwarded, stats.rx_dropped());
    draw_row(target, layout, 3, line);

    line.clear();
    match stats.tx_power_dbm {
        Some(dbm) => {
            let _ = write!(line, "{dbm} dBm  ");
        }
        None => {
            let _ = write!(line, "-- dBm  ");
        }
    }
    let (whole, tenth) = (stats.duty_permille / 10, stats.duty_permille % 10);
    let _ = write!(line, "duty {whole}.{tenth}%");
    draw_row(target, layout, 4, line);

    5
}

/// Draw this device's address.
///
/// The QR code the spec wants here needs a symbol a camera can resolve —
/// about 110 px square for a `umsh:n:` URI — which neither panel in the
/// class can offer below the header. So both fall back to the address as
/// text, wrapped across the rows below, with the four-character hint
/// above it as the part a person can compare by eye where there is room
/// for both.
fn draw_identity_page<D>(target: &mut D, layout: &Layout, status: &StatusModel<'_>) -> usize
where
    D: DrawTarget<Color = BinaryColor>,
{
    let Some(identity) = status.identity else {
        // No identity yet is a real state on a freshly flashed board, and
        // an empty screen says it better than a row of placeholder.
        return 2;
    };

    // The address is 44 characters and no panel in the class shows more
    // than 21, so it wraps. Splitting on the character grid rather than
    // at a fixed width keeps every chunk the same length, which is what
    // makes a transcription check possible at all.
    let room = layout.size.width.saturating_sub(layout.left.max(0) as u32);
    let per_row = clip(layout, identity.address, room).chars().count().max(1);
    let needed = identity.address.chars().count().div_ceil(per_row);

    // The address goes on whole or not at all. An address cut off at the
    // bottom of the panel is worse than none, because it looks like a
    // complete one — and this screen exists to be transcribed from.
    let mut row = 2;
    let available = layout.rows.saturating_sub(row);
    if needed > available {
        // Not even alone. Show what a person can compare by eye and leave
        // the machine-readable form to the phone.
        draw_row(target, layout, row, identity.hint);
        return row + 1;
    }
    // The hint is what yields the row when both will not fit: the spec
    // offers it as a convenience, and the header still names the device.
    if needed < available {
        draw_row(target, layout, row, identity.hint);
        row += 1;
    }

    let mut rest = identity.address;
    while !rest.is_empty() && row < layout.rows {
        let end = rest
            .char_indices()
            .nth(per_row)
            .map_or(rest.len(), |(at, _)| at);
        let (chunk, remainder) = rest.split_at(end);
        draw_row(target, layout, row, chunk);
        rest = remainder;
        row += 1;
    }
    row
}

/// Draw one settings level as a list, with the highlight on `selected`.
///
/// The window always contains the highlighted entry drawn complete: a
/// Select against a row the user can only half read is a guess.
fn draw_level_list<D>(
    target: &mut D,
    layout: &Layout,
    model: &UiModel,
    status: &StatusModel<'_>,
    selected: MenuItem,
) -> usize
where
    D: DrawTarget<Color = BinaryColor>,
{
    let level = selected.level();
    let items = model.items();
    let count = items.entries(level).count();
    let index = items
        .entries(level)
        .position(|item| item == selected)
        .unwrap_or(0);

    // Rows 1.. belong to the list; row 0 is the header.
    let available = layout.rows.saturating_sub(1);
    let overflows = count > available;
    // With a clipped row the last slot shows a partial entry, so one
    // fewer entry is drawn complete. A scroll bar costs width, not rows.
    let visible = match (overflows, layout.overflow) {
        (true, Overflow::ClipRow) => available.saturating_sub(1).max(1),
        _ => available,
    };

    let start = if index < visible {
        0
    } else {
        (index + 1 - visible).min(count.saturating_sub(visible))
    };

    let mut line: String<LINE> = String::new();
    for (offset, item) in items.entries(level).skip(start).take(visible).enumerate() {
        line.clear();
        write_entry(&mut line, item, &status.settings);
        draw_row_selectable(target, layout, 1 + offset, &line, item == selected);
    }

    if !overflows {
        return 1 + count;
    }

    match layout.overflow {
        Overflow::ClipRow => {
            let after = start + visible;
            if let Some(item) = items.entries(level).nth(after) {
                line.clear();
                write_entry(&mut line, item, &status.settings);
                draw_clipped_row(target, layout, 1 + visible, &line);
            }
        }
        Overflow::ScrollBar => draw_scroll_bar(target, layout, count, start, visible),
    }
    layout.rows
}

/// An entry's name and, for a toggle, the state it is in.
fn write_entry(line: &mut String<LINE>, item: MenuItem, settings: &SettingsModel) {
    let _ = write!(line, "{}", menu_label(item));
    let state = toggle_label(item, settings);
    if !state.is_empty() {
        let _ = write!(line, "  {state}");
    }
}

/// Draw a row cut off half-way by the bottom of the panel.
///
/// The clip is explicit rather than left to the panel: a partially
/// off-target row is a bug everywhere else, and the test panel rightly
/// asserts on one.
fn draw_clipped_row<D>(target: &mut D, layout: &Layout, row: usize, text: &str)
where
    D: DrawTarget<Color = BinaryColor>,
{
    let band = layout.row_rect(row);
    let half = Rectangle::new(
        band.top_left,
        Size::new(band.size.width, band.size.height / 2),
    );
    if half.size.height == 0 {
        return;
    }
    let mut clipped = target.clipped(&half);
    draw_row(&mut clipped, layout, row, text);
}

/// Draw the scroll bar: a track down the right edge with a thumb sized to
/// the visible fraction and placed at the current position.
fn draw_scroll_bar<D>(target: &mut D, layout: &Layout, count: usize, start: usize, visible: usize)
where
    D: DrawTarget<Color = BinaryColor>,
{
    if count == 0 {
        return;
    }
    let width = layout.battery.border.max(2);
    let x = layout.size.width as i32 - width as i32;
    let top = layout.row_top(1);
    let bottom = layout.size.height as i32;
    let height = (bottom - top).max(0) as u32;
    if height == 0 {
        return;
    }

    let track = Rectangle::new(Point::new(x, top), Size::new(width, height));
    let _ = track
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(BinaryColor::On)
                .stroke_width(1)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(target);

    let thumb_height = ((height as usize * visible.min(count)) / count).max(2) as u32;
    let span = height.saturating_sub(thumb_height);
    let scrollable = count.saturating_sub(visible).max(1);
    let offset = (span as usize * start.min(scrollable)) / scrollable;
    let thumb = Rectangle::new(
        Point::new(x, top + offset as i32),
        Size::new(width, thumb_height.min(height)),
    );
    let _ = thumb
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(target);
}

// ─── Drawing helpers ─────────────────────────────────────────────────────────

fn draw_header<D>(target: &mut D, layout: &Layout, status: &StatusModel<'_>)
where
    D: DrawTarget<Color = BinaryColor>,
{
    // The battery owns its corner: the name is cut to the room left over
    // rather than being allowed to run under the indicator and off the
    // panel. Blanking the zone afterwards keeps that true no matter what
    // else the header grows.
    //
    // The clock is deliberately *not* here. It fits, but only by taking
    // the room from the device name, and on the 200 px e-paper's
    // twenty-pixel font that cut the name from fourteen characters to
    // seven — which across a fleet of `umsh-`-prefixed radios is the
    // difference between identifying one and guessing. The clock lives on
    // the status page instead, where a row costs nothing that was being
    // read.
    let zone = layout.battery_zone();
    let room = (zone.top_left.x - layout.left).max(0) as u32;
    draw_row(target, layout, 0, clip(layout, status.device_name, room));
    let _ = zone
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::Off))
        .draw(target);
    draw_battery_icon(target, zone.top_left, &layout.battery, &status.battery);
}

/// Longest prefix of `text` that fits in `width` pixels.
fn clip<'a>(layout: &Layout, text: &'a str, width: u32) -> &'a str {
    let advance = layout.font.character_size.width + layout.font.character_spacing;
    if advance == 0 {
        return text;
    }
    let fits = (width / advance) as usize;
    match text.char_indices().nth(fits) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

fn draw_row<D>(target: &mut D, layout: &Layout, row: usize, text: &str)
where
    D: DrawTarget<Color = BinaryColor>,
{
    if row >= layout.rows || text.is_empty() {
        return;
    }
    let room = layout.size.width.saturating_sub(layout.left.max(0) as u32);
    let text = clip(layout, text, room);
    draw_text(
        target,
        layout,
        Point::new(layout.left, layout.row_top(row)),
        text,
    );
}

fn draw_row_centered<D>(target: &mut D, layout: &Layout, row: usize, text: &str)
where
    D: DrawTarget<Color = BinaryColor>,
{
    if row >= layout.rows || text.is_empty() {
        return;
    }
    let advance = layout.font.character_size.width + layout.font.character_spacing;
    let text = clip(layout, text, layout.size.width);
    let width = advance.saturating_mul(text.chars().count() as u32);
    let x = (layout.size.width.saturating_sub(width) / 2) as i32;
    draw_text(target, layout, Point::new(x, layout.row_top(row)), text);
}

fn draw_text<D>(target: &mut D, layout: &Layout, at: Point, text: &str)
where
    D: DrawTarget<Color = BinaryColor>,
{
    let style = MonoTextStyle::new(layout.font, BinaryColor::On);
    let _ = Text::with_baseline(text, at, style, Baseline::Top).draw(target);
}

/// Draw `row` inverted: the panel's foreground and background swap across
/// the whole width of the row, including the space either side of the
/// label.
///
/// Inversion survives everything these panels do badly. It needs no color,
/// no second font, and no glyph column stolen from a row that is already
/// narrow, and it is legible on a monochrome OLED at a glance and on a
/// bistable panel with no backlight. Filling the band and *then* drawing
/// the glyphs on their own inverted background is what makes it one solid
/// bar rather than a row of boxed letters.
fn draw_row_inverted<D>(target: &mut D, layout: &Layout, row: usize, text: &str)
where
    D: DrawTarget<Color = BinaryColor>,
{
    if row >= layout.rows {
        return;
    }
    let band = layout.row_rect(row);
    let _ = band
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(target);

    let room = layout.size.width.saturating_sub(layout.left.max(0) as u32);
    let text = clip(layout, text, room);
    if text.is_empty() {
        return;
    }
    let style = MonoTextStyleBuilder::new()
        .font(layout.font)
        .text_color(BinaryColor::Off)
        .background_color(BinaryColor::On)
        .build();
    let _ = Text::with_baseline(
        text,
        Point::new(layout.left, layout.row_top(row)),
        style,
        Baseline::Top,
    )
    .draw(target);
}

/// Draw a row highlighted or plain, so callers stop repeating the choice.
fn draw_row_selectable<D>(target: &mut D, layout: &Layout, row: usize, text: &str, selected: bool)
where
    D: DrawTarget<Color = BinaryColor>,
{
    if selected {
        draw_row_inverted(target, layout, row, text);
    } else {
        draw_row(target, layout, row, text);
    }
}

/// Park the gesture hints against the bottom of the panel, dropping them
/// from the front when the page has left fewer rows than there are hints.
///
/// This is what lets one renderer serve both panel shapes: the five-row
/// OLED silently loses both hints on the crowded status page and keeps
/// the last one on the confirmation page, while the seven-row e-paper has
/// room for both everywhere.
fn draw_hints<D>(target: &mut D, layout: &Layout, content_end: usize, hints: &[&str])
where
    D: DrawTarget<Color = BinaryColor>,
{
    let shown = hints.len().min(layout.rows.saturating_sub(content_end));
    let first_row = layout.rows - shown;
    for (offset, hint) in hints[hints.len() - shown..].iter().enumerate() {
        draw_row(target, layout, first_row + offset, hint);
    }
}

fn draw_bolt<D>(target: &mut D, top_left: Point, size: Size, style: PrimitiveStyle<BinaryColor>)
where
    D: DrawTarget<Color = BinaryColor>,
{
    let (x, y) = (top_left.x, top_left.y);
    let (w, h) = (size.width as i32, size.height as i32);
    // Two overlapping wedges: the upper one falls left, the lower one
    // rises right, and the rows they share join them into one stroke.
    let upper = Triangle::new(
        Point::new(x + w * 2 / 3, y),
        Point::new(x, y + h * 3 / 5),
        Point::new(x + w * 2 / 3, y + h * 3 / 5),
    );
    let lower = Triangle::new(
        Point::new(x + w / 3, y + h - 1),
        Point::new(x + w - 1, y + h * 2 / 5),
        Point::new(x + w / 3, y + h * 2 / 5),
    );
    let _ = upper.into_styled(style).draw(target);
    let _ = lower.into_styled(style).draw(target);
}

// ─── Strings ─────────────────────────────────────────────────────────────────

/// The entry's name, with no cursor decoration — the highlight is the
/// inversion, not a prefix.
///
/// Back reads as the way out of the level it sits in rather than naming
/// the destination, because that is the word the user is looking for.
const fn menu_label(item: MenuItem) -> &'static str {
    match item {
        MenuItem::Status => "Status",
        MenuItem::Identity => "Identity",
        MenuItem::Settings => "Settings",
        MenuItem::SettingsBack
        | MenuItem::BluetoothBack
        | MenuItem::GnssBack
        | MenuItem::RadioBack => "Back",
        MenuItem::Bluetooth => "Bluetooth",
        MenuItem::Gnss => "GNSS",
        MenuItem::Radio => "Radio",
        MenuItem::BluetoothToggle => "Bluetooth",
        MenuItem::StartPairing => "Start pairing",
        MenuItem::ClearBonds => "Clear bonds",
        MenuItem::GnssToggle => "GNSS",
        MenuItem::ShareLocation => "Share location",
        MenuItem::Forwarding => "Forwarding",
        MenuItem::Stats => "Statistics",
    }
}

/// How this board says "move to the next entry".
const fn move_hint(controls: Controls) -> &'static str {
    match controls {
        Controls::OneButton => "1x: next",
        Controls::Dpad => "up/dn: move",
    }
}

/// What a Select would do from this entry, or `None` where it would do
/// nothing and the hint would be a lie.
///
/// The verb comes from the entry and the gesture from the hardware, so
/// the two tables below say the same things in each board's own words.
/// A reading entry is the one whose verb depends on where it sits: at the
/// top level it is already the whole screen and Select has nothing left
/// to do, while below the top it is a row that Select opens.
const fn select_hint(controls: Controls, item: MenuItem) -> Option<&'static str> {
    let reading_opens = matches!(item.kind(), EntryKind::Reading(_)) && !item.reads_in_place();
    match (controls, item.kind()) {
        (Controls::OneButton, _) if reading_opens => Some("2x: open"),
        (Controls::Dpad, _) if reading_opens => Some("OK: open"),
        (_, EntryKind::Reading(None)) => None,
        (Controls::OneButton, kind) => Some(match kind {
            EntryKind::Reading(Some(UiEffect::CheckIn)) => "2x: check in",
            EntryKind::Submenu(_) => "2x: open",
            EntryKind::Back => "2x: back",
            EntryKind::Toggle(_) => "2x: toggle",
            _ => "2x: select",
        }),
        (Controls::Dpad, kind) => Some(match kind {
            EntryKind::Reading(Some(UiEffect::CheckIn)) => "OK: check in",
            EntryKind::Submenu(_) => "OK: open",
            EntryKind::Back => "OK: back",
            EntryKind::Toggle(_) => "OK: toggle",
            _ => "OK: select",
        }),
    }
}

/// The state a toggle entry reports, drawn after its name.
///
/// A board that cannot say draws nothing rather than guessing, which is
/// why this returns an empty string rather than "off".
fn toggle_label(item: MenuItem, settings: &SettingsModel) -> &'static str {
    let value = match item.kind() {
        EntryKind::Toggle(ToggleId::Bluetooth) => settings.bluetooth,
        EntryKind::Toggle(ToggleId::Gnss) => settings.gnss,
        EntryKind::Toggle(ToggleId::ShareLocation) => settings.share_location,
        EntryKind::Toggle(ToggleId::Forwarding) => settings.forwarding,
        _ => return "",
    };
    match value {
        Some(true) => "on",
        Some(false) => "off",
        None => "",
    }
}

const fn notice_label(notice: UiNotice) -> &'static str {
    match notice {
        UiNotice::CheckInRequested => "checking in...",
        UiNotice::PairingStarted => "pairing started",
        UiNotice::PairingUnavailable => "pair unavailable",
        UiNotice::BondsCleared => "bonds cleared",
        UiNotice::ClearFailed => "CLEAR FAILED",
        UiNotice::ToggleUnavailable => "not available",
    }
}

/// The link line, or `None` when there is nothing worth a row.
///
/// Advertising is what a tracker does whenever nobody is talking to it, so
/// announcing it says only that the device is behaving normally. What
/// earns a row is a host actually being on the other end, or advertising
/// being suppressed — the case where a user looking for the device on a
/// phone would otherwise be left wondering.
const fn link_label(link: LinkState) -> Option<&'static str> {
    match link {
        LinkState::Attached => Some("host attached"),
        LinkState::Connected => Some("host connected"),
        LinkState::OffWired => Some("off (wired)"),
        LinkState::Disabled => Some("off"),
        LinkState::Advertising => None,
    }
}

/// Write the pairing line, reporting whether it wrote anything.
///
/// A closed window is the resting state of every tracker; saying so costs
/// a row to report that nothing is happening.
fn write_pairing(line: &mut String<LINE>, pairing: PairingState) -> bool {
    let _ = match pairing {
        PairingState::LockedOut => write!(line, "PAIR LOCKED"),
        PairingState::Open { pin: Some(pin) } => write!(line, "PIN {pin:06}"),
        PairingState::Open { pin: None } => write!(line, "pairing (no PIN)"),
        PairingState::Closed => return false,
    };
    true
}

fn write_clear_question(line: &mut String<LINE>, bonds: u8) {
    let _ = match bonds {
        0 => write!(line, "No bonds to clear"),
        1 => write!(line, "Clear 1 bond?"),
        n => write!(line, "Clear {n} bonds?"),
    };
}

fn write_battery(line: &mut String<LINE>, status: &StatusModel<'_>) {
    let Some(mv) = status.battery_mv else {
        let _ = write!(line, "batt --");
        return;
    };
    let _ = write!(line, "batt {mv} mV");
    match status.battery.level_percent {
        Some(level) => {
            let _ = write!(line, " {level}%");
        }
        // Charging with no level is a known state, not a stalled reading,
        // so the row says which one it is rather than trailing off.
        None if status.battery.shows_bolt() => {
            let _ = write!(line, " chg");
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::menu::{Level, MenuItems, UiInput};

    /// Widest panel in the class, bit-packed: 200 × 200 costs 5 kB, which
    /// a test can keep several of without thinking about it.
    const TEST_PANEL_BYTES: usize = 200 * 200 / 8;

    /// A plain bitmap `DrawTarget` so the tests can ask what actually
    /// landed on the glass rather than trusting the call sequence.
    struct TestPanel {
        size: Size,
        pixels: [u8; TEST_PANEL_BYTES],
    }

    impl TestPanel {
        fn new(size: Size) -> Self {
            assert!((size.width * size.height) as usize <= TEST_PANEL_BYTES * 8);
            Self {
                size,
                pixels: [0; TEST_PANEL_BYTES],
            }
        }

        fn lit(&self, x: u32, y: u32) -> bool {
            let bit = y * self.size.width + x;
            self.pixels[(bit / 8) as usize] & (1 << (bit % 8)) != 0
        }

        /// How many pixels are lit inside `area`.
        fn lit_in(&self, area: Rectangle) -> usize {
            let mut count = 0;
            for y in area.top_left.y..area.top_left.y + area.size.height as i32 {
                for x in area.top_left.x..area.top_left.x + area.size.width as i32 {
                    if x >= 0
                        && y >= 0
                        && (x as u32) < self.size.width
                        && (y as u32) < self.size.height
                        && self.lit(x as u32, y as u32)
                    {
                        count += 1;
                    }
                }
            }
            count
        }
    }

    impl OriginDimensions for TestPanel {
        fn size(&self) -> Size {
            self.size
        }
    }

    impl DrawTarget for TestPanel {
        type Color = BinaryColor;
        type Error = core::convert::Infallible;

        fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
        where
            I: IntoIterator<Item = Pixel<BinaryColor>>,
        {
            for Pixel(Point { x, y }, color) in pixels {
                // Anything drawn off-panel is a layout bug, not something
                // to silently absorb the way a real driver would.
                assert!(
                    x >= 0
                        && y >= 0
                        && (x as u32) < self.size.width
                        && (y as u32) < self.size.height,
                    "drew outside the panel at ({x}, {y}) on {:?}",
                    self.size
                );
                let bit = y as u32 * self.size.width + x as u32;
                let mask = 1 << (bit % 8);
                if color.is_on() {
                    self.pixels[(bit / 8) as usize] |= mask;
                } else {
                    self.pixels[(bit / 8) as usize] &= !mask;
                }
            }
            Ok(())
        }
    }

    fn demo_status() -> StatusModel<'static> {
        StatusModel {
            device_name: "umsh-tracker",
            battery: BatteryIndicator {
                level_percent: Some(75),
                charge: Some(ChargeClass::Discharging),
            },
            battery_mv: Some(3_950),
            link: LinkState::Advertising,
            bonds: 1,
            pairing: PairingState::Closed,
            stats: StatsModel {
                tx_frames: 12,
                rx_frames: 340,
                rx_accepted: 300,
                forwarded: 7,
                tx_power_dbm: Some(22),
                duty_permille: 4,
            },
            // The device does not know what time it is, which is the
            // state every panel must render as no clock at all.
            clock: None,
            settings: SettingsModel {
                bluetooth: Some(true),
                gnss: Some(false),
                share_location: Some(false),
                forwarding: Some(true),
            },
            identity: Some(IdentityModel {
                hint: "7bQ*",
                address: "1BvYtT4nCJmqvKGpZbW8XdRfLhNs2eQaUxAyDzMr6HkP",
            }),
        }
    }

    fn layouts() -> [Layout; 2] {
        [Layout::OLED_128X64, Layout::EPD_200X200]
    }

    /// Walk to `item` within the level it lives in.
    fn walk_to(model: &mut UiModel, item: MenuItem) {
        for _ in 0..MenuItem::ALL.len() + 1 {
            if model.page() == Page::Menu(item) {
                return;
            }
            model.apply(UiInput::Forward);
        }
        panic!("never reached {item:?}");
    }

    /// Descend from home into `item`'s level and highlight it.
    fn navigate_to(model: &mut UiModel, item: MenuItem) {
        let level = item.level();
        if level != Level::Top {
            walk_to(model, MenuItem::Settings);
            model.apply(UiInput::Select);
            if let Some(opener) = level.opened_by() {
                if opener.level() != Level::Top {
                    walk_to(model, opener);
                    model.apply(UiInput::Select);
                }
            }
        }
        walk_to(model, item);
    }

    #[test]
    fn segments_center_each_bar_count_on_the_level_it_depicts() {
        assert_eq!(battery_segments(0), 0);
        assert_eq!(battery_segments(14), 0);
        assert_eq!(battery_segments(15), 1);
        assert_eq!(battery_segments(36), 1);
        assert_eq!(battery_segments(37), 2);
        assert_eq!(battery_segments(62), 2);
        assert_eq!(battery_segments(63), 3);
        assert_eq!(battery_segments(84), 3);
        assert_eq!(battery_segments(85), 4);
        assert_eq!(battery_segments(100), 4);
        // Clamped rather than wrapped, so a bad sample cannot overdraw.
        assert_eq!(battery_segments(200), 4);

        // Just over half draws half a body, not three quarters of one.
        assert_eq!(battery_segments(55), 2);

        // Never falls as the level rises, and never overdraws.
        let mut previous = 0;
        for level in 0..=255u8 {
            let bars = battery_segments(level);
            assert!(bars >= previous, "{level} % lost a bar");
            assert!(bars <= BATTERY_SEGMENTS, "{level} % overdrew");
            previous = bars;
        }
    }

    /// The requirement that started this: a battery reading on every
    /// frame the user can be looking at, on every board.
    #[test]
    fn every_frame_kind_carries_the_battery_indicator() {
        for layout in layouts() {
            let zone = layout.battery_zone();
            let mut model = UiModel::new(MenuItems::all());

            let mut panel = TestPanel::new(layout.size);
            render_frame(&mut panel, &layout, &model, &demo_status());
            assert!(panel.lit_in(zone) > 0, "menu frame lost the battery");

            let mut panel = TestPanel::new(layout.size);
            render_message(
                &mut panel,
                &layout,
                &demo_status(),
                "Clearing",
                "bonds + PIN...",
            );
            assert!(panel.lit_in(zone) > 0, "message frame lost the battery");

            // Walk to the destructive item and open its confirmation.
            navigate_to(&mut model, MenuItem::ClearBonds);
            model.apply(UiInput::Select);
            assert!(matches!(model.page(), Page::Confirm { .. }));
            let mut panel = TestPanel::new(layout.size);
            render_frame(&mut panel, &layout, &model, &demo_status());
            assert!(panel.lit_in(zone) > 0, "confirm frame lost the battery");

            // And the reading page a submenu entry opens.
            let mut model = UiModel::new(MenuItems::all());
            navigate_to(&mut model, MenuItem::Stats);
            model.apply(UiInput::Select);
            assert!(matches!(model.page(), Page::Detail(_)));
            let mut panel = TestPanel::new(layout.size);
            render_frame(&mut panel, &layout, &model, &demo_status());
            assert!(panel.lit_in(zone) > 0, "detail frame lost the battery");
        }
    }

    /// Whether the panel renders `text` as one of its rows.
    ///
    /// Draws the row alone on a reference panel and checks every lit
    /// pixel of it is also lit on `panel` — the closest a bitmap target
    /// gets to reading text back off the glass.
    fn shows_row(panel: &TestPanel, layout: &Layout, text: &str) -> bool {
        (1..layout.rows).any(|row| {
            let mut reference = TestPanel::new(layout.size);
            draw_row(&mut reference, layout, row, text);
            let top = layout.row_top(row);
            let bottom = top + layout.font.character_size.height as i32;
            let mut any = false;
            for y in top..bottom {
                for x in 0..layout.size.width {
                    if reference.lit(x, y as u32) {
                        any = true;
                        if !panel.lit(x, y as u32) {
                            return false;
                        }
                    }
                }
            }
            any
        })
    }

    /// The requirement this whole feature is conditioned on: a device
    /// that does not know what time it is shows **nothing** about the
    /// time — not a placeholder, not zeros, not dashes, and not a row
    /// saying it does not know.
    #[test]
    fn an_unknown_time_draws_no_clock_at_all() {
        for layout in layouts() {
            let mut status = demo_status();
            status.pairing = PairingState::Closed;

            let mut known = TestPanel::new(layout.size);
            status.clock = Some(ClockModel {
                hour: 23,
                minute: 5,
            });
            render_frame(
                &mut known,
                &layout,
                &UiModel::new(MenuItems::all()),
                &status,
            );
            assert!(
                shows_row(&known, &layout, "time 23:05"),
                "the reference case drew no clock, so the negative proves nothing"
            );

            let mut unknown = TestPanel::new(layout.size);
            status.clock = None;
            render_frame(
                &mut unknown,
                &layout,
                &UiModel::new(MenuItems::all()),
                &status,
            );
            assert!(
                !shows_row(&unknown, &layout, "time 23:05"),
                "a device that does not know the time indicated one"
            );
            // The row is absent rather than blanked, so nothing about the
            // time is left on the panel at all.
            for label in ["time --:--", "time 00:00", "time"] {
                assert!(
                    !shows_row(&unknown, &layout, label),
                    "an unset clock rendered {label:?}"
                );
            }
        }
    }

    #[test]
    fn a_known_time_draws_a_clock_row_on_the_status_page() {
        for layout in layouts() {
            let mut status = demo_status();
            // A quiet device, so the status page has room for every row
            // it wants; the crowding behavior has its own test.
            status.pairing = PairingState::Closed;

            for (clock, expected) in [
                (
                    ClockModel {
                        hour: 23,
                        minute: 5,
                    },
                    "time 23:05",
                ),
                // Midnight is a real reading, not an absent one: 00:00
                // must draw, or the minute a day it is midnight would
                // look like a device that has forgotten the time.
                (ClockModel { hour: 0, minute: 0 }, "time 00:00"),
            ] {
                status.clock = Some(clock);
                let mut panel = TestPanel::new(layout.size);
                render_frame(
                    &mut panel,
                    &layout,
                    &UiModel::new(MenuItems::all()),
                    &status,
                );
                assert!(
                    shows_row(&panel, &layout, expected),
                    "the status page lost {expected:?}"
                );
            }
        }
    }

    /// The clock lives in the body, so it takes nothing from the header —
    /// a long device name reads exactly as far as it did before there was
    /// a clock at all.
    #[test]
    fn the_clock_costs_the_device_name_nothing() {
        for layout in layouts() {
            let header = Rectangle::new(
                Point::new(0, layout.row_top(0)),
                Size::new(layout.size.width, layout.font.character_size.height),
            );
            let mut status = demo_status();
            status.device_name = "a-very-long-device-name-indeed";

            let mut without = TestPanel::new(layout.size);
            status.clock = None;
            render_frame(
                &mut without,
                &layout,
                &UiModel::new(MenuItems::all()),
                &status,
            );

            let mut with = TestPanel::new(layout.size);
            status.clock = Some(ClockModel {
                hour: 14,
                minute: 30,
            });
            render_frame(&mut with, &layout, &UiModel::new(MenuItems::all()), &status);

            assert!(without.lit_in(header) > 0, "the name drew nothing");
            assert_eq!(
                with.lit_in(header),
                without.lit_in(header),
                "the clock moved the header"
            );
        }
    }

    /// On a panel that has run out of rows the clock is what falls off,
    /// never the battery: how much charge is left is a fact somebody is
    /// deciding something with, and what time it is is not.
    #[test]
    fn a_crowded_status_page_drops_the_clock_before_the_battery() {
        // The five-row OLED with every optional row asking for space.
        let layout = Layout::OLED_128X64;
        let mut status = demo_status();
        status.pairing = PairingState::Open { pin: Some(123_456) };
        status.link = LinkState::Attached;
        status.clock = Some(ClockModel {
            hour: 14,
            minute: 30,
        });

        let mut panel = TestPanel::new(layout.size);
        render_frame(
            &mut panel,
            &layout,
            &UiModel::new(MenuItems::all()),
            &status,
        );
        assert!(
            shows_row(&panel, &layout, "batt 3950 mV 75%"),
            "the battery row was displaced"
        );
        assert!(
            !shows_row(&panel, &layout, "time 14:30"),
            "the clock survived a page with no room for it"
        );
    }

    #[test]
    fn fill_grows_with_the_level_and_an_unknown_level_draws_nothing() {
        for layout in layouts() {
            let zone = layout.battery_zone();
            let mut previous = 0;
            // One level from each of the five bands, lowest first.
            for level in [5, 25, 50, 75, 100] {
                let mut panel = TestPanel::new(layout.size);
                let mut status = demo_status();
                status.battery.level_percent = Some(level);
                render_frame(
                    &mut panel,
                    &layout,
                    &UiModel::new(MenuItems::all()),
                    &status,
                );
                let lit = panel.lit_in(zone);
                assert!(lit > previous, "level {level} did not add fill");
                previous = lit;
            }

            // An empty body means a flat pack, and only that. "No
            // reading" is said by drawing no indicator at all.
            let mut flat = TestPanel::new(layout.size);
            let mut status = demo_status();
            status.battery.level_percent = Some(0);
            render_frame(&mut flat, &layout, &UiModel::new(MenuItems::all()), &status);
            assert!(flat.lit_in(zone) > 0, "a flat pack drew no body at all");

            let mut unknown = TestPanel::new(layout.size);
            let mut status = demo_status();
            status.battery = BatteryIndicator::UNKNOWN;
            render_frame(
                &mut unknown,
                &layout,
                &UiModel::new(MenuItems::all()),
                &status,
            );
            assert_eq!(
                unknown.lit_in(zone),
                0,
                "an unknown level drew something in the zone"
            );
        }
    }

    /// The bolt has its own reserved column, so a charger going in must
    /// not shift the body — on the e-paper that is the difference between
    /// re-inking a bolt and re-inking the whole header.
    #[test]
    fn charging_adds_a_bolt_without_moving_the_body() {
        for layout in layouts() {
            let zone = layout.battery_zone();
            let body = Rectangle::new(
                Point::new(
                    zone.top_left.x + (layout.battery.bolt_width + layout.battery.spacing) as i32,
                    zone.top_left.y,
                ),
                Size::new(
                    layout.battery.body.width + layout.battery.nub.width,
                    layout.battery.body.height,
                ),
            );
            let bolt = Rectangle::new(
                zone.top_left,
                Size::new(layout.battery.bolt_width, zone.size.height),
            );

            let mut idle = TestPanel::new(layout.size);
            let mut status = demo_status();
            status.battery.charge = Some(ChargeClass::Discharging);
            render_frame(&mut idle, &layout, &UiModel::new(MenuItems::all()), &status);

            let mut charging = TestPanel::new(layout.size);
            let mut status = demo_status();
            status.battery.charge = Some(ChargeClass::Charging);
            render_frame(
                &mut charging,
                &layout,
                &UiModel::new(MenuItems::all()),
                &status,
            );

            assert_eq!(
                idle.lit_in(bolt),
                0,
                "a discharging pack drew something in the bolt slot"
            );
            assert!(charging.lit_in(bolt) > 0, "charging drew no bolt");
            assert_eq!(
                idle.lit_in(body),
                charging.lit_in(body),
                "the body moved when the charger went in"
            );
        }
    }

    /// The indicator must stay inside the rectangle the layout reserved
    /// for it — that rectangle is what the header blanks before drawing,
    /// and anything spilling out of it lands on top of the device name.
    #[test]
    fn the_indicator_stays_inside_its_zone() {
        for layout in layouts() {
            let zone = layout.battery_zone();
            for charge in [
                None,
                Some(ChargeClass::Discharging),
                Some(ChargeClass::Charging),
                Some(ChargeClass::Charged),
            ] {
                for level in [None, Some(0), Some(1), Some(50), Some(100)] {
                    let mut panel = TestPanel::new(layout.size);
                    draw_battery_icon(
                        &mut panel,
                        zone.top_left,
                        &layout.battery,
                        &BatteryIndicator {
                            level_percent: level,
                            charge,
                        },
                    );
                    let whole = Rectangle::new(Point::zero(), layout.size);
                    assert_eq!(
                        panel.lit_in(whole),
                        panel.lit_in(zone),
                        "{charge:?}/{level:?} drew outside the reserved zone on {:?}",
                        layout.size
                    );
                }
            }
        }
    }

    /// A board with no charger telemetry says nothing rather than
    /// claiming the pack is discharging.
    #[test]
    fn unknown_charge_state_draws_no_bolt() {
        let layout = Layout::OLED_128X64;
        let zone = layout.battery_zone();
        let bolt = Rectangle::new(
            zone.top_left,
            Size::new(layout.battery.bolt_width, zone.size.height),
        );
        let mut panel = TestPanel::new(layout.size);
        let mut status = demo_status();
        status.battery.charge = None;
        render_frame(
            &mut panel,
            &layout,
            &UiModel::new(MenuItems::all()),
            &status,
        );
        assert_eq!(panel.lit_in(bolt), 0);
    }

    /// A name long enough to run under the indicator must lose, not
    /// smear into it.
    #[test]
    fn an_overlong_device_name_never_reaches_the_indicator() {
        for layout in layouts() {
            let zone = layout.battery_zone();
            let mut panel = TestPanel::new(layout.size);
            let mut status = demo_status();
            status.device_name = "a-very-long-device-name-that-runs-off-the-panel";
            status.battery = BatteryIndicator::UNKNOWN;
            render_frame(
                &mut panel,
                &layout,
                &UiModel::new(MenuItems::all()),
                &status,
            );

            // Whatever is in the zone is the empty body and nothing else.
            let mut bare = TestPanel::new(layout.size);
            let mut short = status;
            short.device_name = "x";
            render_frame(&mut bare, &layout, &UiModel::new(MenuItems::all()), &short);
            assert_eq!(panel.lit_in(zone), bare.lit_in(zone));
        }
    }

    /// A resting device says one thing — its battery — and the rows that
    /// frees are exactly what the five-row panel needed for its gesture
    /// hints. This is the payoff for dropping the nominal-state rows.
    #[test]
    fn a_nominal_status_page_leaves_room_for_the_hints() {
        let model = UiModel::new(MenuItems::all());
        let status = demo_status();
        assert_eq!(status.pairing, PairingState::Closed);
        assert_eq!(status.link, LinkState::Advertising);

        let oled = Layout::OLED_128X64;
        let mut panel = TestPanel::new(oled.size);
        render_frame(&mut panel, &oled, &model, &status);
        // Row 2 is the battery line; rows 3 and 4 are the two hints.
        for row in 2..oled.rows {
            assert!(panel.lit_in(row_area(&oled, row)) > 0, "row {row} is blank");
        }

        let epd = Layout::EPD_200X200;
        let mut panel = TestPanel::new(epd.size);
        render_frame(&mut panel, &epd, &model, &status);
        // Hints bottom-align, so the taller panel leaves the gap in the
        // middle rather than trailing empty rows under the text.
        assert!(panel.lit_in(row_area(&epd, 2)) > 0);
        assert!(panel.lit_in(row_area(&epd, 5)) > 0);
        assert!(panel.lit_in(row_area(&epd, 6)) > 0);
    }

    /// A hint that names a gesture the board does not have is worse than
    /// no hint: every string has to be in the vocabulary of the hardware
    /// it is drawn on, and has to fit the narrowest panel in the class.
    #[test]
    fn each_control_set_is_hinted_in_its_own_words() {
        // 128 px of FONT_6X10.
        let budget = (Layout::OLED_128X64.size.width / 6) as usize;
        for controls in [Controls::OneButton, Controls::Dpad] {
            let clicks = controls == Controls::OneButton;
            let mut hints: heapless::Vec<&str, 24> = heapless::Vec::new();
            hints.push(move_hint(controls)).unwrap();
            for item in MenuItem::ALL {
                // Which entries answer a Select is a property of the
                // entry, so the two vocabularies must agree about it.
                assert_eq!(
                    select_hint(controls, item).is_some(),
                    select_hint(Controls::OneButton, item).is_some(),
                    "{controls:?} disagrees about {item:?}"
                );
                if let Some(hint) = select_hint(controls, item) {
                    let _ = hints.push(hint);
                }
            }
            for hint in hints {
                assert_eq!(
                    hint.contains("1x") || hint.contains("2x"),
                    clicks,
                    "{controls:?} hint {hint:?} counts clicks"
                );
                assert!(hint.len() <= budget, "{hint:?} does not fit a 128px row");
            }
        }
    }

    /// The rows a resting device is not spending: neither a closed
    /// pairing window nor plain advertising may put anything on screen.
    #[test]
    fn nominal_state_costs_no_rows() {
        for layout in layouts() {
            let model = UiModel::new(MenuItems::all());
            let mut nominal = demo_status();
            nominal.pairing = PairingState::Closed;
            nominal.link = LinkState::Advertising;
            let mut quiet = TestPanel::new(layout.size);
            render_frame(&mut quiet, &layout, &model, &nominal);

            for (label, busy) in [
                ("pairing", PairingState::Open { pin: Some(123_456) }),
                ("lockout", PairingState::LockedOut),
            ] {
                let mut status = nominal;
                status.pairing = busy;
                let mut panel = TestPanel::new(layout.size);
                render_frame(&mut panel, &layout, &model, &status);
                assert!(
                    panel.lit_in(row_area(&layout, 2)) != quiet.lit_in(row_area(&layout, 2)),
                    "{label} did not claim a row on {:?}",
                    layout.size
                );
            }

            for link in [
                LinkState::Attached,
                LinkState::Connected,
                LinkState::OffWired,
            ] {
                let mut status = nominal;
                status.link = link;
                let mut panel = TestPanel::new(layout.size);
                render_frame(&mut panel, &layout, &model, &status);
                assert!(
                    panel.lit_in(row_area(&layout, 2)) != quiet.lit_in(row_area(&layout, 2)),
                    "{link:?} did not claim a row on {:?}",
                    layout.size
                );
            }
        }
    }

    /// The bond count moved to where it changes a decision.
    #[test]
    fn the_confirmation_names_how_many_bonds_it_would_destroy() {
        let layout = Layout::EPD_200X200;
        let mut counts = [0usize; 3];
        for (index, bonds) in [0u8, 1, 4].iter().enumerate() {
            let mut model = UiModel::new(MenuItems::all());
            navigate_to(&mut model, MenuItem::ClearBonds);
            model.apply(UiInput::Select);
            assert!(matches!(model.page(), Page::Confirm { .. }));

            let mut status = demo_status();
            status.bonds = *bonds;
            let mut panel = TestPanel::new(layout.size);
            render_frame(&mut panel, &layout, &model, &status);
            counts[index] = panel.lit_in(row_area(&layout, 1));
        }
        assert_ne!(counts[0], counts[1]);
        assert_ne!(counts[1], counts[2]);
    }

    /// The stats page renders three populated rows on every layout — a
    /// deaf node has to be distinguishable from a busy one at a glance.
    #[test]
    fn the_stats_page_shows_its_counters() {
        for layout in layouts() {
            let mut model = UiModel::new(MenuItems::all());
            navigate_to(&mut model, MenuItem::Stats);
            // Below the top level, reading takes a Select.
            model.apply(UiInput::Select);
            assert_eq!(model.page(), Page::Detail(MenuItem::Stats));

            let mut panel = TestPanel::new(layout.size);
            render_frame(&mut panel, &layout, &model, &demo_status());
            for row in 2..=4 {
                assert!(
                    panel.lit_in(row_area(&layout, row)) > 0,
                    "stats row {row} is blank on {:?}",
                    layout.size
                );
            }
        }
    }

    /// Walking onto Statistics shows the Radio list with Statistics
    /// highlighted — not the statistics. Reading in place is the top
    /// level's exception, and this is the entry that used to break it.
    #[test]
    fn a_reading_entry_below_the_top_is_drawn_as_a_row() {
        for layout in layouts() {
            let mut model = UiModel::new(MenuItems::all());
            navigate_to(&mut model, MenuItem::Stats);

            let mut panel = TestPanel::new(layout.size);
            render_frame(&mut panel, &layout, &model, &demo_status());
            assert!(
                shows_row(&panel, &layout, "Forwarding  on"),
                "the Radio list is not on screen at {:?}",
                layout.size
            );
            // The counters belong to the page a Select away.
            assert!(
                !shows_row(&panel, &layout, "tx 12  rx 340"),
                "the statistics leaked onto the list at {:?}",
                layout.size
            );
        }
    }

    /// Every top-level entry takes the whole panel, Settings included:
    /// what it says is what the switches under it are set to.
    #[test]
    fn the_top_level_settings_page_says_only_its_name() {
        for layout in layouts() {
            let mut model = UiModel::new(MenuItems::all());
            walk_to(&mut model, MenuItem::Settings);

            let mut panel = TestPanel::new(layout.size);
            render_frame(&mut panel, &layout, &model, &demo_status());
            // Nothing from the level behind it: rows of labels and states
            // here read as that list rather than as the way into it.
            for switch in ["Bluetooth  on", "GNSS  on", "Forwarding  on"] {
                assert!(
                    !shows_row(&panel, &layout, switch),
                    "{switch:?} leaked onto the doorway at {:?}",
                    layout.size
                );
            }
            // And no inverted bar, which is what made it look like a list
            // with its first row highlighted.
            let rows = inverted_rows(&layout, &model, &demo_status());
            assert!(rows.is_empty(), "inverted {rows:?} on {:?}", layout.size);
        }
    }

    /// Selecting a non-status item frees rows 3 and 4 on the OLED, which
    /// is exactly where its two hints belong.
    #[test]
    fn a_sparse_page_gets_its_hints_back() {
        let mut model = UiModel::new(MenuItems::all());
        model.apply(UiInput::Forward);
        let layout = Layout::OLED_128X64;
        let mut panel = TestPanel::new(layout.size);
        render_frame(&mut panel, &layout, &model, &demo_status());
        assert!(panel.lit_in(row_area(&layout, 3)) > 0);
        assert!(panel.lit_in(row_area(&layout, 4)) > 0);
    }

    fn row_area(layout: &Layout, row: usize) -> Rectangle {
        Rectangle::new(
            Point::new(0, layout.row_top(row)),
            Size::new(layout.size.width, layout.font.character_size.height),
        )
    }

    /// Every page on every layout stays inside the panel — `TestPanel`
    /// asserts on any pixel that does not.
    #[test]
    fn no_page_draws_outside_the_panel() {
        for layout in layouts() {
            for pairing in [
                PairingState::LockedOut,
                PairingState::Open { pin: Some(123_456) },
                PairingState::Open { pin: None },
                PairingState::Closed,
            ] {
                for link in [
                    LinkState::Attached,
                    LinkState::Connected,
                    LinkState::Advertising,
                    LinkState::OffWired,
                ] {
                    let mut status = demo_status();
                    status.pairing = pairing;
                    status.link = link;

                    // Every entry of every level, plus the confirmation
                    // each destructive one opens.
                    for item in MenuItem::ALL {
                        let mut model = UiModel::new(MenuItems::all());
                        navigate_to(&mut model, item);
                        let mut panel = TestPanel::new(layout.size);
                        render_frame(&mut panel, &layout, &model, &status);

                        if item.requires_confirmation() {
                            model.apply(UiInput::Select);
                            // Both sides of the confirmation, since the
                            // highlight moves between them.
                            for _ in 0..2 {
                                assert!(matches!(model.page(), Page::Confirm { .. }));
                                let mut panel = TestPanel::new(layout.size);
                                render_frame(&mut panel, &layout, &model, &status);
                                model.apply(UiInput::Forward);
                            }
                        }

                        // ...and the page every reading entry below the
                        // top level opens.
                        if !item.reads_in_place() && matches!(item.kind(), EntryKind::Reading(_)) {
                            model.apply(UiInput::Select);
                            assert!(matches!(model.page(), Page::Detail(_)));
                            let mut panel = TestPanel::new(layout.size);
                            render_frame(&mut panel, &layout, &model, &status);
                        }
                    }

                    let mut panel = TestPanel::new(layout.size);
                    render_message(
                        &mut panel,
                        &layout,
                        &status,
                        "Locate alert",
                        "Press to stop",
                    );
                }
            }
        }
    }

    /// What fraction of a row band is lit, in percent. An inverted row is
    /// nearly solid; an ordinary one is a scattering of glyph pixels.
    fn row_fill(panel: &TestPanel, layout: &Layout, row: usize) -> usize {
        let band = layout.row_rect(row);
        let area = (band.size.width * band.size.height) as usize;
        if area == 0 {
            return 0;
        }
        panel.lit_in(band) * 100 / area
    }

    /// Which rows read as inverted, on a panel drawn from `model`.
    fn inverted_rows(
        layout: &Layout,
        model: &UiModel,
        status: &StatusModel<'_>,
    ) -> heapless::Vec<usize, 8> {
        let mut panel = TestPanel::new(layout.size);
        render_frame(&mut panel, layout, model, status);
        (0..layout.rows)
            .filter(|&row| row_fill(&panel, layout, row) > 50)
            .collect()
    }

    /// The highlight is a solid bar across the whole row, not emphasized
    /// text — that is what makes it legible on a bistable panel with no
    /// backlight, and it is the contract Select is drawn against.
    ///
    /// Settings is the one frame without one. It is a doorway whose whole
    /// content is its own name, and a bar there had nothing under it to
    /// mark: it read as a list with its first row highlighted, which is
    /// exactly what the page is not.
    #[test]
    fn the_highlight_is_a_solid_bar_and_there_is_exactly_one() {
        for layout in layouts() {
            for item in MenuItem::ALL {
                let mut model = UiModel::new(MenuItems::all());
                navigate_to(&mut model, item);
                let rows = inverted_rows(&layout, &model, &demo_status());
                if item == MenuItem::Settings {
                    assert!(rows.is_empty(), "the doorway inverted {rows:?}");
                    continue;
                }
                assert_eq!(
                    rows.len(),
                    1,
                    "{item:?} inverted {rows:?} on {:?}",
                    layout.size
                );
                // Never the header, which is not a list entry.
                assert_ne!(rows[0], 0, "{item:?} inverted the header");
            }
        }
    }

    /// The confirmation's two choices use the same inversion, and it
    /// follows the cursor rather than sitting on the destructive one.
    #[test]
    fn the_confirmation_inverts_whichever_choice_the_cursor_is_on() {
        for layout in layouts() {
            let mut model = UiModel::new(MenuItems::all());
            navigate_to(&mut model, MenuItem::ClearBonds);
            model.apply(UiInput::Select);

            // Opens on Cancel, per the spec's default.
            let cancel = inverted_rows(&layout, &model, &demo_status());
            model.apply(UiInput::Forward);
            let clear = inverted_rows(&layout, &model, &demo_status());

            assert_eq!(cancel.len(), 1, "confirmation lost its highlight");
            assert_eq!(clear.len(), 1, "confirmation lost its highlight");
            assert_ne!(cancel, clear, "the highlight did not move to CLEAR");
        }
    }

    /// The address is what the screen is transcribed from, so every
    /// character of it reaches the panel. The 128×64 has exactly enough
    /// rows for the 44 characters and none to spare, so the hint yields
    /// its row there and keeps it on the 200×200.
    #[test]
    fn the_identity_page_shows_the_whole_address_or_none_of_it() {
        for layout in layouts() {
            let status = demo_status();
            let identity = status.identity.expect("fixture has an identity");
            let mut model = UiModel::new(MenuItems::all());
            navigate_to(&mut model, MenuItem::Identity);
            let mut panel = TestPanel::new(layout.size);
            render_frame(&mut panel, &layout, &model, &status);

            // Every chunk the wrap produces, at the panel's own width.
            let room = layout.size.width.saturating_sub(layout.left.max(0) as u32);
            let per_row = clip(&layout, identity.address, room).chars().count();
            let mut rest = identity.address;
            while !rest.is_empty() {
                let end = rest
                    .char_indices()
                    .nth(per_row)
                    .map_or(rest.len(), |(at, _)| at);
                let (chunk, remainder) = rest.split_at(end);
                assert!(
                    shows_row(&panel, &layout, chunk),
                    "{:?} lost {chunk:?} off the address",
                    layout.size
                );
                rest = remainder;
            }
        }

        // And a panel with room for both keeps the hint.
        let layout = Layout::EPD_200X200;
        let status = demo_status();
        let mut model = UiModel::new(MenuItems::all());
        navigate_to(&mut model, MenuItem::Identity);
        let mut panel = TestPanel::new(layout.size);
        render_frame(&mut panel, &layout, &model, &status);
        assert!(shows_row(&panel, &layout, status.identity.unwrap().hint));
    }

    /// A settings level is a list: every entry it holds is on the panel at
    /// once, not one at a time behind a gesture.
    #[test]
    fn a_settings_level_draws_all_of_its_entries() {
        for layout in layouts() {
            let items = MenuItems::all();
            for level in [Level::Settings, Level::Bluetooth, Level::Gnss] {
                let selected = items.first_after_back(level);
                let mut model = UiModel::new(items);
                navigate_to(&mut model, selected);
                let mut panel = TestPanel::new(layout.size);
                render_frame(&mut panel, &layout, &model, &demo_status());

                // The highlighted entry is drawn inverted, so its glyphs
                // are unlit and there is nothing for `shows_row` to find;
                // the bar it draws instead is what the highlight tests
                // check.
                for entry in items.entries(level).filter(|&e| e != selected) {
                    assert!(
                        shows_row(&panel, &layout, menu_label(entry)),
                        "{level:?} did not draw {entry:?} on {:?}",
                        layout.size
                    );
                }
            }
        }
    }

    /// A toggle carries its state beside its name, because the state is
    /// the whole reason to walk to it. A board that cannot report one
    /// draws no state rather than guessing "off".
    #[test]
    fn a_toggle_reports_its_state_and_an_unknown_one_reports_nothing() {
        let mut settings = SettingsModel {
            bluetooth: Some(true),
            gnss: Some(false),
            share_location: None,
            forwarding: Some(true),
        };
        let mut line: String<LINE> = String::new();

        write_entry(&mut line, MenuItem::BluetoothToggle, &settings);
        assert_eq!(line.as_str(), "Bluetooth  on");

        line.clear();
        write_entry(&mut line, MenuItem::GnssToggle, &settings);
        assert_eq!(line.as_str(), "GNSS  off");

        line.clear();
        write_entry(&mut line, MenuItem::ShareLocation, &settings);
        assert_eq!(line.as_str(), "Share location");

        // And a non-toggle never grows one.
        line.clear();
        settings.forwarding = Some(false);
        write_entry(&mut line, MenuItem::StartPairing, &settings);
        assert_eq!(line.as_str(), "Start pairing");
    }

    /// Both overflow idioms keep the highlighted entry drawn complete: a
    /// Select against a row the user can only half read is a guess.
    #[test]
    fn overflow_never_leaves_the_highlight_half_drawn() {
        let items = MenuItems::all();
        // Neither shipping panel overflows a level today, so the window
        // arithmetic is exercised against panels short enough that they
        // must — three content rows against a four-entry level.
        for style in [Overflow::ClipRow, Overflow::ScrollBar] {
            for base in layouts() {
                let layout = Layout {
                    rows: 4,
                    overflow: style,
                    ..base
                };
                for entry in items.entries(Level::Bluetooth) {
                    let mut model = UiModel::new(items);
                    navigate_to(&mut model, entry);
                    let mut panel = TestPanel::new(layout.size);
                    render_frame(&mut panel, &layout, &model, &demo_status());

                    // The bar is the highlight, and it is drawn across the
                    // whole row band. A band only half filled is a row
                    // the clip cut in two, which the highlight may never
                    // land on.
                    let bars: heapless::Vec<usize, 8> = (1..layout.rows)
                        .map(|row| row_fill(&panel, &layout, row))
                        .filter(|&fill| fill > 50)
                        .collect();
                    assert_eq!(
                        bars.len(),
                        1,
                        "{entry:?} under {style:?} inverted {bars:?} on {:?}",
                        layout.size
                    );
                    assert!(
                        bars[0] > 80,
                        "{entry:?} was drawn half a row under {style:?} on {:?}",
                        layout.size
                    );
                }
            }
        }
    }

    /// A clipped row hangs over the bottom; a scroll bar takes a column
    /// from every row instead. A board uses one, and the other must leave
    /// no trace.
    #[test]
    fn each_overflow_style_marks_the_list_its_own_way() {
        let items = MenuItems::all();
        let base = Layout::EPD_200X200;
        let mut lit = [0usize; 2];
        for (index, style) in [Overflow::ClipRow, Overflow::ScrollBar]
            .into_iter()
            .enumerate()
        {
            let layout = Layout {
                rows: 4,
                overflow: style,
                ..base
            };
            let mut model = UiModel::new(items);
            navigate_to(&mut model, items.first_after_back(Level::Bluetooth));
            let mut panel = TestPanel::new(layout.size);
            render_frame(&mut panel, &layout, &model, &demo_status());

            // The right-hand column the bar would own, below the header.
            let bar = Rectangle::new(
                Point::new(layout.size.width as i32 - 2, layout.row_top(1)),
                Size::new(2, layout.size.height - layout.row_top(1) as u32),
            );
            lit[index] = panel.lit_in(bar);
        }
        assert!(
            lit[1] > lit[0],
            "the scroll bar did not claim the edge column"
        );
    }

    /// A notice takes the top content row and pushes the rest down rather
    /// than replacing them: with the nominal rows gone there is room for
    /// both, and a PIN the user is mid-way through typing must not
    /// vanish because an unrelated action reported back.
    #[test]
    fn a_notice_takes_the_top_row_without_displacing_the_pin() {
        let layout = Layout::OLED_128X64;
        let mut model = UiModel::new(MenuItems::all());
        let mut status = demo_status();
        status.pairing = PairingState::Open { pin: Some(123_456) };

        let mut with_pin = TestPanel::new(layout.size);
        render_frame(&mut with_pin, &layout, &model, &status);
        let pin_row = with_pin.lit_in(row_area(&layout, 2));
        assert!(pin_row > 0);

        model.set_notice(UiNotice::BondsCleared);
        let mut with_notice = TestPanel::new(layout.size);
        render_frame(&mut with_notice, &layout, &model, &status);

        // The notice is now row 2 and the PIN has moved to row 3.
        assert_ne!(with_notice.lit_in(row_area(&layout, 2)), pin_row);
        assert_eq!(with_notice.lit_in(row_area(&layout, 3)), pin_row);
    }

    /// Charging with no level draws a bolt and nothing else: there is no
    /// level, so there is no body — the two are drawn independently.
    #[test]
    fn charging_without_a_level_replaces_the_body_with_a_bolt() {
        for layout in layouts() {
            let zone = layout.battery_zone();
            let mut charging = TestPanel::new(layout.size);
            let mut status = demo_status();
            status.battery = BatteryIndicator {
                level_percent: None,
                charge: Some(ChargeClass::Charging),
            };
            render_frame(
                &mut charging,
                &layout,
                &UiModel::new(MenuItems::all()),
                &status,
            );

            // Something is in the zone, and it is not the outline: an
            // unknown-level pack that is *not* charging draws the body,
            // and the two must not look alike.
            assert!(charging.lit_in(zone) > 0, "charging drew nothing at all");

            let mut unknown = TestPanel::new(layout.size);
            let mut status = demo_status();
            status.battery = BatteryIndicator::UNKNOWN;
            render_frame(
                &mut unknown,
                &layout,
                &UiModel::new(MenuItems::all()),
                &status,
            );
            assert_ne!(
                charging.lit_in(zone),
                unknown.lit_in(zone),
                "charging and no-reading drew the same picture on {:?}",
                layout.size
            );

            // The bolt keeps the zone's right edge, so the indicator does
            // not shift sideways when a charger goes in. Its rightmost
            // column must be lit and everything left of the bolt clear —
            // which also proves no body outline survived.
            let solo = layout.battery.solo_bolt;
            let right_edge = Rectangle::new(
                Point::new(
                    zone.top_left.x + zone.size.width as i32 - 1,
                    zone.top_left.y,
                ),
                Size::new(1, zone.size.height),
            );
            assert!(
                charging.lit_in(right_edge) > 0,
                "the solo bolt is not right-aligned on {:?}",
                layout.size
            );

            let left_of_bolt = Rectangle::new(
                zone.top_left,
                Size::new(zone.size.width - solo.width, zone.size.height),
            );
            assert_eq!(
                charging.lit_in(left_of_bolt),
                0,
                "something remained left of the solo bolt on {:?}",
                layout.size
            );
        }
    }

    /// A board that *can* see charge completion still supplies a level,
    /// and keeps its body plus a bolt beside it.
    #[test]
    fn a_known_level_keeps_its_body_even_while_charging() {
        let layout = Layout::OLED_128X64;
        let zone = layout.battery_zone();

        let mut charging = TestPanel::new(layout.size);
        let mut status = demo_status();
        status.battery = BatteryIndicator {
            level_percent: Some(100),
            charge: Some(ChargeClass::Charged),
        };
        render_frame(
            &mut charging,
            &layout,
            &UiModel::new(MenuItems::all()),
            &status,
        );

        let mut solo = TestPanel::new(layout.size);
        let mut status = demo_status();
        status.battery = BatteryIndicator {
            level_percent: None,
            charge: Some(ChargeClass::Charged),
        };
        render_frame(&mut solo, &layout, &UiModel::new(MenuItems::all()), &status);

        assert!(charging.lit_in(zone) > solo.lit_in(zone));
    }
}
