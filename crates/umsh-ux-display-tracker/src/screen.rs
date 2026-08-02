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
use embedded_graphics::mono_font::{MonoFont, MonoTextStyle};
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{
    PrimitiveStyle, PrimitiveStyleBuilder, Rectangle, StrokeAlignment, Triangle,
};
use embedded_graphics::text::{Baseline, Text};
use heapless::String;

use crate::menu::{MenuItem, Page, UiModel, UiNotice};
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

/// Number of lit segments for a *known* charge level, from 1 to
/// [`BATTERY_SEGMENTS`].
///
/// Never zero. An empty body is how the indicator says it has no reading
/// yet, so a pack that is nearly flat has to keep a bar — otherwise the
/// one state the user most needs to act on is drawn identically to a
/// sensor that has not reported. The remaining three steps divide the
/// range evenly, which puts the single-bar warning at 16 % and under.
pub const fn battery_segments(level_percent: u8) -> u8 {
    let level = if level_percent > 100 {
        100
    } else {
        level_percent
    } as u16;
    let span = (BATTERY_SEGMENTS - 1) as u16;
    1 + ((level * span + 50) / 100) as u8
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

/// A board's screen geometry.
///
/// Everything the renderer needs to place a row of text and the battery
/// indicator. A board picks one of the constants — or writes its own if
/// its panel is neither of the two shapes in the class today.
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
    };

    /// Top of `row`'s glyph band.
    pub const fn row_top(&self, row: usize) -> i32 {
        self.top + row as i32 * self.row_pitch
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
    /// `None` before the level estimator has had a resting sample —
    /// drawn as an empty body rather than as zero.
    pub level_percent: Option<u8>,
    /// `None` on a board whose charger reports nothing to the MCU, which
    /// is different from knowing the pack is discharging.
    pub charge: Option<ChargeClass>,
}

impl BatteryIndicator {
    /// Nothing known yet: empty body, no bolt.
    pub const UNKNOWN: Self = Self {
        level_percent: None,
        charge: None,
    };

    /// Whether the indicator should carry a charging bolt.
    ///
    /// `Charged` draws one too. It means the pack is full *and still on
    /// external power*, and no board in this class can currently
    /// distinguish the two anyway — only the T-1000E, which has no panel,
    /// reads a real charge-status line.
    const fn shows_bolt(&self) -> bool {
        matches!(
            self.charge,
            Some(ChargeClass::Charging) | Some(ChargeClass::Charged)
        )
    }

    /// Whether the bolt should replace the battery body rather than sit
    /// beside it.
    ///
    /// A charging pack has no state of charge that resting terminal
    /// voltage can supply, and on the boards in this class the charger
    /// reports no completion either — so there is nothing to fill a body
    /// with. Drawing an empty or stale one would be a claim; a bare bolt
    /// says only what is actually known, which is that the pack is on
    /// external power. A board that *can* see completion still supplies a
    /// level and keeps its body.
    const fn bolt_stands_alone(&self) -> bool {
        self.shows_bolt() && self.level_percent.is_none()
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
        Page::Menu(item) => {
            draw_row(target, layout, 1, menu_label(item));
            match item {
                MenuItem::Status => draw_status_page(target, layout, model, status, &mut line),
                MenuItem::Stats => draw_stats_page(target, layout, status, &mut line),
                other => {
                    draw_row(target, layout, 2, action_label(other));
                    3
                }
            }
        }
        Page::Confirm {
            confirm_selected, ..
        } => {
            // The question names the object and its size, which is the
            // only place the bond count changes a decision — and is why
            // the status page no longer spends a row carrying it around.
            write_clear_question(&mut line, status.bonds);
            draw_row(target, layout, 1, &line);
            draw_row(
                target,
                layout,
                2,
                if confirm_selected {
                    "  Cancel"
                } else {
                    "> Cancel"
                },
            );
            draw_row(
                target,
                layout,
                3,
                if confirm_selected {
                    "> CLEAR"
                } else {
                    "  CLEAR"
                },
            );
            4
        }
    };

    let hints: &[&str] = match model.page() {
        Page::Menu(_) => &["1x: next", "hold: back"],
        Page::Confirm { .. } => &["1x/hold: toggle", "2x: confirm"],
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

    // Charging with nothing to fill a body with: the bolt is the whole
    // indicator, centered in the zone the body would otherwise occupy.
    if indicator.bolt_stands_alone() {
        let zone = Size::new(metrics.zone_width(), metrics.body.height);
        let bolt = metrics.solo_bolt;
        let at = Point::new(
            top_left.x + (zone.width.saturating_sub(bolt.width) / 2) as i32,
            top_left.y + (zone.height.saturating_sub(bolt.height) / 2) as i32,
        );
        draw_bolt(target, at, bolt, solid);
        return;
    }

    if indicator.shows_bolt() {
        draw_bolt(
            target,
            top_left,
            Size::new(metrics.bolt_width, metrics.body.height),
            solid,
        );
    }

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

    let Some(level) = indicator.level_percent else {
        return;
    };
    let lit = u32::from(battery_segments(level));
    let inset = metrics.border + metrics.pad;
    let inner = Size::new(
        metrics.body.width.saturating_sub(2 * inset),
        metrics.body.height.saturating_sub(2 * inset),
    );
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
    row + 1
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

// ─── Drawing helpers ─────────────────────────────────────────────────────────

fn draw_header<D>(target: &mut D, layout: &Layout, status: &StatusModel<'_>)
where
    D: DrawTarget<Color = BinaryColor>,
{
    // The battery owns its corner: the name is cut to the room left over
    // rather than being allowed to run under the indicator and off the
    // panel. Blanking the zone afterwards keeps that true no matter what
    // else the header grows.
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

const fn menu_label(item: MenuItem) -> &'static str {
    match item {
        MenuItem::Status => "> Status",
        MenuItem::Stats => "> Stats",
        MenuItem::CheckIn => "> Check in",
        MenuItem::StartPairing => "> Start pairing",
        MenuItem::ClearBonds => "> Clear bonds",
    }
}

/// What a double-click would do from this item. `Status` and `Stats` are
/// pages, not actions, and never reach here.
const fn action_label(item: MenuItem) -> &'static str {
    match item {
        MenuItem::CheckIn => "2x: check in",
        MenuItem::StartPairing => "2x: start",
        MenuItem::ClearBonds => "2x: continue",
        MenuItem::Status | MenuItem::Stats => "",
    }
}

const fn notice_label(notice: UiNotice) -> &'static str {
    match notice {
        UiNotice::CheckInRequested => "checking in...",
        UiNotice::PairingStarted => "pairing started",
        UiNotice::PairingUnavailable => "pair unavailable",
        UiNotice::BondsCleared => "bonds cleared",
        UiNotice::ClearFailed => "CLEAR FAILED",
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
    use crate::menu::{MenuItems, UiInput};

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
        }
    }

    fn layouts() -> [Layout; 2] {
        [Layout::OLED_128X64, Layout::EPD_200X200]
    }

    #[test]
    fn segments_quantize_the_level_without_ever_emptying_the_body() {
        // A known level always keeps a bar: an empty body means "no
        // reading", and a flat pack must not borrow that look.
        assert_eq!(battery_segments(0), 1);
        assert_eq!(battery_segments(16), 1);
        assert_eq!(battery_segments(17), 2);
        assert_eq!(battery_segments(49), 2);
        assert_eq!(battery_segments(50), 3);
        assert_eq!(battery_segments(83), 3);
        assert_eq!(battery_segments(84), 4);
        assert_eq!(battery_segments(100), 4);
        // Clamped rather than wrapped, so a bad sample cannot overdraw.
        assert_eq!(battery_segments(200), 4);
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
            model.apply(UiInput::Backward);
            model.apply(UiInput::Select);
            assert!(matches!(model.page(), Page::Confirm { .. }));
            let mut panel = TestPanel::new(layout.size);
            render_frame(&mut panel, &layout, &model, &demo_status());
            assert!(panel.lit_in(zone) > 0, "confirm frame lost the battery");
        }
    }

    #[test]
    fn fill_grows_with_the_level_and_an_unknown_level_draws_an_empty_body() {
        for layout in layouts() {
            let zone = layout.battery_zone();
            let mut previous = 0;
            // One level from each of the four bands.
            for level in [0, 25, 60, 100] {
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

            // "No reading yet" and "nearly flat" are different things to
            // tell someone, so they must not draw the same picture.
            let mut empty = TestPanel::new(layout.size);
            let mut status = demo_status();
            status.battery = BatteryIndicator::UNKNOWN;
            render_frame(
                &mut empty,
                &layout,
                &UiModel::new(MenuItems::all()),
                &status,
            );
            let outline = empty.lit_in(zone);
            assert!(outline > 0, "unknown level drew no body at all");

            let mut zero = TestPanel::new(layout.size);
            let mut status = demo_status();
            status.battery.level_percent = Some(0);
            render_frame(&mut zero, &layout, &UiModel::new(MenuItems::all()), &status);
            assert!(
                zero.lit_in(zone) > outline,
                "a flat pack drew the same empty body as an unknown one"
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
            model.apply(UiInput::Backward);
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
            model.apply(UiInput::Forward);
            assert_eq!(model.page(), Page::Menu(MenuItem::Stats));

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

                    let mut model = UiModel::new(MenuItems::all());
                    for _ in 0..MenuItem::ALL.len() {
                        let mut panel = TestPanel::new(layout.size);
                        render_frame(&mut panel, &layout, &model, &status);
                        model.apply(UiInput::Forward);
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

    /// Charging with no level draws a bolt and nothing else: no body to
    /// fill, and no empty body either, which would read as a flat pack.
    #[test]
    fn charging_without_a_level_replaces_the_body_with_a_bolt() {
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

            // The right-hand body region is where the outline and nub
            // live; a solo bolt is centered and must leave the nub column
            // clear, so nothing suggests a body outline is still there.
            let nub = Rectangle::new(
                Point::new(
                    body.top_left.x + layout.battery.body.width as i32,
                    body.top_left.y,
                ),
                Size::new(layout.battery.nub.width, layout.battery.body.height),
            );
            assert_eq!(
                charging.lit_in(nub),
                0,
                "the solo bolt spilled into the terminal nub on {:?}",
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
