//! Contact sheets of every frame kind, so a layout change can be looked
//! at instead of reasoned about.
//!
//! Renders each panel at its real resolution and colors — lit pixels on
//! black for the OLEDs, ink on paper for the e-paper — and writes one BMP
//! per layout:
//!
//! ```text
//! PREVIEW_DIR=/tmp cargo test -p umsh-ux-display-tracker \
//!     --features screen --test preview
//! sips -s format png /tmp/oled-128x64.bmp --out /tmp/oled-128x64.png
//! ```
//!
//! Without `PREVIEW_DIR` the test is a no-op, so it costs CI nothing.
//! Worth running before touching geometry: it is what caught a nearly
//! flat pack drawing the same empty body as a pack with no reading at
//! all, which no assertion had thought to ask about.
#![cfg(feature = "screen")]
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use umsh_ux_display_tracker::menu::{
    EntryKind, Level, MenuItem, MenuItems, Page, UiInput, UiModel,
};
use umsh_ux_display_tracker::screen::*;
use umsh_ux_tracker::battery::ChargeClass;

struct Panel {
    size: Size,
    px: Vec<bool>,
}

impl Panel {
    fn new(size: Size) -> Self {
        Panel {
            size,
            px: vec![false; (size.width * size.height) as usize],
        }
    }
    fn lit(&self, x: u32, y: u32) -> bool {
        self.px[(y * self.size.width + x) as usize]
    }
}

impl OriginDimensions for Panel {
    fn size(&self) -> Size {
        self.size
    }
}

impl DrawTarget for Panel {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;
    fn draw_iter<I: IntoIterator<Item = Pixel<BinaryColor>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        for Pixel(Point { x, y }, c) in pixels {
            if x >= 0 && y >= 0 && (x as u32) < self.size.width && (y as u32) < self.size.height {
                self.px[(y as u32 * self.size.width + x as u32) as usize] = c.is_on();
            }
        }
        Ok(())
    }
}

/// Simple RGB canvas that knows how to write itself out as a BMP.
struct Canvas {
    w: u32,
    h: u32,
    px: Vec<[u8; 3]>,
}

impl Canvas {
    fn new(w: u32, h: u32, bg: [u8; 3]) -> Self {
        Canvas {
            w,
            h,
            px: vec![bg; (w * h) as usize],
        }
    }

    fn set(&mut self, x: u32, y: u32, c: [u8; 3]) {
        if x < self.w && y < self.h {
            self.px[(y * self.w + x) as usize] = c;
        }
    }

    fn rect(&mut self, x: u32, y: u32, w: u32, h: u32, c: [u8; 3]) {
        for dy in 0..h {
            for dx in 0..w {
                self.set(x + dx, y + dy, c);
            }
        }
    }

    /// Blit a panel, scaled up, with `on`/`off` colors.
    fn blit(&mut self, panel: &Panel, at: (u32, u32), scale: u32, on: [u8; 3], off: [u8; 3]) {
        for y in 0..panel.size.height {
            for x in 0..panel.size.width {
                let c = if panel.lit(x, y) { on } else { off };
                self.rect(at.0 + x * scale, at.1 + y * scale, scale, scale, c);
            }
        }
    }

    fn write_bmp(&self, path: &std::path::Path) {
        let row_bytes = (self.w * 3).div_ceil(4) * 4;
        let pixel_bytes = row_bytes * self.h;
        let mut out = Vec::with_capacity(54 + pixel_bytes as usize);
        out.extend_from_slice(b"BM");
        out.extend_from_slice(&(54 + pixel_bytes).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&54u32.to_le_bytes());
        out.extend_from_slice(&40u32.to_le_bytes());
        out.extend_from_slice(&(self.w as i32).to_le_bytes());
        out.extend_from_slice(&(self.h as i32).to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&24u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&pixel_bytes.to_le_bytes());
        out.extend_from_slice(&2835i32.to_le_bytes());
        out.extend_from_slice(&2835i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        // BMP scanlines run bottom-up.
        for y in (0..self.h).rev() {
            let mut written = 0;
            for x in 0..self.w {
                let [r, g, b] = self.px[(y * self.w + x) as usize];
                out.extend_from_slice(&[b, g, r]);
                written += 3;
            }
            while written < row_bytes {
                out.push(0);
                written += 1;
            }
        }
        std::fs::write(path, out).expect("write bmp");
    }
}

fn status(
    level: Option<u8>,
    charge: Option<ChargeClass>,
    pairing: PairingState,
    link: LinkState,
) -> StatusModel<'static> {
    StatusModel {
        device_name: "umsh-a1b2c3",
        battery: BatteryIndicator {
            level_percent: level,
            charge,
        },
        battery_mv: Some(3_950),
        link,
        queued: None,
        bonds: 3,
        pairing,
        stats: StatsModel {
            tx_frames: 128,
            rx_frames: 4_071,
            rx_accepted: 3_588,
            forwarded: 42,
            tx_power_dbm: Some(22),
            duty_permille: 13,
        },
        // The preview shows a device that has a clock; the "no clock at
        // all" state has its own unit test, and a blank corner makes for
        // a poor reference image.
        clock: Some(ClockModel {
            hour: 14,
            minute: 30,
        }),
        settings: SettingsModel {
            bluetooth: Some(true),
            gnss: Some(true),
            share_location: Some(false),
            forwarding: Some(true),
        },
        identity: Some(IdentityModel {
            hint: "7bQ*",
            address: "1BvYtT4nCJmqvKGpZbW8XdRfLhNs2eQaUxAyDzMr6HkP",
        }),
    }
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

/// Every frame kind, in the order a user would meet them.
fn frames(layout: &Layout) -> Vec<Panel> {
    let mut out = Vec::new();
    let open = PairingState::Open { pin: Some(123456) };

    let mut push = |f: &dyn Fn(&mut Panel)| {
        let mut p = Panel::new(layout.size);
        f(&mut p);
        out.push(p);
    };

    // The resting frame: nothing to report but the battery.
    push(&|p| {
        render_frame(
            p,
            layout,
            &UiModel::new(MenuItems::all()),
            &status(
                Some(72),
                Some(ChargeClass::Discharging),
                PairingState::Closed,
                LinkState::Advertising,
            ),
        )
    });

    // Status page across the battery range, with a pairing window open.
    for (level, charge) in [
        (Some(100), Some(ChargeClass::Charged)),
        (Some(70), Some(ChargeClass::Discharging)),
        (Some(45), Some(ChargeClass::Discharging)),
        (Some(25), Some(ChargeClass::Discharging)),
        (Some(8), Some(ChargeClass::Discharging)),
        (None, None),
        // Charging with no derivable level: bolt only, no body.
        (None, Some(ChargeClass::Charging)),
    ] {
        push(&|p| {
            render_frame(
                p,
                layout,
                &UiModel::new(MenuItems::all()),
                &status(level, charge, open, LinkState::Advertising),
            )
        });
    }

    // Pairing closed, attached to a phone.
    push(&|p| {
        render_frame(
            p,
            layout,
            &UiModel::new(MenuItems::all()),
            &status(
                Some(60),
                Some(ChargeClass::Discharging),
                PairingState::Closed,
                LinkState::Attached,
            ),
        )
    });

    // Every entry of every level, in the order the tree declares them:
    // the top level's three pages, then each settings list with its
    // highlight on a different row so the window and the bar can both be
    // looked at — and, for the entries that open one, the page behind the
    // Select.
    for item in MenuItem::ALL {
        let mut m = UiModel::new(MenuItems::all());
        navigate_to(&mut m, item);
        push(&|p| {
            render_frame(
                p,
                layout,
                &m,
                &status(
                    Some(60),
                    Some(ChargeClass::Discharging),
                    open,
                    LinkState::Advertising,
                ),
            )
        });

        if !item.reads_in_place() && matches!(item.kind(), EntryKind::Reading(_)) {
            m.apply(UiInput::Select);
            push(&|p| {
                render_frame(
                    p,
                    layout,
                    &m,
                    &status(
                        Some(60),
                        Some(ChargeClass::Discharging),
                        open,
                        LinkState::Advertising,
                    ),
                )
            });
        }
    }

    // The confirmation page, both ways round.
    let mut c = UiModel::new(MenuItems::all());
    navigate_to(&mut c, MenuItem::ClearBonds);
    c.apply(UiInput::Select);
    for _ in 0..2 {
        push(&|p| {
            render_frame(
                p,
                layout,
                &c,
                &status(
                    Some(60),
                    Some(ChargeClass::Discharging),
                    open,
                    LinkState::Advertising,
                ),
            )
        });
        c.apply(UiInput::Forward);
    }

    // A message frame.
    push(&|p| {
        render_message(
            p,
            layout,
            &status(
                Some(60),
                Some(ChargeClass::Charging),
                open,
                LinkState::Advertising,
            ),
            "Locate alert",
            "Press to stop",
        )
    });

    out
}

fn sheet(layout: &Layout, scale: u32, on: [u8; 3], off: [u8; 3], path: &std::path::Path) {
    let panels = frames(layout);
    let cols = 3u32;
    let rows = (panels.len() as u32).div_ceil(cols);
    let gap = 8u32;
    let (pw, ph) = (layout.size.width * scale, layout.size.height * scale);
    let canvas_w = cols * pw + (cols + 1) * gap;
    let canvas_h = rows * ph + (rows + 1) * gap;
    let mut canvas = Canvas::new(canvas_w, canvas_h, [40, 42, 48]);
    for (index, panel) in panels.iter().enumerate() {
        let col = index as u32 % cols;
        let row = index as u32 / cols;
        let x = gap + col * (pw + gap);
        let y = gap + row * (ph + gap);
        canvas.blit(panel, (x, y), scale, on, off);
    }
    canvas.write_bmp(path);
}

#[test]
fn preview() {
    let Ok(dir) = std::env::var("PREVIEW_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    // Each panel rendered the way it actually looks: the OLEDs are lit
    // pixels on black, the e-paper is ink on white paper.
    sheet(
        &Layout::OLED_128X64,
        3,
        [235, 240, 255],
        [8, 10, 14],
        &dir.join("oled-128x64.bmp"),
    );
    // The same panel driven by a pad rather than one button. Only the
    // hints differ, and they are exactly what needs looking at: they are
    // the longest strings on the narrowest screen in the class.
    sheet(
        &Layout {
            controls: Controls::Dpad,
            ..Layout::OLED_128X64
        },
        3,
        [235, 240, 255],
        [8, 10, 14],
        &dir.join("oled-128x64-dpad.bmp"),
    );
    sheet(
        &Layout::EPD_200X200,
        2,
        [20, 20, 20],
        [244, 242, 236],
        &dir.join("epd-200x200.bmp"),
    );
}
