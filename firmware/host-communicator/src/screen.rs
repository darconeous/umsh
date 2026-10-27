//! The board as a window: its front, with the panel in it, drawn at
//! whatever size the window is given and kept to the board's shape. The
//! panel dims and darkens as the board's does; the rest stays as it is. The
//! pointer's position comes in the face's own pixels.

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::{OriginDimensions, Size};
use embedded_graphics::primitives::Rectangle;
use embedded_graphics_simulator::SimulatorDisplay;
use sdl2::event::Event;
use sdl2::pixels::{Color, PixelFormatEnum};
use sdl2::rect::Rect;
use sdl2::render::{Canvas, Texture, TextureCreator};
use sdl2::video::{Window, WindowContext};
use sdl2::{EventPump, Sdl};

/// The dim floor, in permille of full brightness: where a dimming panel
/// settles, as a backlight's lowest step leaves it readable.
const DIM_FLOOR: u32 = 250;
/// The largest the window opens, in multiples of the face's size, and how
/// much of the display it may take.
const SCALE: f32 = 2.0;
const FIT: f32 = 0.9;

pub struct Screen {
    canvas: Canvas<Window>,
    /// The board's front, and the panel's last frame.
    face: Texture<'static>,
    panel: Texture<'static>,
    /// Where on the face the panel is.
    at: Rect,
    events: EventPump,
    /// How bright the panel is, in permille of full: zero is dark.
    brightness: u16,
    _sdl: Sdl,
}

impl Screen {
    /// A window titled `title` showing a face of `size` with the panel at
    /// `panel`, opened as large as fits up to twice that.
    pub fn new(title: &str, size: Size, panel: Rectangle) -> Result<Self, String> {
        let sdl = sdl2::init()?;
        let video = sdl.video()?;
        let scale = video.display_usable_bounds(0).map_or(SCALE, |bounds| {
            let fit = |room: u32, length: u32| room as f32 * FIT / length as f32;
            fit(bounds.width(), size.width)
                .min(fit(bounds.height(), size.height))
                .min(SCALE)
        });
        let window = video
            .window(
                title,
                (size.width as f32 * scale) as u32,
                (size.height as f32 * scale) as u32,
            )
            .position_centered()
            .resizable()
            .allow_highdpi()
            .build()
            .map_err(|e| e.to_string())?;
        let mut canvas = window.into_canvas().build().map_err(|e| e.to_string())?;
        // The face is drawn as large as fits, at its own shape, and the
        // pointer reported in its pixels.
        canvas
            .set_logical_size(size.width, size.height)
            .map_err(|e| e.to_string())?;
        // It lives as long as the window, which is as long as the process.
        let creator: &'static TextureCreator<WindowContext> =
            Box::leak(Box::new(canvas.texture_creator()));
        let texture = |size: Size| {
            creator
                .create_texture_streaming(PixelFormatEnum::RGB565, size.width, size.height)
                .map_err(|e| e.to_string())
        };
        let at = Rect::new(
            panel.top_left.x,
            panel.top_left.y,
            panel.size.width,
            panel.size.height,
        );
        let events = sdl.event_pump()?;
        Ok(Self {
            canvas,
            face: texture(size)?,
            panel: texture(panel.size)?,
            at,
            events,
            brightness: 1000,
            _sdl: sdl,
        })
    }

    /// Shows `display` as the panel's frame.
    pub fn update(&mut self, display: &SimulatorDisplay<Rgb565>) {
        if load(&mut self.panel, display) {
            self.present();
        }
    }

    /// Shows `display` as the board's front.
    pub fn update_face(&mut self, display: &SimulatorDisplay<Rgb565>) {
        if load(&mut self.face, display) {
            self.present();
        }
    }

    /// Sets how bright the panel is, in permille between its dim floor
    /// and full, as [`Attention::brightness_permille`] gives it.
    ///
    /// [`Attention::brightness_permille`]: umsh_ux_display_tracker::attention::Attention::brightness_permille
    pub fn set_brightness(&mut self, permille: u16) {
        let permille = u32::from(permille.min(1000));
        self.brightness = (DIM_FLOOR + (1000 - DIM_FLOOR) * permille / 1000) as u16;
        self.present();
    }

    /// Turns the panel off, or on at full brightness.
    pub fn set_on(&mut self, on: bool) {
        self.brightness = if on { 1000 } else { 0 };
        self.present();
    }

    /// The window's events since the last call.
    pub fn events(&mut self) -> Vec<Event> {
        self.events.poll_iter().collect()
    }

    /// Draws the last frames again, the panel as it is lit, as after the
    /// window was resized or uncovered.
    pub fn present(&mut self) {
        self.canvas.set_draw_color(Color::BLACK);
        self.canvas.clear();
        let _ = self.canvas.copy(&self.face, None, None);
        if self.brightness > 0 {
            let level = (u32::from(self.brightness) * 255 / 1000) as u8;
            self.panel.set_color_mod(level, level, level);
            let _ = self.canvas.copy(&self.panel, None, self.at);
        } else {
            let _ = self.canvas.fill_rect(self.at);
        }
        self.canvas.present();
    }
}

/// Copies `display` into `texture`; returns whether it took.
fn load(texture: &mut Texture<'static>, display: &SimulatorDisplay<Rgb565>) -> bool {
    let pitch = display.size().width as usize * 2;
    texture.update(None, &display.to_ne_bytes(), pitch).is_ok()
}
