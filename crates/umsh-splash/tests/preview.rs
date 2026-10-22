//! The splash at each panel's size, written out to be looked at:
//!
//! ```text
//! PREVIEW_DIR=/tmp cargo test -p umsh-splash --test preview
//! sips -s format png /tmp/splash-480x222.bmp --out /tmp/splash-480x222.png
//! ```
//!
//! Without `PREVIEW_DIR` only the drawing runs, so it costs CI nothing.

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use umsh_splash::Splash;
use umsh_ux_communicator::board::Board;
use umsh_ux_communicator::font::MEDIUM;

struct Panel {
    size: Size,
    px: Vec<Rgb565>,
}

impl Panel {
    fn new(size: Size) -> Self {
        Self {
            size,
            px: vec![Rgb565::new(0x1F, 0, 0x1F); (size.width * size.height) as usize],
        }
    }

    /// A 24-bit bottom-up BMP, the panel's colors widened.
    fn bmp(&self) -> Vec<u8> {
        let (w, h) = (self.size.width, self.size.height);
        let row = (w * 3).div_ceil(4) * 4;
        let data = row * h;
        let mut out = Vec::with_capacity(54 + data as usize);
        out.extend_from_slice(b"BM");
        out.extend_from_slice(&(54 + data).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&54u32.to_le_bytes());
        out.extend_from_slice(&40u32.to_le_bytes());
        out.extend_from_slice(&w.to_le_bytes());
        out.extend_from_slice(&h.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&24u16.to_le_bytes());
        out.extend_from_slice(&[0; 24]);
        for y in (0..h).rev() {
            for x in 0..w {
                let c = self.px[(y * w + x) as usize];
                let widen = |v: u8, bits: u32| (u32::from(v) * 255 / ((1 << bits) - 1)) as u8;
                out.extend_from_slice(&[widen(c.b(), 5), widen(c.g(), 6), widen(c.r(), 5)]);
            }
            out.resize(out.len() + (row - w * 3) as usize, 0);
        }
        out
    }
}

impl OriginDimensions for Panel {
    fn size(&self) -> Size {
        self.size
    }
}

impl DrawTarget for Panel {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        for Pixel(Point { x, y }, c) in pixels {
            if x >= 0 && y >= 0 && (x as u32) < self.size.width && (y as u32) < self.size.height {
                self.px[(y as u32 * self.size.width + x as u32) as usize] = c;
            }
        }
        Ok(())
    }
}

#[test]
fn every_panel_renders_and_can_be_written_out() {
    let dir = std::env::var_os("PREVIEW_DIR");
    // Each board's splash in the face it sets body text in, as the firmware
    // draws it.
    let cases = [
        (
            &Splash::TFT_480X222,
            &Board::PAGER,
            "fw-2026.10.19-44-ga945d5290",
        ),
        (
            &Splash::TFT_320X240,
            &Board::TDECK,
            "fw-2026.10.19-44-ga945d5290-dirty",
        ),
    ];
    for (splash, board, version) in cases {
        let size = board.metrics.size();
        let mut panel = Panel::new(size);
        splash.render(&mut panel, MEDIUM.face(board.metrics.body), version);
        // Nothing of the frame is left undrawn, and the logo's orange is in it.
        assert!(panel.px.iter().all(|&c| c != Rgb565::new(0x1F, 0, 0x1F)));
        assert!(panel.px.contains(&Rgb565::new(0xFA >> 3, 0x50 >> 2, 0)));
        assert!(panel.px.contains(&Rgb565::WHITE));
        if let Some(dir) = &dir {
            let path = std::path::Path::new(dir)
                .join(format!("splash-{}x{}.bmp", size.width, size.height));
            std::fs::write(&path, panel.bmp()).unwrap();
            eprintln!("wrote {}", path.display());
        }
    }
}
