use crate::framebuffer::fill_pixels;
use crate::*;
use embedded_graphics::{
    pixelcolor::{BinaryColor, Rgb565},
    prelude::*,
    primitives::Rectangle,
};
use embedded_hal::digital::{self, ErrorType as PinErrorType};
use embedded_hal_async::delay::DelayNs;
use embedded_hal_async::spi::{self, ErrorType, Operation, SpiDevice};
use std::{boxed::Box, cell::RefCell, rc::Rc, vec, vec::Vec};

fn frame(spec: &PanelSpec) -> Framebuffer {
    let bytes = Box::leak(vec![0; spec.frame_bytes()].into_boxed_slice());
    Framebuffer::new(bytes, spec.width.into(), spec.height.into())
}

#[test]
fn framebuffer_clipping_packing_and_last_stripe() {
    let mut fb = frame(&ST7796_PAGER);
    fb.binary()
        .draw_iter([
            Pixel(Point::new(-1, 0), BinaryColor::On),
            Pixel(Point::new(0, 0), BinaryColor::On),
            Pixel(Point::new(479, 221), BinaryColor::On),
            Pixel(Point::new(480, 221), BinaryColor::On),
        ])
        .unwrap();
    let mut bytes = vec![0; ST7796_PAGER.stripe_bytes()];
    assert_eq!(fb.stripe(0, &mut bytes), ST7796_PAGER.stripe_bytes());
    assert_eq!(&bytes[..4], &[255, 255, 0, 0]);
    let len = fb.stripe(220, &mut bytes);
    assert_eq!(len, 1920);
    assert_eq!(&bytes[len - 2..len], &[255, 255]);
    fb.invert();
    fb.stripe(0, &mut bytes);
    assert_eq!(&bytes[..4], &[0, 0, 255, 255]);
    fb.stripe(220, &mut bytes);
    assert_eq!(&bytes[len - 2..len], &[0, 0]);
    fb.invert();
    fb.stripe(0, &mut bytes);
    assert_eq!(&bytes[..4], &[255, 255, 0, 0]);
}

#[test]
fn pixel_fills_hold_their_byte_order_at_any_alignment() {
    for offset in 0..4 {
        for pixels in 0..9 {
            let mut bytes = [0u8; 32];
            let span = offset..offset + 2 * pixels;
            fill_pixels(&mut bytes[span.clone()], [0xab, 0xcd]);
            for (i, &byte) in bytes.iter().enumerate() {
                let expected = if span.contains(&i) {
                    [0xab, 0xcd][(i - offset) % 2]
                } else {
                    0
                };
                assert_eq!(byte, expected, "offset {offset}, {pixels} pixels, byte {i}");
            }
        }
    }
}

#[test]
fn framebuffer_stores_big_endian_rgb565_and_clips_fills() {
    for spec in [&ST7796_PAGER, &ST7789_TDECK] {
        let (width, height) = (i32::from(spec.width), i32::from(spec.height));
        let mut fb = frame(spec);
        let color = Rgb565::new(0x1f, 0, 0x01);
        fb.draw_iter([Pixel(Point::new(1, 0), color)]).unwrap();
        fb.fill_solid(
            &Rectangle::new(Point::new(width - 2, height - 3), Size::new(10, 10)),
            color,
        )
        .unwrap();
        let mut bytes = vec![0; spec.stripe_bytes()];
        fb.stripe(0, &mut bytes);
        assert_eq!(&bytes[..4], &[0, 0, 0xf8, 0x01]);
        let len = fb.stripe(height as usize - 4, &mut bytes);
        let row = width as usize * 2;
        assert_eq!(len, 4 * row);
        assert_eq!(&bytes[len - 6..len], &[0, 0, 0xf8, 0x01, 0xf8, 0x01]);
        assert_eq!(
            &bytes[len - row - 6..len - row],
            &[0, 0, 0xf8, 0x01, 0xf8, 0x01]
        );
    }
}

#[test]
fn repainting_an_unchanged_frame_needs_no_transfers() {
    // Stripes that differ from what was sent, with their hashes.
    fn changed<const N: usize>(frame: &Framebuffer, sent: &SentStripes<N>) -> Vec<(usize, u64)> {
        let mut out = [0; 480 * STRIPE_ROWS * 2];
        (0..frame.height())
            .step_by(STRIPE_ROWS)
            .enumerate()
            .filter_map(|(index, y)| {
                let len = frame.stripe(y, &mut out);
                sent.changed(index, &out[..len]).map(|hash| (index, hash))
            })
            .collect()
    }
    fn run<const N: usize>(spec: &PanelSpec) {
        let stripes = spec.stripes();
        assert_eq!(stripes, N);
        let (right, bottom) = (i32::from(spec.width) - 1, i32::from(spec.height) - 1);
        let mut frame = frame(spec);
        let mut sent = SentStripes::<N>::new();
        // Nothing is known to be on the panel yet.
        assert_eq!(changed(&frame, &sent).len(), stripes);
        for (index, hash) in changed(&frame, &sent) {
            sent.sent(index, hash);
        }
        assert!(changed(&frame, &sent).is_empty());

        let pixel = Pixel(Point::new(20, 26), BinaryColor::On);
        frame.binary().draw_iter([pixel]).unwrap();
        let pending = changed(&frame, &sent);
        assert_eq!(pending.iter().map(|&(i, _)| i).collect::<Vec<_>>(), [6]);
        // Only successful transfers update history; an unsent stripe retries.
        assert_eq!(changed(&frame, &sent), pending);
        sent.sent(pending[0].0, pending[0].1);
        // Clearing and redrawing the same pixels sends nothing.
        frame.binary().clear(BinaryColor::Off).unwrap();
        frame.binary().draw_iter([pixel]).unwrap();
        assert!(changed(&frame, &sent).is_empty());
        frame.binary().clear(BinaryColor::Off).unwrap();
        assert_eq!(changed(&frame, &sent).len(), 1);

        // The final stripe, short on the Pager, follows the same rules.
        frame
            .binary()
            .draw_iter([Pixel(Point::new(right, bottom), BinaryColor::On)])
            .unwrap();
        let pending = changed(&frame, &sent);
        assert_eq!(pending.last().unwrap().0, stripes - 1);
        for (index, hash) in pending {
            sent.sent(index, hash);
        }
        assert!(changed(&frame, &sent).is_empty());
        // A failed transfer forgets everything.
        sent.forget();
        assert_eq!(changed(&frame, &sent).len(), stripes);
    }
    run::<{ ST7796_PAGER.stripes() }>(&ST7796_PAGER);
    run::<{ ST7789_TDECK.stripes() }>(&ST7789_TDECK);
}

/// Each command with the data written after it.
type Commands = Vec<(u8, Vec<u8>)>;

/// What reached the panel, and whether DC is at data.
#[derive(Clone, Default)]
struct Wire(Rc<RefCell<(bool, Commands)>>);
impl ErrorType for Wire {
    type Error = spi::ErrorKind;
}
impl SpiDevice<u8> for Wire {
    async fn transaction(
        &mut self,
        operations: &mut [Operation<'_, u8>],
    ) -> Result<(), Self::Error> {
        let mut wire = self.0.borrow_mut();
        for operation in operations {
            let Operation::Write(bytes) = operation else {
                unreachable!()
            };
            if wire.0 {
                wire.1.last_mut().unwrap().1.extend_from_slice(bytes);
            } else {
                assert_eq!(bytes.len(), 1);
                wire.1.push((bytes[0], Vec::new()));
            }
        }
        Ok(())
    }
}
struct Dc(Wire);
impl PinErrorType for Dc {
    type Error = digital::ErrorKind;
}
impl digital::OutputPin for Dc {
    fn set_low(&mut self) -> Result<(), Self::Error> {
        self.0.0.borrow_mut().0 = false;
        Ok(())
    }
    fn set_high(&mut self) -> Result<(), Self::Error> {
        self.0.0.borrow_mut().0 = true;
        Ok(())
    }
}
struct NoDelay;
impl DelayNs for NoDelay {
    async fn delay_ns(&mut self, _: u32) {}
}

fn sent(spec: &'static PanelSpec, run: impl AsyncFnOnce(&mut St77xx<Wire, Dc>)) -> Commands {
    let wire = Wire::default();
    let mut panel = St77xx::new(wire.clone(), Dc(wire.clone()), spec);
    embassy_futures::block_on(run(&mut panel));
    core::mem::take(&mut wire.0.borrow_mut().1)
}

#[test]
fn init_wraps_the_panels_list_in_reset_sleep_out_and_display_off() {
    for spec in [&ST7796_PAGER, &ST7789_TDECK] {
        let commands = sent(spec, async |panel| panel.init(&mut NoDelay).await.unwrap());
        let mut expected = vec![(0x01, vec![]), (0x11, vec![])];
        expected.extend(spec.init.iter().map(|&(c, d)| (c, d.to_vec())));
        expected.push((0x28, vec![]));
        assert_eq!(commands, expected);
    }
}

#[test]
fn sleep_and_wake_leave_the_settings_and_frame_alone() {
    let commands = sent(&ST7796_PAGER, async |panel| {
        panel.sleep().await.unwrap();
        panel.wake(&mut NoDelay).await.unwrap();
    });
    assert_eq!(commands, [(0x10, vec![]), (0x11, vec![])]);
}

#[test]
fn a_stripe_sets_its_window_to_the_bottom_then_follows_on() {
    let pixels = vec![0x5a; ST7796_PAGER.stripe_bytes()];
    let commands = sent(&ST7796_PAGER, async |panel| {
        panel.stripe(8, &pixels, false).await.unwrap();
        panel.stripe(12, &pixels, true).await.unwrap();
    });
    assert_eq!(
        commands,
        [
            (0x2a, vec![0, 0, 1, 0xdf]),
            // Rows 49 + 8 through 49 + 221.
            (0x2b, vec![0, 57, 1, 0x0e]),
            (0x2c, pixels.clone()),
            (0x3c, pixels.clone()),
        ]
    );
    let pixels = vec![0xa5; ST7789_TDECK.stripe_bytes() / 2];
    let commands = sent(&ST7789_TDECK, async |panel| {
        panel.stripe(238, &pixels, false).await.unwrap();
    });
    assert_eq!(
        commands,
        [
            (0x2a, vec![0, 0, 1, 0x3f]),
            (0x2b, vec![0, 238, 0, 0xef]),
            (0x2c, pixels.clone()),
        ]
    );
}
