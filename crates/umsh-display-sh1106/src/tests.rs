//! Host tests over a recording mock I²C.
//!
//! These prove the driver's own byte streams and buffer arithmetic. They
//! cannot prove the command values are what an SH1106 wants — that is a
//! hardware-validation item, checked once per board bring-up.

extern crate alloc;

use alloc::vec::Vec;

use embassy_futures::block_on;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};
use embedded_hal_async::i2c::{ErrorType, I2c, Operation};

use super::*;

/// One I²C transaction the mock observed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Txn {
    Write { addr: u8, bytes: Vec<u8> },
    Read { addr: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MockError;

impl embedded_hal_async::i2c::Error for MockError {
    fn kind(&self) -> embedded_hal_async::i2c::ErrorKind {
        embedded_hal_async::i2c::ErrorKind::NoAcknowledge(
            embedded_hal_async::i2c::NoAcknowledgeSource::Address,
        )
    }
}

/// A bus where only the addresses in `present` acknowledge.
struct MockI2c {
    present: Vec<u8>,
    log: Vec<Txn>,
}

impl MockI2c {
    fn new(present: &[u8]) -> Self {
        Self {
            present: present.to_vec(),
            log: Vec::new(),
        }
    }

    fn acks(&self, addr: u8) -> bool {
        self.present.contains(&addr)
    }

    /// Every byte written to `addr`, transaction boundaries dropped.
    fn written(&self) -> Vec<u8> {
        self.log
            .iter()
            .flat_map(|t| match t {
                Txn::Write { bytes, .. } => bytes.clone(),
                Txn::Read { .. } => Vec::new(),
            })
            .collect()
    }

    fn writes(&self) -> Vec<Vec<u8>> {
        self.log
            .iter()
            .filter_map(|t| match t {
                Txn::Write { bytes, .. } => Some(bytes.clone()),
                Txn::Read { .. } => None,
            })
            .collect()
    }
}

impl ErrorType for MockI2c {
    type Error = MockError;
}

impl I2c for MockI2c {
    async fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        for op in operations {
            match op {
                Operation::Write(bytes) => self.log.push(Txn::Write {
                    addr: address,
                    bytes: bytes.to_vec(),
                }),
                Operation::Read(_) => self.log.push(Txn::Read { addr: address }),
            }
        }
        if self.acks(address) {
            Ok(())
        } else {
            Err(MockError)
        }
    }
}

// ─── Address discovery ────────────────────────────────────────────────────

#[test]
fn probe_prefers_0x3d_when_both_addresses_ack() {
    // The QMC6310N population: the magnetometer holds 0x3C and the panel
    // moved to 0x3D. Answering 0x3C here would drive the display at a
    // magnetometer.
    let mut bus = MockI2c::new(&[0x3C, 0x3D]);
    assert_eq!(block_on(probe(&mut bus)), Some(0x3D));
}

#[test]
fn probe_falls_back_to_0x3c() {
    let mut bus = MockI2c::new(&[0x3C]);
    assert_eq!(block_on(probe(&mut bus)), Some(0x3C));
    // 0x3D must have been tried first and refused.
    assert_eq!(bus.log.first(), Some(&Txn::Read { addr: 0x3D }));
}

#[test]
fn probe_finds_0x3d_alone() {
    let mut bus = MockI2c::new(&[0x3D]);
    assert_eq!(block_on(probe(&mut bus)), Some(0x3D));
}

#[test]
fn probe_reports_an_empty_bus() {
    let mut bus = MockI2c::new(&[]);
    assert_eq!(block_on(probe(&mut bus)), None);
    // Both candidates tried, neither answered.
    assert_eq!(
        bus.log,
        [Txn::Read { addr: 0x3D }, Txn::Read { addr: 0x3C }]
    );
}

#[test]
fn probe_uses_a_read_not_a_zero_length_write() {
    // A zero-length write is not reliably lowered to a bare address
    // frame across HALs, so the probe must read.
    let mut bus = MockI2c::new(&[]);
    let _ = block_on(probe(&mut bus));
    assert!(bus.writes().is_empty());
}

// ─── Command framing ──────────────────────────────────────────────────────

#[test]
fn commands_carry_the_command_control_byte() {
    let mut panel = Sh1106::new(MockI2c::new(&[0x3C]), 0x3C);
    block_on(panel.set_contrast(0x42)).unwrap();
    assert_eq!(panel.release().writes(), [[CTRL_CMD, 0x81, 0x42]]);
}

#[test]
fn commands_go_to_the_bound_address() {
    let mut panel = Sh1106::new(MockI2c::new(&[0x3D]), 0x3D);
    block_on(panel.set_display_on(true)).unwrap();
    assert_eq!(
        panel.release().log,
        [Txn::Write {
            addr: 0x3D,
            bytes: [CTRL_CMD, 0xAF].to_vec()
        }]
    );
}

#[test]
fn display_on_and_off_are_distinct_commands() {
    let mut panel = Sh1106::new(MockI2c::new(&[0x3C]), 0x3C);
    block_on(panel.set_display_on(true)).unwrap();
    block_on(panel.set_display_on(false)).unwrap();
    assert_eq!(
        panel.release().writes(),
        [[CTRL_CMD, 0xAF], [CTRL_CMD, 0xAE]]
    );
}

#[test]
fn init_enables_the_charge_pump_after_configuration() {
    let mut panel = Sh1106::new(MockI2c::new(&[0x3C]), 0x3C);
    block_on(panel.init()).unwrap();
    let bytes = panel.release().written();

    // Display-off leads, charge pump and display-on trail.
    assert_eq!(bytes.first(), Some(&CTRL_CMD));
    assert_eq!(bytes.get(1), Some(&0xAE));
    assert_eq!(&bytes[bytes.len() - 3..], &[0x8D, 0x14, 0xAF]);

    let pump = bytes.iter().position(|&b| b == 0x8D).unwrap();
    let mux = bytes.iter().position(|&b| b == 0xA8).unwrap();
    assert!(mux < pump, "multiplex ratio must be set before the pump");
}

#[test]
fn init_splits_into_two_transactions_within_the_command_limit() {
    let mut panel = Sh1106::new(MockI2c::new(&[0x3C]), 0x3C);
    block_on(panel.init()).unwrap();
    let writes = panel.release().writes();
    assert_eq!(writes.len(), 2);
    for w in writes {
        assert!(
            w.len() <= 1 + MAX_CMDS,
            "a command run exceeded the stack buffer and would be truncated"
        );
    }
}

#[test]
fn init_starts_at_normal_contrast() {
    let mut panel = Sh1106::new(MockI2c::new(&[0x3C]), 0x3C);
    block_on(panel.init()).unwrap();
    let bytes = panel.release().written();
    let at = bytes.iter().position(|&b| b == 0x81).unwrap();
    assert_eq!(bytes[at + 1], CONTRAST_NORMAL);
}

#[test]
fn a_refusing_bus_surfaces_as_an_error() {
    let mut panel = Sh1106::new(MockI2c::new(&[]), 0x3C);
    assert!(block_on(panel.init()).is_err());
}

// ─── Flush ────────────────────────────────────────────────────────────────

#[test]
fn flush_walks_every_page_with_the_column_offset() {
    let mut panel = Sh1106::new(MockI2c::new(&[0x3C]), 0x3C);
    let fb = Sh1106Fb::new();
    block_on(panel.flush(&fb)).unwrap();
    let writes = panel.release().writes();

    // One address run plus one data run per page.
    assert_eq!(writes.len(), HEIGHT / 8 * 2);

    for page in 0..HEIGHT / 8 {
        let addr = &writes[page * 2];
        assert_eq!(
            addr,
            &[CTRL_CMD, 0xB0 | page as u8, 0x02, 0x10],
            "page {page} address run"
        );
        let data = &writes[page * 2 + 1];
        assert_eq!(data.len(), 1 + WIDTH);
        assert_eq!(data[0], CTRL_DATA);
    }
}

#[test]
fn flush_sends_the_buffer_in_page_major_order() {
    let mut fb = Sh1106Fb::new();
    // Tag each page with its own index so a transposed flush is visible.
    for page in 0..HEIGHT / 8 {
        for col in 0..WIDTH {
            fb.0[page * WIDTH + col] = page as u8;
        }
    }

    let mut panel = Sh1106::new(MockI2c::new(&[0x3C]), 0x3C);
    block_on(panel.flush(&fb)).unwrap();
    let writes = panel.release().writes();

    for page in 0..HEIGHT / 8 {
        let data = &writes[page * 2 + 1];
        assert!(
            data[1..].iter().all(|&b| b == page as u8),
            "page {page} carried another page's bytes"
        );
    }
}

#[test]
fn flush_stops_at_the_first_bus_error() {
    let mut panel = Sh1106::new(MockI2c::new(&[]), 0x3C);
    let fb = Sh1106Fb::new();
    assert!(block_on(panel.flush(&fb)).is_err());
    // The first page's address run failed; no data run followed it.
    assert_eq!(panel.release().writes().len(), 1);
}

// ─── Frame buffer ─────────────────────────────────────────────────────────

#[test]
fn a_pixel_lands_in_the_right_page_and_bit() {
    let mut fb = Sh1106Fb::new();
    // Row 9 is page 1, bit 1; column 3.
    Pixel(Point::new(3, 9), BinaryColor::On)
        .draw(&mut fb)
        .unwrap();
    assert_eq!(fb.0[WIDTH + 3], 1 << 1);
    // Nothing else lit.
    assert_eq!(fb.0.iter().filter(|&&b| b != 0).count(), 1);
}

#[test]
fn bit_zero_is_the_top_of_a_page() {
    let mut fb = Sh1106Fb::new();
    Pixel(Point::new(0, 0), BinaryColor::On)
        .draw(&mut fb)
        .unwrap();
    Pixel(Point::new(0, 7), BinaryColor::On)
        .draw(&mut fb)
        .unwrap();
    assert_eq!(fb.0[0], 0b1000_0001);
}

#[test]
fn drawing_off_clears_only_that_pixel() {
    let mut fb = Sh1106Fb::new();
    Rectangle::new(Point::new(0, 0), Size::new(1, 8))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(&mut fb)
        .unwrap();
    assert_eq!(fb.0[0], 0xFF);

    Pixel(Point::new(0, 3), BinaryColor::Off)
        .draw(&mut fb)
        .unwrap();
    assert_eq!(fb.0[0], 0xFF & !(1 << 3));
}

#[test]
fn out_of_bounds_pixels_are_dropped_not_wrapped() {
    let mut fb = Sh1106Fb::new();
    for p in [
        Point::new(-1, 0),
        Point::new(0, -1),
        Point::new(WIDTH as i32, 0),
        Point::new(0, HEIGHT as i32),
        Point::new(i32::MAX, i32::MAX),
        Point::new(i32::MIN, i32::MIN),
    ] {
        Pixel(p, BinaryColor::On).draw(&mut fb).unwrap();
    }
    assert!(fb.0.iter().all(|&b| b == 0));
}

#[test]
fn the_corners_are_addressable() {
    let mut fb = Sh1106Fb::new();
    Pixel(
        Point::new(WIDTH as i32 - 1, HEIGHT as i32 - 1),
        BinaryColor::On,
    )
    .draw(&mut fb)
    .unwrap();
    assert_eq!(fb.0[BUF_SIZE - 1], 1 << 7);
}

#[test]
fn clear_empties_the_buffer() {
    let mut fb = Sh1106Fb::new();
    fb.0.fill(0xAA);
    fb.clear();
    assert!(fb.0.iter().all(|&b| b == 0));
}

#[test]
fn the_target_reports_panel_size() {
    assert_eq!(
        Sh1106Fb::new().size(),
        Size::new(WIDTH as u32, HEIGHT as u32)
    );
    assert_eq!(BUF_SIZE, WIDTH * HEIGHT / 8);
}
