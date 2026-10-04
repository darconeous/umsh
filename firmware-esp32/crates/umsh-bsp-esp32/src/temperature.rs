//! On-demand ESP32-S3 die temperature. The pinned esp-hal TSENS driver targets
//! other chips, so this owns SENS and uses the S3 PAC plus its ROM analog-I2C
//! accessors. No external I2C bus is involved.
//!
//! Register sequence and calibration follow ESP-IDF v5.4.2:
//! <https://github.com/espressif/esp-idf/blob/v5.4.2/components/hal/esp32s3/include/hal/temperature_sensor_ll.h>
//! <https://github.com/espressif/esp-idf/blob/v5.4.2/components/efuse/esp32s3/esp_efuse_rtc_calib.c>
//! The firmware uses RF entropy, not the ADC `TrngSource` (which would also
//! configure the analog SAR block). ADC voltage channels are left untouched.

mod conversion;

use embassy_time::{Duration, Instant, Timer};
use esp_hal::{efuse, peripherals::SENS};

pub struct TemperatureSensor<'d> {
    _sens: SENS<'d>,
    correction: i32,
}

impl<'d> TemperatureSensor<'d> {
    pub fn new(sens: SENS<'d>) -> Self {
        Self {
            _sens: sens,
            correction: conversion::correction(
                efuse::block_version().0,
                efuse::read_field_le(efuse::TEMP_CALIB),
            ),
        }
    }

    /// Fresh acquisition in tenths of a kelvin. Power and clock are released
    /// on success, failure, or cancellation. A stuck ready bit is bounded.
    pub async fn sample(&mut self) -> Option<u16> {
        let _power = Power;
        for range in conversion::RANGES.iter() {
            configure(range.dac);
            Timer::after_micros(300).await;
            let regs = SENS::regs();
            regs.sar_tsens_ctrl()
                .modify(|_, w| w.sar_tsens_dump_out().set_bit());
            let deadline = Instant::now() + Duration::from_millis(1);
            while !regs.sar_tsens_ctrl().read().sar_tsens_ready().bit_is_set() {
                if Instant::now() >= deadline {
                    return None;
                }
                Timer::after_micros(10).await;
            }
            regs.sar_tsens_ctrl()
                .modify(|_, w| w.sar_tsens_dump_out().clear_bit());
            let raw = regs.sar_tsens_ctrl().read().sar_tsens_out().bits();
            if let Some(value) = range.decode(raw, self.correction) {
                return Some(value);
            }
        }
        None
    }
}

fn configure(dac: u8) {
    critical_section::with(|_| {
        let regs = SENS::regs();
        regs.sar_tsens_ctrl()
            .modify(|_, w| w.sar_tsens_power_up().clear_bit());
        regs.sar_peri_clk_gate_conf()
            .modify(|_, w| w.tsens_clk_en().set_bit());
        regs.sar_peri_reset_conf()
            .modify(|_, w| w.sar_tsens_reset().set_bit());
        regs.sar_peri_reset_conf()
            .modify(|_, w| w.sar_tsens_reset().clear_bit());
        unsafe extern "C" {
            fn esp_rom_regi2c_read(block: u8, host: u8, reg: u8) -> u8;
            fn rom_i2c_writeReg(block: u8, host: u8, reg: u8, data: u8);
        }
        // S3 internal SAR analog block 0x69, host 1, TSENS_DAC low nibble of
        // register 6. Preserve its other bits and serialize the ROM RMW.
        unsafe {
            let old = esp_rom_regi2c_read(0x69, 1, 6);
            rom_i2c_writeReg(0x69, 1, 6, (old & 0xf0) | dac);
        }
        regs.sar_tsens_ctrl2()
            .modify(|_, w| unsafe { w.sar_tsens_xpd_force().bits(1) });
        regs.sar_tsens_ctrl().modify(|_, w| unsafe {
            w.sar_tsens_clk_div()
                .bits(6)
                .sar_tsens_dump_out()
                .clear_bit()
                .sar_tsens_power_up_force()
                .set_bit()
                .sar_tsens_power_up()
                .set_bit()
        });
    });
}

struct Power;
impl Drop for Power {
    fn drop(&mut self) {
        critical_section::with(|_| {
            let regs = SENS::regs();
            regs.sar_tsens_ctrl().modify(|_, w| {
                w.sar_tsens_dump_out()
                    .clear_bit()
                    .sar_tsens_power_up()
                    .clear_bit()
                    .sar_tsens_power_up_force()
                    .clear_bit()
            });
            regs.sar_tsens_ctrl2()
                .modify(|_, w| unsafe { w.sar_tsens_xpd_force().bits(0) });
            regs.sar_peri_clk_gate_conf()
                .modify(|_, w| w.tsens_clk_en().clear_bit());
        });
    }
}
