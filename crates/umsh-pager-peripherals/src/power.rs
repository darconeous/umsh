//! XL9555 power domains and BQ25896/BQ27220 telemetry.
use embedded_hal_async::{delay::DelayNs, i2c::I2c};

const EXPANDER: u8 = 0x20;
const CHARGER: u8 = 0x6b;
const GAUGE: u8 = 0x55;
const BATFET_DIS: u8 = 1 << 5;
const BATFET_DLY: u8 = 1 << 3;
pub const HAPTIC_ENABLE: u16 = 1;
pub const AMPLIFIER_ENABLE: u16 = 1 << 1;
pub const KEYBOARD_RESET: u16 = 1 << 2;
pub const RADIO_ENABLE: u16 = 1 << 3;
pub const GPS_ENABLE: u16 = 1 << 4;
pub const GPS_RESET: u16 = 1 << 7;
pub const KEYBOARD_ENABLE: u16 = 1 << 8;
// Bit 10 is SD detect; bit 11 remains an input, following LilyGo's board setup.
const OUTPUTS: u16 = 0x13bf;

pub struct Expander<I> {
    i2c: I,
    outputs: u16,
    shutting_down: bool,
}
impl<I: I2c> Expander<I> {
    pub fn new(i2c: I) -> Self {
        Self {
            i2c,
            outputs: 0,
            shutting_down: false,
        }
    }
    pub async fn init(&mut self, delay: &mut impl DelayNs) -> Result<(), I::Error> {
        // Latch low before changing direction: no transient enables at boot.
        self.i2c.write(EXPANDER, &[2, 0, 0]).await?;
        self.i2c.write(EXPANDER, &[4, 0, 0]).await?;
        let config = (!OUTPUTS).to_le_bytes();
        self.i2c.write(EXPANDER, &[6, config[0], config[1]]).await?;
        self.outputs = 0;
        self.set(KEYBOARD_ENABLE | RADIO_ENABLE, true).await?;
        delay.delay_ms(10).await;
        self.set(KEYBOARD_RESET, true).await?;
        delay.delay_ms(10).await;
        Ok(())
    }
    pub async fn set(&mut self, mask: u16, enabled: bool) -> Result<(), I::Error> {
        if self.shutting_down && enabled {
            return Ok(());
        }
        let next = if enabled {
            self.outputs | (mask & OUTPUTS)
        } else {
            self.outputs & !mask
        };
        let bytes = next.to_le_bytes();
        self.i2c.write(EXPANDER, &[2, bytes[0], bytes[1]]).await?;
        self.outputs = next;
        Ok(())
    }
    pub async fn shutdown(&mut self) -> Result<(), I::Error> {
        self.shutting_down = true;
        self.set(OUTPUTS, false).await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charge {
    Discharging,
    Charging,
    Charged,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub voltage_mv: Option<u16>,
    pub percent: Option<u8>,
    pub charge: Option<Charge>,
    pub vbus: bool,
}

/// Unmodified BQ27220 standard-command readings; no configuration writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GaugeDiagnostics {
    /// Positive while charging, negative while discharging.
    pub current_ma: i16,
    pub remaining_mah: u16,
    pub full_mah: u16,
    pub design_mah: u16,
    /// 65535 requests the charger's maximum voltage, not 65.535 V.
    pub charging_mv: u16,
    pub status: u16,
    pub operation: u16,
}
pub struct Battery<I> {
    i2c: I,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TerminationLimit {
    pub before_ma: u16,
    pub after_ma: u16,
    pub watchdog_disabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TerminationError<E> {
    Bus(E),
    TaperTooLow(u16),
    Verify {
        register: u8,
        expected: u8,
        actual: u8,
    },
}

// At least 25% nominal current margin, rounded down to the charger's 64 mA
// steps. This provides headroom, not a guarantee of gauge taper-window timing.
pub(crate) fn termination_limit_code(taper_ma: u16) -> Option<u8> {
    let steps = ((u32::from(taper_ma) * 3 / 4) / 64).min(16);
    steps.checked_sub(1).map(|value| value as u8)
}

impl<I: I2c> Battery<I> {
    pub fn new(i2c: I) -> Self {
        Self { i2c }
    }
    /// Restore the battery power path and enable telemetry without changing
    /// charge policy or touching the gauge's configuration/security state.
    pub async fn start_telemetry(&mut self) -> Result<(), I::Error> {
        // A USB-powered restart can retain shipping mode's battery disconnect.
        crate::update(&mut self.i2c, CHARGER, 9, BATFET_DIS, 0).await?;
        crate::update(&mut self.i2c, CHARGER, 2, 0xc0, 0xc0).await
    }

    /// Only lower an excessive cutoff; preserve a more conservative setting.
    /// Do not change charge enable, voltage, fast/precharge current, or the gauge.
    pub async fn limit_termination(
        &mut self,
        taper_ma: u16,
    ) -> Result<TerminationLimit, TerminationError<I::Error>> {
        let limit =
            termination_limit_code(taper_ma).ok_or(TerminationError::TaperTooLow(taper_ma))?;
        let before = crate::read(&mut self.i2c, CHARGER, 5)
            .await
            .map_err(TerminationError::Bus)?;
        let watchdog = crate::read(&mut self.i2c, CHARGER, 7)
            .await
            .map_err(TerminationError::Bus)?;
        // The firmware does not service this watchdog. Disable it so it cannot
        // silently replace the checked cutoff with the chip's 256 mA default.
        let after = (before & 0xf0) | (before & 15).min(limit);
        for (register, old, expected) in [(7, watchdog, watchdog & !0x30), (5, before, after)] {
            if old != expected {
                self.i2c
                    .write(CHARGER, &[register, expected])
                    .await
                    .map_err(TerminationError::Bus)?;
            }
            let actual = crate::read(&mut self.i2c, CHARGER, register)
                .await
                .map_err(TerminationError::Bus)?;
            if actual != expected {
                return Err(TerminationError::Verify {
                    register,
                    expected,
                    actual,
                });
            }
        }
        Ok(TerminationLimit {
            before_ma: 64 * (u16::from(before & 15) + 1),
            after_ma: 64 * (u16::from(after & 15) + 1),
            watchdog_disabled: watchdog & 0x30 != 0,
        })
    }

    async fn word(&mut self, reg: u8) -> Result<u16, I::Error> {
        let mut bytes = [0; 2];
        self.i2c.write_read(GAUGE, &[reg], &mut bytes).await?;
        Ok(u16::from_le_bytes(bytes))
    }
    pub async fn read(&mut self) -> Result<Reading, I::Error> {
        let status = crate::read(&mut self.i2c, CHARGER, 0x0b).await?;
        let vbus = crate::read(&mut self.i2c, CHARGER, 0x11).await? & 0x80 != 0;
        // A missing gauge must not suppress USB attach/detach detection.
        let gauge = match (
            self.word(8).await,
            self.word(0x0a).await,
            self.word(0x2c).await,
            self.word(0x3a).await,
        ) {
            (Ok(mv), Ok(flags), Ok(soc), Ok(operation)) => Some((mv, flags, soc, operation)),
            _ => None,
        };
        Ok(decode_reading(status, vbus, gauge))
    }
    pub async fn diagnostics(&mut self) -> Result<GaugeDiagnostics, I::Error> {
        Ok(GaugeDiagnostics {
            current_ma: self.word(0x0c).await? as i16,
            remaining_mah: self.word(0x10).await?,
            full_mah: self.word(0x12).await?,
            design_mah: self.word(0x3c).await?,
            charging_mv: self.word(0x30).await?,
            status: self.word(0x0a).await?,
            operation: self.word(0x3a).await?,
        })
    }

    async fn sample_word(&mut self, delay: &mut impl DelayNs, reg: u8) -> Result<u16, I::Error> {
        // BQ27220 requires >=66 us bus-free between packets at 400 kHz.
        delay.delay_us(100).await;
        let result = self.word(reg).await;
        delay.delay_us(100).await;
        result
    }

    /// Read requested scalar registers once, retaining independent failures.
    /// The owner separately services explicit configuration inspection requests.
    pub async fn sample(
        &mut self,
        fields: umsh_ulcp::battery_diagnostics::Fields,
        delay: &mut impl DelayNs,
    ) -> umsh_ulcp::battery_diagnostics::Sample {
        use umsh_ulcp::{
            Status,
            battery::{BatteryChargeState, BatteryStatus},
            battery_diagnostics::{Sample, Value, VoltageRequest},
            ids::prop,
        };
        let mut sample = Sample::default();
        let snapshot = fields.contains(prop::BATTERY);
        let needed = |key| fields.contains(key);
        let capacities =
            needed(prop::BATTERY_REMAINING_CAPACITY) || needed(prop::BATTERY_FULL_CAPACITY);
        let voltage_request = needed(prop::BATTERY_CHARGE_VOLTAGE_REQUEST);
        let status_needed = snapshot
            || capacities
            || voltage_request
            || needed(prop::BATTERY_CURRENT)
            || needed(prop::BATTERY_PRESENT)
            || needed(prop::BATTERY_GAUGE_FULL)
            || needed(prop::BATTERY_GAUGE_STATUS);
        let operation_needed = snapshot
            || capacities
            || voltage_request
            || needed(prop::BATTERY_GAUGE_INITIALIZED)
            || needed(prop::BATTERY_GAUGE_SMOOTHING)
            || needed(prop::BATTERY_GAUGE_OPERATION_STATUS);
        let charger = if snapshot {
            crate::read(&mut self.i2c, CHARGER, 0x0b).await.ok()
        } else {
            None
        };
        let vbus = if snapshot || needed(prop::BATTERY_EXT_POWER_PRESENT) {
            crate::read(&mut self.i2c, CHARGER, 0x11)
                .await
                .ok()
                .map(|v| v & 0x80 != 0)
        } else {
            None
        };
        let status = if status_needed {
            self.sample_word(delay, 0x0a).await.ok()
        } else {
            None
        };
        let operation = if operation_needed {
            self.sample_word(delay, 0x3a).await.ok()
        } else {
            None
        };
        if snapshot {
            let mv = self.sample_word(delay, 8).await.ok();
            let soc = self.sample_word(delay, 0x2c).await.ok();
            sample.snapshot = charger
                .zip(vbus)
                .map(|(charger, vbus)| {
                    let gauge = mv
                        .zip(status)
                        .zip(soc)
                        .zip(operation)
                        .map(|(((mv, s), soc), op)| (mv, s, soc, op));
                    let r = decode_reading(charger, vbus, gauge);
                    BatteryStatus {
                        voltage_mv: r.voltage_mv,
                        level_percent: r.percent,
                        charge_state: r.charge.map(|c| match c {
                            Charge::Charging => BatteryChargeState::Charging,
                            Charge::Discharging => BatteryChargeState::Discharging,
                            Charge::Charged => BatteryChargeState::Charged,
                        }),
                    }
                })
                .ok_or(());
        }
        let mut set = |key, value: Option<Value>| {
            if needed(key) {
                sample.set(key, value.map(Some).ok_or(Status::FAILURE));
            }
        };
        set(prop::BATTERY_EXT_POWER_PRESENT, vbus.map(Value::Bool));
        set(
            prop::BATTERY_PRESENT,
            status.map(|s| Value::Bool(s & 8 != 0)),
        );
        set(
            prop::BATTERY_GAUGE_FULL,
            status.map(|s| Value::Bool(s & 0x200 != 0)),
        );
        set(
            prop::BATTERY_GAUGE_STATUS,
            status.map(|s| Value::Unsigned(s.into())),
        );
        set(
            prop::BATTERY_GAUGE_INITIALIZED,
            operation.map(|s| Value::Bool(s & 0x20 != 0)),
        );
        set(
            prop::BATTERY_GAUGE_SMOOTHING,
            operation.map(|s| Value::Bool(s & 0x40 != 0)),
        );
        set(
            prop::BATTERY_GAUGE_OPERATION_STATUS,
            operation.map(|s| Value::Unsigned(s.into())),
        );
        set(prop::BATTERY_GAUGE_FORMAT, Some(Value::Format(1)));
        for (key, reg) in [
            (prop::BATTERY_CURRENT, 0x0c),
            (prop::BATTERY_REMAINING_CAPACITY, 0x10),
            (prop::BATTERY_FULL_CAPACITY, 0x12),
            (prop::BATTERY_DESIGN_CAPACITY, 0x3c),
            (prop::BATTERY_CHARGE_VOLTAGE_REQUEST, 0x30),
        ] {
            if !needed(key) {
                continue;
            }
            if key != prop::BATTERY_DESIGN_CAPACITY {
                let ready = status.map(|s| s & 8 != 0);
                let ready = if key == prop::BATTERY_CURRENT {
                    ready
                } else {
                    ready
                        .zip(operation)
                        .map(|(present, op)| present && op & 0x20 != 0)
                };
                match ready {
                    Some(false) => {
                        sample.set(key, Ok(None));
                        continue;
                    }
                    None => {
                        sample.set(key, Err(Status::FAILURE));
                        continue;
                    }
                    Some(true) => {}
                }
            }
            let value = self
                .sample_word(delay, reg)
                .await
                .map(|v| {
                    Some(match key {
                        prop::BATTERY_CURRENT => Value::Current(i32::from(v as i16)),
                        prop::BATTERY_CHARGE_VOLTAGE_REQUEST => Value::Voltage(if v == u16::MAX {
                            VoltageRequest::Maximum
                        } else {
                            VoltageRequest::Millivolts(v.into())
                        }),
                        _ => Value::Unsigned(v.into()),
                    })
                })
                .map_err(|_| Status::FAILURE);
            sample.set(key, value);
        }
        if needed(prop::BATTERY_GAUGE_TELEMETRY) {
            sample.gauge_telemetry = self.telemetry(delay).await.map_err(|_| Status::FAILURE);
        }
        sample
    }
    /// Standard commands are readable while sealed. No security/configuration writes.
    async fn telemetry(
        &mut self,
        delay: &mut impl DelayNs,
    ) -> Result<umsh_ulcp::battery_gauge_telemetry::Telemetry, I::Error> {
        use umsh_ulcp::battery_gauge_telemetry::{FIELDS, Telemetry};
        let mut result = Telemetry::default();
        for (i, field) in FIELDS.iter().enumerate() {
            result.raw[i] = self.sample_word(delay, field.register).await?;
        }
        Ok(result)
    }
    pub async fn inspect_configuration(
        &mut self,
        delay: &mut impl DelayNs,
    ) -> Result<umsh_ulcp::battery_gauge_config::Config, crate::gauge::ConfigError<I::Error>> {
        crate::gauge::inspect_configuration(&mut self.i2c, delay).await
    }

    pub async fn sleep(&mut self) -> Result<(), I::Error> {
        crate::update(&mut self.i2c, CHARGER, 2, 0xc0, 0).await
    }

    /// Disconnect the battery from SYS (BQ25896 datasheet sections 9.2.10/9.4.10).
    /// Call after peripheral shutdown: battery-only system power falls immediately.
    /// QON or a newly attached USB supply restores power. An existing USB supply
    /// can keep SYS powered, so the caller must still enter its sleep fallback.
    pub async fn power_off(&mut self) -> Result<(), I::Error> {
        // Set BATFET_DIS and clear BATFET_DLY for immediate shipping mode.
        // Preserve the safety timer, JEITA, and QON full-system-reset settings.
        crate::update(
            &mut self.i2c,
            CHARGER,
            9,
            BATFET_DIS | BATFET_DLY,
            BATFET_DIS,
        )
        .await
    }
}

pub fn decode_reading(status: u8, vbus: bool, gauge: Option<(u16, u16, u16, u16)>) -> Reading {
    let mut reading = Reading {
        voltage_mv: None,
        percent: None,
        charge: None,
        vbus,
    };
    if let Some((mv, flags, soc, operation)) = gauge {
        // BAT_DET bit 3 and a plausible single-cell voltage; INITCOMP gates SOC.
        if flags & 8 != 0 && (2000..=4600).contains(&mv) {
            reading.voltage_mv = Some(mv);
            reading.percent = (operation & 0x20 != 0 && soc <= 100).then_some(soc as u8);
            reading.charge = if !vbus {
                Some(Charge::Discharging)
            } else {
                match (status >> 3) & 3 {
                    1 | 2 => Some(Charge::Charging),
                    3 => Some(Charge::Charged),
                    _ => None,
                }
            };
        }
    }
    reading
}

#[derive(Default)]
pub struct LowBattery {
    consecutive: u8,
}
impl LowBattery {
    /// Called only on the one-second cadence, not on host-requested samples.
    pub fn sample(&mut self, sample: Option<&Reading>) -> bool {
        if sample.is_some_and(|r| !r.vbus && r.voltage_mv.is_some_and(|mv| mv <= 3100)) {
            self.consecutive = self.consecutive.saturating_add(1);
        } else {
            self.consecutive = 0;
        }
        self.consecutive >= 10
    }
}
