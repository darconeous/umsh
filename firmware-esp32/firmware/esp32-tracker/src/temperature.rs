//! Ordered inventory owned for the lifetime of the device, across ULCP resets.
//! Sources are explicit so adding another sensor never changes existing indices.
use umsh_bsp_esp32::temperature::TemperatureSensor;
use umsh_ulcp::Status;
use umsh_ulcp_runtime::temperature::TemperatureInventory;

#[derive(Clone, Copy)]
enum Source {
    McuDie,
    #[cfg(feature = "board-tbeam-supreme")]
    Bme280,
    #[cfg(feature = "pmic-axp2101")]
    PmicDie,
    #[cfg(feature = "board-tlora-pager")]
    GaugeTemperature,
    #[cfg(feature = "board-tlora-pager")]
    GaugeDie,
}

pub struct Sensors {
    inventory: TemperatureInventory<Source>,
    mcu: TemperatureSensor<'static>,
    #[cfg(feature = "board-tlora-pager")]
    separate_gauge_registered: bool,
    #[cfg(feature = "pmic-axp2101")]
    pmic: &'static super::SharedPmic,
}

/// Keep the bounded inventory out of the nested driver futures: moving its
/// arrays through each layer duplicates internal RAM and startup temporaries.
/// The device task retains exclusive ownership for the complete physical boot.
#[inline(never)]
pub fn sensors(
    mcu: TemperatureSensor<'static>,
    #[cfg(feature = "pmic-axp2101")] pmic: &'static super::SharedPmic,
) -> &'static mut Sensors {
    static SENSORS: static_cell::StaticCell<Sensors> = static_cell::StaticCell::new();
    SENSORS.init_with(|| {
        Sensors::new(
            mcu,
            #[cfg(feature = "pmic-axp2101")]
            pmic,
        )
    })
}

impl Sensors {
    pub fn new(
        mcu: TemperatureSensor<'static>,
        #[cfg(feature = "pmic-axp2101")] pmic: &'static super::SharedPmic,
    ) -> Self {
        let mut inventory = TemperatureInventory::new();
        inventory
            .register(Source::McuDie, "MCU die")
            .expect("MCU temperature inventory");
        #[cfg(feature = "pmic-axp2101")]
        inventory
            .register(Source::PmicDie, "PMIC die")
            .expect("PMIC temperature inventory");
        #[cfg(feature = "board-tlora-pager")]
        {
            inventory
                .register(Source::GaugeDie, "Gauge die")
                .expect("gauge die inventory");
        }
        #[cfg(feature = "board-tbeam-supreme")]
        if super::bme280::SENSOR.address().is_some() {
            inventory
                .register(Source::Bme280, "BME280")
                .expect("BME280 fits");
        }
        Self {
            inventory,
            mcu,
            #[cfg(feature = "board-tlora-pager")]
            separate_gauge_registered: false,
            #[cfg(feature = "pmic-axp2101")]
            pmic,
        }
    }

    fn update_inventory(&mut self) {
        #[cfg(feature = "board-tlora-pager")]
        if !self.separate_gauge_registered && super::pager::has_separate_gauge_temperature() {
            self.inventory
                .register(Source::GaugeTemperature, "Gauge temperature")
                .expect("gauge temperature inventory");
            self.separate_gauge_registered = true;
        }
    }

    pub fn read_names(&mut self, out: &mut [u8]) -> Result<usize, Status> {
        // Reads the already-published startup result, without touching hardware.
        self.update_inventory();
        self.inventory.read_names(out)
    }

    pub async fn sample(&mut self, out: &mut [u16]) -> Result<usize, Status> {
        self.update_inventory();
        let sources = self.inventory.snapshot();
        if out.len() < sources.len() {
            return Err(Status::NOMEM);
        }
        #[cfg(feature = "board-tlora-pager")]
        let mut gauge = None;
        for (index, source) in sources.iter().enumerate() {
            let value = match source {
                #[cfg(feature = "board-tbeam-supreme")]
                Source::Bme280 => super::bme280::SENSOR.sample().await,
                Source::McuDie => self.mcu.sample().await,
                #[cfg(feature = "pmic-axp2101")]
                Source::PmicDie => {
                    // The existing PMIC mutex serializes battery/IRQ/rail work.
                    // The I2C HAL already bounds transactions; don't cancel one
                    // midway merely because a host abandoned its response.
                    self.pmic
                        .lock()
                        .await
                        .die_temperature()
                        .await
                        .ok()
                        .flatten()
                }
                #[cfg(feature = "board-tlora-pager")]
                Source::GaugeTemperature | Source::GaugeDie => {
                    let readings = match gauge {
                        Some(values) => values,
                        None => {
                            let values = super::pager::sample_temperatures().await;
                            gauge = Some(values);
                            values
                        }
                    };
                    readings[if matches!(source, Source::GaugeDie) {
                        1
                    } else {
                        0
                    }]
                }
            };
            out[index] = value.unwrap_or(u16::MAX);
        }
        Ok(sources.len())
    }
}
