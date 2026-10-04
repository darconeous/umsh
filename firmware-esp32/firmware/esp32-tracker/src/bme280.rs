//! T-Beam sensor worker, sharing the powered sensor bus with the OLED.
use super::board;
use embassy_time::{Duration, with_timeout};
pub static SENSOR: umsh_sensor_bme280::service::Service =
    umsh_sensor_bme280::service::Service::new();

pub async fn start(
    spawner: embassy_executor::Spawner,
    bus: &'static board::I2cBus,
    pmu: &'static board::I2cBus,
) {
    let mut controller = bus.lock().await;
    // Both production address options, preferring the original 0x77 wiring.
    for address in [0x77, 0x76] {
        if matches!(
            with_timeout(
                Duration::from_millis(100),
                umsh_sensor_bme280::probe(&mut *controller, address)
            )
            .await,
            Ok(Ok(()))
        ) {
            SENSOR.detected(address);
            spawner.spawn(worker(bus, pmu, address).unwrap());
            break;
        }
    }
}

async fn acquire(bus: &board::I2cBus, pmu: &board::I2cBus, address: u8) -> Option<u16> {
    // Same PMU-before-sensor lock order as raw host access. Hold the PMU bus
    // so ALDO1 cannot be switched off midway, including by a raw PMIC write.
    let mut power = pmu.lock().await;
    let mut pmic = umsh_pmic_axp2101::Axp2101::new(&mut *power);
    if !pmic.rail_enabled(board::SENSOR_RAIL).await.ok()? {
        return None;
    }
    let mut controller = bus.lock().await;
    umsh_sensor_bme280::sample(&mut *controller, address, &mut embassy_time::Delay)
        .await
        .ok()
}

#[embassy_executor::task]
async fn worker(bus: &'static board::I2cBus, pmu: &'static board::I2cBus, address: u8) {
    loop {
        let request = SENSOR.request().await;
        // esp-hal resets its controller when canceled; bound a stuck bus or
        // contended lock as well as the sensor's own bounded status polling.
        let value = with_timeout(Duration::from_secs(2), acquire(bus, pmu, address))
            .await
            .ok()
            .flatten();
        SENSOR.complete(request, value);
    }
}
