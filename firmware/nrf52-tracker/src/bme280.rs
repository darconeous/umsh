//! T-Echo's optional onboard sensor. This worker is never canceled during DMA.
use embassy_sync::{blocking_mutex::raw::ThreadModeRawMutex, signal::Signal};
use embassy_time::{Duration, with_timeout};
use umsh_bsp_nrf52840::i2c::Bus;
pub static SENSOR: umsh_sensor_bme280::service::Service =
    umsh_sensor_bme280::service::Service::new();
static DETECTED: Signal<ThreadModeRawMutex, bool> = Signal::new();

pub async fn start(spawner: embassy_executor::Spawner, bus: &'static Bus) {
    spawner.spawn(worker(bus).unwrap());
    // Only the waiter times out. A stuck probe retains its DMA buffers in the
    // worker; a late detection cannot alter the boot inventory.
    if matches!(
        with_timeout(Duration::from_secs(2), DETECTED.wait()).await,
        Ok(true)
    ) {
        SENSOR.detected(0x77);
    }
}

pub async fn sample() -> Option<u16> {
    // Dropping this mailbox waiter leaves any physical transfer running safely.
    with_timeout(Duration::from_secs(2), SENSOR.sample())
        .await
        .ok()
        .flatten()
}

#[embassy_executor::task]
async fn worker(bus: &'static Bus) {
    let present = {
        let mut controller = bus.lock().await;
        umsh_sensor_bme280::probe(&mut *controller, 0x77)
            .await
            .is_ok()
    };
    DETECTED.signal(present);
    if !present {
        return;
    }
    loop {
        let request = SENSOR.request().await;
        let value = {
            // Serialize the entire forced conversion against RTC and raw I2C.
            let mut controller = bus.lock().await;
            umsh_sensor_bme280::sample(&mut *controller, 0x77, &mut embassy_time::Delay)
                .await
                .ok()
        };
        SENSOR.complete(request, value);
    }
}
