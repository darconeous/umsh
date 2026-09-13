//! GNSS rail and reset through the shared XL9555.
use crate::{
    SharedExpander,
    battery::{GPS_ENABLE, GPS_RESET},
};
use embassy_time::Timer;
pub struct Gnss {
    expander: &'static SharedExpander,
}
impl Gnss {
    pub fn new(expander: &'static SharedExpander) -> Self {
        Self { expander }
    }
}
impl umsh_gnss::pump::Power for Gnss {
    async fn power_on(&mut self) {
        if self
            .expander
            .lock()
            .await
            .set(GPS_ENABLE, true)
            .await
            .is_err()
        {
            return;
        }
        Timer::after_millis(10).await;
        let _ = self.expander.lock().await.set(GPS_RESET, true).await;
        Timer::after_millis(100).await;
    }
    async fn power_off(&mut self) {
        let _ = self
            .expander
            .lock()
            .await
            .set(GPS_RESET | GPS_ENABLE, false)
            .await;
    }
}
