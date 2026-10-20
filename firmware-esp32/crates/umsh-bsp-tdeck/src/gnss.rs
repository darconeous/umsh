//! The GNSS receiver—the Plus's own, or one on the original's Grove
//! port—has no enable line: it is powered whenever the board is (§12).
//! Only its own standby commands lower its draw.
pub struct Gnss;
impl umsh_gnss::pump::Power for Gnss {
    async fn power_on(&mut self) {}
    async fn power_off(&mut self) {}
}
