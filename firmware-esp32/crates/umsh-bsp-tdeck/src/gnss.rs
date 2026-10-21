//! The GNSS receiver—the Plus's own, or one on the original's Grove
//! port—has no enable line: it is powered whenever the board is (§12).
//! Its UART is the only control, so the firmware's `gnss-uart-standby`
//! parks it there, and nothing is left here to sequence.
pub struct Gnss;
impl umsh_gnss::pump::Power for Gnss {
    async fn power_on(&mut self) {}
    async fn power_off(&mut self) {}
}
