//! Re-export of the shared `embassy-time`-backed clock.
//!
//! The `EmbassyClock` implementation now lives in `umsh-hal` (behind its
//! `embassy` feature) so host and embedded targets share one copy. This module
//! remains as a stable re-export path; every nRF52840 firmware in this tree
//! drives the MAC's timing layer with embassy-time on RTC1.

pub use umsh_hal::EmbassyClock;
