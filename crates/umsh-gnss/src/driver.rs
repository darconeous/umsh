//! Coalescing a receiver's sentence stream into one fix per cycle.
//!
//! A receiver says what it knows across four or more sentences a second,
//! each carrying a different part of the answer: position and date in
//! RMC, altitude and satellite count in GGA, the solution's dimension and
//! dilution in GSA, visibility in GSV. Nothing upstream wants four
//! partial answers a second, so [`Driver`] accumulates them and hands
//! over one [`Fix`] per cycle.
//!
//! **RMC ends a cycle.** It is the only sentence carrying a date, so it
//! is the one that can establish what time it is, and cutting the cycle
//! there means every emitted fix either has a usable instant or is
//! honestly missing one. A receiver that emits RMC first rather than last
//! simply attaches the previous second's altitude to it, which is a
//! second of staleness in a field that changes slowly.

use crate::DateTime;
use crate::nmea::{Assembler, Gsv, Sentence};

/// How many constellations' satellite counts are summed.
///
/// A multi-constellation receiver emits one GSV burst per constellation.
/// Four covers GPS, GLONASS, Galileo and BeiDou together; a fifth is
/// ignored rather than displacing one, so the count is a floor.
const MAX_CONSTELLATIONS: usize = 4;

/// The quality of a position solution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FixQuality {
    /// No position.
    #[default]
    None,
    /// Position without altitude.
    TwoD,
    /// Position with altitude.
    ThreeD,
}

/// Everything one cycle of sentences said, in integers.
///
/// Coordinates are in units of 1e-7 degrees — about 11 mm, and exact,
/// because they were parsed from the receiver's decimal digits without
/// ever passing through a float.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fix {
    /// The dimension of the solution.
    pub quality: FixQuality,
    /// Latitude in 1e-7 degrees, positive north. `None` without a fix.
    pub latitude_e7: Option<i32>,
    /// Longitude in 1e-7 degrees, positive east. `None` without a fix.
    pub longitude_e7: Option<i32>,
    /// Altitude above mean sea level in meters, with a three-dimensional
    /// solution.
    pub altitude_m: Option<i32>,
    /// Horizontal dilution of precision, in hundredths.
    pub hdop_centi: Option<u16>,
    /// Satellites contributing to the solution.
    pub sats_used: u8,
    /// Satellites in view, summed across constellations. `None` when the
    /// receiver reported no GSV since the last cycle.
    pub sats_in_view: Option<u8>,
    /// The UTC instant the receiver reported, if it reported one.
    ///
    /// Present without a position more often than one might expect: a
    /// receiver with a running real-time clock emits the time in every
    /// RMC while it is still searching for satellites.
    pub time: Option<DateTime>,
    /// Whether [`time`](Self::time) accompanied a *valid* position.
    ///
    /// The distinction matters to a caller deciding how much to trust the
    /// instant: a time that came with a fix was disciplined by the
    /// satellites this second, and one that did not came from whatever
    /// the receiver has been keeping on its own.
    pub time_from_fix: bool,
}

impl Fix {
    /// Whether the cycle produced a position at all.
    pub const fn has_position(&self) -> bool {
        self.latitude_e7.is_some() && self.longitude_e7.is_some()
    }
}

/// Satellite counts accumulated across one constellation's GSV burst.
#[derive(Clone, Copy, Default)]
struct Constellation {
    talker: [u8; 2],
    in_view: u8,
}

/// Byte stream in, one [`Fix`] per cycle out.
pub struct Driver {
    assembler: Assembler,
    /// The cycle being accumulated.
    cycle: Cycle,
}

/// The parts of a cycle seen so far.
#[derive(Clone, Copy, Default)]
struct Cycle {
    gga_quality: u8,
    gga_sats_used: u8,
    gga_altitude_m: Option<i32>,
    gga_latitude: Option<i32>,
    gga_longitude: Option<i32>,
    gga_hdop_centi: Option<u16>,
    gsa_fix_mode: u8,
    hdop_centi: Option<u16>,
    constellations: [Constellation; MAX_CONSTELLATIONS],
    constellation_count: usize,
    saw_gsv: bool,
}

impl Cycle {
    /// Total satellites in view across every constellation heard from.
    fn in_view(&self) -> Option<u8> {
        self.saw_gsv.then(|| {
            self.constellations[..self.constellation_count]
                .iter()
                .fold(0u8, |sum, entry| sum.saturating_add(entry.in_view))
        })
    }

    /// Record one GSV. Only the burst's first message carries a count
    /// worth reading; the rest repeat it, and adding them again would
    /// multiply the total by the burst length.
    fn absorb_gsv(&mut self, gsv: Gsv) {
        if gsv.message != 1 {
            return;
        }
        self.saw_gsv = true;
        if let Some(entry) = self.constellations[..self.constellation_count]
            .iter_mut()
            .find(|entry| entry.talker == gsv.talker)
        {
            entry.in_view = gsv.in_view;
            return;
        }
        if self.constellation_count < MAX_CONSTELLATIONS {
            self.constellations[self.constellation_count] = Constellation {
                talker: gsv.talker,
                in_view: gsv.in_view,
            };
            self.constellation_count += 1;
        }
    }
}

impl Default for Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver {
    /// A fresh driver, waiting for the receiver's first sentence.
    pub const fn new() -> Self {
        Self {
            assembler: Assembler::new(),
            cycle: Cycle {
                gga_quality: 0,
                gga_sats_used: 0,
                gga_altitude_m: None,
                gga_latitude: None,
                gga_longitude: None,
                gga_hdop_centi: None,
                gsa_fix_mode: 0,
                hdop_centi: None,
                constellations: [Constellation {
                    talker: [0; 2],
                    in_view: 0,
                }; MAX_CONSTELLATIONS],
                constellation_count: 0,
                saw_gsv: false,
            },
        }
    }

    /// Discard all accumulated state.
    ///
    /// Call after powering the receiver: sentences from before a power
    /// cycle describe where the device was, not where it is, and must not
    /// join a cycle from after it.
    pub fn reset(&mut self) {
        self.assembler.reset();
        self.cycle = Cycle::default();
    }

    /// Feed one byte, yielding a fix when a cycle completes.
    pub fn push(&mut self, byte: u8) -> Option<Fix> {
        let sentence = self.assembler.push(byte)?;
        match sentence {
            Sentence::Gga(gga) => {
                self.cycle.gga_quality = gga.quality;
                self.cycle.gga_sats_used = gga.sats_used;
                self.cycle.gga_altitude_m = gga.altitude_m;
                self.cycle.gga_latitude = gga.latitude;
                self.cycle.gga_longitude = gga.longitude;
                self.cycle.gga_hdop_centi = gga.hdop_centi;
                None
            }
            Sentence::Gsa(gsa) => {
                self.cycle.gsa_fix_mode = gsa.fix_mode;
                // A receiver reporting no dilution has no dilution to
                // report, so this clears rather than holding the last
                // cycle's figure.
                self.cycle.hdop_centi = gsa.hdop_centi;
                None
            }
            Sentence::Gsv(gsv) => {
                self.cycle.absorb_gsv(gsv);
                None
            }
            Sentence::Rmc(rmc) => {
                let cycle = core::mem::take(&mut self.cycle);
                // RMC and GGA both carry a position and normally agree.
                // Preferring RMC's is arbitrary but consistent; taking
                // GGA's when RMC has none covers the cycle where a fix
                // has just been acquired and only GGA reflects it yet.
                let latitude = rmc.latitude.or(cycle.gga_latitude);
                let longitude = rmc.longitude.or(cycle.gga_longitude);
                let has_position = latitude.is_some() && longitude.is_some();

                // The dimension comes from GSA when it said anything.
                // Without GSA there is no dimension indicator anywhere in
                // NMEA — GGA's quality field says *whether* the receiver
                // is fixed, never in how many dimensions — so the presence
                // of an altitude stands in for it. That is not a receiver
                // that emits GSA and merely happened not to this cycle; it
                // is one configured never to emit it at all, which is the
                // shipping state of the AG3335 on some boards.
                //
                // Without a position there is no solution at all, whatever
                // the indicators claim.
                let quality = match (has_position, cycle.gsa_fix_mode, cycle.gga_quality) {
                    (false, _, _) => FixQuality::None,
                    (true, 3, _) => FixQuality::ThreeD,
                    (true, 2, _) => FixQuality::TwoD,
                    (true, _, 0) => FixQuality::None,
                    (true, _, _) if cycle.gga_altitude_m.is_some() => FixQuality::ThreeD,
                    (true, _, _) => FixQuality::TwoD,
                };

                Some(Fix {
                    quality,
                    // Half a coordinate pair is not a position. A
                    // sentence carrying one and not the other is
                    // malformed, and passing the half along would invite
                    // somebody to treat it as a meridian.
                    latitude_e7: has_position.then_some(latitude).flatten(),
                    longitude_e7: has_position.then_some(longitude).flatten(),
                    // Altitude belongs to a three-dimensional solution
                    // and to nothing else: a receiver keeps emitting the
                    // last one it computed as the solution degrades to
                    // two dimensions, and reporting that as current would
                    // be reporting an altitude nothing measured.
                    altitude_m: match quality {
                        FixQuality::ThreeD => cycle.gga_altitude_m,
                        _ => None,
                    },
                    // GSA's figure when there was one, GGA's otherwise:
                    // the two carry the same quantity, and a receiver may
                    // emit either sentence without the other.
                    hdop_centi: cycle.hdop_centi.or(cycle.gga_hdop_centi),
                    sats_used: cycle.gga_sats_used,
                    sats_in_view: cycle.in_view(),
                    time: rmc.time,
                    time_from_fix: rmc.valid,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;

    /// Feed a checksummed sentence body, returning any completed fix.
    fn feed(driver: &mut Driver, body: &str) -> Option<Fix> {
        let checksum = body.bytes().fold(0u8, |sum, byte| sum ^ byte);
        let mut line = heapless::String::<{ crate::nmea::MAX_SENTENCE }>::new();
        line.push('$').unwrap();
        line.push_str(body).unwrap();
        write!(line, "*{checksum:02X}\r\n").unwrap();

        let mut out = None;
        for byte in line.bytes() {
            if let Some(fix) = driver.push(byte) {
                out = Some(fix);
            }
        }
        out
    }

    /// One full cycle of a receiver with a three-dimensional solution.
    fn three_d_cycle(driver: &mut Driver) -> Fix {
        assert!(
            feed(
                driver,
                "GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,"
            )
            .is_none(),
            "GGA ended a cycle"
        );
        assert!(
            feed(driver, "GPGSA,A,3,04,05,,09,12,,,24,,,,,2.5,1.3,2.1").is_none(),
            "GSA ended a cycle"
        );
        assert!(
            feed(driver, "GPGSV,3,1,11,03,03,111,00,04,15,270,00").is_none(),
            "GSV ended a cycle"
        );
        feed(
            driver,
            "GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230326,003.1,W",
        )
        .expect("RMC did not end the cycle")
    }

    #[test]
    fn a_cycle_assembles_into_one_fix() {
        let mut driver = Driver::new();
        let fix = three_d_cycle(&mut driver);
        assert_eq!(fix.quality, FixQuality::ThreeD);
        assert_eq!(fix.latitude_e7, Some(481_173_000));
        assert_eq!(fix.longitude_e7, Some(115_166_666));
        assert_eq!(fix.altitude_m, Some(545));
        assert_eq!(fix.hdop_centi, Some(130));
        assert_eq!(fix.sats_used, 8);
        assert_eq!(fix.sats_in_view, Some(11));
        assert!(fix.time_from_fix);
        assert_eq!(fix.time.map(|at| at.hour), Some(12));
        assert!(fix.has_position());
    }

    /// A cold receiver emits a full cycle of empty sentences before it
    /// has anything. Nothing in it may read as a position.
    #[test]
    fn a_searching_receiver_produces_a_fix_with_nothing_in_it() {
        let mut driver = Driver::new();
        feed(&mut driver, "GPGGA,,,,,,0,00,,,M,,M,,");
        feed(&mut driver, "GPGSA,A,1,,,,,,,,,,,,,,,");
        let fix = feed(&mut driver, "GPRMC,,V,,,,,,,,,,N").expect("no fix emitted");
        assert_eq!(fix.quality, FixQuality::None);
        assert_eq!(fix.latitude_e7, None);
        assert_eq!(fix.altitude_m, None);
        assert_eq!(fix.sats_used, 0);
        assert_eq!(fix.time, None);
        assert!(!fix.time_from_fix);
        assert!(!fix.has_position());
    }

    /// The case the whole receiver-RTC design rests on: a receiver that
    /// knows what time it is and not where it is.
    #[test]
    fn time_without_a_fix_is_reported_and_marked_as_such() {
        let mut driver = Driver::new();
        let fix = feed(&mut driver, "GPRMC,081836.00,V,,,,,,,130926,,").expect("no fix emitted");
        assert_eq!(
            fix.time.map(|at| (at.year, at.month, at.day)),
            Some((2026, 9, 13))
        );
        assert!(
            !fix.time_from_fix,
            "a time from a void fix must not claim satellite discipline"
        );
        assert!(!fix.has_position());
        assert_eq!(fix.quality, FixQuality::None);
    }

    /// Altitude belongs to a three-dimensional solution. A receiver keeps
    /// emitting the last one it computed as the solution degrades, and
    /// reporting that as current would be reporting an altitude nothing
    /// measured.
    #[test]
    fn a_two_dimensional_solution_drops_the_altitude() {
        let mut driver = Driver::new();
        feed(
            &mut driver,
            "GPGGA,123519,4807.038,N,01131.000,E,1,05,2.4,545.4,M,46.9,M,,",
        );
        feed(&mut driver, "GPGSA,A,2,04,05,,,,,,,,,,,4.1,2.4,3.1");
        let fix = feed(
            &mut driver,
            "GPRMC,123519,A,4807.038,N,01131.000,E,,,230326,,",
        )
        .expect("no fix emitted");
        assert_eq!(fix.quality, FixQuality::TwoD);
        assert!(fix.has_position());
        assert_eq!(fix.altitude_m, None);
    }

    /// Indicators claiming a fix while no sentence carries a position
    /// describe a solution that does not exist.
    #[test]
    fn a_quality_indicator_without_a_position_is_not_a_fix() {
        let mut driver = Driver::new();
        feed(&mut driver, "GPGGA,123519,,,,,1,08,0.9,545.4,M,46.9,M,,");
        feed(&mut driver, "GPGSA,A,3,04,05,,,,,,,,,,,2.5,1.3,2.1");
        let fix = feed(&mut driver, "GPRMC,123519,A,,,,,,,230326,,").expect("no fix emitted");
        assert_eq!(fix.quality, FixQuality::None);
        assert_eq!(fix.altitude_m, None);
    }

    /// A receiver emitting GGA but no GSA still says whether it is fixed,
    /// and its altitude is the only available evidence of a third axis.
    #[test]
    fn gga_alone_establishes_a_fix() {
        let mut driver = Driver::new();
        feed(
            &mut driver,
            "GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,",
        );
        let fix = feed(
            &mut driver,
            "GPRMC,123519,A,4807.038,N,01131.000,E,,,230326,,",
        )
        .expect("no fix emitted");
        assert_eq!(fix.quality, FixQuality::ThreeD);
        assert_eq!(fix.altitude_m, Some(545));
        // GGA carries the same dilution figure GSA does.
        assert_eq!(fix.hdop_centi, Some(90));
    }

    /// Without GSA and without an altitude there is nothing to suggest a
    /// third axis, so the solution is flat.
    #[test]
    fn gga_without_an_altitude_is_two_dimensional() {
        let mut driver = Driver::new();
        feed(
            &mut driver,
            "GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,,M,46.9,M,,",
        );
        let fix = feed(
            &mut driver,
            "GPRMC,123519,A,4807.038,N,01131.000,E,,,230326,,",
        )
        .expect("no fix emitted");
        assert_eq!(fix.quality, FixQuality::TwoD);
        assert_eq!(fix.altitude_m, None);
    }

    /// GSA outranks the altitude heuristic: a receiver that says the
    /// solution is flat is telling us something GGA cannot, and GGA's
    /// altitude field may still hold the last figure it computed.
    #[test]
    fn gsa_outranks_a_lingering_gga_altitude() {
        let mut driver = Driver::new();
        feed(
            &mut driver,
            "GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,",
        );
        feed(&mut driver, "GPGSA,A,2,04,05,,,,,,,,,,,2.5,1.3,2.1");
        let fix = feed(
            &mut driver,
            "GPRMC,123519,A,4807.038,N,01131.000,E,,,230326,,",
        )
        .expect("no fix emitted");
        assert_eq!(fix.quality, FixQuality::TwoD);
        assert_eq!(fix.altitude_m, None);
        // GSA's figure wins where both are present.
        assert_eq!(fix.hdop_centi, Some(130));
    }

    /// The T1000-E's AG3335 as it ships: GGA and RMC only, because the
    /// receiver keeps its NMEA output selection in its own non-volatile
    /// memory and the vendor firmware switched GSA and GSV off there.
    /// Everything except the satellites-in-view count is still available,
    /// and taking a 3D fix as 2D would cost the altitude too.
    #[test]
    fn an_ag3335_emitting_only_gga_and_rmc_still_reports_fully() {
        let mut driver = Driver::new();
        feed(
            &mut driver,
            "GNGGA,081519.000,4208.0416,N,12237.0543,W,1,10,1.04,698.3,M,-22.4,M,,",
        );
        let fix = feed(
            &mut driver,
            "GNRMC,081519.000,A,4208.0416,N,12237.0543,W,0.04,0.00,050826,,,A,V",
        )
        .expect("no fix emitted");

        assert_eq!(fix.quality, FixQuality::ThreeD);
        assert_eq!(fix.altitude_m, Some(698));
        assert_eq!(fix.hdop_centi, Some(104));
        assert_eq!(fix.sats_used, 10);
        // Nothing reported it, so nothing is claimed.
        assert_eq!(fix.sats_in_view, None);
        assert!(fix.time_from_fix);
        assert!(fix.has_position());
    }

    /// Each constellation counts only its own satellites, so a
    /// multi-constellation receiver's bursts have to be summed — and the
    /// repeat messages within a burst must not be summed again.
    #[test]
    fn satellites_in_view_sum_across_constellations_once_each() {
        let mut driver = Driver::new();
        feed(&mut driver, "GPGSV,3,1,11,03,03,111,00");
        feed(&mut driver, "GPGSV,3,2,11,09,23,313,00");
        feed(&mut driver, "GPGSV,3,3,11,24,58,065,00");
        feed(&mut driver, "GLGSV,2,1,07,65,12,034,00");
        feed(&mut driver, "GLGSV,2,2,07,66,45,120,00");
        let fix = feed(&mut driver, "GPRMC,,V,,,,,,,,,,N").expect("no fix emitted");
        assert_eq!(fix.sats_in_view, Some(18), "11 GPS + 7 GLONASS");

        // A repeated first message from the same talker replaces rather
        // than adds — the count is a property of the burst.
        let mut driver = Driver::new();
        feed(&mut driver, "GPGSV,1,1,05,03,03,111,00");
        feed(&mut driver, "GPGSV,1,1,05,03,03,111,00");
        let fix = feed(&mut driver, "GPRMC,,V,,,,,,,,,,N").expect("no fix emitted");
        assert_eq!(fix.sats_in_view, Some(5));
    }

    /// A receiver that reports no GSV at all is not reporting zero
    /// satellites in view; it is not reporting.
    #[test]
    fn no_gsv_means_no_answer_rather_than_zero() {
        let mut driver = Driver::new();
        let fix = feed(&mut driver, "GPRMC,,V,,,,,,,,,,N").expect("no fix emitted");
        assert_eq!(fix.sats_in_view, None);
    }

    /// Each cycle stands alone: a fix does not inherit the previous
    /// cycle's altitude, dilution, or satellite count.
    #[test]
    fn a_cycle_does_not_inherit_the_previous_one() {
        let mut driver = Driver::new();
        let first = three_d_cycle(&mut driver);
        assert_eq!(first.altitude_m, Some(545));

        // The receiver loses the sky entirely: nothing but a void RMC.
        let second = feed(&mut driver, "GPRMC,,V,,,,,,,,,,N").expect("no fix emitted");
        assert_eq!(second.quality, FixQuality::None);
        assert_eq!(second.altitude_m, None);
        assert_eq!(second.hdop_centi, None);
        assert_eq!(second.sats_used, 0);
        assert_eq!(second.sats_in_view, None);
    }

    /// Resetting is what a power cycle does: whatever the receiver said
    /// about where it was must not attach itself to where it is.
    #[test]
    fn resetting_discards_a_partial_cycle() {
        let mut driver = Driver::new();
        feed(
            &mut driver,
            "GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,",
        );
        driver.reset();
        let fix = feed(&mut driver, "GPRMC,,V,,,,,,,,,,N").expect("no fix emitted");
        assert_eq!(fix.latitude_e7, None);
        assert_eq!(fix.altitude_m, None);
        assert_eq!(fix.sats_used, 0);
    }

    /// Garbage between sentences is the normal condition of a UART that
    /// just came up, and must cost at most the sentence it landed in.
    #[test]
    fn a_corrupt_sentence_costs_only_itself() {
        let mut driver = Driver::new();
        for byte in b"\x00\xff$GPGGA,tor" {
            driver.push(*byte);
        }
        feed(
            &mut driver,
            "GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,",
        );
        feed(&mut driver, "GPGSA,A,3,04,05,,,,,,,,,,,2.5,1.3,2.1");
        let fix = feed(
            &mut driver,
            "GPRMC,123519,A,4807.038,N,01131.000,E,,,230326,,",
        )
        .expect("no fix emitted");
        assert_eq!(fix.quality, FixQuality::ThreeD);
        assert_eq!(fix.altitude_m, Some(545));
    }
}
