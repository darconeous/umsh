#![no_std]

#[cfg(feature = "service")]
pub mod service;

/// Acceleration in milligravity, in board coordinates: +X toward screen right,
/// +Y from the keyboard toward the top of the screen, +Z out of the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acceleration {
    pub at_ms: u64,
    pub mg: [i32; 3],
    pub clipped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    Moving,
    Stationary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Disabled,
    Starting,
    Ready,
    Failed,
}

/// Latest observations, suitable for a multi-receiver watch. Activity remains
/// independent of display orientation. Receivers each maintain their own cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub generation: u32,
    pub availability: Availability,
    pub activity: Option<(u64, Activity)>,
    pub movement_sequence: u32,
    /// Retained through a subsequent stationary report, so a slower consumer
    /// can date movement even when it observes only the latest state.
    pub last_movement_ms: Option<u64>,
    pub acceleration: Option<Acceleration>,
}

impl State {
    pub const fn new() -> Self {
        Self {
            generation: 0,
            availability: Availability::Disabled,
            activity: None,
            movement_sequence: 0,
            last_movement_ms: None,
            acceleration: None,
        }
    }

    pub fn invalidate(&mut self, availability: Availability) {
        self.generation = self.generation.wrapping_add(1);
        self.availability = availability;
        self.activity = None;
        self.last_movement_ms = None;
        self.acceleration = None;
    }

    pub fn activity(&mut self, at_ms: u64, activity: Activity) {
        self.activity = Some((at_ms, activity));
        if activity == Activity::Moving {
            self.movement_sequence = self.movement_sequence.wrapping_add(1);
            self.last_movement_ms = Some(at_ms);
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

/// A single episode is consumed at qualification, even if its consumer is lit.
/// Only interrupt-triggered windows supply samples; this policy schedules no
/// polling. Stillness starts at the sensor report, never backdated.
pub struct DisplayPolicy {
    consumed: bool,
    still_since: Option<u64>,
    outside_since: Option<u64>,
    movement: Option<u64>,
    up_since: Option<u64>,
    previous: Option<Acceleration>,
    gravity: [i32; 3],
    motion_reference: [i16; 3],
    // 0..3 establish a reference; 6 means a sustained excursion was confirmed.
    motion_evidence: u8,
    excursion_since: u16,
}

impl Default for DisplayPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl DisplayPolicy {
    pub const fn new() -> Self {
        Self {
            consumed: false,
            still_since: None,
            outside_since: None,
            movement: None,
            up_since: None,
            previous: None,
            gravity: [0; 3],
            motion_reference: [0; 3],
            motion_evidence: 0,
            excursion_since: 0,
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Fresh sensor evidence can open a window, but cannot extend one.
    pub fn activity(&mut self, at_ms: u64, activity: Activity) {
        match activity {
            Activity::Stationary => {
                self.still_since.get_or_insert(at_ms);
                self.end_window();
            }
            Activity::Moving => {
                if self
                    .still_since
                    .is_some_and(|t| at_ms.saturating_sub(t) >= 2_000)
                {
                    self.consumed = false;
                }
                self.still_since = None;
                // The last observed orientation remains outside until a new
                // observation contradicts it. It never qualifies a wake: that
                // always needs a new window of fresh screen-up measurements.
                if self
                    .outside_since
                    .is_some_and(|t| at_ms.saturating_sub(t) >= 2_000)
                {
                    self.consumed = false;
                }
                if self.movement.is_none() {
                    self.movement = Some(at_ms);
                    self.up_since = None;
                    self.previous = None;
                    self.motion_evidence = 0;
                }
            }
        }
    }

    pub fn end_window(&mut self) {
        self.movement = None;
        self.up_since = None;
        self.previous = None;
        self.motion_evidence = 0;
    }

    /// Whether this movement episode has already been delivered to the display
    /// owner, including when the owner ignored it because the display was lit.
    pub fn episode_consumed(&self) -> bool {
        self.consumed
    }

    pub fn movement_confirmed(&self) -> bool {
        self.motion_evidence == 6
    }

    /// True once per episode after meaningful movement and 200 ms of
    /// undisturbed, fresh screen-up data in the same verification window.
    pub fn sample(&mut self, now_ms: u64, sample: Acceleration) -> bool {
        let Some(start) = self.movement else {
            return false;
        };
        if now_ms.saturating_sub(start) > 1_000
            || sample.at_ms < start
            || sample.at_ms > now_ms
            || now_ms - sample.at_ms > 100
        {
            self.up_since = None;
            self.previous = None;
            self.motion_evidence = 0;
            return false;
        }
        let norm = squared(sample.mg);
        let valid = !sample.clipped && (800 * 800..=1200 * 1200).contains(&norm);
        let continuous = self.previous.is_some_and(|p| {
            sample.at_ms > p.at_ms
                && sample.at_ms - p.at_ms <= 80
                && squared(core::array::from_fn(|i| {
                    sample.mg[i].saturating_sub(p.mg[i])
                })) <= 250 * 250
        });
        if !valid {
            self.up_since = None;
            self.previous = None;
            self.motion_evidence = 0;
            // An ambiguous interval cannot establish time outside the cone.
            self.outside_since = None;
            return false;
        }
        if continuous {
            for i in 0..3 {
                self.gravity[i] += (sample.mg[i] - self.gravity[i]) / 4;
            }
        } else {
            self.gravity = sample.mg;
            self.up_since = None;
            self.motion_evidence = 0;
        }
        self.previous = Some(sample);
        // Establish the reference over the first three valid samples, then
        // require a filtered vector excursion of 120 mg for at least 80 ms.
        // Do not accumulate
        // tiny oscillations: returning below the threshold resets the streak.
        // Relative vectors avoid treating gravity or sensor bias as movement.
        if self.motion_evidence < 3 {
            self.motion_reference = self.gravity.map(|v| v as i16);
            self.motion_evidence += 1;
            self.excursion_since = 0;
        } else if !self.movement_confirmed() {
            let excursion = squared(core::array::from_fn(|i| {
                self.gravity[i] - i32::from(self.motion_reference[i])
            }));
            if excursion >= 120 * 120 {
                // Offset + 1 reserves zero for an unset timer. Every accepted
                // sample is inside the one-second window, so u16 is sufficient.
                let elapsed = (sample.at_ms - start + 1) as u16;
                if self.excursion_since == 0 {
                    self.excursion_since = elapsed;
                } else if elapsed - self.excursion_since >= 80 {
                    self.motion_evidence = 6;
                }
            } else {
                self.excursion_since = 0;
            }
        }
        let up = within_wake_orientation(self.gravity, false);
        // Test both the current sample and filtered gravity. Filtering must
        // never mask a currently sideways or disturbed measurement.
        let raw_up = within_wake_orientation(sample.mg, false);
        let outside = !within_wake_orientation(self.gravity, true);
        if outside {
            self.outside_since.get_or_insert(sample.at_ms);
        } else {
            self.outside_since = None;
        }
        if !up || !raw_up {
            self.up_since = None;
            return false;
        }
        let since = *self.up_since.get_or_insert(sample.at_ms);
        if !self.consumed && self.movement_confirmed() && sample.at_ms - since >= 200 {
            self.consumed = true;
            return true;
        }
        false
    }
}

/// An elliptical cone extends only the keyboard-down reading direction.
/// Entry allows 45 degrees along +Y, 30 degrees sideways or toward -Y;
/// exit adds ten degrees on each axis. Combined tilts share that allowance.
fn within_wake_orientation(v: [i32; 3], exit: bool) -> bool {
    let [x, y, z] = v.map(i64::from);
    if z <= 0 {
        return false;
    }
    if exit {
        // cot²(40°) and cot²(55°), scaled by one million.
        let along = if y > 0 { 490_291 } else { 1_420_277 };
        x * x * 1_420_277 + y * y * along <= z * z * 1_000_000
    } else {
        let along = if y > 0 { 1 } else { 3 };
        x * x * 3 + y * y * along <= z * z
    }
}

fn squared(v: [i32; 3]) -> i64 {
    // Clamp untrusted adapter values before squaring or summing.
    v.into_iter()
        .map(|x| i64::from(x.clamp(-32_000, 32_000)).pow(2))
        .sum()
}
