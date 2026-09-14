use umsh_motion::{Acceleration, Activity, DisplayPolicy};

fn window(p: &mut DisplayPolicy, t: u64, mg: [i32; 3]) -> usize {
    p.activity(t, Activity::Moving);
    let wakes = (0..25)
        .filter(|n| {
            let at = t + n * 40;
            p.sample(
                at,
                Acceleration {
                    at_ms: at,
                    // A gentle acceleration change at the same orientation.
                    mg: if *n < 3 { mg.map(|v| v * 82 / 100) } else { mg },
                    clipped: false,
                },
            )
        })
        .count();
    p.end_window();
    wakes
}

#[test]
fn face_up_only_and_one_wake_per_episode() {
    for (mg, expected) in [
        ([0, 0, 1000], 1),
        ([1000, 0, 0], 0),
        ([0, 0, -1000], 0),
        ([510, 0, 860], 0),
    ] {
        let mut p = DisplayPolicy::new();
        assert_eq!(window(&mut p, 0, mg), expected);
        assert_eq!(
            window(&mut p, 31_000, mg),
            0,
            "continuous movement through timeout"
        );
    }
}

#[test]
fn small_vibrations_and_sensor_bias_do_not_count_as_a_pickup() {
    for mode in 0..4 {
        let mut p = DisplayPolicy::new();
        p.activity(0, Activity::Moving);
        for n in 0..25 {
            let delta = match mode {
                0 => 0, // Constant gravity/bias after a native activity event.
                1 => {
                    if n % 2 == 0 {
                        30
                    } else {
                        -30
                    }
                }
                2 => {
                    if n % 2 == 0 {
                        100
                    } else {
                        -100
                    }
                }
                _ => {
                    if n == 10 {
                        180
                    } else {
                        0
                    }
                } // An isolated short tap.
            };
            let at = n * 40;
            assert!(
                !p.sample(
                    at,
                    Acceleration {
                        at_ms: at,
                        mg: [0, 0, 950 + delta],
                        clipped: false,
                    }
                ),
                "mode={mode} sample={n}"
            );
        }
        assert!(!p.movement_confirmed());
    }
}

#[test]
fn level_pickup_acceleration_passes_without_requiring_rotation() {
    let mut p = DisplayPolicy::new();
    p.activity(0, Activity::Moving);
    let mut wakes = 0;
    for n in 0..25 {
        let at = n * 40;
        let z = if (4..=10).contains(&n) { 1140 } else { 950 };
        if p.sample(
            at,
            Acceleration {
                at_ms: at,
                mg: [0, 0, z],
                clipped: false,
            },
        ) {
            assert!(at <= 600);
            wakes += 1;
        }
    }
    assert_eq!(wakes, 1);
}

#[test]
fn reading_tilt_extends_only_toward_the_keyboard() {
    for (mg, expected) in [
        ([0, 707, 707], 1),  // 45 degrees, keyboard lower
        ([0, 719, 695], 0),  // 46 degrees
        ([0, -707, 707], 0), // opposite direction
        ([707, 0, 707], 0),  // sideways
        ([-707, 0, 707], 0),
        ([0, -499, 867], 1), // original 30-degree range retained
        ([499, 0, 867], 1),
        ([400, 500, 768], 0), // combined roll and pitch exceed the ellipse
        ([200, 600, 775], 1),
        ([0, 707, -707], 0), // face-down
    ] {
        assert_eq!(window(&mut DisplayPolicy::new(), 0, mg), expected, "{mg:?}");
    }
}

#[test]
fn reading_angle_has_its_own_exit_hysteresis() {
    let mut p = DisplayPolicy::new();
    assert_eq!(window(&mut p, 0, [0, 707, 707]), 1);
    assert_eq!(window(&mut p, 2000, [0, 766, 643]), 0); // 50 degrees
    assert_eq!(window(&mut p, 5000, [0, 707, 707]), 0); // not rearmed
    assert_eq!(window(&mut p, 7000, [0, 829, 559]), 0); // 56 degrees
    assert_eq!(window(&mut p, 8999, [0, 707, 707]), 0);
    assert_eq!(window(&mut p, 11_000, [0, 829, 559]), 0);
    assert_eq!(window(&mut p, 14_000, [0, 707, 707]), 1);
}

#[test]
fn stationary_placement_is_not_movement_and_rearm_waits_two_reported_seconds() {
    let mut p = DisplayPolicy::new();
    p.activity(0, Activity::Stationary);
    assert!(!p.sample(
        100,
        Acceleration {
            at_ms: 100,
            mg: [0, 0, 1000],
            clipped: false
        }
    ));
    assert_eq!(window(&mut p, 3000, [0, 0, 1000]), 1);
    p.activity(4100, Activity::Stationary);
    assert_eq!(window(&mut p, 6099, [0, 0, 1000]), 0);
    p.activity(7100, Activity::Stationary);
    assert_eq!(window(&mut p, 9100, [0, 0, 1000]), 1);
}

#[test]
fn pocket_removal_rearms_but_threshold_chatter_does_not() {
    let mut p = DisplayPolicy::new();
    assert_eq!(window(&mut p, 0, [0, 0, 1000]), 1);
    assert_eq!(window(&mut p, 2000, [570, 0, 820]), 0); // 35 degrees, not outside
    assert_eq!(window(&mut p, 5000, [0, 0, 1000]), 0);
    assert_eq!(window(&mut p, 7000, [1000, 0, 0]), 0);
    assert_eq!(window(&mut p, 8999, [0, 0, 1000]), 0);
    assert_eq!(window(&mut p, 11_000, [1000, 0, 0]), 0);
    assert_eq!(window(&mut p, 14_000, [0, 0, 1000]), 1);
}

#[test]
fn stale_shocks_clipping_and_gaps_break_consistency() {
    for bad in [
        Acceleration {
            at_ms: 0,
            mg: [0, 0, 1000],
            clipped: false,
        },
        Acceleration {
            at_ms: 240,
            mg: [0, 0, 2000],
            clipped: false,
        },
        Acceleration {
            at_ms: 240,
            mg: [0, 0, 1000],
            clipped: true,
        },
    ] {
        let mut p = DisplayPolicy::new();
        p.activity(0, Activity::Moving);
        for at in [0, 40, 80, 120, 160] {
            assert!(!p.sample(
                at,
                Acceleration {
                    at_ms: at,
                    mg: [0, 0, 1000],
                    clipped: false
                }
            ));
        }
        assert!(!p.sample(240, bad));
        for at in [280, 320, 360, 400, 440, 480] {
            assert!(!p.sample(
                at,
                Acceleration {
                    at_ms: at,
                    mg: [0, 0, 1000],
                    clipped: false
                }
            ));
        }
        p.end_window();
        assert_eq!(window(&mut p, 600, [0, 0, 1000]), 1);
    }
}

#[test]
fn bounded_window_and_reset() {
    let mut p = DisplayPolicy::new();
    p.activity(0, Activity::Moving);
    for at in (1040..2000).step_by(40) {
        assert!(!p.sample(
            at,
            Acceleration {
                at_ms: at,
                mg: [0, 0, 1000],
                clipped: false
            }
        ));
    }
    p.reset();
    assert_eq!(window(&mut p, 3000, [0, 0, 1000]), 1);
}

#[cfg(feature = "service")]
#[test]
fn consumers_have_independent_notifications_and_power_demand() {
    use umsh_motion::{
        State,
        service::{Consumer, Service, Wake},
    };
    let s = Service::new();
    let mut display = s.observations.receiver().unwrap();
    let mut gps = s.observations.receiver().unwrap();
    s.request(Consumer::Display, true);
    s.request(Consumer::Location, true);
    let mut state = State::new();
    state.activity(100, Activity::Moving);
    s.observations.sender().send(state);
    assert_eq!(display.try_changed(), Some(state));
    assert_eq!(gps.try_changed(), Some(state));
    state.activity(200, Activity::Stationary);
    s.observations.sender().send(state);
    assert_eq!(gps.try_changed().unwrap().last_movement_ms, Some(100));
    let wake = Wake {
        generation: s.control().generation,
        at_ms: 100,
    };
    assert!(s.accept(wake, 100));
    assert!(!s.accept(wake, 351));
    s.cancel();
    assert!(!s.accept(wake, 100));
    s.request(Consumer::Display, false);
    assert!(s.control().sensing());
    assert!(!s.accept(wake, 100));
    s.request(Consumer::Location, false);
    assert!(!s.control().sensing());
    s.shutdown();
    s.request(Consumer::Display, true);
    assert!(!s.control().sensing());
}
