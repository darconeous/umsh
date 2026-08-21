//! Rough lookup-latency measurement against a real database.
//!
//! Not a benchmark harness — a sanity check against the performance budget
//! (median under 20 ms, worst boundary fallback under 250 ms, on hardware far
//! slower than a build machine). Run with:
//!
//! ```text
//! cargo run --release -p umsh-regiondb --example bench_lookup -- world.regiondb
//! ```

use std::time::Instant;

use umsh_regiondb::RegionDb;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: bench_lookup <database.regiondb>");
    let database = RegionDb::open(&path).expect("open database");
    println!(
        "{}: dataset {}, {} regions",
        path,
        database.dataset_version(),
        database.region_count()
    );

    // A spread of situations: dense metros, borders, remote ocean, dateline,
    // high latitude. Deterministic on purpose, so runs are comparable.
    let positions: Vec<(f64, f64, &str)> = vec![
        (37.5119, -122.2495, "San Carlos (dense airports)"),
        (42.1946, -122.7095, "Ashland OR"),
        (40.7128, -74.0060, "Manhattan"),
        (51.5074, -0.1278, "London"),
        (35.6762, 139.6503, "Tokyo"),
        (28.6139, 77.2090, "Delhi"),
        (-33.8688, 151.2093, "Sydney"),
        (64.7349, 177.7410, "Anadyr (dateline)"),
        (-18.5667, 179.9510, "Moala (dateline)"),
        (46.0, 6.0, "Geneva border area"),
        (49.0, -123.0, "US-Canada border"),
        (10.0, -150.0, "remote Pacific"),
        (82.5, -62.0, "high Arctic"),
        (0.0, 0.0, "Gulf of Guinea"),
    ];

    // Warm the page cache and the prepared statements once.
    for &(latitude, longitude, _) in &positions {
        let _ = database.lookup_codes(latitude, longitude).unwrap();
    }

    let mut timings: Vec<(f64, &str, usize)> = Vec::new();
    for &(latitude, longitude, label) in &positions {
        const ROUNDS: u32 = 20;
        let mut regions = 0;
        let start = Instant::now();
        for _ in 0..ROUNDS {
            regions = database
                .lookup_codes(latitude, longitude)
                .unwrap()
                .radio_regions
                .len();
        }
        let per_lookup = start.elapsed().as_secs_f64() * 1000.0 / f64::from(ROUNDS);
        timings.push((per_lookup, label, regions));
    }

    timings.sort_by(|first, second| first.0.total_cmp(&second.0));
    for (milliseconds, label, regions) in &timings {
        println!("{milliseconds:8.3} ms  {regions:2} regions  {label}");
    }
    let median = timings[timings.len() / 2].0;
    let worst = timings.last().unwrap().0;
    println!("median {median:.3} ms, worst {worst:.3} ms");
}
