//! The committed vectors `tools/ble-test-peripheral` tests its codecs
//! against are what this crate's codecs produce. Regenerate them with
//! `make ble-test-vectors`; this test never writes them.

#[path = "../examples/ble_test_vectors.rs"]
mod generator;

#[test]
fn ble_test_vectors_match() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/ble-test-peripheral/tests/vectors.json"
    );
    let committed = std::fs::read_to_string(path).expect("committed vectors");
    assert!(
        committed == generator::vectors_json(),
        "tools/ble-test-peripheral/tests/vectors.json is stale: run `make ble-test-vectors`"
    );
}
