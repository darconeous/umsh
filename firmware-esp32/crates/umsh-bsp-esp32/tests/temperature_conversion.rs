// Standalone host harness: no Xtensa HAL or device is needed.
// From the repository root:
// rustc +stable --edition=2024 --test firmware-esp32/crates/umsh-bsp-esp32/tests/temperature_conversion.rs -o /tmp/umsh-esp32-temperature-tests
// /tmp/umsh-esp32-temperature-tests
#[path = "../src/temperature/conversion.rs"]
mod conversion;
