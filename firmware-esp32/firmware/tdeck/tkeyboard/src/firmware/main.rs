//! The T-Deck keyboard's ESP32-C3: three tasks around the library's
//! [`Controller`]. `scan` feeds it the matrix, `host` answers the S3 on
//! I²C, and `light` fades the key light to the duty it asks for.
//!
//! The chip light-sleeps whenever every task is waiting and no wake lock
//! is held; `power` has the rule for who holds one.
//!
//! The firmware exists only for the C3; on any other target this is an
//! empty program, so the library's tests can build for the host.
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(not(target_arch = "riscv32"))]
fn main() {}

#[cfg(target_arch = "riscv32")]
mod host;
#[cfg(target_arch = "riscv32")]
mod light;
#[cfg(target_arch = "riscv32")]
mod power;
#[cfg(target_arch = "riscv32")]
mod scan;

#[cfg(target_arch = "riscv32")]
use {
    core::cell::RefCell,
    embassy_executor::Spawner,
    embassy_sync::{
        blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
        signal::Signal,
    },
    esp_hal::{clock::CpuClock, timer::timg::TimerGroup},
    esp_println::println,
    firmware_tdeck_tkeyboard::Controller,
};

#[cfg(target_arch = "riscv32")]
esp_bootloader_esp_idf::esp_app_desc!();

/// The keyboard's whole state, shared by the scan and the host. Every
/// borrow is short, so a host read is answered while its clock is held.
#[cfg(target_arch = "riscv32")]
static KEYBOARD: Mutex<CriticalSectionRawMutex, RefCell<Controller>> =
    Mutex::new(RefCell::new(Controller::new()));

/// The key light's duty, each time it changes.
#[cfg(target_arch = "riscv32")]
static LIGHT: Signal<CriticalSectionRawMutex, u8> = Signal::new();

/// Runs `f` on the keyboard, and passes on any change to the light.
#[cfg(target_arch = "riscv32")]
fn with_keyboard<R>(f: impl FnOnce(&mut Controller) -> R) -> R {
    KEYBOARD.lock(|keyboard| {
        let mut keyboard = keyboard.borrow_mut();
        let before = keyboard.backlight();
        let result = f(&mut keyboard);
        if keyboard.backlight() != before {
            LIGHT.signal(keyboard.backlight());
        }
        result
    })
}

#[cfg(target_arch = "riscv32")]
#[esp_rtos::main]
async fn main(spawner: Spawner) {
    // The stock firmware's clock; lowering it waits for power measurements.
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::_80MHz);
    let p = esp_hal::init(config);
    let sleep = esp_rtos::sleep::configure(p.LPWR);
    esp_rtos::start_with_idle_hook(TimerGroup::new(p.TIMG0).timer0, sleep.light_sleep_hook);
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    // The light comes up dark before the host can reach us, so a host's
    // first `01` is never undone by setup, as it can be on stock firmware.
    spawner.spawn(light::task(light::Light::new(p.LEDC, p.GPIO9)).unwrap());
    let matrix = scan::Matrix::new(
        [
            p.GPIO1.into(),
            p.GPIO4.into(),
            p.GPIO5.into(),
            p.GPIO11.into(),
            p.GPIO13.into(),
        ],
        [
            p.GPIO0.into(),
            p.GPIO3.into(),
            p.GPIO19.into(),
            p.GPIO12.into(),
            p.GPIO18.into(),
            p.GPIO6.into(),
            p.GPIO7.into(),
        ],
    );
    spawner.spawn(scan::task(matrix).unwrap());
    let bus = host::Bus {
        i2c: p.I2C0,
        sda: p.GPIO2.into(),
        scl: p.GPIO10.into(),
    };
    spawner.spawn(host::task(bus).unwrap());
}

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("panic: {info}");
    // Let the UART drain before the reset cuts it off.
    let deadline = esp_hal::time::Instant::now() + esp_hal::time::Duration::from_millis(50);
    while esp_hal::time::Instant::now() < deadline {}
    esp_hal::system::software_reset()
}
