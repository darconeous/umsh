//! Version-pinning spike for the Heltec WiFi LoRa 32 V2 BLE path:
//! esp-radio BLE controller -> bt-hci `ExternalController` -> trouble-host
//! (the audited darconeous fork), with the embassy executor running on
//! esp-rtos. Proves the whole ESP32 BLE stack coexists at the pinned
//! versions before any real firmware believes it.
//!
//! GATT surface mirrors `ble-spike-techo`: a CompanionService-shaped
//! echo characteristic pair with encrypted permissions and a 20 s pairing
//! window, so the same `umsh-companionctl` smoke test applies.

#![no_std]
#![no_main]

use core::future::pending;

use bt_hci::controller::ExternalController;
use embassy_futures::join::join;
use embassy_time::Timer;
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rtc_cntl::{Rtc, RwdtStage};
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_radio::ble::controller::BleConnector;
use trouble_host::prelude::*;

use umsh_bsp_esp32 as _;

esp_bootloader_esp_idf::esp_app_desc!();

const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;
/// HCI command/event slot count for the external controller.
const HCI_SLOTS: usize = 4;

/// 21eb6b15-0001-4ccf-92e4-a079171bec97 in little-endian wire order.
const SERVICE_UUID_LE: [u8; 16] = [
    0x97, 0xec, 0x1b, 0x17, 0x79, 0xa0, 0xe4, 0x92, 0xcf, 0x4c, 0x01, 0x00, 0x15, 0x6b, 0xeb, 0x21,
];

#[gatt_server]
struct Server {
    companion: CompanionService,
}

#[gatt_service(uuid = "21eb6b15-0001-4ccf-92e4-a079171bec97")]
struct CompanionService {
    #[characteristic(
        uuid = "21eb6b15-0002-4ccf-92e4-a079171bec97",
        write,
        permissions(write = encrypted)
    )]
    frame_in: heapless::Vec<u8, 244>,
    #[characteristic(
        uuid = "21eb6b15-0003-4ccf-92e4-a079171bec97",
        notify,
        permissions(cccd = encrypted)
    )]
    frame_out: heapless::Vec<u8, 244>,
}

async fn heartbeat(mut led: Output<'static>, mut rtc: Rtc<'static>) -> ! {
    loop {
        rtc.rwdt.feed();
        led.set_high();
        Timer::after_millis(40).await;
        led.set_low();
        Timer::after_secs(2).await;
    }
}

async fn ble_runner<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) -> ! {
    loop {
        let _ = runner.run().await;
    }
}

async fn pairing_window<C: Controller, P: PacketPool>(stack: &Stack<'_, C, P>) -> ! {
    stack.set_pairing_enabled(true);
    // Generous bench-test window; production firmware gates this on a
    // button press like the nRF NCP does.
    Timer::after_secs(120).await;
    stack.set_pairing_enabled(false);
    pending().await
}

async fn gatt_connection(
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
) -> Result<(), trouble_host::Error> {
    conn.raw().set_bondable(true)?;
    loop {
        match conn.next().await {
            GattConnectionEvent::Disconnected { .. } => return Ok(()),
            GattConnectionEvent::Gatt { event } => {
                let bonded = conn.raw().is_bonded_peer();
                let mut echo: Option<heapless::Vec<u8, 244>> = None;
                if let GattEvent::Write(write) = &event {
                    if write.handle() == server.companion.frame_in.handle {
                        write.with_data(|_, data| {
                            let mut value = heapless::Vec::new();
                            let _ = value.extend_from_slice(data);
                            echo = Some(value);
                        });
                    }
                }

                let reply = if bonded {
                    event.accept()
                } else {
                    event.reject(AttErrorCode::INSUFFICIENT_AUTHENTICATION)
                }?;
                reply.send().await;

                if bonded {
                    if let Some(value) = echo {
                        let _ = server.companion.frame_out.notify(conn, &value, true).await;
                    }
                }
            }
            _ => {}
        }
    }
}

async fn advertise<'values, 'server, C: Controller>(
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    server: &'server Server<'values>,
) -> Result<GattConnection<'values, 'server, DefaultPacketPool>, BleHostError<C::Error>> {
    let mut data = [0u8; 31];
    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteServiceUuids128(&[SERVICE_UUID_LE]),
            AdStructure::ShortenedLocalName(b"UMSH BLE"),
        ],
        &mut data,
    )?;
    let mut scan_data = [0u8; 31];
    let scan_len = AdStructure::encode_slice(
        &[AdStructure::CompleteLocalName(b"UMSH Heltec Spike")],
        &mut scan_data,
    )?;
    Ok(peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &data[..len],
                scan_data: &scan_data[..scan_len],
            },
        )
        .await?
        .accept()
        .await?
        .with_attribute_server(server)?)
}

async fn ble_app<C: Controller>(controller: C) -> ! {
    let mut resources: HostResources<_, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random([0x55, 0x4d, 0x53, 0x48, 0x00, 0x02]))
        .set_io_capabilities(IoCapabilities::DisplayOnly)
        .set_pairing_enabled(true)
        .set_fixed_passkey(Some(123_456))
        .unwrap()
        .build();
    let runner = stack.runner();
    let mut peripheral = stack.peripheral();
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "UMSH Heltec Spike",
        appearance: &appearance::computer::GENERIC_COMPUTER,
    }))
    .unwrap();

    join(
        ble_runner(runner),
        join(pairing_window(&stack), async {
            loop {
                if let Ok(connection) = advertise(&mut peripheral, &server).await {
                    let _ = gatt_connection(&server, &connection).await;
                }
            }
        }),
    )
    .await;
    unreachable!()
}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    esp_alloc::heap_allocator!(size: 72 * 1024);

    let mut rtc = Rtc::new(peripherals.RTC_TIMER);
    rtc.rwdt.set_timeout(RwdtStage::Stage0, WDT_TIMEOUT);
    rtc.rwdt.enable();

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    println!(
        "{} {} on {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        umsh_bsp_heltec_lora32_v2::BOARD_NAME,
    );

    let led = Output::new(peripherals.GPIO25, Level::Low, OutputConfig::default());
    spawner.spawn(heartbeat_task(led, rtc).unwrap());

    let connector = BleConnector::new(peripherals.BT, Default::default()).unwrap();
    let controller: ExternalController<_, HCI_SLOTS> = ExternalController::new(connector);
    ble_app(controller).await
}

#[embassy_executor::task]
async fn heartbeat_task(led: Output<'static>, rtc: Rtc<'static>) -> ! {
    heartbeat(led, rtc).await
}
