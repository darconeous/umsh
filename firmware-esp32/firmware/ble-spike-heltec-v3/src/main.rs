//! Phase 4 BLE spike for the Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262).
//!
//! Promotes the Phase 0 echo spike into the real companion pairing path:
//! the `CompanionService` GATT shape, `ble_security.rs` lockout policy
//! (ported verbatim from the T-Echo NCP), a **PIN shown on the OLED**
//! (`IoCapabilities::DisplayOnly` + `set_fixed_passkey`), and durable
//! bonds through [`umsh_journal_store`] on the discovered `umsh`
//! partition. Behind the bonded GATT edge runs the real minimal
//! companion-radio protocol (`companion.rs`) — radio-less and
//! non-durable, but enough for the UMSH app's `attach_existing` to
//! complete. The full NCP (radio, persistence, device node) is Phase 5.
//!
//! This proves, on S3 hardware, the two things Phase 4 exists to de-risk:
//!   1. Real trouble-host pairing/bonding drives the esp-radio controller,
//!      bonds survive reboot, and a bonded peer reconnects without
//!      re-pairing.
//!   2. Persisting a bond mid-connection (a flash write with no MPSL
//!      arbitration — the esp-storage cache-suspension stall is the analog
//!      of the nRF ~85 ms NVMC halt) does not drop the BLE link. The
//!      persist is timed and logged.

#![no_std]
#![no_main]

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use bt_hci::controller::ExternalController;
use embassy_futures::join::join;
use embassy_time::{Instant, Timer};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rtc_cntl::{Rtc, RwdtStage};
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_radio::ble::controller::BleConnector;
use trouble_host::prelude::*;

use umsh_bsp_esp32::flash_store;
use umsh_bsp_esp32::rng::EspCryptoRng;
use umsh_bsp_heltec_lora32_v3::display::{self, Display, DisplayConfigAsync as _};
use umsh_bsp_heltec_lora32_v3::vext::Vext;

mod ble_security;
mod ble_store;
mod companion;

use static_cell::StaticCell;

use ble_security::{PairingFailureClass, PairingRuntime, pairing_enabled};
use ble_store::{BleStore, MAX_BONDS, ProtoStore, bond_identity_is_persistable, trouble_bond};
use companion::Companion;

/// The one flash driver behind every journal (bonds, snapshot, identity).
static SHARED_FLASH: StaticCell<ble_store::SharedFlash> = StaticCell::new();

esp_bootloader_esp_idf::esp_app_desc!();

const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;
/// HCI command/event slot count for the external controller.
const HCI_SLOTS: usize = 4;
/// Max GATT value payload the companion characteristics carry.
const BLE_VALUE_MAX: usize = 244;

/// 21eb6b15-0001-4ccf-92e4-a079171bec97 in little-endian wire order.
const SERVICE_UUID_LE: [u8; 16] = [
    0x97, 0xec, 0x1b, 0x17, 0x79, 0xa0, 0xe4, 0x92, 0xcf, 0x4c, 0x01, 0x00, 0x15, 0x6b, 0xeb, 0x21,
];

// ─── Pairing runtime state (mirrors the NCP's atomics) ──────────────────

static PAIRING_MODE: AtomicBool = AtomicBool::new(true);
static PAIRING_FAILURES: AtomicU8 = AtomicU8::new(0);
static PAIRING_LOCKED_OUT: AtomicBool = AtomicBool::new(false);
/// `u32::MAX` sentinel means "no PIN configured".
static PAIRING_PIN: AtomicU32 = AtomicU32::new(u32::MAX);
static BLE_BOND_COUNT: AtomicU8 = AtomicU8::new(0);

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
    frame_in: heapless::Vec<u8, BLE_VALUE_MAX>,
    #[characteristic(
        uuid = "21eb6b15-0003-4ccf-92e4-a079171bec97",
        notify,
        permissions(cccd = encrypted)
    )]
    frame_out: heapless::Vec<u8, BLE_VALUE_MAX>,
}

fn pairing_runtime() -> PairingRuntime {
    PairingRuntime {
        pairing_mode: PAIRING_MODE.load(Ordering::Acquire),
        failures: PAIRING_FAILURES.load(Ordering::Acquire),
        locked_out: PAIRING_LOCKED_OUT.load(Ordering::Acquire),
    }
}

fn publish_pairing_runtime(state: PairingRuntime) {
    PAIRING_MODE.store(state.pairing_mode, Ordering::Release);
    PAIRING_FAILURES.store(state.failures, Ordering::Release);
    PAIRING_LOCKED_OUT.store(state.locked_out, Ordering::Release);
}

fn apply_pairing_gate<C: Controller, P: PacketPool>(stack: &Stack<'_, C, P>) {
    let pin_configured = PAIRING_PIN.load(Ordering::Acquire) != u32::MAX;
    let bonds = usize::from(BLE_BOND_COUNT.load(Ordering::Acquire));
    let enabled = pairing_enabled(
        PAIRING_MODE.load(Ordering::Acquire),
        pin_configured,
        PAIRING_LOCKED_OUT.load(Ordering::Acquire),
        bonds,
        MAX_BONDS,
    );
    stack.set_pairing_enabled(enabled);
    println!(
        "pairing gate enabled={} mode={} pin={} locked={} failures={} bonds={}/{}",
        enabled,
        PAIRING_MODE.load(Ordering::Acquire),
        pin_configured,
        PAIRING_LOCKED_OUT.load(Ordering::Acquire),
        PAIRING_FAILURES.load(Ordering::Acquire),
        bonds,
        MAX_BONDS,
    );
}

fn classify_pairing_failure(error: &trouble_host::Error) -> PairingFailureClass {
    match error {
        trouble_host::Error::Security(PairingFailedReason::ConfirmValueFailed) => {
            PairingFailureClass::ConfirmValue
        }
        trouble_host::Error::Security(PairingFailedReason::DHKeyCheckFailed) => {
            PairingFailureClass::DhKeyCheck
        }
        _ => PairingFailureClass::Other,
    }
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

fn draw_line(display: &mut Display, text: &str, row: i32, style: MonoTextStyle<'_, BinaryColor>) {
    let _ = Text::new(text, Point::new(0, 10 + row * 12), style).draw(display);
}

/// Render the pairing status screen. Best-effort — a display error just
/// leaves the panel stale; it never blocks the BLE path.
async fn render_status(display: &mut Display, connected: bool) {
    let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);
    display.clear_buffer();
    draw_line(display, "UMSH V3 BLE bond", 0, style);

    let mut line: heapless::String<24> = heapless::String::new();
    let pin = PAIRING_PIN.load(Ordering::Acquire);
    let pairing_mode = PAIRING_MODE.load(Ordering::Acquire);
    if pairing_mode && pin != u32::MAX {
        let _ = write!(line, "PIN {pin:06}");
    } else if pairing_mode {
        let _ = write!(line, "pairing (no PIN)");
    } else {
        let _ = write!(line, "paired");
    }
    draw_line(display, &line, 1, style);

    line.clear();
    let _ = write!(
        line,
        "bonds {}/{}{}",
        BLE_BOND_COUNT.load(Ordering::Acquire),
        MAX_BONDS,
        if PAIRING_LOCKED_OUT.load(Ordering::Acquire) {
            " LOCK"
        } else {
            ""
        },
    );
    draw_line(display, &line, 2, style);

    draw_line(
        display,
        if connected { "link: up" } else { "link: advertising" },
        3,
        style,
    );
    let _ = display.flush().await;
}

/// Persist a bond, timing and logging only when a flash write actually
/// happens. This is the Phase 4 stability probe: the write occurs while
/// the connection is live and the controller is running, with no MPSL
/// arbitration. `add_bond` is idempotent, so repeated protected-edge
/// writes for an already-stored bond are silent no-ops — logging them
/// would bury the one measurement that matters under `0ms` noise.
async fn persist_bond_timed(store: &mut BleStore, bond: &BondInformation) -> Result<usize, ()> {
    let started = Instant::now();
    let (count, wrote_flash) = store.add_bond(bond).await.inspect_err(|()| {
        println!(
            "bond persist=FAILED flash-stall={}ms",
            started.elapsed().as_millis()
        )
    })?;
    if wrote_flash {
        println!(
            "bond persist=ok count={count} flash-stall={}ms",
            started.elapsed().as_millis()
        );
    }
    Ok(count)
}

/// Fragment one companion response frame into SAR segments and notify
/// them out, sized to the live ATT MTU (same shape as the nRF NCP's
/// `send_ble_frame`, minus the generation tagging — the spike has one
/// session and one transport).
async fn send_companion_frame(
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    frame: &[u8],
) -> Result<(), trouble_host::Error> {
    let segment_payload = usize::from(conn.raw().att_mtu())
        .saturating_sub(4)
        .clamp(1, BLE_VALUE_MAX - 1);
    for segment in companion::segments(frame, segment_payload) {
        let mut value: heapless::Vec<u8, BLE_VALUE_MAX> = heapless::Vec::new();
        value
            .push(segment.header())
            .map_err(|_| trouble_host::Error::InsufficientSpace)?;
        value
            .extend_from_slice(segment.payload())
            .map_err(|_| trouble_host::Error::InsufficientSpace)?;
        server.companion.frame_out.notify(conn, &value, false).await?;
    }
    Ok(())
}

async fn gatt_connection<C: Controller>(
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    stack: &Stack<'_, C, DefaultPacketPool>,
    store: &mut BleStore,
    session: &mut Companion,
    display: &mut Display,
) -> Result<(), trouble_host::Error> {
    conn.raw().set_bondable(true)?;
    render_status(display, true).await;
    let mut attached = false;
    let mut reassembler: companion::Reassembler<{ companion::MAX_FRAME }> =
        companion::Reassembler::new();
    let result = gatt_connection_loop(
        server,
        conn,
        stack,
        store,
        session,
        display,
        &mut attached,
        &mut reassembler,
    )
    .await;
    if attached {
        println!("companion: detach (connection ended)");
        session.detach();
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn gatt_connection_loop<C: Controller>(
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    stack: &Stack<'_, C, DefaultPacketPool>,
    store: &mut BleStore,
    session: &mut Companion,
    display: &mut Display,
    attached: &mut bool,
    reassembler: &mut companion::Reassembler<{ companion::MAX_FRAME }>,
) -> Result<(), trouble_host::Error> {
    loop {
        match conn.next().await {
            GattConnectionEvent::Disconnected { reason } => {
                println!("disconnected reason={reason:?}");
                return Ok(());
            }
            GattConnectionEvent::PairingComplete { bond, .. } => {
                println!(
                    "pairing-complete carried-bond={} table-match={}",
                    bond.is_some(),
                    conn.raw().is_bonded_peer(),
                );
                if let Some(bond) = bond {
                    if !bond_identity_is_persistable(&bond) {
                        println!("pairing bond identity=incomplete; dropping");
                        let _ = stack.remove_bond_information(bond.identity);
                        conn.raw().disconnect();
                        return Ok(());
                    }
                    match persist_bond_timed(store, &bond).await {
                        Ok(count) => BLE_BOND_COUNT.store(count as u8, Ordering::Release),
                        Err(()) => {
                            let _ = stack.remove_bond_information(bond.identity);
                            conn.raw().disconnect();
                            return Ok(());
                        }
                    }
                }
                // Trouble may report success with bond=None and expose the
                // completed bond at the first protected GATT edge. Either
                // way the window closes and the failure counter resets.
                publish_pairing_runtime(pairing_runtime().pairing_succeeded());
                apply_pairing_gate(stack);
                render_status(display, true).await;
            }
            GattConnectionEvent::Encrypted { bond, .. } => {
                println!(
                    "encrypted carried-bond={} table-match={} level={:?}",
                    bond.is_some(),
                    conn.raw().is_bonded_peer(),
                    conn.raw().security_level(),
                );
                if bond.is_some() || conn.raw().is_bonded_peer() {
                    publish_pairing_runtime(pairing_runtime().bonded_reconnect());
                    apply_pairing_gate(stack);
                    render_status(display, true).await;
                }
            }
            GattConnectionEvent::PairingFailed(error) => {
                println!("pairing-failed error={error:?}");
                let failure = classify_pairing_failure(&error);
                if failure.counts_toward_lockout() {
                    let before = pairing_runtime();
                    let after = before.record_failure(failure);
                    publish_pairing_runtime(after);
                    println!(
                        "pairing authentication-failures={} locked={}",
                        after.failures, after.locked_out,
                    );
                    if after.locked_out && !before.locked_out {
                        apply_pairing_gate(stack);
                    }
                    render_status(display, true).await;
                }
            }
            GattConnectionEvent::Gatt { event } => {
                let bonded = conn.raw().is_bonded_peer();
                // Protected edge is authoritative: if trouble says this peer
                // is bonded but PairingComplete never carried the bond, find
                // the live-table entry and make it durable. add_bond is
                // idempotent, so subsequent frames do not re-write flash.
                let frame_in_write = matches!(&event, GattEvent::Write(w) if w.handle() == server.companion.frame_in.handle);
                let cccd_write = matches!(&event, GattEvent::Write(w) if Some(w.handle()) == server.companion.frame_out.cccd_handle);
                if bonded && (frame_in_write || cccd_write) {
                    let peer = conn.raw().peer_identity();
                    let durable = stack.with_bond_information(|bonds| {
                        bonds
                            .iter()
                            .find(|b| b.identity.match_identity(&peer))
                            .cloned()
                    });
                    if let Some(bond) = durable {
                        if bond_identity_is_persistable(&bond) {
                            if let Ok(count) = persist_bond_timed(store, &bond).await {
                                BLE_BOND_COUNT.store(count as u8, Ordering::Release);
                                apply_pairing_gate(stack);
                            }
                        }
                    }
                }

                // Stage the raw SAR segment before replying to the write.
                let mut inbound: Option<heapless::Vec<u8, BLE_VALUE_MAX>> = None;
                if frame_in_write {
                    if let GattEvent::Write(write) = &event {
                        write.with_data(|_, data| {
                            let mut value = heapless::Vec::new();
                            let _ = value.extend_from_slice(data);
                            inbound = Some(value);
                        });
                    }
                }

                let reply = if bonded {
                    event.accept()
                } else {
                    event.reject(AttErrorCode::INSUFFICIENT_AUTHENTICATION)
                }?;
                reply.send().await;

                if !bonded {
                    continue;
                }

                // CCCD writes drive the session attach lifecycle: a
                // subscribe is the host attaching, an unsubscribe (or
                // disconnect) detaches.
                if cccd_write {
                    let subscribed = server.companion.frame_out.should_notify(conn);
                    match (*attached, subscribed) {
                        (false, true) => {
                            println!("companion: attach (cccd subscribed)");
                            *attached = true;
                            session.attach();
                        }
                        (true, false) => {
                            println!("companion: detach (cccd unsubscribed)");
                            *attached = false;
                            reassembler.reset();
                            session.detach();
                        }
                        _ => {}
                    }
                }

                // Reassemble the inbound SAR stream; each complete frame
                // goes through the real companion session, and every
                // response frame is fragmented back out.
                if let Some(segment) = inbound {
                    match reassembler.push(&segment) {
                        Some(Ok(frame)) => {
                            let now_ms = Instant::now().as_millis();
                            let mut staged: companion::OutFrame = heapless::Vec::new();
                            let (responses, pin_request) = match staged.extend_from_slice(frame) {
                                Ok(()) => session.handle_frame(&staged, now_ms).await,
                                Err(_) => {
                                    println!(
                                        "companion: frame staging=FAILED len={}",
                                        frame.len()
                                    );
                                    continue;
                                }
                            };
                            for response in &responses {
                                send_companion_frame(server, conn, response).await?;
                            }
                            if let Some(request) = pin_request {
                                // Persist first, then the live passkey; the
                                // transaction succeeds only when both hold.
                                let mut applied = store.set_pin(request.pin).await.is_ok();
                                if applied {
                                    applied = stack.set_fixed_passkey(request.pin).is_ok();
                                }
                                if applied {
                                    PAIRING_PIN.store(
                                        request.pin.unwrap_or(u32::MAX),
                                        Ordering::Release,
                                    );
                                    apply_pairing_gate(stack);
                                }
                                println!(
                                    "companion: pin applied={applied} present={}",
                                    request.pin.is_some(),
                                );
                                for response in &session.respond_pin(request.tid, applied) {
                                    send_companion_frame(server, conn, response).await?;
                                }
                                render_status(display, true).await;
                            }
                        }
                        Some(Err(error)) => {
                            println!("companion: frame decode=FAILED error={error:?}");
                        }
                        None => {}
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
        &[AdStructure::CompleteLocalName(b"UMSH Heltec V3")],
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

async fn ble_app<C: Controller>(
    controller: C,
    mut store: BleStore,
    mut session: Companion,
    mut display: Display,
    identity: Address,
) -> ! {
    let pin = store.snapshot().pin;
    let bonds_at_boot = store.snapshot().bonds.clone();
    let pairing_mode = bonds_at_boot.is_empty();

    PAIRING_PIN.store(pin.unwrap_or(u32::MAX), Ordering::Release);
    BLE_BOND_COUNT.store(bonds_at_boot.len() as u8, Ordering::Release);
    PAIRING_MODE.store(pairing_mode, Ordering::Release);

    let io_capabilities = if pin.is_some() {
        IoCapabilities::DisplayOnly
    } else {
        IoCapabilities::NoInputNoOutput
    };
    let initial_pairing_enabled = pairing_enabled(
        pairing_mode,
        pin.is_some(),
        false,
        bonds_at_boot.len(),
        MAX_BONDS,
    );
    println!(
        "ble configure identity={identity} io={io_capabilities:?} pairing-enabled={} pin={} bonds={}",
        initial_pairing_enabled,
        pin.is_some(),
        bonds_at_boot.len(),
    );

    let mut resources: HostResources<_, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(identity)
        .set_io_capabilities(io_capabilities)
        .set_pairing_enabled(initial_pairing_enabled)
        .set_fixed_passkey(pin)
        .expect("invalid fixed passkey")
        .build();

    for (index, bond) in bonds_at_boot.iter().enumerate() {
        match trouble_bond(bond) {
            Some(bond) => match stack.add_bond_information(bond) {
                Ok(()) => println!("restored bond index={index} add=ok"),
                Err(error) => println!("restored bond index={index} add=FAILED error={error:?}"),
            },
            None => println!("restored bond index={index} decode=FAILED"),
        }
    }

    let runner = stack.runner();
    let mut peripheral = stack.peripheral();
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "UMSH Heltec V3",
        appearance: &appearance::computer::GENERIC_COMPUTER,
    }))
    .unwrap();

    render_status(&mut display, false).await;

    join(ble_runner(runner), async {
        loop {
            render_status(&mut display, false).await;
            match advertise(&mut peripheral, &server).await {
                Ok(conn) => {
                    let _ = gatt_connection(
                        &server,
                        &conn,
                        &stack,
                        &mut store,
                        &mut session,
                        &mut display,
                    )
                    .await;
                }
                Err(error) => println!("advertise error={error:?}"),
            }
        }
    })
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
        umsh_bsp_heltec_lora32_v3::BOARD_NAME,
    );

    let led = Output::new(peripherals.GPIO35, Level::Low, OutputConfig::default());
    spawner.spawn(heartbeat_task(led, rtc).unwrap());

    // ── Flash: discover the `umsh` partition (never hardcoded) ───────────
    let (flash, partition) = flash_store::open_partition(peripherals.FLASH)
        .unwrap_or_else(|e| panic!("umsh partition not found: {e:?}"));
    println!(
        "storage: umsh partition 0x{:06x}..0x{:06x}",
        partition.start, partition.end,
    );

    // ── BLE controller first: it is the RF entropy source for the TRNG ───
    let connector = BleConnector::new(peripherals.BT, Default::default()).unwrap();
    let mut rng = EspCryptoRng::new().unwrap_or_else(|e| panic!("crypto rng unavailable: {e:?}"));
    let controller: ExternalController<_, HCI_SLOTS> = ExternalController::new(connector);

    // ── Mount the journals; generate+persist PIN and local IRK once ──────
    let shared: &'static ble_store::SharedFlash = SHARED_FLASH.init(ble_store::shared(flash));
    let mut store = BleStore::mount(shared, &partition).await;
    println!(
        "store mounted: bonds={} pin={} local-irk={}",
        store.snapshot().bonds.len(),
        store.snapshot().pin.is_some(),
        store.snapshot().local_irk.is_some(),
    );
    if store.snapshot().local_irk.is_none() {
        let mut local_irk = [0u8; 16];
        rng.fill_bytes(&mut local_irk);
        if local_irk == [0; 16] {
            local_irk[0] = 1;
        }
        store
            .set_local_irk(local_irk)
            .await
            .unwrap_or_else(|_| panic!("local irk persist failed"));
    }
    if store.snapshot().pin.is_none() {
        let mut raw = [0u8; 4];
        rng.fill_bytes(&mut raw);
        let pin = u32::from_le_bytes(raw) % 1_000_000;
        store
            .set_pin(Some(pin))
            .await
            .unwrap_or_else(|_| panic!("pin persist failed"));
        println!("generated pairing PIN {pin:06} on first boot");
    }

    // ── Protocol snapshot + device-identity journals ─────────────────────
    let (proto_store, boot_snapshot) =
        ProtoStore::mount(shared, ble_store::proto_page0(&partition)).await;
    let (identity_store, identity_payload) =
        ProtoStore::mount(shared, ble_store::identity_page0(&partition)).await;
    let boot_identity = identity_payload
        .as_deref()
        .and_then(umsh_journal_store::proto::decode_identity)
        .map(|(_secret, public)| public);
    println!(
        "proto mounted: snapshot={} identity={}",
        boot_snapshot.is_some(),
        boot_identity.is_some(),
    );
    // The companion session outlives connections: host-domain state
    // survives a drop/reconnect exactly as on the nRF NCPs.
    let session = Companion::new(proto_store, identity_store, boot_snapshot, boot_identity);

    // Stable random-static identity (top two bits of the MSB set) so a
    // bonded peer reconnects to the same address across reboots.
    let identity = Address::random([0x55, 0x4d, 0x53, 0x48, 0x00, 0xc3]);

    // ── OLED (Vext up → reset → init), then hand the panel to the app ────
    let mut vext = Vext::new(peripherals.GPIO36);
    let mut oled_reset = Output::new(peripherals.GPIO21, Level::High, OutputConfig::default());
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(400)),
    )
    .unwrap()
    .with_sda(peripherals.GPIO17)
    .with_scl(peripherals.GPIO18)
    .into_async();
    let mut display = display::new_display(i2c);
    vext.enable().await;
    display::reset(&mut oled_reset).await;
    if display.init().await.is_err() {
        println!("oled: init failed (continuing headless)");
    }

    ble_app(controller, store, session, display, identity).await
}

#[embassy_executor::task]
async fn heartbeat_task(led: Output<'static>, rtc: Rtc<'static>) -> ! {
    heartbeat(led, rtc).await
}
