// Companion-radio NCP firmware shared by the LilyGO T-Echo and Seeed
// SenseCAP T-1000E targets. Cargo features select the board-specific glue.
//
// Exposes the board's LoRa radio as a host-controlled PHY speaking the minimal
// companion-radio protocol plus advertised full-profile extensions
// over USB-CDC/HDLC-Lite and encrypted+bonded BLE GATT/SAR. The UMSH MAC does not run here:
// the host owns it and drives this device through
// `umsh::companion_radio::CompanionRadio`.
//
// Protocol behavior lives in `umsh-companion-ncp::Session` (host-tested,
// no I/O); this binary is only glue:
//
// Task layout (steady state):
//   - main():            initializes MPSL/SDC and joins BLE, USB, heartbeat
//   - radio_task:        owns lora_phy::LoRa via umsh_radio_loraphy::ncp_runner;
//                        modulation/frequency/power are pushed at runtime
//                        through NCP_CTL as the host sets properties
//   - usb_in_task:       owns CdcAcmRescue + HDLC decoder; forwards frames and
//                        attach/detach edges into INPUT_CH (keeps
//                        read_packet out of any select, so cancel safety
//                        never depends on the USB driver)
//   - ncp_task:          owns the framing-free Session; sorts INPUT_CH,
//                        radio RX, and TX completions into session calls
//   - output_task:       owns the USB Sender + HDLC encoder, drains OUT_USB_CH
//   - ble_app:           advertising + encrypted/bond-gated GATT/SAR edges,
//                        pairing policy, generation-tagged OUT_BLE_CH, and
//                        MPSL-coordinated PIN/bond persistence
//   - button_task:       resolves the side button into display-menu gestures
//   - display_task:      owns the e-paper BLE menu
//   - touch_task:        preserves the touch button's backlight control
//   - shutdown_task:     tri-states peripheral pins, drops the rail,
//                        enters System OFF
//
// CMD_RST is a protocol-level reset: all protocol state returns to
// post-reset values and the radio is re-applied (disabled), but the MCU
// and the USB link stay up. Host attach resets only session state
// (full-protocol semantics): the device domain — PHY configuration and
// enable state, device name, duty accounting — is untouched, and
// nothing is emitted; the reset notice is only sent for CMD_RST, so the
// host never sees an unsolicited reset it didn't ask for mid-handshake.
//
// Safety primitives inherited from the BSP (see umsh-bsp-nrf52840):
//   * Panic capture into reserved RAM (reported as STATUS_RESET_CRASH).
//   * 1200-baud touchless reset and Ctrl-C × 3 + "dfu" escape to
//     bootloader (baked into CdcAcmRescue).
//   * Watchdog.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
// The no-ble diagnostic image compiles the full BLE support source
// (pairing policy, bond store, GATT plumbing) with the call sites
// cfg'd out. Silence the resulting dead-code noise for that image
// only, so production builds keep full warning strength.
#![cfg_attr(feature = "no-ble", allow(dead_code, unused_imports))]

#[cfg(not(target_os = "none"))]
fn main() {
    // Host placeholder. This binary only runs on the embedded target.
}

// The T-1000E BSP also supports the on-device MAC/CLI firmware and therefore
// links a small amount of alloc-using board glue. The NCP does not allocate in
// steady state, but the final binary still needs a valid global allocator.
#[cfg(all(target_os = "none", feature = "t1000e"))]
#[global_allocator]
static ALLOCATOR: embedded_alloc::Heap = embedded_alloc::Heap::empty();

#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod ble_security;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod ble_store;
mod proto_store;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod transport_policy;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
#[cfg_attr(feature = "t1000e", allow(dead_code))]
mod ui;

// The #[panic_handler] must live in the binary crate.
#[cfg(target_os = "none")]
mod panic;

// lora-phy 3.x unconditionally depends on defmt. Provide a zero-overhead
// no-op global logger so this binary links without any debug transport.
#[cfg(target_os = "none")]
mod defmt_logger {
    #[defmt::global_logger]
    struct Logger;
    unsafe impl defmt::Logger for Logger {
        fn acquire() {}
        unsafe fn flush() {}
        unsafe fn release() {}
        unsafe fn write(_: &[u8]) {}
    }
    defmt::timestamp!("{=u32}", 0u32);
}

#[cfg(target_os = "none")]
mod firmware {
    use super::ble_security::{PairingFailureClass, PairingRuntime, pairing_enabled};
    use super::ble_store::{self, Snapshot, StoredBond};
    use super::proto_store;
    use super::transport_policy::{SessionArbitration, Transport, generation_checked};
    use super::ui::UiNotice;
    #[cfg(not(feature = "t1000e"))]
    use super::ui::{MenuItem, Page, UiEffect, UiInput, UiModel};
    #[cfg(feature = "ble-debug")]
    use core::fmt::Write as _;
    use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, Ordering};
    use embassy_executor::Spawner;
    use embassy_futures::join::join;
    use embassy_futures::select::{Either, Either3, Either4, select, select3, select4};
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
    use embassy_nrf::mode::Async;
    use embassy_nrf::pac;
    use embassy_nrf::peripherals::{self, RNG};
    #[cfg(feature = "t1000e")]
    use embassy_nrf::pwm::{DutyCycle, Prescaler, SimpleConfig, SimplePwm};
    use embassy_nrf::rng;
    #[cfg(feature = "t1000e")]
    use embassy_nrf::saadc::{ChannelConfig, Config as SaadcConfig, Saadc};
    use embassy_nrf::spim::{Config as SpimConfig, Frequency, Spim};
    use embassy_nrf::usb::Driver;
    use embassy_nrf::usb::vbus_detect::SoftwareVbusDetect;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::channel::Channel;
    use embassy_sync::mutex::Mutex;
    use embassy_sync::signal::Signal;
    use embassy_time::{Delay, Duration, Instant, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
    use embassy_usb::{Builder, Config};
    use embedded_hal_bus::spi::ExclusiveDevice;
    use lora_phy::LoRa;
    #[cfg(feature = "t1000e")]
    use lora_phy::iv::GenericLr1110InterfaceVariant;
    #[cfg(not(feature = "t1000e"))]
    use lora_phy::iv::GenericSx126xInterfaceVariant;
    #[cfg(feature = "t1000e")]
    use lora_phy::lr1110::{
        Config as LoraConfig, Lr1110, TcxoCtrlVoltage, radio_kind_params::PaSelection,
        variant::Lr1110 as Lr1110Chip,
    };
    #[cfg(not(feature = "t1000e"))]
    use lora_phy::sx126x::{Config as LoraConfig, Sx126x, Sx1262, TcxoCtrlVoltage};
    use nrf_sdc::mpsl::{self, MultiprotocolServiceLayer};
    use nrf_sdc::{self as sdc};
    use static_cell::StaticCell;
    use trouble_host::prelude::*;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_bsp_nrf52840::system_off::Port;
    #[cfg(not(feature = "t1000e"))]
    use umsh_bsp_nrf52840::system_off::{WakePin, WakeSense, power_off, tristate_pin};
    #[cfg(feature = "t1000e")]
    use umsh_bsp_nrf52840::system_off::drive_pin_low;
    #[cfg(feature = "t1000e")]
    use umsh_bsp_t1000e::RF_SWITCH;
    #[cfg(not(feature = "t1000e"))]
    use umsh_bsp_techo::display;
    use umsh_companion::{Status, gatt, hdlc};
    use umsh_companion_ncp::{
        Effect, IdentitySource, MAX_DEVICE_NAME_LEN, RadioSettings, SessionConfig, TxPower,
    };
    use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
    use umsh_crypto::{CryptoEngine, NodeIdentity as _};

    /// The NCP session instantiated with this firmware's crypto
    /// providers (software AES/SHA; Ed25519 comes in only through the
    /// device-identity provisioning path).
    type Session = umsh_companion_ncp::Session<SoftwareAes, SoftwareSha256>;

    /// Deterministic CSPRNG for device-identity generation, seeded from
    /// the hardware TRNG at boot: the RNG peripheral itself is owned by
    /// the SoftDevice Controller for the lifetime of the BLE stack.
    type IdentityRng = rand_chacha::ChaCha20Rng;
    use umsh_radio_loraphy::{
        MAX_PAYLOAD, NcpControl, NcpSettings, RxFrame, TxRequest, bandwidth_from_hz,
        coding_rate_from_denom, spreading_factor_from_u8,
    };
    use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm, ButtonTimings};
    #[cfg(feature = "t1000e")]
    use umsh_ux_tracker::buzzer::melodies as buzzer_melodies;
    #[cfg(not(feature = "t1000e"))]
    use umsh_ux_tracker::led::{LedEngine, LedTimings};
    #[cfg(feature = "t1000e")]
    use umsh_ux_tracker::led::{LedSequence, T1000eLedEngine};

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        RNG         => rng::InterruptHandler<RNG>;
        EGU0_SWI0   => nrf_sdc::mpsl::LowPrioInterruptHandler;
        CLOCK_POWER => nrf_sdc::mpsl::ClockInterruptHandler;
        RADIO       => nrf_sdc::mpsl::HighPrioInterruptHandler;
        TIMER0      => nrf_sdc::mpsl::HighPrioInterruptHandler;
        RTC0        => nrf_sdc::mpsl::HighPrioInterruptHandler;
        // SPIM0 → LR1110 on the T-1000E.
        TWISPI0     => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI0>;
        // SPIM1 → SX1262 LoRa SPI bus. embassy-nrf names this peripheral
        // TWISPI1 (it's the shared TWIM1/SPIM1 block on nRF52840).
        TWISPI1     => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI1>;
        // SPIM2 → SSD1681 e-paper SPI bus. embassy-nrf names this interrupt SPI2.
        SPI2        => embassy_nrf::spim::InterruptHandler<peripherals::SPI2>;
        SAADC       => embassy_nrf::saadc::InterruptHandler;
    });

    // ─── Configuration ───────────────────────────────────────────────────────

    /// SX1262 PA limits on this module.
    const MIN_TX_POWER_DBM: i8 = -9;
    const MAX_TX_POWER_DBM: i8 = 22;

    const BLE_CONNECTIONS_MAX: usize = 1;
    const BLE_L2CAP_CHANNELS_MAX: usize = 2;
    const BLE_L2CAP_TXQ: u8 = 3;
    const BLE_L2CAP_RXQ: u8 = 3;
    /// Nordic's SDC buffer configuration accepts 27..=251 octets.
    const SDC_PACKET_SIZE: u16 = 251;
    const BLE_VALUE_MAX: usize = 244;
    #[cfg(not(feature = "t1000e"))]
    const DEFAULT_DEVICE_NAME: &str = "UMSH T-Echo NCP";
    #[cfg(feature = "t1000e")]
    const DEFAULT_DEVICE_NAME: &str = "UMSH T-1000E NCP";

    #[gatt_server]
    struct CompanionServer {
        companion: CompanionService,
    }

    #[gatt_service(uuid = "21eb6b15-0001-4ccf-92e4-a079171bec97")]
    struct CompanionService {
        #[characteristic(
            uuid = "21eb6b15-0002-4ccf-92e4-a079171bec97",
            write,
            write_without_response,
            permissions(write = encrypted)
        )]
        frame_in: heapless09::Vec<u8, BLE_VALUE_MAX>,
        #[characteristic(
            uuid = "21eb6b15-0003-4ccf-92e4-a079171bec97",
            notify,
            permissions(cccd = encrypted)
        )]
        frame_out: heapless09::Vec<u8, BLE_VALUE_MAX>,
    }

    /// Compose the NCP version string once at boot. `crumb` is the
    /// previous boot's last breadcrumb stage (temporary freeze
    /// diagnostics; see `panic::breadcrumb_take`).
    fn ncp_version(bonds: u8, crumb: u8) -> &'static str {
        use core::fmt::Write as _;
        #[cfg(not(feature = "t1000e"))]
        const BOARD: &str = "umsh-ncp-techo";
        #[cfg(feature = "t1000e")]
        const BOARD: &str = "umsh-ncp-t1000e";
        static VERSION: StaticCell<heapless09::String<96>> = StaticCell::new();
        let version = VERSION.init(heapless09::String::new());
        // Compact diagnostic form: PROP_NCP_VERSION is truncated to the
        // session's 96-byte property buffer, so the SHA and bond count
        // yield their space to the freeze capture for now. `d5` is the
        // diagnostic build tag — bump it every diagnostic rebuild so the
        // running image is provably the fresh one.
        let _ = write!(
            version,
            "{BOARD} d6 c={crumb} b={} rr={:#x} rc={} pc={:#010x} lr={:#010x} ps={:#010x}",
            PREV_BOOT_BEATS.load(Ordering::Acquire),
            BOOT_RESETREAS.load(Ordering::Acquire),
            PREV_RING_COUNT.load(Ordering::Acquire),
            PREV_WDT_PC.load(Ordering::Acquire),
            PREV_WDT_LR.load(Ordering::Acquire),
            PREV_WDT_PSR.load(Ordering::Acquire),
        );
        let _ = bonds;
        version.as_str()
    }

    fn session_config() -> SessionConfig {
        SessionConfig {
            ncp_version: ncp_version(
                BLE_BONDS_AT_BOOT.load(Ordering::Acquire),
                PREV_BOOT_CRUMB.load(Ordering::Acquire),
            ),
            default_device_name: DEFAULT_DEVICE_NAME,
            mtu: MAX_PAYLOAD as u16,
            // Fixed at build time: LoRa::new(.., false, ..) below sets the
            // private-network word 0x12 → SX126x registers 0x1424.
            sync_word: 0x1424,
            min_tx_power_dbm: MIN_TX_POWER_DBM,
            max_tx_power_dbm: MAX_TX_POWER_DBM,
            // SX1262 tunable range.
            freq_khz_min: 150_000,
            freq_khz_max: 960_000,
            // Post-reset defaults (PHY disabled until the host enables it);
            // RF values match the MeshCore-US bringup profile.
            defaults: RadioSettings {
                enabled: false,
                freq_khz: 910_525,
                bw_hz: 62_500,
                sf: 7,
                cr_denom: 5,
                tx_power_dbm: 14,
            },
            default_duty_limit: umsh_companion::ids::DUTY_LIMIT_DISABLED,
        }
    }

    // ─── Concrete types ──────────────────────────────────────────────────────

    type RadioSpiBus = ExclusiveDevice<Spim<'static>, Output<'static>, Delay>;
    #[cfg(not(feature = "t1000e"))]
    type RadioIv = GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>;
    #[cfg(feature = "t1000e")]
    type RadioIv = GenericLr1110InterfaceVariant<Output<'static>, Input<'static>>;
    #[cfg(not(feature = "t1000e"))]
    type RadioKind = Sx126x<RadioSpiBus, RadioIv, Sx1262>;
    #[cfg(feature = "t1000e")]
    type RadioKind = Lr1110<RadioSpiBus, RadioIv, Lr1110Chip>;
    type LoraRadio = LoRa<RadioKind, Delay>;

    type NcpUsbDriver = Driver<'static, &'static SoftwareVbusDetect>;
    type NcpSender = embassy_usb::class::cdc_acm::Sender<'static, NcpUsbDriver>;
    type NcpRescue = CdcAcmRescue<'static, NcpUsbDriver>;
    type BleStoreMutex = Mutex<ThreadModeRawMutex, BleStore>;
    /// The one MPSL-coordinated flash driver, shared between the BLE
    /// bond/PIN journal and the protocol snapshot journal.
    type SharedFlash = Mutex<ThreadModeRawMutex, nrf_mpsl::Flash<'static>>;

    struct BleStore {
        flash: &'static SharedFlash,
        snapshot: Snapshot,
        slot: Option<u32>,
    }

    impl ble_store::RecordWriter for nrf_mpsl::Flash<'static> {
        type Error = ();

        async fn write_record(&mut self, address: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            #[cfg(feature = "ble-store-fault-inject")]
            if BLE_STORE_FAULT_ARMED.load(Ordering::Acquire) {
                debug_log(format_args!(
                    "store fault-inject write address=0x{address:06x} len={}",
                    bytes.len(),
                ));
                return Err(());
            }
            self.write(address, bytes).await.map_err(|_| ())
        }
    }

    impl ble_store::PageEraser for nrf_mpsl::Flash<'static> {
        type Error = ();

        async fn erase_page(&mut self, start: u32, end: u32) -> Result<(), Self::Error> {
            #[cfg(feature = "ble-store-fault-inject")]
            if BLE_STORE_FAULT_ARMED.load(Ordering::Acquire) {
                debug_log(format_args!(
                    "store fault-inject erase start=0x{start:06x} end=0x{end:06x}",
                ));
                return Err(());
            }
            self.erase(start, end).await.map_err(|_| ())
        }
    }

    /// Scan a two-page journal's slot range for a fully erased slot.
    fn erased_journal_slot(
        flash: &mut nrf_mpsl::Flash<'static>,
        start: u32,
        end: u32,
        slot_size: usize,
    ) -> Option<u32> {
        let mut address = start;
        while address < end {
            let mut erased = true;
            let mut offset = 0usize;
            while offset < slot_size {
                let mut chunk = [0u8; 256];
                let take = (slot_size - offset).min(chunk.len());
                match flash.read(address + offset as u32, &mut chunk[..take]) {
                    Ok(()) if chunk[..take].iter().all(|byte| *byte == 0xff) => {}
                    Ok(()) => {
                        erased = false;
                        break;
                    }
                    Err(_) => {
                        debug_log(format_args!(
                            "store erased-slot read=FAILED address=0x{address:06x}"
                        ));
                        erased = false;
                        break;
                    }
                }
                offset += take;
            }
            if erased {
                return Some(address);
            }
            address += slot_size as u32;
        }
        None
    }

    /// Pick the write target for a two-page rotating journal starting at
    /// `page0`: the next erased slot after the current record, or the
    /// opposite page after erasing it.
    async fn journal_write_target(
        flash: &mut nrf_mpsl::Flash<'static>,
        current: Option<u32>,
        page0: u32,
        slot_size: usize,
    ) -> Result<u32, ()> {
        let page1 = page0 + ble_store::PAGE_SIZE;
        let target = if let Some(current) = current {
            let page = if current < page1 { page0 } else { page1 };
            erased_journal_slot(
                flash,
                current + slot_size as u32,
                page + ble_store::PAGE_SIZE,
                slot_size,
            )
        } else {
            erased_journal_slot(flash, page0, page0 + ble_store::PAGE_SIZE, slot_size)
        };
        match target {
            Some(target) => Ok(target),
            None => {
                let page = if current.is_some_and(|slot| slot < page1) {
                    page1
                } else {
                    page0
                };
                debug_log(format_args!("store erase begin page=0x{page:06x}"));
                if ble_store::erase_journal_page(flash, page).await.is_err() {
                    debug_log(format_args!("store erase=FAILED page=0x{page:06x}"));
                    return Err(());
                }
                debug_log(format_args!("store erase=ok page=0x{page:06x}"));
                Ok(page)
            }
        }
    }

    impl BleStore {
        async fn mount(shared: &'static SharedFlash) -> Self {
            let mut flash = shared.lock().await;
            let mut latest: Option<(u32, Snapshot)> = None;
            let mut read_failures = 0u8;
            let mut valid_records = 0u8;
            for page in [ble_store::PAGE0, ble_store::PAGE1] {
                let mut address = page;
                while address < page + ble_store::PAGE_SIZE {
                    let mut bytes = [0u8; ble_store::SLOT_SIZE];
                    if flash.read(address, &mut bytes).is_ok() {
                        if Snapshot::decode(&bytes).is_some() {
                            valid_records = valid_records.saturating_add(1);
                        }
                        latest = ble_store::consider_snapshot(latest, address, &bytes);
                    } else {
                        read_failures = read_failures.saturating_add(1);
                    }
                    address += ble_store::SLOT_SIZE as u32;
                }
            }
            let (slot, snapshot) = latest
                .map(|(slot, snapshot)| (Some(slot), snapshot))
                .unwrap_or((None, Snapshot::empty()));
            debug_log(format_args!(
                "store mount valid-records={} read-failures={} selected-slot={:?} generation={} bonds={} pin={} local-irk={}",
                valid_records,
                read_failures,
                slot,
                snapshot.generation,
                snapshot.bonds.len(),
                snapshot.pin.is_some(),
                snapshot.local_irk.is_some(),
            ));
            drop(flash);
            Self {
                flash: shared,
                snapshot,
                slot,
            }
        }

        fn snapshot(&self) -> &Snapshot {
            &self.snapshot
        }

        async fn persist(&mut self, mut snapshot: Snapshot) -> Result<(), ()> {
            snapshot.generation = self.snapshot.generation.wrapping_add(1);
            let mut flash = self.flash.lock().await;
            let target = journal_write_target(
                &mut flash,
                self.slot,
                ble_store::PAGE0,
                ble_store::SLOT_SIZE,
            )
            .await?;

            let bytes = snapshot.encode();
            debug_log(format_args!(
                "store body-write begin generation={} target=0x{target:06x}",
                snapshot.generation
            ));
            match ble_store::write_committed_record(&mut *flash, target, &bytes).await {
                Ok(()) => debug_log(format_args!(
                    "store body-write=ok commit-write=ok target=0x{target:06x}"
                )),
                Err(ble_store::CommitError::Body(())) => {
                    debug_log(format_args!(
                        "store body-write=FAILED target=0x{target:06x}"
                    ));
                    return Err(());
                }
                Err(ble_store::CommitError::Commit(())) => {
                    debug_log(format_args!(
                        "store body-write=ok commit-write=FAILED target=0x{target:06x}"
                    ));
                    return Err(());
                }
            }
            self.snapshot = snapshot;
            self.slot = Some(target);
            debug_log(format_args!(
                "store commit generation={} slot=0x{:06x} bonds={} pin={} local_irk={}",
                self.snapshot.generation,
                target,
                self.snapshot.bonds.len(),
                self.snapshot.pin.is_some(),
                self.snapshot.local_irk.is_some(),
            ));
            Ok(())
        }

        async fn set_pin(&mut self, pin: Option<u32>) -> Result<(), ()> {
            let mut next = self.snapshot.clone();
            next.pin = pin;
            self.persist(next).await
        }

        async fn set_local_irk(&mut self, local_irk: [u8; 16]) -> Result<(), ()> {
            if self.snapshot.local_irk == Some(local_irk) {
                return Ok(());
            }
            let mut next = self.snapshot.clone();
            next.local_irk = Some(local_irk);
            self.persist(next).await
        }

        async fn add_bond(&mut self, bond: &BondInformation) -> Result<(), ()> {
            let stored = stored_bond(bond);
            let mut next = self.snapshot.clone();
            if let Some(existing) = next.bonds.iter_mut().find(|existing| {
                existing.address_kind == stored.address_kind && existing.address == stored.address
            }) {
                if *existing == stored {
                    return Ok(());
                }
                *existing = stored;
            } else {
                next.bonds.push(stored).map_err(|_| ())?;
            }
            self.persist(next).await
        }

        async fn clear_security(&mut self) -> Result<(), ()> {
            let mut next = Snapshot::empty();
            next.generation = self.snapshot.generation;
            next.local_irk = self.snapshot.local_irk;
            self.persist(next).await
        }
    }

    /// The stored protocol snapshot payload as read at boot.
    type BootSnapshot = heapless::Vec<u8, { proto_store::MAX_PAYLOAD }>;

    /// Runtime handle for one full-protocol record journal
    /// (`proto_store`): the snapshot journal or the device-identity
    /// journal, selected by its first page. Executes the session's
    /// durable effects; the session's RAM mirrors are only updated
    /// through the respond_* completions after these return.
    #[cfg(not(feature = "no-ble"))]
    struct ProtoStore {
        flash: &'static SharedFlash,
        /// First page of this journal's two-page rotation.
        page0: u32,
        generation: u32,
        slot: Option<u32>,
    }

    #[cfg(not(feature = "no-ble"))]
    impl ProtoStore {
        async fn mount(shared: &'static SharedFlash, page0: u32) -> (Self, Option<BootSnapshot>) {
            let mut flash = shared.lock().await;
            let mut latest: Option<(u32, proto_store::Stored)> = None;
            for page in [page0, page0 + proto_store::PAGE_SIZE] {
                let mut address = page;
                while address < page + proto_store::PAGE_SIZE {
                    let mut bytes = [0u8; proto_store::SLOT_SIZE];
                    if flash.read(address, &mut bytes).is_ok() {
                        latest = proto_store::consider_record(latest, address, &bytes);
                    }
                    address += proto_store::SLOT_SIZE as u32;
                }
            }
            drop(flash);
            // A tombstone is authoritative "nothing saved": older
            // snapshot records still physically present are void.
            let (slot, generation, payload) = match latest {
                Some((slot, stored)) => {
                    let payload = match stored.record {
                        proto_store::Record::Snapshot(payload) => Some(payload),
                        proto_store::Record::Cleared => None,
                    };
                    (Some(slot), stored.generation, payload)
                }
                None => (None, 0, None),
            };
            debug_log(format_args!(
                "proto-store mount page0=0x{page0:06x} slot={:?} generation={} payload={}",
                slot,
                generation,
                payload.as_ref().map_or(0, |payload| payload.len()),
            ));
            (
                Self {
                    flash: shared,
                    page0,
                    generation,
                    slot,
                },
                payload,
            )
        }

        async fn persist(&mut self, payload: &[u8]) -> Result<(), ()> {
            let mut buffered = heapless::Vec::new();
            buffered.extend_from_slice(payload).map_err(|_| ())?;
            self.write(proto_store::Record::Snapshot(buffered)).await
        }

        /// The clear transaction is one committed tombstone record: if
        /// its write fails or is interrupted, the previous snapshot
        /// remains authoritative and CMD_CLEAR reports failure. Pages
        /// are never erased as part of a clear — stale records are
        /// reclaimed by the ordinary rotation.
        async fn clear(&mut self) -> Result<(), ()> {
            self.write(proto_store::Record::Cleared).await
        }

        async fn write(&mut self, record: proto_store::Record) -> Result<(), ()> {
            let stored = proto_store::Stored {
                generation: self.generation.wrapping_add(1),
                record,
            };
            let mut flash = self.flash.lock().await;
            let target =
                journal_write_target(&mut flash, self.slot, self.page0, proto_store::SLOT_SIZE)
                    .await?;
            match proto_store::write_record(&mut *flash, target, &stored).await {
                Ok(()) => {
                    debug_log(format_args!(
                        "proto-store commit generation={} slot=0x{target:06x} cleared={}",
                        stored.generation,
                        matches!(stored.record, proto_store::Record::Cleared),
                    ));
                    self.generation = stored.generation;
                    self.slot = Some(target);
                    Ok(())
                }
                Err(_) => {
                    debug_log(format_args!(
                        "proto-store write=FAILED target=0x{target:06x}"
                    ));
                    Err(())
                }
            }
        }
    }

    #[cfg(feature = "t1000e")]
    fn mapped_ux_preferences() -> Option<umsh_ux_tracker::state::UserPreferences> {
        let mut latest: Option<(u32, proto_store::Stored)> = None;
        for page in [
            proto_store::UX_PAGE0,
            proto_store::UX_PAGE0 + proto_store::PAGE_SIZE,
        ] {
            let mut address = page;
            while address < page + proto_store::PAGE_SIZE {
                let mut bytes = [0u8; proto_store::SLOT_SIZE];
                // Internal flash is memory mapped. This early read happens
                // before MPSL takes NVMC and never mutates flash.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        address as *const u8,
                        bytes.as_mut_ptr(),
                        bytes.len(),
                    );
                }
                latest = proto_store::consider_record(latest, address, &bytes);
                address += proto_store::SLOT_SIZE as u32;
            }
        }
        let (_, stored) = latest?;
        let proto_store::Record::Snapshot(payload) = stored.record else {
            return None;
        };
        let mut preferences = umsh_ux_tracker::state::UserPreferences::try_decode(*payload.first()?)?;
        // Critical shutdown is a live protective condition mirrored in the
        // retained register, not a durable user preference.
        preferences.battery_critical = false;
        Some(preferences)
    }

    /// Callers deliberately ignore the result: the preference is already
    /// applied in RAM and mirrored in GPREGRET2, so a failed journal write
    /// costs only durability across the next reset. There is no user-facing
    /// fault channel, and confirmation feedback reflects the applied state,
    /// not the flash commit.
    #[cfg(feature = "t1000e")]
    async fn persist_ux_preferences(
        store: &mut ProtoStore,
        mut preferences: umsh_ux_tracker::state::UserPreferences,
    ) -> Result<(), ()> {
        preferences.battery_critical = false;
        store.persist(&[preferences.encode()]).await
    }

    /// The no-ble diagnostic image has no MPSL flash driver; durable
    /// protocol state is unavailable and saves fail honestly.
    #[cfg(feature = "no-ble")]
    struct ProtoStore;

    #[cfg(feature = "no-ble")]
    impl ProtoStore {
        async fn persist(&mut self, _payload: &[u8]) -> Result<(), ()> {
            Err(())
        }

        async fn clear(&mut self) -> Result<(), ()> {
            Err(())
        }
    }

    fn stored_bond(bond: &BondInformation) -> StoredBond {
        let address = bond.identity.addr.to_bytes();
        StoredBond {
            address_kind: address[0],
            address: address[1..].try_into().unwrap(),
            irk: bond.identity.irk.map(IdentityResolvingKey::to_le_bytes),
            ltk: bond.ltk.to_le_bytes(),
            security_level: match bond.security_level {
                SecurityLevel::NoEncryption => 0,
                SecurityLevel::Encrypted => 1,
                SecurityLevel::EncryptedAuthenticated => 2,
            },
            is_bonded: bond.is_bonded,
        }
    }

    fn bond_identity_is_persistable(bond: &BondInformation) -> bool {
        let address = bond.identity.addr.to_bytes();
        let public = address[0] & 1 == 0;
        let random_static = address[1] & 0xc0 == 0xc0;
        public || random_static || bond.identity.irk.is_some()
    }

    fn trouble_bond(bond: &StoredBond) -> Option<BondInformation> {
        let mut raw = bond.address;
        raw.reverse();
        let identity = Identity {
            addr: Address::new(AddrKind::new(bond.address_kind), BdAddr::new(raw)),
            irk: bond.irk.and_then(IdentityResolvingKey::from_le_bytes),
        };
        let security_level = match bond.security_level {
            0 => SecurityLevel::NoEncryption,
            1 => SecurityLevel::Encrypted,
            2 => SecurityLevel::EncryptedAuthenticated,
            _ => return None,
        };
        Some(BondInformation::new(
            identity,
            LongTermKey::from_le_bytes(bond.ltk),
            security_level,
            bond.is_bonded,
        ))
    }

    fn ble_identity_address() -> Address {
        let low = embassy_nrf::pac::FICR.deviceaddr(0).read().to_le_bytes();
        let high = embassy_nrf::pac::FICR.deviceaddr(1).read().to_le_bytes();
        let mut address = [low[0], low[1], low[2], low[3], high[0], high[1]];
        address[5] |= 0xc0;
        Address::random(address)
    }

    // ─── Static shared state ─────────────────────────────────────────────────

    /// Channels shared between the radio runner and the NCP session task.
    type RadioCh = umsh_radio_loraphy::Channels<ThreadModeRawMutex, 4, 2>;
    static RADIO_CH: RadioCh = RadioCh::new();

    /// Runtime radio settings pushed by the session to the runner.
    static NCP_CTL: NcpControl<ThreadModeRawMutex> = NcpControl::new();

    const FRAME_IN_MAX: usize = 300;

    /// Framing-free receive path and connection edges into ncp_task.
    enum InEvent {
        Attached(Transport),
        Detached(Transport),
        Frame(Transport, heapless::Vec<u8, FRAME_IN_MAX>),
    }
    static INPUT_CH: Channel<ThreadModeRawMutex, InEvent, 8> = Channel::new();

    /// One raw companion frame in the USB output queue.
    type FrameBuf = heapless::Vec<u8, FRAME_IN_MAX>;
    struct OutFrame {
        generation: u32,
        frame: FrameBuf,
    }
    static OUT_USB_CH: Channel<ThreadModeRawMutex, OutFrame, 4> = Channel::new();
    static OUT_BLE_CH: Channel<ThreadModeRawMutex, OutFrame, 4> = Channel::new();

    type DeviceName = heapless::Vec<u8, { MAX_DEVICE_NAME_LEN }>;
    static DEVICE_NAME: Mutex<ThreadModeRawMutex, DeviceName> = Mutex::new(DeviceName::new());
    static DEVICE_NAME_CHANGED: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Published session epoch, checked by each transport at framing edges.
    static SESSION_GEN: AtomicU32 = AtomicU32::new(0);

    /// Previous boot's last breadcrumb stage (temporary freeze
    /// diagnostics; surfaced in the version string as `crumb=N`).
    static PREV_BOOT_CRUMB: AtomicU8 = AtomicU8::new(0);
    /// Previous boot's heartbeat-iteration count (~50 ms each;
    /// surfaced as `beats=N`).
    static PREV_BOOT_BEATS: AtomicU16 = AtomicU16::new(0);
    /// Raw `RESETREAS` bits captured at this boot (surfaced as `rr=0x…`
    /// so a simultaneous LOCKUP+DOG cannot hide behind the DOG-first
    /// reset-reason mapping).
    static BOOT_RESETREAS: AtomicU32 = AtomicU32::new(0);
    /// Previous boot's watchdog-timeout capture (stacked PC/LR/xPSR of
    /// the code executing ~61 µs before the watchdog reset).
    static PREV_WDT_PC: AtomicU32 = AtomicU32::new(0);
    static PREV_WDT_LR: AtomicU32 = AtomicU32::new(0);
    static PREV_WDT_PSR: AtomicU32 = AtomicU32::new(0);
    /// Previous boot's PC-ring sample count (proves the 1 kHz sampler
    /// ran; surfaced as `rc=N`).
    static PREV_RING_COUNT: AtomicU16 = AtomicU16::new(0);

    /// RAM-only until BLE persistence lands. `u32::MAX` means unset.
    static PAIRING_PIN: AtomicU32 = AtomicU32::new(u32::MAX);
    static BLE_BONDS_AT_BOOT: AtomicU8 = AtomicU8::new(0);
    static BLE_BOND_COUNT: AtomicU8 = AtomicU8::new(0);
    static PAIRING_MODE: AtomicBool = AtomicBool::new(true);
    static PAIRING_LOCKED_OUT: AtomicBool = AtomicBool::new(false);
    static PAIRING_FAILURES: AtomicU8 = AtomicU8::new(0);
    /// Set when the T-1000E user button is held through power-on. This is
    /// deliberately independent of bond count: physical presence opens one
    /// pairing window even when existing bonds are present.
    static FORCE_PAIRING_AT_BOOT: AtomicBool = AtomicBool::new(false);
    #[cfg(feature = "ble-store-fault-inject")]
    static BLE_STORE_FAULT_ARMED: AtomicBool = AtomicBool::new(false);
    static PAIRING_CONFIG_CH: Channel<ThreadModeRawMutex, Option<u32>, 1> = Channel::new();
    static PAIRING_CONFIG_ACK: Signal<ThreadModeRawMutex, bool> = Signal::new();
    static PAIRING_MODE_REQUEST: Signal<ThreadModeRawMutex, ()> = Signal::new();
    static PAIRING_TIMER_RESET: Signal<ThreadModeRawMutex, ()> = Signal::new();
    static BLE_WIPE_REQUEST: Signal<ThreadModeRawMutex, ()> = Signal::new();
    #[cfg(not(feature = "t1000e"))]
    static UI_INPUT_CH: Channel<ThreadModeRawMutex, UiInput, 8> = Channel::new();
    static UI_REFRESH: Signal<ThreadModeRawMutex, ()> = Signal::new();
    static UI_NOTICE: Signal<ThreadModeRawMutex, UiNotice> = Signal::new();
    #[cfg(not(feature = "t1000e"))]
    static DISPLAY_SHUTDOWN: Signal<ThreadModeRawMutex, ()> = Signal::new();
    #[cfg(not(feature = "t1000e"))]
    static DISPLAY_SHUTDOWN_DONE: Signal<ThreadModeRawMutex, ()> = Signal::new();
    /// 0 = normal heartbeat, 1 = pairing mode, 2 = BLE state wiped.
    static BLE_LED_MODE: AtomicU8 = AtomicU8::new(0);

    /// USB protocol attachment suppresses BLE advertising. The signal wakes a
    /// pending advertiser/connection so it can apply the atomic policy.
    static ADV_ALLOWED: AtomicBool = AtomicBool::new(true);
    static ADV_POLICY_CHANGED: Signal<ThreadModeRawMutex, ()> = Signal::new();

    #[cfg(feature = "ble-debug")]
    type DebugLine = heapless::String<192>;
    #[cfg(feature = "ble-debug")]
    static DEBUG_CH: Channel<ThreadModeRawMutex, DebugLine, 32> = Channel::new();
    #[cfg(feature = "ble-debug")]
    static DEBUG_DROPPED: AtomicU32 = AtomicU32::new(0);

    fn debug_log(args: core::fmt::Arguments<'_>) {
        #[cfg(feature = "ble-debug")]
        {
            let mut line = DebugLine::new();
            let dropped = DEBUG_DROPPED.swap(0, Ordering::AcqRel);
            if write!(line, "[{:>8} ms] ", Instant::now().as_millis()).is_err()
                || (dropped != 0 && write!(line, "[debug-dropped={dropped}] ").is_err())
                || line.write_fmt(args).is_err()
                || line.push_str("\r\n").is_err()
            {
                DEBUG_DROPPED.fetch_add(dropped.saturating_add(1), Ordering::AcqRel);
                return;
            }
            if DEBUG_CH.try_send(line).is_err() {
                DEBUG_DROPPED.fetch_add(dropped.saturating_add(1), Ordering::AcqRel);
            }
        }
        #[cfg(not(feature = "ble-debug"))]
        let _ = args;
    }

    #[cfg(feature = "ble-debug")]
    fn trouble_security_trace(event: SecurityTrace) {
        debug_log(format_args!(
            "smp {:?} opcode=0x{:02x} detail={:02x?}",
            event.direction,
            event.command,
            &event.detail[..usize::from(event.detail_len)],
        ));
    }

    #[cfg(feature = "ble-debug")]
    fn trouble_connection_trace(event: ConnectionTrace) {
        debug_log(format_args!("trouble connection {event:?}"));
    }

    #[cfg(feature = "ble-debug")]
    fn trouble_security_diagnostic_trace(event: SecurityDiagnosticTrace) {
        debug_log(format_args!("trouble security {event:?}"));
    }

    /// Fired by button_task on a 2 s hold; consumed by shutdown_task.
    #[cfg(not(feature = "t1000e"))]
    static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    // ─── Outgoing frame staging ──────────────────────────────────────────────

    /// Largest companion frame the session emits (CMD_STR_RECV around a
    /// full-MTU payload).
    const FRAME_OUT_MAX: usize = 300;
    const WIRE_MAX: usize = hdlc::max_encoded_len(300);

    /// Collects frames emitted synchronously by the session, then
    /// flushes them to OUT_USB_CH asynchronously. The session emits at
    /// most one frame per call; two slots give headroom.
    struct Emitter {
        bufs: [[u8; FRAME_OUT_MAX]; 2],
        lens: [usize; 2],
        count: usize,
    }

    impl Emitter {
        const fn new() -> Self {
            Self {
                bufs: [[0; FRAME_OUT_MAX]; 2],
                lens: [0; 2],
                count: 0,
            }
        }

        /// Copy one raw companion frame into the next slot.
        ///
        /// The session is expected to emit at most `bufs.len()` frames per call
        /// and every frame is expected to fit `FRAME_OUT_MAX`. Both invariants are
        /// asserted in debug builds so a future session change that violates
        /// them is caught rather than silently dropping a response.
        fn push(&mut self, frame: &[u8]) {
            if self.count >= self.bufs.len() {
                debug_assert!(
                    false,
                    "Emitter overflow: session emitted more frames per call than staging slots"
                );
                return;
            }
            if frame.len() <= FRAME_OUT_MAX {
                self.bufs[self.count][..frame.len()].copy_from_slice(frame);
                self.lens[self.count] = frame.len();
                self.count += 1;
            } else {
                debug_assert!(false, "Emitter: companion frame exceeds FRAME_OUT_MAX");
            }
        }

        /// Queue all staged frames for the active transport output task.
        async fn flush(&mut self, destination: Option<(Transport, u32)>) {
            if let Some((transport, generation)) = destination {
                for index in 0..self.count {
                    let mut frame: FrameBuf = heapless::Vec::new();
                    if frame
                        .extend_from_slice(&self.bufs[index][..self.lens[index]])
                        .is_err()
                    {
                        debug_log(format_args!(
                            "emitter frame copy=FAILED index={} len={}",
                            index, self.lens[index]
                        ));
                        continue;
                    }
                    let outbound = OutFrame { generation, frame };
                    match transport {
                        Transport::Usb => OUT_USB_CH.send(outbound).await,
                        Transport::Ble => OUT_BLE_CH.send(outbound).await,
                    }
                }
            }
            self.count = 0;
        }
    }

    fn set_advertising_allowed(allowed: bool) {
        let previous = ADV_ALLOWED.swap(allowed, Ordering::AcqRel);
        debug_log(format_args!(
            "advertising policy set previous={} allowed={} changed={}",
            previous,
            allowed,
            previous != allowed,
        ));
        ADV_POLICY_CHANGED.signal(());
    }

    fn apply_pairing_gate<C: Controller, P: PacketPool>(stack: &Stack<'_, C, P>) {
        let pin_configured = PAIRING_PIN.load(Ordering::Acquire) != u32::MAX;
        let bonds = usize::from(BLE_BOND_COUNT.load(Ordering::Acquire));
        let enabled = pairing_enabled(
            PAIRING_MODE.load(Ordering::Acquire),
            pin_configured,
            PAIRING_LOCKED_OUT.load(Ordering::Acquire),
            bonds,
            ble_store::MAX_BONDS,
        );
        stack.set_pairing_enabled(enabled);
        debug_log(format_args!(
            "pairing gate enabled={} mode={} pin={} locked={} failures={} bonds={}/{}",
            enabled,
            PAIRING_MODE.load(Ordering::Acquire),
            pin_configured,
            PAIRING_LOCKED_OUT.load(Ordering::Acquire),
            PAIRING_FAILURES.load(Ordering::Acquire),
            bonds,
            ble_store::MAX_BONDS,
        ));
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
        UI_REFRESH.signal(());
    }

    async fn persist_bond(store: &BleStoreMutex, bond: &BondInformation) -> Result<usize, ()> {
        let mut store = store.lock().await;
        store.add_bond(bond).await?;
        Ok(store.snapshot().bonds.len())
    }

    fn build_sdc<'d, const N: usize>(
        p: sdc::Peripherals<'d>,
        rng: &'d mut rng::Rng<Async>,
        mpsl: &'d MultiprotocolServiceLayer,
        mem: &'d mut sdc::Mem<N>,
    ) -> Result<sdc::SoftdeviceController<'d>, sdc::Error> {
        sdc::Builder::new()?
            .support_adv()
            .support_peripheral()
            .peripheral_count(1)?
            .buffer_cfg(
                SDC_PACKET_SIZE,
                SDC_PACKET_SIZE,
                BLE_L2CAP_TXQ,
                BLE_L2CAP_RXQ,
            )?
            .build(p, rng, mpsl, mem)
    }

    /// Execute a radio side effect requested by the session.
    async fn apply_effect(session: &Session, effect: Option<Effect>) {
        match effect {
            Some(Effect::ApplyRadio(settings)) => {
                publish_device_name(session).await;
                // The session validates values against the same discrete
                // sets these converters accept, so None here is
                // unreachable; bail out defensively rather than panic.
                let (Some(sf), Some(bw), Some(cr)) = (
                    spreading_factor_from_u8(settings.sf),
                    bandwidth_from_hz(settings.bw_hz),
                    coding_rate_from_denom(settings.cr_denom),
                ) else {
                    return;
                };
                NCP_CTL.apply(NcpSettings {
                    enabled: settings.enabled,
                    freq_hz: settings.freq_khz.saturating_mul(1_000),
                    sf,
                    bw,
                    cr,
                    power_dbm: i32::from(settings.tx_power_dbm),
                });
            }
            Some(Effect::StartTransmit) => {
                let mut data: heapless::Vec<u8, MAX_PAYLOAD> = heapless::Vec::new();
                if data.extend_from_slice(session.tx_data()).is_err() {
                    debug_log(format_args!(
                        "radio tx staging=FAILED len={}",
                        session.tx_data().len()
                    ));
                    return;
                }
                let power_dbm = match session.tx_power() {
                    TxPower::Default => None,
                    TxPower::Max => Some(i32::from(MAX_TX_POWER_DBM)),
                    TxPower::Dbm(dbm) => Some(i32::from(dbm)),
                };
                RADIO_CH.tx.send(TxRequest { data, power_dbm }).await;
            }
            Some(Effect::DeviceNameChanged) => publish_device_name(session).await,
            // Deferred effects needing `&mut Session` + the emitter are
            // handled inline in ncp_task rather than here.
            Some(Effect::SampleRssi { .. })
            | Some(Effect::SetPairingPin { .. })
            | Some(Effect::WipeHostDomain { .. })
            | Some(Effect::DrainQueue)
            | Some(Effect::SaveSnapshot { .. })
            | Some(Effect::ClearSaved { .. })
            | Some(Effect::ProvisionIdentity { .. })
            | None => {}
        }
    }

    async fn publish_device_name(session: &Session) {
        let bytes = session.device_name().as_bytes();
        let mut current = DEVICE_NAME.lock().await;
        if current.as_slice() == bytes {
            return;
        }
        current.clear();
        if current.extend_from_slice(bytes).is_ok() {
            DEVICE_NAME_CHANGED.signal(());
        }
    }

    // ─── Tasks ───────────────────────────────────────────────────────────────

    #[embassy_executor::task]
    async fn mpsl_task(mpsl: &'static MultiprotocolServiceLayer<'static>) -> ! {
        mpsl.run().await
    }

    async fn ble_runner<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) -> ! {
        loop {
            match runner.run().await {
                Ok(()) => debug_log(format_args!("ble runner exited cleanly")),
                Err(error) => debug_log(format_args!("ble runner error={error:?}")),
            }
        }
    }

    async fn pairing_timeout<C: Controller, P: PacketPool>(stack: &Stack<'_, C, P>) -> ! {
        loop {
            match select(Timer::after_secs(30), PAIRING_TIMER_RESET.wait()).await {
                Either::First(()) => {
                    debug_log(format_args!("pairing window expired"));
                    PAIRING_MODE.store(false, Ordering::Release);
                    BLE_LED_MODE.store(0, Ordering::Release);
                    UI_REFRESH.signal(());
                    apply_pairing_gate(stack);
                }
                Either::Second(()) => debug_log(format_args!("pairing timer reset")),
            }
        }
    }

    async fn pairing_config_task<C: Controller, P: PacketPool>(
        stack: &Stack<'_, C, P>,
        store: &BleStoreMutex,
    ) -> ! {
        loop {
            match select3(
                PAIRING_CONFIG_CH.receive(),
                PAIRING_MODE_REQUEST.wait(),
                BLE_WIPE_REQUEST.wait(),
            )
            .await
            {
                Either3::First(pin) => {
                    debug_log(format_args!(
                        "pin config begin configured={}",
                        pin.is_some()
                    ));
                    let persisted = match store.lock().await.set_pin(pin).await {
                        Ok(()) => {
                            debug_log(format_args!("pin config persist=ok"));
                            true
                        }
                        Err(()) => {
                            debug_log(format_args!("pin config persist=FAILED"));
                            false
                        }
                    };
                    let applied = if persisted {
                        match stack.set_fixed_passkey(pin) {
                            Ok(()) => {
                                debug_log(format_args!("pin config trouble-passkey=ok"));
                                true
                            }
                            Err(error) => {
                                debug_log(format_args!(
                                    "pin config trouble-passkey=FAILED error={error:?}"
                                ));
                                false
                            }
                        }
                    } else {
                        debug_log(format_args!("pin config trouble-passkey=skipped"));
                        false
                    };
                    let result = persisted && applied;
                    if result {
                        stack.set_io_capabilities(if pin.is_some() {
                            IoCapabilities::DisplayOnly
                        } else {
                            IoCapabilities::NoInputNoOutput
                        });
                        PAIRING_PIN.store(pin.unwrap_or(u32::MAX), Ordering::Release);
                        apply_pairing_gate(stack);
                    }
                    debug_log(format_args!(
                        "pin config requested={} persisted={} applied={}",
                        pin.is_some(),
                        persisted,
                        result,
                    ));
                    PAIRING_CONFIG_ACK.signal(result);
                }
                Either3::Second(()) => {
                    debug_log(format_args!("pairing mode requested"));
                    PAIRING_MODE.store(true, Ordering::Release);
                    BLE_LED_MODE.store(1, Ordering::Release);
                    let unavailable = PAIRING_LOCKED_OUT.load(Ordering::Acquire)
                        || usize::from(BLE_BOND_COUNT.load(Ordering::Acquire))
                            >= ble_store::MAX_BONDS;
                    UI_NOTICE.signal(if unavailable {
                        UiNotice::PairingUnavailable
                    } else {
                        UiNotice::PairingStarted
                    });
                    PAIRING_TIMER_RESET.signal(());
                    apply_pairing_gate(stack);
                }
                Either3::Third(()) => {
                    debug_log(format_args!("security wipe requested"));
                    if store.lock().await.clear_security().await.is_ok() {
                        debug_log(format_args!("security wipe flash=ok"));
                        BLE_BOND_COUNT.store(0, Ordering::Release);
                        let mut identities: heapless::Vec<Identity, { ble_store::MAX_BONDS }> =
                            heapless::Vec::new();
                        stack.with_bond_information(|bonds| {
                            for bond in bonds {
                                if identities.push(bond.identity).is_err() {
                                    debug_log(format_args!("security wipe identity-list=FULL"));
                                }
                            }
                        });
                        debug_log(format_args!(
                            "security wipe removing-bonds count={}",
                            identities.len()
                        ));
                        for identity in identities {
                            match stack.remove_bond_information(identity) {
                                Ok(()) => debug_log(format_args!("security wipe remove-bond=ok")),
                                Err(error) => debug_log(format_args!(
                                    "security wipe remove-bond=FAILED error={error:?}"
                                )),
                            }
                        }
                        match stack.set_fixed_passkey(None) {
                            Ok(()) => debug_log(format_args!("security wipe clear-passkey=ok")),
                            Err(error) => debug_log(format_args!(
                                "security wipe clear-passkey=FAILED error={error:?}"
                            )),
                        }
                        stack.set_io_capabilities(IoCapabilities::NoInputNoOutput);
                        PAIRING_PIN.store(u32::MAX, Ordering::Release);
                        PAIRING_FAILURES.store(0, Ordering::Release);
                        PAIRING_LOCKED_OUT.store(false, Ordering::Release);
                        PAIRING_MODE.store(true, Ordering::Release);
                        BLE_LED_MODE.store(2, Ordering::Release);
                        PAIRING_TIMER_RESET.signal(());
                        apply_pairing_gate(stack);
                        debug_log(format_args!("security wipe complete"));
                        UI_NOTICE.signal(UiNotice::BondsCleared);
                    } else {
                        debug_log(format_args!("security wipe flash=FAILED"));
                        UI_NOTICE.signal(UiNotice::ClearFailed);
                    }
                }
            }
        }
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

    async fn advertise<'values, 'server, C: Controller>(
        peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
        server: &'server CompanionServer<'values>,
    ) -> Result<GattConnection<'values, 'server, DefaultPacketPool>, BleHostError<C::Error>> {
        const SERVICE_UUID_LE: [u8; 16] = gatt::SERVICE_UUID.to_le_bytes();
        let name = {
            let configured = DEVICE_NAME.lock().await;
            if configured.is_empty() {
                DeviceName::from_slice(DEFAULT_DEVICE_NAME.as_bytes()).expect("default name fits")
            } else {
                configured.clone()
            }
        };
        let adv_name_len = utf8_prefix_len(name.as_slice(), 8);
        let mut adv_data = [0u8; 31];
        let adv_len = AdStructure::encode_slice(
            &[
                AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                AdStructure::CompleteServiceUuids128(&[SERVICE_UUID_LE]),
                AdStructure::ShortenedLocalName(&name[..adv_name_len]),
            ],
            &mut adv_data,
        )?;
        let scan_name_len = utf8_prefix_len(name.as_slice(), 29);
        let scan_name = if scan_name_len == name.len() {
            AdStructure::CompleteLocalName(&name[..scan_name_len])
        } else {
            AdStructure::ShortenedLocalName(&name[..scan_name_len])
        };
        let mut scan_data = [0u8; 31];
        let scan_len = AdStructure::encode_slice(&[scan_name], &mut scan_data)?;
        debug_log(format_args!(
            "advertising start adv-bytes={} scan-bytes={}",
            adv_len, scan_len
        ));
        let advertiser = peripheral
            .advertise(
                &Default::default(),
                Advertisement::ConnectableScannableUndirected {
                    adv_data: &adv_data[..adv_len],
                    scan_data: &scan_data[..scan_len],
                },
            )
            .await?;
        debug_log(format_args!("advertising controller-active"));
        let raw_connection = advertiser.accept().await?;
        debug_log(format_args!("advertising raw-connection accepted"));
        let connection = raw_connection.with_attribute_server(server)?;
        debug_log(format_args!("advertising gatt-server attached"));
        Ok(connection)
    }

    fn utf8_prefix_len(bytes: &[u8], maximum: usize) -> usize {
        let text = core::str::from_utf8(bytes).expect("validated device name");
        let mut len = bytes.len().min(maximum);
        while !text.is_char_boundary(len) {
            len -= 1;
        }
        len
    }

    async fn send_ble_frame(
        server: &CompanionServer<'_>,
        conn: &GattConnection<'_, '_, DefaultPacketPool>,
        outbound: OutFrame,
    ) -> Result<(), trouble_host::Error> {
        if SESSION_GEN.load(Ordering::Acquire) != outbound.generation {
            debug_log(format_args!(
                "ble outbound dropped stale-generation frame-gen={} active-gen={}",
                outbound.generation,
                SESSION_GEN.load(Ordering::Acquire),
            ));
            return Ok(());
        }
        let segment_payload = usize::from(conn.raw().att_mtu())
            .saturating_sub(4)
            .clamp(1, BLE_VALUE_MAX - 1);
        let mut segments = generation_checked(
            gatt::segments(&outbound.frame, segment_payload),
            outbound.generation,
            || SESSION_GEN.load(Ordering::Acquire),
        );
        for segment in segments.by_ref() {
            let mut value: heapless09::Vec<u8, BLE_VALUE_MAX> = heapless09::Vec::new();
            value
                .push(segment.header())
                .map_err(|_| trouble_host::Error::InsufficientSpace)?;
            value
                .extend_from_slice(segment.payload())
                .map_err(|_| trouble_host::Error::InsufficientSpace)?;
            server
                .companion
                .frame_out
                .notify(conn, &value, false)
                .await?;
        }
        if segments.stale() {
            debug_log(format_args!(
                "ble outbound segmentation stopped generation-changed"
            ));
        }
        Ok(())
    }

    async fn gatt_connection<C: Controller, P: PacketPool>(
        stack: &Stack<'_, C, P>,
        store: &BleStoreMutex,
        server: &CompanionServer<'_>,
        conn: &GattConnection<'_, '_, DefaultPacketPool>,
    ) -> Result<(), trouble_host::Error> {
        match conn.raw().set_bondable(true) {
            Ok(()) => debug_log(format_args!("connection set-bondable=ok")),
            Err(error) => {
                debug_log(format_args!(
                    "connection set-bondable=FAILED error={error:?}"
                ));
                return Err(error);
            }
        }
        let peer = conn.raw().peer_identity();
        debug_log(format_args!(
            "connected peer={} kind={} irk={} table_match={} level={:?} mtu={}",
            peer.addr,
            peer.addr.to_bytes()[0],
            peer.irk.is_some(),
            conn.raw().is_bonded_peer(),
            conn.raw().security_level(),
            conn.raw().att_mtu(),
        ));
        let mut attached = false;
        let mut reassembler: gatt::Reassembler<{ gatt::MAX_FRAME }> = gatt::Reassembler::new();

        loop {
            match select3(conn.next(), OUT_BLE_CH.receive(), ADV_POLICY_CHANGED.wait()).await {
                Either3::First(GattConnectionEvent::Disconnected { reason }) => {
                    debug_log(format_args!("disconnected reason={reason:?}"));
                    break;
                }
                Either3::First(GattConnectionEvent::PairingComplete { bond, .. }) => {
                    debug_log(format_args!(
                        "pairing-complete bond={} table_match={}",
                        bond.is_some(),
                        conn.raw().is_bonded_peer(),
                    ));
                    if let Some(bond) = bond {
                        if !bond_identity_is_persistable(&bond) {
                            debug_log(format_args!("pairing bond identity=incomplete"));
                            match stack.remove_bond_information(bond.identity) {
                                Ok(()) => {
                                    debug_log(format_args!("pairing incomplete bond remove=ok"))
                                }
                                Err(error) => debug_log(format_args!(
                                    "pairing incomplete bond remove=FAILED error={error:?}"
                                )),
                            }
                            debug_log(format_args!(
                                "disconnect initiated by incomplete pairing identity"
                            ));
                            conn.raw().disconnect();
                            break;
                        }
                        let persisted_bonds = match persist_bond(store, &bond).await {
                            Ok(count) => count,
                            Err(()) => {
                                debug_log(format_args!("pairing bond persist=FAILED"));
                                match stack.remove_bond_information(bond.identity) {
                                    Ok(()) => debug_log(format_args!(
                                        "pairing unpersisted bond remove=ok"
                                    )),
                                    Err(error) => debug_log(format_args!(
                                        "pairing unpersisted bond remove=FAILED error={error:?}"
                                    )),
                                }
                                debug_log(format_args!(
                                    "disconnect initiated by pairing persistence failure"
                                ));
                                conn.raw().disconnect();
                                break;
                            }
                        };
                        BLE_BOND_COUNT.store(persisted_bonds as u8, Ordering::Release);
                        UI_REFRESH.signal(());
                        debug_log(format_args!(
                            "pairing bond persist=ok peer={} kind={} irk={} bonded={} level={:?}",
                            bond.identity.addr,
                            bond.identity.addr.to_bytes()[0],
                            bond.identity.irk.is_some(),
                            bond.is_bonded,
                            bond.security_level,
                        ));
                    }
                    // Trouble may report a successful peripheral pairing with
                    // bond=None and expose the completed bond at the first
                    // protected GATT edge. Pairing success still resets the
                    // failure counter and closes the window in that case.
                    publish_pairing_runtime(pairing_runtime().pairing_succeeded());
                    BLE_LED_MODE.store(0, Ordering::Release);
                    apply_pairing_gate(stack);
                }
                Either3::First(GattConnectionEvent::PassKeyDisplay(_)) => {
                    debug_log(format_args!("passkey display requested"));
                }
                Either3::First(GattConnectionEvent::PassKeyConfirm(_)) => {
                    debug_log(format_args!("passkey confirmation requested"));
                }
                Either3::First(GattConnectionEvent::PassKeyInput) => {
                    debug_log(format_args!("passkey input requested"));
                }
                Either3::First(GattConnectionEvent::BondLost) => {
                    debug_log(format_args!("bond lost event"));
                }
                Either3::First(GattConnectionEvent::OobRequest) => {
                    debug_log(format_args!("oob requested"));
                }
                Either3::First(GattConnectionEvent::Encrypted { bond, .. }) => {
                    debug_log(format_args!(
                        "encrypted event_bond={} table_match={} level={:?}",
                        bond.is_some(),
                        conn.raw().is_bonded_peer(),
                        conn.raw().security_level(),
                    ));
                    if bond.is_some() || conn.raw().is_bonded_peer() {
                        publish_pairing_runtime(pairing_runtime().bonded_reconnect());
                        BLE_LED_MODE.store(0, Ordering::Release);
                        apply_pairing_gate(stack);
                    }
                }
                Either3::First(GattConnectionEvent::PairingFailed(error)) => {
                    debug_log(format_args!("pairing-failed error={error:?}"));
                    let failure = classify_pairing_failure(&error);
                    if failure.counts_toward_lockout() {
                        let before = pairing_runtime();
                        let after = before.record_failure(failure);
                        publish_pairing_runtime(after);
                        debug_log(format_args!(
                            "pairing authentication-failures={} locked={}",
                            after.failures, after.locked_out,
                        ));
                        if after.locked_out && !before.locked_out {
                            apply_pairing_gate(stack);
                        }
                    }
                }
                Either3::First(GattConnectionEvent::Gatt { event }) => {
                    match &event {
                        GattEvent::Read(read) => debug_log(format_args!(
                            "gatt read handle=0x{:04x} level={:?}",
                            read.handle(),
                            conn.raw().security_level(),
                        )),
                        GattEvent::Write(write) => debug_log(format_args!(
                            "gatt write handle=0x{:04x} level={:?}",
                            write.handle(),
                            conn.raw().security_level(),
                        )),
                        GattEvent::NotAllowed(event) => debug_log(format_args!(
                            "gatt not-allowed handle=0x{:04x} level={:?}",
                            event.handle(),
                            conn.raw().security_level(),
                        )),
                        GattEvent::Other(event) => debug_log(format_args!(
                            "gatt other handle={:?} level={:?}",
                            event.payload().handle(),
                            conn.raw().security_level(),
                        )),
                    }
                    let frame_in = matches!(&event, GattEvent::Write(write) if write.handle() == server.companion.frame_in.handle);
                    let cccd = matches!(&event, GattEvent::Write(write) if Some(write.handle()) == server.companion.frame_out.cccd_handle);
                    let protected = frame_in || cccd;
                    let bonded = conn.raw().is_bonded_peer();
                    let mut bond_persist_failed = false;
                    // PairingComplete is not guaranteed to carry the newly-created bond on
                    // every peripheral path.  The protected GATT edge is authoritative: if
                    // Trouble says this peer is bonded, find that exact live-table entry and
                    // make it durable before granting access.  add_bond is idempotent, so
                    // subsequent frames do not write flash.
                    let durable_bond = if protected && bonded {
                        let peer = conn.raw().peer_identity();
                        let bond = stack.with_bond_information(|bonds| {
                            bonds
                                .iter()
                                .find(|bond| bond.identity.match_identity(&peer))
                                .cloned()
                        });
                        match bond {
                            Some(bond) if !bond_identity_is_persistable(&bond) => {
                                debug_log(format_args!("protected bond identity=pending"));
                                false
                            }
                            Some(bond) => match persist_bond(store, &bond).await {
                                Ok(count) => {
                                    debug_log(format_args!("protected bond persist=ok"));
                                    BLE_BOND_COUNT.store(count as u8, Ordering::Release);
                                    UI_REFRESH.signal(());
                                    apply_pairing_gate(stack);
                                    true
                                }
                                Err(()) => {
                                    debug_log(format_args!("protected bond persist=FAILED"));
                                    bond_persist_failed = true;
                                    match stack.remove_bond_information(bond.identity) {
                                        Ok(()) => debug_log(format_args!(
                                            "protected unpersisted bond remove=ok"
                                        )),
                                        Err(error) => debug_log(format_args!(
                                            "protected unpersisted bond remove=FAILED error={error:?}"
                                        )),
                                    }
                                    false
                                }
                            },
                            None => {
                                debug_log(format_args!("protected bond lookup=missing"));
                                false
                            }
                        }
                    } else {
                        !protected
                    };
                    if protected {
                        let peer = conn.raw().peer_identity();
                        debug_log(format_args!(
                            "gatt protected={} bonded={} durable={} peer={} kind={} irk={} level={:?}",
                            if cccd { "cccd" } else { "frame-in" },
                            bonded,
                            durable_bond,
                            peer.addr,
                            peer.addr.to_bytes()[0],
                            peer.irk.is_some(),
                            conn.raw().security_level(),
                        ));
                    }
                    let mut inbound: heapless09::Vec<u8, BLE_VALUE_MAX> = heapless09::Vec::new();
                    if frame_in {
                        if let GattEvent::Write(write) = &event {
                            write.with_data(|_, data| {
                                if inbound.extend_from_slice(data).is_err() {
                                    debug_log(format_args!(
                                        "gatt frame-in staging=FAILED len={}",
                                        data.len()
                                    ));
                                }
                            });
                        }
                    }

                    let server_permission_denied = matches!(&event, GattEvent::NotAllowed(_));
                    let reply = if protected && !(bonded && durable_bond) {
                        debug_log(format_args!(
                            "gatt decision=reject insufficient-authentication"
                        ));
                        event.reject(AttErrorCode::INSUFFICIENT_AUTHENTICATION)
                    } else if server_permission_denied {
                        // `NotAllowedEvent::accept()` preserves and returns the
                        // attribute server's permission error; it does not grant
                        // the operation. Make that non-obvious Trouble API
                        // behavior explicit in the hardware trace.
                        debug_log(format_args!("gatt decision=return-server-permission-error"));
                        event.accept()
                    } else {
                        debug_log(format_args!("gatt decision=accept"));
                        event.accept()
                    }?;
                    reply.send().await;

                    if protected && bonded && !durable_bond && bond_persist_failed {
                        debug_log(format_args!(
                            "disconnect initiated by protected bond persistence failure"
                        ));
                        conn.raw().disconnect();
                        break;
                    }

                    if frame_in && bonded {
                        match reassembler.push(&inbound) {
                            Some(Ok(frame)) => {
                                let mut value: FrameBuf = heapless::Vec::new();
                                match value.extend_from_slice(frame) {
                                    Ok(()) => {
                                        debug_log(format_args!(
                                            "gatt frame-in complete len={}",
                                            frame.len()
                                        ));
                                        INPUT_CH.send(InEvent::Frame(Transport::Ble, value)).await;
                                    }
                                    Err(()) => debug_log(format_args!(
                                        "gatt frame-in complete staging=FAILED len={}",
                                        frame.len()
                                    )),
                                }
                            }
                            Some(Err(error)) => debug_log(format_args!(
                                "gatt frame-in decode=FAILED error={error:?} segment-len={}",
                                inbound.len()
                            )),
                            None => debug_log(format_args!(
                                "gatt frame-in segment accepted segment-len={} complete=false",
                                inbound.len()
                            )),
                        }
                    }
                    if cccd && bonded {
                        let subscribed = server.companion.frame_out.should_notify(conn);
                        match (attached, subscribed) {
                            (false, true) => {
                                debug_log(format_args!("cccd subscribed=true"));
                                attached = true;
                                INPUT_CH.send(InEvent::Attached(Transport::Ble)).await;
                            }
                            (true, false) => {
                                debug_log(format_args!("cccd subscribed=false"));
                                attached = false;
                                reassembler.reset();
                                INPUT_CH.send(InEvent::Detached(Transport::Ble)).await;
                            }
                            (false, false) => debug_log(format_args!(
                                "cccd state unchanged attached=false subscribed=false"
                            )),
                            (true, true) => debug_log(format_args!(
                                "cccd state unchanged attached=true subscribed=true"
                            )),
                        }
                    }
                }
                Either3::First(GattConnectionEvent::PhyUpdated { tx_phy, rx_phy }) => {
                    debug_log(format_args!(
                        "connection phy-updated tx={tx_phy:?} rx={rx_phy:?}"
                    ));
                }
                Either3::First(GattConnectionEvent::ConnectionParamsUpdated {
                    conn_interval,
                    peripheral_latency,
                    supervision_timeout,
                }) => {
                    debug_log(format_args!(
                        "connection params-updated interval-us={} latency={} timeout-us={}",
                        conn_interval.as_micros(),
                        peripheral_latency,
                        supervision_timeout.as_micros(),
                    ));
                }
                Either3::First(GattConnectionEvent::RequestConnectionParams(request)) => {
                    debug_log(format_args!(
                        "connection params-requested params={:?}",
                        request.params()
                    ));
                    match request.accept(None, stack).await {
                        Ok(()) => debug_log(format_args!("connection params-response=accepted")),
                        Err(error) => debug_log(format_args!(
                            "connection params-response=FAILED error={error:?}"
                        )),
                    }
                }
                Either3::First(GattConnectionEvent::DataLengthUpdated {
                    max_tx_octets,
                    max_tx_time,
                    max_rx_octets,
                    max_rx_time,
                }) => debug_log(format_args!(
                    "connection data-length tx-octets={} tx-time={} rx-octets={} rx-time={}",
                    max_tx_octets, max_tx_time, max_rx_octets, max_rx_time,
                )),
                Either3::First(GattConnectionEvent::FrameSpaceUpdated {
                    frame_space,
                    initiator,
                    phys,
                    spacing_types,
                }) => debug_log(format_args!(
                    "connection frame-space us={} initiator={initiator:?} phys={phys:?} spacing={spacing_types:?}",
                    frame_space.as_micros(),
                )),
                Either3::First(GattConnectionEvent::ConnectionRateChanged {
                    conn_interval,
                    subrate_factor,
                    peripheral_latency,
                    continuation_number,
                    supervision_timeout,
                }) => debug_log(format_args!(
                    "connection rate-changed interval-us={} subrate={} latency={} continuation={} timeout-us={}",
                    conn_interval.as_micros(),
                    subrate_factor,
                    peripheral_latency,
                    continuation_number,
                    supervision_timeout.as_micros(),
                )),
                Either3::Second(outbound) => {
                    if attached && conn.raw().is_bonded_peer() {
                        send_ble_frame(server, conn, outbound).await?;
                    } else {
                        debug_log(format_args!(
                            "ble outbound dropped attached={} bonded={} level={:?}",
                            attached,
                            conn.raw().is_bonded_peer(),
                            conn.raw().security_level(),
                        ));
                    }
                }
                Either3::Third(()) => {
                    if !ADV_ALLOWED.load(Ordering::Acquire) {
                        debug_log(format_args!(
                            "disconnect initiated by transport arbitration"
                        ));
                        conn.raw().disconnect();
                        break;
                    }
                }
            }
        }
        if attached {
            INPUT_CH.send(InEvent::Detached(Transport::Ble)).await;
        }
        Ok(())
    }

    async fn ble_peripheral<'values, C: Controller>(
        stack: &Stack<'_, C, DefaultPacketPool>,
        store: &BleStoreMutex,
        peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
        server: &CompanionServer<'values>,
    ) -> ! {
        loop {
            if !ADV_ALLOWED.load(Ordering::Acquire) {
                ADV_POLICY_CHANGED.wait().await;
                continue;
            }
            super::panic::breadcrumb_mark(12);
            match select3(
                advertise(peripheral, server),
                ADV_POLICY_CHANGED.wait(),
                DEVICE_NAME_CHANGED.wait(),
            )
            .await
            {
                Either3::First(Ok(connection)) => {
                    match gatt_connection(stack, store, server, &connection).await {
                        Ok(()) => debug_log(format_args!("gatt connection task ended ok")),
                        Err(error) => {
                            debug_log(format_args!("gatt connection task error={error:?}"))
                        }
                    }
                }
                Either3::First(Err(error)) => {
                    debug_log(format_args!("advertising error={error:?}"))
                }
                Either3::Second(()) => debug_log(format_args!("advertising policy changed")),
                Either3::Third(()) => debug_log(format_args!("advertising device name changed")),
            }
        }
    }

    async fn ble_app<C: Controller>(controller: C, store: BleStore) -> ! {
        super::panic::breadcrumb_mark(10);
        let mut resources: HostResources<
            _,
            DefaultPacketPool,
            BLE_CONNECTIONS_MAX,
            BLE_L2CAP_CHANNELS_MAX,
        > = HostResources::new();
        let initial = store.snapshot().clone();
        debug_log(format_args!(
            "ble boot identity={} bonds={} pin={} local_irk={} privacy=false",
            ble_identity_address(),
            initial.bonds.len(),
            initial.pin.is_some(),
            initial.local_irk.is_some(),
        ));
        for bond in &initial.bonds {
            debug_log(format_args!(
                "restored bond peer-kind={} peer={:02x?} irk={} bonded={} level={}",
                bond.address_kind,
                bond.address,
                bond.irk.is_some(),
                bond.is_bonded,
                bond.security_level,
            ));
        }
        PAIRING_PIN.store(initial.pin.unwrap_or(u32::MAX), Ordering::Release);
        BLE_BOND_COUNT.store(initial.bonds.len() as u8, Ordering::Release);
        let initial_pairing_mode =
            initial.bonds.is_empty() || FORCE_PAIRING_AT_BOOT.load(Ordering::Acquire);
        PAIRING_MODE.store(initial_pairing_mode, Ordering::Release);
        BLE_LED_MODE.store(u8::from(initial_pairing_mode), Ordering::Release);
        UI_REFRESH.signal(());
        let io_capabilities = if initial.pin.is_some() {
            IoCapabilities::DisplayOnly
        } else {
            IoCapabilities::NoInputNoOutput
        };
        let initial_pairing_enabled = pairing_enabled(
            initial_pairing_mode,
            initial.pin.is_some(),
            false,
            initial.bonds.len(),
            ble_store::MAX_BONDS,
        );
        debug_log(format_args!(
            "ble stack configure io={io_capabilities:?} pairing-enabled={} fixed-passkey={}",
            initial_pairing_enabled,
            initial.pin.is_some(),
        ));
        let stack_builder = trouble_host::new(controller, &mut resources)
            .set_random_address(ble_identity_address())
            .set_io_capabilities(io_capabilities)
            .set_pairing_enabled(initial_pairing_enabled)
            .set_fixed_passkey(initial.pin);
        let stack = match stack_builder {
            Ok(builder) => {
                debug_log(format_args!("ble stack fixed-passkey configure=ok"));
                builder.build()
            }
            Err(error) => {
                debug_log(format_args!(
                    "ble stack fixed-passkey configure=FAILED error={error:?}"
                ));
                panic!("invalid fixed passkey")
            }
        };
        for (index, bond) in initial.bonds.iter().enumerate() {
            if let Some(bond) = trouble_bond(bond) {
                match stack.add_bond_information(bond) {
                    Ok(()) => debug_log(format_args!("restored bond index={index} add=ok")),
                    Err(error) => debug_log(format_args!(
                        "restored bond index={index} add=FAILED error={error:?}"
                    )),
                }
            } else {
                debug_log(format_args!("restored bond index={index} decode=FAILED"));
            }
        }
        let store = BleStoreMutex::new(store);
        let runner = stack.runner();
        let mut peripheral = stack.peripheral();
        let server_result =
            CompanionServer::new_with_config(GapConfig::Peripheral(PeripheralConfig {
                name: DEFAULT_DEVICE_NAME,
                appearance: &appearance::computer::GENERIC_COMPUTER,
            }));
        let server = match server_result {
            Ok(server) => {
                debug_log(format_args!("gatt server construction=ok"));
                server
            }
            Err(error) => {
                debug_log(format_args!(
                    "gatt server construction=FAILED error={error:?}"
                ));
                panic!("gatt server construction failed")
            }
        };

        super::panic::breadcrumb_mark(11);
        join(
            ble_runner(runner),
            join(
                pairing_timeout(&stack),
                join(
                    pairing_config_task(&stack, &store),
                    ble_peripheral(&stack, &store, &mut peripheral, &server),
                ),
            ),
        )
        .await;
        unreachable!()
    }

    /// Owns the `lora_phy::LoRa` instance via the reconfigurable NCP
    /// runner. RX preamble 8 symbols, TX preamble 16 (MeshCore parity).
    #[embassy_executor::task]
    async fn radio_task(lora: LoraRadio) {
        #[cfg(not(feature = "t1000e"))]
        const RX_PREAMBLE: u16 = 8;
        // Hardware bring-up established that the LR1110 misses MeshCore-US
        // traffic with an 8-symbol detector even though the SX1262 does not.
        #[cfg(feature = "t1000e")]
        const RX_PREAMBLE: u16 = 16;
        umsh_radio_loraphy::ncp_runner(lora, &RADIO_CH, &NCP_CTL, RX_PREAMBLE, 16).await;
    }

    /// Owns the USB `Sender`, HDLC-encodes frames, and writes USB packets.
    #[embassy_executor::task]
    async fn output_task(mut tx: NcpSender, wdt_report: Option<&'static str>) {
        // TEMPORARY freeze diagnostics: emit the previous boot's watchdog
        // capture as ASCII to the first USB reader. HDLC hosts
        // resynchronize past it; humans read it with a serial terminal.
        // Wait for DTR — the OS CDC driver drains the IN endpoint even
        // with no process attached, so writing before a real opener
        // exists would discard the report into the void.
        if let Some(report) = wdt_report {
            while !tx.dtr() {
                Timer::after_millis(50).await;
            }
            Timer::after_millis(300).await;
            for chunk in report.as_bytes().chunks(64) {
                let _ = tx.write_packet(chunk).await;
            }
        }
        loop {
            #[cfg(feature = "ble-debug")]
            let outbound = match select(OUT_USB_CH.receive(), DEBUG_CH.receive()).await {
                Either::First(outbound) => outbound,
                Either::Second(line) => {
                    for chunk in line.as_bytes().chunks(64) {
                        let _ = tx.write_packet(chunk).await;
                    }
                    continue;
                }
            };
            #[cfg(not(feature = "ble-debug"))]
            let outbound = OUT_USB_CH.receive().await;
            if SESSION_GEN.load(Ordering::Acquire) != outbound.generation {
                continue;
            }
            let mut wire = [0u8; WIRE_MAX];
            let Ok(len) = hdlc::encode_frame(&outbound.frame, &mut wire) else {
                continue;
            };
            for chunk in generation_checked(wire[..len].chunks(64), outbound.generation, || {
                SESSION_GEN.load(Ordering::Acquire)
            }) {
                let _ = tx.write_packet(chunk).await;
            }
        }
    }

    /// Owns the CDC receive half and HDLC decoder. Forwards frames and edges
    /// into INPUT_CH; `wait_connection` always precedes the read loop so
    /// a disconnected port never busy-loops.
    #[embassy_executor::task]
    async fn usb_in_task(mut rx: NcpRescue) {
        loop {
            rx.wait_connection().await;
            debug_log(format_args!("usb debug attached"));
            let mut decoder: hdlc::Decoder<FRAME_IN_MAX> = hdlc::Decoder::new();
            let mut local_generation = SESSION_GEN.load(Ordering::Acquire);
            INPUT_CH.send(InEvent::Attached(Transport::Usb)).await;
            loop {
                let generation = SESSION_GEN.load(Ordering::Acquire);
                if generation != local_generation {
                    decoder.reset();
                    local_generation = generation;
                }
                let mut packet = [0u8; 64];
                match rx.read_packet(&mut packet).await {
                    Ok(0) | Err(_) => break,
                    Ok(len) => {
                        for &byte in &packet[..len] {
                            let Some(Ok(bytes)) = decoder.push(byte) else {
                                continue;
                            };
                            let mut frame = heapless::Vec::new();
                            let _ = frame.extend_from_slice(bytes);
                            INPUT_CH.send(InEvent::Frame(Transport::Usb, frame)).await;
                        }
                    }
                }
            }
            INPUT_CH.send(InEvent::Detached(Transport::Usb)).await;
        }
    }

    /// Owns the framing-free protocol session. Sorts host frames,
    /// radio receptions, and transmit completions into session calls and
    /// executes the resulting radio effects.
    #[embassy_executor::task]
    async fn ncp_task(
        boot_reason: Status,
        mut proto_store: ProtoStore,
        boot_snapshot: Option<BootSnapshot>,
        mut identity_store: ProtoStore,
        boot_identity: Option<[u8; 32]>,
        mut identity_rng: IdentityRng,
    ) {
        // The retained hardware reset cause answers the first
        // PROP_LAST_STATUS query; attach itself never modifies it.
        let mut session = Session::new(
            session_config(),
            boot_reason,
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
        );
        let mut emitter = Emitter::new();
        let mut arbitration = SessionArbitration::new(SESSION_GEN.load(Ordering::Acquire));

        // The device identity is persisted independently of snapshots;
        // its post-reset value is whatever the identity journal holds.
        if let Some(public_key) = boot_identity {
            session.set_boot_identity(public_key);
        }

        // Restore a stored snapshot before processing any host command:
        // the saved configuration is applied, the PHY re-enabled if it
        // was enabled when saved, and detached operation begins
        // immediately. A snapshot that fails to decode is ignored.
        if let Some(payload) = boot_snapshot {
            let effect = session.restore_at_boot(&payload);
            debug_log(format_args!(
                "proto-store boot-restore={}",
                if effect.is_some() { "ok" } else { "IGNORED" }
            ));
            apply_effect(&session, effect).await;
        }

        loop {
            // Only wait for a TX completion while one is outstanding,
            // so a spurious tx_done can never be consumed early.
            let tx_done = async {
                if session.has_pending_tx() {
                    RADIO_CH.tx_done.wait().await
                } else {
                    core::future::pending().await
                }
            };

            match select3(INPUT_CH.receive(), RADIO_CH.rx.receive(), tx_done).await {
                Either3::First(InEvent::Attached(transport)) => {
                    // Fresh session state for the new host session; the
                    // device domain (PHY configuration and enable state,
                    // device name, duty accounting) is deliberately
                    // untouched and nothing is emitted (full-protocol
                    // attach semantics).
                    arbitration.attach(transport);
                    SESSION_GEN.store(arbitration.generation(), Ordering::Release);
                    #[cfg(not(feature = "ble-debug"))]
                    set_advertising_allowed(arbitration.advertising_allowed());
                    #[cfg(feature = "ble-debug")]
                    {
                        let _ = arbitration.advertising_allowed();
                        set_advertising_allowed(true);
                    }
                    // Both transports meet their provisioning-security
                    // binding here: USB-CDC by physical possession, BLE
                    // because the companion GATT service refuses any
                    // access outside an encrypted LESC-bonded link.
                    session.attach(true);
                }
                Either3::First(InEvent::Detached(transport)) => {
                    // Only the active transport's detach ends the
                    // session; a displaced transport's stale detach
                    // must not clear the successor's session state.
                    if arbitration.detach(transport) {
                        set_advertising_allowed(true);
                        session.detach();
                    }
                }
                Either3::First(InEvent::Frame(transport, frame_bytes)) => {
                    if arbitration.accepts_frame(transport) {
                        let now_ms = Instant::now().as_millis();
                        let effect =
                            session.handle_frame(&frame_bytes, now_ms, &mut |frame: &[u8]| {
                                emitter.push(frame)
                            });
                        emitter.flush(arbitration.destination()).await;
                        match effect {
                            Some(Effect::SampleRssi { tid }) => {
                                // Round-trip to the radio runner for an
                                // instantaneous RSSI sample, then answer the
                                // deferred PROP_PHY_RSSI get.
                                NCP_CTL.request_rssi();
                                let sample = NCP_CTL.wait_rssi().await;
                                session.respond_rssi(tid, sample, &mut |frame: &[u8]| {
                                    emitter.push(frame)
                                });
                                emitter.flush(arbitration.destination()).await;
                            }
                            Some(Effect::DrainQueue) => {
                                // Deliver the covered frames one per
                                // step, flushing between steps so the
                                // two-slot emitter never overflows and
                                // the transport applies backpressure.
                                loop {
                                    let more = session.drain_step(
                                        Instant::now().as_millis(),
                                        &mut |frame: &[u8]| emitter.push(frame),
                                    );
                                    emitter.flush(arbitration.destination()).await;
                                    if !more {
                                        break;
                                    }
                                }
                                #[cfg(feature = "t1000e")]
                                umsh_bsp_t1000e::indicator::clear_attention();
                            }
                            Some(Effect::WipeHostDomain { tid }) => {
                                // Durably wipe the host-domain portion of
                                // any saved snapshot before the new host
                                // key takes effect; with nothing saved the
                                // wipe is trivially satisfied.
                                let mut buf = [0u8; umsh_companion_ncp::SNAPSHOT_MAX];
                                let result = match session.encode_wiped_snapshot(&mut buf) {
                                    Some(len) => proto_store.persist(&buf[..len]).await,
                                    None => Ok(()),
                                };
                                session.respond_host_wipe(tid, result, &mut |frame: &[u8]| {
                                    emitter.push(frame)
                                });
                                emitter.flush(arbitration.destination()).await;
                            }
                            Some(Effect::SaveSnapshot { tid }) => {
                                let mut buf = [0u8; umsh_companion_ncp::SNAPSHOT_MAX];
                                let result = match session.encode_snapshot(&mut buf) {
                                    Some(len) => proto_store.persist(&buf[..len]).await,
                                    None => Err(()),
                                };
                                session.respond_save(tid, result, &mut |frame: &[u8]| {
                                    emitter.push(frame)
                                });
                                emitter.flush(arbitration.destination()).await;
                            }
                            Some(Effect::ClearSaved { tid }) => {
                                // CMD_CLEAR covers all persisted
                                // provisioning: the snapshot and the
                                // independently persisted device
                                // identity. Each journal's tombstone is
                                // individually atomic; an interruption
                                // between them reports failure and the
                                // host's retry completes the erase.
                                let result = match proto_store.clear().await {
                                    Ok(()) => identity_store.clear().await,
                                    Err(()) => Err(()),
                                };
                                session.respond_clear(tid, result, &mut |frame: &[u8]| {
                                    emitter.push(frame)
                                });
                                emitter.flush(arbitration.destination()).await;
                            }
                            Some(Effect::ProvisionIdentity { tid }) => {
                                // Build the keypair (drawing a fresh
                                // secret from the TRNG-seeded CSPRNG for
                                // on-device generation), persist it, and
                                // only then report the public key.
                                let result = match session.identity_request() {
                                    Some(source) => {
                                        let secret = match source {
                                            IdentitySource::Install(secret) => secret,
                                            IdentitySource::Generate => {
                                                let mut secret = [0u8; 32];
                                                rand_core::RngCore::fill_bytes(
                                                    &mut identity_rng,
                                                    &mut secret,
                                                );
                                                secret
                                            }
                                        };
                                        let identity = SoftwareIdentity::from_secret_bytes(&secret);
                                        let public_key = identity.public_key().0;
                                        let payload =
                                            proto_store::encode_identity(&secret, &public_key);
                                        identity_store.persist(&payload).await.map(|()| public_key)
                                    }
                                    None => Err(()),
                                };
                                session.respond_identity(tid, result, &mut |frame: &[u8]| {
                                    emitter.push(frame)
                                });
                                emitter.flush(arbitration.destination()).await;
                            }
                            Some(Effect::SetPairingPin { tid, pin }) => {
                                PAIRING_CONFIG_CH.send(pin).await;
                                let applied = PAIRING_CONFIG_ACK.wait().await;
                                session.respond_pin_set(
                                    tid,
                                    applied.then_some(()).ok_or(()),
                                    &mut |frame: &[u8]| emitter.push(frame),
                                );
                                emitter.flush(arbitration.destination()).await;
                            }
                            other => apply_effect(&session, other).await,
                        }
                        #[cfg(feature = "t1000e")]
                        if session.queued_frame_count() == 0 {
                            umsh_bsp_t1000e::indicator::clear_attention();
                        }
                    }
                }
                Either3::Second(RxFrame { data, info }) => {
                    // While detached this may stage a delegated MAC
                    // acknowledgement (Effect::StartTransmit).
                    #[cfg(feature = "t1000e")]
                    let queued_before = session.queued_frame_count();
                    let effect = session.on_radio_rx(
                        &data,
                        info.rssi,
                        info.snr.as_centibels(),
                        info.lqi,
                        Instant::now().as_millis(),
                        &mut |frame: &[u8]| emitter.push(frame),
                    );
                    #[cfg(feature = "t1000e")]
                    if session.queued_frame_count() > queued_before {
                        umsh_bsp_t1000e::indicator::request_attention();
                    }
                    emitter.flush(arbitration.destination()).await;
                    apply_effect(&session, effect).await;
                }
                Either3::Third(result) => {
                    let now_ms = Instant::now().as_millis();
                    session.on_tx_result(result.is_ok(), now_ms, &mut |frame: &[u8]| {
                        emitter.push(frame)
                    });
                    emitter.flush(arbitration.destination()).await;
                }
            }
        }
    }

    #[cfg(not(feature = "t1000e"))]
    fn render_ui_frame(buf: &mut [u8; display::BUF_SIZE], model: UiModel) {
        use core::fmt::Write as _;
        use embedded_graphics::Drawable;
        use embedded_graphics::geometry::Point;
        use embedded_graphics::mono_font::MonoTextStyle;
        use embedded_graphics::mono_font::ascii::FONT_10X20;
        use embedded_graphics::pixelcolor::BinaryColor;
        use embedded_graphics::text::{Baseline, Text};
        use heapless::String;

        buf.fill(0xff);
        let mut fb = display::EpdFb(buf);
        let style = MonoTextStyle::new(&FONT_10X20, BinaryColor::On);
        let mut y = 8;
        let mut line = |text: &str| {
            let _ = Text::with_baseline(text, Point::new(5, y), style, Baseline::Top).draw(&mut fb);
            y += 27;
        };

        line("UMSH BLE");
        match model.page() {
            Page::Menu(item) => {
                line(match item {
                    MenuItem::Status => "> Status",
                    MenuItem::StartPairing => "> Start pairing",
                    MenuItem::ClearBonds => "> Clear bonds",
                });

                let mut bonds: String<20> = String::new();
                let _ = write!(
                    bonds,
                    "Bonds: {}/{}",
                    BLE_BOND_COUNT.load(Ordering::Acquire),
                    ble_store::MAX_BONDS
                );
                line(&bonds);

                let pairing = if PAIRING_LOCKED_OUT.load(Ordering::Acquire) {
                    "Pairing: LOCKED"
                } else if PAIRING_MODE.load(Ordering::Acquire) {
                    "Pairing: open"
                } else {
                    "Pairing: closed"
                };
                line(pairing);
                line(match item {
                    MenuItem::Status => match model.notice() {
                        Some(UiNotice::PairingStarted) => "Pairing started",
                        Some(UiNotice::PairingUnavailable) => "Pair unavailable",
                        Some(UiNotice::BondsCleared) => "Bonds cleared",
                        Some(UiNotice::ClearFailed) => "CLEAR FAILED",
                        None => "2x: no action",
                    },
                    MenuItem::StartPairing => "2x: start",
                    MenuItem::ClearBonds => "2x: continue",
                });
                line("1x: next");
                line("hold: back");
            }
            Page::ConfirmClear { clear_selected } => {
                line("Clear all bonds?");
                line(if clear_selected {
                    "  Cancel"
                } else {
                    "> Cancel"
                });
                line(if clear_selected { "> CLEAR" } else { "  CLEAR" });
                line("1x/hold: toggle");
                line("2x: confirm");
            }
        }
    }

    #[cfg(not(feature = "t1000e"))]
    fn render_message_frame(buf: &mut [u8; display::BUF_SIZE], title: &str, detail: &str) {
        use embedded_graphics::Drawable;
        use embedded_graphics::geometry::Point;
        use embedded_graphics::mono_font::MonoTextStyle;
        use embedded_graphics::mono_font::ascii::FONT_10X20;
        use embedded_graphics::pixelcolor::BinaryColor;
        use embedded_graphics::text::{Baseline, Text};

        buf.fill(0xff);
        let mut fb = display::EpdFb(buf);
        let style = MonoTextStyle::new(&FONT_10X20, BinaryColor::On);
        let center_x = |text: &str| (display::WIDTH as i32 - text.len() as i32 * 10) / 2;
        let _ = Text::with_baseline(title, Point::new(center_x(title), 70), style, Baseline::Top)
            .draw(&mut fb);
        let _ = Text::with_baseline(
            detail,
            Point::new(center_x(detail), 105),
            style,
            Baseline::Top,
        )
        .draw(&mut fb);
    }

    /// Owns the e-paper bus and renders the BLE menu. Input is serialized
    /// through the full-refresh cycle so Select can never activate an item the
    /// user has not yet seen on the panel.
    #[cfg(not(feature = "t1000e"))]
    #[embassy_executor::task]
    async fn display_task(
        mut spi: Spim<'static>,
        mut cs: Output<'static>,
        mut dc: Output<'static>,
        mut rst: Output<'static>,
        mut busy: Input<'static>,
    ) {
        let mut model = UiModel::new();
        let mut shown = [0xff; display::BUF_SIZE];
        let mut next = [0xff; display::BUF_SIZE];
        render_ui_frame(&mut next, model);
        display::init(&mut spi, &mut cs, &mut dc, &mut rst, &mut busy).await;
        display::render(&mut spi, &mut cs, &mut dc, &mut busy, &next).await;
        shown.copy_from_slice(&next);

        loop {
            match select4(
                UI_INPUT_CH.receive(),
                UI_REFRESH.wait(),
                UI_NOTICE.wait(),
                DISPLAY_SHUTDOWN.wait(),
            )
            .await
            {
                Either4::First(input) => {
                    debug_log(format_args!("ui input={input:?}"));
                    let effect = model.apply(input);
                    match effect {
                        Some(UiEffect::StartPairing) => {
                            render_message_frame(&mut next, "Starting", "pairing mode...");
                            display::render_partial(
                                &mut spi, &mut cs, &mut dc, &mut busy, &mut shown, &next,
                            )
                            .await;
                            PAIRING_MODE_REQUEST.signal(());
                        }
                        Some(UiEffect::ClearBonds) => {
                            render_message_frame(&mut next, "Clearing", "bonds + PIN...");
                            display::render_partial(
                                &mut spi, &mut cs, &mut dc, &mut busy, &mut shown, &next,
                            )
                            .await;
                            BLE_WIPE_REQUEST.signal(());
                        }
                        None => {
                            render_ui_frame(&mut next, model);
                            display::render_partial(
                                &mut spi, &mut cs, &mut dc, &mut busy, &mut shown, &next,
                            )
                            .await;
                        }
                    }
                }
                Either4::Second(()) => {
                    model.clear_notice();
                    render_ui_frame(&mut next, model);
                    display::render_partial(
                        &mut spi, &mut cs, &mut dc, &mut busy, &mut shown, &next,
                    )
                    .await;
                }
                Either4::Third(notice) => {
                    model.set_notice(notice);
                    render_ui_frame(&mut next, model);
                    display::render_partial(
                        &mut spi, &mut cs, &mut dc, &mut busy, &mut shown, &next,
                    )
                    .await;
                }
                Either4::Fourth(()) => {
                    render_message_frame(&mut next, "Sleeping", "Good night");
                    display::render_partial(
                        &mut spi, &mut cs, &mut dc, &mut busy, &mut shown, &next,
                    )
                    .await;
                    display::sleep(&mut spi, &mut cs, &mut dc).await;
                    DISPLAY_SHUTDOWN_DONE.signal(());
                    core::future::pending::<()>().await;
                }
            }
        }
    }

    #[cfg(not(feature = "t1000e"))]
    fn techo_button_timings() -> ButtonTimings {
        ButtonTimings {
            max_click_hold: core::time::Duration::from_millis(500),
            inter_click_gap: core::time::Duration::from_millis(400),
            long_press: core::time::Duration::from_secs(1),
            very_long_press: Some(core::time::Duration::from_secs(4)),
        }
    }

    /// Resolves the P1.10 side button (active-low, pull-up) through the same
    /// tested state machine used by T-1000E. Single advances, double selects,
    /// a 1–4 second hold released by the user goes back, and a continuing
    /// four-second hold always powers off.
    #[cfg(not(feature = "t1000e"))]
    #[embassy_executor::task]
    async fn button_task(mut button: Input<'static>) {
        const DEBOUNCE: Duration = Duration::from_millis(10);
        let mut fsm = ButtonFsm::new(techo_button_timings());
        let mut pressed = button.is_low();
        loop {
            let event = {
                let now_ms = Instant::now().as_millis();
                let edge_fut = async {
                    if pressed {
                        button.wait_for_high().await;
                        Timer::after(DEBOUNCE).await;
                        ButtonEdge::Release
                    } else {
                        button.wait_for_low().await;
                        Timer::after(DEBOUNCE).await;
                        ButtonEdge::Press
                    }
                };
                let deadline = fsm.next_deadline().unwrap_or(now_ms.saturating_add(60_000));
                match select(edge_fut, Timer::at(Instant::from_millis(deadline))).await {
                    Either::First(edge) => {
                        pressed = matches!(edge, ButtonEdge::Press);
                        fsm.on_edge(edge, Instant::now().as_millis())
                    }
                    Either::Second(()) => fsm.poll(Instant::now().as_millis()),
                }
            };

            let input = match event {
                Some(ButtonEvent::Single) => Some(UiInput::Forward),
                Some(ButtonEvent::Double) => Some(UiInput::Select),
                Some(ButtonEvent::Long) => Some(UiInput::Backward),
                Some(ButtonEvent::VeryLong) => {
                    pressed = false;
                    fsm = ButtonFsm::new(techo_button_timings());
                    SHUTDOWN_SIGNAL.signal(());
                    None
                }
                Some(ButtonEvent::Triple | ButtonEvent::Quad) | None => None,
            };
            if let Some(input) = input {
                UI_INPUT_CH.send(input).await;
            }
        }
    }

    /// The capacitive touch button remains dedicated to the unusual e-paper
    /// backlight. T-Echo defines P0.11 as active-low with a pull-up: illuminate
    /// on a debounced low level and turn it off on the corresponding release.
    #[cfg(not(feature = "t1000e"))]
    #[embassy_executor::task]
    async fn touch_task(mut touch: Input<'static>, mut backlight: Output<'static>) {
        const DEBOUNCE: Duration = Duration::from_millis(20);
        loop {
            touch.wait_for_low().await;
            Timer::after(DEBOUNCE).await;
            if !touch.is_low() {
                continue;
            }
            backlight.set_high();
            debug_log(format_args!("backlight on=true"));
            touch.wait_for_high().await;
            Timer::after(DEBOUNCE).await;
            backlight.set_low();
            debug_log(format_args!("backlight on=false"));
        }
    }

    /// T-1000E piezo driver. Kept as a task shim so the BSP's generic async
    /// runner is monomorphized in this binary.
    #[cfg(feature = "t1000e")]
    #[embassy_executor::task]
    async fn t1000e_buzzer_task(
        pwm: SimplePwm<'static>,
        enable: Output<'static>,
        initially_silenced: bool,
    ) {
        umsh_bsp_t1000e::buzzer::run(pwm, enable, initially_silenced).await;
    }

    /// Apply the T-1000E device profile: the unsupported single and quadruple
    /// slots remain inert, double-click toggles persisted Silence State,
    /// triple-click is reserved for unsupported GPS control, and the
    /// three-second long press enters persisted Sleep State. A startup-held press has already
    /// been consumed by the force-pairing ceremony, so it is ignored through
    /// its release instead of becoming an immediate shutdown.
    #[cfg(feature = "t1000e")]
    #[embassy_executor::task]
    async fn t1000e_button_task(
        mut button: Input<'static>,
        held_at_boot: bool,
        mut ux_store: ProtoStore,
    ) {
        const DEBOUNCE: Duration = Duration::from_millis(10);

        if held_at_boot {
            button.wait_for_low().await;
            Timer::after(DEBOUNCE).await;
        }

        let mut fsm = ButtonFsm::new(ButtonTimings::default());
        let mut pressed = false;
        loop {
            let event = {
                let now_ms = Instant::now().as_millis();
                let edge_fut = async {
                    if pressed {
                        button.wait_for_low().await;
                        Timer::after(DEBOUNCE).await;
                        ButtonEdge::Release
                    } else {
                        button.wait_for_high().await;
                        Timer::after(DEBOUNCE).await;
                        ButtonEdge::Press
                    }
                };
                let deadline = fsm.next_deadline().unwrap_or(now_ms.saturating_add(60_000));
                match select(edge_fut, Timer::at(Instant::from_millis(deadline))).await {
                    Either::First(edge) => {
                        pressed = matches!(edge, ButtonEdge::Press);
                        fsm.on_edge(edge, Instant::now().as_millis())
                    }
                    Either::Second(()) => fsm.poll(Instant::now().as_millis()),
                }
            };

            match event {
                Some(ButtonEvent::Single) => {
                    // The NCP has no autonomous primary action. An unsupported
                    // slot is inert and must not emit a false confirmation.
                }
                Some(ButtonEvent::Double) => {
                    let preferences = umsh_bsp_t1000e::preferences::toggle_silent();
                    umsh_bsp_t1000e::BUZZER_SILENCE_SET.signal(preferences.silent);
                    umsh_bsp_t1000e::indicator::LED_SEQUENCE_SIGNAL
                        .signal(LedSequence::ActionConfirm);
                    let _ = persist_ux_preferences(&mut ux_store, preferences).await;
                }
                Some(ButtonEvent::Triple) => {
                    // Reserved for GPS power control. The NCP does not own
                    // GNSS, so the slot remains inert.
                }
                Some(ButtonEvent::Long) => {
                    pressed = false;
                    fsm = ButtonFsm::new(ButtonTimings::default());
                    let preferences = umsh_bsp_t1000e::preferences::set_asleep(true);
                    let _ = persist_ux_preferences(&mut ux_store, preferences).await;
                    umsh_bsp_t1000e::SHUTDOWN_SIGNAL.signal(());
                }
                Some(ButtonEvent::Quad | ButtonEvent::VeryLong) | None => {}
            }
        }
    }

    #[cfg(feature = "t1000e")]
    #[embassy_executor::task]
    async fn t1000e_shutdown_task() -> ! {
        umsh_bsp_t1000e::shutdown::run().await
    }

    #[cfg(feature = "t1000e")]
    #[embassy_executor::task]
    async fn t1000e_power_task(
        saadc: Saadc<'static, 1>,
        sensor_rail: Output<'static>,
        external_power: Input<'static>,
        charge_active: Input<'static>,
    ) {
        umsh_bsp_t1000e::power::run_battery_monitor(
            saadc,
            sensor_rail,
            external_power,
            charge_active,
        )
        .await;
    }

    /// Controlled power-off: put the e-paper controller to sleep, tri-state
    /// peripheral signal pins, drop the rail, and enter System OFF.
    #[cfg(not(feature = "t1000e"))]
    #[embassy_executor::task]
    async fn shutdown_task(peripheral_power: Output<'static>) -> ! {
        SHUTDOWN_SIGNAL.wait().await;

        DISPLAY_SHUTDOWN.signal(());
        let _ = select(
            DISPLAY_SHUTDOWN_DONE.wait(),
            Timer::after(Duration::from_secs(5)),
        )
        .await;

        // E-paper SPI bus (SPIM2): SCK=P0.31, MISO=P1.07, MOSI=P0.29
        // E-paper control:         CS=P0.30, DC=P0.28, RST=P0.02, BUSY=P0.03
        // Radio SPI bus (TWISPI1): SCK=P0.19, MOSI=P0.22, MISO=P0.23
        // Radio control:           CS=P0.24, RST=P0.25, BUSY=P0.17, DIO1=P0.20
        // The display and touch tasks still own these pins; direct PIN_CNF
        // writes are deliberate here because every task is about to lose power.
        for (port, pin) in [
            (Port::P0, 31u8),
            (Port::P1, 7u8),
            (Port::P0, 29u8),
            (Port::P0, 30u8),
            (Port::P0, 28u8),
            (Port::P0, 2u8),
            (Port::P0, 3u8),
            (Port::P0, 11u8), // touch input ← async wait may have set SENSE
            (Port::P1, 11u8), // e-paper backlight
            (Port::P0, 19u8),
            (Port::P0, 22u8),
            (Port::P0, 23u8),
            (Port::P0, 24u8),
            (Port::P0, 25u8),
            (Port::P0, 17u8),
            (Port::P0, 20u8), // radio DIO1 ← has SENSE set by async radio wait
        ] {
            tristate_pin(port, pin);
        }

        drop(peripheral_power);

        // P1.10 is the side user button. Active-low, pull-up → DETECT-low wakes.
        power_off(&[WakePin {
            port: Port::P1,
            pin: 10,
            sense: WakeSense::Low,
        }])
    }

    // ─── Main ────────────────────────────────────────────────────────────────

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        // Temporary freeze diagnostics: recover the previous boot's last
        // breadcrumb stage, then mark progress through boot. Stage map:
        //  1 main entered            8 USB built, core tasks spawned
        //  2 embassy init done       9 chirp signaled / pre-join
        //  3 WDT armed              10 ble_app entered
        //  4 radio ready            11 trouble stack + GATT server built
        //  5 MPSL ready             12 advertising loop reached
        //  6 bond store ready       13 usb.run() first polled
        //  7 SDC built
        let (previous_crumb, previous_beats) = super::panic::breadcrumb_take();
        PREV_BOOT_CRUMB.store(previous_crumb, Ordering::Release);
        PREV_BOOT_BEATS.store(previous_beats, Ordering::Release);
        let wdt_capture = super::panic::wdt_capture_take();
        let mut pc_ring = [0u32; super::panic::PC_RING_ENTRIES];
        let pc_ring_count = super::panic::pc_ring_take(&mut pc_ring);
        PREV_RING_COUNT.store(pc_ring_count as u16, Ordering::Release);
        super::panic::breadcrumb_mark(1);

        #[cfg(feature = "t1000e")]
        {
            use core::mem::MaybeUninit;
            const HEAP_SIZE: usize = 8192;
            static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
            unsafe { crate::ALLOCATOR.init(core::ptr::addr_of!(HEAP) as usize, HEAP_SIZE) }
        }

        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::ble_config());
        // GPIO state survives the soft reset/DFU handoff. Silence the T-1000E
        // piezo before any potentially lengthy radio, flash, or BLE work so a
        // retained PWM/enable state cannot sound until the buzzer task starts.
        #[cfg(feature = "t1000e")]
        {
            drive_pin_low(Port::P0, 25); // buzzer PWM input
            drive_pin_low(Port::P1, 5); // buzzer driver enable
        }
        super::panic::breadcrumb_mark(2);
        // RESETREAS survives reset. Capture and clear it before starting the
        // watchdog so a later host query can distinguish a watchdog reboot
        // from a cold start or an external reset.
        let hardware_reset_reasons = pac::POWER.resetreas().read();
        pac::POWER.resetreas().write(|reasons| reasons.0 = u32::MAX);
        BOOT_RESETREAS.store(hardware_reset_reasons.0, Ordering::Release);
        #[cfg(feature = "t1000e")]
        let t1000e_external_power = umsh_bsp_t1000e::power::usb_power_present();
        #[cfg(feature = "t1000e")]
        let t1000e_gpregret_state = umsh_bsp_t1000e::preferences::load_retained();
        #[cfg(feature = "t1000e")]
        let t1000e_retained_critical = t1000e_gpregret_state
            .is_some_and(|preferences| preferences.battery_critical);
        #[cfg(feature = "t1000e")]
        let mut t1000e_retained_state = mapped_ux_preferences().unwrap_or_default();
        #[cfg(feature = "t1000e")]
        {
            t1000e_retained_state.battery_critical = t1000e_retained_critical;
            umsh_bsp_t1000e::preferences::store(t1000e_retained_state);
        }
        #[cfg(feature = "t1000e")]
        if t1000e_retained_state.battery_critical && !t1000e_external_power {
            umsh_bsp_t1000e::shutdown::resume_persisted_sleep().await;
        }
        #[cfg(feature = "t1000e")]
        if t1000e_retained_state.battery_critical && t1000e_external_power {
            umsh_bsp_t1000e::preferences::set_battery_critical(false);
        }
        // RESETREAS.OFF alone proves a button wake: P0.06 is the only GPIO
        // DETECT source armed at System OFF entry (USB insertion wakes via
        // the native VBUS detector and sets its own reason bit). The pin
        // itself cannot be sampled this early — PIN_CNF resets to
        // input-disconnected, so the IN register reads 0 regardless of the
        // physical level.
        #[cfg(feature = "t1000e")]
        let t1000e_wake_requested = hardware_reset_reasons.off()
            || (hardware_reset_reasons.sreq()
                && t1000e_gpregret_state.is_some_and(|preferences| !preferences.asleep));
        #[cfg(feature = "t1000e")]
        let t1000e_wake_cleared_sleep = t1000e_wake_requested && t1000e_retained_state.asleep;
        #[cfg(feature = "t1000e")]
        if t1000e_wake_requested {
            umsh_bsp_t1000e::preferences::set_asleep(false);
        } else if umsh_bsp_t1000e::preferences::load().asleep {
            if t1000e_external_power {
                let mut led_config = SimpleConfig::default();
                led_config.prescaler = Prescaler::Div16;
                let led_pwm = SimplePwm::new_1ch(p.PWM1, p.P0_24, &led_config);
                let sleep_button = Input::new(p.P0_06, Pull::Down);
                let sleep_external_power = Input::new(p.P0_05, Pull::Down);
                let sleep_charge_active = Input::new(p.P1_03, Pull::Up);
                umsh_bsp_t1000e::shutdown::run_charging_sleep(
                    led_pwm,
                    sleep_button,
                    sleep_external_power,
                    sleep_charge_active,
                )
                .await;
            } else {
                umsh_bsp_t1000e::shutdown::resume_persisted_sleep().await;
            }
        }

        // Disarm POWER USB interrupt state inherited across the DFU
        // handoff. The bootloader's USB stack enables the POWER
        // USBDETECTED/USBREMOVED/USBPWRRDY interrupts, and POWER lives
        // in the always-on domain, so the enables survive the DFU
        // activation reset. MPSL later owns the shared CLOCK_POWER
        // vector but services only CLOCK events, so with VBUS present a
        // pending USB power event re-enters the handler forever,
        // starving thread mode until the watchdog fires — the post-DFU
        // first-boot freeze. This firmware never uses these interrupts
        // (USB runs on SoftwareVbusDetect precisely because MPSL owns
        // POWER), so clear the enables and any pending events before
        // MPSL takes the vector.
        pac::POWER.intenclr().write(|w| {
            w.set_usbdetected(true);
            w.set_usbremoved(true);
            w.set_usbpwrrdy(true);
        });
        pac::POWER.events_usbdetected().write_value(0);
        pac::POWER.events_usbremoved().write_value(0);
        pac::POWER.events_usbpwrrdy().write_value(0);

        // TEMPORARY freeze diagnostics: format the previous boot's
        // watchdog capture and PC-sample ring for the ASCII dump on the
        // first USB connect.
        let wdt_report: Option<&'static str> = (wdt_capture.is_some()
            || (pc_ring_count > 0 && hardware_reset_reasons.dog()))
        .then(|| {
            use core::fmt::Write as _;
            static REPORT: StaticCell<heapless09::String<2048>> = StaticCell::new();
            let report = REPORT.init(heapless09::String::new());
            let _ = write!(report, "\r\n=== WDT CAPTURE (previous boot) ===\r\n");
            if let Some(capture) = wdt_capture {
                PREV_WDT_PC.store(capture.pc, Ordering::Release);
                PREV_WDT_LR.store(capture.lr, Ordering::Release);
                PREV_WDT_PSR.store(capture.xpsr, Ordering::Release);
                let _ = write!(
                    report,
                    "pc={:#010x} lr={:#010x} psr={:#010x} exc={:#010x} sp={:#010x}\r\n",
                    capture.pc, capture.lr, capture.xpsr, capture.exc_return, capture.sp,
                );
                let _ = write!(
                    report,
                    "CLOCK hfstat={:#x} lfstat={:#x} inten={:#x} evhf={} evlf={} evdone={} evctto={} lfsrc={:#x}\r\n",
                    capture.clock[0],
                    capture.clock[1],
                    capture.clock[2],
                    capture.clock[3],
                    capture.clock[4],
                    capture.clock[5],
                    capture.clock[6],
                    capture.clock[7],
                );
                let _ = write!(report, "stack above frame:\r\n");
                for row in capture.stack.chunks(4) {
                    for word in row {
                        let _ = write!(report, "{word:#010x} ");
                    }
                    let _ = write!(report, "\r\n");
                }
            } else {
                let _ = write!(report, "no exception-frame capture (WDT IRQ shielded)\r\n");
            }
            let _ = write!(report, "pc ring ({pc_ring_count} samples, oldest first):\r\n");
            for row in pc_ring[..pc_ring_count].chunks(4) {
                for word in row {
                    let _ = write!(report, "{word:#010x} ");
                }
                let _ = write!(report, "\r\n");
            }
            let _ = write!(report, "=== END WDT CAPTURE ===\r\n");
            report.as_str()
        });
        #[cfg(feature = "ble-debug")]
        {
            set_security_trace_handler(Some(trouble_security_trace));
            set_security_diagnostic_trace_handler(Some(trouble_security_diagnostic_trace));
            set_connection_trace_handler(Some(trouble_connection_trace));
        }

        // Peripheral power enable (P0.12). Must be high before the LoRa
        // module is addressed. Ownership transfers to shutdown_task.
        #[cfg(not(feature = "t1000e"))]
        let peripheral_power = Output::new(p.P0_12, Level::High, OutputDrive::Standard);

        // On T-1000E, seize LR1110 reset before any lengthy initialization.
        // The user button is active-high. Holding it through power-on is the
        // BLE spec's physical-presence ceremony; it must not invoke the
        // bootloader. The runtime task suppresses this same press until release.
        #[cfg(feature = "t1000e")]
        let radio_rst = Output::new(p.P1_10, Level::Low, OutputDrive::Standard);
        #[cfg(feature = "t1000e")]
        let mut button = Input::new(p.P0_06, Pull::Down);
        #[cfg(feature = "t1000e")]
        cortex_m::asm::delay(640_000);
        // A short press is how a powered-off T-1000E is started normally, so
        // the initial HIGH level alone cannot distinguish force pairing. Only
        // a press still held after one second is the deliberate ceremony.
        #[cfg(feature = "t1000e")]
        let force_pairing_at_boot = if button.is_high() {
            match select(button.wait_for_low(), Timer::after_secs(1)).await {
                Either::First(()) => false,
                Either::Second(()) => button.is_high(),
            }
        } else {
            false
        };
        #[cfg(feature = "t1000e")]
        FORCE_PAIRING_AT_BOOT.store(force_pairing_at_boot, Ordering::Release);

        // WDT: 8 s timeout, petted by the heartbeat task every ~2 s.
        let mut wdt_config = WdtConfig::default();
        wdt_config.timeout_ticks = 32768 * 8;
        let (mut wdt, [wdt_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, wdt_config).unwrap_or_else(|_| panic!("wdt"));
        // Freeze diagnostics: the TIMEOUT interrupt fires ~61 µs before
        // the watchdog reset; its handler (panic.rs `WDT`) records the
        // interrupted context's stacked PC/LR/xPSR into retained RAM.
        // Highest priority so it can preempt a storming lower-priority
        // handler; it runs only in the doomed final microseconds.
        wdt.enable_interrupt();
        unsafe {
            let mut peripherals = cortex_m::Peripherals::steal();
            peripherals
                .NVIC
                .set_priority(embassy_nrf::pac::Interrupt::WDT, 0);
            cortex_m::peripheral::NVIC::unmask(embassy_nrf::pac::Interrupt::WDT);
        }
        // Freeze diagnostics: 1 kHz PC sampler on TIMER2 (free on both
        // boards; MPSL owns TIMER0 only). Priority 1 — above the
        // thread-mode executor and MPSL's low-priority signal
        // processing, below MPSL's radio-critical priority 0.
        {
            let timer = pac::TIMER2;
            timer
                .mode()
                .write(|w| w.set_mode(pac::timer::vals::Mode::Timer));
            timer
                .bitmode()
                .write(|w| w.set_bitmode(pac::timer::vals::Bitmode::_32bit));
            timer.prescaler().write(|w| w.set_prescaler(4)); // 16 MHz / 2^4 = 1 MHz
            timer.cc(0).write_value(1_000); // 1 kHz sampling
            timer.shorts().write(|w| w.set_compare_clear(0, true));
            timer.intenset().write(|w| w.set_compare(0, true));
            timer.tasks_start().write_value(1);
            unsafe {
                let mut peripherals = cortex_m::Peripherals::steal();
                peripherals
                    .NVIC
                    .set_priority(embassy_nrf::pac::Interrupt::TIMER2, 1 << 5);
                cortex_m::peripheral::NVIC::unmask(embassy_nrf::pac::Interrupt::TIMER2);
            }
        }
        #[cfg(not(feature = "t1000e"))]
        let led = Output::new(p.P0_14, Level::High, OutputDrive::Standard);
        #[cfg(feature = "t1000e")]
        let led = {
            let mut config = SimpleConfig::default();
            config.prescaler = Prescaler::Div16;
            SimplePwm::new_1ch(p.PWM1, p.P0_24, &config)
        };
        // Service the watchdog throughout radio, persistence, MPSL, and BLE
        // initialization. Deferring this task until the final steady-state
        // join caused first-boot persistence to consume the entire watchdog
        // window and reset once before the device became usable.
        spawner.spawn(heartbeat(led, wdt_handle).unwrap());
        super::panic::breadcrumb_mark(3);

        // A message in the panic slot means the last reset was a crash;
        // report that as the reset reason. The slot is cleared either way.
        let boot_reason = {
            let mut slot = PanicSlot::new(super::panic::panic_region());
            if slot.read().is_some() {
                slot.clear();
                Status::RESET_CRASH
            } else if hardware_reset_reasons.dog() {
                Status::RESET_WATCHDOG
            } else if hardware_reset_reasons.lockup() {
                Status::RESET_CRASH
            } else if hardware_reset_reasons.resetpin() {
                Status::RESET_EXTERNAL
            } else if hardware_reset_reasons.sreq() {
                Status::RESET_SOFTWARE
            } else {
                Status::RESET_POWER_ON
            }
        };

        // ── SX1262 LoRa radio ────────────────────────────────────────────────
        // Pin assignment (T-Echo hardware, firmware-confirmed):
        //   SPI bus: SCK=P0.19, MOSI=P0.22, MISO=P0.23 (TWISPI1)
        //   CS=P0.24, RST=P0.25, BUSY=P0.17, DIO1=P0.20
        //   DIO2: internal RF switch; DIO3: 1.8 V TCXO.
        #[cfg(not(feature = "t1000e"))]
        {
            let mut cfg = SpimConfig::default();
            // SX1262 datasheet §8.2: max SCK = 16 MHz, Mode 0.
            cfg.frequency = Frequency::M16;
            let radio_bus = Spim::new(
                p.TWISPI1, Irqs, p.P0_19, // SCK
                p.P0_23, // MISO
                p.P0_22, // MOSI
                cfg,
            );
            let radio_cs = Output::new(p.P0_24, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();

            let radio_rst = Output::new(p.P0_25, Level::High, OutputDrive::Standard);
            let radio_dio1 = Input::new(p.P0_20, Pull::None);
            let radio_busy = Input::new(p.P0_17, Pull::None);

            let iv = GenericSx126xInterfaceVariant::new(
                radio_rst, radio_dio1, radio_busy,
                None, // rf_switch_rx: DIO2 wired internally on the T-Echo module
                None, // rf_switch_tx: same
            )
            .unwrap();

            let lora_config = LoraConfig {
                chip: Sx1262,
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8), // DIO3 → 1.8 V TCXO
                use_dcdc: true,
                rx_boost: true,
            };

            // enable_public_network=false → sync word 0x1424 (private).
            // session_config().sync_word must match this choice.
            let lora = LoRa::new(Sx126x::new(radio_spi, iv, lora_config), false, Delay)
                .await
                .unwrap_or_else(|_| panic!("radio init"));

            spawner.spawn(radio_task(lora).unwrap());
        }

        // ── LR1110 LoRa radio (T-1000E) ─────────────────────────────────────
        #[cfg(feature = "t1000e")]
        {
            let mut cfg = SpimConfig::default();
            cfg.frequency = Frequency::M8;
            let radio_bus = Spim::new(p.TWISPI0, Irqs, p.P0_11, p.P1_08, p.P1_09, cfg);
            let radio_cs = Output::new(p.P0_12, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();
            let radio_interrupt = Input::new(p.P1_01, Pull::Down);
            let radio_busy = Input::new(p.P0_07, Pull::None);
            let iv = GenericLr1110InterfaceVariant::new(
                radio_rst,
                radio_interrupt,
                radio_busy,
                None,
                None,
            )
            .unwrap_or_else(|_| panic!("lr1110 iv"));
            let lora_config = LoraConfig {
                chip: Lr1110Chip::with_pa(PaSelection::Hp),
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V6),
                use_dcdc: false,
                rx_boost: true,
                rf_switch: Some(RF_SWITCH),
            };
            let lora = LoRa::new(Lr1110::new(radio_spi, iv, lora_config), false, Delay)
                .await
                .unwrap_or_else(|_| panic!("radio init"));
            spawner.spawn(radio_task(lora).unwrap());
        }

        super::panic::breadcrumb_mark(4);

        // ── MPSL + Nordic SoftDevice Controller ────────────────────────────
        // MPSL owns CLOCK/POWER, RADIO, RTC0, TIMER0, TEMP, and the listed
        // PPI channels. embassy-time remains on RTC1; LoRa remains on SPIM1.
        //
        // The `no-ble` diagnostic build skips this entire section (and the
        // SDC/Trouble construction below); the firmware is then a USB-only
        // NCP with the identical clock configuration.
        #[cfg(not(feature = "no-ble"))]
        let mut rng = rng::Rng::new(p.RNG, Irqs);
        #[cfg(not(feature = "no-ble"))]
        let mut sdc_memory = sdc::Mem::<8192>::new();
        #[cfg(not(feature = "no-ble"))]
        let (
            controller,
            ble_store,
            proto_store,
            boot_snapshot,
            identity_store,
            boot_identity,
            identity_rng,
            ux_store,
        ) = {
            let mpsl_peripherals = mpsl::Peripherals::new(
                p.RTC0, p.TIMER0, p.TEMP, p.PPI_CH19, p.PPI_CH30, p.PPI_CH31,
            );
            let lfclk = mpsl::raw::mpsl_clock_lfclk_cfg_t {
                source: mpsl::raw::MPSL_CLOCK_LF_SRC_XTAL as u8,
                rc_ctiv: 0,
                rc_temp_ctiv: 0,
                accuracy_ppm: 20,
                skip_wait_lfclk_started: false,
            };
            static MPSL: StaticCell<MultiprotocolServiceLayer> = StaticCell::new();
            static TIMESLOT_MEM: StaticCell<mpsl::SessionMem<1>> = StaticCell::new();
            let mpsl = MPSL.init(
                MultiprotocolServiceLayer::with_timeslots(
                    mpsl_peripherals,
                    Irqs,
                    lfclk,
                    TIMESLOT_MEM.init(mpsl::SessionMem::new()),
                )
                .unwrap_or_else(|_| panic!("mpsl init")),
            );
            spawner.spawn(mpsl_task(mpsl).unwrap());
            super::panic::breadcrumb_mark(5);
            static SHARED_FLASH: StaticCell<SharedFlash> = StaticCell::new();
            let flash = SHARED_FLASH.init(Mutex::new(nrf_mpsl::Flash::take(mpsl, p.NVMC)));
            let mut ble_store = BleStore::mount(flash).await;
            // Mount the protocol journals before the NCP session starts: a
            // stored snapshot must be restored (and the PHY re-applied) and
            // the persisted device identity installed before the first host
            // command.
            let (proto_store, boot_snapshot) = ProtoStore::mount(flash, proto_store::PAGE0).await;
            let (identity_store, identity_payload) =
                ProtoStore::mount(flash, proto_store::IDENTITY_PAGE0).await;
            let (ux_store, _) = ProtoStore::mount(flash, proto_store::UX_PAGE0).await;
            #[cfg(feature = "t1000e")]
            let mut ux_store = ux_store;
            #[cfg(feature = "t1000e")]
            if t1000e_wake_cleared_sleep {
                let _ = persist_ux_preferences(
                    &mut ux_store,
                    umsh_bsp_t1000e::preferences::load(),
                )
                .await;
            }
            let boot_identity = identity_payload
                .as_deref()
                .and_then(proto_store::decode_identity)
                .map(|(_secret, public)| public);

            // Deliberate recovery image for hardware testing. This runs before the
            // Trouble host is constructed, so there is no live bond table to keep
            // in sync: the empty persisted snapshot becomes the host's initial
            // state below. Preserve the device's local IRK, matching the normal
            // security-wipe operation.
            #[cfg(feature = "ble-wipe-on-boot")]
            {
                debug_log(format_args!(
                    "ONE-TIME BLE WIPE begin bonds={} pin={}",
                    ble_store.snapshot().bonds.len(),
                    ble_store.snapshot().pin.is_some(),
                ));
                ble_store
                    .clear_security()
                    .await
                    .unwrap_or_else(|_| panic!("one-time ble wipe failed"));
                debug_log(format_args!(
                    "ONE-TIME BLE WIPE complete bonds={} pin={}",
                    ble_store.snapshot().bonds.len(),
                    ble_store.snapshot().pin.is_some(),
                ));
            }
            BLE_BONDS_AT_BOOT.store(ble_store.snapshot().bonds.len() as u8, Ordering::Release);
            BLE_BOND_COUNT.store(ble_store.snapshot().bonds.len() as u8, Ordering::Release);
            PAIRING_MODE.store(
                ble_store.snapshot().bonds.is_empty()
                    || FORCE_PAIRING_AT_BOOT.load(Ordering::Acquire),
                Ordering::Release,
            );

            let sdc_peripherals = sdc::Peripherals::new(
                p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23, p.PPI_CH24,
                p.PPI_CH25, p.PPI_CH26, p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
            );
            if ble_store.snapshot().local_irk.is_none() {
                let mut local_irk = [0u8; 16];
                rng.fill_bytes(&mut local_irk).await;
                if local_irk == [0; 16] {
                    local_irk[0] = 1;
                }
                ble_store
                    .set_local_irk(local_irk)
                    .await
                    .unwrap_or_else(|_| panic!("local irk persist"));
            }
            #[cfg(feature = "ble-store-fault-inject")]
            {
                BLE_STORE_FAULT_ARMED.store(true, Ordering::Release);
                debug_log(format_args!(
                    "STORE FAULT INJECTION ARMED: all runtime writes and erases will fail"
                ));
            }
            // Seed the identity-generation CSPRNG from the TRNG while the
            // peripheral is still ours: build_sdc below hands the RNG to
            // the SoftDevice Controller for its lifetime.
            let mut identity_seed = [0u8; 32];
            rng.fill_bytes(&mut identity_seed).await;
            let identity_rng = <IdentityRng as rand_core::SeedableRng>::from_seed(identity_seed);
            super::panic::breadcrumb_mark(6);
            let controller = build_sdc(sdc_peripherals, &mut rng, mpsl, &mut sdc_memory)
                .unwrap_or_else(|_| panic!("sdc init"));
            super::panic::breadcrumb_mark(7);
            (
                controller,
                ble_store,
                proto_store,
                boot_snapshot,
                identity_store,
                boot_identity,
                identity_rng,
                ux_store,
            )
        };
        #[cfg(feature = "no-ble")]
        let (proto_store, boot_snapshot, identity_store, boot_identity, identity_rng, ux_store): (
            ProtoStore,
            Option<BootSnapshot>,
            ProtoStore,
            Option<[u8; 32]>,
            IdentityRng,
            ProtoStore,
        ) = {
            // No MPSL flash driver, so identity provisioning fails
            // closed; the TRNG peripheral is free in this image and
            // seeds the (unused) generator directly.
            let mut rng = rng::Rng::new(p.RNG, Irqs);
            let mut identity_seed = [0u8; 32];
            rng.fill_bytes(&mut identity_seed).await;
            (
                ProtoStore,
                None,
                ProtoStore,
                None,
                <IdentityRng as rand_core::SeedableRng>::from_seed(identity_seed),
                ProtoStore,
            )
        };

        // ── USB stack ────────────────────────────────────────────────────────
        // HardwareVbusDetect cannot share POWER with MPSL. This tethered NCP
        // treats USB as present/ready; CDC connection state still supplies the
        // protocol attach/detach edges used by advertising arbitration.
        static VBUS: StaticCell<SoftwareVbusDetect> = StaticCell::new();
        let vbus = VBUS.init(SoftwareVbusDetect::new(true, true));
        let driver = Driver::new(p.USBD, Irqs, &*vbus);

        let mut config = Config::new(0x16c0, 0x27dd);
        config.manufacturer = Some("UMSH");
        #[cfg(not(feature = "t1000e"))]
        {
            config.product = Some("T-Echo UMSH NCP");
            config.serial_number = Some("companion-ncp-techo");
        }
        #[cfg(feature = "t1000e")]
        {
            config.product = Some("T-1000E UMSH NCP");
            config.serial_number = Some("companion-ncp-t1000e");
        }
        config.max_power = 100;
        config.max_packet_size_0 = 64;

        static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static MSOS_DESC: StaticCell<[u8; 0]> = StaticCell::new();
        static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
        static STATE: StaticCell<State> = StaticCell::new();

        let mut builder = Builder::new(
            driver,
            config,
            CONFIG_DESC.init([0; 256]),
            BOS_DESC.init([0; 256]),
            MSOS_DESC.init([0; 0]),
            CONTROL_BUF.init([0; 64]),
        );

        let class = CdcAcmClass::new(&mut builder, STATE.init(State::new()), 64);
        let mut usb = builder.build();

        let (tx, raw_rx, ctrl) = class.split_with_control();
        let rx = CdcAcmRescue::new(raw_rx, ctrl);

        spawner.spawn(output_task(tx, wdt_report).unwrap());
        spawner.spawn(usb_in_task(rx).unwrap());
        spawner.spawn(
            ncp_task(
                boot_reason,
                proto_store,
                boot_snapshot,
                identity_store,
                boot_identity,
                identity_rng,
            )
            .unwrap(),
        );
        super::panic::breadcrumb_mark(8);

        // The touch button only controls the e-paper backlight. Menu input is
        // exclusively the side button below.
        #[cfg(not(feature = "t1000e"))]
        {
            let touch = Input::new(p.P0_11, Pull::Up);
            let backlight = Output::new(p.P1_11, Level::Low, OutputDrive::Standard);
            spawner.spawn(touch_task(touch, backlight).unwrap());

            let mut display_config = SpimConfig::default();
            display_config.frequency = Frequency::M4;
            let display_spi = Spim::new(p.SPI2, Irqs, p.P0_31, p.P1_07, p.P0_29, display_config);
            let display_cs = Output::new(p.P0_30, Level::High, OutputDrive::Standard);
            let display_dc = Output::new(p.P0_28, Level::Low, OutputDrive::Standard);
            let display_reset = Output::new(p.P0_02, Level::High, OutputDrive::Standard);
            let display_busy = Input::new(p.P0_03, Pull::None);
            spawner.spawn(
                display_task(
                    display_spi,
                    display_cs,
                    display_dc,
                    display_reset,
                    display_busy,
                )
                .unwrap(),
            );

            let button = Input::new(p.P1_10, Pull::Up);
            spawner.spawn(button_task(button).unwrap());
            spawner.spawn(shutdown_task(peripheral_power).unwrap());
        }

        #[cfg(feature = "t1000e")]
        {
            let mut buzzer_config = SimpleConfig::default();
            buzzer_config.prescaler = Prescaler::Div16;
            let buzzer_pwm = SimplePwm::new_1ch(p.PWM0, p.P0_25, &buzzer_config);
            let buzzer_enable = Output::new(p.P1_05, Level::Low, OutputDrive::Standard);
            let initial_preferences = umsh_bsp_t1000e::preferences::load();
            spawner.spawn(
                t1000e_buzzer_task(buzzer_pwm, buzzer_enable, initial_preferences.silent).unwrap(),
            );
            // The normal power-on chirp is intentional. Early startup already
            // forced both buzzer pins low, so this is the first and only sound.
            umsh_bsp_t1000e::BUZZER_SIGNAL.signal(&buzzer_melodies::POWER_ON);

            let sensor_rail = Output::new(p.P1_06, Level::Low, OutputDrive::Standard);
            let saadc = Saadc::new(
                p.SAADC,
                Irqs,
                SaadcConfig::default(),
                [ChannelConfig::single_ended(p.P0_02)],
            );
            let external_power = Input::new(p.P0_05, Pull::Down);
            let charge_active = Input::new(p.P1_03, Pull::Up);
            spawner.spawn(
                t1000e_power_task(saadc, sensor_rail, external_power, charge_active).unwrap(),
            );
            spawner.spawn(t1000e_button_task(button, force_pairing_at_boot, ux_store).unwrap());
            spawner.spawn(t1000e_shutdown_task().unwrap());
        }

        #[cfg(not(feature = "t1000e"))]
        drop(ux_store);

        super::panic::breadcrumb_mark(9);
        #[cfg(not(feature = "no-ble"))]
        join(ble_app(controller, ble_store), async {
            super::panic::breadcrumb_mark(13);
            usb.run().await
        })
        .await;
        #[cfg(feature = "no-ble")]
        {
            super::panic::breadcrumb_mark(13);
            usb.run().await;
        }
    }

    // ─── Heartbeat + WDT pet ─────────────────────────────────────────────────

    #[cfg(not(feature = "t1000e"))]
    #[embassy_executor::task]
    async fn heartbeat(mut led: Output<'static>, mut wdt: WatchdogHandle) -> ! {
        let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
        loop {
            wdt.pet();
            super::panic::breadcrumb_beat();
            let ble_mode = BLE_LED_MODE.load(Ordering::Acquire);
            if ble_mode != 0 {
                let phase = Instant::now().as_millis() % 2_000;
                let on = if ble_mode == 1 {
                    phase < 100 || (500..600).contains(&phase)
                } else {
                    phase < 100 || (200..300).contains(&phase) || (400..500).contains(&phase)
                };
                #[cfg(not(feature = "t1000e"))]
                if on {
                    led.set_low();
                } else {
                    led.set_high();
                }
                #[cfg(feature = "t1000e")]
                if on {
                    led.set_high();
                } else {
                    led.set_low();
                }
                Timer::after_millis(50).await;
                continue;
            }
            let decision = engine.tick(Instant::now().as_millis());
            // T-Echo P0.14 is active-low; T-1000E P0.24 is active-high.
            if decision.on {
                led.set_low()
            } else {
                led.set_high()
            }
            Timer::at(Instant::from_millis(decision.next_deadline_ms)).await;
        }
    }

    #[cfg(feature = "t1000e")]
    #[embassy_executor::task]
    async fn heartbeat(mut led: SimplePwm<'static>, mut wdt: WatchdogHandle) -> ! {
        led.set_period(1_000);
        led.enable();
        let mut engine = T1000eLedEngine::new(Instant::now().as_millis());
        loop {
            wdt.pet();
            super::panic::breadcrumb_beat();
            let battery = umsh_bsp_t1000e::battery_state();
            engine.set_battery(battery);
            engine.set_attention(umsh_bsp_t1000e::indicator::attention_requested());

            let ble_mode = BLE_LED_MODE.load(Ordering::Acquire);
            if ble_mode != 0
                && matches!(
                    battery,
                    umsh_ux_tracker::battery::BatteryState::BatteryOnly
                        | umsh_ux_tracker::battery::BatteryState::BatteryCharged
                )
            {
                let phase = Instant::now().as_millis() % 2_000;
                let on = if ble_mode == 1 {
                    phase < 100 || (500..600).contains(&phase)
                } else {
                    phase < 100 || (200..300).contains(&phase) || (400..500).contains(&phase)
                };
                let duty = if on { led.max_duty() } else { 0 };
                led.set_duty(0, DutyCycle::inverted(duty));
                Timer::after_millis(50).await;
                continue;
            }

            let decision = engine.tick(Instant::now().as_millis());
            let duty =
                ((u32::from(led.max_duty()) * u32::from(decision.brightness)) / 1_000) as u16;
            led.set_duty(0, DutyCycle::inverted(duty));
            match select4(
                Timer::at(Instant::from_millis(decision.next_deadline_ms)),
                umsh_bsp_t1000e::BATTERY_STATE_CHANGED.wait(),
                umsh_bsp_t1000e::indicator::INDICATOR_CHANGED.wait(),
                umsh_bsp_t1000e::indicator::LED_SEQUENCE_SIGNAL.wait(),
            )
            .await
            {
                Either4::First(()) | Either4::Second(_) | Either4::Third(()) => {}
                Either4::Fourth(sequence) => {
                    engine.play(sequence, Instant::now().as_millis());
                }
            }
        }
    }
}
