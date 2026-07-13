//! T-Echo BLE coexistence and security spike.
//!
//! The companion echo service is encrypted and additionally rejects dynamic
//! GATT operations from peers that are not bonded. New pairing is enabled for
//! the first 20 seconds after boot, then disabled through UMSH's Trouble fork.
//! USB CDC echoes packets concurrently; the SX1262 and watchdog stay active.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
use panic_halt as _;

// lora-phy currently links defmt 0.3 even when no transport is selected.
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
    use core::future::pending;

    use embassy_executor::Spawner;
    use embassy_futures::join::join;
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
    use embassy_nrf::mode::Async;
    use embassy_nrf::peripherals::{self, RNG};
    use embassy_nrf::rng;
    use embassy_nrf::spim::{Config as SpimConfig, Frequency, Spim};
    use embassy_nrf::usb::Driver;
    use embassy_nrf::usb::vbus_detect::SoftwareVbusDetect;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_time::{Delay, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};
    use embedded_hal_bus::spi::ExclusiveDevice;
    use lora_phy::LoRa;
    use lora_phy::iv::GenericSx126xInterfaceVariant;
    use lora_phy::sx126x::{Config as LoraConfig, Sx126x, Sx1262, TcxoCtrlVoltage};
    use nrf_sdc::mpsl::{self, MultiprotocolServiceLayer};
    use nrf_sdc::{self as sdc};
    use static_cell::StaticCell;
    use trouble_host::prelude::*;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_companion::gatt;

    bind_interrupts!(struct Irqs {
        RNG => rng::InterruptHandler<RNG>;
        EGU0_SWI0 => nrf_sdc::mpsl::LowPrioInterruptHandler;
        CLOCK_POWER => nrf_sdc::mpsl::ClockInterruptHandler;
        RADIO => nrf_sdc::mpsl::HighPrioInterruptHandler;
        TIMER0 => nrf_sdc::mpsl::HighPrioInterruptHandler;
        RTC0 => nrf_sdc::mpsl::HighPrioInterruptHandler;
        USBD => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        TWISPI1 => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI1>;
    });

    type UsbDriver = Driver<'static, &'static SoftwareVbusDetect>;
    type UsbSender = embassy_usb::class::cdc_acm::Sender<'static, UsbDriver>;
    type UsbRescue = CdcAcmRescue<'static, UsbDriver>;
    type RadioSpiBus = ExclusiveDevice<Spim<'static>, Output<'static>, Delay>;
    type RadioIv = GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>;
    type Radio = LoRa<Sx126x<RadioSpiBus, RadioIv, Sx1262>, Delay>;

    const CONNECTIONS_MAX: usize = 1;
    const L2CAP_CHANNELS_MAX: usize = 2;
    const L2CAP_TXQ: u8 = 3;
    const L2CAP_RXQ: u8 = 3;
    const SDC_PACKET_SIZE: u16 = 251;

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
            .buffer_cfg(SDC_PACKET_SIZE, SDC_PACKET_SIZE, L2CAP_TXQ, L2CAP_RXQ)?
            .build(p, rng, mpsl, mem)
    }

    #[embassy_executor::task]
    async fn mpsl_task(mpsl: &'static MultiprotocolServiceLayer<'static>) -> ! {
        mpsl.run().await
    }

    async fn usb_echo(mut tx: UsbSender, mut rx: UsbRescue) -> ! {
        loop {
            rx.wait_connection().await;
            loop {
                let mut packet = [0u8; 64];
                match rx.read_packet(&mut packet).await {
                    Ok(0) | Err(_) => break,
                    Ok(len) if tx.write_packet(&packet[..len]).await.is_err() => break,
                    Ok(_) => {}
                }
            }
        }
    }

    async fn heartbeat(mut led: Output<'static>, mut watchdog: WatchdogHandle) -> ! {
        loop {
            watchdog.pet();
            led.set_low();
            Timer::after_millis(40).await;
            led.set_high();
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
        Timer::after_secs(20).await;
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
        const SERVICE_UUID_LE: [u8; 16] = gatt::SERVICE_UUID.to_le_bytes();
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
            &[AdStructure::CompleteLocalName(b"UMSH BLE Spike")],
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

    async fn ble_app<C: Controller>(controller: C, pin_mode: bool) -> ! {
        let mut resources: HostResources<
            _,
            DefaultPacketPool,
            CONNECTIONS_MAX,
            L2CAP_CHANNELS_MAX,
        > = HostResources::new();
        let io_capabilities = if pin_mode {
            IoCapabilities::DisplayOnly
        } else {
            IoCapabilities::NoInputNoOutput
        };
        let stack = trouble_host::new(controller, &mut resources)
            .set_random_address(Address::random([0x55, 0x4d, 0x53, 0x48, 0x00, 0x01]))
            .set_io_capabilities(io_capabilities)
            .set_pairing_enabled(true)
            .set_fixed_passkey(pin_mode.then_some(123_456))
            .unwrap()
            .build();
        let runner = stack.runner();
        let mut peripheral = stack.peripheral();
        let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
            name: "UMSH BLE Spike",
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

    async fn hold_radio(_radio: Radio) -> ! {
        pending().await
    }

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::ble_config());
        let _power = Output::new(p.P0_12, Level::High, OutputDrive::Standard);

        let mut watchdog_config = WdtConfig::default();
        watchdog_config.timeout_ticks = 32768 * 8;
        let (_watchdog, [watchdog_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, watchdog_config).unwrap();
        let button = Input::new(p.P1_10, Pull::Up);
        let pin_mode = button.is_low();
        drop(button);

        let mut spi_config = SpimConfig::default();
        spi_config.frequency = Frequency::M16;
        let spi = Spim::new(p.TWISPI1, Irqs, p.P0_19, p.P0_23, p.P0_22, spi_config);
        let device = ExclusiveDevice::new(
            spi,
            Output::new(p.P0_24, Level::High, OutputDrive::Standard),
            Delay,
        )
        .unwrap();
        let interface = GenericSx126xInterfaceVariant::new(
            Output::new(p.P0_25, Level::High, OutputDrive::Standard),
            Input::new(p.P0_20, Pull::None),
            Input::new(p.P0_17, Pull::None),
            None,
            None,
        )
        .unwrap();
        let radio = LoRa::new(
            Sx126x::new(
                device,
                interface,
                LoraConfig {
                    chip: Sx1262,
                    tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8),
                    use_dcdc: true,
                    rx_boost: true,
                },
            ),
            false,
            Delay,
        )
        .await
        .unwrap();

        let mpsl_peripherals =
            mpsl::Peripherals::new(p.RTC0, p.TIMER0, p.TEMP, p.PPI_CH19, p.PPI_CH30, p.PPI_CH31);
        let lfclk = mpsl::raw::mpsl_clock_lfclk_cfg_t {
            source: mpsl::raw::MPSL_CLOCK_LF_SRC_XTAL as u8,
            rc_ctiv: 0,
            rc_temp_ctiv: 0,
            accuracy_ppm: 20,
            skip_wait_lfclk_started: false,
        };
        static MPSL: StaticCell<MultiprotocolServiceLayer> = StaticCell::new();
        let mpsl =
            MPSL.init(MultiprotocolServiceLayer::new(mpsl_peripherals, Irqs, lfclk).unwrap());
        spawner.spawn(mpsl_task(mpsl).unwrap());

        let sdc_peripherals = sdc::Peripherals::new(
            p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23, p.PPI_CH24,
            p.PPI_CH25, p.PPI_CH26, p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
        );
        let mut rng = rng::Rng::new(p.RNG, Irqs);
        let mut sdc_memory = sdc::Mem::<8192>::new();
        let controller = build_sdc(sdc_peripherals, &mut rng, mpsl, &mut sdc_memory).unwrap();

        // MPSL owns CLOCK/POWER. The spike is USB-powered, so use the
        // software detector in the permanently-present/ready state.
        static VBUS: StaticCell<SoftwareVbusDetect> = StaticCell::new();
        let vbus = VBUS.init(SoftwareVbusDetect::new(true, true));
        let usb_driver = Driver::new(p.USBD, Irqs, &*vbus);
        let mut usb_config = UsbConfig::new(0x16c0, 0x27de);
        usb_config.manufacturer = Some("UMSH");
        usb_config.product = Some("T-Echo BLE Spike");
        usb_config.serial_number = Some("ble-spike-techo");
        usb_config.max_packet_size_0 = 64;

        static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static MSOS_DESC: StaticCell<[u8; 0]> = StaticCell::new();
        static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
        static CDC_STATE: StaticCell<State> = StaticCell::new();
        let mut usb_builder = UsbBuilder::new(
            usb_driver,
            usb_config,
            CONFIG_DESC.init([0; 256]),
            BOS_DESC.init([0; 256]),
            MSOS_DESC.init([]),
            CONTROL_BUF.init([0; 64]),
        );
        let cdc = CdcAcmClass::new(&mut usb_builder, CDC_STATE.init(State::new()), 64);
        let mut usb = usb_builder.build();
        let (tx, raw_rx, ctrl) = cdc.split_with_control();
        let rx = CdcAcmRescue::new(raw_rx, ctrl);
        let led = Output::new(p.P0_14, Level::High, OutputDrive::Standard);

        join(
            ble_app(controller, pin_mode),
            join(
                usb.run(),
                join(
                    usb_echo(tx, rx),
                    join(heartbeat(led, watchdog_handle), hold_radio(radio)),
                ),
            ),
        )
        .await;
    }
}
