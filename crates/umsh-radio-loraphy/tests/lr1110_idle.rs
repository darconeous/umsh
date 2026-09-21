//! Exercise the pinned LR1110 driver, including BUSY remaining high in sleep.
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_hal_async::{
    delay::DelayNs,
    spi::{ErrorKind, ErrorType, Operation, SpiDevice},
};
use lora_phy::{
    LoRa,
    lr1110::{Config, Lr1110, TcxoCtrlVoltage, variant::Lr1110 as Lr1110Chip},
    mod_params::{Bandwidth, CodingRate, RadioError, SpreadingFactor},
    mod_traits::InterfaceVariant,
};
use std::{cell::RefCell, rc::Rc};
use umsh_radio_loraphy::{Channels, DeviceControl, DeviceSettings, RxStrategy, device_runner};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Standby,
    Receiving,
    Transmitting,
    Sleeping,
}
#[derive(Default)]
struct Chip {
    mode: Mode,
    commands: Vec<Vec<u8>>,
}
struct Bus(Rc<RefCell<Chip>>);
impl ErrorType for Bus {
    type Error = ErrorKind;
}
impl SpiDevice for Bus {
    async fn transaction(&mut self, ops: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        let mut chip = self.0.borrow_mut();
        if matches!(ops, [Operation::Read(bytes)] if bytes.len() == 1) {
            // The LR1110 wake helper pulses NSS with a dummy one-byte read.
            chip.mode = Mode::Standby;
        }
        if let Some(Operation::Write(command)) = ops.first() {
            assert_ne!(
                chip.mode,
                Mode::Sleeping,
                "a sleeping LR1110 needs an NSS wake pulse"
            );
            chip.commands.push(command.to_vec());
            match command.get(..2) {
                Some([0x01, 0x1b]) => chip.mode = Mode::Sleeping,
                Some([0x01, 0x1c]) => chip.mode = Mode::Standby,
                Some([0x02, 0x09]) => chip.mode = Mode::Receiving,
                Some([0x02, 0x0a]) => chip.mode = Mode::Transmitting,
                _ => (),
            }
        }
        for op in ops {
            match op {
                Operation::Read(bytes)
                | Operation::Transfer(bytes, _)
                | Operation::TransferInPlace(bytes) => bytes.fill(0),
                _ => (),
            }
        }
        Ok(())
    }
}
struct Pins(Rc<RefCell<Chip>>);
impl InterfaceVariant for Pins {
    async fn reset(&mut self, _: &mut impl DelayNs) -> Result<(), RadioError> {
        self.0.borrow_mut().mode = Mode::Standby;
        Ok(())
    }
    async fn wait_on_busy(&mut self) -> Result<(), RadioError> {
        if self.0.borrow().mode == Mode::Sleeping {
            core::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn await_irq(&mut self) -> Result<(), RadioError> {
        core::future::pending().await
    }
    async fn enable_rf_switch_rx(&mut self) -> Result<(), RadioError> {
        Ok(())
    }
    async fn enable_rf_switch_tx(&mut self) -> Result<(), RadioError> {
        Ok(())
    }
    async fn disable_rf_switch(&mut self) -> Result<(), RadioError> {
        Ok(())
    }
}
struct Delay;
impl DelayNs for Delay {
    async fn delay_ns(&mut self, _: u32) {}
}
fn poll<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}
fn settings(enabled: bool) -> DeviceSettings {
    DeviceSettings {
        enabled,
        freq_hz: 917_500_000,
        sf: SpreadingFactor::_7,
        bw: Bandwidth::_62KHz,
        cr: CodingRate::_4_8,
        power_dbm: 22,
    }
}
fn fixture(
    chip: Rc<RefCell<Chip>>,
) -> (
    LoRa<Lr1110<Bus, Pins, Lr1110Chip>, Delay>,
    &'static Channels<NoopRawMutex, 4, 2>,
    &'static DeviceControl<NoopRawMutex>,
) {
    let kind = Lr1110::new(
        Bus(chip.clone()),
        Pins(chip),
        Config {
            chip: Lr1110Chip::default(),
            tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V6),
            use_dcdc: false,
            rx_boost: true,
            rf_switch: None,
        },
    );
    let Poll::Ready(Ok(lora)) = poll(core::pin::pin!(LoRa::new(kind, false, Delay))) else {
        panic!("initialization must complete");
    };
    (
        lora,
        Box::leak(Box::new(Channels::new())),
        Box::leak(Box::new(DeviceControl::new())),
    )
}

#[test]
fn lr1110_reaches_rx_after_boot_settings_arrive() {
    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    let mut runner = core::pin::pin!(device_runner(
        lora,
        channel,
        control,
        16,
        32,
        RxStrategy::Continuous,
        None
    ));
    assert!(poll(runner.as_mut()).is_pending());
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Receiving);
}

#[test]
fn lr1110_disable_reenable_and_shutdown_use_cold_sleep() {
    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    let mut runner = core::pin::pin!(device_runner(
        lora,
        channel,
        control,
        16,
        32,
        RxStrategy::Continuous,
        None
    ));
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Sleeping);
    for _ in 0..3 {
        control.apply(settings(true));
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(chip.borrow().mode, Mode::Receiving);
        control.apply(settings(false));
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(chip.borrow().mode, Mode::Sleeping);
        let count = chip.borrow().commands.len();
        control.apply(settings(false));
        control.request_rssi();
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(
            poll(core::pin::pin!(control.wait_rssi())),
            Poll::Ready(Err(()))
        );
        assert_eq!(chip.borrow().commands.len(), count);
    }
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());
    control.shutdown();
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(
        poll(core::pin::pin!(control.wait_shutdown())),
        Poll::Ready(())
    );
    assert_eq!(chip.borrow().mode, Mode::Sleeping);
    assert!(
        chip.borrow()
            .commands
            .iter()
            .any(|c| c.starts_with(&[0x01, 0x1b]))
    );
}

#[test]
fn lr1110_can_start_a_transmission_after_reenable() {
    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    let mut runner = core::pin::pin!(device_runner(
        lora,
        channel,
        control,
        16,
        32,
        RxStrategy::Continuous,
        None
    ));
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());
    control.apply(settings(false));
    assert!(poll(runner.as_mut()).is_pending());
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());
    assert!(
        channel
            .tx
            .try_send(umsh_radio_loraphy::TxRequest {
                data: heapless::Vec::from_slice(&[1, 2, 3]).unwrap(),
                power_dbm: None,
                cad: umsh_hal::CadPolicy::Skip,
            })
            .is_ok()
    );
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Transmitting);
}
