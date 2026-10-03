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
use umsh_radio_loraphy::{device_runner_with_temperature, temperature::Lr1110Temperature};

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
    fail_temperature: bool,
    temperature_response: bool,
}
struct Bus(Rc<RefCell<Chip>>);
impl ErrorType for Bus {
    type Error = ErrorKind;
}
impl SpiDevice for Bus {
    async fn transaction(&mut self, ops: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        let mut chip = self.0.borrow_mut();
        let temperature = matches!(ops.first(), Some(Operation::Write([0x01, 0x1a])));
        if temperature && chip.fail_temperature {
            return Err(ErrorKind::Other);
        }
        if matches!(ops, [Operation::Read(bytes)] if bytes.len() == 1) {
            // The LR1110 wake helper pulses NSS with a dummy one-byte read.
            chip.mode = Mode::Standby;
        }
        if let Some(Operation::Write(command)) = ops.first() {
            chip.temperature_response = temperature;
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
        for (index, op) in ops.iter_mut().enumerate() {
            match op {
                Operation::Read(bytes)
                | Operation::Transfer(bytes, _)
                | Operation::TransferInPlace(bytes) => {
                    bytes.fill(0);
                    if chip.temperature_response && index == 1 {
                        assert_eq!(chip.mode, Mode::Standby);
                        bytes.copy_from_slice(&1106u16.to_be_bytes());
                        chip.temperature_response = false;
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }
}

#[test]
fn lr1110_temperature_is_fresh_restores_rx_and_never_wakes_disabled_radio() {
    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    let mut runner = core::pin::pin!(device_runner_with_temperature(
        lora,
        channel,
        control,
        16,
        32,
        RxStrategy::Continuous,
        None,
        Lr1110Temperature,
    ));
    assert!(poll(runner.as_mut()).is_pending());
    let count = chip.borrow().commands.len();
    {
        let mut request = core::pin::pin!(control.sample_temperature());
        assert!(poll(request.as_mut()).is_pending());
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(poll(request.as_mut()), Poll::Ready(None));
    }
    assert_eq!(chip.borrow().commands.len(), count);
    assert_eq!(chip.borrow().mode, Mode::Sleeping);
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());
    for failure in [false, false, true, false] {
        chip.borrow_mut().fail_temperature = failure;
        let mut request = core::pin::pin!(control.sample_temperature());
        assert!(poll(request.as_mut()).is_pending());
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(
            poll(request.as_mut()),
            Poll::Ready(if failure { None } else { Some(2982) })
        );
        assert_eq!(chip.borrow().mode, Mode::Receiving);
    }
    assert_eq!(
        chip.borrow()
            .commands
            .iter()
            .filter(|c| c.starts_with(&[0x01, 0x1a]))
            .count(),
        3
    );
    control.apply(settings(false));
    assert!(poll(runner.as_mut()).is_pending());
    let count = chip.borrow().commands.len();
    let mut request = core::pin::pin!(control.sample_temperature());
    assert!(poll(request.as_mut()).is_pending());
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(poll(request.as_mut()), Poll::Ready(None));
    assert_eq!(chip.borrow().commands.len(), count);
    assert_eq!(chip.borrow().mode, Mode::Sleeping);
    control.shutdown();
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(
        poll(core::pin::pin!(control.sample_temperature())),
        Poll::Ready(None)
    );
}

#[test]
fn lr1110_canceled_temperature_reply_is_not_reused() {
    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    let mut runner = core::pin::pin!(device_runner_with_temperature(
        lora,
        channel,
        control,
        16,
        32,
        RxStrategy::Continuous,
        None,
        Lr1110Temperature,
    ));
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());
    assert!(poll(core::pin::pin!(control.sample_temperature())).is_pending()); // dropped
    assert!(poll(runner.as_mut()).is_pending()); // late success
    chip.borrow_mut().fail_temperature = true;
    let mut request = core::pin::pin!(control.sample_temperature());
    assert!(poll(request.as_mut()).is_pending());
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(poll(request.as_mut()), Poll::Ready(None));
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
