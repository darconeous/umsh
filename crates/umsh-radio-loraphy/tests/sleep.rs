//! Exercise the real runner and pinned SX1262 driver against a recording bus.
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use std::{cell::RefCell, rc::Rc};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_hal_async::{
    delay::DelayNs,
    spi::{ErrorKind, ErrorType, Operation, SpiDevice},
};
use lora_phy::{
    LoRa,
    mod_params::{Bandwidth, CodingRate, RadioError, SpreadingFactor},
    mod_traits::InterfaceVariant,
    sx126x::{Config, Sx126x, Sx1262, TcxoCtrlVoltage},
};
use umsh_radio_loraphy::{Channels, DeviceControl, DeviceSettings, RxStrategy, device_runner};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Standby,
    Receiving,
    Sleeping,
}

#[derive(Default)]
struct Chip {
    mode: Mode,
    commands: Vec<Vec<u8>>,
    sleep_failures: usize,
}

struct Bus(Rc<RefCell<Chip>>);
impl ErrorType for Bus {
    type Error = ErrorKind;
}
impl SpiDevice for Bus {
    async fn transaction(
        &mut self,
        operations: &mut [Operation<'_, u8>],
    ) -> Result<(), Self::Error> {
        let mut chip = self.0.borrow_mut();
        if let Some(Operation::Write(command)) = operations.first() {
            let opcode = command[0];
            if chip.mode == Mode::Sleeping {
                assert_eq!(opcode, 0xc0, "sleeping SX1262 needs its wake pulse first");
                chip.mode = Mode::Standby;
            }
            chip.commands.push(command.to_vec());
            match opcode {
                0x80 => chip.mode = Mode::Standby,
                0x82 => chip.mode = Mode::Receiving,
                0x84 => {
                    assert_eq!(chip.mode, Mode::Standby, "SetSleep requires standby");
                    if chip.sleep_failures != 0 {
                        chip.sleep_failures -= 1;
                        return Err(ErrorKind::Other);
                    }
                    chip.mode = Mode::Sleeping;
                }
                _ => (),
            }
        }
        for operation in operations {
            match operation {
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
        assert_ne!(
            self.0.borrow().mode,
            Mode::Sleeping,
            "BUSY stays high asleep"
        );
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

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn settings(enabled: bool) -> DeviceSettings {
    DeviceSettings {
        enabled,
        freq_hz: 917_500_000,
        sf: SpreadingFactor::_10,
        bw: Bandwidth::_500KHz,
        cr: CodingRate::_4_5,
        power_dbm: 22,
    }
}

fn fixture(
    chip: Rc<RefCell<Chip>>,
) -> (
    LoRa<Sx126x<Bus, Pins, Sx1262>, Delay>,
    &'static Channels<NoopRawMutex, 4, 2>,
    &'static DeviceControl<NoopRawMutex>,
) {
    let kind = Sx126x::new(
        Bus(chip.clone()),
        Pins(chip),
        Config {
            chip: Sx1262,
            tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl3V0),
            use_dcdc: true,
            rx_boost: true,
        },
    );
    let lora = match poll(core::pin::pin!(LoRa::new(kind, false, Delay))) {
        Poll::Ready(Ok(lora)) => lora,
        _ => panic!("mock initialization should finish synchronously"),
    };
    (
        lora,
        Box::leak(Box::new(Channels::new())),
        Box::leak(Box::new(DeviceControl::new())),
    )
}

#[test]
fn disabled_radio_sleeps_without_polling_and_reenable_restores_rx() {
    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    let mut runner = core::pin::pin!(device_runner(
        lora,
        channel,
        control,
        8,
        32,
        RxStrategy::Continuous,
        None
    ));
    // A bare boot must sleep too, before the first configuration arrives.
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Sleeping);
    for _ in 0..3 {
        control.apply(settings(true));
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(chip.borrow().mode, Mode::Receiving);
        // Re-enable restores the configured TCXO and RF frequency after cold sleep.
        {
            let commands = &chip.borrow().commands;
            let wake = commands.iter().rposition(|cmd| cmd[0] == 0xc0).unwrap();
            assert!(commands[wake..].iter().any(|cmd| cmd[0] == 0x97));
            assert!(commands[wake..].iter().any(|cmd| cmd[0] == 0x86));
        }

        control.apply(settings(false));
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(chip.borrow().mode, Mode::Sleeping);
        let count = chip.borrow().commands.len();
        assert_eq!(
            &chip.borrow().commands[count - 3..],
            &[vec![0x80, 0], vec![0x02, 0xff, 0xff], vec![0x84, 0]]
        );
        // Repeated disable and RSSI requests cannot wake or poll the chip.
        control.apply(settings(false));
        control.request_rssi();
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(
            poll(core::pin::pin!(control.wait_rssi())),
            Poll::Ready(Err(()))
        );
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(chip.borrow().commands.len(), count);
    }
    let count = chip.borrow().commands.len();
    control.shutdown();
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(
        poll(core::pin::pin!(control.wait_shutdown())),
        Poll::Ready(())
    );
    assert_eq!(chip.borrow().commands.len(), count);
}

#[test]
fn sleep_recovery_is_bounded_and_retries_on_the_next_configuration() {
    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    chip.borrow_mut().sleep_failures = 3;
    let mut runner = core::pin::pin!(device_runner(
        lora,
        channel,
        control,
        8,
        32,
        RxStrategy::Continuous,
        None
    ));
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Standby);
    assert_eq!(
        chip.borrow()
            .commands
            .iter()
            .filter(|cmd| cmd[0] == 0x84)
            .count(),
        3
    );
    let count = chip.borrow().commands.len();
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().commands.len(), count);
    control.apply(settings(false));
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Sleeping);
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Receiving);
    chip.borrow_mut().sleep_failures = 1;
    control.shutdown();
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Sleeping);
    assert_eq!(
        poll(core::pin::pin!(control.wait_shutdown())),
        Poll::Ready(())
    );
}
