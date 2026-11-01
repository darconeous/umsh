//! Exercise the real runner and pinned SX1262 driver against a recording bus.
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

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
use umsh_hal::{CadPolicy, Clock};
use umsh_radio_loraphy::{
    Channels, DeviceControl, DeviceSettings, RxStrategy, TxError, TxRequest, device_runner,
};
use umsh_ulcp::stats::{Counter, StatsLedger};

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
    sleep_failures: usize,
    /// IRQ flags latched for the next `GetIrqStatus`; DIO1 is high while
    /// any are set.
    irq_flags: u16,
    /// BUSY is stuck high until the next reset.
    busy_stuck: bool,
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
                0x02 => chip.irq_flags = 0,
                0x80 => chip.mode = Mode::Standby,
                0x82 => chip.mode = Mode::Receiving,
                0x83 => chip.mode = Mode::Transmitting,
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
        let irq_status = matches!(operations.first(), Some(Operation::Write([0x12])));
        for (index, operation) in operations.iter_mut().enumerate() {
            match operation {
                Operation::Read(bytes)
                | Operation::Transfer(bytes, _)
                | Operation::TransferInPlace(bytes) => {
                    bytes.fill(0);
                    // GetIrqStatus: opcode, status byte, then the flags.
                    if irq_status && index == 2 {
                        bytes.copy_from_slice(&chip.irq_flags.to_be_bytes());
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }
}

struct Pins(Rc<RefCell<Chip>>);
impl InterfaceVariant for Pins {
    async fn reset(&mut self, _: &mut impl DelayNs) -> Result<(), RadioError> {
        let mut chip = self.0.borrow_mut();
        chip.mode = Mode::Standby;
        chip.busy_stuck = false;
        Ok(())
    }
    async fn wait_on_busy(&mut self) -> Result<(), RadioError> {
        assert_ne!(
            self.0.borrow().mode,
            Mode::Sleeping,
            "BUSY stays high asleep"
        );
        core::future::poll_fn(|_| {
            if self.0.borrow().busy_stuck {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        })
        .await
    }
    async fn await_irq(&mut self) -> Result<(), RadioError> {
        core::future::poll_fn(|_| {
            if self.0.borrow().irq_flags != 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await
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

#[derive(Clone, Default)]
struct TestClock(Rc<Cell<u64>>);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.get()
    }
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
        None,
        TestClock::default(),
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
        None,
        TestClock::default(),
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

fn tx_request() -> TxRequest {
    TxRequest {
        data: heapless::Vec::from_slice(&[1, 2, 3]).unwrap(),
        power_dbm: None,
        cad: CadPolicy::Skip,
    }
}

/// A disabled radio refuses transmits at once rather than leaving them
/// queued, without waking the chip, and transmits again once re-enabled.
#[test]
fn disabled_radio_refuses_transmits_without_waking() {
    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    let mut runner = core::pin::pin!(device_runner(
        lora,
        channel,
        control,
        8,
        32,
        RxStrategy::Continuous,
        None,
        TestClock::default(),
    ));
    // Before the first configuration, and after an explicit disable.
    for enabled in [None, Some(false)] {
        if let Some(enabled) = enabled {
            control.apply(settings(true));
            assert!(poll(runner.as_mut()).is_pending());
            control.apply(settings(enabled));
        }
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(chip.borrow().mode, Mode::Sleeping);
        let count = chip.borrow().commands.len();
        for _ in 0..3 {
            assert!(channel.tx.try_send(tx_request()).is_ok());
            assert!(poll(runner.as_mut()).is_pending());
            assert!(matches!(
                poll(core::pin::pin!(channel.tx_done.wait())),
                Poll::Ready(Err(TxError::CadTimeout))
            ));
        }
        assert_eq!(chip.borrow().commands.len(), count);
        assert_eq!(chip.borrow().mode, Mode::Sleeping);
    }
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());
    assert!(channel.tx.try_send(tx_request()).is_ok());
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Transmitting);
}

/// A detected preamble holds off transmits for one maximum-length frame
/// time, however often they are retried, and no longer.
#[test]
fn preamble_refuses_transmits_until_a_max_frame_could_have_ended() {
    const PREAMBLE_DETECTED: u16 = 0x0004;
    // SF10/500 kHz/CR 4/5 with a 32-symbol preamble and a 255-byte
    // payload is on the air for 623.104 ms.
    const WINDOW_MS: u64 = 624;

    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    let clock = TestClock::default();
    let mut runner = core::pin::pin!(device_runner(
        lora,
        channel,
        control,
        8,
        32,
        RxStrategy::Continuous,
        None,
        clock.clone(),
    ));
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Receiving);

    clock.0.set(1_000);
    chip.borrow_mut().irq_flags = PREAMBLE_DETECTED;
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().irq_flags, 0, "the runner clears the IRQ");

    // Five refusals, more than any fixed retry budget would allow.
    for now in [1_000, 1_050, 1_200, 1_400, 1_000 + WINDOW_MS - 1] {
        clock.0.set(now);
        assert!(channel.tx.try_send(tx_request()).is_ok());
        assert!(poll(runner.as_mut()).is_pending());
        assert!(
            matches!(
                poll(core::pin::pin!(channel.tx_done.wait())),
                Poll::Ready(Err(TxError::CadTimeout))
            ),
            "refused at {now}"
        );
        assert_eq!(chip.borrow().mode, Mode::Receiving, "RX kept at {now}");
    }

    // The preamble never became a frame: once one could no longer be on
    // the air, the stale detection stops blocking.
    clock.0.set(1_000 + WINDOW_MS);
    assert!(channel.tx.try_send(tx_request()).is_ok());
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Transmitting);
}

/// A transmit the chip never completes fails once its deadline passes,
/// and the runner cold-starts the chip and goes back to receiving.
#[test]
fn transmit_without_completion_times_out_and_cold_starts_the_chip() {
    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    let clock = TestClock::default();
    let stats: &'static StatsLedger = Box::leak(Box::new(StatsLedger::new()));
    let mut runner = core::pin::pin!(device_runner(
        lora,
        channel,
        control,
        8,
        32,
        RxStrategy::Continuous,
        Some(stats),
        clock.clone(),
    ));
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());

    // No TX-done IRQ ever arrives. Well inside the deadline the runner
    // keeps waiting.
    assert!(channel.tx.try_send(tx_request()).is_ok());
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Transmitting);
    clock.0.set(200);
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(poll(core::pin::pin!(channel.tx_done.wait())), Poll::Pending);

    let set_tx = chip.borrow().commands.len();
    clock.0.set(10_000);
    assert!(poll(runner.as_mut()).is_pending());
    assert!(matches!(
        poll(core::pin::pin!(channel.tx_done.wait())),
        Poll::Ready(Err(TxError::Io(RadioError::TransmitTimeout)))
    ));
    // The cold start restores the TCXO mode a refused SetTx can clear.
    assert!(
        chip.borrow().commands[set_tx..]
            .iter()
            .any(|cmd| cmd[0] == 0x97)
    );
    assert_eq!(chip.borrow().mode, Mode::Receiving);
    assert_eq!(stats.get(Counter::RadioResets), 1);

    assert!(channel.tx.try_send(tx_request()).is_ok());
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Transmitting);
}

/// A chip that holds BUSY high after a receive IRQ is reset once the IRQ
/// read outlasts a whole frame, the reset is counted, and the runner goes
/// back to receiving and transmitting.
#[test]
fn busy_stuck_after_a_receive_irq_resets_the_chip() {
    const RX_DONE: u16 = 0x0002;

    let chip = Rc::new(RefCell::new(Chip::default()));
    let (lora, channel, control) = fixture(chip.clone());
    let clock = TestClock::default();
    let stats: &'static StatsLedger = Box::leak(Box::new(StatsLedger::new()));
    let mut runner = core::pin::pin!(device_runner(
        lora,
        channel,
        control,
        8,
        32,
        RxStrategy::Continuous,
        Some(stats),
        clock.clone(),
    ));
    control.apply(settings(true));
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Receiving);

    {
        let mut chip = chip.borrow_mut();
        chip.irq_flags = RX_DONE;
        chip.busy_stuck = true;
    }
    assert!(poll(runner.as_mut()).is_pending());
    // A frame can legitimately keep BUSY high this long.
    clock.0.set(800);
    assert!(poll(runner.as_mut()).is_pending());
    assert!(chip.borrow().busy_stuck, "not reset inside a frame time");
    assert_eq!(stats.get(Counter::RadioResets), 0);

    clock.0.set(2_000);
    assert!(poll(runner.as_mut()).is_pending());
    assert!(!chip.borrow().busy_stuck);
    assert_eq!(chip.borrow().mode, Mode::Receiving);
    assert_eq!(stats.get(Counter::RadioResets), 1);

    assert!(channel.tx.try_send(tx_request()).is_ok());
    assert!(poll(runner.as_mut()).is_pending());
    assert_eq!(chip.borrow().mode, Mode::Transmitting);
}
