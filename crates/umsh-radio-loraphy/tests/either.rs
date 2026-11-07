//! The real runner drives either chip through one `EitherRadioKind`.
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
    lr1110::{self, Lr1110, variant::Lr1121},
    mod_params::{Bandwidth, CodingRate, RadioError, SpreadingFactor},
    mod_traits::InterfaceVariant,
    sx126x::{self, Sx126x, Sx1262},
};
use umsh_radio_loraphy::{
    Channels, DeviceControl, DeviceSettings, EitherRadioKind, RxStrategy, TxRequest, device_runner,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Standby,
    Receiving,
    Transmitting,
    Sleeping,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Sx126x,
    Lr11xx,
}

struct Chip {
    family: Family,
    mode: Mode,
}

struct Bus(Rc<RefCell<Chip>>);
impl ErrorType for Bus {
    type Error = ErrorKind;
}
impl SpiDevice for Bus {
    async fn transaction(&mut self, ops: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        let mut chip = self.0.borrow_mut();
        match chip.family {
            Family::Sx126x => {
                if let Some(Operation::Write(command)) = ops.first() {
                    match command[0] {
                        0x80 => chip.mode = Mode::Standby,
                        0x82 => chip.mode = Mode::Receiving,
                        0x83 => chip.mode = Mode::Transmitting,
                        0x84 => chip.mode = Mode::Sleeping,
                        // Any command wakes a sleeping SX126x.
                        _ if chip.mode == Mode::Sleeping => chip.mode = Mode::Standby,
                        _ => (),
                    }
                }
            }
            Family::Lr11xx => {
                if matches!(ops, [Operation::Read(bytes)] if bytes.len() == 1) {
                    // The NSS wake pulse.
                    chip.mode = Mode::Standby;
                }
                if let Some(Operation::Write(command)) = ops.first() {
                    match command.get(..2) {
                        Some([0x01, 0x1b]) => chip.mode = Mode::Sleeping,
                        Some([0x01, 0x1c]) => chip.mode = Mode::Standby,
                        Some([0x02, 0x09]) => chip.mode = Mode::Receiving,
                        Some([0x02, 0x0a]) => chip.mode = Mode::Transmitting,
                        _ => (),
                    }
                }
            }
        }
        for op in ops.iter_mut() {
            if let Operation::Read(bytes)
            | Operation::Transfer(bytes, _)
            | Operation::TransferInPlace(bytes) = op
            {
                bytes.fill(0);
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

/// No test here raises a preamble IRQ, so the receive-busy gate never arms.
struct StoppedClock;
impl umsh_hal::Clock for StoppedClock {
    fn now_ms(&self) -> u64 {
        0
    }
}

type Kind = EitherRadioKind<Sx126x<Bus, Pins, Sx1262>, Lr1110<Bus, Pins, Lr1121>>;

fn poll<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}

fn kind(chip: &Rc<RefCell<Chip>>) -> Kind {
    let (bus, pins) = (Bus(chip.clone()), Pins(chip.clone()));
    match chip.borrow().family {
        Family::Sx126x => EitherRadioKind::A(Sx126x::new(
            bus,
            pins,
            sx126x::Config {
                chip: Sx1262,
                tcxo_ctrl: Some(sx126x::TcxoCtrlVoltage::Ctrl3V0),
                use_dcdc: true,
                rx_boost: true,
            },
        )),
        Family::Lr11xx => EitherRadioKind::B(Lr1110::new(
            bus,
            pins,
            lr1110::Config {
                chip: Lr1121::default(),
                tcxo_ctrl: Some(lr1110::TcxoCtrlVoltage::Ctrl3V0),
                use_dcdc: false,
                rx_boost: true,
                rf_switch: None,
            },
        )),
    }
}

#[test]
fn either_chip_boots_receives_and_transmits() {
    for (family, rx_preamble) in [(Family::Sx126x, 8), (Family::Lr11xx, 16)] {
        let chip = Rc::new(RefCell::new(Chip {
            family,
            mode: Mode::Standby,
        }));
        let Poll::Ready(Ok(lora)) = poll(core::pin::pin!(LoRa::new(kind(&chip), false, Delay)))
        else {
            panic!("{family:?} must initialize");
        };
        let channel: &'static Channels<NoopRawMutex, 4, 2> = Box::leak(Box::new(Channels::new()));
        let control: &'static DeviceControl<NoopRawMutex> =
            Box::leak(Box::new(DeviceControl::new()));
        let mut runner = core::pin::pin!(device_runner(
            lora,
            channel,
            control,
            rx_preamble,
            32,
            RxStrategy::Continuous,
            None,
            StoppedClock,
        ));
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(
            chip.borrow().mode,
            Mode::Sleeping,
            "{family:?}: disabled at boot"
        );
        control.apply(DeviceSettings {
            enabled: true,
            freq_hz: 917_500_000,
            sf: SpreadingFactor::_7,
            bw: Bandwidth::_62KHz,
            cr: CodingRate::_4_8,
            power_dbm: 22,
        });
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(chip.borrow().mode, Mode::Receiving, "{family:?}");
        assert!(
            channel
                .tx
                .try_send(TxRequest {
                    id: 7,
                    data: heapless::Vec::from_slice(&[1, 2, 3]).unwrap(),
                    power_dbm: None,
                    cad: umsh_hal::CadPolicy::Skip,
                })
                .is_ok()
        );
        assert!(poll(runner.as_mut()).is_pending());
        assert_eq!(chip.borrow().mode, Mode::Transmitting, "{family:?}");
    }
}
