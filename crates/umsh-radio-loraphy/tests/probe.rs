//! The chip probe and the timed bring-up, against a scripted chip that
//! answers as an LR1121, an SX1262, or an empty bus.
use core::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use std::{cell::RefCell, rc::Rc};

use embedded_hal::digital::{ErrorType as PinErrorType, InputPin, OutputPin};
use embedded_hal_async::{
    delay::DelayNs,
    spi::{ErrorKind, ErrorType, Operation, SpiDevice},
};
use lora_phy::{
    LoRa,
    lr1110::{self, ChipType, Lr1110},
    mod_params::RadioError,
    mod_traits::InterfaceVariant,
    sx126x::{self, Sx126x, Sx1262},
};
use umsh_radio_loraphy::{
    EitherRadioKind,
    probe::{self, BUSY_LIMIT_MS, ChipFamily, ProbeError, Step, TimedOut},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Fitted {
    #[default]
    Lr1121,
    Sx1262,
    /// MISO held low.
    Zeros,
    /// MISO floating high.
    Ones,
}

/// When BUSY goes high and stays there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stick {
    AtReset,
    AfterGetVersion,
    AfterReadRegister,
    /// Through the whole probe, then at the driver's own reset.
    InDriver,
}

#[derive(Default)]
struct Chip {
    fitted: Fitted,
    stick: Option<Stick>,
    busy: bool,
    get_version_pending: bool,
    commands: Vec<Vec<u8>>,
    elapsed_us: u64,
}

impl Chip {
    fn new(fitted: Fitted, stick: Option<Stick>) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            fitted,
            stick,
            ..Self::default()
        }))
    }

    fn event(&mut self, event: Stick) {
        if self.stick == Some(event) {
            self.busy = true;
        }
    }
}

struct Bus(Rc<RefCell<Chip>>);
impl ErrorType for Bus {
    type Error = ErrorKind;
}
impl SpiDevice for Bus {
    async fn transaction(&mut self, ops: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        let mut chip = self.0.borrow_mut();
        let fitted = chip.fitted;
        match ops {
            [Operation::Write([0x01, 0x01])] => {
                chip.commands.push(vec![0x01, 0x01]);
                chip.get_version_pending = true;
                chip.event(Stick::AfterGetVersion);
            }
            [Operation::Read(response)] if response.len() == 5 && chip.get_version_pending => {
                chip.get_version_pending = false;
                response.copy_from_slice(&match fitted {
                    // Stat1 CMD_DAT, hardware 0x22, LR1121, firmware 0x0103.
                    Fitted::Lr1121 => [0x06, 0x22, 0x03, 0x01, 0x03],
                    // STBY_RC with a command error: what an SX126x clocks out.
                    Fitted::Sx1262 => [0x2a; 5],
                    Fitted::Zeros => [0x00; 5],
                    Fitted::Ones => [0xff; 5],
                });
            }
            [
                Operation::Write([0x1d, 0x03, 0x20, 0x00]),
                Operation::Read(version),
            ] => {
                chip.commands.push(vec![0x1d, 0x03, 0x20, 0x00]);
                match fitted {
                    Fitted::Sx1262 => version.copy_from_slice(b"SX1261 V2D 2D02\0"),
                    Fitted::Ones => version.fill(0xff),
                    Fitted::Lr1121 | Fitted::Zeros => version.fill(0x00),
                }
                chip.event(Stick::AfterReadRegister);
            }
            // The driver, once it owns the bus.
            ops => {
                if let Some(Operation::Write(command)) = ops.first() {
                    chip.commands.push(command.to_vec());
                }
                for op in ops.iter_mut() {
                    if let Operation::Read(bytes) | Operation::TransferInPlace(bytes) = op {
                        bytes.fill(0);
                    }
                }
            }
        }
        Ok(())
    }
}

struct Reset(Rc<RefCell<Chip>>);
impl PinErrorType for Reset {
    type Error = Infallible;
}
impl OutputPin for Reset {
    fn set_low(&mut self) -> Result<(), Infallible> {
        Ok(())
    }
    fn set_high(&mut self) -> Result<(), Infallible> {
        let mut chip = self.0.borrow_mut();
        chip.busy = false;
        chip.event(Stick::AtReset);
        Ok(())
    }
}

struct Busy(Rc<RefCell<Chip>>);
impl PinErrorType for Busy {
    type Error = Infallible;
}
impl InputPin for Busy {
    fn is_high(&mut self) -> Result<bool, Infallible> {
        Ok(self.0.borrow().busy)
    }
    fn is_low(&mut self) -> Result<bool, Infallible> {
        Ok(!self.0.borrow().busy)
    }
}

/// Virtual time: every delay completes at once and is counted.
struct Delay(Rc<RefCell<Chip>>);
impl DelayNs for Delay {
    async fn delay_ns(&mut self, ns: u32) {
        self.0.borrow_mut().elapsed_us += u64::from(ns.div_ceil(1_000));
    }
}

/// The driver's view of the same RESET and BUSY lines.
struct Pins(Rc<RefCell<Chip>>);
impl InterfaceVariant for Pins {
    async fn reset(&mut self, _: &mut impl DelayNs) -> Result<(), RadioError> {
        let mut chip = self.0.borrow_mut();
        chip.busy = false;
        chip.event(Stick::InDriver);
        Ok(())
    }
    async fn wait_on_busy(&mut self) -> Result<(), RadioError> {
        core::future::poll_fn(|_| {
            if self.0.borrow().busy {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        })
        .await
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

/// A deadline the test fires by hand.
struct Deadline(Rc<RefCell<bool>>);
impl Future for Deadline {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if *self.0.borrow() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn poll<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}

fn identify(chip: &Rc<RefCell<Chip>>) -> Result<ChipFamily, ProbeError> {
    let (mut bus, mut reset, mut busy, mut delay) = (
        Bus(chip.clone()),
        Reset(chip.clone()),
        Busy(chip.clone()),
        Delay(chip.clone()),
    );
    let Poll::Ready(result) = poll(core::pin::pin!(probe::identify(
        &mut bus, &mut reset, &mut busy, &mut delay
    ))) else {
        panic!("the probe never waits on anything but virtual time");
    };
    result
}

#[test]
fn an_lr1121_reports_its_version() {
    let chip = Chip::new(Fitted::Lr1121, None);
    let Ok(ChipFamily::Lr11xx(version)) = identify(&chip) else {
        panic!("an LR1121 must be identified");
    };
    assert_eq!(version.chip_type, ChipType::Lr1121);
    assert_eq!(version.hw, 0x22);
    assert_eq!(version.fw, 0x0103);
    // Identified on GetVersion alone: no SX126x opcode reaches it.
    assert_eq!(chip.borrow().commands, [vec![0x01, 0x01]]);
}

#[test]
fn an_sx1262_reports_its_version_string() {
    let chip = Chip::new(Fitted::Sx1262, None);
    assert!(matches!(identify(&chip), Ok(ChipFamily::Sx126x)));
}

#[test]
fn an_empty_bus_is_neither_family() {
    for fitted in [Fitted::Zeros, Fitted::Ones] {
        let chip = Chip::new(fitted, None);
        assert_eq!(
            identify(&chip).unwrap_err(),
            ProbeError::Unknown,
            "{fitted:?}"
        );
    }
}

#[test]
fn a_stuck_busy_names_the_step_and_gives_up_on_time() {
    for (fitted, stick, after) in [
        (Fitted::Lr1121, Stick::AtReset, Step::Reset),
        (Fitted::Lr1121, Stick::AfterGetVersion, Step::GetVersion),
        (Fitted::Sx1262, Stick::AfterGetVersion, Step::GetVersion),
        (Fitted::Sx1262, Stick::AfterReadRegister, Step::ReadRegister),
    ] {
        let chip = Chip::new(fitted, Some(stick));
        assert_eq!(
            identify(&chip).unwrap_err(),
            ProbeError::BusyStuck { after },
            "{stick:?}"
        );
        let elapsed_ms = chip.borrow().elapsed_us / 1_000;
        assert!(
            (u64::from(BUSY_LIMIT_MS)..u64::from(BUSY_LIMIT_MS) + 50).contains(&elapsed_ms),
            "{stick:?}: gave up after {elapsed_ms} ms"
        );
    }
}

type Kind = EitherRadioKind<Sx126x<Bus, Pins, Sx1262>, Lr1110<Bus, Pins, lr1110::variant::Lr1121>>;

/// What a board's bring-up does: probe, build the matching driver, and
/// initialize it, all under one deadline.
async fn bring_up(chip: Rc<RefCell<Chip>>) -> Result<LoRa<Kind, Delay>, ProbeError> {
    let (mut bus, mut reset, mut busy, mut delay) = (
        Bus(chip.clone()),
        Reset(chip.clone()),
        Busy(chip.clone()),
        Delay(chip.clone()),
    );
    let family = probe::identify(&mut bus, &mut reset, &mut busy, &mut delay).await?;
    let kind = match family {
        ChipFamily::Sx126x => EitherRadioKind::A(Sx126x::new(
            bus,
            Pins(chip.clone()),
            sx126x::Config {
                chip: Sx1262,
                tcxo_ctrl: Some(sx126x::TcxoCtrlVoltage::Ctrl3V0),
                use_dcdc: true,
                rx_boost: true,
            },
        )),
        ChipFamily::Lr11xx(_) => EitherRadioKind::B(Lr1110::new(
            bus,
            Pins(chip.clone()),
            lr1110::Config {
                chip: lr1110::variant::Lr1121::default(),
                tcxo_ctrl: Some(lr1110::TcxoCtrlVoltage::Ctrl3V0),
                use_dcdc: false,
                rx_boost: true,
                rf_switch: None,
            },
        )),
    };
    Ok(LoRa::new(kind, false, delay)
        .await
        .expect("the scripted chip accepts every command"))
}

#[test]
fn both_families_come_up_inside_the_deadline() {
    // Each family's SetStandby: the matching driver ran after the probe.
    for (fitted, standby) in [
        (Fitted::Sx1262, &[0x80][..]),
        (Fitted::Lr1121, &[0x01, 0x1c][..]),
    ] {
        let chip = Chip::new(fitted, None);
        let fired = Rc::new(RefCell::new(false));
        let mut init = core::pin::pin!(probe::init_within(Deadline(fired), bring_up(chip.clone())));
        assert!(
            matches!(poll(init.as_mut()), Poll::Ready(Ok(Ok(_)))),
            "{fitted:?} must initialize"
        );
        assert!(
            chip.borrow()
                .commands
                .iter()
                .any(|c| c.starts_with(standby)),
            "{fitted:?}"
        );
    }
}

#[test]
fn busy_stuck_in_driver_init_times_out() {
    for fitted in [Fitted::Sx1262, Fitted::Lr1121] {
        let chip = Chip::new(fitted, Some(Stick::InDriver));
        let fired = Rc::new(RefCell::new(false));
        let mut init = core::pin::pin!(probe::init_within(
            Deadline(fired.clone()),
            bring_up(chip.clone())
        ));
        assert!(poll(init.as_mut()).is_pending(), "{fitted:?}");
        *fired.borrow_mut() = true;
        assert!(
            matches!(poll(init.as_mut()), Poll::Ready(Err(TimedOut))),
            "{fitted:?}: the deadline must end a wedged init"
        );
    }
}

#[test]
fn busy_stuck_while_probing_fails_before_the_deadline() {
    let chip = Chip::new(Fitted::Lr1121, Some(Stick::AfterGetVersion));
    let fired = Rc::new(RefCell::new(false));
    let mut init = core::pin::pin!(probe::init_within(Deadline(fired), bring_up(chip)));
    assert!(matches!(
        poll(init.as_mut()),
        Poll::Ready(Ok(Err(ProbeError::BusyStuck {
            after: Step::GetVersion
        })))
    ));
}
