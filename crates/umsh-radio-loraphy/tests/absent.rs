//! A board whose radio did not come up, and requests that outlive their
//! callers.
use core::{
    future::Future,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use heapless::Vec;
use lora_phy::mod_params::{Bandwidth, CodingRate, SpreadingFactor};
use umsh_hal::{CadPolicy, Clock};
use umsh_radio_loraphy::{
    Channels, ControlRequest, DeviceControl, DeviceSettings, TxError, TxRequest, serve_absent,
};

struct NoClock;
impl Clock for NoClock {
    fn now_ms(&self) -> u64 {
        0
    }
    fn poll_delay_until(&self, _cx: &mut Context<'_>, _deadline_ms: u64) -> Poll<()> {
        Poll::Pending
    }
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn settings(enabled: bool) -> DeviceSettings {
    DeviceSettings {
        enabled,
        freq_hz: 910_525_000,
        sf: SpreadingFactor::_7,
        bw: Bandwidth::_62KHz,
        cr: CodingRate::_4_5,
        power_dbm: 14,
    }
}

/// With no radio, every request is answered, settings are kept for a
/// runner that starts later, and a shutdown is acknowledged at once.
#[test]
fn an_absent_radio_answers_everything_asked_of_it() {
    let channel = Channels::<NoopRawMutex, 4, 4>::new();
    let control = DeviceControl::<NoopRawMutex>::new();
    let mut task = pin!(serve_absent(&channel, &control, &NoClock, None));
    assert!(poll(task.as_mut()).is_pending());

    assert!(
        channel
            .tx
            .try_send(TxRequest {
                id: 7,
                data: Vec::from_slice(&[1, 2, 3]).unwrap(),
                power_dbm: None,
                cad: CadPolicy::default(),
            })
            .is_ok()
    );
    assert!(poll(task.as_mut()).is_pending());
    assert!(matches!(
        poll(pin!(channel.tx_done.wait())),
        Poll::Ready((7, Err(TxError::CadTimeout)))
    ));

    let mut rssi = pin!(control.sample_rssi());
    assert!(poll(rssi.as_mut()).is_pending());
    assert!(poll(task.as_mut()).is_pending());
    assert_eq!(poll(rssi.as_mut()), Poll::Ready(Err(())));

    let mut temperature = pin!(control.sample_temperature());
    assert!(poll(temperature.as_mut()).is_pending());
    assert!(poll(task.as_mut()).is_pending());
    assert_eq!(poll(temperature.as_mut()), Poll::Ready(None));

    control.apply(settings(true));
    assert!(poll(task.as_mut()).is_pending());
    assert_eq!(control.latest(), Some(settings(true)));

    control.shutdown();
    assert!(poll(task.as_mut()).is_pending());
    assert_eq!(poll(pin!(control.wait_shutdown())), Poll::Ready(()));
}

/// A request whose caller gave up is answered late; that answer belongs
/// to it, and the next caller still gets its own.
#[test]
fn a_late_rssi_answer_does_not_satisfy_a_newer_request() {
    let control = DeviceControl::<NoopRawMutex>::new();
    let first = {
        let mut abandoned = pin!(control.sample_rssi());
        assert!(poll(abandoned.as_mut()).is_pending());
        match poll(pin!(control.next_request())) {
            Poll::Ready(ControlRequest::Rssi(id)) => id,
            other => panic!("expected an RSSI request, got {other:?}"),
        }
    };

    let mut current = pin!(control.sample_rssi());
    assert!(poll(current.as_mut()).is_pending());
    control.answer_rssi(first, Ok(-40));
    assert!(poll(current.as_mut()).is_pending());

    let second = match poll(pin!(control.next_request())) {
        Poll::Ready(ControlRequest::Rssi(id)) => id,
        other => panic!("expected an RSSI request, got {other:?}"),
    };
    assert_ne!(first, second);
    control.answer_rssi(second, Ok(-97));
    assert_eq!(poll(current.as_mut()), Poll::Ready(Ok(-97)));
}

/// Two callers take turns: the second request is not made, and so cannot
/// replace the first, until the first has its answer.
#[test]
fn rssi_callers_take_turns() {
    let control = DeviceControl::<NoopRawMutex>::new();
    let mut first = pin!(control.sample_rssi());
    let mut second = pin!(control.sample_rssi());
    assert!(poll(first.as_mut()).is_pending());
    assert!(poll(second.as_mut()).is_pending());

    let Poll::Ready(ControlRequest::Rssi(id)) = poll(pin!(control.next_request())) else {
        panic!("expected the first caller's request");
    };
    control.answer_rssi(id, Ok(-50));
    assert_eq!(poll(first.as_mut()), Poll::Ready(Ok(-50)));

    assert!(poll(second.as_mut()).is_pending());
    let Poll::Ready(ControlRequest::Rssi(next)) = poll(pin!(control.next_request())) else {
        panic!("expected the second caller's request");
    };
    assert_ne!(id, next);
    control.answer_rssi(next, Ok(-60));
    assert_eq!(poll(second.as_mut()), Poll::Ready(Ok(-60)));
}
