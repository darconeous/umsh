//! Driving async code that has nothing to wait for.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Run a future that must complete on its first poll: the software crypto
/// and in-memory stores these harnesses use never suspend.
pub fn ready<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    match pin!(future).poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("a future with nothing to wait for suspended"),
    }
}

/// Poll a future once. `None` means it went idle.
pub fn poll_once<F: Future>(future: F) -> Option<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    match pin!(future).poll(&mut context) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}
