//! Single-threaded, no_std + alloc port of the `AsyncCondition` primitive from
//! rust-lumanoi-core (originally under the Fuchsia BSD-style license).
//!
//! Upstream source:
//! `/Users/darco/Projects/rust-lumanoi/rust-lumanoi-core/src/async_condition.rs`
//!
//! Differences from the upstream:
//! - `std::sync::Mutex` → `core::cell::RefCell` (UMSH is single-threaded).
//! - `AtomicUsize` trigger counter → `Cell<usize>`.
//!
//! Everything else (`Slab<Waker>`, ticket-based deregistration, `forget_ticket`,
//! the counter-snapshot check in `poll_wait` that prevents lost wakes across
//! trigger-then-wait races) is preserved.
//
// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file of the upstream rust-lumanoi repository.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use slab::Slab;

/// An asynchronous condition that can block multiple tasks until triggered.
#[derive(Debug)]
pub struct AsyncCondition {
    wakers: RefCell<Slab<Waker>>,
    trigger_counter: Cell<usize>,
}

impl Default for AsyncCondition {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncCondition {
    pub fn new() -> Self {
        AsyncCondition {
            wakers: RefCell::new(Slab::with_capacity(4)),
            trigger_counter: Cell::new(1),
        }
    }

    /// Returns a future that will block until `trigger()` is next called.
    pub fn wait(&self) -> AsyncConditionWait<'_> {
        AsyncConditionWait {
            condition: self,
            ticket: self.ticket(),
        }
    }

    pub fn ticket(&self) -> AsyncConditionTicket {
        AsyncConditionTicket {
            key: None,
            trigger_after: self.trigger_counter.get(),
        }
    }

    /// Wakes all pending `AsyncConditionWait` instances vended by `wait()`.
    pub fn trigger(&self) {
        let wakers = self.wakers.borrow();
        self.trigger_counter
            .set(self.trigger_counter.get().wrapping_add(1));
        for (_, waker) in wakers.iter() {
            waker.wake_by_ref();
        }
    }

    pub fn is_ticket_triggered(&self, ticket: &AsyncConditionTicket) -> bool {
        ticket.is_terminated() || ticket.trigger_after != self.trigger_counter.get()
    }

    pub fn forget_ticket(&self, ticket: &mut AsyncConditionTicket) {
        if let Some(key) = ticket.key.take() {
            let mut wakers = self.wakers.borrow_mut();
            assert!(
                wakers.contains(key),
                "AsyncConditionTicket contained invalid waker key"
            );
            wakers.remove(key);
        }
        ticket.trigger_after = 0;
    }

    pub fn poll_wait(
        &self,
        context: &mut Context<'_>,
        ticket: &mut AsyncConditionTicket,
    ) -> Poll<()> {
        if self.is_ticket_triggered(ticket) {
            ticket.trigger_after = 0;
            return Poll::Ready(());
        }
        let mut wakers = self.wakers.borrow_mut();
        if let Some(slot) = ticket.key.and_then(|k| wakers.get_mut(k)) {
            *slot = context.waker().clone();
        } else {
            ticket.key = Some(wakers.insert(context.waker().clone()));
        }
        Poll::Pending
    }
}

#[derive(Debug, Default)]
pub struct AsyncConditionTicket {
    key: Option<usize>,
    trigger_after: usize,
}

impl AsyncConditionTicket {
    pub fn is_terminated(&self) -> bool {
        self.trigger_after == 0
    }
}

/// Instance of `Future` returned by `AsyncCondition.wait()`.
#[must_use = "futures do nothing unless polled"]
#[derive(Debug)]
pub struct AsyncConditionWait<'a> {
    condition: &'a AsyncCondition,
    ticket: AsyncConditionTicket,
}

impl<'a> AsyncConditionWait<'a> {
    pub fn is_triggered(&self) -> bool {
        self.condition.is_ticket_triggered(&self.ticket)
    }

    pub fn is_terminated(&self) -> bool {
        self.ticket.is_terminated()
    }
}

impl<'a> Future for AsyncConditionWait<'a> {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        this.condition.poll_wait(context, &mut this.ticket)
    }
}

impl<'a> Drop for AsyncConditionWait<'a> {
    fn drop(&mut self) {
        self.condition.forget_ticket(&mut self.ticket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::{Either, FutureExt, pending, ready, select};

    /// Straight port of the upstream `test_async_condition` test, adapted
    /// to `futures::executor::block_on` since we don't have `fuchsia_async`.
    #[test]
    fn test_async_condition() {
        let condition = AsyncCondition::new();
        assert_eq!(condition.wait().now_or_never(), None);
        let waiter = condition.wait();
        condition.trigger();
        assert_eq!(waiter.now_or_never(), Some(()));

        // Join a waiter with a trigger — the trigger resolves the waiter.
        futures::executor::block_on(async {
            let waiter = condition.wait();
            futures::join!(waiter, async {
                condition.trigger();
            });
        });
    }

    /// Ported from upstream `test_cancel_upon`, rewritten to use `select`
    /// directly so we don't have to port the `FutureExt::cancel_upon` helper.
    #[test]
    fn test_cancel_upon_equivalent() {
        let condition = AsyncCondition::new();

        // Pending future + un-triggered condition: neither side resolves.
        let fut = select(pending::<()>(), condition.wait());
        assert!(fut.now_or_never().is_none());

        // Trigger, then the condition-side wins and the combined future resolves.
        let fut = select(pending::<()>(), condition.wait());
        condition.trigger();
        let resolved = fut
            .map(|e| match e {
                Either::Left(((), _)) => 1,
                Either::Right(((), _)) => 2,
            })
            .now_or_never();
        assert_eq!(resolved, Some(2));
        let _ = ready::<()>(()); // touch `ready` import to avoid unused-import lint
    }

    /// Dropping one waiter must not stop a later trigger from waking a
    /// different waiter. This exercises the slab's per-ticket deregistration.
    #[test]
    fn dropping_one_waiter_does_not_disturb_others() {
        futures::executor::block_on(async {
            let condition = AsyncCondition::new();
            let wait_a = condition.wait();
            let wait_b = condition.wait();

            drop(wait_a);

            // Trigger after drop; wait_b must still resolve.
            futures::join!(wait_b, async { condition.trigger() });
        });
    }

    /// `forget_ticket` terminates a ticket even before it's polled.
    #[test]
    fn forget_ticket_terminates() {
        let condition = AsyncCondition::new();
        let mut tkt = condition.ticket();
        assert!(!tkt.is_terminated());
        condition.forget_ticket(&mut tkt);
        assert!(tkt.is_terminated());
    }
}
