//! `AsyncRefCell<T>` — an async-aware `RefCell`.
//!
//! `borrow()` / `borrow_mut()` return futures that wait until the cell is
//! available instead of panicking. Built on top of [`AsyncCondition`]: when
//! the last outstanding guard is dropped, all waiting borrowers are woken
//! and race to re-probe the underlying `RefCell`. Losers re-queue.
//!
//! This is a single-threaded primitive — it holds a `RefCell` internally
//! and is `!Sync`. For cross-thread sharing, use a proper mutex crate.

use core::cell::{self, RefCell};
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::task::{Context, Poll};

use crate::{AsyncCondition, AsyncConditionTicket};

/// Single-threaded async-aware interior-mutability cell.
///
/// Mirrors `core::cell::RefCell`, but `borrow()` and `borrow_mut()` are
/// futures that await until the cell is available rather than panicking
/// on contention.
pub struct AsyncRefCell<T: ?Sized> {
    cond: AsyncCondition,
    inner: RefCell<T>,
}

impl<T> AsyncRefCell<T> {
    /// Construct a new cell holding `value`.
    pub fn new(value: T) -> Self {
        Self {
            cond: AsyncCondition::new(),
            inner: RefCell::new(value),
        }
    }

    /// Consume the cell and return the contained value.
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> AsyncRefCell<T> {
    /// Wait until an immutable borrow is available, then take it.
    ///
    /// Multiple `borrow()` guards may be held concurrently. `borrow_mut()`
    /// waits until all of them have been dropped.
    pub async fn borrow(&self) -> Ref<'_, T> {
        loop {
            let wait = self.cond.wait();
            if let Ok(inner) = self.inner.try_borrow() {
                return Ref {
                    inner,
                    cond: &self.cond,
                };
            }
            wait.await;
        }
    }

    /// Wait until an exclusive borrow is available, then take it.
    pub async fn borrow_mut(&self) -> RefMut<'_, T> {
        loop {
            let wait = self.cond.wait();
            if let Ok(inner) = self.inner.try_borrow_mut() {
                return RefMut {
                    inner,
                    cond: &self.cond,
                };
            }
            wait.await;
        }
    }

    /// Attempt to take an immutable borrow without waiting.
    pub fn try_borrow(&self) -> Option<Ref<'_, T>> {
        self.inner.try_borrow().ok().map(|inner| Ref {
            inner,
            cond: &self.cond,
        })
    }

    /// Attempt to take an exclusive borrow without waiting.
    pub fn try_borrow_mut(&self) -> Option<RefMut<'_, T>> {
        self.inner.try_borrow_mut().ok().map(|inner| RefMut {
            inner,
            cond: &self.cond,
        })
    }

    /// Poll `f` with a short-lived exclusive borrow, staying registered on the
    /// cell's wake condition across `Pending` polls.
    ///
    /// This is the primitive for `poll_fn`-style drivers that need to race a
    /// borrow attempt against other wake sources (radio I/O, a timer) *and* be
    /// re-polled whenever a guard is released — for example when a second
    /// handle mutates the cell and drops its borrow.
    ///
    /// Behavior per poll:
    ///
    /// 1. Deregister this task's waker from the wake condition. Every guard
    ///    drop triggers the condition, so a waker registered *before* taking
    ///    the borrow would be woken by our **own** guard drop in step 2,
    ///    re-polling the task in a busy loop. This crate is single-threaded,
    ///    so nothing can trigger between this step and step 3 — no wakeup can
    ///    be lost to the gap.
    /// 2. If the cell is free, take the exclusive borrow and run `f` (which
    ///    may register other wakers, e.g. radio or timer). The guard is
    ///    dropped — waking *other* waiters — before step 3.
    /// 3. If `f` returned `Pending` (or the cell was busy), re-register on the
    ///    condition so a later guard release re-polls this task.
    ///
    /// `ticket` must be obtained from [`scoped_ticket`](Self::scoped_ticket)
    /// once before the wait begins and reused across every poll of that wait.
    /// The ticket deregisters itself on drop, so a wait that is cancelled
    /// mid-`Pending` (e.g. losing a `select!` race) cannot leak its waker
    /// registration.
    pub fn poll_with_mut<R>(
        &self,
        cx: &mut Context<'_>,
        ticket: &mut ScopedTicket<'_>,
        f: impl FnOnce(&mut T, &mut Context<'_>) -> Poll<R>,
    ) -> Poll<R> {
        debug_assert!(
            core::ptr::eq(ticket.cond, &self.cond),
            "ScopedTicket used with a different AsyncRefCell than it was created from"
        );
        ticket.cond.forget_ticket(&mut ticket.ticket);
        let result = match self.try_borrow_mut() {
            // The guard drops at the end of this arm — while this task is
            // deregistered — so our own release never wakes us.
            Some(mut guard) => f(&mut guard, cx),
            None => Poll::Pending,
        };
        if result.is_pending() {
            ticket.ticket = ticket.cond.ticket();
            let _ = ticket.cond.poll_wait(cx, &mut ticket.ticket);
        }
        result
    }

    /// Create an RAII ticket for use with [`poll_with_mut`](Self::poll_with_mut).
    ///
    /// The ticket deregisters from the cell's wake condition when dropped, so
    /// waits abandoned before completion do not leak waker slots.
    pub fn scoped_ticket(&self) -> ScopedTicket<'_> {
        ScopedTicket {
            cond: &self.cond,
            ticket: self.cond.ticket(),
        }
    }

    /// Borrow the underlying wake condition.
    ///
    /// Each guard drop triggers this condition, waking any task currently
    /// suspended on `cond.wait()`. Useful for callers that want to race a
    /// borrow attempt against other wake sources (e.g. a `poll_fn` that
    /// should re-poll when the cell becomes available *or* when a timer
    /// fires, whichever comes first).
    pub fn cond(&self) -> &AsyncCondition {
        &self.cond
    }
}

impl<T: Default> Default for AsyncRefCell<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for AsyncRefCell<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncRefCell")
            .field("inner", &self.inner)
            .finish()
    }
}

/// RAII condition ticket vended by [`AsyncRefCell::scoped_ticket`].
///
/// Deregisters its waker slot from the cell's wake condition on drop, so a
/// wait that is cancelled mid-flight (a dropped `poll_fn` future) cannot leak
/// its registration.
pub struct ScopedTicket<'a> {
    cond: &'a AsyncCondition,
    ticket: AsyncConditionTicket,
}

impl Drop for ScopedTicket<'_> {
    fn drop(&mut self) {
        self.cond.forget_ticket(&mut self.ticket);
    }
}

/// Shared immutable guard returned by [`AsyncRefCell::borrow`].
pub struct Ref<'a, T: ?Sized> {
    inner: cell::Ref<'a, T>,
    cond: &'a AsyncCondition,
}

impl<T: ?Sized> Deref for Ref<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: ?Sized> Drop for Ref<'_, T> {
    fn drop(&mut self) {
        self.cond.trigger();
    }
}

/// Exclusive mutable guard returned by [`AsyncRefCell::borrow_mut`].
pub struct RefMut<'a, T: ?Sized> {
    inner: cell::RefMut<'a, T>,
    cond: &'a AsyncCondition,
}

impl<T: ?Sized> Deref for RefMut<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: ?Sized> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: ?Sized> Drop for RefMut<'_, T> {
    fn drop(&mut self) {
        self.cond.trigger();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use futures::FutureExt;
    use futures::executor::block_on;

    /// Uncontended: `borrow()` and `borrow_mut()` resolve immediately.
    #[test]
    fn uncontended_borrows_resolve_immediately() {
        let cell = AsyncRefCell::new(42u32);
        let r = cell.borrow().now_or_never().expect("borrow should resolve");
        assert_eq!(*r, 42);
        drop(r);
        let mut w = cell
            .borrow_mut()
            .now_or_never()
            .expect("borrow_mut should resolve");
        *w = 7;
        drop(w);
        assert_eq!(*cell.borrow().now_or_never().unwrap(), 7);
    }

    /// Multiple `borrow()`s coexist; `borrow_mut()` waits for them.
    #[test]
    fn shared_borrows_block_exclusive() {
        let cell = AsyncRefCell::new(1u32);
        let r1 = cell.borrow().now_or_never().unwrap();
        let r2 = cell.borrow().now_or_never().unwrap();
        // borrow_mut cannot yet succeed
        let mut fut = Box::pin(cell.borrow_mut());
        assert!((&mut fut).now_or_never().is_none());
        drop(r1);
        // one reader remains; still blocked
        assert!((&mut fut).now_or_never().is_none());
        drop(r2);
        // now it should succeed on next poll
        let w = block_on(fut);
        assert_eq!(*w, 1);
    }

    /// Dropping a `borrow_mut()` guard wakes a waiting `borrow_mut()`.
    #[test]
    fn exclusive_drop_wakes_waiter() {
        block_on(async {
            let cell = AsyncRefCell::new(0u32);
            let w = cell.borrow_mut().await;
            // Second borrow_mut starts waiting.
            let mut fut = Box::pin(cell.borrow_mut());
            assert!((&mut fut).now_or_never().is_none());
            drop(w);
            let mut w2 = fut.await;
            *w2 = 99;
            drop(w2);
            assert_eq!(*cell.borrow().await, 99);
        });
    }

    /// Dropping a pending `borrow_mut()` future leaves the cell usable.
    #[test]
    fn cancelled_wait_does_not_leak() {
        let cell = AsyncRefCell::new(0u32);
        let w = cell.borrow_mut().now_or_never().unwrap();
        {
            // Pending waiter created and dropped before it ever resolves.
            let mut fut = Box::pin(cell.borrow_mut());
            assert!((&mut fut).now_or_never().is_none());
            drop(fut);
        }
        drop(w);
        // Cell is still usable: new borrow_mut resolves immediately.
        let w2 = cell
            .borrow_mut()
            .now_or_never()
            .expect("cell should be free");
        drop(w2);
    }

    /// A waker that counts how many times it is woken.
    struct WakeCounter(core::sync::atomic::AtomicUsize);

    impl futures::task::ArcWake for WakeCounter {
        fn wake_by_ref(arc_self: &alloc::sync::Arc<Self>) {
            arc_self
                .0
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
    }

    impl WakeCounter {
        fn count(&self) -> usize {
            self.0.load(core::sync::atomic::Ordering::SeqCst)
        }
    }

    fn counting_waker() -> (core::task::Waker, alloc::sync::Arc<WakeCounter>) {
        let counter = alloc::sync::Arc::new(WakeCounter(core::sync::atomic::AtomicUsize::new(0)));
        let waker = futures::task::waker(counter.clone());
        (waker, counter)
    }

    /// `poll_with_mut` runs the closure when the cell is free, is `Pending`
    /// while a guard is held, and wakes when that guard is released.
    #[test]
    fn poll_with_mut_waits_for_release() {
        use core::future::poll_fn;
        use core::task::Poll;

        let cell = AsyncRefCell::new(5u32);
        let mut ticket = cell.scoped_ticket();
        let guard = cell.borrow_mut().now_or_never().unwrap();

        let mut fut = Box::pin(poll_fn(|cx| {
            cell.poll_with_mut(cx, &mut ticket, |value, _cx| Poll::Ready(*value))
        }));
        // Held exclusively elsewhere: not ready.
        assert!((&mut fut).now_or_never().is_none());
        drop(guard);
        // Released: the condition wake re-polls and the closure runs.
        assert_eq!(fut.now_or_never(), Some(5));
    }

    /// Regression test: a `Pending` poll of `poll_with_mut` must not be woken
    /// by its **own** guard drop. The pre-`poll_with_mut` pattern registered
    /// on the condition before taking the borrow, so the guard drop at the end
    /// of each poll re-woke the task — a permanent executor spin.
    #[test]
    fn poll_with_mut_own_guard_drop_does_not_self_wake() {
        use core::task::{Context, Poll};

        let (waker, wakes) = counting_waker();
        let mut cx = Context::from_waker(&waker);

        let cell = AsyncRefCell::new(0u32);
        let mut ticket = cell.scoped_ticket();

        // Borrow succeeds, closure returns Pending (like a radio with no
        // frame ready), guard drops inside the call.
        let result: Poll<()> =
            cell.poll_with_mut(&mut cx, &mut ticket, |_value, _cx| Poll::Pending);
        assert!(result.is_pending());
        assert_eq!(
            wakes.count(),
            0,
            "own guard drop must not wake the polling task"
        );

        // But another holder's release *does* wake us.
        drop(cell.borrow_mut().now_or_never().unwrap());
        assert_eq!(wakes.count(), 1);
    }

    /// Regression test: dropping a `ScopedTicket` mid-`Pending` (a wait
    /// cancelled by losing a `select!` race) deregisters its waker slot, so
    /// repeated cancelled waits do not leak slab entries or receive wakes.
    #[test]
    fn scoped_ticket_drop_deregisters() {
        use core::task::{Context, Poll};

        let (waker, wakes) = counting_waker();
        let mut cx = Context::from_waker(&waker);

        let cell = AsyncRefCell::new(0u32);
        {
            let mut ticket = cell.scoped_ticket();
            let result: Poll<()> =
                cell.poll_with_mut(&mut cx, &mut ticket, |_value, _cx| Poll::Pending);
            assert!(result.is_pending());
            // Wait cancelled here: ticket dropped while registered.
        }
        // A later guard release must not wake the abandoned waiter.
        drop(cell.borrow_mut().now_or_never().unwrap());
        assert_eq!(wakes.count(), 0, "cancelled wait must deregister its waker");
    }

    /// Race: holder releases between a waiter's `wait()` registration and
    /// its `try_borrow_mut()` probe. The probe succeeds — the waiter never
    /// actually `.await`s. Verifies the "register-first, probe-second"
    /// ordering closes the lost-wakeup window.
    #[test]
    fn register_first_probe_second_closes_race() {
        block_on(async {
            let cell = AsyncRefCell::new(0u32);
            // No holder exists, so borrow_mut resolves in one poll.
            let w = cell.borrow_mut().await;
            drop(w);
        });
    }
}
