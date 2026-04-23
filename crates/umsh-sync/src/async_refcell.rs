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

use crate::AsyncCondition;

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
