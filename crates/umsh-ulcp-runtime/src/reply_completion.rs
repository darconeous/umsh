//! One outstanding response whose successful transmission permits DFU.
//!
//! The driver owns the transition. Transport tasks can only complete its
//! expiring token; a stale writer can neither send nor authorize a later reset.

use core::cell::RefCell;
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    signal::Signal,
};
use embassy_time::{Instant, with_deadline};

#[derive(Default)]
struct State {
    next: u32,
    active: Option<(u32, Option<bool>)>,
}

impl State {
    fn begin(&mut self) -> u32 {
        self.next = self.next.wrapping_add(1);
        self.active = Some((self.next, None));
        self.next
    }

    fn complete(&mut self, id: u32, sent: bool) -> bool {
        if let Some((active, result)) = &mut self.active {
            if *active == id && result.is_none() {
                *result = Some(sent);
                return sent;
            }
        }
        false
    }
}

static STATE: Mutex<CriticalSectionRawMutex, RefCell<State>> = Mutex::new(RefCell::new(State {
    next: 0,
    active: None,
}));
static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

#[derive(Clone, Copy, Debug)]
pub struct ReplyCompletion {
    id: u32,
    deadline: Instant,
}

impl ReplyCompletion {
    pub(crate) fn begin(deadline: Instant) -> Self {
        let id = STATE.lock(|state| state.borrow_mut().begin());
        Self { id, deadline }
    }

    pub fn deadline(self) -> Instant {
        self.deadline
    }

    /// Check before writing each segment, including the first one.
    pub fn is_pending(self) -> bool {
        Instant::now() < self.deadline
            && STATE.lock(|state| state.borrow().active == Some((self.id, None)))
    }

    /// Returns true only if this call authorized the current handoff.
    /// Cache owners must invalidate success if the deadline expired or the
    /// driver retired the token while transmission was finishing.
    pub fn complete(self, sent: bool) -> bool {
        let accepted = STATE.lock(|state| {
            state
                .borrow_mut()
                .complete(self.id, sent && Instant::now() < self.deadline)
        });
        CHANGED.signal(());
        accepted
    }

    pub(crate) async fn wait(self) -> bool {
        loop {
            let result = STATE.lock(|state| {
                let state = state.borrow();
                match state.active {
                    Some((id, result)) if id == self.id => result,
                    _ => Some(false),
                }
            });
            if let Some(sent) = result {
                STATE.lock(|state| {
                    let mut state = state.borrow_mut();
                    if state.active.is_some_and(|(id, _)| id == self.id) {
                        state.active = None;
                    }
                });
                return sent;
            }
            if with_deadline(self.deadline, CHANGED.wait()).await.is_err() {
                self.complete(false);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_current_response_can_complete_once() {
        let mut state = State::default();
        let first = state.begin();
        assert_eq!(state.active, Some((first, None)));
        state.complete(first, false);
        state.complete(first, true);
        assert_eq!(state.active, Some((first, Some(false))));
        let second = state.begin();
        state.complete(first, true);
        assert_eq!(state.active, Some((second, None)));
        state.complete(second, true);
        state.complete(second, false);
        assert_eq!(state.active, Some((second, Some(true))));
    }
}
