//! Pure companion-session transport arbitration.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Usb,
    Ble,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionArbitration {
    active: Option<Transport>,
    generation: u32,
}

impl SessionArbitration {
    pub const fn new(generation: u32) -> Self {
        Self {
            active: None,
            generation,
        }
    }

    /// Start a fresh protocol session for `transport` and invalidate every
    /// frame queued by the previous session.
    pub fn attach(&mut self, transport: Transport) {
        self.generation = self.generation.wrapping_add(1);
        self.active = Some(transport);
    }

    /// Detach only if the edge belongs to the active session. A late detach
    /// from a displaced transport must not tear down its replacement.
    pub fn detach(&mut self, transport: Transport) -> bool {
        if self.active == Some(transport) {
            self.active = None;
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    pub const fn active(&self) -> Option<Transport> {
        self.active
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub fn accepts_frame(&self, transport: Transport) -> bool {
        self.active == Some(transport)
    }

    pub const fn destination(&self) -> Option<(Transport, u32)> {
        match self.active {
            Some(transport) => Some((transport, self.generation)),
            None => None,
        }
    }

    #[cfg(test)]
    pub fn is_current(&self, generation: u32) -> bool {
        self.generation == generation
    }

    pub fn advertising_allowed(&self) -> bool {
        self.active != Some(Transport::Usb)
    }
}

/// Stop yielding transport writes as soon as their session generation is
/// displaced. The generation is checked on every `next()` call, which means an
/// async caller checks again after each completed USB write or BLE notify.
pub struct GenerationChecked<I, L> {
    items: I,
    load_generation: L,
    expected: u32,
    stale: bool,
}

impl<I, L> GenerationChecked<I, L> {
    pub const fn stale(&self) -> bool {
        self.stale
    }
}

impl<I, L> Iterator for GenerationChecked<I, L>
where
    I: Iterator,
    L: FnMut() -> u32,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        if (self.load_generation)() != self.expected {
            self.stale = true;
            return None;
        }
        self.items.next()
    }
}

pub fn generation_checked<I, L>(
    items: I,
    expected: u32,
    load_generation: L,
) -> GenerationChecked<I::IntoIter, L>
where
    I: IntoIterator,
    L: FnMut() -> u32,
{
    GenerationChecked {
        items: items.into_iter(),
        load_generation,
        expected,
        stale: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn attachment_displaces_previous_transport_and_invalidates_frames() {
        let mut state = SessionArbitration::new(10);
        state.attach(Transport::Ble);
        let ble_generation = state.generation();
        assert!(state.accepts_frame(Transport::Ble));
        assert!(state.advertising_allowed());

        state.attach(Transport::Usb);
        assert_eq!(state.active(), Some(Transport::Usb));
        assert!(!state.accepts_frame(Transport::Ble));
        assert!(state.accepts_frame(Transport::Usb));
        assert!(!state.is_current(ble_generation));
        assert!(!state.advertising_allowed());
    }

    #[test]
    fn late_displaced_detach_does_not_clear_replacement() {
        let mut state = SessionArbitration::new(0);
        state.attach(Transport::Ble);
        state.attach(Transport::Usb);
        assert!(!state.detach(Transport::Ble));
        assert_eq!(state.active(), Some(Transport::Usb));
        assert!(state.detach(Transport::Usb));
        assert_eq!(state.active(), None);
        assert!(state.advertising_allowed());
    }

    #[test]
    fn no_session_has_no_output_destination_or_accepted_frames() {
        let state = SessionArbitration::new(7);
        assert_eq!(state.destination(), None);
        assert!(!state.accepts_frame(Transport::Usb));
        assert!(!state.accepts_frame(Transport::Ble));
        assert!(state.advertising_allowed());
    }

    #[test]
    fn generation_wrap_still_invalidates_previous_session() {
        let mut state = SessionArbitration::new(u32::MAX);
        assert!(!state.is_current(0));
        state.attach(Transport::Ble);
        assert_eq!(state.destination(), Some((Transport::Ble, 0)));
        assert!(state.is_current(0));
        state.attach(Transport::Usb);
        assert_eq!(state.generation(), 1);
        assert!(!state.is_current(0));
    }

    #[test]
    fn generation_checked_stops_between_transport_writes() {
        let generation = Cell::new(4);
        let mut writes = generation_checked(["one", "two", "three"], 4, || generation.get());
        assert_eq!(writes.next(), Some("one"));

        // Models displacement while the first async write is awaiting its
        // completion. The next chunk/segment must never be returned.
        generation.set(5);
        assert_eq!(writes.next(), None);
        assert!(writes.stale());
    }

    #[test]
    fn generation_checked_yields_every_write_for_current_session() {
        let writes: heapless::Vec<_, 4> = generation_checked(0..4, 9, || 9).collect();
        assert_eq!(writes.as_slice(), &[0, 1, 2, 3]);
    }
}
