//! A ULCP link carried on a UART without hardware flow control: HDLC-Lite
//! framing, and the reader's XON and XOFF under `PROP_UART_WINDOW` (spec
//! §Flow Control on a UART).
//!
//! One task serves both directions of the link, generic over the UART's
//! halves and over where its frames go ([`UartInbound`]) and come from
//! ([`UartOutbound`]): the host input and output for a UART a host
//! attaches over, the device's own interface for an application wired to
//! it. It knows nothing else about which it serves.
//!
//! The device always reads, so it never sends XON or XOFF itself. What
//! the reader permits bounds what goes on the wire: each XON permits one
//! window of octets, or any number with a window of 0, and XOFF withdraws
//! the permission. Octets are handed to the UART in chunks of at most
//! [`CHUNK`], each flushed before the next, and whatever has arrived is
//! read before every chunk. That is what keeps the overrun after an XOFF
//! to one chunk.
//!
//! The reader's octets and frames are one ordered stream, and the link
//! acts on them in that order although the session handles the frames
//! elsewhere: an XON waits for the session to act on every frame that
//! came before it, so a window set ahead of an XON is the window that XON
//! grants.

use core::cell::Cell;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_futures::join::join;
use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::signal::Signal;
use embedded_io_async::{Read, Write};
use umsh_ulcp::hdlc::{self, Decoder};

/// The most octets handed to the UART at once, and so the most that can
/// follow an XOFF onto the wire.
pub const CHUNK: usize = 16;

/// What the session tells a UART link's task: `PROP_UART_WINDOW` as last
/// published, and how many of the link's frames it has acted on.
///
/// The session owns the window and the driver publishes it with the rest
/// of the device domain, once before any host interaction and after
/// every change. A link task waits for that first publication before it
/// decides whether it may send: a saved window means the device boots
/// without permission.
///
/// The count is what puts a window set and the XON after it in order.
/// The driver adds to it once it has acted on a frame from the link and
/// published whatever that changed.
pub struct Window {
    octets: AtomicU32,
    acted: AtomicU32,
    changed: Signal<CriticalSectionRawMutex, ()>,
}

impl Window {
    const UNPUBLISHED: u32 = u32::MAX;

    pub const fn new() -> Self {
        Self {
            octets: AtomicU32::new(Self::UNPUBLISHED),
            acted: AtomicU32::new(0),
            changed: Signal::new(),
        }
    }

    /// The session's window: the octets each XON permits, 0 for no limit.
    pub fn publish(&self, octets: u16) {
        let previous = self.octets.swap(u32::from(octets), Ordering::AcqRel);
        if previous == Self::UNPUBLISHED {
            self.changed.signal(());
        }
    }

    /// The session acted on one more frame from the link, and the window
    /// published is the one in force after it.
    pub fn frame_acted_on(&self) {
        self.acted.fetch_add(1, Ordering::AcqRel);
        self.changed.signal(());
    }

    /// The window in force, once published.
    pub fn get(&self) -> Option<u16> {
        u16::try_from(self.octets.load(Ordering::Acquire)).ok()
    }

    /// Whether the session has acted on the link's first `frames` frames.
    pub(crate) fn acted_on(&self, frames: u32) -> bool {
        // Both counts wrap; the session is never 2^31 frames behind.
        self.acted.load(Ordering::Acquire).wrapping_sub(frames) < u32::MAX / 2
    }

    /// The window, waiting for its first publication.
    async fn first(&self) -> u16 {
        loop {
            if let Some(octets) = self.get() {
                return octets;
            }
            self.changed.wait().await;
        }
    }
}

impl Default for Window {
    fn default() -> Self {
        Self::new()
    }
}

/// The window of the board's UART link. No board has more than one.
pub static WINDOW: Window = Window::new();

/// What the reader currently permits the device to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    /// `None` for no limit; otherwise the octets still permitted, which
    /// is 0 while the device waits for XON.
    permitted: Option<usize>,
}

impl Flow {
    /// At boot: with a window of 0 the device starts permitted, and with
    /// any other it has no permission until the first XON.
    pub const fn new(window: u16) -> Self {
        Self {
            permitted: if window == 0 { None } else { Some(0) },
        }
    }

    /// XON: one window of octets, counted from here and not added to what
    /// was left of the last permission. `window` is the one in force now,
    /// so a new window takes effect at the next XON.
    pub fn grant(&mut self, window: u16) {
        self.permitted = if window == 0 {
            None
        } else {
            Some(usize::from(window))
        };
    }

    /// XOFF: no permission until the next XON.
    pub fn withdraw(&mut self) {
        self.permitted = Some(0);
    }

    /// How many octets may go on the wire now.
    pub fn allowance(&self) -> usize {
        self.permitted.unwrap_or(usize::MAX)
    }

    /// `octets` went on the wire.
    pub fn spend(&mut self, octets: usize) {
        if let Some(permitted) = &mut self.permitted {
            *permitted = permitted.saturating_sub(octets);
        }
    }
}

/// Where a UART link's received frames go.
#[allow(async_fn_in_trait)]
pub trait UartInbound {
    /// A whole frame arrived. It is handed to the session, which answers
    /// each one with [`Window::frame_acted_on`]: an XON received after
    /// the frame waits for that.
    ///
    /// The link reads nothing more until this returns, so a session that
    /// cannot take the frame holds back the link's input, and never its
    /// output.
    async fn frame(&mut self, frame: &[u8]);

    /// A frame sent to the device was lost: the decoder gave up on one,
    /// or the UART lost octets.
    async fn lost(&mut self);

    /// Whether the decoder should discard the frame it is partway
    /// through, asked before every read: the session it belonged to is
    /// gone.
    fn resync(&mut self) -> bool {
        false
    }
}

/// Where the octets a UART link sends come from.
#[allow(async_fn_in_trait)]
pub trait UartOutbound {
    /// Wait for the next run of octets to send, and encode it into `wire`:
    /// an HDLC-Lite frame or marked text. Returns its length.
    async fn next(&mut self, wire: &mut [u8]) -> usize;

    /// Whether the run last returned by [`next`](Self::next) is still
    /// wanted. Checked before each chunk; a run that is not is abandoned
    /// where it stands.
    fn current(&self) -> bool {
        true
    }
}

/// What the link's two halves share: the receive half hears the reader's
/// XON and XOFF, and the send half is bound by them.
struct Pace<'a> {
    window: &'a Window,
    flow: Cell<Flow>,
    /// Frames handed to the session so far.
    delivered: Cell<u32>,
    /// An XON not yet acted on, and how many frames came before it: it
    /// grants the window in force once the session has acted on those.
    xon_after: Cell<Option<u32>>,
    /// The receive half heard an XON.
    heard: Signal<NoopRawMutex, ()>,
}

impl Pace<'_> {
    /// An octet from the reader: XON or XOFF changes the permission, and
    /// anything else is not the flow's.
    fn receive(&self, octet: u8) {
        match octet {
            hdlc::XON => {
                self.xon_after.set(Some(self.delivered.get()));
                self.heard.signal(());
            }
            // At once, and whatever XON came before it.
            hdlc::XOFF => {
                self.xon_after.set(None);
                let mut flow = self.flow.get();
                flow.withdraw();
                self.flow.set(flow);
            }
            _ => {}
        }
    }

    /// Act on an XON whose turn has come.
    fn settle(&self) {
        if let Some(frames) = self.xon_after.get()
            && self.window.acted_on(frames)
        {
            self.xon_after.set(None);
            let mut flow = self.flow.get();
            flow.grant(self.window.get().unwrap_or(0));
            self.flow.set(flow);
        }
    }

    /// How many octets may go on the wire, waiting until some may.
    async fn permission(&self) -> usize {
        loop {
            self.settle();
            let allowance = self.flow.get().allowance();
            if allowance > 0 {
                return allowance;
            }
            // Until the reader's XON, or the session catching up to one.
            select(self.heard.wait(), self.window.changed.wait()).await;
        }
    }

    fn spend(&self, octets: usize) {
        let mut flow = self.flow.get();
        flow.spend(octets);
        self.flow.set(flow);
    }
}

/// Serve a UART link until the end of time.
///
/// `FRAME` bounds a received frame and `WIRE` an encoded outbound run.
///
/// The two directions run side by side and neither is ever cancelled, so
/// nothing here asks the UART's reads or writes to be cancel-safe, and a
/// session that is slow to take a frame does not stop the link's output.
pub async fn run<R, W, I, O, const FRAME: usize, const WIRE: usize>(
    rx: &mut R,
    tx: &mut W,
    inbound: &mut I,
    outbound: &mut O,
    window: &Window,
) where
    R: Read,
    W: Write,
    I: UartInbound,
    O: UartOutbound,
{
    let pace = Pace {
        window,
        flow: Cell::new(Flow::new(window.first().await)),
        delivered: Cell::new(0),
        xon_after: Cell::new(None),
        heard: Signal::new(),
    };
    // The receive half first: `join` polls in order, so what has arrived
    // is read before the send half decides on its next chunk.
    join(
        receive::<_, _, FRAME>(rx, inbound, &pace),
        send::<_, _, WIRE>(tx, outbound, &pace),
    )
    .await;
}

async fn receive<R: Read, I: UartInbound, const FRAME: usize>(
    rx: &mut R,
    inbound: &mut I,
    pace: &Pace<'_>,
) {
    let mut decoder: Decoder<FRAME> = Decoder::new();
    let mut received = [0u8; 64];
    // After the UART lost octets: the rest of the frame they were in is
    // the same loss, already reported, so it is skipped to the next flag.
    let mut skipping = false;
    loop {
        if inbound.resync() {
            decoder.reset();
        }
        let Ok(len) = rx.read(&mut received).await else {
            // The UART lost octets, so whatever frame they were in.
            decoder.reset();
            skipping = true;
            inbound.lost().await;
            continue;
        };
        for &octet in &received[..len] {
            pace.receive(octet);
            if skipping {
                skipping = octet != hdlc::FLAG;
                continue;
            }
            match decoder.push(octet) {
                None => {}
                Some(Ok(frame)) => {
                    pace.delivered.set(pace.delivered.get().wrapping_add(1));
                    inbound.frame(frame).await;
                }
                Some(Err(_)) => inbound.lost().await,
            }
        }
    }
}

async fn send<W: Write, O: UartOutbound, const WIRE: usize>(
    tx: &mut W,
    outbound: &mut O,
    pace: &Pace<'_>,
) {
    let mut wire = [0u8; WIRE];
    loop {
        let len = outbound.next(&mut wire).await.min(WIRE);
        let mut sent = 0;
        while sent < len {
            let allowance = pace.permission().await;
            // The wait may have been long.
            if !outbound.current() {
                break;
            }
            let end = len.min(sent + CHUNK.min(allowance));
            match tx.write(&wire[sent..end]).await {
                Ok(written) if written > 0 => {
                    pace.spend(written);
                    sent += written;
                }
                // The UART refused octets; the run is abandoned.
                _ => break,
            }
            if tx.flush().await.is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::rc::Rc;
    use std::task::{Context, Poll, Waker};
    use umsh_ulcp::hdlc::{XOFF, XON};

    #[test]
    fn a_window_of_zero_starts_permitted_and_any_other_does_not() {
        assert_eq!(Flow::new(0).allowance(), usize::MAX);
        assert_eq!(Flow::new(64).allowance(), 0);
    }

    #[test]
    fn each_xon_permits_one_window_and_never_accumulates() {
        let mut flow = Flow::new(64);
        flow.grant(64);
        assert_eq!(flow.allowance(), 64);
        flow.spend(10);
        assert_eq!(flow.allowance(), 54);
        flow.grant(64);
        assert_eq!(flow.allowance(), 64);
        flow.grant(64);
        assert_eq!(flow.allowance(), 64);
        flow.spend(100);
        assert_eq!(flow.allowance(), 0);
    }

    #[test]
    fn xoff_withdraws_permission_with_or_without_a_window() {
        let mut flow = Flow::new(0);
        flow.withdraw();
        assert_eq!(flow.allowance(), 0);
        flow.grant(0);
        assert_eq!(flow.allowance(), usize::MAX);
        let mut flow = Flow::new(64);
        flow.grant(64);
        flow.withdraw();
        assert_eq!(flow.allowance(), 0);
    }

    #[test]
    fn a_new_window_takes_effect_at_the_next_xon() {
        let mut flow = Flow::new(0);
        flow.withdraw();
        // Set while permission is withdrawn: nothing yet.
        assert_eq!(flow.allowance(), 0);
        flow.grant(32);
        assert_eq!(flow.allowance(), 32);
        // And back to no limit, again only at an XON.
        flow.spend(32);
        assert_eq!(flow.allowance(), 0);
        flow.grant(0);
        assert_eq!(flow.allowance(), usize::MAX);
    }

    // ─── The link task against in-memory pipes ───────────────────────

    #[derive(Default)]
    struct Wires {
        /// Octets from the reader, not yet read by the device.
        to_device: VecDeque<u8>,
        /// Whether the next read fails, as a UART overrun does.
        overrun: bool,
        /// Octets the device put on the wire, each write separately.
        writes: Vec<Vec<u8>>,
        /// Octets written since the last flush.
        unflushed: usize,
        /// Largest number of octets ever written and not yet flushed.
        most_unflushed: usize,
        /// Runs waiting to be sent.
        outbound: VecDeque<Vec<u8>>,
        /// Whether the run being sent is still wanted.
        current: bool,
        frames: Vec<Vec<u8>>,
        lost: usize,
        /// Whether the session is not taking frames.
        input_full: bool,
    }

    #[derive(Clone, Default)]
    struct Pipes(Rc<RefCell<Wires>>);

    impl Pipes {
        fn sent(&self) -> Vec<u8> {
            self.0.borrow().writes.concat()
        }

        fn feed(&self, octets: &[u8]) {
            self.0.borrow_mut().to_device.extend(octets);
        }

        fn queue(&self, payload: &[u8]) {
            let mut wire = [0u8; 600];
            let len = hdlc::encode_frame(payload, &mut wire).unwrap();
            self.0.borrow_mut().outbound.push_back(wire[..len].to_vec());
        }
    }

    impl embedded_io_async::ErrorType for Pipes {
        type Error = embedded_io_async::ErrorKind;
    }

    impl Read for Pipes {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            core::future::poll_fn(|_| {
                let mut wires = self.0.borrow_mut();
                if core::mem::take(&mut wires.overrun) {
                    return Poll::Ready(Err(embedded_io_async::ErrorKind::Other));
                }
                if wires.to_device.is_empty() {
                    return Poll::Pending;
                }
                let len = buf.len().min(wires.to_device.len());
                for slot in &mut buf[..len] {
                    *slot = wires.to_device.pop_front().unwrap();
                }
                Poll::Ready(Ok(len))
            })
            .await
        }
    }

    impl Write for Pipes {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            let mut wires = self.0.borrow_mut();
            wires.writes.push(buf.to_vec());
            wires.unflushed += buf.len();
            wires.most_unflushed = wires.most_unflushed.max(wires.unflushed);
            Ok(buf.len())
        }

        /// Takes a poll to finish, as a UART takes time to empty: octets
        /// can arrive meanwhile.
        async fn flush(&mut self) -> Result<(), Self::Error> {
            let mut emptying = false;
            core::future::poll_fn(|_| {
                if !core::mem::replace(&mut emptying, true) {
                    return Poll::Pending;
                }
                self.0.borrow_mut().unflushed = 0;
                Poll::Ready(Ok(()))
            })
            .await
        }
    }

    impl UartOutbound for Pipes {
        async fn next(&mut self, wire: &mut [u8]) -> usize {
            core::future::poll_fn(|_| {
                let mut wires = self.0.borrow_mut();
                match wires.outbound.pop_front() {
                    Some(run) => {
                        wire[..run.len()].copy_from_slice(&run);
                        wires.current = true;
                        Poll::Ready(run.len())
                    }
                    None => Poll::Pending,
                }
            })
            .await
        }

        fn current(&self) -> bool {
            self.0.borrow().current
        }
    }

    impl UartInbound for Pipes {
        async fn frame(&mut self, frame: &[u8]) {
            core::future::poll_fn(|_| {
                let mut wires = self.0.borrow_mut();
                if wires.input_full {
                    return Poll::Pending;
                }
                wires.frames.push(frame.to_vec());
                Poll::Ready(())
            })
            .await
        }

        async fn lost(&mut self) {
            self.0.borrow_mut().lost += 1;
        }
    }

    /// The link task, polled by hand: every call to [`Link::settle`] runs
    /// it until it waits on something only the test can provide.
    struct Link<F> {
        task: core::pin::Pin<Box<F>>,
    }

    impl<F: Future<Output = ()>> Link<F> {
        fn settle(&mut self) {
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..1000 {
                assert!(self.task.as_mut().poll(&mut cx).is_pending());
            }
        }
    }

    fn link(pipes: &Pipes, window: &'static Window) -> Link<impl Future<Output = ()>> {
        let (mut rx, mut tx) = (pipes.clone(), pipes.clone());
        let (mut inbound, mut outbound) = (pipes.clone(), pipes.clone());
        Link {
            task: Box::pin(async move {
                run::<_, _, _, _, 600, 600>(&mut rx, &mut tx, &mut inbound, &mut outbound, window)
                    .await
            }),
        }
    }

    fn window(octets: u16) -> &'static Window {
        let window = Box::leak(Box::new(Window::new()));
        window.publish(octets);
        window
    }

    fn encoded(payload: &[u8]) -> Vec<u8> {
        let mut wire = [0u8; 600];
        let len = hdlc::encode_frame(payload, &mut wire).unwrap();
        wire[..len].to_vec()
    }

    #[test]
    fn nothing_is_sent_before_the_window_is_published() {
        let pipes = Pipes::default();
        let window: &'static Window = Box::leak(Box::new(Window::new()));
        let mut link = link(&pipes, window);
        pipes.queue(&[0x81, 0x02]);
        link.settle();
        assert!(pipes.sent().is_empty());
        window.publish(0);
        link.settle();
        assert_eq!(pipes.sent(), encoded(&[0x81, 0x02]));
    }

    /// A reader that sends neither octet sees a link with no flow control.
    #[test]
    fn a_window_of_zero_sends_at_once_and_in_chunks() {
        let pipes = Pipes::default();
        let mut link = link(&pipes, window(0));
        let payload: Vec<u8> = (0..100).collect();
        pipes.queue(&payload);
        link.settle();
        assert_eq!(pipes.sent(), encoded(&payload));
        let wires = pipes.0.borrow();
        assert!(wires.writes.iter().all(|write| write.len() <= CHUNK));
        assert!(wires.most_unflushed <= CHUNK);
    }

    #[test]
    fn a_frame_is_split_across_windows() {
        let pipes = Pipes::default();
        let mut link = link(&pipes, window(10));
        let payload: Vec<u8> = (0x20..0x40).collect();
        let wire = encoded(&payload);
        pipes.queue(&payload);
        link.settle();
        assert!(pipes.sent().is_empty(), "no permission at boot");
        pipes.feed(&[XON]);
        link.settle();
        assert_eq!(pipes.sent(), wire[..10]);
        // Two XONs before the device sends again permit one window, not
        // two.
        pipes.feed(&[XON, XON]);
        link.settle();
        assert_eq!(pipes.sent(), wire[..20]);
        while pipes.sent().len() < wire.len() {
            pipes.feed(&[XON]);
            link.settle();
        }
        assert_eq!(pipes.sent(), wire);
    }

    #[test]
    fn xoff_mid_frame_stops_the_device_until_xon() {
        let pipes = Pipes::default();
        let mut link = link(&pipes, window(0));
        pipes.feed(&[XOFF]);
        link.settle();
        let payload: Vec<u8> = (0..40).collect();
        let wire = encoded(&payload);
        pipes.queue(&payload);
        link.settle();
        assert!(pipes.sent().is_empty());
        pipes.feed(&[XON]);
        // One poll's worth: the first chunk goes out, then the XOFF that
        // arrived during it is read before the next.
        let mut cx = Context::from_waker(Waker::noop());
        let _ = link.task.as_mut().poll(&mut cx);
        pipes.feed(&[XOFF]);
        link.settle();
        let sent = pipes.sent().len();
        assert!(sent > 0 && sent <= CHUNK, "{sent} octets followed the XOFF");
        pipes.feed(&[XON]);
        link.settle();
        assert_eq!(pipes.sent(), wire);
    }

    #[test]
    fn flow_octets_between_frames_and_inside_one_reach_no_frame() {
        let pipes = Pipes::default();
        let mut link = link(&pipes, window(8));
        let mut octets = vec![XOFF];
        let wire = encoded(&[0x81, 0x05, 0x11, 0x13]);
        octets.extend_from_slice(&wire[..3]);
        octets.push(XON);
        octets.extend_from_slice(&wire[3..]);
        pipes.feed(&octets);
        link.settle();
        let wires = pipes.0.borrow();
        assert_eq!(wires.frames, [vec![0x81, 0x05, 0x11, 0x13]]);
        assert_eq!(wires.lost, 0);
    }

    #[test]
    fn a_damaged_frame_is_reported_once() {
        let pipes = Pipes::default();
        let mut link = link(&pipes, window(0));
        let mut wire = encoded(&[0x81, 0x05, 0x01]);
        let last = wire.len() - 2;
        wire[last] ^= 0x01;
        pipes.feed(&wire);
        pipes.feed(&encoded(&[0x82, 0x05]));
        link.settle();
        let wires = pipes.0.borrow();
        assert_eq!(wires.lost, 1);
        assert_eq!(wires.frames, [vec![0x82, 0x05]]);
    }

    #[test]
    fn octets_the_uart_lost_lose_the_frame_they_were_in() {
        let pipes = Pipes::default();
        let mut link = link(&pipes, window(0));
        let wire = encoded(&[0x81, 0x05, 0x01]);
        pipes.feed(&wire[..3]);
        link.settle();
        pipes.0.borrow_mut().overrun = true;
        link.settle();
        pipes.feed(&wire[3..]);
        pipes.feed(&encoded(&[0x82, 0x05]));
        link.settle();
        let wires = pipes.0.borrow();
        assert_eq!(wires.lost, 1);
        assert_eq!(wires.frames, [vec![0x82, 0x05]]);
    }

    /// The reader's opening: XOFF, the window, and XON. The session takes
    /// the frame elsewhere and later, and the XON still grants the window
    /// set ahead of it and not the one before.
    #[test]
    fn an_xon_grants_the_window_set_ahead_of_it() {
        let pipes = Pipes::default();
        let window = window(0);
        let mut link = link(&pipes, window);
        let payload: Vec<u8> = (0x20..0x40).collect();
        let wire = encoded(&payload);
        let mut opening = vec![XOFF];
        opening.extend_from_slice(&encoded(&[0x81, 0x03, 0x01]));
        opening.push(XON);
        pipes.feed(&opening);
        pipes.queue(&payload);
        link.settle();
        assert_eq!(pipes.0.borrow().frames.len(), 1);
        assert!(pipes.sent().is_empty(), "the session has not acted yet");
        // The session acts on the frame: the window is now 8.
        window.publish(8);
        window.frame_acted_on();
        link.settle();
        assert_eq!(pipes.sent(), wire[..8]);
    }

    /// An XOFF after an XON that is still waiting its turn withdraws it.
    #[test]
    fn an_xoff_withdraws_an_xon_still_waiting_its_turn() {
        let pipes = Pipes::default();
        let window = window(8);
        let mut link = link(&pipes, window);
        let mut octets = encoded(&[0x81, 0x03, 0x01]);
        octets.extend_from_slice(&[XON, XOFF]);
        pipes.feed(&octets);
        pipes.queue(&[0x81, 0x02]);
        link.settle();
        window.frame_acted_on();
        link.settle();
        assert!(pipes.sent().is_empty());
        pipes.feed(&[XON]);
        link.settle();
        assert_eq!(pipes.sent().len(), 8.min(encoded(&[0x81, 0x02]).len()));
    }

    /// A session that is slow to take a frame holds back the link's
    /// input and never its output.
    #[test]
    fn a_session_not_taking_frames_does_not_stop_output() {
        let pipes = Pipes::default();
        let mut link = link(&pipes, window(0));
        pipes.0.borrow_mut().input_full = true;
        pipes.feed(&encoded(&[0x81, 0x05, 0x01]));
        link.settle();
        assert!(pipes.0.borrow().frames.is_empty());
        pipes.queue(&[0x82, 0x06]);
        link.settle();
        assert_eq!(pipes.sent(), encoded(&[0x82, 0x06]));
        pipes.0.borrow_mut().input_full = false;
        link.settle();
        assert_eq!(pipes.0.borrow().frames, [vec![0x81, 0x05, 0x01]]);
    }

    #[test]
    fn a_run_no_longer_wanted_is_abandoned_where_it_stands() {
        let pipes = Pipes::default();
        let mut link = link(&pipes, window(10));
        let first: Vec<u8> = (0x20..0x40).collect();
        pipes.queue(&first);
        pipes.queue(&[0x83, 0x05]);
        link.settle();
        pipes.feed(&[XON]);
        link.settle();
        assert_eq!(pipes.sent().len(), 10);
        pipes.0.borrow_mut().current = false;
        pipes.feed(&[XON]);
        link.settle();
        let mut expected = encoded(&first)[..10].to_vec();
        expected.extend_from_slice(&encoded(&[0x83, 0x05]));
        assert_eq!(pipes.sent(), expected);
    }
}
