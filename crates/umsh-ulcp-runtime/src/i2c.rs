//! The bus half of `CMD_I2C_TRANSFER` and `CMD_I2C_SCAN`, over any
//! `embedded-hal-async` bus.
//!
//! [`transfer_with`] and [`scan_with`] are the part that is the same on
//! every board: turning the staged operation list into HAL operations
//! that read straight into the result buffer, walking a scan range, and
//! naming what went wrong in the protocol's terms. [`guarded_transfer`]
//! and [`guarded_scan`] add what a board with a shared bus needs around
//! them—a bounded wait for the bus mutex, a deadline on the transaction,
//! and a [`Reservation`] through which the board's own multi-transaction
//! procedures keep a host out of a peripheral mid-procedure. A board with
//! an exclusively owned bus can call the bare functions instead.

use core::sync::atomic::{AtomicU8, Ordering};

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, with_timeout};
use embedded_hal_async::i2c::{Error as _, ErrorKind, I2c, NoAcknowledgeSource, Operation};
use umsh_ulcp::Status;
use umsh_ulcp::i2c::{Op, ScanRequest, TransferRequest, TransferShape};
use umsh_ulcp_device::{I2C_DATA_MAX, I2C_MAX_OPS};

/// Perform `request` on `bus`, writing the concatenated read data into
/// `out` and returning its length.
///
/// The operations are handed to the HAL as one transaction, so the wire
/// semantics—repeated START on a change of direction, no restart between
/// consecutive operations of the same direction, one STOP—are the HAL's
/// `transaction` contract. Consecutive reads are coalesced before carving
/// `out`. Write data is packed into scratch space so consecutive writes
/// also reach the HAL as one operation, without an extra START/address.
pub async fn transfer_with<I: I2c>(
    bus: &mut I,
    request: TransferRequest<'_>,
    out: &mut [u8],
) -> Result<usize, Status> {
    let mut writes = [0u8; I2C_DATA_MAX];
    let mut written = 0;
    for op in request.ops() {
        if let Op::Write(data) = op.map_err(|error| error.status())? {
            let end = written + data.len();
            writes
                .get_mut(written..end)
                .ok_or(Status::INVALID_ARGUMENT)?
                .copy_from_slice(data);
            written = end;
        }
    }
    let mut write_rest = &writes[..written];
    let mut operations: heapless::Vec<Operation<'_>, I2C_MAX_OPS> = heapless::Vec::new();
    let mut rest = out;
    let mut read_len = 0usize;
    let mut ops = request.ops().peekable();
    while let Some(op) = ops.next() {
        let operation = match op.map_err(|error| error.status())? {
            Op::Write(data) => {
                let mut len = data.len();
                while let Some(Ok(Op::Write(next))) = ops.peek() {
                    len += next.len();
                    ops.next();
                }
                let (head, tail) = write_rest.split_at(len);
                write_rest = tail;
                Operation::Write(head)
            }
            Op::Read(mut len) => {
                while let Some(Ok(Op::Read(next))) = ops.peek() {
                    len = len.checked_add(*next).ok_or(Status::NOMEM)?;
                    ops.next();
                }
                if rest.len() < len {
                    return Err(Status::NOMEM);
                }
                let (head, tail) = core::mem::take(&mut rest).split_at_mut(len);
                rest = tail;
                read_len += len;
                Operation::Read(head)
            }
        };
        operations
            .push(operation)
            .map_err(|_| Status::INVALID_ARGUMENT)?;
    }
    bus.transaction(request.addr, &mut operations)
        .await
        .map_err(|error| status_for(error.kind()))?;
    Ok(read_len)
}

/// Probe every address in `request`'s range with a one-octet read,
/// writing the addresses that acknowledged into `out` in ascending order
/// and returning how many.
///
/// An address that does not acknowledge is absent; any other failure
/// ends the scan, because a bus that has just reported an error is not
/// one whose silence means anything.
pub async fn scan_with<I: I2c>(
    bus: &mut I,
    request: ScanRequest,
    out: &mut [u8],
) -> Result<usize, Status> {
    let mut found = 0usize;
    for addr in request.first..=request.last {
        let mut probe = [0u8; 1];
        match bus.read(addr, &mut probe).await {
            Ok(()) => {
                let slot = out.get_mut(found).ok_or(Status::NOMEM)?;
                *slot = addr;
                found += 1;
            }
            Err(error) => match error.kind() {
                ErrorKind::NoAcknowledge(_) => {}
                other => return Err(status_for(other)),
            },
        }
    }
    Ok(found)
}

/// The status a HAL error kind answers with.
///
/// An unacknowledged address is nobody home; an unacknowledged data
/// octet is somebody home who refused it; everything else is the bus
/// itself misbehaving, which is what a host sees whether the cause was
/// arbitration, an overrun, or the board's own deadline.
pub const fn status_for(kind: ErrorKind) -> Status {
    match kind {
        ErrorKind::NoAcknowledge(NoAcknowledgeSource::Address) => Status::NO_DEVICE,
        ErrorKind::NoAcknowledge(_) => Status::NACK,
        _ => Status::BUS_ERROR,
    }
}

/// The peripheral one of the board's own multi-transaction procedures
/// currently holds, if any.
///
/// The bus mutex serializes transactions, not procedures: a gauge unseal,
/// read, and reseal are three transactions, and a host transfer to the
/// gauge between them would land inside the procedure. A procedure
/// publishes its peripheral's address here for its duration through
/// [`hold`](Self::hold), and the guarded functions answer `STATUS_BUSY`
/// to anything addressed to it, or to a scan whose range covers it. One
/// address at a time is enough: a board runs one such procedure at a time.
pub struct Reservation(AtomicU8);

impl Reservation {
    const NONE: u8 = 0xFF;

    pub const fn new() -> Self {
        Self(AtomicU8::new(Self::NONE))
    }

    /// Publish `addr` as held until the returned guard drops. Every exit
    /// from the procedure, error paths included, releases it.
    #[must_use = "the reservation lasts as long as the guard"]
    pub fn hold(&self, addr: u8) -> Held<'_> {
        self.0.store(addr, Ordering::Release);
        Held(self)
    }

    /// Whether `addr` is held.
    pub fn holds(&self, addr: u8) -> bool {
        let held = self.0.load(Ordering::Acquire);
        held != Self::NONE && held == addr
    }

    /// Whether a scan of `range` would probe the held address.
    pub fn covers(&self, range: &ScanRequest) -> bool {
        let held = self.0.load(Ordering::Acquire);
        held != Self::NONE && range.covers(held)
    }
}

impl Default for Reservation {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`Reservation`] in force; dropping it releases the peripheral.
pub struct Held<'a>(&'a Reservation);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.0.store(Reservation::NONE, Ordering::Release);
    }
}

/// The floor under every transaction deadline: clock stretching and the
/// controller's own bookkeeping cost more than the octets do on a short
/// transfer.
const DEADLINE_FLOOR: Duration = Duration::from_millis(100);

/// How long a transaction moving `octets` on a bus clocked at `speed_khz`
/// may take before it is declared stuck.
///
/// Ten times the nominal wire time on top of the floor: generous enough
/// that a peripheral stretching the clock is not mistaken for a stuck
/// bus, and still well under the host's response timeout.
pub const fn deadline_for(octets: usize, speed_khz: u16) -> Duration {
    // Nine clocks per octet (eight bits and an acknowledge), in
    // microseconds at `speed_khz` kilohertz.
    let speed_khz = if speed_khz == 0 { 1 } else { speed_khz as u64 };
    let nominal_us = (octets as u64 * 9 * 1000) / speed_khz;
    Duration::from_micros(DEADLINE_FLOOR.as_micros() + 10 * nominal_us)
}

/// The deadline for a transfer of `shape`: its data plus one address
/// octet per operation.
pub const fn transfer_deadline(shape: TransferShape, speed_khz: u16) -> Duration {
    deadline_for(shape.data_len + shape.ops + 1, speed_khz)
}

/// The deadline for a whole scan: an address and a probe octet per
/// address in the range.
pub const fn scan_deadline(request: &ScanRequest, speed_khz: u16) -> Duration {
    deadline_for(request.len() * 2, speed_khz)
}

/// Acquire `bus` within `lock_timeout`, refuse the transfer if
/// `reserved` holds its address, and perform it within `deadline`.
///
/// The reservation is checked *after* the bus is acquired. Checked
/// before, a transfer could pass while the peripheral is free, wait for
/// the mutex while a procedure begins, and then run inside it.
/// A wait for the bus that outlasts `lock_timeout` is `STATUS_BUSY`; a
/// transaction that outlasts `deadline` is `STATUS_BUS_ERROR`, and
/// dropping the HAL's future is how the transaction is abandoned—a HAL
/// whose drop does not reset the controller is not one to use here.
pub async fn guarded_transfer<M: RawMutex, I: I2c>(
    bus: &Mutex<M, I>,
    reserved: &Reservation,
    lock_timeout: Duration,
    deadline: Duration,
    request: TransferRequest<'_>,
    out: &mut [u8],
) -> Result<usize, Status> {
    let mut bus = with_timeout(lock_timeout, bus.lock())
        .await
        .map_err(|_| Status::BUSY)?;
    if reserved.holds(request.addr) {
        return Err(Status::BUSY);
    }
    with_timeout(deadline, transfer_with(&mut *bus, request, out))
        .await
        .map_err(|_| Status::BUS_ERROR)?
}

/// The scan counterpart of [`guarded_transfer`]: a range that covers a
/// held address is refused whole rather than silently skipping it, so
/// the host learns to try again instead of drawing a wrong inventory.
pub async fn guarded_scan<M: RawMutex, I: I2c>(
    bus: &Mutex<M, I>,
    reserved: &Reservation,
    lock_timeout: Duration,
    deadline: Duration,
    request: ScanRequest,
    out: &mut [u8],
) -> Result<usize, Status> {
    let mut bus = with_timeout(lock_timeout, bus.lock())
        .await
        .map_err(|_| Status::BUSY)?;
    if reserved.covers(&request) {
        return Err(Status::BUSY);
    }
    with_timeout(deadline, scan_with(&mut *bus, request, out))
        .await
        .map_err(|_| Status::BUS_ERROR)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use embassy_futures::block_on;
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embedded_hal_async::i2c::ErrorType;
    use std::vec::Vec;

    const LOCK_TIMEOUT: Duration = Duration::from_millis(30);
    const DEADLINE: Duration = Duration::from_millis(30);
    /// Long enough that no test waits it out by accident.
    const NEVER: Duration = Duration::from_secs(60);

    /// One transaction the fake bus expects: the address, the operations
    /// as (`is_read`, octets written or to be returned), and the outcome.
    struct Expected {
        addr: u8,
        ops: Vec<(bool, Vec<u8>)>,
        result: Result<(), ErrorKind>,
    }

    #[derive(Default)]
    struct Bus {
        expected: std::collections::VecDeque<Expected>,
        transactions: usize,
    }

    impl ErrorType for Bus {
        type Error = ErrorKind;
    }

    impl I2c for Bus {
        async fn transaction(
            &mut self,
            address: u8,
            operations: &mut [Operation<'_>],
        ) -> Result<(), Self::Error> {
            self.transactions += 1;
            let expected = self.expected.pop_front().expect("unexpected transaction");
            assert_eq!(address, expected.addr);
            assert_eq!(operations.len(), expected.ops.len(), "operation count");
            for (operation, (is_read, octets)) in operations.iter_mut().zip(&expected.ops) {
                match operation {
                    Operation::Write(data) => {
                        assert!(!is_read, "expected a read");
                        assert_eq!(*data, octets.as_slice());
                    }
                    Operation::Read(buffer) => {
                        assert!(*is_read, "expected a write");
                        assert_eq!(buffer.len(), octets.len());
                        buffer.copy_from_slice(octets);
                    }
                }
            }
            expected.result
        }
    }

    fn request(bus: u8, addr: u8, ops: &[Op<'_>]) -> Vec<u8> {
        let mut buf = [0u8; 300];
        let len = umsh_ulcp::i2c::encode_transfer(&mut buf, 0, bus, addr, ops).unwrap();
        // Strip the frame header; the session hands the glue a parsed
        // request.
        buf[2..len].to_vec()
    }

    #[test]
    fn reads_are_carved_out_of_the_result_in_order() {
        let mut bus = Bus::default();
        bus.expected.push_back(Expected {
            addr: 0x55,
            ops: vec![
                (false, vec![0x08]),
                (true, vec![0x34, 0x12]),
                (false, vec![0x0A]),
                (true, vec![0xEF, 0xBE, 0xAD]),
            ],
            result: Ok(()),
        });
        let payload = request(
            0,
            0x55,
            &[
                Op::Write(&[0x08]),
                Op::Read(2),
                Op::Write(&[0x0A]),
                Op::Read(3),
            ],
        );
        let request = TransferRequest::parse(&payload).unwrap();
        let mut out = [0u8; 8];
        let len = block_on(transfer_with(&mut bus, request, &mut out)).unwrap();
        assert_eq!(&out[..len], &[0x34, 0x12, 0xEF, 0xBE, 0xAD]);
        assert_eq!(bus.transactions, 1);
    }

    #[test]
    fn consecutive_reads_and_writes_are_merged_without_crossing_direction_changes() {
        let cases = [
            (
                vec![Op::Read(2), Op::Read(2)],
                vec![(true, vec![1, 2, 3, 4])],
                vec![1, 2, 3, 4],
            ),
            (
                vec![Op::Write(&[8]), Op::Write(&[9, 10])],
                vec![(false, vec![8, 9, 10])],
                vec![],
            ),
            (
                vec![
                    Op::Read(1),
                    Op::Read(2),
                    Op::Write(&[8]),
                    Op::Write(&[9, 10]),
                    Op::Read(2),
                    Op::Read(1),
                ],
                vec![
                    (true, vec![1, 2, 3]),
                    (false, vec![8, 9, 10]),
                    (true, vec![4, 5, 6]),
                ],
                vec![1, 2, 3, 4, 5, 6],
            ),
        ];
        for (ops, expected, read) in cases {
            let mut bus = Bus::default();
            bus.expected.push_back(Expected {
                addr: 0x55,
                ops: expected,
                result: Ok(()),
            });
            let payload = request(0, 0x55, &ops);
            let request = TransferRequest::parse(&payload).unwrap();
            let mut out = [0xFF; 8];
            let len = block_on(transfer_with(&mut bus, request, &mut out)).unwrap();
            assert_eq!(&out[..len], read);
            assert!(out[len..].iter().all(|byte| *byte == 0xFF));
            assert_eq!(bus.transactions, 1);
        }
    }

    #[test]
    fn merged_writes_fill_the_entire_transfer_limit() {
        let first = [0xA5; 127];
        let second = [0x5A; 128];
        let expected = [first.as_slice(), second.as_slice()].concat();
        let mut bus = Bus::default();
        bus.expected.push_back(Expected {
            addr: 0x55,
            ops: vec![(false, expected)],
            result: Ok(()),
        });
        let payload = request(0, 0x55, &[Op::Write(&first), Op::Write(&second)]);
        let request = TransferRequest::parse(&payload).unwrap();
        assert_eq!(block_on(transfer_with(&mut bus, request, &mut [])), Ok(0));
        assert_eq!(bus.transactions, 1);
    }

    #[test]
    fn merged_reads_check_the_combined_output_capacity_before_the_bus() {
        let mut bus = Bus::default();
        let payload = request(0, 0x55, &[Op::Read(2), Op::Read(3)]);
        let request = TransferRequest::parse(&payload).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(
            block_on(transfer_with(&mut bus, request, &mut out)),
            Err(Status::NOMEM)
        );
        assert_eq!(bus.transactions, 0);
    }

    #[test]
    fn a_write_only_transfer_reads_nothing() {
        let mut bus = Bus::default();
        bus.expected.push_back(Expected {
            addr: 0x6B,
            ops: vec![(false, vec![0x00, 0x14])],
            result: Ok(()),
        });
        let payload = request(0, 0x6B, &[Op::Write(&[0x00, 0x14])]);
        let request = TransferRequest::parse(&payload).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(
            block_on(transfer_with(&mut bus, request, &mut out)).unwrap(),
            0
        );
    }

    #[test]
    fn bus_errors_become_the_statuses_the_table_names() {
        let cases = [
            (
                ErrorKind::NoAcknowledge(NoAcknowledgeSource::Address),
                Status::NO_DEVICE,
            ),
            (
                ErrorKind::NoAcknowledge(NoAcknowledgeSource::Data),
                Status::NACK,
            ),
            (
                ErrorKind::NoAcknowledge(NoAcknowledgeSource::Unknown),
                Status::NACK,
            ),
            (ErrorKind::Bus, Status::BUS_ERROR),
            (ErrorKind::ArbitrationLoss, Status::BUS_ERROR),
            (ErrorKind::Overrun, Status::BUS_ERROR),
            (ErrorKind::Other, Status::BUS_ERROR),
        ];
        for (kind, status) in cases {
            assert_eq!(status_for(kind), status, "{kind:?}");
            let mut bus = Bus::default();
            bus.expected.push_back(Expected {
                addr: 0x50,
                ops: vec![(true, vec![0])],
                result: Err(kind),
            });
            let payload = request(0, 0x50, &[Op::Read(1)]);
            let request = TransferRequest::parse(&payload).unwrap();
            let mut out = [0u8; 4];
            assert_eq!(
                block_on(transfer_with(&mut bus, request, &mut out)),
                Err(status)
            );
        }
    }

    #[test]
    fn a_result_buffer_too_small_is_refused_before_the_bus() {
        let mut bus = Bus::default();
        let payload = request(0, 0x50, &[Op::Read(5)]);
        let request = TransferRequest::parse(&payload).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(
            block_on(transfer_with(&mut bus, request, &mut out)),
            Err(Status::NOMEM)
        );
        assert_eq!(bus.transactions, 0);
    }

    #[test]
    fn a_scan_reports_who_acknowledged_and_skips_who_did_not() {
        let mut bus = Bus::default();
        for addr in 0x50..=0x53u8 {
            bus.expected.push_back(Expected {
                addr,
                ops: vec![(true, vec![0])],
                result: if addr % 2 == 0 {
                    Ok(())
                } else {
                    Err(ErrorKind::NoAcknowledge(NoAcknowledgeSource::Address))
                },
            });
        }
        let mut out = [0u8; 8];
        let request = ScanRequest {
            bus: 0,
            first: 0x50,
            last: 0x53,
        };
        let len = block_on(scan_with(&mut bus, request, &mut out)).unwrap();
        assert_eq!(&out[..len], &[0x50, 0x52]);
        assert_eq!(bus.transactions, 4);
    }

    #[test]
    fn a_scan_stops_at_the_first_bus_error() {
        let mut bus = Bus::default();
        bus.expected.push_back(Expected {
            addr: 0x50,
            ops: vec![(true, vec![0])],
            result: Ok(()),
        });
        bus.expected.push_back(Expected {
            addr: 0x51,
            ops: vec![(true, vec![0])],
            result: Err(ErrorKind::ArbitrationLoss),
        });
        let mut out = [0u8; 8];
        let request = ScanRequest {
            bus: 0,
            first: 0x50,
            last: 0x5F,
        };
        assert_eq!(
            block_on(scan_with(&mut bus, request, &mut out)),
            Err(Status::BUS_ERROR)
        );
        assert_eq!(bus.transactions, 2);
    }
    /// A bus whose every transaction hangs: what a stuck peripheral or a
    /// held-low SCL looks like to the HAL.
    struct Stuck;

    impl ErrorType for Stuck {
        type Error = ErrorKind;
    }

    impl I2c for Stuck {
        async fn transaction(
            &mut self,
            _address: u8,
            _operations: &mut [Operation<'_>],
        ) -> Result<(), Self::Error> {
            core::future::pending().await
        }
    }

    fn poll_once<F: core::future::Future>(fut: core::pin::Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    fn successful_probe(addr: u8) -> Expected {
        Expected {
            addr,
            ops: vec![(true, vec![0])],
            result: Ok(()),
        }
    }

    /// The race the reservation exists for, in the order that defeats a
    /// check-before-lock implementation: the transfer is already parked
    /// on the bus mutex when the procedure publishes its reservation.
    #[test]
    fn a_transfer_parked_on_the_bus_sees_a_reservation_published_meanwhile() {
        let bus: Mutex<NoopRawMutex, Bus> = Mutex::new(Bus::default());
        let reserved = Reservation::new();
        let payload = request(0, 0x55, &[Op::Write(&[0x00]), Op::Read(2)]);
        let transfer = TransferRequest::parse(&payload).unwrap();
        let mut out = [0u8; 4];

        // (1) Something else holds the bus, and nothing is reserved.
        let holder = block_on(bus.lock());
        let held = {
            // (2) The transfer starts and parks on the mutex.
            let mut fut = pin!(guarded_transfer(
                &bus, &reserved, NEVER, NEVER, transfer, &mut out
            ));
            assert!(poll_once(fut.as_mut()).is_pending(), "waiting for the bus");
            // (3) The procedure begins, then the bus frees up.
            let held = reserved.hold(0x55);
            drop(holder);
            // (4) The transfer is refused and never touched the bus.
            assert_eq!(block_on(fut.as_mut()), Err(Status::BUSY));
            held
        };
        assert_eq!(block_on(bus.lock()).transactions, 0);
        // (5) The procedure ends and the same transfer goes through.
        drop(held);
        block_on(bus.lock()).expected.push_back(Expected {
            addr: 0x55,
            ops: vec![(false, vec![0x00]), (true, vec![0xAA, 0xBB])],
            result: Ok(()),
        });
        let len = block_on(guarded_transfer(
            &bus, &reserved, NEVER, NEVER, transfer, &mut out,
        ))
        .unwrap();
        assert_eq!(&out[..len], &[0xAA, 0xBB]);
    }

    #[test]
    fn a_scan_parked_on_the_bus_is_refused_whole_when_its_range_covers_the_reservation() {
        let bus: Mutex<NoopRawMutex, Bus> = Mutex::new(Bus::default());
        let reserved = Reservation::new();
        let scan = ScanRequest {
            bus: 0,
            first: 0x50,
            last: 0x57,
        };
        let mut out = [0u8; 8];

        let holder = block_on(bus.lock());
        let held = {
            let mut fut = pin!(guarded_scan(&bus, &reserved, NEVER, NEVER, scan, &mut out));
            assert!(poll_once(fut.as_mut()).is_pending());
            let held = reserved.hold(0x55);
            drop(holder);
            assert_eq!(block_on(fut.as_mut()), Err(Status::BUSY));
            held
        };
        assert_eq!(
            block_on(bus.lock()).transactions,
            0,
            "no address was probed"
        );

        drop(held);
        for addr in 0x50..=0x57u8 {
            block_on(bus.lock())
                .expected
                .push_back(successful_probe(addr));
        }
        let len = block_on(guarded_scan(&bus, &reserved, NEVER, NEVER, scan, &mut out)).unwrap();
        assert_eq!(len, 8);
    }

    #[test]
    fn a_reservation_elsewhere_on_the_bus_does_not_get_in_the_way() {
        let bus: Mutex<NoopRawMutex, Bus> = Mutex::new(Bus::default());
        let reserved = Reservation::new();
        let _held = reserved.hold(0x55);
        block_on(bus.lock()).expected.push_back(Expected {
            addr: 0x6B,
            ops: vec![(false, vec![0x00, 0x14])],
            result: Ok(()),
        });
        let payload = request(0, 0x6B, &[Op::Write(&[0x00, 0x14])]);
        let transfer = TransferRequest::parse(&payload).unwrap();
        let mut out = [0u8; 8];
        assert_eq!(
            block_on(guarded_transfer(
                &bus, &reserved, NEVER, NEVER, transfer, &mut out
            )),
            Ok(0)
        );
        // A scan that stops short of the reserved address is fine too.
        let scan = ScanRequest {
            bus: 0,
            first: 0x50,
            last: 0x54,
        };
        for addr in 0x50..=0x54u8 {
            block_on(bus.lock())
                .expected
                .push_back(successful_probe(addr));
        }
        assert_eq!(
            block_on(guarded_scan(&bus, &reserved, NEVER, NEVER, scan, &mut out)),
            Ok(5)
        );
    }

    #[test]
    fn the_guard_releases_the_reservation_on_every_exit() {
        let reserved = Reservation::new();
        {
            let _held = reserved.hold(0x55);
            assert!(reserved.holds(0x55));
            assert!(!reserved.holds(0x54));
        }
        assert!(!reserved.holds(0x55));
        // Nothing held: the sentinel is never mistaken for an address.
        assert!(!reserved.holds(0xFF));
        assert!(!reserved.covers(&ScanRequest {
            bus: 0,
            first: 0x00,
            last: 0x7F,
        }));
    }

    #[test]
    fn a_bus_that_stays_busy_is_reported_as_busy_not_as_broken() {
        let bus: Mutex<NoopRawMutex, Bus> = Mutex::new(Bus::default());
        let reserved = Reservation::new();
        let _holder = block_on(bus.lock());
        let payload = request(0, 0x50, &[Op::Read(1)]);
        let transfer = TransferRequest::parse(&payload).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(
            block_on(guarded_transfer(
                &bus,
                &reserved,
                LOCK_TIMEOUT,
                NEVER,
                transfer,
                &mut out
            )),
            Err(Status::BUSY)
        );
    }

    #[test]
    fn a_transaction_that_never_completes_is_a_bus_error_and_frees_the_bus() {
        let bus: Mutex<NoopRawMutex, Stuck> = Mutex::new(Stuck);
        let reserved = Reservation::new();
        let payload = request(0, 0x50, &[Op::Read(1)]);
        let transfer = TransferRequest::parse(&payload).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(
            block_on(guarded_transfer(
                &bus, &reserved, NEVER, DEADLINE, transfer, &mut out
            )),
            Err(Status::BUS_ERROR)
        );
        let scan = ScanRequest::new(0);
        assert_eq!(
            block_on(guarded_scan(
                &bus, &reserved, NEVER, DEADLINE, scan, &mut out
            )),
            Err(Status::BUS_ERROR)
        );
        // The abandoned transaction released the mutex with it.
        assert!(bus.try_lock().is_ok());
    }

    #[test]
    fn deadlines_scale_with_the_wire_time_above_a_floor() {
        let short = transfer_deadline(
            TransferShape {
                ops: 2,
                data_len: 3,
                read_len: 2,
            },
            400,
        );
        assert!(short >= DEADLINE_FLOOR && short < Duration::from_millis(110));
        let long = transfer_deadline(
            TransferShape {
                ops: 16,
                data_len: 255,
                read_len: 0,
            },
            100,
        );
        // 272 octets at 100 kHz is about 24 ms on the wire; ten times
        // that plus the floor.
        assert!(long > Duration::from_millis(300) && long < Duration::from_millis(400));
        let scan = scan_deadline(&ScanRequest::new(0), 400);
        assert!(scan > DEADLINE_FLOOR && scan < Duration::from_millis(200));
        // A zero speed is nonsense, but must not divide by it.
        let _ = deadline_for(10, 0);
    }
}
