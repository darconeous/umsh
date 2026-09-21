//! Application-owned controller adapters: fail-closed privacy initialization
//! and an ACL completion fence for the final response before forgetting a host.
pub use bt_hci;
use bt_hci::{
    ControllerToHostPacket, FromHciBytes, WriteHci,
    cmd::{self, AsyncCmd, Cmd, SyncCmd, le::*},
    controller::{Controller, ControllerCmdAsync, ControllerCmdSync},
    data::{AclPacket, AclPacketBoundary, IsoPacket, SyncPacket},
    event::{EventKind, NumberOfCompletedPackets},
};
use core::cell::RefCell;
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use trouble_host::{
    att::{AttClient, AttReq},
    prelude::Uuid,
};

/// Includes equality probes, not just reads: Find By Type Value is a name oracle.
pub fn accesses_device_name(request: AttClient<'_>, name_handle: u16) -> bool {
    let AttClient::Request(request) = request else {
        return false;
    };
    let in_range = |start, end| start <= name_handle && name_handle <= end;
    match request {
        AttReq::Read { handle } | AttReq::ReadBlob { handle, .. } => handle == name_handle,
        AttReq::ReadMultiple { handles } => handles
            .chunks_exact(2)
            .any(|h| u16::from_le_bytes([h[0], h[1]]) == name_handle),
        AttReq::ReadByType {
            start,
            end,
            attribute_type,
        } => in_range(start, end) && attribute_type == Uuid::Uuid16([0x00, 0x2a]),
        AttReq::ReadByGroupType {
            start,
            end,
            group_type,
        } => in_range(start, end) && group_type == Uuid::Uuid16([0x00, 0x2a]),
        AttReq::FindByTypeValue {
            start_handle,
            end_handle,
            att_type,
            ..
        } => in_range(start_handle, end_handle) && att_type == 0x2a00,
        _ => false,
    }
}

#[derive(Default)]
struct State {
    failed: bool,
    runner_exited: bool,
    local_irk: bool,
    resolution: bool,
    timeout: bool,
    private_advertiser: bool,
    advertising_invalidated: bool,
    sent: u64,
    completed: u64,
    disconnected: bool,
    tx_failed: bool,
    notify_handle: u16,
    queued_notifications: u64,
    written_notifications: u64,
    notification_remaining: usize,
    notification_active: bool,
    fence_notification: u64,
    fence_packet: Option<u64>,
}

impl State {
    fn ready(&self) -> bool {
        !self.failed
            && !self.runner_exited
            && !self.advertising_invalidated
            && self.local_irk
            && self.resolution
            && self.timeout
            && self.private_advertiser
    }
    fn acl(&mut self, data: &[u8], continuing: bool) {
        self.sent += 1;
        if !continuing {
            // Firmware notifications always start with the L2CAP/ATT headers.
            self.notification_active = data.len() >= 7
                && data[2..4] == [4, 0]
                && data[4] == 0x1b
                && u16::from_le_bytes([data[5], data[6]]) == self.notify_handle;
            self.notification_remaining = if self.notification_active {
                usize::from(u16::from_le_bytes([data[0], data[1]])) + 4
            } else {
                0
            };
        }
        if self.notification_active {
            self.notification_remaining = self.notification_remaining.saturating_sub(data.len());
            if self.notification_remaining == 0 {
                self.notification_active = false;
                self.written_notifications += 1;
                if self.fence_notification == self.written_notifications {
                    self.fence_packet = Some(self.sent);
                }
            }
        }
    }
    fn fence_done(&self) -> bool {
        !self.tx_failed
            && !self.disconnected
            && self
                .fence_packet
                .is_some_and(|packet| self.completed >= packet)
    }
}

pub struct ControllerState(
    Mutex<CriticalSectionRawMutex, RefCell<State>>,
    embassy_sync::signal::Signal<CriticalSectionRawMutex, ()>,
);
impl Default for ControllerState {
    fn default() -> Self {
        Self::new()
    }
}
impl ControllerState {
    pub const fn new() -> Self {
        Self(
            Mutex::new(RefCell::new(State {
                failed: false,
                runner_exited: false,
                local_irk: false,
                resolution: false,
                timeout: false,
                private_advertiser: false,
                advertising_invalidated: false,
                sent: 0,
                completed: 0,
                disconnected: false,
                tx_failed: false,
                notify_handle: 0,
                queued_notifications: 0,
                written_notifications: 0,
                notification_remaining: 0,
                notification_active: false,
                fence_notification: 0,
                fence_packet: None,
            })),
            embassy_sync::signal::Signal::new(),
        )
    }
    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        self.0.lock(|s| f(&mut s.borrow_mut()))
    }
    /// Called only after the previous runner and stack have completely stopped.
    pub fn reset(&self) {
        self.with(|s| *s = State::default());
        self.1.reset();
    }
    /// A pairing-boundary transition invalidates an in-flight configuration.
    /// Only rebuilding the host, with a fresh advertising address, clears it.
    pub fn invalidate_advertising(&self) {
        self.with(|s| s.advertising_invalidated = true);
        self.1.signal(());
    }
    pub fn failed(&self) -> bool {
        self.with(|s| s.failed)
    }
    pub fn fail(&self) {
        self.with(|s| s.failed = true);
        self.1.signal(());
    }
    /// Transport/runner exits request reconstruction, not a privacy lockout.
    /// A privacy failure remains latched even if the runner subsequently exits.
    pub fn runner_exited(&self) {
        self.with(|s| s.runner_exited = true);
        self.1.signal(());
    }
    pub fn needs_recovery(&self) -> bool {
        self.with(|s| s.runner_exited && !s.failed)
    }
    /// Trouble publishes its generic initialized flag before syncing privacy.
    /// Do not request an advertising operation until that sync has completed:
    /// an already active operation can make the host skip resolving-list sync.
    pub async fn wait_for_privacy(&self) -> bool {
        loop {
            let status = self.with(|s| {
                if s.failed || s.runner_exited || s.advertising_invalidated {
                    Some(false)
                } else if s.local_irk && s.resolution && s.timeout {
                    Some(true)
                } else {
                    None
                }
            });
            if let Some(ready) = status {
                return ready;
            }
            self.1.wait().await;
        }
    }
    /// Count every firmware notification, before enqueueing it. The ordinal
    /// distinguishes even byte-identical earlier responses still in the queue.
    pub fn notification(&self, handle: u16, final_reply: bool) {
        self.with(|s| {
            s.notify_handle = handle;
            s.queued_notifications += 1;
            if final_reply {
                s.fence_notification = s.queued_notifications;
                s.fence_packet = None;
            }
        });
    }
    pub fn fence_done(&self) -> bool {
        self.with(|s| s.fence_done())
    }
    pub fn link_failed(&self) -> bool {
        self.with(|s| s.tx_failed || s.disconnected)
    }
}

/// Owns the controller on ESP32; on nRF it owns a forwarding borrow so the
/// SDC and its hardware resources survive host-stack reconstruction.
pub struct Guarded<C> {
    inner: C,
    state: &'static ControllerState,
}
impl<C> Guarded<C> {
    pub fn new(inner: C, state: &'static ControllerState) -> Self {
        Self { inner, state }
    }
}
impl<C: embedded_io::ErrorType> embedded_io::ErrorType for Guarded<C> {
    type Error = C::Error;
}
impl<C: Controller> Controller for Guarded<C> {
    async fn write_acl_data(&self, packet: &AclPacket<'_>) -> Result<(), Self::Error> {
        // Reserve the sequence before awaiting: a controller completion can
        // race the return of the write future on another runner branch.
        self.state.with(|s| {
            s.acl(
                packet.data(),
                packet.boundary_flag() == AclPacketBoundary::Continuing,
            )
        });
        let result = self.inner.write_acl_data(packet).await;
        if result.is_err() {
            self.state.with(|s| s.tx_failed = true);
        }
        result
    }
    async fn write_sync_data(&self, packet: &SyncPacket<'_>) -> Result<(), Self::Error> {
        self.inner.write_sync_data(packet).await
    }
    async fn write_iso_data(&self, packet: &IsoPacket<'_>) -> Result<(), Self::Error> {
        self.inner.write_iso_data(packet).await
    }
    async fn read<'a>(&self, buf: &'a mut [u8]) -> Result<ControllerToHostPacket<'a>, Self::Error> {
        let packet = self.inner.read(buf).await?;
        if let ControllerToHostPacket::Event(event) = &packet {
            match event.kind {
                EventKind::NumberOfCompletedPackets => {
                    if let Ok(completed) =
                        NumberOfCompletedPackets::from_hci_bytes_complete(event.data)
                    {
                        for entry in completed.completed_packets {
                            if let Ok(count) = entry.num_completed_packets() {
                                self.state.with(|s| s.completed += u64::from(count));
                            }
                        }
                    }
                }
                EventKind::DisconnectionComplete => self.state.with(|s| s.disconnected = true),
                _ => {}
            }
        }
        Ok(packet)
    }
}

impl<C, T> ControllerCmdSync<T> for Guarded<C>
where
    C: ControllerCmdSync<T> + ControllerCmdSync<LeReadResolvingListSize>,
    T: SyncCmd,
{
    async fn exec(&self, command: &T) -> Result<T::Return, cmd::Error<Self::Error>> {
        let opcode = T::OPCODE;
        let tracked = opcode == LeSetAdvParams::OPCODE
            || opcode == LeSetAdvEnable::OPCODE
            || opcode == LeAddDeviceToResolvingList::OPCODE
            || opcode == LeSetPrivacyMode::OPCODE
            || opcode == LeClearResolvingList::OPCODE
            || opcode == LeSetAddrResolutionEnable::OPCODE
            || opcode == LeSetResolvablePrivateAddrTimeout::OPCODE;
        if !tracked {
            return self.inner.exec(command).await;
        }
        let mut bytes = [0; 40];
        command
            .params()
            .write_hci(&mut bytes[..])
            .map_err(|_| cmd::Error::Hci(bt_hci::param::Error::INVALID_HCI_PARAMETERS))?;
        if opcode == LeSetAdvEnable::OPCODE && bytes[0] != 0 && !self.state.with(|s| s.ready()) {
            return Err(cmd::Error::Hci(bt_hci::param::Error::CMD_DISALLOWED));
        }
        if opcode == LeClearResolvingList::OPCODE {
            let capacity = self.inner.exec(&LeReadResolvingListSize::new()).await;
            // Four retained peers plus Trouble's local-IRK sentinel entry.
            match capacity {
                Ok(size) if size >= 5 => {}
                result => {
                    crate::log::debug_log(format_args!(
                        "BLE privacy resolving-list capacity {result:?}; require at least 5"
                    ));
                    self.state.fail();
                    return Err(cmd::Error::Hci(bt_hci::param::Error::CMD_DISALLOWED));
                }
            }
            self.state.with(|s| {
                s.local_irk = false;
                s.resolution = false;
            });
        }
        let result = self.inner.exec(command).await;
        if let Err(error) = &result {
            crate::log::debug_log(format_args!(
                "BLE privacy HCI command 0x{:04x} failed: {error:?}",
                opcode.to_raw()
            ));
        }
        self.state.with(|s| {
            if result.is_err() {
                s.failed = true;
                return;
            }
            if opcode == LeAddDeviceToResolvingList::OPCODE && bytes[..7] == [0; 7] {
                s.local_irk = bytes[23..39] != [0; 16];
                if !s.local_irk {
                    s.failed = true;
                }
            }
            if opcode == LeSetAddrResolutionEnable::OPCODE {
                s.resolution = bytes[0] != 0;
            }
            if opcode == LeSetResolvablePrivateAddrTimeout::OPCODE {
                s.timeout = u64::from(u16::from_le_bytes([bytes[0], bytes[1]]))
                    == crate::ble_privacy::RPA_TIMEOUT_SECS;
            }
            if opcode == LeSetAdvParams::OPCODE {
                s.private_advertiser = matches!(bytes[5], 2 | 3);
            }
        });
        self.state.1.signal(());
        result
    }
}
impl<C: ControllerCmdAsync<T>, T: AsyncCmd> ControllerCmdAsync<T> for Guarded<C> {
    async fn exec(&self, command: &T) -> Result<(), cmd::Error<Self::Error>> {
        self.inner.exec(command).await
    }
}

pub struct Borrowed<'a, C>(pub &'a C);
impl<C: embedded_io::ErrorType> embedded_io::ErrorType for Borrowed<'_, C> {
    type Error = C::Error;
}
impl<C: Controller> Controller for Borrowed<'_, C> {
    async fn write_acl_data(&self, p: &AclPacket<'_>) -> Result<(), Self::Error> {
        self.0.write_acl_data(p).await
    }
    async fn write_sync_data(&self, p: &SyncPacket<'_>) -> Result<(), Self::Error> {
        self.0.write_sync_data(p).await
    }
    async fn write_iso_data(&self, p: &IsoPacket<'_>) -> Result<(), Self::Error> {
        self.0.write_iso_data(p).await
    }
    async fn read<'a>(&self, buf: &'a mut [u8]) -> Result<ControllerToHostPacket<'a>, Self::Error> {
        self.0.read(buf).await
    }
}
impl<C: ControllerCmdSync<T>, T: SyncCmd> ControllerCmdSync<T> for Borrowed<'_, C> {
    async fn exec(&self, command: &T) -> Result<T::Return, cmd::Error<Self::Error>> {
        self.0.exec(command).await
    }
}
impl<C: ControllerCmdAsync<T>, T: AsyncCmd> ControllerCmdAsync<T> for Borrowed<'_, C> {
    async fn exec(&self, command: &T) -> Result<(), cmd::Error<Self::Error>> {
        self.0.exec(command).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_supported_name_read_and_equality_probe_is_guarded() {
        let reads = [
            AttReq::Read { handle: 3 },
            AttReq::ReadBlob {
                handle: 3,
                offset: 12,
            },
            AttReq::ReadMultiple {
                handles: &[2, 0, 3, 0],
            },
            AttReq::ReadByType {
                start: 1,
                end: 9,
                attribute_type: Uuid::Uuid16([0x00, 0x2a]),
            },
            AttReq::ReadByGroupType {
                start: 1,
                end: 9,
                group_type: Uuid::Uuid16([0x00, 0x2a]),
            },
            AttReq::FindByTypeValue {
                start_handle: 1,
                end_handle: 9,
                att_type: 0x2a00,
                att_value: b"Alice",
            },
        ];
        for read in reads {
            assert!(accesses_device_name(AttClient::Request(read), 3));
        }
        assert!(!accesses_device_name(
            AttClient::Request(AttReq::Read { handle: 7 }),
            3
        ));
        assert!(!accesses_device_name(
            AttClient::Request(AttReq::ReadByType {
                start: 4,
                end: 9,
                attribute_type: Uuid::Uuid16([0x00, 0x2a])
            }),
            3
        ));
    }
    #[test]
    fn fence_waits_for_the_right_notification_and_last_acl_fragment() {
        let mut s = State {
            notify_handle: 3,
            fence_notification: 2,
            ..State::default()
        };
        let earlier = [4, 0, 4, 0, 0x1b, 3, 0, 42];
        s.acl(&earlier, false);
        s.completed = 1;
        assert!(!s.fence_done());
        s.acl(&[6, 0, 4, 0, 0x1b, 3, 0, 42], false);
        s.completed = 2;
        assert!(!s.fence_done());
        s.acl(&[43, 44], true);
        assert!(!s.fence_done());
        s.completed = 3;
        assert!(s.fence_done());
        s.disconnected = true;
        assert!(!s.fence_done());
    }
    #[test]
    fn privacy_is_fail_closed() {
        let mut s = State::default();
        assert!(!s.ready());
        s.local_irk = true;
        s.resolution = true;
        s.timeout = true;
        s.private_advertiser = true;
        assert!(s.ready());
        s.failed = true;
        assert!(!s.ready());
    }
    struct Fake {
        capacity: u8,
        fail: Option<cmd::Opcode>,
        calls: RefCell<std::vec::Vec<(cmd::Opcode, std::vec::Vec<u8>)>>,
    }
    impl embedded_io::ErrorType for Fake {
        type Error = core::convert::Infallible;
    }
    impl Controller for Fake {
        async fn write_acl_data(&self, _: &AclPacket<'_>) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn write_sync_data(&self, _: &SyncPacket<'_>) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn write_iso_data(&self, _: &IsoPacket<'_>) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn read<'a>(
            &self,
            _: &'a mut [u8],
        ) -> Result<ControllerToHostPacket<'a>, Self::Error> {
            core::future::pending().await
        }
    }
    impl<T: SyncCmd> ControllerCmdSync<T> for Fake {
        async fn exec(&self, command: &T) -> Result<T::Return, cmd::Error<Self::Error>> {
            let mut data = [0; 40];
            command.params().write_hci(&mut data[..]).unwrap();
            self.calls
                .borrow_mut()
                .push((T::OPCODE, data[..command.params().size()].to_vec()));
            if self.fail == Some(T::OPCODE) {
                return Err(cmd::Error::Hci(bt_hci::param::Error::CMD_DISALLOWED));
            }
            let capacity = [self.capacity];
            let result: &[u8] = if T::OPCODE == LeReadResolvingListSize::OPCODE {
                &capacity
            } else {
                &[]
            };
            Ok(T::Return::from_hci_bytes_complete(result).unwrap())
        }
    }
    fn controller(capacity: u8, fail: Option<cmd::Opcode>) -> Guarded<Fake> {
        Guarded::new(
            Fake {
                capacity,
                fail,
                calls: RefCell::new(std::vec::Vec::new()),
            },
            Box::leak(Box::new(ControllerState::new())),
        )
    }
    fn advertising_params(private: bool) -> LeSetAdvParams {
        use bt_hci::param::*;
        LeSetAdvParams::new(
            Duration::from_micros(crate::ble_privacy::ADVERTISING_INTERVAL_US),
            Duration::from_micros(crate::ble_privacy::ADVERTISING_INTERVAL_US),
            AdvKind::AdvInd,
            if private {
                AddrKind::RESOLVABLE_PRIVATE_OR_RANDOM
            } else {
                AddrKind::RANDOM
            },
            AddrKind::PUBLIC,
            BdAddr::default(),
            AdvChannelMap::ALL,
            AdvFilterPolicy::default(),
        )
    }
    async fn setup(c: &Guarded<Fake>) {
        use bt_hci::param::*;
        c.exec(&LeSetResolvablePrivateAddrTimeout::new(
            Duration::from_secs(crate::ble_privacy::RPA_TIMEOUT_SECS.try_into().unwrap()),
        ))
        .await
        .unwrap();
        c.exec(&LeClearResolvingList::new()).await.unwrap();
        c.exec(&LeAddDeviceToResolvingList::new(
            AddrKind::PUBLIC,
            BdAddr::default(),
            [0; 16],
            [1; 16],
        ))
        .await
        .unwrap();
        c.exec(&LeSetAddrResolutionEnable::new(true)).await.unwrap();
        c.exec(&advertising_params(true)).await.unwrap();
    }
    #[test]
    fn hci_enable_requires_capacity_local_irk_timeout_and_private_address() {
        embassy_futures::block_on(async {
            let c = controller(5, None);
            assert!(c.exec(&LeSetAdvEnable::new(true)).await.is_err());
            setup(&c).await;
            c.exec(&LeSetAdvEnable::new(true)).await.unwrap();
            let calls = c.inner.calls.borrow();
            let (_, bytes) = calls
                .iter()
                .find(|(op, _)| *op == LeSetAdvParams::OPCODE)
                .unwrap();
            assert_eq!(&bytes[..4], &[0x64, 0x06, 0x64, 0x06]); // 1636 x 625 us
            drop(calls);
            c.exec(&advertising_params(false)).await.unwrap();
            assert!(c.exec(&LeSetAdvEnable::new(true)).await.is_err());
            c.exec(&advertising_params(true)).await.unwrap();
            c.state.invalidate_advertising();
            assert!(c.exec(&LeSetAdvEnable::new(true)).await.is_err());
            assert!(!c.state.failed()); // expected pairing-boundary restart, not a fault
        });
    }
    #[test]
    fn controller_failures_cannot_fall_back_to_static_advertising() {
        embassy_futures::block_on(async {
            for capacity in [0, 4] {
                let c = controller(capacity, None);
                assert!(c.exec(&LeClearResolvingList::new()).await.is_err());
                assert!(c.state.failed());
                assert!(c.exec(&LeSetAdvEnable::new(true)).await.is_err());
            }
            let c = controller(5, Some(LeAddDeviceToResolvingList::OPCODE));
            c.exec(&LeClearResolvingList::new()).await.unwrap();
            use bt_hci::param::*;
            assert!(
                c.exec(&LeAddDeviceToResolvingList::new(
                    AddrKind::PUBLIC,
                    BdAddr::default(),
                    [0; 16],
                    [1; 16]
                ))
                .await
                .is_err()
            );
            // Trouble tolerates this command failure; the adapter must not.
            assert!(c.state.failed());
            assert!(c.exec(&LeSetAdvEnable::new(true)).await.is_err());
        });
    }
    #[test]
    fn advertising_waits_for_privacy_initialization_or_explicit_failure() {
        use core::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let c = controller(5, None);
        let mut wait = core::pin::pin!(c.state.wait_for_privacy());
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(wait.as_mut().poll(&mut cx), Poll::Pending);
        embassy_futures::block_on(setup(&c));
        assert_eq!(wait.as_mut().poll(&mut cx), Poll::Ready(true));
        c.state.reset();
        let mut wait = core::pin::pin!(c.state.wait_for_privacy());
        assert_eq!(wait.as_mut().poll(&mut cx), Poll::Pending);
        c.state.fail();
        assert_eq!(wait.as_mut().poll(&mut cx), Poll::Ready(false));
        c.state.reset();
        c.state.invalidate_advertising();
        assert!(!embassy_futures::block_on(c.state.wait_for_privacy()));
    }

    #[test]
    fn runner_recovery_never_clears_a_privacy_failure() {
        let c = controller(5, None);
        embassy_futures::block_on(setup(&c));
        c.state.runner_exited();
        assert!(c.state.needs_recovery());
        assert!(!c.state.failed());
        assert!(!embassy_futures::block_on(c.state.wait_for_privacy()));
        assert!(embassy_futures::block_on(c.exec(&LeSetAdvEnable::new(true))).is_err());
        c.state.fail();
        c.state.runner_exited();
        assert!(c.state.failed());
        assert!(!c.state.needs_recovery());
        c.state.reset();
        assert!(!c.state.needs_recovery());
        embassy_futures::block_on(setup(&c));
        assert!(embassy_futures::block_on(c.exec(&LeSetAdvEnable::new(true))).is_ok());
    }
}
