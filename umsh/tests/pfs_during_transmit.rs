//! Forward-secrecy operations against a pump that is mid-transmit.
//!
//! The pump holds the MAC for the length of a transmission, and when the
//! transmission ends it dispatches the result through the node's state. An
//! application task that wants the MAC in the meantime must be waiting on it
//! with that state free, or the pump finds it borrowed.

#![cfg(feature = "tokio-support")]

#[allow(
    unused_macros,
    reason = "the mesh macro serves the tests with two nodes"
)]
#[path = "support/node_mesh.rs"]
mod fixture;

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use fixture::{PATIENCE, Scratch, SimMac, build_mac, link};
use umsh::core::PublicKey;
use umsh::crypto::NodeIdentity;
use umsh::crypto::software::SoftwareIdentity;
use umsh::hal::{Radio, RxInfo, TxError, TxOptions};
use umsh::mac::test_support::SimulatedRadio;
use umsh::mac::{MacHandle, SendOptions};
use umsh::node::{Host, LocalNode, PfsStatus};
use umsh_sync::AsyncRefCell;

/// A radio that stays on the air until the test says the transmission is
/// done.
struct GatedRadio {
    inner: SimulatedRadio,
    on_air: Rc<Cell<bool>>,
    finish: Rc<Cell<bool>>,
}

impl Radio for GatedRadio {
    type Error = ();

    async fn transmit(&mut self, data: &[u8], options: TxOptions) -> Result<(), TxError<()>> {
        self.on_air.set(true);
        let finish = self.finish.clone();
        poll_fn(move |_| {
            if finish.get() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        self.inner.transmit(data, options).await
    }

    fn poll_receive(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<RxInfo, ()>> {
        self.inner.poll_receive(cx, buf)
    }

    fn max_frame_size(&self) -> usize {
        self.inner.max_frame_size()
    }

    fn t_frame_ms(&self) -> u32 {
        self.inner.t_frame_ms()
    }
}

/// Holds `pump` on the air, starts `operation` so that it waits on the MAC,
/// then lets the transmission finish and the pump dispatch its result.
async fn run_during_transmit<T>(
    pump: impl Future<Output = T>,
    on_air: &Cell<bool>,
    finish: &Cell<bool>,
    operation: impl Future<Output = ()>,
) {
    let mut cx = Context::from_waker(Waker::noop());
    let mut pump = Box::pin(pump);
    while !on_air.get() {
        assert!(pump.as_mut().poll(&mut cx).is_pending());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut operation = Box::pin(operation);
    assert!(operation.as_mut().poll(&mut cx).is_pending());

    finish.set(true);
    tokio::time::timeout(PATIENCE, pump)
        .await
        .expect("the pump finishes once the transmission does");
    tokio::time::timeout(PATIENCE, operation)
        .await
        .expect("the operation finishes once the pump lets go of the MAC");
}

/// A node with `hello` queued for `peer`, and the handles to hold its
/// transmission on the air.
macro_rules! node_with_a_queued_send {
    ($scratch:ident, $mac:ident, $host:ident, $node:ident, $peer:ident, $on_air:ident, $finish:ident) => {
        let $scratch = Scratch::new("pfs-during-transmit");
        let (radio, _other) = link();
        let $on_air = Rc::new(Cell::new(false));
        let $finish = Rc::new(Cell::new(false));
        let gated = GatedRadio {
            inner: radio,
            on_air: $on_air.clone(),
            finish: $finish.clone(),
        };
        let $mac: AsyncRefCell<SimMac<GatedRadio>> =
            AsyncRefCell::new(build_mac(gated, $scratch.join("counters")));
        let handle = MacHandle::new(&$mac);
        let id = handle
            .add_identity(SoftwareIdentity::from_secret_bytes(&[0x11; 32]))
            .await
            .expect("identity");
        let mut $host = Host::new(handle);
        let $node: LocalNode<_> = $host.add_node(id);
        let $peer: PublicKey = *SoftwareIdentity::from_secret_bytes(&[0x22; 32]).public_key();
        $node
            .peer($peer)
            .await
            .expect("peer")
            .send(b"hello", &SendOptions::default())
            .await
            .expect("queued");
    };
}

#[tokio::test(flavor = "current_thread")]
async fn a_request_waits_for_the_mac_with_the_state_free() {
    node_with_a_queued_send!(scratch, mac, host, node, peer, on_air, finish);
    let options = SendOptions::default();

    run_during_transmit(host.pump_once(), &on_air, &finish, async {
        node.request_pfs(&peer, 60, &options).await.expect("sent");
    })
    .await;

    assert!(matches!(
        node.pfs_status(&peer).await,
        Ok(PfsStatus::Requested)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn an_end_waits_for_the_mac_with_the_state_free() {
    node_with_a_queued_send!(scratch, mac, host, node, peer, on_air, finish);
    let options = SendOptions::default();
    node.request_pfs(&peer, 60, &options).await.expect("sent");

    run_during_transmit(host.pump_once(), &on_air, &finish, async {
        node.end_pfs(&peer, &options).await.expect("ended");
    })
    .await;

    assert!(matches!(
        node.pfs_status(&peer).await,
        Ok(PfsStatus::Inactive)
    ));
}
