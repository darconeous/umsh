//! A whole ULCP attachment carried over the Node Management binding.
//!
//! `node_management_mesh` proves the binding itself works across a real
//! mesh. This goes one layer up and puts an ordinary
//! [`UlcpDevice`](umsh::ulcp::UlcpDevice) on top of it: the handle every
//! host command in the tree is written against, attached to a device it
//! can only reach over the air, with [`MeshFrameLink`] standing in for the
//! wire.
//!
//! What that adds is everything the adapter is responsible for and the
//! binding is not — that opening a handle puts nothing on the air, that a
//! reply files as a response despite the TID the binding insists on, that
//! the properties out of an administrator's reach are absent rather than
//! fatal, and that the commands the binding answers with silence still
//! complete.

#![cfg(feature = "tokio-support")]

#[macro_use]
#[path = "support/node_mesh.rs"]
mod fixture;

use std::time::Duration;

use fixture::*;

use umsh::hal::Radio;
use umsh::node_mgmt::Outcome;
use umsh::ulcp::{
    AttachMode, HostOwnership, RestoreCompletion, UlcpDevice, UlcpDeviceConfig, UlcpError,
};
use umsh::ulcp_mesh::{DeliveredOutcome, MeshEndpoint, MeshFrameLink, mesh_link};
use umsh::ulcp_wire::Status;
use umsh::ulcp_wire::ids::prop;

/// The attach config a mesh session wants: the response timeout has to
/// outlast the exchange engine's own retry budget, or the handle gives up
/// on a slow answer before the binding has finished trying for it.
fn mesh_config() -> UlcpDeviceConfig {
    let mut config = UlcpDeviceConfig::new(910_525, 62_500, 7, 5);
    config.response_timeout = Duration::from_secs(60);
    config
}

/// Carry whatever `work` asks for over the mesh until it finishes.
///
/// The device handle and the driver are two halves of one conversation
/// with no thread between them, so the test plays both: `work` is polled
/// against a loop that takes each request off the link, runs it as a real
/// administrative exchange, and hands the outcome back.
async fn with_mesh<R: Radio, T>(
    mesh: &mut Mesh<'_, R>,
    endpoint: &mut MeshEndpoint,
    work: impl Future<Output = T>,
) -> T
where
    R::Error: core::fmt::Debug,
{
    let work = std::pin::pin!(work);
    let mut work = work;
    loop {
        tokio::select! {
            // Biased so a finished unit of work is seen before another
            // request is taken off a link that is about to be dropped.
            biased;
            done = &mut work => return done,
            request = endpoint.next() => {
                let Some(request) = request else {
                    // The link is gone but `work` has not resolved yet;
                    // let it.
                    std::future::pending::<()>().await;
                    unreachable!()
                };
                match mesh.run(request.frame()).await {
                    Outcome::Replied { .. } => {
                        let reply = mesh.manager.reply().to_vec();
                        endpoint.deliver(&request, DeliveredOutcome::Replied(&reply));
                    }
                    Outcome::NoResponse => {
                        endpoint.deliver(&request, DeliveredOutcome::NoResponse)
                    }
                    Outcome::Failed(failure) => {
                        endpoint.deliver(&request, DeliveredOutcome::Failed(failure))
                    }
                }
            }
        }
    }
}

/// Open a device handle over the mesh, as `umshctl remote` does.
fn open(link: MeshFrameLink) -> UlcpDevice<MeshFrameLink> {
    UlcpDevice::open_remote(link, mesh_config())
}

#[tokio::test(flavor = "current_thread")]
async fn opening_a_handle_puts_nothing_on_the_air() {
    mesh!("open", mesh);
    let (link, mut endpoint) = mesh_link();
    let mut device = open(link);

    assert_eq!(device.attach_mode(), AttachMode::Remote);
    assert!(device.is_remote());
    assert_eq!(
        mesh.device.borrow().executed,
        0,
        "opening a remote handle is not a conversation"
    );

    // Which is not the same as being unusable: the first exchange is
    // whatever the caller actually wanted.
    let name = with_mesh(&mut mesh, &mut endpoint, device.device_name())
        .await
        .expect("the device answers its name");
    assert_eq!(name, "Simulated Device");
    assert_eq!(mesh.device.borrow().executed, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn the_frame_ceiling_comes_from_the_binding_not_a_read() {
    mesh!("ceiling", mesh);
    let (link, _endpoint) = mesh_link();
    let device = open(link);

    // The device's own PHY MTU is 255, but a request over the binding is
    // bounded by what fits in an administrative payload, and nobody had
    // to ask for either number.
    assert_eq!(device.max_frame_size(), umsh::node_mgmt::REQUEST_MAX);
    assert_eq!(mesh.device.borrow().executed, 0);

    // Nothing was learned about the far end, and the handle does not
    // pretend otherwise.
    assert_eq!(device.dev_version(), "");
    assert_eq!(device.dev_model(), None);
    assert_eq!(device.boot_status(), Status::RESET_UNKNOWN);
}

#[tokio::test(flavor = "current_thread")]
async fn a_property_read_comes_back_wearing_the_tid_it_asked_with() {
    mesh!("read", mesh);
    let (link, mut endpoint) = mesh_link();
    let mut device = open(link);

    // Several in a row, because the allocator hands out a different TID
    // each time and every one of them has to survive the round trip.
    for _ in 0..3 {
        let name = with_mesh(&mut mesh, &mut endpoint, device.device_name())
            .await
            .expect("the device answers its name");
        assert_eq!(name, "Simulated Device");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_write_round_trips_and_the_device_kept_it() {
    mesh!("write", mesh);
    let (link, mut endpoint) = mesh_link();
    let mut device = open(link);

    with_mesh(
        &mut mesh,
        &mut endpoint,
        device.set_device_name("Ridgeline"),
    )
    .await
    .expect("the device accepts the name");

    // Read back over the device's own local binding, not the one that
    // just wrote it.
    let stored = mesh.device.borrow_mut().local_get(prop::DEV_NAME);
    assert_eq!(
        String::from_utf8_lossy(&stored).trim_end_matches('\0'),
        "Ridgeline"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn the_synchronization_procedure_reads_the_host_domain_too() {
    mesh!("sync", mesh);
    let (link, mut endpoint) = mesh_link();
    let mut device = open(link);

    let sync = with_mesh(&mut mesh, &mut endpoint, device.sync(None))
        .await
        .expect("sync completes over the administrative binding");

    // Reads are not the gated half. An administrator asks for the host
    // domain like anything else and is told what is actually there —
    // here, a device no host has claimed.
    assert_eq!(sync.ownership, HostOwnership::Unclaimed);
    assert_eq!(sync.host_key, None);
    assert_eq!(sync.filters, Some(Vec::new()));
    assert_eq!(sync.host_channel_ids, Some(Vec::new()));
    assert_eq!(sync.host_peer_keys, Some(Vec::new()));
    assert_eq!(sync.auto_ack, Some(false));
    assert_eq!(sync.queue_count, Some(0));
    assert_eq!(sync.queue_dropped, Some(0));

    // The device domain and radio configuration alike.
    assert_eq!(sync.device_name, "Simulated Device");
    assert_eq!(sync.last_status, Status::RESET_POWER_ON);
    assert_eq!(sync.freq_khz, 910_525);
    assert!(!sync.phy_enabled);
    assert!(!sync.capabilities.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn a_host_domain_write_is_refused_without_spending_an_exchange() {
    mesh!("hostwrite", mesh);
    let (link, _endpoint) = mesh_link();
    let mut device = open(link);

    let before = mesh.device.borrow().executed;
    let refused = device.set_prop(prop::HOST_AUTO_ACK, &[1]).await;
    assert!(matches!(refused, Err(UlcpError::AdministrativeAttach)));
    assert_eq!(
        mesh.device.borrow().executed,
        before,
        "the refusal happened here, not across the mesh"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_reset_completes_on_the_silence_the_binding_answers_with() {
    mesh!("reset", mesh);
    let (link, mut endpoint) = mesh_link();
    let mut device = open(link);

    // Over a wire the device would announce its new status; over the
    // binding, delivery is the whole of the answer. The caller waits for
    // the announcement either way.
    let status = with_mesh(&mut mesh, &mut endpoint, device.reset())
        .await
        .expect("the reset completes");
    assert_eq!(status, Status::RESET_SOFTWARE);
}

#[tokio::test(flavor = "current_thread")]
async fn a_restore_completes_on_silence_even_when_the_device_refused_it() {
    mesh!("restore", mesh);
    let (link, mut endpoint) = mesh_link();
    let mut device = open(link);

    // Nothing has been saved, so the device refuses with
    // STATUS_INVALID_STATE — and the caller is told the restore
    // completed anyway. The exchange engine classifies a command as
    // reset-class from the request and settles it the moment the
    // acknowledgment lands, so the refusal never gets drained. Pinned
    // here because it is a property of the binding worth noticing if it
    // ever changes, not because it is what one would want.
    let completion = with_mesh(&mut mesh, &mut endpoint, device.restore())
        .await
        .expect("the exchange settles on its acknowledgment");
    assert_eq!(completion, RestoreCompletion::Reset);

    // Which is why the spec sends a caller to PROP_LAST_STATUS to learn
    // what actually happened. It says the restore never ran.
    let status = with_mesh(&mut mesh, &mut endpoint, device.get_prop(prop::LAST_STATUS))
        .await
        .expect("the device is still answering");
    assert_ne!(decode_status(&status), Status::RESET_RESTORED);
}

/// The status a `PROP_LAST_STATUS` value carries.
fn decode_status(value: &[u8]) -> Status {
    Status(
        umsh::ulcp_wire::pui::decode(value)
            .expect("a status is a PUI")
            .0,
    )
}
