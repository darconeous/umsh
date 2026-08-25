//! The Node Management binding carried by a real MAC.
//!
//! `umsh-node-mgmt`'s own integration test puts the two engines face to
//! face with the transport reduced to a function call, which is where the
//! binding's semantics are pinned down. This one puts a whole mesh between
//! them: two nodes on a simulated link, each with its own identity, secure
//! unicast doing the sealing, and the administrator half being the async
//! `NodeManager` that `umshctl manage` drives.
//!
//! What that adds is everything the engines deliberately know nothing
//! about — that a request reaches the device sealed and comes back
//! authenticated, that a response is attributed to the peer that sent it,
//! and that the administrator's loop terminates.

#![cfg(feature = "tokio-support")]

#[macro_use]
#[path = "support/node_mesh.rs"]
mod fixture;

use fixture::*;

use umsh::node_mgmt::Outcome;
use umsh::ulcp_wire::frame;
use umsh::ulcp_wire::ids::prop;

// ─── Tests ───────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn an_administrator_reads_a_property_across_the_mesh() {
    mesh!("read", mesh);
    let mut buf = [0u8; 16];
    let len = frame::prop_get(&mut buf, 0, prop::DEV_NAME).unwrap();
    let reply = mesh.reply(&buf[..len]).await;
    assert_eq!(value_of(&reply), b"Simulated Device");
    assert_eq!(mesh.device.borrow().executed, 1);
    assert_eq!(mesh.manager.stray(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_write_takes_effect_and_is_echoed_back() {
    mesh!("write", mesh);
    let mut buf = [0u8; 64];
    let len = frame::prop_set(&mut buf, 0, prop::DEV_NAME, b"Ridgeline").unwrap();
    let reply = mesh.reply(&buf[..len]).await;
    assert_eq!(value_of(&reply), b"Ridgeline");
    assert_eq!(
        mesh.device.borrow_mut().local_get(prop::DEV_NAME),
        b"Ridgeline"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn several_properties_travel_in_one_exchange() {
    mesh!("multi", mesh);
    let keys = [prop::PROTOCOL_VERSION, prop::DEV_VERSION, prop::DEV_NAME];
    let mut buf = [0u8; 32];
    let len = frame::prop_multi_get(&mut buf, 0, &keys).unwrap();
    let reply = mesh.reply(&buf[..len]).await;
    let entries = entries_of(&reply);
    assert_eq!(
        entries.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        keys.to_vec()
    );
    assert_eq!(entries[2].1, b"Simulated Device");
    assert_eq!(mesh.device.borrow().executed, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_read_larger_than_one_payload_is_continued_across_exchanges() {
    mesh!("cursor", mesh);
    // Enough state that the answer cannot fit one payload: each peer is
    // 32 octets of entry, and the whole table is read at once.
    for index in 0..6u8 {
        let mut key = [0x70u8; 32];
        key[31] = index;
        mesh.device.borrow_mut().provision_peer(&key);
    }

    let keys = [
        prop::DEV_PEERS,
        prop::DEV_ADMINS,
        prop::DEV_NAME,
        prop::CAPS,
    ];
    let mut buf = [0u8; 32];
    let len = frame::prop_multi_get(&mut buf, 0, &keys).unwrap();
    let reply = mesh.reply(&buf[..len]).await;
    let entries = entries_of(&reply);
    assert_eq!(
        entries.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        keys.to_vec(),
        "the reassembled entry list covers every slot"
    );
    assert_eq!(entries[0].1.len(), 6 * 32);
    assert!(
        mesh.device.borrow().executed > 1,
        "a continued read takes several exchanges"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_reset_is_answered_by_the_acknowledgment_and_nothing_else() {
    mesh!("reset", mesh);
    let mut buf = [0u8; 8];
    let len = frame::reset(&mut buf, 0).unwrap();
    assert_eq!(mesh.run(&buf[..len]).await, Outcome::NoResponse);
    assert_eq!(mesh.device.borrow().executed, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn an_unlisted_administrator_is_answered_by_silence() {
    mesh!("unlisted", mesh);
    // The device forgets who may manage it, without telling anyone.
    mesh.device.borrow_mut().admins.clear();
    let mut buf = [0u8; 16];
    let len = frame::prop_get(&mut buf, 0, prop::DEV_NAME).unwrap();
    mesh.manager.begin(&buf[..len], mesh.now_ms()).unwrap();
    // Waiting out the whole attempt budget would take half a minute and
    // prove nothing further: what matters is that the request arrived,
    // was refused, and drew no answer.
    mesh.settle(8).await;
    assert!(mesh.manager.is_busy(), "still waiting on an answer");
    assert!(mesh.device.borrow().unauthorized > 0);
    assert_eq!(mesh.device.borrow().executed, 0);
}
