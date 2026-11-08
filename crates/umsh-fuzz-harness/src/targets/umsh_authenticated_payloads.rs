//! Past the MIC: payloads from a party the node trusts, through the node
//! layer and into a chat session, the way an application receives them.

use std::cell::RefCell;
use std::pin::pin;
use std::rc::Rc;

use umsh_hal::{Clock, RxOrigin};
use umsh_mac::MacHandle;
use umsh_node::Host;
use umsh_sync::AsyncRefCell;
use umsh_text::chat::{ChatFacade, Seeds};
use umsh_text::engine::EngineConfig;
use umsh_text::node_adapter::{Inbound, WellKnownChannels, inbound_text};
use umsh_text::validate::DirectChannelProfile;

use crate::block_on;
use crate::fixup::{self, cast};
use crate::mac::Station;
use crate::script::{Fields, records};

pub const OP_RX: u8 = 0;
pub const OP_ADVANCE: u8 = 1;
const OPS: u8 = 2;

pub fn run(data: &[u8]) {
    let cast = cast();
    let pinned: Vec<_> = cast.parties[..fixup::PINNED_PARTIES]
        .iter()
        .map(|party| party.key)
        .collect();
    let station = Station::<16, 0>::new(&[], false, &cast.local_secret, &pinned);
    let clock = station.clock.clone();
    let local = station.local;
    let cell = Box::new(AsyncRefCell::new(*station.mac));
    let mut host = Host::new(MacHandle::new(&cell));
    let node = host.add_node(local);

    let chat = Rc::new(RefCell::new(ChatFacade::<DirectChannelProfile>::new(
        DirectChannelProfile,
        cast.local_key,
        EngineConfig::default(),
        Seeds {
            session_id: 1,
            jitter_seed: 1,
        },
    )));
    let tag = fixup::engine().derive_channel_tag(&cast.channel_key);
    chat.borrow_mut()
        .channels_mut()
        .register(tag, cast.channel_key, None);

    let well_known = WellKnownChannels::derive();
    let receiver = chat.clone();
    let time = clock.clone();
    let local_key = cast.local_key;
    let _subscription = node.on_receive(move |packet| {
        if let Some(Inbound::Text(text)) = inbound_text(packet, &local_key, &well_known) {
            let mut chat = receiver.borrow_mut();
            if let Some(source) = text.source(chat.channels()) {
                let _ = chat.receive(source, &text.payload, time.now_ms());
            }
        }
        false
    });

    // The pump is one future for the whole run, as on a device: a cycle
    // it has begun is finished on a later poll, never dropped. Each poll
    // runs it until it waits; a node that never does trips the radio's
    // own bound on polls.
    let mut pump = pin!(host.run());
    let mut settle = || {
        block_on::ready(async { cell.borrow_mut().await.radio_mut().refill() });
        if let Some(result) = block_on::poll_pinned(pump.as_mut()) {
            panic!("the pump stopped: {result:?}");
        }
    };

    for record in records(data) {
        match record.op % OPS {
            OP_RX => {
                let mut fields = Fields::new(record.body);
                let selector = fields.u8();
                clock.advance_ms(u64::from(fields.u16()));
                let frame = fixup::apply(fields.rest(), selector);
                if frame.len() <= 255 {
                    block_on::ready(async {
                        cell.borrow_mut()
                            .await
                            .radio_mut()
                            .inject(frame, -60, 5, RxOrigin::Air);
                    });
                }
            }
            _ => clock.advance_ms(u64::from(Fields::new(record.body).u16()) * 8),
        }
        settle();
        let mut chat = chat.borrow_mut();
        chat.tick(clock.now_ms());
        let _ = chat.drain();
    }
}
