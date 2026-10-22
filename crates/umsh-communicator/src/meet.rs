//! Add peer's contact exchange (`app-meet.md`): the shared
//! [`umsh_node::meet::Meeting`], fed by the device node through
//! [`crate::task`], and what the interface reads of it.

use umsh_core::PublicKey;
use umsh_node::meet::{self, EndReason, Exchanged, MeetCommand};
use umsh_ux_communicator::model::{
    Exchange, ExchangeEnd, MeetState, Member, NearbyDevice, NearbyId, NodeEvent,
};

use crate::task::Command;

/// The contact exchange of the communicator's node.
pub struct Meeting(meet::Meeting<Member>);

impl Meeting {
    pub const fn new() -> Self {
        Self(meet::Meeting::new())
    }

    /// This board's model id (`boards.json`), which its Hellos carry.
    pub fn set_model(&mut self, model: u16) {
        self.0.set_model(model);
    }

    /// Opens Add peer for an attempt under a key never used before. `own`
    /// is the device identity's key and `frame_ms` the longest frame's
    /// airtime at the radio's settings, when known.
    pub fn open(
        &mut self,
        now_ms: u64,
        own: PublicKey,
        frame_ms: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        self.0.open(now_ms, own, frame_ms, &mut changed(events));
    }

    /// The device node drew a session key, or could not.
    pub fn opened(
        &mut self,
        now_ms: u64,
        session: Option<(PublicKey, [u8; 32])>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Exchanged> {
        self.0.opened(now_ms, session, &mut changed(events))
    }

    /// Leaves Add peer, backing out of any attempt in progress.
    pub fn close(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) {
        self.0.close(now_ms, &mut changed(events));
    }

    /// Takes a Meet frame the device node received.
    pub fn hear(
        &mut self,
        now_ms: u64,
        from: PublicKey,
        broadcast: bool,
        rssi: Option<i16>,
        body: &[u8],
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Exchanged> {
        self.0
            .hear(now_ms, from, broadcast, rssi, body, &mut changed(events))
    }

    /// Services the exchange's deadlines that have come.
    pub fn tick(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) -> Option<Exchanged> {
        self.0.tick(now_ms, &mut changed(events))
    }

    /// When [`Meeting::tick`] next has something to do.
    pub fn deadline(&self) -> Option<u64> {
        self.0.deadline()
    }

    pub fn ask(
        &mut self,
        now_ms: u64,
        device: NearbyId,
        events: &mut dyn FnMut(NodeEvent),
    ) -> bool {
        self.0.ask(now_ms, device, &mut changed(events))
    }

    pub fn answer(&mut self, now_ms: u64, accept: bool, events: &mut dyn FnMut(NodeEvent)) {
        self.0.answer(now_ms, accept, &mut changed(events));
    }

    /// Our holder found the codes the same: `identity` is the node
    /// identity payload to send.
    pub fn same(
        &mut self,
        now_ms: u64,
        identity: &[u8],
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Exchanged> {
        self.0.same(now_ms, identity, &mut changed(events))
    }

    pub fn different(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) {
        self.0.different(now_ms, &mut changed(events));
    }

    pub fn cancel(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) {
        self.0.cancel(now_ms, &mut changed(events));
    }

    /// Whether an attempt is comparing codes, for Same to send into.
    pub fn comparing(&self) -> bool {
        self.0.comparing()
    }

    /// Who the other device turned out to be, as the chats know them now.
    pub fn exchanged_with(&mut self, member: Member, events: &mut dyn FnMut(NodeEvent)) {
        self.0.exchanged_with(member, &mut changed(events));
    }

    /// What the device node is asked to do next for the exchange.
    pub fn command(&mut self) -> Option<Command> {
        Some(match self.0.command()? {
            MeetCommand::Open => Command::OpenMeet,
            MeetCommand::Send { to, frame } => Command::SendMeet { to, frame },
            MeetCommand::Close => Command::CloseMeet,
        })
    }

    /// Whether the device node has been asked something it has yet to take.
    pub fn has_commands(&self) -> bool {
        self.0.has_commands()
    }

    /// What Add peer shows, read into `state`.
    pub fn state(&self, state: &mut MeetState) {
        *state = MeetState::new();
        if !self.0.is_open() {
            return;
        }
        state.own_color = self.0.own_color();
        state.with = self.0.with().map(device);
        for nearby in self.0.devices() {
            if state.devices.push(device(nearby)).is_err() {
                break;
            }
        }
        state.exchange = match self.0.exchange() {
            meet::Exchange::Closed => Exchange::Closed,
            meet::Exchange::Opening => Exchange::Opening,
            meet::Exchange::Idle => Exchange::Idle,
            meet::Exchange::Asking(with) => Exchange::Asking(device(with)),
            meet::Exchange::Asked(with) => Exchange::Asked(device(with)),
            meet::Exchange::Accepted(with) => Exchange::Accepted(device(with)),
            meet::Exchange::Comparing { with, code, sent } => Exchange::Comparing {
                with: device(with),
                code,
                sent,
            },
            meet::Exchange::Ended(reason) => Exchange::Ended(ending(reason)),
            meet::Exchange::Exchanged(member) => Exchange::Exchanged(member),
        };
    }
}

impl Default for Meeting {
    fn default() -> Self {
        Self::new()
    }
}

/// The shared machine's change, as the interface hears of it.
fn changed(events: &mut dyn FnMut(NodeEvent)) -> impl FnMut() + '_ {
    move || events(NodeEvent::MeetChanged)
}

const fn device(nearby: meet::Nearby) -> NearbyDevice {
    NearbyDevice {
        id: nearby.id,
        model: nearby.model,
        color: nearby.color,
        nearness: nearby.nearness,
    }
}

const fn ending(reason: EndReason) -> ExchangeEnd {
    match reason {
        EndReason::NotNow => ExchangeEnd::NotNow,
        EndReason::Busy => ExchangeEnd::Busy,
        EndReason::Different => ExchangeEnd::Different,
        EndReason::Left => ExchangeEnd::Left,
        EndReason::TimedOut => ExchangeEnd::TimedOut,
        EndReason::Failed | EndReason::Unknown(_) => ExchangeEnd::Failed,
    }
}
