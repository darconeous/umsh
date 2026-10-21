//! Add peer's contact exchange (`app-meet.md`): the exchange's machine,
//! fed by the device node through [`crate::task`], and what the interface
//! reads of it.
//!
//! A session key lasts for one attempt at most. Once an attempt ends, for
//! any reason, the key goes back to the device node, and opening Add peer
//! again draws a new one. Nearby keeps its rows across keys.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use umsh_core::PublicKey;
use umsh_node::meet::{EndReason, Exchanged, Meet, MeetAction, MeetStage, session_hue};
use umsh_ux_communicator::model::{
    Exchange, ExchangeEnd, MeetState, Member, NearbyDevice, NearbyId, NodeEvent,
};

use crate::task::Command;

/// The Hello interval, in the longest frame's airtimes. A Hello is a small
/// part of the longest frame, so this keeps Hellos to a few percent of the
/// air.
const HELLO_FRAMES: u64 = 10;

/// The signal, in dBm, above which a device is one step nearer: past the
/// first it is at 1, past the last at 3.
const NEAR_DBM: [i16; 3] = [-100, -85, -70];

/// How far past a step's signal a device moves before its nearness
/// changes, so a signal at the edge does not flicker between the two.
const NEAR_HYSTERESIS_DB: i16 = 3;

/// One device listed on Nearby, as the interface names it.
struct Device {
    key: PublicKey,
    id: NearbyId,
    /// Its signal, smoothed over the Hellos heard.
    smoothed: Option<i16>,
    nearness: Option<u8>,
}

/// The contact exchange of the communicator's node.
pub struct Meeting {
    model: u16,
    meet: Option<Meet>,
    /// A session key has been asked of the device node and not yet given.
    opening: bool,
    /// The device node could not give one.
    broken: bool,
    /// The current session key has gone back to the device node.
    spent: bool,
    devices: Vec<Device>,
    next_id: NearbyId,
    /// The device the attempt is with, as it was listed: its row goes once
    /// the attempt ends.
    with: Option<NearbyDevice>,
    exchanged: Option<Member>,
    commands: VecDeque<Command>,
}

impl Meeting {
    pub const fn new() -> Self {
        Self {
            model: 0,
            meet: None,
            opening: false,
            broken: false,
            spent: true,
            devices: Vec::new(),
            next_id: 0,
            with: None,
            exchanged: None,
            commands: VecDeque::new(),
        }
    }

    /// This board's model id (`boards.json`), which its Hellos carry.
    pub fn set_model(&mut self, model: u16) {
        self.model = model;
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
        let model = self.model;
        let meet = self.meet.get_or_insert_with(|| {
            let interval = u64::from(frame_ms.unwrap_or(0)) * HELLO_FRAMES;
            Meet::new(own, model, interval)
        });
        // An attempt in progress ends from its own key, before that key
        // goes.
        meet.cancel(now_ms);
        self.drain(events);
        self.exchanged = None;
        self.with = None;
        self.broken = false;
        self.ask_for_key();
        events(NodeEvent::MeetChanged);
    }

    /// The device node drew a session key, or could not.
    pub fn opened(
        &mut self,
        now_ms: u64,
        session: Option<(PublicKey, [u8; 32])>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Exchanged> {
        self.opening = false;
        let Some(meet) = self.meet.as_mut() else {
            // Add peer closed while the key was drawn.
            if session.is_some() {
                self.commands.push_back(Command::CloseMeet);
            }
            return None;
        };
        match session {
            Some((key, seed)) => {
                self.spent = false;
                meet.start(now_ms, key, seed);
            }
            None => {
                self.broken = true;
                events(NodeEvent::MeetChanged);
            }
        }
        self.drain(events)
    }

    /// Leaves Add peer, backing out of any attempt in progress.
    pub fn close(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) {
        let Some(meet) = self.meet.as_mut() else {
            return;
        };
        meet.close(now_ms);
        self.drain(events);
        self.meet = None;
        if !self.spent && !self.opening {
            self.commands.push_back(Command::CloseMeet);
        }
        self.spent = true;
        self.devices.clear();
        self.with = None;
        self.exchanged = None;
        self.broken = false;
        events(NodeEvent::MeetChanged);
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
        let meet = self.meet.as_mut()?;
        meet.hear(now_ms, from, broadcast, rssi, body);
        let theirs = self.drain(events);
        if broadcast
            && let Some(rssi) = rssi
            && let Some(device) = self.devices.iter_mut().find(|device| device.key == from)
        {
            let smoothed = device.smoothed.map_or(rssi, |before| {
                ((3 * i32::from(before) + i32::from(rssi)) / 4) as i16
            });
            let nearness = nearness(smoothed, device.nearness);
            device.smoothed = Some(smoothed);
            if device.nearness != Some(nearness) {
                device.nearness = Some(nearness);
                events(NodeEvent::MeetChanged);
            }
        }
        theirs
    }

    /// Services the exchange's deadlines that have come.
    pub fn tick(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) -> Option<Exchanged> {
        let meet = self.meet.as_mut()?;
        if meet.deadline().is_some_and(|at| now_ms >= at) {
            meet.tick(now_ms);
        }
        self.drain(events)
    }

    /// When [`Meeting::tick`] next has something to do.
    pub fn deadline(&self) -> Option<u64> {
        self.meet.as_ref()?.deadline()
    }

    pub fn ask(
        &mut self,
        now_ms: u64,
        device: NearbyId,
        events: &mut dyn FnMut(NodeEvent),
    ) -> bool {
        let Some(key) = self
            .devices
            .iter()
            .find(|listed| listed.id == device)
            .map(|listed| listed.key)
        else {
            return false;
        };
        let asked = self.meet.as_mut().is_some_and(|meet| meet.ask(now_ms, key));
        self.drain(events);
        asked
    }

    pub fn answer(&mut self, now_ms: u64, accept: bool, events: &mut dyn FnMut(NodeEvent)) {
        if let Some(meet) = self.meet.as_mut() {
            meet.answer(now_ms, accept);
        }
        self.drain(events);
    }

    /// Our holder found the codes the same: `identity` is the node
    /// identity payload to send.
    pub fn same(
        &mut self,
        now_ms: u64,
        identity: &[u8],
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Exchanged> {
        self.meet.as_mut()?.same(now_ms, identity);
        self.drain(events)
    }

    pub fn different(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) {
        if let Some(meet) = self.meet.as_mut() {
            meet.different(now_ms);
        }
        self.drain(events);
    }

    pub fn cancel(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) {
        if let Some(meet) = self.meet.as_mut() {
            meet.cancel(now_ms);
        }
        self.drain(events);
    }

    /// Whether an attempt is comparing codes, for Same to send into.
    pub fn comparing(&self) -> bool {
        self.meet
            .as_ref()
            .is_some_and(|meet| matches!(meet.stage(), MeetStage::Comparing { sent: false, .. }))
    }

    /// Who the other device turned out to be, as the chats know them now.
    pub fn exchanged_with(&mut self, member: Member, events: &mut dyn FnMut(NodeEvent)) {
        if self.meet.is_some() {
            self.exchanged = Some(member);
            events(NodeEvent::MeetChanged);
        }
    }

    /// What the device node is asked to do next for the exchange.
    pub fn command(&mut self) -> Option<Command> {
        self.commands.pop_front()
    }

    /// Whether the device node has been asked something it has yet to take.
    pub fn has_commands(&self) -> bool {
        !self.commands.is_empty()
    }

    /// What Add peer shows, read into `state`.
    pub fn state(&self, state: &mut MeetState) {
        state.devices.clear();
        let Some(meet) = &self.meet else {
            *state = MeetState::new();
            return;
        };
        state.own_hue = meet.session_key().map(|key| session_hue(&key));
        state.with = self.with;
        for device in &self.devices {
            if state.devices.push(self.listed(device, meet)).is_err() {
                break;
            }
        }
        state.exchange = if self.broken {
            Exchange::Ended(ExchangeEnd::Failed)
        } else if let Some(member) = &self.exchanged {
            Exchange::Exchanged(member.clone())
        } else {
            match meet.stage() {
                MeetStage::Closed => Exchange::Opening,
                MeetStage::Idle => Exchange::Idle,
                MeetStage::Requesting { peer } => Exchange::Asking(self.device_of(&peer, meet)),
                MeetStage::Asked { peer } => Exchange::Asked(self.device_of(&peer, meet)),
                MeetStage::Accepted { peer } => Exchange::Accepted(self.device_of(&peer, meet)),
                MeetStage::Comparing { peer, code, sent } => Exchange::Comparing {
                    with: self.device_of(&peer, meet),
                    code,
                    sent,
                },
                // Its key is on its way out, and a new one on its way in.
                MeetStage::Ended(_) if self.opening => Exchange::Opening,
                MeetStage::Ended(reason) => Exchange::Ended(ending(reason)),
                // What crossed is on its way to the chats.
                MeetStage::Exchanged => Exchange::Opening,
            }
        };
    }

    fn ask_for_key(&mut self) {
        if !self.opening {
            self.opening = true;
            self.commands.push_back(Command::OpenMeet);
        }
    }

    /// Carries out what the machine asks, and keeps the rows and the
    /// session key in step with it. Returns what crossed, when an exchange
    /// completed.
    fn drain(&mut self, events: &mut dyn FnMut(NodeEvent)) -> Option<Exchanged> {
        let meet = self.meet.as_mut()?;
        let mut changed = false;
        let mut theirs = None;
        let mut renew = false;
        while let Some(action) = meet.poll_action() {
            match action {
                MeetAction::Send { to, frame } => {
                    self.commands.push_back(Command::SendMeet { to, frame });
                }
                MeetAction::Renew => renew = true,
                MeetAction::Changed => changed = true,
                MeetAction::Exchanged(exchanged) => theirs = Some(exchanged),
            }
        }
        let stage = meet.stage();
        let rows: Vec<PublicKey> = meet.rows().iter().map(|row| row.key).collect();

        self.devices.retain(|device| rows.contains(&device.key));
        for key in rows {
            if !self.devices.iter().any(|device| device.key == key) {
                self.devices.push(Device {
                    key,
                    id: self.next_id,
                    smoothed: None,
                    nearness: None,
                });
                self.next_id = self.next_id.wrapping_add(1);
            }
        }
        if let MeetStage::Requesting { peer }
        | MeetStage::Asked { peer }
        | MeetStage::Accepted { peer }
        | MeetStage::Comparing { peer, .. } = stage
            && let Some(meet) = &self.meet
        {
            self.with = Some(self.device_of(&peer, meet));
        }
        if matches!(stage, MeetStage::Ended(_) | MeetStage::Exchanged) && !self.spent {
            self.spent = true;
            self.commands.push_back(Command::CloseMeet);
        }
        if renew {
            self.ask_for_key();
        }
        if changed {
            events(NodeEvent::MeetChanged);
        }
        theirs
    }

    fn listed(&self, device: &Device, meet: &Meet) -> NearbyDevice {
        let row = meet.rows().iter().find(|row| row.key == device.key);
        NearbyDevice {
            id: device.id,
            model: row.map_or(0, |row| row.model),
            hue: session_hue(&device.key),
            nearness: device.nearness,
        }
    }

    /// The attempt's device: as listed, or as it was when its row went.
    fn device_of(&self, key: &PublicKey, meet: &Meet) -> NearbyDevice {
        if let Some(device) = self.devices.iter().find(|device| device.key == *key) {
            return self.listed(device, meet);
        }
        self.with.unwrap_or(NearbyDevice {
            id: NearbyId::MAX,
            model: 0,
            hue: session_hue(key),
            nearness: None,
        })
    }
}

impl Default for Meeting {
    fn default() -> Self {
        Self::new()
    }
}

/// How near a device at `smoothed` dBm is, from how near it was.
fn nearness(smoothed: i16, before: Option<u8>) -> u8 {
    let Some(mut level) = before else {
        return NEAR_DBM.iter().filter(|&&floor| smoothed > floor).count() as u8;
    };
    while usize::from(level) < NEAR_DBM.len()
        && smoothed > NEAR_DBM[usize::from(level)] + NEAR_HYSTERESIS_DB
    {
        level += 1;
    }
    while level > 0 && smoothed < NEAR_DBM[usize::from(level) - 1] - NEAR_HYSTERESIS_DB {
        level -= 1;
    }
    level
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearness_holds_at_the_edge() {
        assert_eq!(nearness(-90, None), 1);
        assert_eq!(nearness(-84, Some(1)), 1);
        assert_eq!(nearness(-81, Some(1)), 2);
        assert_eq!(nearness(-87, Some(2)), 2);
        assert_eq!(nearness(-89, Some(2)), 1);
        assert_eq!(nearness(-40, Some(0)), 3);
        assert_eq!(nearness(-120, Some(3)), 0);
    }
}
