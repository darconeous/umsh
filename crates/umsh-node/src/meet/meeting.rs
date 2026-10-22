//! Add peer's contact exchange as an interface drives it: [`Meet`], the
//! session key's lifecycle around it, and Nearby as a list of devices with
//! ids, colors, and how near each seems.
//!
//! A session key lasts for one attempt at most. Once an attempt ends, for
//! any reason, the key goes back to the node, and opening Add peer again
//! draws a new one. Nearby keeps its rows across keys.
//!
//! The node carries out the [`MeetCommand`]s queued here: drawing a session
//! key ([`LocalNode::open_meet`](crate::LocalNode::open_meet)), sending a
//! frame from it, and giving it back. `T` is what the interface knows the
//! other device's holder as once contacts have crossed.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use umsh_core::PublicKey;

use super::{EndReason, Exchanged, Meet, MeetAction, MeetStage, session_color};

/// The Hello interval, in the longest frame's airtimes. A Hello is a small
/// part of the longest frame, so this keeps Hellos to a few percent of the
/// air.
pub const HELLO_FRAMES: u64 = 10;

/// The signal, in dBm, above which a device is one step nearer: past the
/// first it is at 1, past the last at 3.
const NEAR_DBM: [i16; 3] = [-100, -85, -70];

/// How far past a step's signal a device moves before its nearness
/// changes, so a signal at the edge does not flicker between the two.
const NEAR_HYSTERESIS_DB: i16 = 3;

/// A device's place on Nearby, stable while it stays listed.
pub type NearbyId = u32;

/// A device listed on Nearby. It says what kind of device it is and the
/// color it shows for this visit, and nothing of whose it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nearby {
    pub id: NearbyId,
    /// Its model id (`boards.json`, `platforms.json`).
    pub model: u16,
    /// Its session color, as `0xRRGGBB`.
    pub color: u32,
    /// How near it seems, 0 (far) to 3 (close), when the bearer reports
    /// signal strength.
    pub nearness: Option<u8>,
}

/// Where the exchange stands, as Add peer shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exchange<T> {
    /// Add peer is not open.
    Closed,
    /// Add peer is open and its session is being set up.
    Opening,
    /// Listed on Nearby, nothing in progress.
    Idle,
    /// We asked; waiting for an answer.
    Asking(Nearby),
    /// We were asked; waiting for our holder.
    Asked(Nearby),
    /// We agreed; waiting for the other device to go on.
    Accepted(Nearby),
    /// Both hold `code`. `sent` once our holder pressed Same.
    Comparing { with: Nearby, code: u32, sent: bool },
    /// It ended without contacts crossing.
    Ended(EndReason),
    /// Contacts crossed: who the other device says it is. Nothing is saved.
    Exchanged(T),
}

/// What the node is asked to do for the exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeetCommand {
    /// Draw a session key, giving back any earlier one, and hand it to
    /// [`Meeting::opened`].
    Open,
    /// Send `frame` from the session key: to `to`, or as a broadcast.
    Send {
        to: Option<PublicKey>,
        frame: Vec<u8>,
    },
    /// Give back the session key.
    Close,
}

/// One device listed on Nearby.
struct Device {
    key: PublicKey,
    id: NearbyId,
    /// Its signal, smoothed over the Hellos heard.
    smoothed: Option<i16>,
    nearness: Option<u8>,
}

/// Add peer's contact exchange. Every method that can change what Add peer
/// shows calls `changed` when it does.
pub struct Meeting<T> {
    model: u16,
    meet: Option<Meet>,
    /// A session key has been asked of the node and not yet given.
    opening: bool,
    /// The node could not give one.
    broken: bool,
    /// The current session key has gone back to the node.
    spent: bool,
    devices: Vec<Device>,
    next_id: NearbyId,
    /// The device the attempt is with, as it was listed: its row goes once
    /// the attempt ends.
    with: Option<Nearby>,
    exchanged: Option<T>,
    commands: VecDeque<MeetCommand>,
}

impl<T: Clone> Meeting<T> {
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

    /// This device's model id, which its Hellos carry.
    pub fn set_model(&mut self, model: u16) {
        self.model = model;
    }

    /// Opens Add peer for an attempt under a key never used before. `own`
    /// is the node identity's key and `frame_ms` the longest frame's
    /// airtime at the radio's settings, when known.
    pub fn open(
        &mut self,
        now_ms: u64,
        own: PublicKey,
        frame_ms: Option<u32>,
        changed: &mut dyn FnMut(),
    ) {
        let model = self.model;
        let meet = self.meet.get_or_insert_with(|| {
            let interval = u64::from(frame_ms.unwrap_or(0)) * HELLO_FRAMES;
            Meet::new(own, model, interval)
        });
        // An attempt in progress ends from its own key, before that key
        // goes.
        meet.cancel(now_ms);
        self.drain(changed);
        self.exchanged = None;
        self.with = None;
        self.broken = false;
        self.ask_for_key();
        changed();
    }

    /// The node drew a session key, or could not.
    pub fn opened(
        &mut self,
        now_ms: u64,
        session: Option<(PublicKey, [u8; 32])>,
        changed: &mut dyn FnMut(),
    ) -> Option<Exchanged> {
        self.opening = false;
        let Some(meet) = self.meet.as_mut() else {
            // Add peer closed while the key was drawn.
            if session.is_some() {
                self.commands.push_back(MeetCommand::Close);
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
                changed();
            }
        }
        self.drain(changed)
    }

    /// Leaves Add peer, backing out of any attempt in progress.
    pub fn close(&mut self, now_ms: u64, changed: &mut dyn FnMut()) {
        let Some(meet) = self.meet.as_mut() else {
            return;
        };
        meet.close(now_ms);
        self.drain(changed);
        self.meet = None;
        if !self.spent && !self.opening {
            self.commands.push_back(MeetCommand::Close);
        }
        self.spent = true;
        self.devices.clear();
        self.with = None;
        self.exchanged = None;
        self.broken = false;
        changed();
    }

    /// Whether Add peer is open.
    pub fn is_open(&self) -> bool {
        self.meet.is_some()
    }

    /// Takes a Meet frame the node received.
    pub fn hear(
        &mut self,
        now_ms: u64,
        from: PublicKey,
        broadcast: bool,
        rssi: Option<i16>,
        body: &[u8],
        changed: &mut dyn FnMut(),
    ) -> Option<Exchanged> {
        let meet = self.meet.as_mut()?;
        meet.hear(now_ms, from, broadcast, rssi, body);
        let theirs = self.drain(changed);
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
                changed();
            }
        }
        theirs
    }

    /// Services the exchange's deadlines that have come.
    pub fn tick(&mut self, now_ms: u64, changed: &mut dyn FnMut()) -> Option<Exchanged> {
        let meet = self.meet.as_mut()?;
        if meet.deadline().is_some_and(|at| now_ms >= at) {
            meet.tick(now_ms);
        }
        self.drain(changed)
    }

    /// When [`Meeting::tick`] next has something to do.
    pub fn deadline(&self) -> Option<u64> {
        self.meet.as_ref()?.deadline()
    }

    /// Asks `device` to exchange. Returns whether the ask went out.
    pub fn ask(&mut self, now_ms: u64, device: NearbyId, changed: &mut dyn FnMut()) -> bool {
        let Some(key) = self
            .devices
            .iter()
            .find(|listed| listed.id == device)
            .map(|listed| listed.key)
        else {
            return false;
        };
        let asked = self.meet.as_mut().is_some_and(|meet| meet.ask(now_ms, key));
        self.drain(changed);
        asked
    }

    /// Answers the device that asked.
    pub fn answer(&mut self, now_ms: u64, accept: bool, changed: &mut dyn FnMut()) {
        if let Some(meet) = self.meet.as_mut() {
            meet.answer(now_ms, accept);
        }
        self.drain(changed);
    }

    /// Our holder found the codes the same: `identity` is the node
    /// identity payload to send.
    pub fn same(
        &mut self,
        now_ms: u64,
        identity: &[u8],
        changed: &mut dyn FnMut(),
    ) -> Option<Exchanged> {
        self.meet.as_mut()?.same(now_ms, identity);
        self.drain(changed)
    }

    /// Our holder found the codes different.
    pub fn different(&mut self, now_ms: u64, changed: &mut dyn FnMut()) {
        if let Some(meet) = self.meet.as_mut() {
            meet.different(now_ms);
        }
        self.drain(changed);
    }

    /// Our holder backed out of the attempt in progress.
    pub fn cancel(&mut self, now_ms: u64, changed: &mut dyn FnMut()) {
        if let Some(meet) = self.meet.as_mut() {
            meet.cancel(now_ms);
        }
        self.drain(changed);
    }

    /// Whether an attempt is comparing codes, for Same to send into.
    pub fn comparing(&self) -> bool {
        self.meet
            .as_ref()
            .is_some_and(|meet| matches!(meet.stage(), MeetStage::Comparing { sent: false, .. }))
    }

    /// Who the other device turned out to be, as the interface knows them
    /// now.
    pub fn exchanged_with(&mut self, them: T, changed: &mut dyn FnMut()) {
        if self.meet.is_some() {
            self.exchanged = Some(them);
            changed();
        }
    }

    /// What the node is asked to do next for the exchange.
    pub fn command(&mut self) -> Option<MeetCommand> {
        self.commands.pop_front()
    }

    /// Whether the node has been asked something it has yet to take.
    pub fn has_commands(&self) -> bool {
        !self.commands.is_empty()
    }

    /// This device's color for this visit, once the session is up.
    pub fn own_color(&self) -> Option<u32> {
        self.meet
            .as_ref()?
            .session_key()
            .map(|key| session_color(&key))
    }

    /// The devices heard, oldest first.
    pub fn devices(&self) -> impl Iterator<Item = Nearby> + '_ {
        self.meet.iter().flat_map(move |meet| {
            self.devices
                .iter()
                .map(move |device| self.listed(device, meet))
        })
    }

    /// The device the exchange is with, or was until it ended.
    pub fn with(&self) -> Option<Nearby> {
        self.meet.as_ref().and(self.with)
    }

    /// Where the exchange stands.
    pub fn exchange(&self) -> Exchange<T> {
        let Some(meet) = &self.meet else {
            return Exchange::Closed;
        };
        if self.broken {
            return Exchange::Ended(EndReason::Failed);
        }
        if let Some(them) = &self.exchanged {
            return Exchange::Exchanged(them.clone());
        }
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
            MeetStage::Ended(reason) => Exchange::Ended(reason),
            // What crossed is on its way to the interface.
            MeetStage::Exchanged => Exchange::Opening,
        }
    }

    fn ask_for_key(&mut self) {
        if !self.opening {
            self.opening = true;
            self.commands.push_back(MeetCommand::Open);
        }
    }

    /// Carries out what the machine asks, and keeps the rows and the
    /// session key in step with it. Returns what crossed, when an exchange
    /// completed.
    fn drain(&mut self, changed: &mut dyn FnMut()) -> Option<Exchanged> {
        let meet = self.meet.as_mut()?;
        let mut moved = false;
        let mut theirs = None;
        let mut renew = false;
        while let Some(action) = meet.poll_action() {
            match action {
                MeetAction::Send { to, frame } => {
                    self.commands.push_back(MeetCommand::Send { to, frame });
                }
                MeetAction::Renew => renew = true,
                MeetAction::Changed => moved = true,
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
            self.commands.push_back(MeetCommand::Close);
        }
        if renew {
            self.ask_for_key();
        }
        if moved {
            changed();
        }
        theirs
    }

    fn listed(&self, device: &Device, meet: &Meet) -> Nearby {
        let row = meet.rows().iter().find(|row| row.key == device.key);
        Nearby {
            id: device.id,
            model: row.map_or(0, |row| row.model),
            color: session_color(&device.key),
            nearness: device.nearness,
        }
    }

    /// The attempt's device: as listed, or as it was when its row went.
    fn device_of(&self, key: &PublicKey, meet: &Meet) -> Nearby {
        if let Some(device) = self.devices.iter().find(|device| device.key == *key) {
            return self.listed(device, meet);
        }
        self.with.unwrap_or(Nearby {
            id: NearbyId::MAX,
            model: 0,
            color: session_color(key),
            nearness: None,
        })
    }
}

impl<T: Clone> Default for Meeting<T> {
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
