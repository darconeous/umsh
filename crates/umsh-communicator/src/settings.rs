//! The device's settings, as the communicator shows and changes them.
//!
//! Every setting is a property of the device's own ULCP session, reached
//! through a [`LocalExchange`]. A change is a request the session serves as
//! it serves any host's, and what the session publishes keeps the cache
//! current, whoever made the change: this interface, an attached phone, or
//! an administrator across the mesh.
//!
//! A setter changes what its read reports at once. The outcome follows as
//! an event: [`NodeEvent::SettingsChanged`] once the device has applied
//! it, or [`NodeEvent::SettingRefused`], after which the read reports what
//! the device kept.
//!
//! **Saving.** The device keeps an existing snapshot in step with every
//! change made here (`ulcp-saved-state.md`, Changes Made at the Device),
//! but never makes one. So the first boot saves one, and a change whose
//! loss would matter—the name, the radio—is followed by a save when the
//! device has none in effect. Brightness, the volume, the keyboard, and
//! pairing never ask for one.
//!
//! **The radio.** A reset leaves the radio off until a host turns it on
//! (`ulcp-radio.md`). A communicator is its own host, so its first boot
//! turns the radio on before saving; from then on the radio is as it was
//! last left.
//!
//! **Peers and channels.** The device's store keeps `PROP_DEV_PEERS` and
//! `PROP_DEV_CHANNEL_KEYS` outside the snapshot, so changing them asks for
//! no save. A communicator starts out on `public` and `EMERGENCY`: they are
//! what its channel keys hold after a reset (`ulcp-device.md`, Lists Held
//! by the Device's Store; see
//! [`ChannelCrypto::starting_keys`](crate::ChannelCrypto::starting_keys)).

use umsh_core::ChannelTag;
use umsh_ulcp::ids::{DEFAULT_SOUND_VOLUME, cap, keyboard_aids, prop, saved};
use umsh_ulcp::profiles::VETTED;
use umsh_ulcp_admin::descriptor::Value;
use umsh_ulcp_admin::{
    Event, Freshness, LocalExchange, LocalPort, Model, Refusal, WriteId, WriteOutcome,
};
use umsh_ux_communicator::avatar::{AvatarStyle, PeerShape};
use umsh_ux_communicator::heapless::{Deque, String, Vec};
use umsh_ux_communicator::model::{
    ClockSettings, DEFAULT_AUTO_LOCK_S, KeyboardSettings, NodeEvent, Profile, RadioSettings, Rule,
    Setting, ShareUri, Statistics, brightness_at,
};

use crate::chat::address;

/// How long after a change worth saving the device is asked to save it, so
/// that a burst of changes is saved once.
pub const SAVE_DELAY_MS: u64 = 2_000;

/// How often the airtime spent is read again. The device counts it in
/// four-minute steps.
pub const AIRTIME_READ_MS: u64 = 60_000;

/// How often the device's counters are read while they are watched.
pub const STATISTICS_READ_MS: u64 = 5_000;

/// The counters the Statistics screen shows, read together.
const STATISTICS: [u32; 13] = [
    prop::STAT_TX_PACKETS,
    prop::STAT_TX_CHANNEL_BUSY,
    prop::STAT_RX_PACKETS,
    prop::STAT_RX_BAD_CRC,
    prop::STAT_RX_NON_UMSH,
    prop::STAT_RX_ACCEPTED,
    prop::STAT_FORWARDED,
    prop::STAT_FORWARD_DROPPED,
    prop::STAT_FORWARD_CANCELLED,
    prop::STAT_MESHCORE_SEEN,
    prop::STAT_MESHCORE_FORWARDED_ROUTED,
    prop::STAT_MESHCORE_FORWARDED_FLOOD,
    prop::STAT_MESHCORE_DECLINED,
];

/// The screen's brightness until the device reports it.
pub const DEFAULT_BRIGHTNESS: u8 = brightness_at(5);

/// How many recent writes are remembered by the setting they changed. The
/// local link answers in milliseconds, far sooner than this many changes
/// can be made.
const WRITES_KEPT: usize = 16;

/// How many saves and forgets of peers are remembered until the device
/// answers them.
const PEER_WRITES_KEPT: usize = 8;

/// How many joins of channels are remembered until the device answers
/// them.
const CHANNEL_WRITES_KEPT: usize = 4;

/// The settings half of the communicator's node.
pub struct Settings<P> {
    model: Model,
    exchange: LocalExchange<P>,
    /// The setting each recent write changed, oldest first.
    writes: Deque<(WriteId, Setting), WRITES_KEPT>,
    /// Peers saved, or with `false` forgotten, that the device has yet to
    /// answer for, oldest first.
    peer_writes: Deque<(WriteId, [u8; 32], bool), PEER_WRITES_KEPT>,
    /// Channels joined (`true`) or left that the device has yet to answer
    /// for, oldest first.
    channel_writes: Deque<(WriteId, ChannelTag, bool), CHANNEL_WRITES_KEPT>,
    /// Channels the device would not join, for the chats to let go of.
    refused_joins: Vec<ChannelTag, CHANNEL_WRITES_KEPT>,
    /// When to ask the device to save.
    save_at: Option<u64>,
    /// Whether the device's saved state at boot has been looked at.
    boot_checked: bool,
    /// When the airtime spent is next read.
    airtime_at: u64,
    /// When the counters are next read, while they are watched.
    statistics_at: Option<u64>,
    now_ms: u64,
}

impl<P: LocalPort> Settings<P> {
    /// Settings read over `port`. Nothing is known until the first
    /// [`Settings::pump`] has asked and the device has answered.
    pub fn new(port: P) -> Self {
        let mut model = Model::new();
        model.refresh();
        Self {
            model,
            exchange: LocalExchange::new(port),
            writes: Deque::new(),
            peer_writes: Deque::new(),
            channel_writes: Deque::new(),
            refused_joins: Vec::new(),
            save_at: None,
            boot_checked: false,
            airtime_at: AIRTIME_READ_MS,
            statistics_at: None,
            now_ms: 0,
        }
    }

    pub fn port(&self) -> &P {
        self.exchange.port()
    }

    /// Whether every setting has been read once.
    pub fn primed(&self) -> bool {
        self.boot_checked
    }

    /// Hands what is waiting to the device and takes in what has come back,
    /// passing on what the interface should hear to `events`. The board
    /// calls it after the interface has changed something, and whenever
    /// the device has something for it.
    pub fn pump(&mut self, now_ms: u64, events: &mut impl FnMut(NodeEvent)) {
        self.now_ms = now_ms;
        if now_ms >= self.airtime_at {
            self.airtime_at = now_ms + AIRTIME_READ_MS;
            self.model.read(prop::PHY_DUTY_NOW);
        }
        if self.statistics_at.is_some_and(|at| now_ms >= at) {
            self.statistics_at = Some(now_ms + STATISTICS_READ_MS);
            self.read_statistics();
        }
        if self.save_at.is_some_and(|at| now_ms >= at) {
            self.save_at = None;
            // The device refuses a save only when it has no saved state to
            // keep, which no change made here can fix.
            let _ = self.model.save();
        }
        loop {
            self.model.pump(&mut self.exchange, now_ms);
            let mut took = false;
            while let Some(event) = self.model.next_event() {
                took = true;
                self.take(event, events);
            }
            // Until nothing comes back at once: a save asked for here, or
            // an answer a port gave while being asked.
            if !self.check_boot() && !took {
                break;
            }
        }
    }

    /// When [`Settings::pump`] next has something to do without being
    /// woken by the device.
    pub fn next_deadline(&self) -> Option<u64> {
        [self.save_at, self.statistics_at]
            .into_iter()
            .flatten()
            .fold(Some(self.airtime_at), |next, at| {
                next.map(|next| next.min(at))
            })
    }

    /// Keeps the counters being read while `on`: at the next pump, and
    /// every [`STATISTICS_READ_MS`] after.
    pub fn watch_statistics(&mut self, on: bool) {
        match (on, self.statistics_at) {
            (true, None) => self.statistics_at = Some(self.now_ms),
            (false, Some(_)) => self.statistics_at = None,
            _ => {}
        }
    }

    /// Asks the device for its counters, how long it has run, and the
    /// airtime spent, as far as it keeps them.
    fn read_statistics(&mut self) {
        self.model.read(prop::UPTIME);
        if self.model.has_cap(cap::PHY_DUTY_LIMIT) == Some(true) {
            self.model.read(prop::PHY_DUTY_NOW);
        }
        if self.model.has_cap(cap::STATS) == Some(true) {
            for key in STATISTICS {
                self.model.read(key);
            }
        }
    }

    fn take(&mut self, event: Event, events: &mut impl FnMut(NodeEvent)) {
        match event {
            Event::Changed(_) | Event::Resync => events(NodeEvent::SettingsChanged),
            Event::Written { id, outcome, .. } => {
                if self.peer_writes.iter().any(|(write, ..)| *write == id) {
                    self.peer_writes.retain(|(write, ..)| *write != id);
                    events(NodeEvent::SettingsChanged);
                    return;
                }
                if let Some(&(_, tag, joined)) =
                    self.channel_writes.iter().find(|(write, ..)| *write == id)
                {
                    self.channel_writes.retain(|(write, ..)| *write != id);
                    // An answer that went astray says nothing: the device
                    // is read again, and the channel stays until it says.
                    let refused = matches!(
                        outcome,
                        WriteOutcome::Refused(_) | WriteOutcome::Skipped | WriteOutcome::Unsent
                    );
                    if joined && refused && !self.model.channels().any(|held| *held == tag.0) {
                        _ = self.refused_joins.push(tag);
                    }
                    return;
                }
                let Some(setting) = self
                    .writes
                    .iter()
                    .find(|(write, _)| *write == id)
                    .map(|&(_, setting)| setting)
                else {
                    return;
                };
                match outcome {
                    WriteOutcome::Applied | WriteOutcome::Adjusted => {
                        if matters(setting) {
                            self.save_if_unsaved();
                        }
                        events(NodeEvent::SettingsChanged);
                    }
                    WriteOutcome::Refused(_)
                    | WriteOutcome::Skipped
                    | WriteOutcome::Unknown
                    | WriteOutcome::Unsent => events(NodeEvent::SettingRefused(setting)),
                }
            }
            Event::Saved { .. } | Event::Unavailable { .. } => {}
        }
    }

    /// At first boot nothing is saved: save, so that a snapshot is in
    /// effect from then on. Returns whether a save was asked for.
    fn check_boot(&mut self) -> bool {
        if self.boot_checked
            || !matches!(self.model.freshness(prop::SAVED), Freshness::Fresh { .. })
        {
            return false;
        }
        self.boot_checked = true;
        if self.model.saved() != Some(saved::NONE) {
            return false;
        }
        _ = self.model.set_radio_enabled(true);
        self.model.save().is_ok()
    }

    /// A change that would matter if it were lost is saved, unless the
    /// device kept a snapshot in step with it already.
    fn save_if_unsaved(&mut self) {
        if self.model.saved() != Some(saved::CURRENT) {
            self.save_at = Some(self.now_ms + SAVE_DELAY_MS);
        }
    }

    // ─── Changes ─────────────────────────────────────────────────────
    //
    // Each returns whether the change was taken: false when the device
    // cannot have it, such as a property it does not have. The change goes
    // out at the next pump.

    pub fn set_name(&mut self, name: &str) -> bool {
        let write = self.model.set_device_name(name);
        self.written(Setting::Name, write)
    }

    /// Adopts the vetted profile at `index`.
    pub fn set_profile(&mut self, index: usize) -> bool {
        let Some(profile) = VETTED.get(index) else {
            return false;
        };
        let write = self.model.set_profile(profile);
        self.written(Setting::Profile, write)
    }

    pub fn set_transmit_power(&mut self, dbm: i8) -> bool {
        let write = self.model.set_tx_power_dbm(dbm);
        self.written(Setting::TransmitPower, write)
    }

    pub fn set_radio_enabled(&mut self, on: bool) -> bool {
        let write = self.model.set_radio_enabled(on);
        self.written(Setting::Radio, write)
    }

    pub fn set_bluetooth_enabled(&mut self, on: bool) -> bool {
        let write = self.model.set_bluetooth_enabled(on);
        self.written(Setting::Bluetooth, write)
    }

    pub fn set_sound_enabled(&mut self, on: bool) -> bool {
        let write = self.model.set_sound_enabled(on);
        self.written(Setting::Sound, write)
    }

    pub fn set_sound_volume(&mut self, volume: u8) -> bool {
        let write = self.model.set_sound_volume(volume);
        self.written(Setting::Volume, write)
    }

    pub fn set_setup_complete(&mut self, complete: bool) -> bool {
        let write = self.model.set_setup_complete(complete);
        self.written(Setting::Setup, write)
    }

    pub fn set_pairing(&mut self, open: bool) -> bool {
        let write = self.model.set_pairing(open);
        self.written(Setting::Pairing, write)
    }

    pub fn clear_pairings(&mut self) -> bool {
        let write = self.model.clear_pairings();
        self.written(Setting::Pairing, write)
    }

    /// Erases everything the device keeps and restarts it. Returns whether
    /// it was asked.
    pub fn factory_reset(&mut self) -> bool {
        self.model.factory_reset().is_ok()
    }

    pub fn set_gnss_enabled(&mut self, on: bool) -> bool {
        let write = self.model.set_gnss_enabled(on);
        self.written(Setting::Gnss, write)
    }

    pub fn set_forwarding(&mut self, on: bool) -> bool {
        let write = self.model.set_forwarding(on);
        self.written(Setting::Forwarding, write)
    }

    pub fn set_share_location(&mut self, on: bool) -> bool {
        let write = self.model.set_share_location(on);
        self.written(Setting::ShareLocation, write)
    }

    pub fn set_keyboard(&mut self, settings: KeyboardSettings) -> bool {
        let mut aids = 0;
        if settings.capitalize {
            aids |= keyboard_aids::CAPITALIZE;
        }
        if settings.period {
            aids |= keyboard_aids::PERIOD;
        }
        let write = self.model.set_many(&[
            (prop::KEYBOARD_AIDS, &[aids]),
            (prop::KEYBOARD_LIGHT, &[u8::from(settings.light)]),
        ]);
        self.written(Setting::Keyboard, write)
    }

    pub fn set_clock_automatic(&mut self, on: bool) -> bool {
        let write = self.model.set_gnss_time_trust(on);
        self.written(Setting::Clock, write)
    }

    pub fn set_time(&mut self, time: u32) -> bool {
        let write = self.model.set_time(Some(time));
        self.written(Setting::Time, write)
    }

    pub fn set_zone(&mut self, rule: &str) -> bool {
        let write = self.model.set_tz_rule(rule);
        self.written(Setting::Clock, write)
    }

    pub fn set_hour24(&mut self, on: bool) -> bool {
        let write = self.model.set_time_24h(on);
        self.written(Setting::Clock, write)
    }

    pub fn set_brightness(&mut self, brightness: u8) -> bool {
        let write = self.model.set_brightness(brightness);
        self.written(Setting::Brightness, write)
    }

    pub fn set_auto_lock(&mut self, seconds: u16) -> bool {
        let write = self.model.set_display_timeout(seconds);
        self.written(Setting::AutoLock, write)
    }

    /// Keeps `key` among the device's peers.
    pub fn save_peer(&mut self, key: &[u8; 32]) -> bool {
        let write = self.model.save_peer(key);
        self.peer_written(key, true, write)
    }

    /// No longer keeps `key` among the device's peers.
    pub fn forget_peer(&mut self, key: &[u8; 32]) -> bool {
        let write = self.model.forget_peer(key);
        self.peer_written(key, false, write)
    }

    /// Has the device join the channel `key`, whose tag is `tag`.
    pub fn join_channel(&mut self, key: &[u8; 32], tag: ChannelTag) -> bool {
        let Ok(id) = self.model.join_channel(key) else {
            return false;
        };
        self.channel_written(id, tag, true);
        true
    }

    /// Asks the device to let go of the channel `key`, whose tag is `tag`.
    /// It is no longer among [`Settings::channels`] from now on, unless
    /// the device refuses.
    pub fn leave_channel(&mut self, key: &[u8; 32], tag: ChannelTag) -> bool {
        let Ok(id) = self.model.leave_channel(key) else {
            return false;
        };
        self.channel_written(id, tag, false);
        true
    }

    /// Keeps the write `id`, which joins (`joined`) or leaves `tag`, for the
    /// device's answer, in place of any earlier one for the same channel.
    fn channel_written(&mut self, id: WriteId, tag: ChannelTag, joined: bool) {
        self.channel_writes.retain(|&(_, kept, _)| kept != tag);
        if self.channel_writes.is_full() {
            self.channel_writes.pop_front();
        }
        let _ = self.channel_writes.push_back((id, tag, joined));
    }

    /// The channels the device would not join since last asked.
    pub fn take_refused_joins(&mut self) -> Vec<ChannelTag, CHANNEL_WRITES_KEPT> {
        core::mem::take(&mut self.refused_joins)
    }

    fn peer_written(
        &mut self,
        key: &[u8; 32],
        saved: bool,
        write: Result<WriteId, Refusal>,
    ) -> bool {
        let Ok(id) = write else {
            return false;
        };
        if self.peer_writes.is_full() {
            self.peer_writes.pop_front();
        }
        let _ = self.peer_writes.push_back((id, *key, saved));
        true
    }

    fn written(&mut self, setting: Setting, write: Result<WriteId, Refusal>) -> bool {
        let Ok(id) = write else {
            return false;
        };
        if self.writes.is_full() {
            self.writes.pop_front();
        }
        let _ = self.writes.push_back((id, setting));
        true
    }

    // ─── Reads ───────────────────────────────────────────────────────

    /// `PROP_DEV_KEY`: the device identity, once read.
    pub fn key(&self) -> Option<&[u8; 32]> {
        self.model.device_key()
    }

    /// The device identity's address.
    pub fn address(&self) -> String<44> {
        self.key().map(address).unwrap_or_default()
    }

    /// The device identity's peers: what `PROP_DEV_PEERS` holds once the
    /// device has answered every save and forget asked of it.
    pub fn peers(&self) -> alloc::vec::Vec<[u8; 32]> {
        let mut peers: alloc::vec::Vec<[u8; 32]> = self.model.peers().copied().collect();
        for (_, key, saved) in &self.peer_writes {
            peers.retain(|peer| peer != key);
            if *saved {
                peers.push(*key);
            }
        }
        peers
    }

    /// The channels the device identity holds, by tag, and those it has
    /// been asked to join and has yet to answer for, less those it has been
    /// asked to leave.
    pub fn channels(&self) -> impl Iterator<Item = ChannelTag> + '_ {
        let joining = self
            .channel_writes
            .iter()
            .filter(|&&(_, _, joined)| joined)
            .map(|&(_, tag, _)| tag)
            .filter(|tag| !self.model.channels().any(|held| *held == tag.0));
        let leaving = |tag: &ChannelTag| {
            self.channel_writes
                .iter()
                .any(|&(_, kept, joined)| !joined && kept == *tag)
        };
        self.model
            .channels()
            .map(|tag| ChannelTag(*tag))
            .filter(move |tag| !leaving(tag))
            .chain(joining)
    }

    /// How the device identity is drawn: its key's leading octets as the
    /// fill, and its address's first characters as the lettering.
    pub fn avatar(&self) -> AvatarStyle {
        let key = self.key().copied().unwrap_or_default();
        let address = self.address();
        AvatarStyle::peer(
            [key[0], key[1], key[2]],
            address.get(..4).unwrap_or_default(),
            PeerShape::Circle,
        )
    }

    /// The link that shares the device identity: its address, and its
    /// contact once the device has given one.
    pub fn share_uri(&self) -> Option<ShareUri> {
        self.key()?;
        let mut uri = ShareUri::new();
        uri.push_str("umsh:n:").ok()?;
        uri.push_str(&self.address()).ok()?;
        if let Some(contact) = self.contact() {
            let mut whole = uri.clone();
            let carried = whole.push(':').is_ok()
                && whole
                    .push_str(&umsh_uri::encode_base58_bytes(contact))
                    .is_ok();
            if carried {
                uri = whole;
            }
        }
        Some(uri)
    }

    /// Asks the device afresh for its contact: its node identity as it is
    /// kept, signed (`PROP_IDENT_CONTACT`). Each one is dated as it is
    /// signed.
    pub fn read_contact(&mut self) {
        self.model.read(prop::IDENT_CONTACT);
    }

    /// Asks the device afresh for what a contact exchange uses: its
    /// contact, and the longest frame's airtime.
    pub fn read_for_meet(&mut self) {
        self.read_contact();
        self.model.read(prop::PHY_T_FRAME);
    }

    /// The device identity's contact, signed, as last read.
    pub fn contact(&self) -> Option<&[u8]> {
        self.model.raw(prop::IDENT_CONTACT)
    }

    /// The longest frame's airtime at the radio's settings, in
    /// milliseconds (`PROP_PHY_T_FRAME`).
    pub fn frame_ms(&self) -> Option<u32> {
        self.u32(prop::PHY_T_FRAME)
    }

    pub fn device_name(&self) -> String<24> {
        let mut name = String::new();
        if let Some(Value::Text(text)) = self.model.intended(prop::DEV_NAME) {
            for c in text.chars() {
                if name.push(c).is_err() {
                    break;
                }
            }
        }
        name
    }

    pub fn radio(&self) -> RadioSettings {
        let profile = match (
            self.u32(prop::PHY_FREQ),
            self.u32(prop::PHY_LORA_BW),
            self.u8(prop::PHY_LORA_SF),
            self.u8(prop::PHY_LORA_CR),
        ) {
            (Some(freq), Some(bw), Some(sf), Some(cr)) => VETTED
                .iter()
                .position(|profile| profile.interoperates_with(freq, bw, sf, cr))
                .map_or(Profile::Custom, Profile::Vetted),
            _ => Profile::Custom,
        };
        let airtime = self.model.duty_now().map_or(0, |duty| {
            (u32::from(duty) * 100 / u32::from(u16::MAX)) as u8
        });
        RadioSettings {
            enabled: self.bool(prop::PHY_ENABLED).unwrap_or(false),
            profile,
            forwarding: self.bool(prop::MAC_REPEATER_ENABLED).unwrap_or(false),
            share_location: self.bool(prop::GNSS_IDENT_UPDATE).unwrap_or(false),
            transmit_power: match self.model.intended(prop::PHY_TX_POWER) {
                Some(Value::I8(dbm)) => dbm,
                _ => 0,
            },
            airtime,
        }
    }

    /// Whether Bluetooth is on, where the device has it.
    pub fn bluetooth_enabled(&self) -> Option<bool> {
        self.model
            .has_cap(cap::BLE)?
            .then(|| self.bool(prop::BLE_ENABLED).unwrap_or(true))
    }

    /// Whether the device plays its sounds, where it has a sounder.
    pub fn sound_enabled(&self) -> Option<bool> {
        self.model
            .has_cap(cap::SOUND)?
            .then(|| self.bool(prop::SOUND_ENABLED).unwrap_or(true))
    }

    pub fn sound_volume(&self) -> u8 {
        self.u8(prop::SOUND_VOLUME).unwrap_or(DEFAULT_SOUND_VOLUME)
    }

    /// Whether the device can be reset to how it left the factory.
    pub fn can_factory_reset(&self) -> bool {
        self.model.has_cap(cap::REBOOT) == Some(true)
    }

    /// Whether the device has been set up, once read.
    pub fn setup_complete(&self) -> Option<bool> {
        self.bool(prop::SETUP_COMPLETE)
    }

    /// Whether the GNSS receiver is on, where the device has one.
    pub fn gnss_enabled(&self) -> Option<bool> {
        self.model
            .has_cap(cap::GNSS)?
            .then(|| self.bool(prop::GNSS_ENABLED).unwrap_or(false))
    }

    pub fn keyboard(&self) -> KeyboardSettings {
        let aids = self.u8(prop::KEYBOARD_AIDS).unwrap_or(keyboard_aids::ALL);
        KeyboardSettings {
            capitalize: aids & keyboard_aids::CAPITALIZE != 0,
            period: aids & keyboard_aids::PERIOD != 0,
            light: self.bool(prop::KEYBOARD_LIGHT).unwrap_or(true),
        }
    }

    pub fn brightness(&self) -> u8 {
        self.u8(prop::DISPLAY_BRIGHTNESS)
            .unwrap_or(DEFAULT_BRIGHTNESS)
    }

    /// How long the screen stays lit without input, in seconds, 0 for
    /// never, where the device has a screen of its own.
    pub fn auto_lock(&self) -> Option<u16> {
        self.model.has_cap(cap::DISPLAY)?.then(|| {
            self.u16(prop::DISPLAY_TIMEOUT)
                .unwrap_or(DEFAULT_AUTO_LOCK_S)
        })
    }

    /// The device's counters, as last read.
    pub fn statistics(&self) -> Statistics {
        Statistics {
            uptime: self.u32(prop::UPTIME),
            sent: self.u32(prop::STAT_TX_PACKETS),
            channel_busy: self.u32(prop::STAT_TX_CHANNEL_BUSY),
            heard: self.u32(prop::STAT_RX_PACKETS),
            bad_crc: self.u32(prop::STAT_RX_BAD_CRC),
            other: self.u32(prop::STAT_RX_NON_UMSH),
            accepted: self.u32(prop::STAT_RX_ACCEPTED),
            forwarded: self.u32(prop::STAT_FORWARDED),
            forward_dropped: self.u32(prop::STAT_FORWARD_DROPPED),
            forward_cancelled: self.u32(prop::STAT_FORWARD_CANCELLED),
            meshcore_seen: self.u32(prop::STAT_MESHCORE_SEEN),
            meshcore_routed: self.u32(prop::STAT_MESHCORE_FORWARDED_ROUTED),
            meshcore_flooded: self.u32(prop::STAT_MESHCORE_FORWARDED_FLOOD),
            meshcore_declined: self.u32(prop::STAT_MESHCORE_DECLINED),
        }
    }

    pub fn clock(&self) -> ClockSettings {
        let zone = match self.model.intended(prop::TZ_RULE) {
            Some(Value::Text(rule)) => Rule::parse(rule).ok(),
            _ => None,
        };
        ClockSettings {
            automatic: self.bool(prop::GNSS_TIME_TRUST),
            hour24: self.bool(prop::TIME_24H).unwrap_or(true),
            zone: zone.unwrap_or(Rule::UTC),
        }
    }

    fn bool(&self, key: u32) -> Option<bool> {
        match self.model.intended(key)? {
            Value::Bool(value) => Some(value),
            _ => None,
        }
    }

    fn u8(&self, key: u32) -> Option<u8> {
        match self.model.intended(key)? {
            Value::U8(value) => Some(value),
            _ => None,
        }
    }

    fn u16(&self, key: u32) -> Option<u16> {
        match self.model.intended(key)? {
            Value::U16(value) => Some(value),
            _ => None,
        }
    }

    fn u32(&self, key: u32) -> Option<u32> {
        match self.model.intended(key)? {
            Value::U32(value) => Some(value),
            _ => None,
        }
    }
}

/// Whether losing a change to `setting` would matter enough to save one.
/// The time is never saved: the board's real-time clock keeps it.
const fn matters(setting: Setting) -> bool {
    !matches!(
        setting,
        Setting::Keyboard
            | Setting::Brightness
            | Setting::Volume
            | Setting::AutoLock
            | Setting::Time
            | Setting::Pairing
    )
}
