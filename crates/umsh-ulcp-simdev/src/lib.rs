//! Soft ULCP devices: the production device [`Session`] behind an
//! HDLC-Lite byte stream, with no hardware under it.
//!
//! [`soft::SoftDevice`] is the core, generic over a [`soft::SoftPlatform`]
//! that supplies storage, entropy, a clock, and peripherals. Two platforms
//! ship here:
//!
//! - [`SimulatedDevice`]: a deterministic test fixture. Storage is RAM,
//!   identities come from a counter, and the battery, receiver, Wi-Fi
//!   station, and I2C bus are canned. Every protocol decision is still
//!   made by the real session. Transmissions accumulate until
//!   [`SimulatedDevice::take_transmitted`] drains them, so the caller
//!   decides what "the air" is—the web debugger discards it, a bridge
//!   copies it to real segments.
//! - [`host::HostPlatform`]: a real device with no radio of its own, such
//!   as a LAN virtual radio. State persists in files, identities come
//!   from the operating system's generator, and the clock is the system's.
//! - [`lan`]: that device with the LAN bearer's group as its PHY, driven
//!   for as long as its owner runs it.
//!
//! The [`SessionConfig`] is the caller's: it names the device and
//! declares its capability surface. A simulated device has no node
//! behind it, so its configuration must leave
//! [`SessionConfig::mac_node`] unset—a backhaul would connect the host
//! to nothing.

#[cfg(feature = "host")]
pub mod host;
#[cfg(feature = "lan")]
pub mod lan;
pub mod soft;

use umsh_core::{NodeHint, PacketBuilder};
use umsh_ulcp::battery::{BatteryChargeState, BatteryStatus};
use umsh_ulcp::gnss::{FixKind, GnssSnapshot};
use umsh_ulcp::i2c::{BusInfo, DeviceInfo, ScanRequest, TransferRequest};
use umsh_ulcp::ids::prop;
use umsh_ulcp::ip::{FamilyState, V4Address, V6Item};
use umsh_ulcp::wifi::{
    Association, Link, LinkReason, LinkState, NetworkEntry, ScanResult, SecurityMode,
};
use umsh_ulcp::{Status, items};
use umsh_ulcp_device::{AnnounceRequest, Effect};

use soft::{DeviceSession, SoftDevice, SoftPlatform};

pub use umsh_ulcp_device::{
    AlertConfig, BatteryFields, DisplayConfig, DutyLedger, GnssConfig, IpConfig, LanBearerRole,
    RadioRxInfo, RadioSettings, SessionConfig, TimeConfig, WifiConfig,
};

/// Bonds a fresh simulated device pretends to be holding.
const SIMULATED_BONDS: u8 = 2;

/// A deterministic, RAM-backed device that speaks HDLC-Lite exactly like USB.

/// A deterministic, RAM-backed device that speaks HDLC-Lite exactly like USB.
pub struct SimulatedDevice {
    device: SoftDevice<SimulatedPlatform>,
}

/// What stands where a board's hardware and storage would.
pub struct SimulatedPlatform {
    snapshot: Option<Vec<u8>>,
    /// The channel keys the device lists hold after a reset, on a device
    /// whose store keeps the lists outside the snapshot.
    held_lists: Option<&'static [[u8; 32]]>,
    lists: Option<Vec<u8>>,
    identity: Option<[u8; 32]>,
    identity_seed: u8,
    pairing_pin: Option<u32>,
    /// Bonds the simulated transport is holding. Nothing here pairs, so
    /// the count only ever falls—it starts non-zero so a host has
    /// something to clear, which is the state the command is for.
    bond_count: u8,
    /// The simulated wall clock, as a Unix second, or `None` for a device
    /// that has not been told and has never had a fix. Starts unset so the
    /// property's most interesting state is the one you see first.
    epoch: Option<u32>,
    /// Where the simulated receiver currently thinks it is. Advanced one
    /// step per sample so a host watching `PROP_GNSS_LOCATION` sees a
    /// track rather than a fixed point.
    fix_step: u32,
    /// What stands where a Wi-Fi driver and an IP stack would.
    network: SimulatedNetwork,
    /// The one peripheral on the simulated bus.
    i2c: SimulatedI2c,
    temperatures: Vec<(String, u16)>,
    temperature_samples: u64,
    temperature_append_on_sample: Option<(String, u16)>,
}

/// The bus the simulated device advertises: one controller, one
/// peripheral, so `CMD_I2C_TRANSFER` and `CMD_I2C_SCAN` have something to
/// find.
pub const SIMULATED_I2C_BUSES: &[BusInfo<'static>] = &[BusInfo {
    bus: 0,
    speed_khz: 400,
    max_data: 255,
    max_ops: 16,
    name: "I2C0 (simulated)",
}];

/// What the simulated firmware knows to be on that bus.
pub const SIMULATED_I2C_DEVICES: &[DeviceInfo<'static>] = &[DeviceInfo {
    bus: 0,
    addr: SimulatedI2c::ADDRESS,
    name: "Register file (simulated)",
}];

/// A small register-file peripheral at one address: a write sets the
/// register pointer and stores whatever follows, a read returns from the
/// pointer onward, and both advance it. Enough to make a register read
/// (`write pointer, read N`) mean something.
#[derive(Debug, Default)]
pub struct SimulatedI2c {
    registers: [u8; 8],
    pointer: u8,
    /// Transactions performed, failures included. A test that checks a
    /// retransmission was answered from a retained response rather than
    /// executed again needs this: an unchanged register file would not
    /// tell an idempotent second write from a suppressed one.
    executed: u32,
}

impl SimulatedI2c {
    /// The peripheral's 7-bit address.
    pub const ADDRESS: u8 = 0x50;

    /// Perform one transaction, returning the concatenated read data.
    pub fn transact(&mut self, addr: u8, request: TransferRequest<'_>) -> Result<Vec<u8>, Status> {
        self.executed += 1;
        if addr != Self::ADDRESS {
            return Err(Status::NO_DEVICE);
        }
        let mut out = Vec::new();
        for op in request.ops() {
            match op.map_err(|error| error.status())? {
                umsh_ulcp::i2c::Op::Write(data) => {
                    self.pointer = data[0];
                    for byte in &data[1..] {
                        self.registers[usize::from(self.pointer % 8)] = *byte;
                        self.pointer = self.pointer.wrapping_add(1);
                    }
                }
                umsh_ulcp::i2c::Op::Read(len) => {
                    for _ in 0..len {
                        out.push(self.registers[usize::from(self.pointer % 8)]);
                        self.pointer = self.pointer.wrapping_add(1);
                    }
                }
            }
        }
        Ok(out)
    }

    /// The addresses in a range that acknowledge.
    pub fn scan(&mut self, request: ScanRequest) -> Vec<u8> {
        self.executed += 1;
        if request.covers(Self::ADDRESS) {
            vec![Self::ADDRESS]
        } else {
            Vec::new()
        }
    }

    /// Transactions performed so far, scans included.
    pub fn executed(&self) -> u32 {
        self.executed
    }

    /// The register file as it stands.
    pub fn registers(&self) -> &[u8; 8] {
        &self.registers
    }
}

/// The access points the simulated receiver can hear.
///
/// Two of them share a name, which is the case a host has to handle and
/// the one a single canned network would never exercise: a picker groups
/// on SSID and keeps the strongest, a list of radios shows both. One is
/// nameless, standing for a hidden network, and it is the reason the
/// BSSID is what identifies an entry.
const SIMULATED_ACCESS_POINTS: &[(u16, i8, [u8; 6], &[u8])] = &[
    (
        5220,
        -48,
        [0x02, 0x11, 0xA0, 0x01, 0x00, 0x01],
        b"Field Office",
    ),
    (
        2437,
        -71,
        [0x02, 0x11, 0xA0, 0x01, 0x00, 0x02],
        b"Field Office",
    ),
    (
        2412,
        -66,
        [0x02, 0x33, 0xB4, 0x0C, 0x10, 0x07],
        b"Depot Guest",
    ),
    (5745, -83, [0x02, 0x9E, 0x44, 0x2D, 0x88, 0x01], b""),
];

/// The station's own address, which never changes.
const SIMULATED_WIFI_MAC: [u8; 6] = [0x02, 0x55, 0x4D, 0x53, 0x48, 0x01];

/// The simulated Wi-Fi station and IP stack.
///
/// Where the driver would be: the network table with its credentials, the
/// results of a scan, and whatever the link and the stack have made of
/// the configuration the session holds. Nothing here is protocol state —
/// the session owns that—which is exactly the division the effects
/// exist to draw.
#[derive(Default)]
struct SimulatedNetwork {
    /// Stored networks in item form, credential included, keyed by SSID.
    networks: Vec<Vec<u8>>,
    /// Whether the station is currently on the selected network.
    associated: bool,
    /// Whether a scan has run. A device that has never looked reports an
    /// empty table rather than the results of a scan nobody asked for.
    scanned: bool,
}

impl SimulatedNetwork {
    /// Where a stored network with this SSID sits, if one does.
    fn position(&self, ssid: &[u8]) -> Option<usize> {
        self.networks
            .iter()
            .position(|entry| Self::ssid_of(entry) == ssid)
    }

    fn ssid_of(entry: &[u8]) -> &[u8] {
        NetworkEntry::decode(entry)
            .map(|entry| entry.ssid)
            .unwrap_or(&[])
    }

    /// Store an entry, replacing any held under the same name.
    fn store(&mut self, entry: &[u8]) {
        match self.position(Self::ssid_of(entry)) {
            Some(index) => self.networks[index] = entry.to_vec(),
            None => self.networks.push(entry.to_vec()),
        }
    }
}

impl SimulatedDevice {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            device: SoftDevice::new(config, SimulatedPlatform::new()),
        }
    }

    /// A device whose own store keeps the device lists outside the
    /// snapshot, as a communicator's does, with `defaults` the channel
    /// keys they hold after a reset with none kept.
    pub fn holding_lists(config: SessionConfig, defaults: &'static [[u8; 32]]) -> Self {
        let mut platform = SimulatedPlatform::new();
        platform.held_lists = Some(defaults);
        Self {
            device: SoftDevice::new(config, platform),
        }
    }

    /// Append a sensor without changing any existing index or name.
    pub fn append_temperature_sensor(&mut self, name: &str, value: u16) -> Result<usize, Status> {
        self.device
            .platform_mut()
            .append_temperature_sensor(name, value)
    }

    /// Change availability or temperature while preserving the inventory.
    pub fn set_temperature(&mut self, index: usize, value: u16) -> Result<(), Status> {
        self.device.platform_mut().set_temperature(index, value)
    }

    /// Stage registration during the next acquisition for UI/transport scenarios.
    pub fn append_temperature_during_next_sample(
        &mut self,
        name: &str,
        value: u16,
    ) -> Result<(), Status> {
        self.device
            .platform_mut()
            .append_temperature_during_next_sample(name, value)
    }

    pub fn temperature_samples(&self) -> u64 {
        self.device.platform().temperature_samples()
    }

    /// Attach over the virtual equivalent of a physically secure serial link.
    pub fn attach(&mut self) {
        self.device.attach();
    }

    pub fn detach(&mut self) {
        self.device.detach();
    }

    /// Feed an arbitrary serial byte chunk into the virtual USB link.
    pub fn ingest(&mut self, bytes: &[u8], now_ms: u64) -> Result<(), String> {
        self.device.ingest(bytes, now_ms)
    }

    pub fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.device.take_outbound()
    }

    /// Give the device a settings interface of its own, as a communicator
    /// has.
    pub fn open_device_interface(&mut self) {
        self.device.open_device_interface();
    }

    /// Serve one raw ULCP frame from the device's own interface.
    pub fn device_request(&mut self, frame: &[u8], now_ms: u64) {
        self.device.device_request(frame, now_ms);
    }

    /// The next raw frame for the device's own interface: an answer, or a
    /// publication.
    pub fn take_device_frame(&mut self) -> Option<Vec<u8>> {
        self.device.take_device_frame()
    }

    /// The snapshot in the device's storage, if one has been saved.
    pub fn saved_snapshot(&self) -> Option<&[u8]> {
        self.device.platform().snapshot.as_deref()
    }

    /// Flip a switch at the device, as a board's own control would,
    /// publishing the transition to everyone listening.
    pub fn toggle_ble(&mut self) {
        self.device.toggle_ble();
    }

    /// Everything the device has transmitted since the last drain, in
    /// order. The queue grows until drained; a caller with no air to put
    /// frames on drains and discards.
    pub fn take_transmitted(&mut self) -> Vec<Vec<u8>> {
        self.device.take_transmitted()
    }

    /// Every `CMD_ANNOUNCE` the device has taken since the last drain, in
    /// order. Nothing reaches the air—there is no node here—so this is
    /// where a test reads what was asked for.
    pub fn take_announcements(&mut self) -> Vec<AnnounceRequest> {
        self.device.take_announcements()
    }

    /// Put a canned radio frame through the real device receive path.
    pub fn inject_radio_rx(&mut self, bytes: &[u8], now_ms: u64) {
        self.inject_radio_rx_with_info(bytes, &RadioRxInfo::measured(-82, 35, None), now_ms);
    }

    /// Put a radio frame through the real device receive path with the
    /// caller's own reception facts—all-`None` for a frame that
    /// crossed no air and was measured by nobody.
    pub fn inject_radio_rx_with_info(&mut self, bytes: &[u8], info: &RadioRxInfo, now_ms: u64) {
        self.device.inject_radio_rx(bytes, info, now_ms);
    }

    /// Build and inject a small valid UMSH packet for interactive UI demos.
    pub fn inject_demo_rx(&mut self, now_ms: u64) {
        let mut bytes = [0; 64];
        let packet = PacketBuilder::new(&mut bytes)
            .broadcast()
            .source_hint(NodeHint([0x11, 0x22, 0x33]))
            .flood_hops(3)
            .payload(b"hello from the simulated radio")
            .build()
            .expect("fixed demo packet fits")
            .to_vec();
        self.inject_radio_rx(&packet, now_ms);
    }

    /// The simulated bus peripheral, for checking what a transfer did.
    pub fn i2c(&self) -> &SimulatedI2c {
        &self.device.platform().i2c
    }
}

impl SimulatedPlatform {
    fn new() -> Self {
        Self {
            snapshot: None,
            held_lists: None,
            lists: None,
            identity: None,
            identity_seed: 0,
            pairing_pin: None,
            bond_count: SIMULATED_BONDS,
            epoch: None,
            fix_step: 0,
            network: SimulatedNetwork::default(),
            i2c: SimulatedI2c::default(),
            temperatures: vec![
                ("MCU die".into(), 2981),
                ("Battery".into(), 2931),
                ("External".into(), 0xffff),
            ],
            temperature_samples: 0,
            temperature_append_on_sample: None,
        }
    }

    /// Append a sensor without changing any existing index or name.
    pub fn append_temperature_sensor(&mut self, name: &str, value: u16) -> Result<usize, Status> {
        if !umsh_ulcp::temperature::valid_name(name) {
            return Err(Status::INVALID_ARGUMENT);
        }
        let pending_bytes = self
            .temperature_append_on_sample
            .as_ref()
            .map_or(0, |(name, _)| name.len() + 1);
        let pending_count = usize::from(self.temperature_append_on_sample.is_some());
        let bytes: usize = self
            .temperatures
            .iter()
            .map(|(name, _)| 1 + name.len())
            .sum();
        if self.temperatures.len() + pending_count >= umsh_ulcp_device::MAX_TEMPERATURE_SENSORS
            || bytes + pending_bytes + 1 + name.len() > umsh_ulcp_device::TEMPERATURE_NAMES_MAX
        {
            return Err(Status::NOMEM);
        }
        let index = self.temperatures.len();
        self.temperatures.push((name.into(), value));
        Ok(index)
    }

    /// Change availability or temperature while preserving the inventory.
    pub fn set_temperature(&mut self, index: usize, value: u16) -> Result<(), Status> {
        self.temperatures
            .get_mut(index)
            .ok_or(Status::INVALID_ARGUMENT)?
            .1 = value;
        Ok(())
    }

    /// Stage registration during the next acquisition for UI/transport scenarios.
    pub fn append_temperature_during_next_sample(
        &mut self,
        name: &str,
        value: u16,
    ) -> Result<(), Status> {
        if self.temperature_append_on_sample.is_some() {
            return Err(Status::BUSY);
        }
        // Validate capacity using the same registration path without exposing it yet.
        self.append_temperature_sensor(name, value)?;
        self.temperature_append_on_sample = self.temperatures.pop();
        Ok(())
    }

    pub fn temperature_samples(&self) -> u64 {
        self.temperature_samples
    }

    /// What the simulated access points offer, by name.
    ///
    /// The office network is a WPA2/WPA3 transition deployment, the guest
    /// network is Enhanced Open beside a plain open BSS, and the nameless
    /// one is ordinary WPA2—three shapes a picker has to render
    /// differently.
    fn simulated_modes(ssid: &[u8]) -> u16 {
        match ssid {
            b"Field Office" => SecurityMode::Wpa2.bit() | SecurityMode::Wpa3.bit(),
            b"Depot Guest" => SecurityMode::Open.bit() | SecurityMode::Owe.bit(),
            _ => SecurityMode::Wpa2.bit(),
        }
    }

    /// One of the tables the platform owns rather than the session,
    /// encoded as a length-prefixed item list.
    fn network_table(&self, session: &DeviceSession, key: u32) -> Vec<u8> {
        let mut items = Vec::new();
        let mut push = |item: &[u8]| {
            let mut buf = [0u8; 1 + umsh_ulcp::wifi::NETWORK_ENTRY_MAX_LEN];
            if let Ok(len) = items::encode_prefixed_item(item, &mut buf) {
                items.extend_from_slice(&buf[..len]);
            }
        };
        match key {
            // Reported form: the credential stops here and goes no
            // further, which is the entire point of the table living
            // with the driver.
            prop::WIFI_NETWORKS => {
                for entry in &self.network.networks {
                    let mut reported = [0u8; umsh_ulcp::wifi::NETWORK_ENTRY_MAX_LEN];
                    let encoded = NetworkEntry::decode(entry)
                        .and_then(|entry| entry.encode_reported(&mut reported));
                    if let Ok(len) = encoded {
                        push(&reported[..len]);
                    }
                }
            }
            // Whatever the last scan heard, strongest first, which is
            // how a device reports its retained table.
            prop::WIFI_SCAN_RESULTS if self.network.scanned => {
                for &(frequency_mhz, rssi_dbm, bssid, ssid) in SIMULATED_ACCESS_POINTS {
                    let mut buf = [0u8; umsh_ulcp::wifi::SCAN_RESULT_MAX_LEN];
                    let result = ScanResult {
                        modes: Self::simulated_modes(ssid),
                        frequency_mhz,
                        rssi_dbm,
                        bssid,
                        ssid,
                    };
                    if let Ok(len) = result.encode(&mut buf) {
                        push(&buf[..len]);
                    }
                }
            }
            prop::IPV4_ADDRESS if self.network.associated => {
                let mut buf = [0u8; umsh_ulcp::ip::V4_ADDRESS_LEN];
                let address = V4Address {
                    address: [192, 168, 8, 42],
                    prefix: 24,
                    gateway: [192, 168, 8, 1],
                };
                if let Ok(len) = address.encode(&mut buf) {
                    push(&buf[..len]);
                }
            }
            prop::IPV6_ADDRESSES if self.network.associated => {
                let mut address = [0u8; 16];
                address[..2].copy_from_slice(&[0x20, 0x01]);
                address[2..4].copy_from_slice(&[0x0d, 0xb8]);
                address[15] = 0x2a;
                let mut router = [0u8; 16];
                router[0] = 0xfe;
                router[1] = 0x80;
                router[15] = 0x01;
                for item in [
                    V6Item::Address {
                        address,
                        prefix: 64,
                    },
                    V6Item::Router { address: router },
                ] {
                    let mut buf = [0u8; umsh_ulcp::ip::V6_ADDRESS_ITEM_LEN];
                    if let Ok(len) = item.encode(&mut buf) {
                        push(&buf[..len]);
                    }
                }
            }
            // What the stack resolves through: the device's own list
            // where it has one, and the network's offer where it does
            // not.
            prop::IP_RESOLVERS if self.network.associated => {
                let configured: Vec<Vec<u8>> =
                    session.dns_resolvers().iter().map(<[u8]>::to_vec).collect();
                match configured.is_empty() {
                    true => push(&[192, 168, 8, 1]),
                    false => configured.iter().for_each(|resolver| push(resolver)),
                }
            }
            _ => {}
        }
        items
    }

    /// Bring the simulated link and stack to what the session now holds.
    ///
    /// Where a driver would react to the device-domain mirror. Called
    /// after every frame, so a write that switches the station off or
    /// picks a different network is followed by the state that write
    /// produced.
    fn settle_network(&mut self, session: &mut DeviceSession, mut emit: &mut dyn FnMut(&[u8])) {
        if !session.wifi_station() {
            return;
        }
        session.set_wifi_mac(SIMULATED_WIFI_MAC);
        let selected = session.selected_network().to_vec();
        let associated = session.wifi_enabled()
            && !selected.is_empty()
            && session
                .known_networks()
                .get(&selected)
                .is_some_and(|entry| {
                    // The office AP advertises WPA2/WPA3 transition mode.
                    // Upgrading its offered mode set never changes the saved
                    // minimum or allows a weaker authentication method.
                    [SecurityMode::Wpa3, SecurityMode::Wpa2]
                        .into_iter()
                        .any(|mode| entry.security.permits(mode, entry.raw_key))
                        || entry.security.permits(SecurityMode::Open, entry.raw_key)
                });
        self.network.associated = associated;
        let link = match associated {
            true => Link {
                state: LinkState::Up,
                reason: LinkReason::None,
                association: Some(Association {
                    bssid: SIMULATED_ACCESS_POINTS[0].2,
                    frequency_mhz: SIMULATED_ACCESS_POINTS[0].0,
                }),
            },
            false => Link::default(),
        };
        session.set_wifi_link(link, &mut emit);
        session.set_wifi_rssi(associated.then_some(SIMULATED_ACCESS_POINTS[0].1));
        let state = match associated {
            true => FamilyState::Ready,
            false => FamilyState::NoLink,
        };
        session.set_ip_state(prop::IPV4_STATE, state, &mut emit);
        session.set_ip_state(prop::IPV6_STATE, state, &mut emit);
    }

    /// The simulated receiver's view, walked one cell east per sample.
    ///
    /// A receiver that has been switched off reports
    /// [`GnssSnapshot::SEARCHING`]—zero for the facts it is sure of,
    /// empty for the position it does not have—which is the state most
    /// worth being able to see in a debugger.
    fn gnss_sample(&mut self, session: &DeviceSession) -> GnssSnapshot {
        if !session.gnss_enabled() {
            return GnssSnapshot::SEARCHING;
        }
        self.fix_step = self.fix_step.wrapping_add(1);
        let mut snapshot = GnssSnapshot::SEARCHING;
        snapshot.fix = FixKind::ThreeD;
        snapshot.altitude_m = Some(64);
        snapshot.accuracy_dm = Some(GnssSnapshot::accuracy_from_hdop_centi(120));
        snapshot.sats_used = 9;
        snapshot.sats_in_view = Some(14);
        let step = (self.fix_step % 16) as u8;
        snapshot.set_location(&[0x8a, 0x1f, 0x4c, 0x00, 0xd0 | step]);
        snapshot
    }
}

impl SoftPlatform for SimulatedPlatform {
    fn load_snapshot(&mut self) -> Option<Vec<u8>> {
        self.snapshot.clone()
    }

    fn store_snapshot(&mut self, snapshot: Option<&[u8]>) -> Result<(), ()> {
        self.snapshot = snapshot.map(<[u8]>::to_vec);
        Ok(())
    }

    fn load_identity(&mut self) -> Option<[u8; 32]> {
        self.identity
    }

    fn held_lists(&self) -> Option<&'static [[u8; 32]]> {
        self.held_lists
    }

    fn load_lists(&mut self) -> Option<Vec<u8>> {
        self.lists.clone()
    }

    fn store_lists(&mut self, record: Option<&[u8]>) -> Result<(), ()> {
        self.lists = record.map(<[u8]>::to_vec);
        Ok(())
    }

    fn store_identity(&mut self, secret: Option<&[u8; 32]>) -> Result<(), ()> {
        self.identity = secret.copied();
        Ok(())
    }

    /// Deterministic: the first identity generated is all ones, the next
    /// all twos.
    fn generate_secret(&mut self) -> [u8; 32] {
        self.identity_seed = self.identity_seed.wrapping_add(1).max(1);
        [self.identity_seed; 32]
    }

    fn wall_clock(&mut self) -> Option<u32> {
        self.epoch
    }

    fn set_wall_clock(&mut self, epoch: Option<u32>) {
        self.epoch = epoch;
    }

    /// Bonds outlive a reboot, and a fresh session starts from zero, so
    /// the transport reports itself exactly as a board's does on the way
    /// up.
    fn on_boot(&mut self, session: &mut DeviceSession) {
        session.set_ble_bond_count(self.bond_count, &mut |_| {});
    }

    fn erase(&mut self) {
        self.identity_seed = 0;
        self.pairing_pin = None;
        self.bond_count = 0;
    }

    fn settle(&mut self, session: &mut DeviceSession, emit: &mut dyn FnMut(&[u8])) {
        self.settle_network(session, emit);
    }

    fn peripheral(
        &mut self,
        effect: Effect,
        session: &mut DeviceSession,
        mut emit: &mut dyn FnMut(&[u8]),
    ) {
        match effect {
            Effect::SampleRssi { tid } => {
                session.respond_rssi(tid, Ok(-77), &mut emit);
            }
            Effect::SampleBattery { tid } => {
                // Stable, human-recognizable simulated measurement; the
                // configured field set decides what of it is reported.
                session.respond_battery(
                    tid,
                    Ok(BatteryStatus {
                        voltage_mv: Some(4111),
                        level_percent: Some(87),
                        charge_state: Some(BatteryChargeState::Charging),
                    }),
                    &mut emit,
                );
            }
            Effect::SampleBatteryGroup {
                tid,
                key,
                fields: _,
            } => {
                use umsh_ulcp::battery_diagnostics::{KEYS, Sample, Value, VoltageRequest};
                let mut sample = Sample::default();
                sample.snapshot = Ok(BatteryStatus {
                    voltage_mv: Some(4111),
                    level_percent: Some(87),
                    charge_state: Some(BatteryChargeState::Charging),
                });
                let values = [
                    Value::Current(100),
                    Value::Unsigned(1305),
                    Value::Unsigned(1500),
                    Value::Unsigned(1500),
                    Value::Bool(true),
                    Value::Bool(true),
                    Value::Bool(false),
                    Value::Bool(true),
                    Value::Bool(false),
                    Value::Voltage(VoltageRequest::Millivolts(4200)),
                    Value::Format(1),
                    Value::Unsigned(8),
                    Value::Unsigned(0x26),
                ];
                for (key, value) in KEYS.into_iter().zip(values) {
                    sample.set(key, Ok(Some(value)));
                }
                session.respond_battery_group(tid, key, sample, &mut emit);
            }
            Effect::SampleTemperatures { tid } => {
                self.temperature_samples += 1;
                let values: Vec<_> = self.temperatures.iter().map(|(_, value)| *value).collect();
                if let Some((name, value)) = self.temperature_append_on_sample.take() {
                    self.append_temperature_sensor(&name, value)
                        .expect("staged registration fits");
                }
                session.respond_temperatures(tid, Ok(&values), &mut emit);
            }
            Effect::ReadTemperatureNames { tid } => {
                let names: Vec<_> = self
                    .temperatures
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect();
                let mut value = [0; umsh_ulcp_device::TEMPERATURE_NAMES_MAX];
                let len = umsh_ulcp::temperature::encode_names(&names, &mut value)
                    .expect("bounded inventory");
                session.respond_temperature_names(tid, Ok(&value[..len]), &mut emit);
            }
            Effect::SampleIlluminance { tid } => {
                // A stable simulated reading: ordinary office lighting.
                session.respond_illuminance(tid, Some(320_000), &mut emit);
            }
            Effect::SetPairingPin { tid, pin } => {
                self.pairing_pin = pin;
                session.respond_pin_set(tid, Ok(()), &mut emit);
            }
            Effect::ClearBleBonds { tid } => {
                // The full security reset a board performs: bonds, PIN,
                // and lockout together, and the pairing window a
                // freshly-cleared device opens.
                self.bond_count = 0;
                self.pairing_pin = None;
                session.set_ble_bond_count(0, &mut emit);
                session.set_ble_pairing(true, &mut emit);
                session.respond_ble_bond_count(tid, Ok(()), &mut emit);
            }
            Effect::SetBlePairing { tid, open } => {
                // Nothing here can pair, so the window opens and nothing
                // walks through it. A full store is not a refusal—
                // enrollment at capacity evicts—and the one state that
                // would refuse an open, a pairing lockout, needs failed
                // pairings this device cannot have.
                session.respond_ble_pairing(tid, Ok(open), &mut emit);
            }
            Effect::SampleGnss { tid, key } => {
                let sample = self.gnss_sample(session);
                session.respond_gnss(tid, key, Ok(sample), &mut emit);
            }
            // A scan the whole way through, in the four frames the spec
            // orders: the clear, the reply, an insert per access point,
            // and the drop to zero. Instant rather than progressive,
            // which is the shape of every stack that hands a scan back
            // only when it finishes.
            Effect::SetWifiScanning { tid, scanning } => {
                if session.wifi_station() && !session.wifi_enabled() {
                    session.respond_wifi_scanning(tid, Err(Status::INVALID_STATE), &mut emit);
                    return;
                }
                if !scanning {
                    session.respond_wifi_scanning(tid, Ok(false), &mut emit);
                    return;
                }
                self.network.scanned = true;
                session.clear_scan_results(&mut emit);
                session.respond_wifi_scanning(tid, Ok(true), &mut emit);
                for &(frequency_mhz, rssi_dbm, bssid, ssid) in SIMULATED_ACCESS_POINTS {
                    session.publish_scan_result(
                        &ScanResult {
                            modes: Self::simulated_modes(ssid),
                            frequency_mhz,
                            rssi_dbm,
                            bssid,
                            ssid,
                        },
                        &mut emit,
                    );
                }
                session.set_wifi_scanning(false, &mut emit);
            }
            Effect::SelectWifiNetwork { tid } => {
                let ssid = session.pending_network().to_vec();
                let result = match ssid.is_empty() || self.network.position(&ssid).is_some() {
                    true => Ok(()),
                    false => Err(Status::ITEM_NOT_FOUND),
                };
                session.respond_wifi_network(tid, result, &mut emit);
            }
            Effect::InsertWifiNetwork { tid } => {
                let entry = session.pending_network_entry().to_vec();
                // A mode the simulated hardware does not do, so that a
                // host's step-down path has something to step down from.
                let result = match NetworkEntry::decode(&entry).map(|entry| entry.security) {
                    Ok(SecurityMode::Wpa3Ent192) => Err(Status::UNIMPLEMENTED),
                    _ => {
                        self.network.store(&entry);
                        Ok(())
                    }
                };
                session.respond_wifi_network_stored(tid, result, &mut emit);
            }
            Effect::RemoveWifiNetwork { tid } => {
                let ssid = session.pending_network().to_vec();
                let result = match self.network.position(&ssid) {
                    Some(index) => {
                        self.network.networks.remove(index);
                        Ok(())
                    }
                    None => Err(Status::ITEM_NOT_FOUND),
                };
                session.respond_wifi_network_forgotten(tid, result, &mut emit);
            }
            Effect::ReadNetworkTable { tid, key } => {
                let items = self.network_table(session, key);
                session.respond_network_table(tid, key, Ok(&items), &mut emit);
            }
            Effect::I2cTransfer { tid } => {
                let request = session.i2c_request();
                let result = self.i2c.transact(request.addr, request);
                session.respond_i2c(tid, result.as_deref().map_err(|status| *status), &mut emit);
            }
            Effect::I2cScan { tid } => {
                let found = self.i2c.scan(session.i2c_scan_request());
                session.respond_i2c(tid, Ok(&found), &mut emit);
            }
            // Everything else is served by the core.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soft::WIRE_CAPACITY;
    use umsh_ulcp::announce::{Announcement, AnnouncementKind};
    use umsh_ulcp::hdlc;
    use umsh_ulcp::{Frame, PropPayload, frame, ids::prop};

    pub(crate) fn test_config() -> SessionConfig {
        SessionConfig {
            dev_version: "umsh-simdev-test/0.1",
            dev_model: None,
            default_device_name: "Simulated test device",
            mtu: 255,
            tx_preamble_symbols: 32,
            sync_word: 0x1424,
            min_tx_power_dbm: -9,
            max_tx_power_dbm: 22,
            freq_khz_min: 150_000,
            freq_khz_max: 960_000,
            defaults: RadioSettings {
                enabled: false,
                freq_khz: 910_525,
                bw_hz: 62_500,
                sf: 7,
                cr_denom: 5,
                tx_power_dbm: 14,
            },
            default_duty_limit: 0xFFFF,
            duty: Box::leak(Box::new(DutyLedger::new())),
            battery_diagnostics: Default::default(),
            battery: Some(BatteryFields {
                voltage: true,
                level: true,
                charge_state: true,
            }),
            alert: Some(AlertConfig::DEFAULT),
            time: Some(TimeConfig),
            gnss: Some(GnssConfig::DEFAULT),
            display_motion_wake: false,
            display: Some(DisplayConfig {
                brightness: 128,
                timeout_s: 30,
            }),
            keyboard: true,
            sound: true,
            illuminance: true,
            temperatures: true,
            ble: true,
            ble_pairing: true,
            ble_pin: true,
            // A simulated power cycle is a rebuilt session, which is
            // exactly what a host watching this device would see.
            reboot: true,
            dev_identity: true,
            messaging: false,
            // A simulated device has no radio to count for.
            stats: None,
            mac_node: false,
            meshcore_forwarder: false,
            lan_bearer: umsh_ulcp_device::LanBearerRole::None,
            wifi: Some(WifiConfig::STATION),
            ip: Some(IpConfig::DUAL),
            bridge_client: false,
            i2c_buses: SIMULATED_I2C_BUSES,
            i2c_devices: SIMULATED_I2C_DEVICES,
        }
    }

    /// Attach and take delivery of the `CMD_SESSION_RESET` the attach
    /// owes, the way a host does. What it asserts along the way is that
    /// the notice is the first frame of the session and the only one the
    /// attach itself produces.
    fn attach(sim: &mut SimulatedDevice) {
        sim.attach();
        let frame = decode(sim.take_outbound().expect("the attach announces itself"));
        assert_eq!(
            Frame::parse(&frame).unwrap().command(),
            Some(umsh_ulcp::Cmd::SessionReset)
        );
        assert!(sim.take_outbound().is_none(), "and nothing else");
    }

    fn decode(wire: Vec<u8>) -> Vec<u8> {
        let mut decoder = hdlc::Decoder::<WIRE_CAPACITY>::new();
        wire.into_iter()
            .find_map(|byte| decoder.push(byte).map(|frame| frame.unwrap().to_vec()))
            .unwrap()
    }

    fn exchange(sim: &mut SimulatedDevice, request: &[u8]) -> Vec<Vec<u8>> {
        exchange_at(sim, request, 100)
    }

    fn exchange_at(sim: &mut SimulatedDevice, request: &[u8], now_ms: u64) -> Vec<Vec<u8>> {
        let mut wire = vec![0; hdlc::max_encoded_len(request.len())];
        let len = hdlc::encode_frame(request, &mut wire).unwrap();
        sim.ingest(&wire[..len], now_ms).unwrap();

        let mut frames = Vec::new();
        while let Some(wire) = sim.take_outbound() {
            frames.push(decode(wire));
        }
        frames
    }

    fn temperature_get(sim: &mut SimulatedDevice, key: u32) -> Vec<u8> {
        let mut request = [0; 16];
        let len = frame::prop_get(&mut request, 1, key).unwrap();
        let frames = exchange(sim, &request[..len]);
        let parsed = Frame::parse(&frames[0]).unwrap();
        let payload = PropPayload::parse(parsed.payload).unwrap();
        assert_eq!(payload.key, key);
        payload.value.to_vec()
    }

    #[test]
    fn temperature_simulator_multi_get_completes() {
        let mut sim = SimulatedDevice::new(test_config());
        attach(&mut sim);
        let mut request = [0; 32];
        let len = frame::prop_multi_get(
            &mut request,
            2,
            &[prop::TEMPERATURES, prop::TEMPERATURE_NAMES],
        )
        .unwrap();
        let frames = exchange(&mut sim, &request[..len]);
        assert_eq!(frames.len(), 1);
        let response = Frame::parse(&frames[0]).unwrap();
        assert_eq!(response.command(), Some(umsh_ulcp::Cmd::PropAre));
        let entries: Vec<_> = umsh_ulcp::MultiEntries::new(response.payload)
            .map(Result::unwrap)
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, prop::TEMPERATURES);
        assert_eq!(entries[1].key, prop::TEMPERATURE_NAMES);
        assert_eq!(sim.temperature_samples(), 1);
    }

    #[test]
    fn temperature_inventory_acquisition_append_failures_and_resets() {
        let mut sim = SimulatedDevice::new(test_config());
        attach(&mut sim);
        let initial_names = temperature_get(&mut sim, prop::TEMPERATURE_NAMES);
        assert_eq!(sim.temperature_samples(), 0);
        assert_eq!(
            umsh_ulcp::temperature::names(&initial_names)
                .unwrap()
                .count(),
            3
        );
        sim.append_temperature_during_next_sample("External", 2800)
            .unwrap();
        let first = temperature_get(&mut sim, prop::TEMPERATURES);
        assert_eq!(
            umsh_ulcp::temperature::readings(&first)
                .unwrap()
                .collect::<Vec<_>>(),
            [Some(2981), Some(2931), None]
        );
        let names = temperature_get(&mut sim, prop::TEMPERATURE_NAMES);
        assert!(names.starts_with(&initial_names));
        assert_eq!(umsh_ulcp::temperature::names(&names).unwrap().count(), 4);
        assert_eq!(sim.temperature_samples(), 1);
        let second = temperature_get(&mut sim, prop::TEMPERATURES);
        assert_eq!(
            umsh_ulcp::temperature::readings(&second).unwrap().last(),
            Some(Some(2800))
        );
        assert_eq!(sim.temperature_samples(), 2);
        for index in 0..4 {
            sim.set_temperature(index, 0xffff).unwrap();
        }
        assert_eq!(temperature_get(&mut sim, prop::TEMPERATURES), vec![0xff; 8]);
        sim.detach();
        attach(&mut sim);
        assert_eq!(temperature_get(&mut sim, prop::TEMPERATURE_NAMES), names);
        let mut request = [0; 16];
        let len = frame::reset(&mut request, 2).unwrap();
        exchange(&mut sim, &request[..len]);
        assert_eq!(temperature_get(&mut sim, prop::TEMPERATURE_NAMES), names);
        // Reference capacity failures leave the existing inventory untouched.
        while sim.append_temperature_sensor("a", 0).is_ok() {}
        let full = temperature_get(&mut sim, prop::TEMPERATURE_NAMES);
        assert_eq!(sim.append_temperature_sensor("b", 0), Err(Status::NOMEM));
        assert_eq!(temperature_get(&mut sim, prop::TEMPERATURE_NAMES), full);
    }

    #[test]
    fn real_session_answers_attach_property_over_hdlc() {
        let mut sim = SimulatedDevice::new(test_config());
        attach(&mut sim);
        let mut request = [0; 16];
        let len = frame::prop_get(&mut request, 1, prop::DEV_VERSION).unwrap();
        let responses = exchange(&mut sim, &request[..len]);
        assert_eq!(responses.len(), 1);
        let response = Frame::parse(&responses[0]).unwrap();
        let payload = PropPayload::parse(response.payload).unwrap();
        assert_eq!(payload.key, prop::DEV_VERSION);
        assert_eq!(payload.value, b"umsh-simdev-test/0.1\0");
    }

    /// The simulated reboot has to restart the simulated clock, or a
    /// factory-reset device would report the uptime of whatever process
    /// happens to be driving it.
    #[test]
    fn a_factory_reset_restarts_the_uptime_clock() {
        let mut sim = SimulatedDevice::new(test_config());
        attach(&mut sim);

        let read_uptime = |sim: &mut SimulatedDevice, now_ms: u64| -> u32 {
            let mut request = [0; 16];
            let len = frame::prop_get(&mut request, 1, prop::UPTIME).unwrap();
            let responses = exchange_at(sim, &request[..len], now_ms);
            let response = Frame::parse(&responses[0]).unwrap();
            let payload = PropPayload::parse(response.payload).unwrap();
            assert_eq!(payload.key, prop::UPTIME);
            u32::from_le_bytes(payload.value.try_into().expect("UINT32"))
        };

        assert_eq!(read_uptime(&mut sim, 5_000), 5);

        let mut request = [0; 16];
        let len = frame::factory_reset(&mut request, 2).unwrap();
        exchange_at(&mut sim, &request[..len], 5_000);

        // The caller's clock keeps running; the device's does not.
        assert_eq!(read_uptime(&mut sim, 7_000), 2);
    }

    /// An announcement is recorded rather than aired—there is no node
    /// here—and the status says it was taken, exactly as a board's would.
    #[test]
    fn an_announcement_is_taken_and_recorded() {
        let mut sim = SimulatedDevice::new(test_config());
        attach(&mut sim);

        let status_of = |responses: Vec<Vec<u8>>| -> u32 {
            assert_eq!(responses.len(), 1);
            let response = Frame::parse(&responses[0]).unwrap();
            let payload = PropPayload::parse(response.payload).unwrap();
            assert_eq!(payload.key, prop::LAST_STATUS);
            u32::from(payload.value[0])
        };

        let mut request = [0; 64];
        let len = frame::announce(&mut request, 3, &Announcement::default()).unwrap();
        assert_eq!(status_of(exchange(&mut sim, &request[..len])), Status::OK.0);
        let taken = sim.take_announcements();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].kind, AnnouncementKind::Advertisement);
        assert!(taken[0].channel_key.is_none());
        assert!(sim.take_announcements().is_empty(), "taking drains");

        // A channel the device does not hold is refused by name, and
        // nothing is recorded for it.
        let multicast = Announcement {
            channel: Some([0xEE; items::CHANNEL_IDENTIFIER_LEN]),
            ..Announcement::default()
        };
        let len = frame::announce(&mut request, 4, &multicast).unwrap();
        assert_eq!(
            status_of(exchange(&mut sim, &request[..len])),
            Status::CHANNEL_NOT_FOUND.0
        );
        assert!(sim.take_announcements().is_empty());
    }

    #[test]
    fn real_session_executes_radio_transmit_effect() {
        let mut sim = SimulatedDevice::new(test_config());
        attach(&mut sim);
        let mut request = [0; 64];
        let len = frame::prop_set(&mut request, 1, prop::PHY_ENABLED, &[1]).unwrap();
        exchange(&mut sim, &request[..len]);
        let len = frame::str_send(
            &mut request,
            2,
            umsh_ulcp::ids::stream::PHY_RAW,
            b"demo",
            &[],
        )
        .unwrap();
        exchange(&mut sim, &request[..len]);
        assert_eq!(sim.take_transmitted(), &[b"demo".to_vec()]);
        assert!(
            sim.take_transmitted().is_empty(),
            "the drain leaves nothing behind"
        );
    }

    #[test]
    fn demo_packet_uses_the_real_receive_path() {
        let mut sim = SimulatedDevice::new(test_config());
        attach(&mut sim);
        let mut request = [0; 16];
        let len = frame::prop_set(&mut request, 1, prop::PHY_ENABLED, &[1]).unwrap();
        exchange(&mut sim, &request[..len]);

        sim.inject_demo_rx(200);
        let wire = sim.take_outbound().expect("demo receive is delivered");
        let mut decoder = hdlc::Decoder::<WIRE_CAPACITY>::new();
        let response = wire
            .into_iter()
            .find_map(|byte| decoder.push(byte).map(|frame| frame.unwrap().to_vec()))
            .unwrap();
        assert_eq!(
            Frame::parse(&response).unwrap().command(),
            Some(umsh_ulcp::Cmd::StrRecv)
        );
    }

    /// The whole point of the honest capability surface: nothing this
    /// device advertises invites a bridge to backhaul through it.
    #[test]
    fn a_simulated_device_claims_no_node() {
        let mut sim = SimulatedDevice::new(test_config());
        attach(&mut sim);
        let mut request = [0; 16];
        let len = frame::prop_get(&mut request, 1, umsh_ulcp::ids::prop::CAPS).unwrap();
        let responses = exchange(&mut sim, &request[..len]);
        let response = Frame::parse(&responses[0]).unwrap();
        let payload = PropPayload::parse(response.payload).unwrap();
        let mut caps = Vec::new();
        let mut offset = 0;
        while offset < payload.value.len() {
            let (value, used) = umsh_ulcp::pui::decode(&payload.value[offset..]).unwrap();
            caps.push(value);
            offset += used;
        }
        assert!(!caps.contains(&umsh_ulcp::ids::cap::MAC_BACKHAUL));
        assert!(!caps.contains(&umsh_ulcp::ids::cap::REPEATER));
        assert!(caps.contains(&umsh_ulcp::ids::cap::WRITABLE_RAW_STREAM));
    }

    /// A device whose store keeps its lists hands each change to the
    /// platform, saves none in the snapshot, brings them back on
    /// `CMD_RST`, and forgets them on `CMD_CLEAR`.
    #[test]
    fn a_store_keeps_the_lists_the_snapshot_leaves_out() {
        static DEFAULTS: [[u8; 32]; 1] = [[7; 32]];
        let mut sim = SimulatedDevice::holding_lists(test_config(), &DEFAULTS);
        attach(&mut sim);
        let read = |sim: &mut SimulatedDevice, key: u32| -> Vec<u8> {
            let mut request = [0; 16];
            let len = frame::prop_get(&mut request, 6, key).unwrap();
            let responses = exchange(sim, &request[..len]);
            let response = Frame::parse(&responses[0]).unwrap();
            PropPayload::parse(response.payload).unwrap().value.to_vec()
        };
        // What the list reports of the keys, not the keys.
        let defaults = read(&mut sim, prop::DEV_CHANNEL_KEYS);
        assert!(!defaults.is_empty());

        let mut request = [0; 64];
        let len = frame::prop_insert(&mut request, 1, prop::DEV_PEERS, &[9; 32]).unwrap();
        exchange(&mut sim, &request[..len]);
        assert!(sim.device.platform().lists.is_some());
        let len = frame::save(&mut request, 2).unwrap();
        exchange(&mut sim, &request[..len]);
        let snapshot = sim.device.platform().snapshot.clone().unwrap();
        assert!(!snapshot.windows(32).any(|window| window == [9; 32]));

        let len = frame::reset(&mut request, 3).unwrap();
        exchange(&mut sim, &request[..len]);
        assert_eq!(read(&mut sim, prop::DEV_PEERS), [9; 32]);

        let len = frame::clear(&mut request, 4).unwrap();
        exchange(&mut sim, &request[..len]);
        assert!(sim.device.platform().lists.is_none());
        let len = frame::reset(&mut request, 5).unwrap();
        exchange(&mut sim, &request[..len]);
        assert!(read(&mut sim, prop::DEV_PEERS).is_empty());
        assert_eq!(read(&mut sim, prop::DEV_CHANNEL_KEYS), defaults);
    }
}
