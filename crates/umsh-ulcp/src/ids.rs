//! Property, stream, and capability identifiers, plus protocol
//! constants. The complete allocation is in
//! `docs/protocol/src/ulcp-index.md`.

/// Protocol version advertised in `PROP_PROTOCOL_VERSION`.
pub const PROTOCOL_MAJOR_VERSION: u8 = 6;
/// Protocol version advertised in `PROP_PROTOCOL_VERSION`.
pub const PROTOCOL_MINOR_VERSION: u8 = 0;

/// Value of `PROP_INTERFACE_TYPE` for this protocol.
pub const INTERFACE_TYPE: u32 = 8;

/// Property identifiers.
pub mod prop {
    /// Status of the last operation (`PROP_LAST_STATUS`).
    pub const LAST_STATUS: u32 = 0;
    /// Protocol major/minor version (`PROP_PROTOCOL_VERSION`).
    pub const PROTOCOL_VERSION: u32 = 1;
    /// device firmware version string (`PROP_DEV_VERSION`).
    pub const DEV_VERSION: u32 = 2;
    /// Interface type discriminator (`PROP_INTERFACE_TYPE`).
    pub const INTERFACE_TYPE: u32 = 3;
    /// Hardware model name (`PROP_DEV_MODEL`) — what the board *is*, where
    /// `DEV_VERSION` is what it *runs*. Optional and ungated: a device
    /// that cannot name its own hardware refuses the get.
    pub const DEV_MODEL: u32 = 4;
    /// Supported capability list (`PROP_CAPS`).
    pub const CAPS: u32 = 5;
    /// Seconds since the device booted (`PROP_UPTIME`). Optional and
    /// ungated, like `DEV_MODEL`: a device with no monotonic clock to
    /// answer from refuses the get. Reads next to `LAST_STATUS`, which
    /// says why the device last reset — this says how long ago.
    pub const UPTIME: u32 = 6;
    /// PHY enabled flag (`PROP_PHY_ENABLED`).
    pub const PHY_ENABLED: u32 = 32;
    /// Frequency in kHz (`PROP_PHY_FREQ`).
    pub const PHY_FREQ: u32 = 35;
    /// TX power in dBm (`PROP_PHY_TX_POWER`).
    pub const PHY_TX_POWER: u32 = 37;
    /// Current RSSI in dBm (`PROP_PHY_RSSI`).
    pub const PHY_RSSI: u32 = 38;
    /// LoRa bandwidth in Hz (`PROP_PHY_LORA_BW`).
    pub const PHY_LORA_BW: u32 = 39;
    /// LoRa spreading factor (`PROP_PHY_LORA_SF`).
    pub const PHY_LORA_SF: u32 = 40;
    /// LoRa coding rate (`PROP_PHY_LORA_CR`).
    pub const PHY_LORA_CR: u32 = 41;
    /// Maximum `STR_PHY_RAW` data size in octets (`PROP_PHY_MTU`).
    pub const PHY_MTU: u32 = 42;
    /// LoRa sync word, SX126x-style 16-bit (`PROP_PHY_LORA_SW`).
    pub const PHY_LORA_SW: u32 = 43;
    /// Deliver all received frames, bypassing host receive filtering
    /// (`PROP_MAC_PROMISCUOUS`). Session-scoped.
    pub const MAC_PROMISCUOUS: u32 = 48;
    /// Whether a saved snapshot exists (`PROP_SAVED`).
    pub const SAVED: u32 = 49;
    /// Carry the host on a point-to-point link to the device's own node
    /// instead of the shared medium (`PROP_MAC_BACKHAUL`). Session-scoped.
    pub const MAC_BACKHAUL: u32 = 50;
    /// Device identity public key (`PROP_DEV_KEY`).
    pub const DEV_KEY: u32 = 64;
    /// Device identity private key, write-only (`PROP_DEV_PRIVATE_KEY`).
    pub const DEV_PRIVATE_KEY: u32 = 65;
    /// Device identity channel keys (`PROP_DEV_CHANNEL_KEYS`).
    pub const DEV_CHANNEL_KEYS: u32 = 66;
    /// Device identity peer list (`PROP_DEV_PEERS`).
    pub const DEV_PEERS: u32 = 67;
    /// Human-readable device name (`PROP_DEV_NAME`).
    pub const DEV_NAME: u32 = 68;
    /// Battery status snapshot (`PROP_BATTERY`).
    pub const BATTERY: u32 = 69;
    /// Autonomous MAC-layer repeater/forwarding enable (`PROP_MAC_REPEATER_ENABLED`).
    ///
    /// First of the device-behavior settings range (70–95), which is
    /// subdivided as 70–79 repeater and identity, 80–87 advertisement
    /// policy (80–84 allocated, 85–87 spare), 88–93 positioning, 94–95
    /// environmental sensing (94 illuminance, 95 spare — the board's
    /// thermistor is the expected claimant). A
    /// single-octet identifier is the scarce resource, so the positioning
    /// range holds the enable toggle and the fix telemetry a host reads
    /// and the device announces continually; the rarely-touched
    /// positioning *configuration* lives in the extended device range
    /// alongside `PROP_TIME`. A persisted, device-domain boolean: when
    /// set, the device identity's on-board MAC forwards overheard routable
    /// frames and advertises the `REP` capability bit. The advertised
    /// *role* is a separate matter — see `IDENT_ROLE`.
    pub const MAC_REPEATER_ENABLED: u32 = 70;
    /// The device identity's complete signed node-identity blob
    /// (`PROP_IDENT`), served through a deferred signing effect.
    pub const IDENT: u32 = 71;
    /// Advertised `ROLE` byte of the device identity (`PROP_IDENT_ROLE`).
    /// Empty means "derive it from what the device is actually doing".
    pub const IDENT_ROLE: u32 = 72;
    /// Whether the device identity advertises the `MOB` capability bit
    /// (`PROP_IDENT_MOBILE`) — mobile versus fixed, which is orthogonal
    /// to tethered versus standalone.
    pub const IDENT_MOBILE: u32 = 73;
    /// Regions the device identity flood-forwards for
    /// (`PROP_MAC_REPEATER_REGIONS`) — multiple-value, each item 1 to 24
    /// octets of UTF-8 naming a region in its string form, empty for
    /// "forward regardless of region code". The device derives the
    /// 2-octet forwarding codes itself; the strings are what it
    /// advertises, since a hash-derived code names nothing.
    pub const MAC_REPEATER_REGIONS: u32 = 74;
    /// Region code inserted into untagged flood packets
    /// (`PROP_MAC_REPEATER_DEFAULT_REGION`) — one 2-octet code, or empty
    /// to never tag.
    pub const MAC_REPEATER_DEFAULT_REGION: u32 = 75;
    /// Minimum received RSSI in dBm for flood forwarding
    /// (`PROP_MAC_REPEATER_MIN_RSSI`) — INT16, or empty for no threshold.
    pub const MAC_REPEATER_MIN_RSSI: u32 = 76;
    /// Minimum received SNR in whole dB for flood forwarding
    /// (`PROP_MAC_REPEATER_MIN_SNR`) — INT8, or empty for no threshold.
    pub const MAC_REPEATER_MIN_SNR: u32 = 77;
    /// Whether the device identity answers Identity Requests
    /// (`PROP_DEV_DISCOVERABLE`) — BOOL, default 1. Requires
    /// `CAP_DEV_IDENTITY`.
    pub const DEV_DISCOVERABLE: u32 = 78;
    /// Locate-alert state (`PROP_ALERT`) — what the device is currently
    /// doing to draw attention to where it physically is. Volatile: never
    /// saved, unaffected by `CMD_RST`, `ALERT_NONE` after every reset.
    /// Requires `CAP_ALERT`.
    pub const ALERT: u32 = 79;
    /// Seconds between unsolicited advertisements (`PROP_ADVERT_INTERVAL`)
    /// — UINT32, 0 to send none. An advertisement carries the signed node
    /// identity and goes out with no flood hops and no source route, so it
    /// reaches the neighbours that can hear the device directly and stops
    /// there. The accepted range is [`MIN_AUTO_ANNOUNCE_INTERVAL_S`] to
    /// [`MAX_AUTO_ANNOUNCE_INTERVAL_S`], and the value is a floor rather
    /// than a period: the device scatters each send later by up to a
    /// quarter of it. Requires `CAP_ADVERT`.
    pub const ADVERT_INTERVAL: u32 = 80;
    /// Seconds between unsolicited beacons (`PROP_BEACON_INTERVAL`) —
    /// UINT32, 0 to send none. A beacon carries no payload and goes out
    /// with a flood budget and the trace-route and trace-signal options,
    /// so what it announces is the path back to the device rather than who
    /// the device is. Same range and same scatter as
    /// [`ADVERT_INTERVAL`]. Requires `CAP_ADVERT`.
    pub const BEACON_INTERVAL: u32 = 81;
    /// Whether the device emits one beacon once it comes up
    /// (`PROP_STARTUP_BEACON`) — BOOL, default 1. Requires `CAP_ADVERT`.
    pub const STARTUP_BEACON: u32 = 82;
    /// Location the device identity advertises (`PROP_IDENT_LOCATION`) —
    /// 0–7 octets in the variable-precision interleaved format, empty to
    /// advertise none. The value carries its own precision, so a location
    /// entered by hand needs no separate precision setting.
    ///
    /// This and [`IDENT_ALTITUDE`] are where the advertised identity gets
    /// its position, whether a fix wrote them or an administrator did.
    /// [`GNSS_IDENT_UPDATE`] set, the device writes them itself from each
    /// fix and refuses a write with `STATUS_INVALID_STATE`; cleared, they
    /// are writable and hold whatever they last held. Requires
    /// `CAP_IDENT`, not `CAP_GNSS` — a fixed repeater with no receiver
    /// still has somewhere to be.
    pub const IDENT_LOCATION: u32 = 83;
    /// Altitude the device identity advertises (`PROP_IDENT_ALTITUDE`) —
    /// a minimal-length signed integer (see [`crate::sint`]) of meters
    /// above the WGS-84 ellipsoid, or empty. Advertised only alongside a
    /// location. Same writability rule as [`IDENT_LOCATION`]; requires
    /// `CAP_IDENT`.
    pub const IDENT_ALTITUDE: u32 = 84;
    /// Whether the GNSS receiver is powered (`PROP_GNSS_ENABLED`) — BOOL,
    /// default 0. Off means the lowest power state the receiver reaches;
    /// a board whose receiver RTC is the board's only clock keeps that
    /// domain alive regardless. Requires `CAP_GNSS`.
    pub const GNSS_ENABLED: u32 = 88;
    /// Last position fix (`PROP_GNSS_LOCATION`) — 0–7 octets in the
    /// variable-precision interleaved format. Empty means no fix has been
    /// obtained this power cycle. Requires `CAP_GNSS`.
    pub const GNSS_LOCATION: u32 = 89;
    /// Altitude of the last fix (`PROP_GNSS_ALTITUDE`) — `INT32_LE`
    /// meters above the WGS-84 ellipsoid, matching the units of node
    /// identity option 2. Empty when there is no fix. Requires `CAP_GNSS`.
    pub const GNSS_ALTITUDE: u32 = 90;
    /// Fix quality (`PROP_GNSS_FIX`) — `UINT8`, 0 none, 1 two-dimensional,
    /// 2 three-dimensional. Reads 0 while the receiver is disabled.
    /// Requires `CAP_GNSS`.
    pub const GNSS_FIX: u32 = 91;
    /// Estimated horizontal accuracy of the last fix
    /// (`PROP_GNSS_PRECISION`) — `UINT16_LE` decimeters. An estimate
    /// derived from the receiver's dilution of precision, not a measured
    /// error bound. Empty when there is no fix. Requires `CAP_GNSS`.
    pub const GNSS_PRECISION: u32 = 92;
    /// Satellite counts (`PROP_GNSS_SATELLITES`) — `UINT8` satellites used
    /// in the solution, optionally followed by `UINT8` satellites in view.
    /// Reads 0 while the receiver is disabled. Requires `CAP_GNSS`.
    pub const GNSS_SATELLITES: u32 = 93;
    /// Ambient illuminance (`PROP_ILLUMINANCE`) — `UINT32_LE` millilux.
    /// Millilux rather than lux because the interesting region for an
    /// indicator that should not be intrusive at night is below one lux.
    /// Sampled when read; empty when the sensor could not be read. A
    /// board reports its clamped maximum above the sensor's saturation
    /// point rather than extrapolating past it. Requires
    /// `CAP_ILLUMINANCE`.
    pub const ILLUMINANCE: u32 = 94;
    /// Tethered host identity public key (`PROP_HOST_KEY`).
    pub const HOST_KEY: u32 = 96;
    /// Host channel keys (`PROP_HOST_CHANNEL_KEYS`).
    pub const HOST_CHANNEL_KEYS: u32 = 97;
    /// Host pairwise peer keys (`PROP_HOST_PEER_KEYS`).
    pub const HOST_PEER_KEYS: u32 = 98;
    /// Host receive filter table (`PROP_HOST_RX_FILTERS`).
    pub const HOST_RX_FILTERS: u32 = 99;
    /// Acknowledgement-delegation enable (`PROP_HOST_AUTO_ACK`).
    pub const HOST_AUTO_ACK: u32 = 100;
    /// Frames currently queued (`PROP_HOST_RX_QUEUE_COUNT`).
    pub const HOST_RX_QUEUE_COUNT: u32 = 101;
    /// Inbound queue capacity in frames (`PROP_HOST_RX_QUEUE_CAPACITY`).
    pub const HOST_RX_QUEUE_CAPACITY: u32 = 102;
    /// Cumulative frames dropped from the queue (`PROP_HOST_RX_QUEUE_DROPPED`).
    pub const HOST_RX_QUEUE_DROPPED: u32 = 103;
    /// Transmit duty usage over the past hour (`PROP_PHY_DUTY_NOW`).
    pub const PHY_DUTY_NOW: u32 = 4820;
    /// Duty-cycle limit (`PROP_PHY_DUTY_LIMIT`).
    pub const PHY_DUTY_LIMIT: u32 = 4822;
    /// Persisted, write-only BLE pairing passkey (`PROP_BLE_PAIRING_PIN`).
    pub const BLE_PAIRING_PIN: u32 = 4864;
    /// Nodes authorized to manage this device over the mesh
    /// (`PROP_DEV_ADMINS`) — a multiple-value property whose items are
    /// 32-octet Ed25519 public keys, reported verbatim. An empty list
    /// disables node management. Requires `CAP_ADMIN`.
    pub const DEV_ADMINS: u32 = 4865;
    /// Wall-clock time (`PROP_TIME`) — `UINT32_LE` seconds since the Unix
    /// epoch, or **empty** when the device does not know what time it is.
    /// Unsigned, so the encoding is wrap-free into 2106. Requires
    /// `CAP_TIME`.
    pub const TIME: u32 = 4866;
    /// Local time-zone offset from UTC (`PROP_TZ_OFFSET`) — `INT16_LE`
    /// minutes, default 0. Unlike `PROP_TIME` this always has a value:
    /// where the device is configured to be is known even when what time
    /// it is is not. Requires `CAP_TIME`.
    pub const TZ_OFFSET: u32 = 4867;
    /// Whether position fixes update the advertised node identity
    /// (`PROP_GNSS_IDENT_UPDATE`) — BOOL, default 0. Requires `CAP_GNSS`.
    pub const GNSS_IDENT_UPDATE: u32 = 4868;
    /// Precision the advertised location is clamped to
    /// (`PROP_GNSS_IDENT_PRECISION`) — `UINT8` 1–7, default 5. Requires
    /// `CAP_GNSS`.
    pub const GNSS_IDENT_PRECISION: u32 = 4869;
    /// Whether receiver-derived time may set the wall clock
    /// (`PROP_GNSS_TIME_TRUST`) — BOOL, default 1. Cleared, neither a fix
    /// nor a receiver-RTC read touches `PROP_TIME`, which leaves a
    /// manually-set clock proof against a jammed or spoofed sky. Position
    /// reporting is unaffected. Requires `CAP_GNSS`.
    pub const GNSS_TIME_TRUST: u32 = 4870;
    /// Whether the device is reachable over Bluetooth
    /// (`PROP_BLE_ENABLED`) — BOOL, default 1. Requires `CAP_BLE`.
    ///
    /// Cleared, the device stops advertising and drops any attached
    /// host; bonds survive, and the host reconnects when it is set
    /// again. It does not claim the radio is powered down: tearing a
    /// vendor stack down at runtime is not something every platform can
    /// do, and a property that says "off" while a stack is still up
    /// would be lying about the thing a user turns it off for.
    pub const BLE_ENABLED: u32 = 4871;
}

/// `PROP_SAVED` values.
///
/// A snapshot that exists but cannot be read is distinguishable from no
/// snapshot at all, and running on an older generation than the one last
/// written is distinguishable from running on the newest.
pub mod saved {
    /// Nothing is saved.
    pub const NONE: u8 = 0;
    /// The newest saved generation is in effect.
    pub const CURRENT: u8 = 1;
    /// A newer generation was rejected; an older one is in effect.
    pub const FALLBACK: u8 = 2;
    /// A snapshot exists but no generation could be read.
    pub const UNREADABLE: u8 = 3;
}

/// Stream identifiers.
pub mod stream {
    /// Raw radio frame stream (`STR_PHY_RAW`).
    pub const PHY_RAW: u32 = 113;
}

/// Capability codes advertised via `PROP_CAPS`.
pub mod cap {
    /// `CAP_WRITABLE_RAW_STREAM`
    pub const WRITABLE_RAW_STREAM: u32 = 8;
    /// `CAP_PHY_DUTY_LIMIT`
    pub const PHY_DUTY_LIMIT: u32 = 16;
    /// `CAP_PHY_LORA`
    pub const PHY_LORA: u32 = 515;
    /// `CAP_HOST_FILTER`
    pub const HOST_FILTER: u32 = 32;
    /// `CAP_HOST_RX_QUEUE` (requires `CAP_HOST_FILTER`)
    pub const HOST_RX_QUEUE: u32 = 33;
    /// `CAP_HOST_KEYS` (requires `CAP_HOST_FILTER`)
    pub const HOST_KEYS: u32 = 34;
    /// `CAP_HOST_AUTO_ACK` (requires `CAP_HOST_KEYS` and `CAP_HOST_RX_QUEUE`)
    pub const HOST_AUTO_ACK: u32 = 35;
    /// `CAP_SAVE`
    pub const SAVE: u32 = 36;
    /// `CAP_DEV_IDENTITY`
    pub const DEV_IDENTITY: u32 = 37;
    /// `CAP_DEV_NAME`
    pub const DEV_NAME: u32 = 38;
    /// `CAP_BATTERY`
    pub const BATTERY: u32 = 39;
    /// `CAP_REPEATER` — the device can act as an autonomous mesh repeater
    /// (`PROP_MAC_REPEATER_ENABLED`). Requires `CAP_DEV_IDENTITY`.
    pub const REPEATER: u32 = 40;
    /// `CAP_IDENT` — the device serves and configures its own advertised
    /// node identity (`PROP_IDENT`, `PROP_IDENT_ROLE`,
    /// `PROP_IDENT_MOBILE`). Requires `CAP_DEV_IDENTITY`.
    pub const IDENT: u32 = 41;
    /// `CAP_ALERT` — the device has some means of making itself
    /// physically conspicuous on demand (`PROP_ALERT`). It says nothing
    /// about *which* means, so a host must not assume audibility.
    pub const ALERT: u32 = 42;
    /// `CAP_ADMIN` — the device can be managed over the mesh by the nodes
    /// listed in `PROP_DEV_ADMINS`. Requires `CAP_DEV_IDENTITY`, since an
    /// administrator addresses the device identity, and `CAP_CMD_MULTI`,
    /// so an administrator may rely on the multi-property commands.
    pub const ADMIN: u32 = 43;
    /// `CAP_TIME` — the device keeps a wall clock (`PROP_TIME`,
    /// `PROP_TZ_OFFSET`). It says nothing about where the time comes from
    /// or whether it survives a power cycle.
    pub const TIME: u32 = 44;
    /// `CAP_GNSS` — a GNSS receiver is fitted, so the positioning
    /// properties exist and the wall clock has a source that can set
    /// itself. Requires `CAP_TIME`.
    pub const GNSS: u32 = 45;
    /// `CAP_ADVERT` — the device announces itself on a schedule of its own
    /// (`PROP_ADVERT_INTERVAL`, `PROP_BEACON_INTERVAL`,
    /// `PROP_STARTUP_BEACON`). Requires `CAP_DEV_IDENTITY`, since what an
    /// advertisement carries is the device identity.
    pub const ADVERT: u32 = 46;
    /// `CAP_ILLUMINANCE` — an ambient light sensor is fitted, so
    /// `PROP_ILLUMINANCE` reads a measurement rather than nothing.
    pub const ILLUMINANCE: u32 = 47;
    /// `CAP_MAC_BACKHAUL` — the device can carry the host on a
    /// point-to-point link to its own node (`PROP_MAC_BACKHAUL`).
    /// Requires `CAP_REPEATER`: without a repeater there is nothing on
    /// the far side of that link to carry the host's traffic onward.
    pub const MAC_BACKHAUL: u32 = 48;
    /// `CAP_CMD_MULTI` — the device accepts `CMD_PROP_MULTI_GET` and
    /// `CMD_PROP_MULTI_SET` and answers them with `CMD_PROP_ARE`.
    pub const CMD_MULTI: u32 = 49;
    /// `CAP_BLE` — the device has a Bluetooth transport whose
    /// reachability it can turn on and off (`PROP_BLE_ENABLED`). It says
    /// nothing about the stack underneath, and in particular does not
    /// promise that clearing the property powers a radio down.
    pub const BLE: u32 = 50;
    /// `CAP_REBOOT` — the device can restart its hardware on command
    /// (`CMD_REBOOT`). A device that cannot — one whose ULCP session is
    /// a process rather than a board — leaves this out and answers the
    /// command `STATUS_UNIMPLEMENTED`.
    pub const REBOOT: u32 = 51;
}

/// Whether a property is reachable from a mesh administrator.
///
/// The out-of-reach set is small and named explicitly by the spec rather
/// than derived, because "device domain" is not a property of the key: a
/// host-domain table and a device-domain one differ only by which half of
/// the device they configure. A device answers all three with
/// `STATUS_PROP_NOT_FOUND` — an administrator learns that the property does
/// not exist for it, not that it exists and was refused — and an
/// administrator that reads this first spends no airtime asking.
pub fn admin_reachable(key: u32) -> bool {
    !matches!(
        key,
        // The host domain in full: the assistance the device owes to
        // whatever host it serves is that host's business.
        prop::HOST_KEY
            | prop::HOST_CHANNEL_KEYS
            | prop::HOST_PEER_KEYS
            | prop::HOST_RX_FILTERS
            | prop::HOST_AUTO_ACK
            | prop::HOST_RX_QUEUE_COUNT
            | prop::HOST_RX_QUEUE_CAPACITY
            | prop::HOST_RX_QUEUE_DROPPED
            // Session state: an exchange is not an attach, so there is no
            // session for it to describe.
            | prop::MAC_PROMISCUOUS
            | prop::MAC_BACKHAUL
            // A device identity cannot be installed over the mesh.
            | prop::DEV_PRIVATE_KEY
    )
}

/// Value used in `PROP_PHY_DUTY_LIMIT` to disable duty-cycle limiting.
pub const DUTY_LIMIT_DISABLED: u16 = 0xFFFF;

/// Shortest accepted `PROP_ADVERT_INTERVAL` / `PROP_BEACON_INTERVAL`, in
/// seconds.
///
/// An absolute floor, and one a device may only ever round *up* from:
/// scheduling jitter delays an announcement and never brings it forward,
/// so no configuration can put an unsolicited broadcast on the air more
/// often than this. The duty ledger remains the airtime control; this is
/// what keeps a mistyped interval from spending the whole budget on
/// announcements before anything else can speak.
pub const MIN_AUTO_ANNOUNCE_INTERVAL_S: u32 = 20 * 60;

/// Longest accepted `PROP_ADVERT_INTERVAL` / `PROP_BEACON_INTERVAL`, in
/// seconds.
///
/// A ceiling on how stale the mesh's picture of a node may get while that
/// node still considers itself to be announcing. Past a day the schedule
/// has stopped being one, and 0 says so more honestly.
pub const MAX_AUTO_ANNOUNCE_INTERVAL_S: u32 = 24 * 60 * 60;

/// Default `PROP_ADVERT_INTERVAL`, in seconds.
pub const DEFAULT_ADVERT_INTERVAL_S: u32 = 4 * 60 * 60;

/// Default `PROP_BEACON_INTERVAL`, in seconds.
pub const DEFAULT_BEACON_INTERVAL_S: u32 = 60 * 60;
