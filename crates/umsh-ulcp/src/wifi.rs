//! Wi-Fi codecs (`PROP_WIFI_*`).
//!
//! The structures of `docs/protocol/src/ulcp-wifi.md`: a known-network
//! entry and its credential, a scan result, the station's link, and the
//! access point's configuration, state, and clients.
//!
//! Every codec here is used by both sides, which is the point: a device
//! that builds `PROP_WIFI_LINK` with the same writer a host parses it
//! with cannot disagree with that host about the format.
//!
//! Decoding is structural and tolerant in the way
//! `docs/protocol/src/ulcp-conformance.md` requires of receivers: it
//! rejects what it cannot parse and accepts what it can, including
//! trailing octets a later revision may append. Well-formedness, the
//! rules a device answers `STATUS_INVALID_ARGUMENT` to, is
//! [`NetworkEntry::validate`] and [`ApConfig::validate`], kept separate
//! so that a sender can check itself before transmitting and a device
//! can check the sender.
//!
//! Whole-table values concatenate items with a length prefix each; that
//! framing is [`crate::items::prefixed_items`] and is not repeated here.

/// Longest SSID, in octets. Not text: an SSID is 0 to 32 arbitrary
/// octets, and a device compares it bytewise.
pub const SSID_MAX_LEN: usize = 32;
/// Length of a BSSID or a station MAC address.
pub const MAC_LEN: usize = 6;
/// Length of a raw pairwise master key.
pub const PMK_LEN: usize = 32;
/// Shortest WPA/WPA2 passphrase, per 802.11 Annex J.
pub const PASSPHRASE_MIN_LEN: usize = 8;
/// Longest WPA/WPA2 passphrase, per 802.11 Annex J.
pub const PASSPHRASE_MAX_LEN: usize = 63;
/// Longest SAE password this protocol admits. SAE itself sets no bound;
/// this is where the more generous stacks stop.
pub const SAE_PASSWORD_MAX_LEN: usize = 128;

/// `FLAGS` bit 0: the network hides its SSID, so the device probes for
/// it by name rather than waiting to hear it.
pub const FLAG_HIDDEN: u8 = 1 << 0;
/// `FLAGS` bit 1: the credential is a raw [`PMK_LEN`]-octet pairwise
/// master key rather than a passphrase.
pub const FLAG_RAW_KEY: u8 = 1 << 1;

const FLAGS_RESERVED: u8 = !(FLAG_HIDDEN | FLAG_RAW_KEY);

/// Largest encoded [`NetworkEntry`]: flags, mode, length, a full SSID,
/// and the longest credential any mode defines.
pub const NETWORK_ENTRY_MAX_LEN: usize = 3 + SSID_MAX_LEN + SAE_PASSWORD_MAX_LEN;
/// Largest encoded [`ScanResult`].
pub const SCAN_RESULT_MAX_LEN: usize = 11 + SSID_MAX_LEN;
/// Largest encoded [`Link`]: state, reason, BSSID, and frequency.
pub const LINK_MAX_LEN: usize = 10;
/// Largest encoded [`ApConfig`].
pub const AP_CONFIG_MAX_LEN: usize = 11 + SSID_MAX_LEN + SAE_PASSWORD_MAX_LEN;
/// Encoded length of an [`ApClient`].
pub const AP_CLIENT_LEN: usize = 11;

/// Decode or well-formedness failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiError {
    /// The input ended before the structure was complete, or a declared
    /// length ran past it.
    Truncated,
    /// The value is structurally wrong: a reserved flag bit set, an
    /// unknown enumeration code, a field of impossible length.
    Malformed,
    /// The value parses but is not something a device may be asked for:
    /// an empty SSID, a credential of the wrong length or kind for its
    /// mode, a mode with no credential form. This is the
    /// `STATUS_INVALID_ARGUMENT` set.
    NotWellFormed,
    /// The output buffer cannot hold the encoded value.
    BufferTooSmall,
}

/// A station's minimum security requirement, or an advertised/AP mode.
/// Numeric codes are not a security ranking; use [`Self::permits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityMode {
    /// `WIFI_SEC_OPEN`: no security at all.
    Open = 0,
    /// `WIFI_SEC_OWE`: Enhanced Open. Encrypted against anyone
    /// listening, authenticated against nobody, and the only
    /// credential-free mode permitted on 6 GHz.
    Owe = 1,
    /// `WIFI_SEC_WPA2`: WPA2-Personal, covering the mixed networks that
    /// negotiate CCMP.
    Wpa2 = 2,
    /// `WIFI_SEC_WPA3`: WPA3-Personal, SAE.
    Wpa3 = 3,
    /// `WIFI_SEC_WPA`: the TKIP-only remainder, which a device may
    /// decline to join.
    Wpa = 4,
    /// `WIFI_SEC_WEP`: reportable, not joinable. No credential form is
    /// defined.
    Wep = 5,
    /// `WIFI_SEC_WPA2_ENT`: reportable, not joinable here.
    Wpa2Ent = 6,
    /// `WIFI_SEC_WPA3_ENT`: reportable, not joinable here.
    Wpa3Ent = 7,
    /// `WIFI_SEC_WPA3_ENT_192`: reportable, not joinable here.
    Wpa3Ent192 = 8,
}

impl SecurityMode {
    /// Whether an authentication mode satisfies this station requirement
    /// with the stored credential. A raw PMK cannot authenticate with SAE.
    pub const fn permits(self, negotiated: Self, raw_key: bool) -> bool {
        match (self, negotiated) {
            (Self::Open, Self::Open | Self::Owe) | (Self::Owe, Self::Owe) => !raw_key,
            (Self::Wpa, Self::Wpa | Self::Wpa2) | (Self::Wpa2, Self::Wpa2) => true,
            (Self::Wpa | Self::Wpa2 | Self::Wpa3, Self::Wpa3) => !raw_key,
            _ => false,
        }
    }

    /// Strongest advertised mode supported by both the device and credential.
    /// This preference order is explicit; wire codes are not a ranking.
    pub fn strongest_compatible(
        self,
        advertised: u16,
        supported: u16,
        raw_key: bool,
    ) -> Option<Self> {
        [Self::Wpa3, Self::Wpa2, Self::Wpa, Self::Owe, Self::Open]
            .into_iter()
            .find(|mode| advertised & supported & mode.bit() != 0 && self.permits(*mode, raw_key))
    }

    /// The wire code for this mode.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Strict conversion from a wire octet. Codes 9 through 15 are
    /// reserved and 16 upward cannot be reported at all, since a scan
    /// result carries these as a 16-bit set.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Open),
            1 => Some(Self::Owe),
            2 => Some(Self::Wpa2),
            3 => Some(Self::Wpa3),
            4 => Some(Self::Wpa),
            5 => Some(Self::Wep),
            6 => Some(Self::Wpa2Ent),
            7 => Some(Self::Wpa3Ent),
            8 => Some(Self::Wpa3Ent192),
            _ => None,
        }
    }

    /// This mode's bit in a [`ScanResult::modes`] set.
    pub const fn bit(self) -> u16 {
        1 << (self as u16)
    }

    /// Whether a host can express a credential for this mode, and so
    /// whether an entry naming it can be inserted at all. The four that
    /// cannot are numbered so that a scan result can say what it heard.
    pub const fn has_credential_form(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Owe | Self::Wpa2 | Self::Wpa3 | Self::Wpa
        )
    }

    /// Whether this mode's credential is a passphrase from which the
    /// device derives a pairwise master key, and so whether
    /// [`FLAG_RAW_KEY`] may stand in for one. SAE derives its key
    /// through the exchange rather than from the password, so a stored
    /// key is not a substitute there.
    pub const fn derives_key_from_passphrase(self) -> bool {
        matches!(self, Self::Wpa2 | Self::Wpa)
    }

    /// Whether an access point may offer this mode.
    pub const fn may_be_offered(self) -> bool {
        matches!(self, Self::Open | Self::Owe | Self::Wpa2 | Self::Wpa3)
    }

    /// The credential length bounds for this mode, as a passphrase.
    /// `None` when the mode takes no credential or defines no form.
    pub const fn passphrase_len_bounds(self) -> Option<(usize, usize)> {
        match self {
            Self::Wpa2 | Self::Wpa => Some((PASSPHRASE_MIN_LEN, PASSPHRASE_MAX_LEN)),
            Self::Wpa3 => Some((1, SAE_PASSWORD_MAX_LEN)),
            _ => None,
        }
    }
}

/// Read a little-endian `u16` at `at`, or `None` past the end.
const fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    if at + 2 > bytes.len() {
        return None;
    }
    Some((bytes[at] as u16) | ((bytes[at + 1] as u16) << 8))
}

/// Whether these octets are a credential a host may hand over as a
/// passphrase: UTF-8, and free of U+0000 since the wire carries no
/// terminator and the device derives keys from exactly these octets.
fn passphrase_is_expressible(bytes: &[u8]) -> bool {
    !bytes.contains(&0) && core::str::from_utf8(bytes).is_ok()
}

/// Well-formedness of a credential against the mode it is offered for.
fn credential_is_well_formed(security: SecurityMode, raw_key: bool, credential: &[u8]) -> bool {
    if !security.has_credential_form() {
        return false;
    }
    if raw_key {
        return security.derives_key_from_passphrase() && credential.len() == PMK_LEN;
    }
    match security.passphrase_len_bounds() {
        // Open and OWE carry no credential at all.
        None => credential.is_empty(),
        Some((min, max)) => {
            credential.len() >= min
                && credential.len() <= max
                && passphrase_is_expressible(credential)
        }
    }
}

/// One entry of `PROP_WIFI_NETWORKS`: a network the device knows.
///
/// **Secret-bearing.** The reported form stops at the SSID, which is
/// what [`Self::encode_reported`] writes and what [`Self::decode`]
/// yields from a device's answer, with `credential` empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEntry<'a> {
    /// The network hides its SSID.
    pub hidden: bool,
    /// `credential` is a raw pairwise master key rather than a
    /// passphrase.
    pub raw_key: bool,
    pub security: SecurityMode,
    /// 1 to [`SSID_MAX_LEN`] octets. Never empty: an empty selection
    /// means no selection, so an entry with no name could be stored and
    /// never chosen.
    pub ssid: &'a [u8],
    /// Empty in the reported form, and for the modes that take none.
    pub credential: &'a [u8],
}

impl<'a> NetworkEntry<'a> {
    /// The flags octet for this entry.
    pub const fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.hidden {
            flags |= FLAG_HIDDEN;
        }
        if self.raw_key {
            flags |= FLAG_RAW_KEY;
        }
        flags
    }

    /// Whether this entry is one a device may be asked to store.
    ///
    /// Separate from encoding so that a host can check itself before
    /// transmitting and a device can apply the same rule to what
    /// arrives, answering `STATUS_INVALID_ARGUMENT` to anything this
    /// rejects. A mode that is well-formed but beyond the hardware is a
    /// different answer, `STATUS_UNIMPLEMENTED`, and is not decided
    /// here.
    pub fn validate(&self) -> Result<(), WifiError> {
        if self.ssid.is_empty() || self.ssid.len() > SSID_MAX_LEN {
            return Err(WifiError::NotWellFormed);
        }
        if !credential_is_well_formed(self.security, self.raw_key, self.credential) {
            return Err(WifiError::NotWellFormed);
        }
        Ok(())
    }

    fn encode_inner(&self, out: &mut [u8], with_credential: bool) -> Result<usize, WifiError> {
        let credential: &[u8] = if with_credential {
            self.credential
        } else {
            &[]
        };
        let len = 3 + self.ssid.len() + credential.len();
        if self.ssid.len() > SSID_MAX_LEN {
            return Err(WifiError::NotWellFormed);
        }
        if out.len() < len {
            return Err(WifiError::BufferTooSmall);
        }
        out[0] = self.flags();
        out[1] = self.security.code();
        out[2] = self.ssid.len() as u8;
        out[3..3 + self.ssid.len()].copy_from_slice(self.ssid);
        out[3 + self.ssid.len()..len].copy_from_slice(credential);
        Ok(len)
    }

    /// Encode the item form, credential included.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WifiError> {
        self.encode_inner(out, true)
    }

    /// Encode the reported form: the item through its SSID. No
    /// `CMD_PROP_GET` and no notification ever carries a credential.
    pub fn encode_reported(&self, out: &mut [u8]) -> Result<usize, WifiError> {
        self.encode_inner(out, false)
    }

    /// Decode one item. The credential is whatever follows the SSID,
    /// which is empty in a reported entry.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, WifiError> {
        if bytes.len() < 3 {
            return Err(WifiError::Truncated);
        }
        let flags = bytes[0];
        if flags & FLAGS_RESERVED != 0 {
            return Err(WifiError::Malformed);
        }
        let security = SecurityMode::from_code(bytes[1]).ok_or(WifiError::Malformed)?;
        let ssid_len = bytes[2] as usize;
        if ssid_len > SSID_MAX_LEN {
            return Err(WifiError::Malformed);
        }
        if bytes.len() < 3 + ssid_len {
            return Err(WifiError::Truncated);
        }
        Ok(Self {
            hidden: flags & FLAG_HIDDEN != 0,
            raw_key: flags & FLAG_RAW_KEY != 0,
            security,
            ssid: &bytes[3..3 + ssid_len],
            credential: &bytes[3 + ssid_len..],
        })
    }
}

/// One entry of `PROP_WIFI_SCAN_RESULTS`: an access point the device
/// heard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanResult<'a> {
    /// The security modes this access point offers, as
    /// [`SecurityMode::bit`] flags. **No bits set** means the device did
    /// not determine them, which a receiver that reads beacon headers
    /// for their addresses has no reason to do.
    pub modes: u16,
    /// Center frequency of the primary 20 MHz channel.
    pub frequency_mhz: u16,
    pub rssi_dbm: i8,
    /// The key: one item per access point.
    pub bssid: [u8; MAC_LEN],
    /// Empty when no name was reported, whether hidden or unread.
    pub ssid: &'a [u8],
}

impl<'a> ScanResult<'a> {
    /// Whether the device determined the offered modes at all.
    pub const fn modes_known(&self) -> bool {
        self.modes != 0
    }

    /// Whether this access point offers `mode`.
    pub const fn offers(&self, mode: SecurityMode) -> bool {
        self.modes & mode.bit() != 0
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WifiError> {
        if self.ssid.len() > SSID_MAX_LEN {
            return Err(WifiError::NotWellFormed);
        }
        let len = 11 + self.ssid.len();
        if out.len() < len {
            return Err(WifiError::BufferTooSmall);
        }
        out[0..2].copy_from_slice(&self.modes.to_le_bytes());
        out[2..4].copy_from_slice(&self.frequency_mhz.to_le_bytes());
        out[4] = self.rssi_dbm as u8;
        out[5..11].copy_from_slice(&self.bssid);
        out[11..len].copy_from_slice(self.ssid);
        Ok(len)
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, WifiError> {
        if bytes.len() < 11 {
            return Err(WifiError::Truncated);
        }
        let ssid = &bytes[11..];
        if ssid.len() > SSID_MAX_LEN {
            return Err(WifiError::Malformed);
        }
        let mut bssid = [0u8; MAC_LEN];
        bssid.copy_from_slice(&bytes[5..11]);
        Ok(Self {
            modes: le16(bytes, 0).ok_or(WifiError::Truncated)?,
            frequency_mhz: le16(bytes, 2).ok_or(WifiError::Truncated)?,
            rssi_dbm: bytes[4] as i8,
            bssid,
            ssid,
        })
    }
}

/// `PROP_WIFI_LINK` states.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LinkState {
    /// `WIFI_LINK_DOWN`: not trying. The station is off, or nothing is
    /// selected.
    #[default]
    Down = 0,
    /// `WIFI_LINK_CONNECTING`: the whole of trying, including the waits
    /// between attempts.
    Connecting = 1,
    /// `WIFI_LINK_UP`: authenticated and associated.
    Up = 2,
}

impl LinkState {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Down),
            1 => Some(Self::Connecting),
            2 => Some(Self::Up),
            _ => None,
        }
    }
}

/// Why the station is [`LinkState::Connecting`] rather than up.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LinkReason {
    /// `WIFI_REASON_NONE`: no attempt has failed yet. Also the value in
    /// the other two states.
    #[default]
    None = 0,
    /// `WIFI_REASON_NOT_FOUND`: not heard, and no answer to a probe.
    NotFound = 1,
    /// `WIFI_REASON_AUTH`: the network rejected the credential.
    Auth = 2,
    /// `WIFI_REASON_REJECTED`: the association was refused for another
    /// reason.
    Rejected = 3,
    /// `WIFI_REASON_LOST`: the association was up and dropped.
    Lost = 4,
    /// `WIFI_REASON_OTHER`: something the device has no name for.
    Other = 5,
}

impl LinkReason {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::NotFound),
            2 => Some(Self::Auth),
            3 => Some(Self::Rejected),
            4 => Some(Self::Lost),
            5 => Some(Self::Other),
            _ => None,
        }
    }
}

/// Which access point the station is on, present only while up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Association {
    pub bssid: [u8; MAC_LEN],
    /// Center frequency of the access point's primary channel.
    pub frequency_mhz: u16,
}

/// `PROP_WIFI_LINK`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub state: LinkState,
    pub reason: LinkReason,
    /// `Some` exactly when `state` is [`LinkState::Up`].
    pub association: Option<Association>,
}

impl Link {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WifiError> {
        let len = if self.association.is_some() { 10 } else { 2 };
        if out.len() < len {
            return Err(WifiError::BufferTooSmall);
        }
        out[0] = self.state.code();
        out[1] = self.reason.code();
        if let Some(association) = self.association {
            out[2..8].copy_from_slice(&association.bssid);
            out[8..10].copy_from_slice(&association.frequency_mhz.to_le_bytes());
        }
        Ok(len)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WifiError> {
        if bytes.len() < 2 {
            return Err(WifiError::Truncated);
        }
        let state = LinkState::from_code(bytes[0]).ok_or(WifiError::Malformed)?;
        let reason = LinkReason::from_code(bytes[1]).ok_or(WifiError::Malformed)?;
        let association = if matches!(state, LinkState::Up) {
            if bytes.len() < 10 {
                return Err(WifiError::Truncated);
            }
            let mut bssid = [0u8; MAC_LEN];
            bssid.copy_from_slice(&bytes[2..8]);
            Some(Association {
                bssid,
                frequency_mhz: le16(bytes, 8).ok_or(WifiError::Truncated)?,
            })
        } else {
            None
        };
        Ok(Self {
            state,
            reason,
            association,
        })
    }
}

/// `PROP_WIFI_AP_STATE` states.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ApState {
    /// `WIFI_AP_DOWN`: disabled, unconfigured, or refused the radio.
    #[default]
    Down = 0,
    /// `WIFI_AP_UP`: beaconing and accepting stations.
    Up = 1,
}

impl ApState {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Down),
            1 => Some(Self::Up),
            _ => None,
        }
    }
}

/// `PROP_WIFI_AP_STATE`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApStatus {
    pub state: ApState,
    /// Where the access point is actually beaconing, present exactly
    /// when it is up. Not necessarily the configured frequency: where
    /// one radio serves both, the access point follows the station.
    pub frequency_mhz: Option<u16>,
}

impl ApStatus {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WifiError> {
        let len = if self.frequency_mhz.is_some() { 3 } else { 1 };
        if out.len() < len {
            return Err(WifiError::BufferTooSmall);
        }
        out[0] = self.state.code();
        if let Some(frequency) = self.frequency_mhz {
            out[1..3].copy_from_slice(&frequency.to_le_bytes());
        }
        Ok(len)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WifiError> {
        let state = ApState::from_code(*bytes.first().ok_or(WifiError::Truncated)?)
            .ok_or(WifiError::Malformed)?;
        let frequency_mhz = if matches!(state, ApState::Up) {
            Some(le16(bytes, 1).ok_or(WifiError::Truncated)?)
        } else {
            None
        };
        Ok(Self {
            state,
            frequency_mhz,
        })
    }
}

/// `PROP_WIFI_AP_CONFIG`: the network the device offers.
///
/// **Secret-bearing**, like [`NetworkEntry`]: the reported form stops at
/// the SSID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApConfig<'a> {
    /// Beacon without the name. A courtesy to neighbors' pickers, not a
    /// secret: the name is in every association.
    pub hidden: bool,
    pub security: SecurityMode,
    /// Stations admitted at once, or 0 for the device's own limit. A
    /// device clamps a larger value to what it can hold rather than
    /// refusing it.
    pub max_clients: u8,
    /// Preferred primary channel frequency, or 0 for the device's
    /// choice. A preference, not a promise.
    pub frequency_mhz: u16,
    /// The device's own address on the offered subnet, or all-zero with
    /// `prefix` 0 for the device's default.
    pub address: [u8; 4],
    /// Prefix of the offered subnet, 8 to 30, or 0 with an all-zero
    /// address.
    pub prefix: u8,
    pub ssid: &'a [u8],
    pub credential: &'a [u8],
}

impl<'a> ApConfig<'a> {
    /// The default subnet a device offers when `address` is all-zero:
    /// what a phone joining an embedded device has come to expect.
    pub const DEFAULT_ADDRESS: [u8; 4] = [192, 168, 4, 1];
    /// Prefix that goes with [`Self::DEFAULT_ADDRESS`].
    pub const DEFAULT_PREFIX: u8 = 24;

    pub const fn flags(&self) -> u8 {
        if self.hidden { FLAG_HIDDEN } else { 0 }
    }

    /// Whether the device's own address and prefix were left to it.
    pub fn uses_default_subnet(&self) -> bool {
        self.address == [0; 4] && self.prefix == 0
    }

    /// Whether this configuration is one a device may be asked to
    /// offer. Excludes the modes an access point may not offer, and the
    /// subnets that are not usable to hand addresses out on.
    ///
    /// Whether the frequency is one the device may transmit on is a
    /// regulatory question this cannot answer, and belongs to the
    /// device.
    pub fn validate(&self) -> Result<(), WifiError> {
        if self.ssid.is_empty() || self.ssid.len() > SSID_MAX_LEN {
            return Err(WifiError::NotWellFormed);
        }
        if !self.security.may_be_offered() {
            return Err(WifiError::NotWellFormed);
        }
        // An access point holds the key it hands out, so a raw key is
        // not a form it accepts.
        if !credential_is_well_formed(self.security, false, self.credential) {
            return Err(WifiError::NotWellFormed);
        }
        if !self.uses_default_subnet() {
            if !(8..=30).contains(&self.prefix) {
                return Err(WifiError::NotWellFormed);
            }
            if !crate::ip::ipv4_is_usable_host(&self.address) {
                return Err(WifiError::NotWellFormed);
            }
        }
        Ok(())
    }

    fn encode_inner(&self, out: &mut [u8], with_credential: bool) -> Result<usize, WifiError> {
        let credential: &[u8] = if with_credential {
            self.credential
        } else {
            &[]
        };
        if self.ssid.len() > SSID_MAX_LEN {
            return Err(WifiError::NotWellFormed);
        }
        let len = 11 + self.ssid.len() + credential.len();
        if out.len() < len {
            return Err(WifiError::BufferTooSmall);
        }
        out[0] = self.flags();
        out[1] = self.security.code();
        out[2] = self.max_clients;
        out[3..5].copy_from_slice(&self.frequency_mhz.to_le_bytes());
        out[5..9].copy_from_slice(&self.address);
        out[9] = self.prefix;
        out[10] = self.ssid.len() as u8;
        out[11..11 + self.ssid.len()].copy_from_slice(self.ssid);
        out[11 + self.ssid.len()..len].copy_from_slice(credential);
        Ok(len)
    }

    /// Encode the value, credential included.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WifiError> {
        self.encode_inner(out, true)
    }

    /// Encode the reported form: the value through its SSID.
    pub fn encode_reported(&self, out: &mut [u8]) -> Result<usize, WifiError> {
        self.encode_inner(out, false)
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, WifiError> {
        if bytes.len() < 11 {
            return Err(WifiError::Truncated);
        }
        let flags = bytes[0];
        if flags & !FLAG_HIDDEN != 0 {
            return Err(WifiError::Malformed);
        }
        let security = SecurityMode::from_code(bytes[1]).ok_or(WifiError::Malformed)?;
        let ssid_len = bytes[10] as usize;
        if ssid_len > SSID_MAX_LEN {
            return Err(WifiError::Malformed);
        }
        if bytes.len() < 11 + ssid_len {
            return Err(WifiError::Truncated);
        }
        let mut address = [0u8; 4];
        address.copy_from_slice(&bytes[5..9]);
        Ok(Self {
            hidden: flags & FLAG_HIDDEN != 0,
            security,
            max_clients: bytes[2],
            frequency_mhz: le16(bytes, 3).ok_or(WifiError::Truncated)?,
            address,
            prefix: bytes[9],
            ssid: &bytes[11..11 + ssid_len],
            credential: &bytes[11 + ssid_len..],
        })
    }
}

/// One entry of `PROP_WIFI_AP_CLIENTS`: a station on the device's
/// network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApClient {
    /// The key.
    pub mac: [u8; MAC_LEN],
    /// As the device last heard this client.
    pub rssi_dbm: i8,
    /// What the device's DHCP server leased it, all-zero until it has
    /// one.
    pub address: [u8; 4],
}

impl ApClient {
    /// Whether the client has taken a lease yet.
    pub fn has_address(&self) -> bool {
        self.address != [0; 4]
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WifiError> {
        if out.len() < AP_CLIENT_LEN {
            return Err(WifiError::BufferTooSmall);
        }
        out[0..6].copy_from_slice(&self.mac);
        out[6] = self.rssi_dbm as u8;
        out[7..11].copy_from_slice(&self.address);
        Ok(AP_CLIENT_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WifiError> {
        if bytes.len() < AP_CLIENT_LEN {
            return Err(WifiError::Truncated);
        }
        let mut mac = [0u8; MAC_LEN];
        mac.copy_from_slice(&bytes[0..6]);
        let mut address = [0u8; 4];
        address.copy_from_slice(&bytes[7..11]);
        Ok(Self {
            mac,
            rssi_dbm: bytes[6] as i8,
            address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSID: &[u8] = b"umsh-test";

    #[test]
    fn minimum_security_is_a_credential_compatible_relation() {
        use SecurityMode::*;
        for minimum in [Open, Owe, Wpa, Wpa2, Wpa3] {
            for offered in [
                Open, Owe, Wpa, Wpa2, Wpa3, Wep, Wpa2Ent, Wpa3Ent, Wpa3Ent192,
            ] {
                let passphrase = matches!(
                    (minimum, offered),
                    (Open, Open | Owe)
                        | (Owe, Owe)
                        | (Wpa, Wpa | Wpa2 | Wpa3)
                        | (Wpa2, Wpa2 | Wpa3)
                        | (Wpa3, Wpa3)
                );
                assert_eq!(minimum.permits(offered, false), passphrase);
                let pmk = matches!((minimum, offered), (Wpa, Wpa | Wpa2) | (Wpa2, Wpa2));
                assert_eq!(minimum.permits(offered, true), pmk);
            }
        }
    }

    #[test]
    fn strongest_selection_supports_legacy_wpa_without_lowering_stronger_profiles() {
        use SecurityMode::*;
        let supported = Open.bit() | Wpa.bit() | Wpa2.bit() | Wpa3.bit();
        assert_eq!(
            Wpa.strongest_compatible(Wpa.bit(), supported, false),
            Some(Wpa)
        );
        assert_eq!(
            Wpa.strongest_compatible(supported, supported, false),
            Some(Wpa3)
        );
        assert_eq!(
            Wpa.strongest_compatible(supported, supported, true),
            Some(Wpa2)
        );
        assert_eq!(
            Wpa.strongest_compatible(Wpa.bit(), supported, true),
            Some(Wpa)
        );
        assert_eq!(Wpa2.strongest_compatible(Wpa.bit(), supported, false), None);
        assert_eq!(
            Wpa3.strongest_compatible(Wpa.bit() | Wpa2.bit(), supported, false),
            None
        );
        assert_eq!(
            Wpa2.strongest_compatible(Wpa3.bit(), supported, false),
            Some(Wpa3)
        );
        assert_eq!(Wpa2.strongest_compatible(Wpa3.bit(), supported, true), None);
    }

    #[test]
    fn security_codes_round_trip_strictly() {
        for code in 0..=8u8 {
            let mode = SecurityMode::from_code(code).expect("allocated");
            assert_eq!(mode.code(), code);
        }
        // 9 through 15 are reserved; SAE-PK is the likeliest occupant.
        assert_eq!(SecurityMode::from_code(9), None);
        assert_eq!(SecurityMode::from_code(15), None);
        assert_eq!(SecurityMode::from_code(16), None);
    }

    #[test]
    fn every_mode_fits_the_sixteen_bit_scan_set() {
        for code in 0..=8u8 {
            let mode = SecurityMode::from_code(code).expect("allocated");
            assert_ne!(mode.bit(), 0, "mode {code} has no bit in the set");
        }
    }

    #[test]
    fn only_four_modes_may_be_offered() {
        assert!(SecurityMode::Open.may_be_offered());
        assert!(SecurityMode::Owe.may_be_offered());
        assert!(SecurityMode::Wpa2.may_be_offered());
        assert!(SecurityMode::Wpa3.may_be_offered());
        // Joinable but not offerable: no credential form for offering
        // TKIP, and the rest have no credential form at all.
        assert!(!SecurityMode::Wpa.may_be_offered());
        assert!(!SecurityMode::Wep.may_be_offered());
        assert!(!SecurityMode::Wpa2Ent.may_be_offered());
    }

    #[test]
    fn a_network_entry_round_trips_with_its_passphrase() {
        let entry = NetworkEntry {
            hidden: true,
            raw_key: false,
            security: SecurityMode::Wpa2,
            ssid: SSID,
            credential: b"correct horse",
        };
        entry.validate().expect("well formed");
        let mut buf = [0u8; NETWORK_ENTRY_MAX_LEN];
        let len = entry.encode(&mut buf).expect("encodes");
        assert_eq!(len, 3 + SSID.len() + 13);
        assert_eq!(buf[0], FLAG_HIDDEN);
        assert_eq!(buf[1], SecurityMode::Wpa2.code());
        assert_eq!(buf[2], SSID.len() as u8);
        assert_eq!(NetworkEntry::decode(&buf[..len]), Ok(entry));
    }

    #[test]
    fn the_reported_form_carries_no_credential() {
        let entry = NetworkEntry {
            hidden: false,
            raw_key: false,
            security: SecurityMode::Wpa3,
            ssid: SSID,
            credential: b"a password nobody should read back",
        };
        let mut buf = [0u8; NETWORK_ENTRY_MAX_LEN];
        let len = entry.encode_reported(&mut buf).expect("encodes");
        assert_eq!(len, 3 + SSID.len());
        let decoded = NetworkEntry::decode(&buf[..len]).expect("decodes");
        assert!(decoded.credential.is_empty());
        assert_eq!(decoded.ssid, SSID);
        assert_eq!(decoded.security, SecurityMode::Wpa3);
        // The secret is nowhere in the octets, not merely unparsed.
        assert!(!buf[..len].windows(8).any(|w| w == b"a passwo"));
    }

    #[test]
    fn credential_bounds_follow_the_mode() {
        let entry = |security, raw_key, credential| NetworkEntry {
            hidden: false,
            raw_key,
            security,
            ssid: SSID,
            credential,
        };
        // WPA2 takes 8 to 63 octets, per 802.11 Annex J.
        assert!(
            entry(SecurityMode::Wpa2, false, b"1234567")
                .validate()
                .is_err()
        );
        assert!(
            entry(SecurityMode::Wpa2, false, b"12345678")
                .validate()
                .is_ok()
        );
        assert!(
            entry(SecurityMode::Wpa2, false, &[b'x'; 63])
                .validate()
                .is_ok()
        );
        assert!(
            entry(SecurityMode::Wpa2, false, &[b'x'; 64])
                .validate()
                .is_err()
        );
        // SAE puts no bound on its password, so the 8 to 63 rule does
        // not apply and one octet is legal.
        assert!(entry(SecurityMode::Wpa3, false, b"x").validate().is_ok());
        assert!(
            entry(SecurityMode::Wpa3, false, &[b'x'; 128])
                .validate()
                .is_ok()
        );
        assert!(
            entry(SecurityMode::Wpa3, false, &[b'x'; 129])
                .validate()
                .is_err()
        );
        // Open and OWE carry no credential at all.
        assert!(entry(SecurityMode::Open, false, b"").validate().is_ok());
        assert!(
            entry(SecurityMode::Open, false, b"anything")
                .validate()
                .is_err()
        );
        assert!(entry(SecurityMode::Owe, false, b"").validate().is_ok());
        // The four reportable modes cannot be joined.
        for mode in [
            SecurityMode::Wep,
            SecurityMode::Wpa2Ent,
            SecurityMode::Wpa3Ent,
            SecurityMode::Wpa3Ent192,
        ] {
            assert!(entry(mode, false, b"").validate().is_err());
            assert!(entry(mode, false, b"secret12").validate().is_err());
        }
    }

    #[test]
    fn a_raw_key_stands_in_only_where_a_passphrase_is_derived() {
        let entry = |security, credential| NetworkEntry {
            hidden: false,
            raw_key: true,
            security,
            ssid: SSID,
            credential,
        };
        assert!(
            entry(SecurityMode::Wpa2, &[0xAB; PMK_LEN])
                .validate()
                .is_ok()
        );
        assert!(
            entry(SecurityMode::Wpa, &[0xAB; PMK_LEN])
                .validate()
                .is_ok()
        );
        assert!(entry(SecurityMode::Wpa2, &[0xAB; 31]).validate().is_err());
        // SAE derives its key through the exchange, not from the
        // password, so a stored key is not a substitute.
        assert!(
            entry(SecurityMode::Wpa3, &[0xAB; PMK_LEN])
                .validate()
                .is_err()
        );
        assert!(
            entry(SecurityMode::Open, &[0xAB; PMK_LEN])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn a_passphrase_is_utf8_without_a_terminator() {
        let entry = |credential| NetworkEntry {
            hidden: false,
            raw_key: false,
            security: SecurityMode::Wpa2,
            ssid: SSID,
            credential,
        };
        assert!(entry("passwörter".as_bytes()).validate().is_ok());
        assert!(entry(b"with\0a\0nul").validate().is_err());
        assert!(
            entry(&[0xFF, 0xFE, b'a', b'b', b'c', b'd', b'e', b'f'])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn an_empty_ssid_is_never_storable() {
        let entry = NetworkEntry {
            hidden: false,
            raw_key: false,
            security: SecurityMode::Open,
            ssid: b"",
            credential: b"",
        };
        assert_eq!(entry.validate(), Err(WifiError::NotWellFormed));
        let long = NetworkEntry {
            ssid: &[b'x'; 33],
            ..entry
        };
        assert_eq!(long.validate(), Err(WifiError::NotWellFormed));
    }

    #[test]
    fn a_reserved_flag_bit_is_malformed() {
        let mut buf = [0u8; 8];
        buf[0] = 1 << 2;
        buf[1] = SecurityMode::Open.code();
        buf[2] = 1;
        buf[3] = b'x';
        assert_eq!(NetworkEntry::decode(&buf[..4]), Err(WifiError::Malformed));
    }

    #[test]
    fn a_truncated_entry_is_not_a_malformed_one() {
        assert_eq!(NetworkEntry::decode(&[]), Err(WifiError::Truncated));
        assert_eq!(NetworkEntry::decode(&[0, 0]), Err(WifiError::Truncated));
        // Declares a 9-octet SSID and carries four.
        assert_eq!(
            NetworkEntry::decode(&[0, 0, 9, b'a', b'b', b'c', b'd']),
            Err(WifiError::Truncated)
        );
    }

    #[test]
    fn a_scan_result_round_trips() {
        let result = ScanResult {
            modes: SecurityMode::Wpa2.bit() | SecurityMode::Wpa3.bit(),
            frequency_mhz: 2437,
            rssi_dbm: -67,
            bssid: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
            ssid: SSID,
        };
        let mut buf = [0u8; SCAN_RESULT_MAX_LEN];
        let len = result.encode(&mut buf).expect("encodes");
        assert_eq!(len, 11 + SSID.len());
        assert_eq!(ScanResult::decode(&buf[..len]), Ok(result));
        // A transition network offers both, and the host picks.
        assert!(result.offers(SecurityMode::Wpa2));
        assert!(result.offers(SecurityMode::Wpa3));
        assert!(!result.offers(SecurityMode::Open));
        assert!(result.modes_known());
    }

    #[test]
    fn a_nameless_result_is_still_an_access_point() {
        let result = ScanResult {
            modes: 0,
            frequency_mhz: 5180,
            rssi_dbm: -80,
            bssid: [1, 2, 3, 4, 5, 6],
            ssid: b"",
        };
        let mut buf = [0u8; SCAN_RESULT_MAX_LEN];
        let len = result.encode(&mut buf).expect("encodes");
        assert_eq!(len, 11);
        let decoded = ScanResult::decode(&buf[..len]).expect("decodes");
        assert_eq!(decoded, result);
        // No bits set means the device did not determine the modes,
        // which is not the same as an access point offering nothing.
        assert!(!decoded.modes_known());
    }

    #[test]
    fn a_link_carries_its_association_only_when_up() {
        let down = Link {
            state: LinkState::Connecting,
            reason: LinkReason::Auth,
            association: None,
        };
        let mut buf = [0u8; LINK_MAX_LEN];
        let len = down.encode(&mut buf).expect("encodes");
        assert_eq!(len, 2);
        assert_eq!(Link::decode(&buf[..len]), Ok(down));

        let up = Link {
            state: LinkState::Up,
            reason: LinkReason::None,
            association: Some(Association {
                bssid: [0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
                frequency_mhz: 5745,
            }),
        };
        let len = up.encode(&mut buf).expect("encodes");
        assert_eq!(len, 10);
        assert_eq!(Link::decode(&buf[..len]), Ok(up));
    }

    #[test]
    fn an_up_link_without_an_association_is_truncated() {
        assert_eq!(
            Link::decode(&[LinkState::Up.code(), 0]),
            Err(WifiError::Truncated)
        );
        assert_eq!(Link::decode(&[9, 0]), Err(WifiError::Malformed));
        assert_eq!(Link::decode(&[0, 9]), Err(WifiError::Malformed));
    }

    #[test]
    fn the_access_point_state_reports_where_it_landed() {
        let mut buf = [0u8; 3];
        let down = ApStatus {
            state: ApState::Down,
            frequency_mhz: None,
        };
        assert_eq!(down.encode(&mut buf), Ok(1));
        assert_eq!(ApStatus::decode(&buf[..1]), Ok(down));

        let up = ApStatus {
            state: ApState::Up,
            frequency_mhz: Some(2412),
        };
        assert_eq!(up.encode(&mut buf), Ok(3));
        assert_eq!(ApStatus::decode(&buf[..3]), Ok(up));
    }

    #[test]
    fn an_access_point_config_round_trips_and_redacts() {
        let config = ApConfig {
            hidden: false,
            security: SecurityMode::Wpa2,
            max_clients: 4,
            frequency_mhz: 2437,
            address: [192, 168, 4, 1],
            prefix: 24,
            ssid: SSID,
            credential: b"sharedsecret",
        };
        config.validate().expect("well formed");
        let mut buf = [0u8; AP_CONFIG_MAX_LEN];
        let len = config.encode(&mut buf).expect("encodes");
        assert_eq!(ApConfig::decode(&buf[..len]), Ok(config));

        let len = config.encode_reported(&mut buf).expect("encodes");
        let reported = ApConfig::decode(&buf[..len]).expect("decodes");
        assert!(reported.credential.is_empty());
        assert_eq!(reported.ssid, SSID);
        assert_eq!(reported.address, [192, 168, 4, 1]);
    }

    #[test]
    fn an_access_point_refuses_what_it_cannot_offer() {
        let base = ApConfig {
            hidden: false,
            security: SecurityMode::Wpa2,
            max_clients: 0,
            frequency_mhz: 0,
            address: [0; 4],
            prefix: 0,
            ssid: SSID,
            credential: b"sharedsecret",
        };
        // The default subnet is the all-zero address with prefix 0.
        assert!(base.validate().is_ok());
        assert!(base.uses_default_subnet());
        // TKIP and the reportable-only modes are not offerable.
        assert!(
            ApConfig {
                security: SecurityMode::Wpa,
                ..base
            }
            .validate()
            .is_err()
        );
        // A subnet the device cannot hand addresses out on.
        assert!(
            ApConfig {
                address: [169, 254, 1, 1],
                prefix: 24,
                ..base
            }
            .validate()
            .is_err()
        );
        assert!(
            ApConfig {
                address: [192, 168, 4, 1],
                prefix: 31,
                ..base
            }
            .validate()
            .is_err()
        );
        assert!(
            ApConfig {
                address: [192, 168, 4, 1],
                prefix: 24,
                ..base
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn an_access_point_client_round_trips() {
        let client = ApClient {
            mac: [2, 4, 6, 8, 10, 12],
            rssi_dbm: -45,
            address: [192, 168, 4, 37],
        };
        let mut buf = [0u8; AP_CLIENT_LEN];
        assert_eq!(client.encode(&mut buf), Ok(AP_CLIENT_LEN));
        assert_eq!(ApClient::decode(&buf), Ok(client));
        assert!(client.has_address());

        let unleased = ApClient {
            address: [0; 4],
            ..client
        };
        assert!(!unleased.has_address());
    }

    #[test]
    fn encoders_report_a_buffer_too_small_rather_than_truncating() {
        let entry = NetworkEntry {
            hidden: false,
            raw_key: false,
            security: SecurityMode::Open,
            ssid: SSID,
            credential: b"",
        };
        let mut small = [0u8; 4];
        assert_eq!(entry.encode(&mut small), Err(WifiError::BufferTooSmall));
        let mut client = [0u8; 10];
        assert_eq!(
            ApClient {
                mac: [0; 6],
                rssi_dbm: 0,
                address: [0; 4]
            }
            .encode(&mut client),
            Err(WifiError::BufferTooSmall)
        );
    }

    #[test]
    fn a_decoder_tolerates_octets_a_later_revision_appends() {
        // A scan result's SSID is the remainder, so it cannot grow; the
        // link and the client can, and a receiver keeps what it knows.
        let mut buf = [0u8; 16];
        buf[0] = LinkState::Up.code();
        buf[10] = 0xFF;
        buf[11] = 0xFF;
        let decoded = Link::decode(&buf[..12]).expect("decodes");
        assert_eq!(decoded.state, LinkState::Up);
        assert!(decoded.association.is_some());
    }
}
