//! The u-blox UBX frames UMSH sends.
//!
//! Receivers are otherwise read as NMEA and never configured. These exist
//! for a board whose u-blox receiver has no enable or standby line, where
//! the receiver's own UART is the only way to lower its draw.

/// UBX-RXM-PMREQ: enter backup with no time limit, waking on activity at
/// the receiver's UART RX.
///
/// The receiver's RTC and backup RAM keep running, so the time it reports
/// on waking is still the time, and the fix that follows is a hot start.
/// The long form the M10 requires (version 0); `flags` sets `backup` and
/// `force`, and `wakeupSources` sets `uartrx`.
///
/// A receiver that does not speak UBX skips it as noise: an L76K's
/// binary protocol has another sync pair, and NMEA starts at `$`.
pub const BACKUP: [u8; 24] = with_checksum([
    0xB5, 0x62, // sync
    0x02, 0x41, // RXM-PMREQ
    0x10, 0x00, // payload length, little-endian
    0x00, // version
    0x00, 0x00, 0x00, // reserved
    0x00, 0x00, 0x00, 0x00, // duration: none
    0x06, 0x00, 0x00, 0x00, // flags: backup, force
    0x08, 0x00, 0x00, 0x00, // wakeupSources: uartrx
    0x00, 0x00, // checksum
]);

/// What wakes a receiver parked by [`BACKUP`]: any edge at its RX does,
/// and the byte that carries it is lost.
pub const WAKE: u8 = 0xFF;

/// Fill in the 8-bit Fletcher checksum over the class, id, length, and
/// payload, which is every byte but the sync pair and the checksum itself.
const fn with_checksum<const N: usize>(mut frame: [u8; N]) -> [u8; N] {
    let (mut a, mut b) = (0u8, 0u8);
    let mut i = 2;
    while i < N - 2 {
        a = a.wrapping_add(frame[i]);
        b = b.wrapping_add(a);
        i += 1;
    }
    frame[N - 2] = a;
    frame[N - 1] = b;
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_frame_checksum() {
        assert_eq!(BACKUP[22..], [0x61, 0x6B]);
    }

    #[test]
    fn backup_frame_length_matches_payload() {
        let payload = u16::from_le_bytes([BACKUP[4], BACKUP[5]]) as usize;
        assert_eq!(BACKUP.len(), 6 + payload + 2);
    }
}
