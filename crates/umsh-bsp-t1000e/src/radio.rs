//! LR1110 radio wiring helpers for the T1000-E.

use lora_phy::lr1110::RfSwitchConfig;

/// T1000-E LR1110 RF-switch DIO table.
///
/// Sourced from MeshCore's `variants/t1000-e/target.cpp`:
///
/// | State  | DIOs                  | Mask |
/// |--------|-----------------------|------|
/// | STBY   | LOW LOW LOW LOW       | 0x00 |
/// | RX     | HIGH LOW LOW HIGH     | 0x09 |
/// | TX     | HIGH HIGH LOW HIGH    | 0x0B  (LP PA) |
/// | TX_HP  | LOW HIGH LOW HIGH     | 0x0A  (HP PA) |
/// | GNSS   | LOW LOW HIGH LOW      | 0x04 |
///
/// Pass this to the LR1110 configuration as
/// `rf_switch: Some(umsh_bsp_t1000e::RF_SWITCH)`.
pub const RF_SWITCH: RfSwitchConfig = RfSwitchConfig {
    standby: 0x00,
    rx: 0x09,
    tx: 0x0B,
    tx_hp: 0x0A,
    tx_hf: 0x00,
    gnss: 0x04,
    wifi: 0x00,
};
