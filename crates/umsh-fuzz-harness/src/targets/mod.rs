//! One module per fuzz target, each with `run(data: &[u8])`.
//!
//! A panic in `run` is a finding. An oracle beyond "it did not panic" is an
//! `assert!` in the target.

pub mod lan_bridge;
pub mod meshcore_forwarder;
pub mod node_mgmt_device;
pub mod node_mgmt_envelope;
pub mod node_mgmt_loop;
pub mod text_codec;
pub mod text_engine;
pub mod ulcp_admin_model;
pub mod ulcp_device;
pub mod ulcp_frame;
pub mod ulcp_gatt;
pub mod ulcp_hdlc;
pub mod ulcp_host_mobile;
pub mod ulcp_host_web;
pub mod ulcp_snapshot;
pub mod ulcp_values;
pub mod umsh_authenticated_payloads;
pub mod umsh_mac;
pub mod umsh_mac_loop;
pub mod umsh_mac_noninterference;
pub mod umsh_mac_raw;
pub mod umsh_options;
pub mod umsh_packet;
pub mod umsh_payloads;
pub mod uri_base58;

/// A target and its entry point.
pub struct Target {
    pub name: &'static str,
    pub run: fn(&[u8]),
}

macro_rules! targets {
    ($($name:ident),* $(,)?) => {
        /// Every target, for the replay test and the seed generator.
        pub const ALL: &[Target] = &[
            $(Target { name: stringify!($name), run: $name::run },)*
        ];
    };
}

targets![
    lan_bridge,
    meshcore_forwarder,
    node_mgmt_device,
    node_mgmt_envelope,
    node_mgmt_loop,
    text_codec,
    text_engine,
    ulcp_admin_model,
    ulcp_device,
    ulcp_frame,
    ulcp_gatt,
    ulcp_hdlc,
    ulcp_host_mobile,
    ulcp_host_web,
    ulcp_snapshot,
    ulcp_values,
    umsh_authenticated_payloads,
    umsh_mac,
    umsh_mac_loop,
    umsh_mac_noninterference,
    umsh_mac_raw,
    umsh_options,
    umsh_packet,
    umsh_payloads,
    uri_base58,
];
