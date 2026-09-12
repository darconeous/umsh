//! Configure the device's own bridge client, using its existing identity.
use super::{persist, values::KeyArg};
use crate::{App, output::subfield};
use anyhow::{Result, bail};
use umsh::ulcp_wire::{
    bridge::{DEFAULT_PORT, Link, valid_host},
    ids::prop,
};

#[derive(Debug, clap::Subcommand)]
pub enum BridgeOp {
    Show,
    On,
    Off,
    Configure {
        host: String,
        /// Bridge TCP port (the global --port selects the serial device).
        #[arg(long = "server-port", default_value_t = DEFAULT_PORT, value_parser = clap::value_parser!(u16).range(1..))]
        bridge_port: u16,
        #[arg(long)]
        server_key: KeyArg,
    },
}

pub async fn run(app: &mut App, op: Option<BridgeOp>) -> Result<()> {
    let no_save = app.no_save;
    let device = app.device()?;
    let enabled = device.get_prop(prop::BRIDGE_ENABLED).await?;
    match op.unwrap_or(BridgeOp::Show) {
        BridgeOp::Show => {
            subfield(
                "bridge",
                if enabled == [1] {
                    "enabled"
                } else {
                    "disabled"
                },
            );
            let host = device.get_prop(prop::BRIDGE_HOST).await?;
            subfield(
                "host",
                String::from_utf8_lossy(host.strip_suffix(&[0]).unwrap_or(&host)),
            );
            let port = device.get_prop(prop::BRIDGE_PORT).await?;
            if let Ok(port) = <[u8; 2]>::try_from(port.as_slice()) {
                subfield("port", u16::from_le_bytes(port).to_string());
            }
            for (name, key) in [
                ("server identity", prop::BRIDGE_SERVER_KEY),
                ("device identity", prop::DEV_KEY),
            ] {
                let bytes = device.get_prop(key).await?;
                subfield(
                    name,
                    match <[u8; 32]>::try_from(bytes.as_slice()) {
                        Ok(bytes) => umsh::core::PublicKey(bytes).to_string(),
                        Err(_) => "unset".into(),
                    },
                );
            }
            if let Some(link) = Link::decode(&device.get_prop(prop::BRIDGE_LINK).await?) {
                subfield(
                    "connection",
                    format!("{:?} ({:?})", link.state, link.reason),
                );
            }
            let repeater = device.get_prop(prop::MAC_REPEATER_ENABLED).await?;
            subfield("node", if repeater == [1] { "repeater" } else { "leaf" });
            return Ok(());
        }
        BridgeOp::On => {
            device.set_prop(prop::BRIDGE_ENABLED, &[1]).await?;
        }
        BridgeOp::Off => {
            device.set_prop(prop::BRIDGE_ENABLED, &[0]).await?;
        }
        BridgeOp::Configure {
            host,
            bridge_port,
            server_key,
        } => {
            if host.is_empty() || !valid_host(&host) {
                bail!("host must be a DNS hostname or IP literal without scheme or port");
            }
            let mut bytes = host.into_bytes();
            bytes.push(0);
            device.set_prop(prop::BRIDGE_HOST, &bytes).await?;
            device
                .set_prop(prop::BRIDGE_PORT, &bridge_port.to_le_bytes())
                .await?;
            device
                .set_prop(prop::BRIDGE_SERVER_KEY, &server_key.0)
                .await?;
        }
    }
    persist(device, no_save).await
}
