//! State lifecycle and one-off device settings: `save`, `restore`,
//! `clear`, `reset`, `factory-reset`, `pin`, `identity`, `name`, and
//! `alert`.

use anyhow::{Result, bail};

use umsh::core::PublicKey;
use umsh::ulcp::{FrameLink, UlcpDevice};
use umsh::ulcp_wire::alert::AlertState;
use umsh::ulcp_wire::ids::prop;

use super::persist;
use super::values::PinArg;
use crate::App;
use crate::connection::confirm;
use crate::output::field;

#[derive(Debug, clap::Subcommand)]
pub enum IdentityOp {
    /// Print the device identity public key.
    Show,
    /// Generate a device identity if none exists.
    Generate,
}

#[derive(Debug, clap::Subcommand)]
pub enum AlertOp {
    /// Print the locate-alert state.
    Show,
    /// Make the radio conspicuous so it can be found.
    #[command(alias = "on", alias = "find")]
    Locate,
    /// Stop the locate alert.
    #[command(name = "none", alias = "off", alias = "stop")]
    None,
}

pub async fn save<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<()> {
    device.save().await?;
    println!("saved: live state persists across reboots");
    Ok(())
}

pub async fn restore<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<()> {
    let completion = device.restore().await?;
    println!("restored live state from the saved snapshot ({completion:?} form)");
    Ok(())
}

pub async fn clear<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<()> {
    device.clear().await?;
    println!(
        "cleared: persisted state erased; live state keeps running until reboot \
         (BLE bonds and pairing PIN are retained)"
    );
    Ok(())
}

pub async fn reset<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<()> {
    let status = device.reset().await?;
    println!("reset complete ({status:?})");
    Ok(())
}

/// Restart the device, keeping everything it has persisted.
///
/// No confirmation: unlike a factory reset this destroys nothing, and the
/// device comes back as itself. The handle is worthless afterward either
/// way, so detach for the same reason `factory_reset` does.
pub async fn reboot(app: &mut App) -> Result<()> {
    let device = app.device()?;
    if !device.reboot().await? {
        bail!("this device does not advertise CAP_REBOOT; it cannot restart on command");
    }
    println!("reboot sent; the radio is restarting and the link will drop");
    app.detach().await;
    Ok(())
}

const FACTORY_RESET_WARNING: &str = "factory-reset erases ALL mutable state — persisted provisioning, the device identity, \
     BLE bonds, and the pairing PIN — then reboots";

pub async fn factory_reset(app: &mut App, yes: bool) -> Result<()> {
    if !yes {
        if !app.interactive {
            bail!("{FACTORY_RESET_WARNING}; re-run with --yes to confirm");
        }
        println!("{FACTORY_RESET_WARNING}.");
        if !confirm("erase everything and reboot?")? {
            println!("cancelled");
            return Ok(());
        }
    }
    let device = app.device()?;
    device.factory_reset().await?;
    println!(
        "factory reset sent; the radio is erasing ALL state (provisioning, device identity, \
         BLE bonds, pairing PIN) and rebooting. The link will drop; re-pair to use it again."
    );
    // The device is rebooting, so the handle is worthless. Say so once
    // rather than letting the next command fail obscurely. Over the mesh
    // this also ends the session, which hands the borrowed radio back.
    app.detach().await;
    Ok(())
}

pub async fn pin<L: FrameLink>(device: &mut UlcpDevice<L>, value: PinArg) -> Result<()> {
    device.set_ble_pairing_pin(value.0).await?;
    match value.0 {
        Some(_) => println!("BLE pairing PIN set (persisted; applies to new pairings)"),
        None => println!("BLE pairing PIN cleared"),
    }
    Ok(())
}

pub async fn identity<L: FrameLink>(
    device: &mut UlcpDevice<L>,
    op: Option<IdentityOp>,
) -> Result<()> {
    match op.unwrap_or(IdentityOp::Show) {
        IdentityOp::Show => {
            let value = device.get_prop(prop::DEV_KEY).await?;
            match <[u8; 32]>::try_from(value.as_slice()) {
                Ok(key) => field("device identity", PublicKey(key)),
                Err(_) if value.is_empty() => {
                    println!("no device identity configured (run `identity generate`)");
                }
                Err(_) => bail!("malformed PROP_DEV_KEY"),
            }
            Ok(())
        }
        IdentityOp::Generate => {
            let value = device.get_prop(prop::DEV_KEY).await?;
            if let Ok(key) = <[u8; 32]>::try_from(value.as_slice()) {
                println!("device identity already exists: {}", PublicKey(key));
                println!("(identities are never regenerated in place; factory-reset discards one)");
                return Ok(());
            }
            let key = device.ensure_device_identity().await?;
            println!("generated device identity: {}", PublicKey(key));
            println!("(persisted immediately; device identities are independent of save/restore)");
            Ok(())
        }
    }
}

pub async fn name(app: &mut App, name: Option<String>) -> Result<()> {
    let no_save = app.no_save;
    let Some(name) = name else {
        let device = app.device()?;
        let current = device.device_name().await?;
        field("device name", format!("{current:?}"));
        return Ok(());
    };
    let device = app.device()?;
    device.set_device_name(&name).await?;
    println!("device name set to {name:?}");
    persist(device, no_save).await?;
    // The prompt follows the device, so it has to follow a rename.
    app.rename(name);
    Ok(())
}

/// Report or drive the locate alert (`PROP_ALERT`).
///
/// Deliberately outside the auto-save path: the alert is live behavior
/// that no snapshot carries, so there is nothing to persist.
pub async fn alert<L: FrameLink>(device: &mut UlcpDevice<L>, op: Option<AlertOp>) -> Result<()> {
    let desired = match op.unwrap_or(AlertOp::Show) {
        AlertOp::Show => {
            match device.alert().await? {
                Some(state) => field("alert", display(state)),
                None => field("alert", "unsupported (no CAP_ALERT)"),
            }
            return Ok(());
        }
        AlertOp::Locate => AlertState::Locate,
        AlertOp::None => AlertState::None,
    };
    match device.set_alert(desired).await? {
        AlertState::Locate => println!(
            "locate alert started. It stops when you send `alert none`, when someone \
             cancels it at the radio, or when the radio's own deadline expires — \
             re-send `alert locate` to keep it going."
        ),
        AlertState::None => println!("locate alert stopped"),
    }
    Ok(())
}

/// Human-readable rendering of a `PROP_ALERT` state.
fn display(state: AlertState) -> &'static str {
    match state {
        AlertState::None => "none",
        AlertState::Locate => "locate (the radio is making itself conspicuous)",
    }
}
