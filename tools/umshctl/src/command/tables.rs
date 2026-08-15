//! `dev-channel` / `dev-peer` / `dev-admin`: the device identity's own
//! key tables.
//!
//! The digest form differs by table (a 2-byte channel id versus the
//! 32-byte peer key itself), so listings and mutation reports print
//! whatever digest the device quotes.

use anyhow::{Result, bail};

use umsh::ulcp_wire::ids::prop;

use super::persist;
use super::values::KeyArg;
use crate::App;
use crate::output::hex;

#[derive(Debug, clap::Subcommand)]
pub enum TableOp {
    /// List the entries the device holds, in digest form.
    List,
    /// Add an entry.
    Add {
        #[arg(value_name = "KEY")]
        key: KeyArg,
    },
    /// Remove an entry.
    Remove {
        #[arg(value_name = "KEY")]
        key: KeyArg,
    },
}

pub async fn run(app: &mut App, key: u32, noun: &str, op: Option<TableOp>) -> Result<()> {
    let no_save = app.no_save;
    let device = app.device()?;
    match op.unwrap_or(TableOp::List) {
        TableOp::List => {
            let value = device.get_prop(key).await?;
            let digest_len = if key == prop::DEV_CHANNEL_KEYS { 2 } else { 32 };
            if value.is_empty() {
                println!("no device {noun}s provisioned");
            } else if !value.len().is_multiple_of(digest_len) {
                bail!("malformed device {noun} listing");
            } else {
                for digest in value.chunks(digest_len) {
                    println!("{}", hex(digest));
                }
            }
            Ok(())
        }
        TableOp::Add { key: item } => {
            let digest = device.insert_prop_item(key, &item.0).await?;
            println!("device {noun} added (digest {})", hex(&digest));
            persist(device, no_save).await
        }
        TableOp::Remove { key: item } => {
            let digest = device.remove_prop_item(key, &item.0).await?;
            println!("device {noun} removed (digest {})", hex(&digest));
            persist(device, no_save).await
        }
    }
}
