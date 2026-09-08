//! `dev-channel` / `dev-peer` / `dev-admin`: the device identity's own
//! key tables.
//!
//! What a device reports differs by table (a channel identifier versus
//! the 32-byte peer key itself), so listings and mutation reports print
//! whatever the device quotes—a channel identifier as hex, a key as
//! the base58 address it is everywhere else.

use anyhow::{Result, bail};

use umsh::ulcp_wire::ids::prop;
use umsh::ulcp_wire::items;

use super::persist;
use super::values::KeyArg;
use crate::App;
use crate::output::{address, hex};

#[derive(Debug, clap::Subcommand)]
pub enum TableOp {
    /// List the entries the device holds, as it reports them.
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

/// How what the device reports for `prop` reads back to the user. The
/// channel table reports a channel identifier, which has no address form;
/// every other table reports the public key itself.
fn item_text(prop: u32, item: &[u8]) -> String {
    if prop == prop::DEV_CHANNEL_KEYS {
        hex(item)
    } else {
        address(item)
    }
}

pub async fn run(app: &mut App, key: u32, noun: &str, op: Option<TableOp>) -> Result<()> {
    let no_save = app.no_save;
    let device = app.device()?;
    match op.unwrap_or(TableOp::List) {
        TableOp::List => {
            let value = device.get_prop(key).await?;
            let item_len = if key == prop::DEV_CHANNEL_KEYS {
                items::CHANNEL_IDENTIFIER_LEN
            } else {
                items::PUBLIC_KEY_LEN
            };
            if value.is_empty() {
                println!("no device {noun}s provisioned");
            } else if !value.len().is_multiple_of(item_len) {
                bail!("malformed device {noun} listing");
            } else {
                for item in value.chunks(item_len) {
                    println!("{}", item_text(key, item));
                }
            }
            Ok(())
        }
        TableOp::Add { key: item } => {
            let reported = device.insert_prop_item(key, &item.0).await?;
            println!("device {noun} added ({})", item_text(key, &reported));
            persist(device, no_save).await
        }
        TableOp::Remove { key: item } => {
            let reported = device.remove_prop_item(key, &item.0).await?;
            println!("device {noun} removed ({})", item_text(key, &reported));
            persist(device, no_save).await
        }
    }
}
