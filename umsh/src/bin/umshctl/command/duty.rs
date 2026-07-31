//! `duty`: report or bound the combined duty-cycle budget.
//!
//! The limit spans every radio client on the device — host transmits,
//! delegated acks, and the on-board node's own traffic all draw from one
//! ledger — and `PROP_PHY_DUTY_NOW` reports that combined figure.

use anyhow::{Result, anyhow};

use umsh::ulcp_wire::ids::prop;

use super::values::DutyLimitArg;
use super::{decode_u16, duty_percent, persist};
use crate::App;

#[derive(Debug, clap::Subcommand)]
pub enum DutyOp {
    /// Print current usage and the limit in force.
    Show,
    /// Set the limit on its raw 0-65535 scale (655 ≈ 1% of the hour),
    /// or `off` to stop enforcing one.
    Limit {
        #[arg(value_name = "N|off")]
        value: DutyLimitArg,
    },
}

pub async fn run(app: &mut App, op: Option<DutyOp>) -> Result<()> {
    let no_save = app.no_save;
    let device = app.device()?;
    match op.unwrap_or(DutyOp::Show) {
        DutyOp::Show => {
            let now = device.get_prop(prop::PHY_DUTY_NOW).await?;
            let now = decode_u16(&now).ok_or_else(|| anyhow!("malformed PHY_DUTY_NOW"))?;
            let limit = device.get_prop(prop::PHY_DUTY_LIMIT).await?;
            println!("duty now   {now} ({:.2}% of the hour)", duty_percent(now));
            print_limit(decode_u16(&limit).ok_or_else(|| anyhow!("malformed PHY_DUTY_LIMIT"))?);
            Ok(())
        }
        DutyOp::Limit { value } => {
            let echoed = device
                .set_prop(prop::PHY_DUTY_LIMIT, &value.0.to_le_bytes())
                .await?;
            print_limit(
                decode_u16(&echoed).ok_or_else(|| anyhow!("malformed PHY_DUTY_LIMIT echo"))?,
            );
            persist(device, no_save).await
        }
    }
}

fn print_limit(raw: u16) {
    match raw {
        u16::MAX => println!("duty limit off (enforcement disabled)"),
        raw => println!("duty limit {raw} ({:.2}% of the hour)", duty_percent(raw)),
    }
}
