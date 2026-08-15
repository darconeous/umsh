//! The command tree.
//!
//! One `clap` `Subcommand` enum serves four surfaces: the one-shot argv
//! grammar, the REPL line grammar, `--help` at every level, and the
//! completion tree the REPL's tab handler walks.

pub mod advert;
pub mod capture;
pub mod duty;
pub mod gnss;
pub mod info;
pub mod lifecycle;
pub mod phy;
pub mod provision;
pub mod repeater;
pub mod tables;
pub mod time;
pub mod values;

use anyhow::{Result, bail};

use umsh::ulcp::{FrameLink, UlcpDevice};
use umsh::ulcp_wire::ids::prop;

use crate::App;
use crate::connection::{self, Target};
use crate::output;
use values::PinArg;

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Print capabilities, ownership, PHY state, and provisioning
    /// digests. Changes nothing.
    Info(info::InfoArgs),

    /// Establish host provisioning: keys, filters, and the delegation
    /// policy for the host that will tether to this device.
    Provision(provision::ProvisionArgs),

    /// Show or generate the device identity public key.
    Identity {
        #[command(subcommand)]
        op: Option<lifecycle::IdentityOp>,
    },

    /// Show or set the human-readable device name.
    Name {
        #[arg(value_name = "NEW-NAME")]
        name: Option<String>,
    },

    /// Persist live state across reboots (CMD_SAVE).
    Save,

    /// Revert live state to the saved snapshot.
    Restore,

    /// Erase persisted state; live state keeps running.
    Clear,

    /// Protocol reset (CMD_RST): state returns to its post-reset values,
    /// restoring any saved snapshot. The MCU does not reboot.
    Reset,

    /// Erase ALL state including BLE bonds and the pairing PIN, then
    /// reboot into a blank factory state.
    FactoryReset {
        /// Confirm the wipe. Required outside the REPL, which asks.
        #[arg(long)]
        yes: bool,
    },

    /// Set or clear the persisted BLE pairing PIN.
    Pin {
        #[arg(value_name = "6-DIGITS|clear")]
        value: PinArg,
    },

    /// Show or set the PHY enable state and LoRa parameters.
    Phy {
        #[command(subcommand)]
        op: Option<phy::PhyOp>,
    },

    /// Show duty-cycle usage, or bound it.
    Duty {
        #[command(subcommand)]
        op: Option<duty::DutyOp>,
    },

    /// Show or set the autonomous repeater forwarding policy.
    Repeater {
        #[command(subcommand)]
        op: Option<repeater::RepeaterOp>,
    },

    /// Show or set the device's wall clock and time zone.
    Time {
        #[command(subcommand)]
        op: Option<time::TimeOp>,
    },

    /// Show or set the GNSS receiver and what is done with its fixes.
    Gnss {
        #[command(subcommand)]
        op: Option<gnss::GnssOp>,
    },

    /// Show or set what the device announces on its own schedule.
    Advert {
        #[command(subcommand)]
        op: Option<advert::AdvertOp>,
    },

    /// Device-identity channel keys: the multicast this device's own
    /// node joins.
    DevChannel {
        #[command(subcommand)]
        op: Option<tables::TableOp>,
    },

    /// Device-identity peer public keys.
    DevPeer {
        #[command(subcommand)]
        op: Option<tables::TableOp>,
    },

    /// Read several properties in one exchange.
    Props {
        /// Property identifiers, decimal or `0x`-prefixed.
        #[arg(value_name = "PROP", required = true, value_parser = values::parse_u32)]
        keys: Vec<u32>,
    },

    /// Take one ambient light reading.
    Illuminance,

    /// Show or drive the locate alert: make the radio conspicuous so it
    /// can be found.
    Alert {
        #[command(subcommand)]
        op: Option<lifecycle::AlertOp>,
    },

    /// Listen on the device's radio, decoding frames and optionally
    /// writing a Wireshark-compatible capture.
    Capture(capture::CaptureArgs),

    /// List nearby ULCP radios without connecting.
    Scan {
        /// Seconds to listen.
        #[arg(long, default_value_t = 2, value_name = "SECS")]
        timeout: u64,
    },

    /// Show, set, or clear the radio this tool reaches for when the
    /// command line names none.
    Default {
        #[command(subcommand)]
        op: Option<DefaultOp>,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum DefaultOp {
    /// Print the saved default radio.
    Show,
    /// Save a default radio. With no selector, saves the attached one.
    Set {
        #[arg(value_name = "SELECTOR")]
        selector: Option<String>,
    },
    /// Forget the saved default radio.
    Clear,
}

impl Command {
    /// Whether this command needs an attached device.
    pub fn needs_device(&self) -> bool {
        match self {
            Self::Scan { .. } => false,
            // Saving the attached radio as the default needs one; naming
            // a selector outright does not.
            Self::Default { op } => matches!(op, Some(DefaultOp::Set { selector: None })),
            _ => true,
        }
    }

    /// Whether this command needs a tethered attach rather than the
    /// administrative one everything else uses.
    pub fn needs_tethered(&self) -> bool {
        matches!(self, Self::Provision(_))
    }

    /// Check whatever clap's grammar cannot — combinations of flags,
    /// and the provisioning file — *before* a device is opened.
    ///
    /// Connecting takes seconds over BLE and disturbs a radio that was
    /// minding its own business; an argument mistake should cost
    /// neither.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Capture(args) => args.validate(),
            Self::Provision(args) => args.desired().map(drop),
            _ => Ok(()),
        }
    }

    pub async fn run(self, app: &mut App) -> Result<()> {
        match self {
            Self::Info(args) => info::run(app.device()?, args).await,
            Self::Provision(args) => provision::run(app, args).await,
            Self::Identity { op } => lifecycle::identity(app.device()?, op).await,
            Self::Name { name } => lifecycle::name(app, name).await,
            Self::Save => lifecycle::save(app.device()?).await,
            Self::Restore => lifecycle::restore(app.device()?).await,
            Self::Clear => lifecycle::clear(app.device()?).await,
            Self::Reset => lifecycle::reset(app.device()?).await,
            Self::FactoryReset { yes } => lifecycle::factory_reset(app, yes).await,
            Self::Pin { value } => lifecycle::pin(app.device()?, value).await,
            Self::Phy { op } => phy::run(app, op).await,
            Self::Duty { op } => duty::run(app, op).await,
            Self::Repeater { op } => repeater::run(app, op).await,
            Self::Time { op } => time::run(app, op).await,
            Self::Gnss { op } => gnss::run(app, op).await,
            Self::Advert { op } => advert::run(app, op).await,
            Self::DevChannel { op } => {
                tables::run(app, prop::DEV_CHANNEL_KEYS, "channel", op).await
            }
            Self::DevPeer { op } => tables::run(app, prop::DEV_PEERS, "peer", op).await,
            Self::Props { keys } => info::props(app.device()?, &keys).await,
            Self::Illuminance => info::illuminance(app.device()?).await,
            Self::Alert { op } => lifecycle::alert(app.device()?, op).await,
            Self::Capture(args) => capture::run(app, args).await,
            Self::Scan { timeout } => scan(app, timeout).await,
            Self::Default { op } => default(app, op.unwrap_or(DefaultOp::Show)),
        }
    }
}

async fn scan(app: &mut App, timeout: u64) -> Result<()> {
    println!("scanning for ULCP radios ({timeout} s) ...");
    let found = connection::scan(std::time::Duration::from_secs(timeout)).await?;
    connection::render_found(&found);
    // Retained so `connect <N>` can refer to this listing by number.
    app.last_scan = found;
    Ok(())
}

fn default(app: &mut App, op: DefaultOp) -> Result<()> {
    match op {
        DefaultOp::Show => {
            match &app.prefs.default_device {
                Some(device) => output::field("default", device.display()),
                None => println!("no default radio saved"),
            }
            if let Some(path) = connection::config_path() {
                output::field("settings", path.display());
            }
            Ok(())
        }
        DefaultOp::Set { selector } => {
            let device = match selector {
                Some(selector) => connection::DefaultDevice {
                    selector,
                    name: None,
                },
                None => {
                    let session = app.session()?;
                    match &session.target {
                        Target::Ble { selector, .. } => connection::DefaultDevice {
                            selector: selector.clone(),
                            name: Some(session.label.clone()),
                        },
                        Target::Serial { .. } => bail!(
                            "the saved default is a BLE radio: serial port names change between \
                             plug-ins, so name one with --port or set UMSHCTL_PORT instead"
                        ),
                    }
                }
            };
            app.prefs.default_device = Some(device.clone());
            let path = app.prefs.store()?;
            println!("default radio set to {}", device.display());
            output::field("settings", path.display());
            Ok(())
        }
        DefaultOp::Clear => {
            app.prefs.default_device = None;
            app.prefs.store()?;
            println!("default radio cleared");
            Ok(())
        }
    }
}

/// Finish a mutating command: persist by default, or report the
/// live-only state under `--no-save`.
///
/// Both modes behave the same. A REPL session killed by a dropped link
/// would otherwise silently lose everything since the last manual
/// `save`, and the device treats saving as cheap.
pub async fn persist<L: FrameLink>(device: &mut UlcpDevice<L>, no_save: bool) -> Result<()> {
    if no_save {
        output::note("--no-save — changes are live only; the save command persists them");
    } else {
        device.save().await?;
        println!("saved: changes persist across reboots");
    }
    Ok(())
}

fn decode_u16(value: &[u8]) -> Option<u16> {
    <[u8; 2]>::try_from(value).ok().map(u16::from_le_bytes)
}

fn decode_u32(value: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(value).ok().map(u32::from_le_bytes)
}

/// Percentage of the hour a raw 0-65535 duty figure represents.
fn duty_percent(raw: u16) -> f64 {
    f64::from(raw) * 100.0 / 65535.0
}
