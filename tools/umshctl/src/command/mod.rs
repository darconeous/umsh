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
pub mod manage;
pub mod phy;
pub mod ping;
pub mod props;
pub mod repeater;
pub mod routes_cmd;
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
    /// Report what the device says about itself, whole or by topic.
    /// Changes nothing.
    Info(info::InfoArgs),

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

    /// Restart the device (CMD_REBOOT): a power cycle that keeps
    /// everything the device has persisted.
    Reboot,

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

    /// Nodes authorized to manage this device over the mesh.
    DevAdmin {
        #[command(subcommand)]
        op: Option<tables::TableOp>,
    },

    /// Administer another device over the mesh, using the attached radio
    /// to reach it.
    Manage {
        /// The device to manage, as its node public key.
        #[arg(value_name = "KEY")]
        target: values::KeyArg,

        #[command(subcommand)]
        op: manage::ManageOp,
    },

    /// Ask a repeater which repeaters it knows of, using the attached
    /// radio to reach it.
    PeerRepeaters {
        /// The repeater to ask, as its node public key.
        #[arg(value_name = "KEY")]
        target: values::KeyArg,
    },

    /// Measure the path to another node: reachability, round-trip time,
    /// hops, and signal. Needs no authorization from the far end.
    Ping(ping::PingArgs),

    /// Show or forget the routes this tool has learned to other nodes.
    ///
    /// Learned from replies and remembered between invocations, so a
    /// script does not re-flood the mesh for a path it was told a second
    /// ago. Needs no radio.
    Routes {
        #[command(subcommand)]
        op: Option<routes_cmd::RoutesOp>,
    },

    /// Show the administrator identity this tool manages devices with.
    AdminKey,

    /// Read properties by name or number.
    ///
    /// Names are the spec mnemonics without their prefix
    /// (`phy-freq`, `dev-name`); numbers are decimal or `0x`-prefixed.
    /// Several are read in one exchange where the device supports it.
    Get {
        #[arg(value_name = "PROP", required = true)]
        keys: Vec<props::PropArg>,

        /// Print values as raw octets rather than reading them.
        #[arg(long)]
        hex: bool,
    },

    /// Write one property by name or number.
    ///
    /// The value is written the way `get` reads it back: `on`/`off` for
    /// a switch, a decimal number for a count, an address for a key. A
    /// property whose shape is a structure takes hex.
    Set {
        #[arg(value_name = "PROP")]
        key: props::PropArg,

        #[arg(value_name = "VALUE")]
        value: String,

        /// Print the stored value as raw octets.
        #[arg(long)]
        hex: bool,
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
            // The administrator identity is this tool's own; no radio is
            // involved in reading it out.
            Self::AdminKey => false,
            // Learned routes are this tool's own notes, and reading them
            // is exactly what you want to do with nothing attached.
            Self::Routes { .. } => false,
            // Saving the attached radio as the default needs one; naming
            // a selector outright does not.
            Self::Default { op } => matches!(op, Some(DefaultOp::Set { selector: None })),
            _ => true,
        }
    }

    /// Why this command cannot run against a device reached over the
    /// mesh, if it cannot.
    ///
    /// Most of the tool works unchanged over a mesh session: the handle
    /// is an ordinary one and the properties behind it are the same. The
    /// exceptions are the commands that need something the Node
    /// Management binding does not carry, and the ones that would want
    /// the radio this session has already borrowed. Refusing them here
    /// beats letting each fail in its own way somewhere over the air.
    pub fn mesh_refusal(&self) -> Option<&'static str> {
        match self {
            // Captured frames arrive as unsolicited stream traffic, and
            // the binding carries nothing unsolicited — there is no
            // remote form of this to reach for.
            Self::Capture(_) => Some(
                "capture listens on the attached radio's own receiver, which a mesh session \
                 cannot reach; `disconnect` first",
            ),
            // Each of these becomes a node on the mesh, and this session
            // is already using the only radio there is.
            Self::Manage { .. } | Self::PeerRepeaters { .. } | Self::Ping(_) => Some(
                "this session has already borrowed the radio; `disconnect` first, then reach \
                 the node from there",
            ),
            _ => None,
        }
    }

    /// Check whatever clap's grammar cannot — combinations of flags —
    /// *before* a device is opened.
    ///
    /// Connecting takes seconds over BLE and disturbs a radio that was
    /// minding its own business; an argument mistake should cost
    /// neither.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Capture(args) => args.validate(),
            // A value the property cannot hold is a typing mistake, and
            // finding out after a BLE discovery pass and a handshake is
            // no way to learn it.
            Self::Set { key, value, .. } => props::encode_value(key.0, value).map(drop),
            _ => Ok(()),
        }
    }

    pub async fn run(self, app: &mut App) -> Result<()> {
        if app
            .session
            .as_ref()
            .is_some_and(|session| session.is_mesh())
            && let Some(refusal) = self.mesh_refusal()
        {
            bail!("{refusal}");
        }
        match self {
            Self::Info(args) => info::run(app.device()?, args).await,
            Self::Identity { op } => lifecycle::identity(app.device()?, op).await,
            Self::Name { name } => lifecycle::name(app, name).await,
            Self::Save => lifecycle::save(app.device()?).await,
            Self::Restore => lifecycle::restore(app.device()?).await,
            Self::Clear => lifecycle::clear(app.device()?).await,
            Self::Reset => lifecycle::reset(app.device()?).await,
            Self::Reboot => lifecycle::reboot(app).await,
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
            Self::DevAdmin { op } => tables::run(app, prop::DEV_ADMINS, "administrator", op).await,
            Self::Manage { target, op } => {
                manage::run(app, target, manage::Operation::Manage(op)).await
            }
            Self::PeerRepeaters { target } => {
                manage::run(app, target, manage::Operation::PeerRepeaters).await
            }
            Self::Ping(args) => {
                let target = args.target;
                manage::run(app, target, manage::Operation::Ping(args)).await
            }
            Self::Routes { op } => routes_cmd::run(op),
            Self::AdminKey => crate::mesh::show_admin_key(),
            Self::Get { keys, hex } => props::get(app.device()?, &keys, hex).await,
            Self::Set { key, value, hex } => {
                let no_save = app.no_save;
                let device = app.device()?;
                props::set(device, key, &value, hex).await?;
                persist(device, no_save).await
            }
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
                        Target::Tcp { .. } => bail!(
                            "the saved default is a BLE radio: a bridged radio is already named \
                             by its endpoint, so give it with --tcp or set UMSHCTL_TCP instead"
                        ),
                        Target::Mesh { .. } => bail!(
                            "the saved default is a radio to attach to, not a node to manage: \
                             `disconnect` first, then save the radio underneath"
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

/// A span of seconds at human scale, to at most two units: `45s`, `20m`,
/// `1h30m`, `12d6h`.
///
/// Two units is the point where more precision stops helping — nobody
/// reading an uptime of `12d6h` wanted the seconds. Days matter because
/// this also renders uptimes, where hour counts run into the hundreds.
fn format_duration(seconds: u32) -> String {
    const MINUTE: u32 = 60;
    const HOUR: u32 = 60 * MINUTE;
    const DAY: u32 = 24 * HOUR;
    match seconds {
        s if s >= DAY && s % DAY == 0 => format!("{}d", s / DAY),
        s if s >= DAY => format!("{}d{}h", s / DAY, (s % DAY) / HOUR),
        s if s >= HOUR && s % HOUR == 0 => format!("{}h", s / HOUR),
        s if s >= HOUR => format!("{}h{}m", s / HOUR, (s % HOUR) / MINUTE),
        s if s >= MINUTE && s % MINUTE == 0 => format!("{}m", s / MINUTE),
        s if s >= MINUTE => format!("{}m{}s", s / MINUTE, s % MINUTE),
        s => format!("{s}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::format_duration;

    #[test]
    fn a_duration_reads_at_human_scale_to_two_units() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(1200), "20m");
        assert_eq!(format_duration(90), "1m30s");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(5400), "1h30m");
        assert_eq!(format_duration(14400), "4h");
        // Days, which is where uptimes live and advert intervals do not.
        assert_eq!(format_duration(86400), "1d");
        assert_eq!(format_duration(1_058_400), "12d6h");
        // A day boundary with no leftover hours still reads as whole days.
        assert_eq!(format_duration(172_800), "2d");
    }
}
