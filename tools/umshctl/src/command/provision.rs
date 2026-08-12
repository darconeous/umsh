//! `provision`: establish the host domain — the keys, filters, and
//! delegation policy for the host that will tether to this device.
//!
//! The one command that needs a tethered attach. Everything else this
//! tool does administers a device without becoming its host, and the
//! handle refuses host-domain writes to keep that honest.

use anyhow::{Context as _, Result, bail};

use umsh::core::PublicKey;
use umsh::ulcp::{HostOwnership, HostProvisioning};

use super::values::{FilterArg, KeyArg, OnOffArg, PeerArg, parse_bool, parse_key32};
use crate::App;
use crate::connection::confirm;
use crate::output::note;

#[derive(Debug, clap::Args)]
pub struct ProvisionArgs {
    /// Host identity public key. Required, by flag or by file.
    #[arg(long, value_name = "KEY", action = clap::ArgAction::Append)]
    pub host_key: Vec<KeyArg>,

    /// Channel key. Repeatable.
    #[arg(long, value_name = "KEY", action = clap::ArgAction::Append)]
    pub channel_key: Vec<KeyArg>,

    /// Peer public key plus its two 32-byte hex pairwise secrets.
    /// Repeatable.
    #[arg(long, value_name = "PUB,KENC,KMIC", action = clap::ArgAction::Append)]
    pub peer: Vec<PeerArg>,

    /// Receive filter: `dest-hint:HHHHHH`, `channel-id:HHHH`, or
    /// `pkt-type:N`. Repeatable.
    #[arg(long, value_name = "SPEC", action = clap::ArgAction::Append)]
    pub filter: Vec<FilterArg>,

    /// Delegated MAC acknowledgements.
    #[arg(long, value_name = "on|off", action = clap::ArgAction::Append)]
    pub auto_ack: Vec<OnOffArg>,

    /// Read the same settings from a `setting = value` file.
    #[arg(long, value_name = "PATH")]
    pub file: Option<std::path::PathBuf>,

    /// Displace another host's provisioning.
    #[arg(long)]
    pub force: bool,
}

impl ProvisionArgs {
    /// Fold flags and the optional file into one desired state. Both
    /// sources share the same vocabulary on purpose.
    pub fn desired(&self) -> Result<HostProvisioning> {
        let mut settings = Settings::default();
        for key in &self.host_key {
            if settings.host_key.is_some() {
                bail!("host-key given more than once");
            }
            settings.host_key = Some(key.0);
        }
        for key in &self.channel_key {
            settings.channel_keys.push(key.0);
        }
        for peer in &self.peer {
            settings.peer_keys.push(peer.0);
        }
        for filter in &self.filter {
            settings.filters.push(filter.0);
        }
        for value in &self.auto_ack {
            if settings.auto_ack.is_some() {
                bail!("auto-ack given more than once");
            }
            settings.auto_ack = Some(value.0);
        }
        if let Some(path) = &self.file {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            parse_file(&text, &mut settings).with_context(|| path.display().to_string())?;
        }
        settings.finish()
    }
}

/// Provisioning inputs accumulated from flags and file lines.
#[derive(Debug, Default)]
struct Settings {
    host_key: Option<[u8; 32]>,
    channel_keys: Vec<[u8; 32]>,
    peer_keys: Vec<umsh::ulcp_wire::items::PeerKeyEntry>,
    filters: Vec<umsh::ulcp_wire::items::Filter>,
    auto_ack: Option<bool>,
}

impl Settings {
    fn add(&mut self, setting: &str, value: &str) -> Result<()> {
        let text = |error: String| anyhow::anyhow!(error);
        match setting {
            "host-key" => {
                if self.host_key.is_some() {
                    bail!("host-key given more than once");
                }
                self.host_key = Some(parse_key32(value).map_err(text)?);
            }
            "channel-key" => self.channel_keys.push(parse_key32(value).map_err(text)?),
            "peer" => self
                .peer_keys
                .push(value.parse::<PeerArg>().map_err(text)?.0),
            "filter" => self
                .filters
                .push(value.parse::<FilterArg>().map_err(text)?.0),
            "auto-ack" => {
                if self.auto_ack.is_some() {
                    bail!("auto-ack given more than once");
                }
                self.auto_ack = Some(parse_bool(value).map_err(text)?);
            }
            other => bail!("unknown provisioning setting {other:?}"),
        }
        Ok(())
    }

    fn finish(self) -> Result<HostProvisioning> {
        let Some(host_key) = self.host_key else {
            bail!("provisioning requires a host-key (flag or file)");
        };
        Ok(HostProvisioning {
            host_key,
            filters: self.filters,
            channel_keys: self.channel_keys,
            peer_keys: self.peer_keys,
            auto_ack: self.auto_ack.unwrap_or(true),
        })
    }
}

fn parse_file(text: &str, settings: &mut Settings) -> Result<()> {
    for (number, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((setting, value)) = line.split_once('=') else {
            bail!("line {}: expected `setting = value`", number + 1);
        };
        settings
            .add(setting.trim(), value.trim())
            .with_context(|| format!("line {}", number + 1))?;
    }
    Ok(())
}

pub async fn run(app: &mut App, args: ProvisionArgs) -> Result<()> {
    let desired = args.desired()?;

    // Host-domain writes need a tethered handle. One-shot mode attaches
    // that way to begin with; the REPL is administrative, so it borrows
    // the open link for the duration of this one command rather than
    // making the user restart the tool.
    let borrowed = app.session()?.is_administrative();
    if borrowed {
        app.reattach(true).await?;
    }
    let outcome = provision(app, desired, args.force).await;
    if borrowed && let Err(error) = app.reattach(false).await {
        crate::output::warn(format!(
            "could not return to an administrative attach ({error}); reconnect with `connect`"
        ));
    }
    outcome
}

async fn provision(app: &mut App, desired: HostProvisioning, force: bool) -> Result<()> {
    let interactive = app.interactive;
    let device = app.device()?;
    let sync = device.sync(Some(&desired.host_key)).await?;
    match sync.ownership {
        HostOwnership::Unsupported => {
            bail!("this device does not support host provisioning (no CAP_HOST_FILTER)");
        }
        HostOwnership::OtherHost(other) if !force => {
            let message = format!(
                "the device is provisioned for another host ({})",
                PublicKey(other)
            );
            if !interactive {
                bail!(
                    "{message}; re-run with --force to displace it (its host domain will be \
                     wiped)"
                );
            }
            println!("{message}.");
            if !confirm("displace it, wiping its host domain?")? {
                println!("cancelled");
                return Ok(());
            }
        }
        _ => {}
    }
    let device = app.device()?;
    let report = device.provision(&desired).await?;
    if report.host_replaced {
        println!("host identity replaced; the previous host domain was discarded");
    }
    println!("filter table written ({} entries)", desired.filters.len());
    if report.channels_replaced {
        println!(
            "channel-key table replaced ({} keys)",
            desired.channel_keys.len()
        );
    } else {
        println!("channel keys written: {}", report.channels_inserted);
    }
    println!("peer entries written: {}", report.peers_inserted);
    if report.peers_removed > 0 {
        println!("peer entries removed: {}", report.peers_removed);
    }
    println!(
        "auto-ack set to {}",
        if desired.auto_ack { "on" } else { "off" }
    );
    // Host provisioning is deliberately not saved: the host domain is
    // volatile across power cycles by design, and a host re-provisions
    // in full on every attach.
    note("host provisioning is live only — it is re-established on every attach");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh::ulcp_wire::items::Filter;

    const KEY_HEX: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";

    #[test]
    fn file_lines_share_the_flag_vocabulary() {
        let mut settings = Settings::default();
        let text = format!(
            "# operator provisioning\n\
             host-key = {KEY_HEX}\n\
             auto-ack = on\n\
             channel-key = {KEY_HEX}   # primary channel\n\
             peer = {KEY_HEX} {} {}\n\
             filter = pkt-type 1\n",
            "e0".repeat(32),
            "50".repeat(32),
        );
        parse_file(&text, &mut settings).unwrap();
        let desired = settings.finish().unwrap();
        assert_eq!(desired.host_key, [0xC4; 32]);
        assert!(desired.auto_ack);
        assert_eq!(desired.channel_keys.len(), 1);
        assert_eq!(desired.peer_keys.len(), 1);
        assert_eq!(desired.filters, vec![Filter::PktType(1)]);
    }

    #[test]
    fn duplicate_scalar_settings_are_rejected() {
        let mut settings = Settings::default();
        settings.add("host-key", KEY_HEX).unwrap();
        let error = settings.add("host-key", KEY_HEX).unwrap_err().to_string();
        assert!(error.contains("more than once"), "{error}");
    }

    #[test]
    fn a_file_without_setting_syntax_names_the_line() {
        let mut settings = Settings::default();
        let error = parse_file("host-key\n", &mut settings)
            .unwrap_err()
            .to_string();
        assert!(error.contains("line 1"), "{error}");
    }

    #[test]
    fn provisioning_requires_a_host_key() {
        let error = Settings::default().finish().unwrap_err();
        assert!(error.to_string().contains("host-key"), "{error}");
    }
}
