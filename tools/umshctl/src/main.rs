//! `umshctl`: the host tool for ULCP radio devices — inspection,
//! provisioning, device identity, persistence, pairing, radio
//! configuration, and packet capture.
//!
//! Everything except `provision` attaches administratively, with the
//! non-resetting full-protocol handshake, so pointing this tool at an
//! autonomously operating board never disturbs its configuration: only
//! the command explicitly given changes anything.
//!
//! With no command it opens a shell — one attach, many commands — which
//! is worth a great deal over BLE, where each fresh attach costs a
//! discovery pass plus a handshake.

#![cfg_attr(
    not(any(feature = "serial-radio", feature = "ble-radio")),
    allow(unused_variables, dead_code)
)]

mod command;
mod connection;
mod extcap;
mod output;
mod repl;

use std::io::IsTerminal;

use anyhow::{Result, bail};
use clap::Parser;

use umsh::ulcp::UlcpDevice;

use command::Command;
use connection::{Discovery, Found, Prefs, Session, SessionLink, Target};
use output::ColorChoice;

#[derive(Debug, Parser)]
#[command(
    name = "umshctl",
    version,
    about = "Inspect, configure, and capture from ULCP radio devices",
    long_about = "\
Manages a ULCP radio device without disturbing it: attaches with the
non-resetting full-protocol handshake, so an autonomously operating
board keeps its configuration unless the command changes it.

With no command, opens an interactive shell against one attachment.
With no connection, discovers a radio over BLE: one match is used, and
several offer a numbered choice, which --pick asks for outright. A
serial port is used only when named,
because identifying one means opening it, and opening a port can reset
or DFU-trigger hardware that is not a ULCP radio at all. --tcp reaches a
radio whose port has been bridged to a socket, which carries the same
framing a wire does; there is nothing to discover, so it is always named.

KEY values are 44-character base58 or 64-character hex. Secrets are
never echoed in output or traces — though shell history keeps whatever
was typed, the same as any shell.

CODE values are a 3-letter IATA airport code (SJC), a raw 2-byte code
(0x7853), or any other text, which is hashed as a region name
(\"Rogue Valley\"). Region codes are routing-domain tags, not RF band
plans, so every repeater in an area must agree on the same spelling."
)]
pub struct ToolArgs {
    /// Serial port to attach to.
    #[arg(
        short = 'p',
        long,
        value_name = "PORT",
        env = "UMSHCTL_PORT",
        global = true
    )]
    port: Option<String>,

    /// Attach over BLE, optionally naming the radio by name or scan id.
    ///
    /// The selector needs the `=` form (`--ble=T-Echo`); bare `--ble`
    /// discovers.
    #[arg(
        short = 'b',
        long,
        value_name = "SELECTOR",
        num_args(0..=1),
        require_equals = true,
        global = true
    )]
    ble: Option<Option<String>>,

    /// Attach to a radio served over TCP, as `HOST:PORT`.
    ///
    /// The socket carries the same framing a serial port does, so
    /// anything bridging one to a listening socket serves a radio this
    /// way:
    ///
    ///   socat TCP-LISTEN:9000,reuseaddr /dev/cu.usbmodem101,raw,echo=0,b115200
    #[arg(long, value_name = "HOST:PORT", env = "UMSHCTL_TCP", global = true)]
    tcp: Option<String>,

    /// Choose the radio from a numbered listing, ignoring the saved
    /// default.
    ///
    /// The listing appears on its own whenever the answer is ambiguous;
    /// this asks for it even when it is not.
    #[arg(long, global = true)]
    pick: bool,

    /// Serial bit rate.
    #[arg(long, default_value_t = 115_200, value_name = "N", global = true)]
    baud: u32,

    /// Print every ULCP frame on stderr.
    #[arg(long, global = true)]
    trace: bool,

    /// Leave mutations live-only. They otherwise persist automatically
    /// via CMD_SAVE.
    #[arg(long, global = true)]
    no_save: bool,

    /// When to colorize output.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto, value_name = "WHEN", global = true)]
    color: ColorChoice,

    #[command(subcommand)]
    command: Option<Command>,
}

impl ToolArgs {
    fn discovery(&self) -> Discovery {
        if self.pick {
            Discovery::Ask
        } else {
            Discovery::Auto
        }
    }
}

/// Everything a command may need beyond the device itself: the
/// attachment, the settings, and the difference between a shell and a
/// one-shot invocation.
pub struct App {
    pub session: Option<Session>,
    pub prefs: Prefs,
    /// True in the shell, where a question can be asked and a failure
    /// returns to a prompt.
    pub interactive: bool,
    pub trace: bool,
    pub no_save: bool,
    pub baud: u32,
    /// How a bare `connect` resolves a scan — `--pick` at launch keeps
    /// asking for the rest of the shell session.
    pub discovery: Discovery,
    /// The last `scan` listing, so `connect <N>` can refer to it.
    pub last_scan: Vec<Found>,
}

impl App {
    pub fn session(&mut self) -> Result<&mut Session> {
        match &mut self.session {
            Some(session) => Ok(session),
            None => bail!("not attached — try `scan` or `connect`"),
        }
    }

    pub fn device(&mut self) -> Result<&mut UlcpDevice<SessionLink>> {
        Ok(&mut self.session()?.device)
    }

    pub fn target_is_ble(&self) -> bool {
        matches!(
            self.session.as_ref().map(|session| &session.target),
            Some(Target::Ble { .. })
        )
    }

    /// Drop the attachment, returning what it was called. Dropping the
    /// link is what reverts session-scoped device state.
    pub fn detach(&mut self) -> Option<String> {
        self.session.take().map(|session| session.label)
    }

    pub fn rename(&mut self, label: String) {
        if let Some(session) = &mut self.session {
            session.label = label;
        }
    }

    /// An attached, non-interactive app for the Wireshark extcap
    /// interface.
    ///
    /// `interactive` is false in both its senses here: there is no
    /// prompt to return to, and nobody to answer a question. That is
    /// also what lets a dropped BLE link be recovered underneath a
    /// running capture.
    pub fn for_extcap(session: Session, prefs: Prefs, baud: u32) -> Self {
        Self {
            session: Some(session),
            prefs,
            interactive: false,
            trace: false,
            no_save: true,
            baud,
            discovery: Discovery::Auto,
            last_scan: Vec::new(),
        }
    }

    pub async fn attach(&mut self, target: Target) -> Result<()> {
        let session = connection::connect(target, false, self.trace).await?;
        announce_attached(&session);
        self.session = Some(session);
        Ok(())
    }

    /// Re-attach the open link in the other mode. Used by `provision`,
    /// which needs a tethered handle for one command.
    pub async fn reattach(&mut self, tethered: bool) -> Result<()> {
        let Some(session) = self.session.take() else {
            bail!("not attached");
        };
        self.session = Some(session.reattach(tethered, self.trace).await?);
        Ok(())
    }

    /// Open a fresh link to the same radio, keeping the capture tap so a
    /// recovered capture stays one file.
    pub async fn reconnect(&mut self) -> Result<()> {
        let Some(session) = self.session.take() else {
            bail!("not attached");
        };
        self.session = Some(session.reconnect(self.trace).await?);
        Ok(())
    }

    pub fn prompt(&self) -> String {
        match &self.session {
            Some(session) => format!("{} ({})> ", session.label, session.target.transport()),
            None => "(unattached)> ".to_string(),
        }
    }
}

fn announce_attached(session: &Session) {
    eprintln!(
        "attached: {} ({}) device={}{} boot_status={:?} mode={}",
        session.label,
        session.target.transport(),
        session.device.dev_version(),
        // `PROP_DEV_MODEL` is optional; say nothing rather than "unknown"
        // when the device does not name its hardware.
        session
            .device
            .dev_model()
            .map(|model| format!(" on {model}"))
            .unwrap_or_default(),
        session.device.boot_status(),
        if session.is_administrative() {
            "administrative"
        } else {
            "tethered"
        },
    );
}

/// Work out which radio to talk to, from the flags, the environment,
/// the saved default, and finally the air.
async fn resolve(args: &ToolArgs, prefs: &Prefs) -> Result<Option<Target>> {
    if args.pick && (args.port.is_some() || args.tcp.is_some() || matches!(args.ble, Some(Some(_))))
    {
        bail!(
            "--pick chooses a radio from a listing; --port, --tcp, and --ble=SELECTOR already \
             name one"
        );
    }
    if let Some(endpoint) = &args.tcp {
        if args.port.is_some() || args.ble.is_some() {
            bail!("--tcp, --port, and --ble name different radios; give one");
        }
        let (host, port) = connection::parse_endpoint(endpoint)?;
        return Ok(Some(Target::Tcp { host, port }));
    }
    if let Some(port) = &args.port {
        if args.ble.is_some() {
            bail!("--port and --ble name different radios; give one");
        }
        return Ok(Some(Target::Serial {
            port: port.clone(),
            baud: args.baud,
        }));
    }
    if let Some(Some(selector)) = &args.ble {
        return Ok(Some(Target::Ble {
            selector: selector.clone(),
            name: None,
        }));
    }
    // Bare `--ble`, or nothing at all: the tool finds the radio itself.
    let target =
        connection::discover(prefs, std::io::stdin().is_terminal(), args.discovery()).await?;
    if let Some(target) = &target {
        // A mutating one-shot must never act on a silently chosen radio.
        eprintln!("discovered: {}", target.provisional_label());
    }
    Ok(target)
}

async fn run(args: ToolArgs) -> Result<()> {
    output::set_color(args.color.enabled());
    let interactive = args.command.is_none();
    let mut app = App {
        session: None,
        prefs: Prefs::load(),
        interactive,
        trace: args.trace,
        no_save: args.no_save,
        baud: args.baud,
        discovery: args.discovery(),
        last_scan: Vec::new(),
    };

    // Everything clap's grammar cannot express is checked before a
    // radio is opened.
    if let Some(command) = &args.command {
        command.validate()?;
    }

    let needs_device = args
        .command
        .as_ref()
        .is_none_or(|command| command.needs_device());
    if needs_device {
        match resolve(&args, &app.prefs).await? {
            Some(target) => {
                let tethered = args
                    .command
                    .as_ref()
                    .is_some_and(|command| command.needs_tethered());
                let session = connection::connect(target, tethered, app.trace).await?;
                announce_attached(&session);
                app.session = Some(session);
            }
            // The shell can still scan and connect; a one-shot cannot.
            None if interactive => {}
            None => bail!("no ULCP radios found; name one with --port, --tcp, or --ble=SELECTOR"),
        }
    }

    match args.command {
        Some(command) => command.run(&mut app).await,
        None => repl::run(&mut app).await,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Wireshark drives this binary through its own argument vocabulary,
    // which is checked before the tool's parser so the two never have to
    // agree on a shared grammar.
    let result = if extcap::is_extcap_invocation() {
        extcap::run().await
    } else {
        run(ToolArgs::parse()).await
    };
    if let Err(error) = result {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use command::values::{DutyLimitArg, PinArg};

    fn parse(argv: &[&str]) -> Result<ToolArgs, clap::Error> {
        let mut args = vec!["umshctl"];
        args.extend_from_slice(argv);
        ToolArgs::try_parse_from(args)
    }

    #[test]
    fn a_bare_invocation_has_no_command_and_no_connection() {
        let args = parse(&[]).unwrap();
        assert!(args.command.is_none());
        assert!(args.port.is_none());
        assert!(args.ble.is_none());
        assert_eq!(args.baud, 115_200);
    }

    #[test]
    fn the_ble_selector_needs_the_equals_form() {
        // Bare `--ble` means "BLE, discover", and must not swallow the
        // command word that follows it.
        let bare = parse(&["--ble", "info"]).unwrap();
        assert_eq!(bare.ble, Some(None));
        assert!(matches!(bare.command, Some(Command::Info(_))));

        let named = parse(&["--ble=UMSH T-Echo", "info"]).unwrap();
        assert_eq!(named.ble, Some(Some("UMSH T-Echo".into())));
        assert!(matches!(named.command, Some(Command::Info(_))));

        // Even a selector that collides with a command word is
        // unambiguous.
        let collision = parse(&["--ble=info", "info"]).unwrap();
        assert_eq!(collision.ble, Some(Some("info".into())));
    }

    #[test]
    fn pick_asks_and_pairs_only_with_discovery() {
        assert_eq!(parse(&[]).unwrap().discovery(), Discovery::Auto);
        let picked = parse(&["--pick", "info"]).unwrap();
        assert_eq!(picked.discovery(), Discovery::Ask);
        // Bare `--ble` still discovers, so it composes; a named radio
        // does not, but that is a resolve-time check, not a grammar one.
        assert_eq!(
            parse(&["--pick", "--ble"]).unwrap().discovery(),
            Discovery::Ask
        );
    }

    #[test]
    fn connection_flags_work_before_or_after_the_command() {
        let before = parse(&["-p", "/dev/cu.usbmodem101", "info"]).unwrap();
        let after = parse(&["info", "-p", "/dev/cu.usbmodem101"]).unwrap();
        assert_eq!(before.port, after.port);
        assert_eq!(before.port.as_deref(), Some("/dev/cu.usbmodem101"));
    }

    #[test]
    fn provision_flags_build_the_desired_state() {
        const KEY: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
        let peer = format!("{KEY},{},{}", "e0".repeat(32), "50".repeat(32));
        let args = parse(&[
            "provision",
            "--host-key",
            KEY,
            "--channel-key",
            KEY,
            "--peer",
            &peer,
            "--filter=pkt-type:1",
            "--filter",
            "channel-id:9b68",
            "--auto-ack=off",
            "--force",
            "--no-save",
        ])
        .unwrap();
        assert!(args.no_save);
        let Some(Command::Provision(provision)) = args.command else {
            panic!("expected provision");
        };
        assert!(provision.force);
        assert_eq!(provision.host_key.len(), 1);
        assert_eq!(provision.channel_key.len(), 1);
        assert_eq!(provision.peer.len(), 1);
        assert_eq!(provision.filter.len(), 2);
        assert_eq!(provision.auto_ack.len(), 1);
        assert!(!provision.auto_ack[0].0);
    }

    #[test]
    fn misplaced_options_are_rejected() {
        assert!(parse(&["info", "--force"]).is_err());
        assert!(parse(&["save", "--host-key", "aa"]).is_err());
        assert!(parse(&["info", "--expect-host-key=aa"]).is_err(), "bad key");
    }

    #[test]
    fn pin_takes_six_digits_or_clear() {
        let Some(Command::Pin { value }) = parse(&["pin", "042319"]).unwrap().command else {
            panic!("expected pin");
        };
        assert_eq!(value, PinArg(Some(42_319)));
        assert!(parse(&["pin", "12345"]).is_err());
        assert!(parse(&["pin"]).is_err());
    }

    #[test]
    fn duty_parses_show_and_limit_forms() {
        assert!(matches!(
            parse(&["duty"]).unwrap().command,
            Some(Command::Duty { op: None })
        ));
        let Some(Command::Duty {
            op: Some(command::duty::DutyOp::Limit { value }),
        }) = parse(&["duty", "limit", "655"]).unwrap().command
        else {
            panic!("expected duty limit");
        };
        assert_eq!(value, DutyLimitArg(655));
        assert!(matches!(
            parse(&["duty", "limit", "off"]).unwrap().command,
            Some(Command::Duty {
                op: Some(command::duty::DutyOp::Limit {
                    value: DutyLimitArg(u16::MAX)
                })
            })
        ));
        assert!(parse(&["duty", "limit"]).is_err());
        assert!(parse(&["duty", "limit", "70000"]).is_err());
        assert!(parse(&["duty", "now"]).is_err());
    }

    #[test]
    fn phy_rejects_out_of_range_modulation() {
        assert!(parse(&["phy", "sf", "7"]).is_ok());
        assert!(parse(&["phy", "sf", "13"]).is_err());
        assert!(parse(&["phy", "cr", "9"]).is_err());
        // A negative TX power is a value, not a flag.
        assert!(parse(&["phy", "power", "-9"]).is_ok());
    }

    #[test]
    fn repeater_gates_accept_negative_values_and_none() {
        use command::repeater::RepeaterOp;
        assert!(matches!(
            parse(&["repeater"]).unwrap().command,
            Some(Command::Repeater { op: None })
        ));
        let Some(Command::Repeater {
            op: Some(RepeaterOp::MinRssi { dbm }),
        }) = parse(&["repeater", "min-rssi", "-110"]).unwrap().command
        else {
            panic!("expected min-rssi");
        };
        assert_eq!(dbm.0, Some(-110));
        assert!(parse(&["repeater", "min-rssi", "none"]).is_ok());
        assert!(parse(&["repeater", "min-rssi", "loud"]).is_err());
        // The region table is edited entry at a time or replaced whole;
        // a bare `regions` lists it.
        assert!(parse(&["repeater", "regions"]).is_ok());
        assert!(parse(&["repeater", "regions", "add", "Rogue Valley"]).is_ok());
        assert!(parse(&["repeater", "regions", "set", "SJC,"]).is_err());
        assert!(parse(&["repeater", "regions", "SJC"]).is_err());
        assert!(parse(&["repeater", "yes"]).is_err());
    }

    #[test]
    fn factory_reset_confirmation_is_a_flag_not_a_parse_error() {
        // Unlike the tool this replaces, refusing an unconfirmed wipe is
        // a decision made against the session — the shell asks instead.
        let Some(Command::FactoryReset { yes }) = parse(&["factory-reset"]).unwrap().command else {
            panic!("expected factory-reset");
        };
        assert!(!yes);
        let Some(Command::FactoryReset { yes }) =
            parse(&["factory-reset", "--yes"]).unwrap().command
        else {
            panic!("expected factory-reset");
        };
        assert!(yes);
    }

    #[test]
    fn commands_that_look_up_nothing_need_no_device() {
        assert!(!parse(&["scan"]).unwrap().command.unwrap().needs_device());
        assert!(
            !parse(&["default", "set", "id-a"])
                .unwrap()
                .command
                .unwrap()
                .needs_device()
        );
        assert!(
            parse(&["default", "set"])
                .unwrap()
                .command
                .unwrap()
                .needs_device()
        );
        assert!(parse(&["info"]).unwrap().command.unwrap().needs_device());
    }

    #[test]
    fn only_provision_asks_to_tether() {
        assert!(!parse(&["info"]).unwrap().command.unwrap().needs_tethered());
        const KEY: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
        assert!(
            parse(&["provision", "--host-key", KEY])
                .unwrap()
                .command
                .unwrap()
                .needs_tethered()
        );
    }

    #[test]
    fn ping_defaults_to_one_traced_ping() {
        const KEY: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
        let Some(Command::Ping(args)) = parse(&["ping", KEY]).unwrap().command else {
            panic!("expected ping");
        };
        assert_eq!(args.target.0, [0xC4; 32]);
        assert_eq!(args.count, 1);
        assert_eq!(args.size, 8);
        assert!(!args.untraced);
        assert!(args.channel.is_none());
        // Borrowing the radio is what a ping does, so it needs one.
        assert!(
            parse(&["ping", KEY])
                .unwrap()
                .command
                .unwrap()
                .needs_device()
        );
    }

    #[test]
    fn ping_flags_shape_the_frame() {
        const KEY: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
        let Some(Command::Ping(args)) = parse(&[
            "ping",
            KEY,
            "-c",
            "5",
            "-i",
            "10",
            "-W",
            "45",
            "-s",
            "120",
            "--hops",
            "3",
            "--route",
            "a1b2,9b68",
            "--channel",
            "trail",
            "--mic",
            "16",
            "--region",
            "SJC",
            "--full-source",
            "--salt",
            "--untraced",
        ])
        .unwrap()
        .command
        else {
            panic!("expected ping");
        };
        assert_eq!((args.count, args.interval, args.timeout), (5, 10, 45));
        assert_eq!(args.size, 120);
        assert_eq!(args.hops, Some(3));
        assert_eq!(args.route.as_ref().unwrap().0.len(), 2);
        assert_eq!(args.channel.as_ref().unwrap().0.name(), "trail");
        assert!(args.full_source && args.salt && args.untraced);
    }

    #[test]
    fn ping_rejects_contradictions_and_out_of_range_values() {
        const KEY: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
        // A steered route and a forced flood ask for opposite things.
        assert!(parse(&["ping", KEY, "--flood", "--route", "a1b2"]).is_err());
        // An ack-only ping carries no echo data to size.
        assert!(parse(&["ping", KEY, "--ack-only", "-s", "40"]).is_err());
        // Two bytes of the echo are the nonce that matches the reply.
        assert!(parse(&["ping", KEY, "-s", "1"]).is_err());
        assert!(parse(&["ping", KEY, "-c", "0"]).is_err());
        assert!(parse(&["ping", KEY, "--hops", "16"]).is_err());
        assert!(parse(&["ping", KEY, "--mic", "10"]).is_err());
    }

    #[test]
    fn the_name_command_replaces_set_name() {
        assert!(matches!(
            parse(&["name"]).unwrap().command,
            Some(Command::Name { name: None })
        ));
        let Some(Command::Name { name }) = parse(&["name", "Repeater 3"]).unwrap().command else {
            panic!("expected name");
        };
        assert_eq!(name.as_deref(), Some("Repeater 3"));
        assert!(parse(&["set-name", "x"]).is_err());
    }
}
