//! The interactive shell: one attach, many commands.
//!
//! Every line is re-parsed with the same `clap` tree the one-shot
//! grammar uses, so `help`, `help phy`, and `phy --help` all work and
//! the completer can walk the tree instead of maintaining a word list.

use anyhow::Result;
use clap::{CommandFactory, Parser};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::{Context, Editor};

use umsh::core::PublicKey;

use crate::App;
use crate::command::Command;
use crate::command::values::KeyArg;
use crate::connection::{self, Target};
use crate::mesh;
use crate::output::warn;

/// What marks a `connect` selector as a TCP endpoint rather than a
/// radio name.
const TCP_SCHEME: &str = "tcp://";

/// The REPL's grammar: everything the one-shot tree has, plus the few
/// verbs that only mean something inside a session.
#[derive(Debug, clap::Subcommand)]
pub enum ReplCommand {
    #[command(flatten)]
    Shared(Command),

    /// Attach to a radio, replacing the current attachment. With no
    /// argument, rediscovers the way a bare launch does.
    Connect {
        /// A scan-listing number, a BLE name or id, a serial port
        /// path, or `tcp://HOST:PORT`.
        #[arg(value_name = "SELECTOR")]
        selector: Option<String>,

        /// Choose from a numbered listing, ignoring the saved default.
        #[arg(long, conflicts_with = "selector")]
        pick: bool,
    },

    /// Open a session to a device across the mesh, using the attached
    /// radio to reach it.
    ///
    /// The radio is borrowed for as long as the session lasts, and every
    /// command that reads or writes the device works the same as it does
    /// over a wire — slower, and without the host domain, which is not an
    /// administrator's to see. `disconnect` gives the radio back.
    Remote {
        /// The device to manage, as its node public key.
        #[arg(value_name = "KEY")]
        target: KeyArg,
    },

    /// Detach from the current radio without leaving the shell.
    ///
    /// On a mesh session this ends the session and returns to the radio
    /// it borrowed; a second `disconnect` lets go of that too.
    Disconnect,

    /// Leave the shell.
    #[command(alias = "quit")]
    Exit,
}

/// Wrapper used to parse REPL lines and to build the completion tree.
#[derive(Debug, Parser)]
#[command(name = "", no_binary_name = true, disable_help_flag = false)]
pub struct ReplCommandLine {
    #[command(subcommand)]
    pub command: ReplCommand,
}

/// Rustyline helper providing tab completion driven by the clap tree.
#[derive(rustyline::Helper, rustyline::Hinter, rustyline::Highlighter, rustyline::Validator)]
struct ReplHelper;

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let line_to_cursor = &line[..pos];

        // Tokenize up to the cursor; give up quietly on an unclosed
        // quote rather than completing something surprising.
        let Some(mut tokens) = shlex::split(line_to_cursor) else {
            return Ok((pos, Vec::new()));
        };

        // Separate the partial word being typed from the tokens behind it.
        let (partial, complete_start) =
            if !line_to_cursor.ends_with(char::is_whitespace) && !tokens.is_empty() {
                let partial = tokens.pop().unwrap_or_default();
                let start = pos.saturating_sub(partial.len());
                (partial, start)
            } else {
                (String::new(), pos)
            };

        // Walk the tree with the finished tokens, tracking whether the
        // next one will be swallowed as a flag's value.
        let mut cmd = ReplCommandLine::command();
        let mut expect_value_for: Option<String> = None;
        for token in &tokens {
            if expect_value_for.take().is_some() {
                continue;
            }
            if let Some(flag) = token.strip_prefix("--").or_else(|| token.strip_prefix('-')) {
                if let Some(arg) = cmd.get_arguments().find(|arg| {
                    arg.get_long() == Some(flag)
                        || arg.get_short().is_some_and(|c| c.to_string() == flag)
                }) && takes_value(arg)
                {
                    expect_value_for = Some(flag.to_string());
                }
            } else if let Some(sub) = cmd.find_subcommand(token) {
                cmd = sub.clone();
            }
        }

        let candidates: Vec<String> = if let Some(flag) = expect_value_for {
            cmd.get_arguments()
                .find(|arg| arg.get_long() == Some(flag.as_str()))
                .map(possible_values)
                .unwrap_or_default()
        } else if partial.starts_with('-') {
            cmd.get_arguments()
                .filter_map(|arg| arg.get_long().map(|long| format!("--{long}")))
                .collect()
        } else {
            // Subcommand names and their aliases, then the possible
            // values of whichever positional comes next.
            let mut candidates: Vec<String> = cmd
                .get_subcommands()
                .flat_map(|sub| {
                    std::iter::once(sub.get_name().to_string())
                        .chain(sub.get_all_aliases().map(str::to_string))
                })
                .collect();
            candidates.extend(cmd.get_positionals().flat_map(possible_values));
            candidates
        };

        let pairs = candidates
            .into_iter()
            .filter(|candidate| candidate.starts_with(&partial))
            .map(|candidate| Pair {
                display: candidate.clone(),
                replacement: format!("{candidate} "),
            })
            .collect();
        Ok((complete_start, pairs))
    }
}

fn possible_values(arg: &clap::Arg) -> Vec<String> {
    arg.get_possible_values()
        .iter()
        .map(|value| value.get_name().to_string())
        .collect()
}

/// Whether a clap argument consumes the next token as its value.
fn takes_value(arg: &clap::Arg) -> bool {
    matches!(
        arg.get_action(),
        clap::ArgAction::Set | clap::ArgAction::Append
    )
}

pub async fn run(app: &mut App) -> Result<()> {
    let mut editor = Editor::<ReplHelper, rustyline::history::DefaultHistory>::new()?;
    editor.set_helper(Some(ReplHelper));
    let history = connection::history_path();
    if let Some(path) = &history {
        // A missing history file is the normal first run.
        let _ = editor.load_history(path);
    }

    banner(app);
    let mut failed = false;
    loop {
        let mut prompt = app.prompt();
        if failed {
            prompt.insert_str(0, "❌ ");
        }
        let line = match editor.readline(&prompt) {
            Ok(line) => line,
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(error) => {
                eprintln!("error: {error}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        editor.add_history_entry(line.as_str())?;
        match process_line(app, &line).await {
            Ok(true) => failed = false,
            Ok(false) => break,
            Err(error) => {
                // `help` renders through clap's error channel, and a
                // help request is not a failure.
                failed =
                    !line.trim_start().starts_with("help") && !line.trim_end().ends_with("help");
                eprintln!("{error}");
            }
        }
    }

    if let Some(path) = &history {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(error) = editor.save_history(path) {
            warn(format!("could not save history: {error}"));
        }
    }
    Ok(())
}

fn banner(app: &App) {
    println!("umshctl — `help` lists commands, `exit` leaves.");
    if app.session.is_none() {
        println!("not attached: `scan` to look for radios, `connect` to attach.");
    }
}

/// Parse and run one line. `Ok(false)` means the user asked to leave.
async fn process_line(app: &mut App, line: &str) -> Result<bool> {
    let Some(args) = shlex::split(line) else {
        anyhow::bail!("unbalanced quotes");
    };
    let command = ReplCommandLine::try_parse_from(args)?.command;
    match command {
        ReplCommand::Exit => return Ok(false),
        ReplCommand::Disconnect => {
            let was_mesh = app.mesh.is_some();
            match app.detach().await {
                Some(label) if was_mesh => match &app.session {
                    Some(session) => println!(
                        "left {label}; back on {} ({})",
                        session.label,
                        session.target.transport()
                    ),
                    None => println!("left {label}"),
                },
                Some(label) => println!("detached from {label}"),
                None => println!("not attached"),
            }
            return Ok(true);
        }
        ReplCommand::Remote { target } => {
            mesh::open_remote(app, PublicKey(target.0), mesh::Greeting::Named).await?;
            if let Some(session) = &app.session {
                println!("on {} over the mesh", session.label);
            }
            return Ok(true);
        }
        ReplCommand::Connect { selector, pick } => {
            connect(app, selector, pick).await?;
            return Ok(true);
        }
        ReplCommand::Shared(command) => {
            command.validate()?;
            if command.needs_device() && app.session.is_none() {
                anyhow::bail!("not attached — try `scan` or `connect`");
            }
            command.run(app).await?;
        }
    }
    Ok(true)
}

/// `connect`: rediscover, or attach to the radio the user named.
async fn connect(app: &mut App, selector: Option<String>, pick: bool) -> Result<()> {
    let target = match selector {
        // A bare number refers to the last `scan` listing, which is the
        // whole reason the REPL keeps it.
        Some(selector) => match selector.parse::<usize>() {
            Ok(index) if (1..=app.last_scan.len()).contains(&index) => {
                Target::from(&app.last_scan[index - 1])
            }
            Ok(index) => anyhow::bail!(
                "no radio {index} in the last scan ({} listed); run `scan` again",
                app.last_scan.len()
            ),
            Err(_) => named_target(selector, app.baud)?,
        },
        None => {
            let how = if pick {
                connection::Discovery::Ask
            } else {
                app.discovery
            };
            let Some(target) = connection::discover(&app.prefs, app.interactive, how).await? else {
                anyhow::bail!("no ULCP radios found");
            };
            target
        }
    };
    // Detaching first reverts session-scoped device state (promiscuous
    // mode) on the radio being left behind, and ends a mesh session so
    // its borrowed radio is not left in a task nobody holds.
    app.detach().await;
    app.attach(target).await
}

/// Classify a `connect` selector that is not a scan-listing number.
///
/// The `tcp://` test comes first: the scheme's own slashes would
/// satisfy the path rule below it. A bare `host:port` stays a BLE
/// selector — the scheme is what separates an endpoint from a name.
fn named_target(selector: String, baud: u32) -> Result<Target> {
    if let Some(endpoint) = selector.strip_prefix(TCP_SCHEME) {
        let (host, port) = connection::parse_endpoint(endpoint)?;
        return Ok(Target::Tcp { host, port });
    }
    if selector.contains('/') {
        return Ok(Target::Serial {
            port: selector,
            baud,
        });
    }
    Ok(Target::Ble {
        selector,
        name: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_tree_is_internally_consistent() {
        ReplCommandLine::command().debug_assert();
        crate::ToolArgs::command().debug_assert();
    }

    fn parse(line: &str) -> Result<ReplCommand> {
        let args = shlex::split(line).expect("balanced quotes");
        Ok(ReplCommandLine::try_parse_from(args)?.command)
    }

    #[test]
    fn a_tcp_selector_beats_the_serial_path_rule() {
        // `tcp://` contains the slashes the path rule looks for, so the
        // order of the two tests is what makes this work at all.
        assert_eq!(
            named_target("tcp://127.0.0.1:9000".into(), 115_200).unwrap(),
            Target::Tcp {
                host: "127.0.0.1".into(),
                port: 9000,
            }
        );
        assert_eq!(
            named_target("/dev/cu.usbmodem101".into(), 115_200).unwrap(),
            Target::Serial {
                port: "/dev/cu.usbmodem101".into(),
                baud: 115_200,
            }
        );
        // A bare endpoint is still a name: BLE radios are named freely,
        // and the scheme is the only reliable signal.
        assert_eq!(
            named_target("127.0.0.1:9000".into(), 115_200).unwrap(),
            Target::Ble {
                selector: "127.0.0.1:9000".into(),
                name: None,
            }
        );
        // A malformed endpoint is reported, not silently taken for a
        // radio name.
        assert!(named_target("tcp://127.0.0.1".into(), 115_200).is_err());
    }

    #[test]
    fn repl_only_verbs_parse_and_shared_ones_still_do() {
        assert!(matches!(parse("exit").unwrap(), ReplCommand::Exit));
        assert!(matches!(parse("quit").unwrap(), ReplCommand::Exit));
        assert!(matches!(
            parse("disconnect").unwrap(),
            ReplCommand::Disconnect
        ));
        assert!(matches!(
            parse("connect 2").unwrap(),
            ReplCommand::Connect {
                selector: Some(ref s),
                pick: false,
            } if s == "2"
        ));
        assert!(matches!(
            parse("connect --pick").unwrap(),
            ReplCommand::Connect {
                selector: None,
                pick: true,
            }
        ));
        // Naming a radio and asking to be shown the listing are two
        // different requests.
        assert!(parse("connect --pick 2").is_err());
        assert!(matches!(
            parse("info").unwrap(),
            ReplCommand::Shared(Command::Info(_))
        ));
    }

    #[test]
    fn quoted_names_survive_the_split() {
        let ReplCommand::Shared(Command::Name { name }) = parse("name \"Rogue Valley\"").unwrap()
        else {
            panic!("expected name");
        };
        assert_eq!(name.as_deref(), Some("Rogue Valley"));
    }

    #[test]
    fn remote_takes_a_key_in_either_written_form() {
        let hex = "c4".repeat(32);
        let ReplCommand::Remote { target } = parse(&format!("remote {hex}")).unwrap() else {
            panic!("expected remote");
        };
        assert_eq!(target.0, [0xC4; 32]);

        // The same key as the tool prints it.
        let base58 = PublicKey(target.0).to_string();
        let ReplCommand::Remote { target } = parse(&format!("remote {base58}")).unwrap() else {
            panic!("expected remote");
        };
        assert_eq!(target.0, [0xC4; 32]);

        // A node is named by its key, never discovered.
        assert!(parse("remote").is_err());
        assert!(parse("remote nonsense").is_err());
    }

    #[test]
    fn unknown_verbs_are_rejected_rather_than_guessed_at() {
        assert!(parse("teleport").is_err());
    }

    #[test]
    fn completion_offers_subcommands_then_narrows_by_prefix() {
        let helper = ReplHelper;
        let ctx_history = rustyline::history::DefaultHistory::new();
        let ctx = Context::new(&ctx_history);

        let (_, all) = helper.complete("", 0, &ctx).unwrap();
        let names: Vec<&str> = all.iter().map(|pair| pair.display.as_str()).collect();
        assert!(names.contains(&"info"), "{names:?}");
        assert!(names.contains(&"capture"), "{names:?}");
        assert!(names.contains(&"exit"), "{names:?}");

        let (start, narrowed) = helper.complete("rep", 3, &ctx).unwrap();
        assert_eq!(start, 0);
        assert_eq!(
            narrowed
                .iter()
                .map(|pair| pair.display.as_str())
                .collect::<Vec<_>>(),
            ["repeater"],
        );
    }

    #[test]
    fn completion_descends_into_a_subcommand() {
        let helper = ReplHelper;
        let ctx_history = rustyline::history::DefaultHistory::new();
        let ctx = Context::new(&ctx_history);

        let (_, pairs) = helper.complete("repeater ", 9, &ctx).unwrap();
        let names: Vec<&str> = pairs.iter().map(|pair| pair.display.as_str()).collect();
        assert!(names.contains(&"min-rssi"), "{names:?}");
        assert!(names.contains(&"default-region"), "{names:?}");
        assert!(!names.contains(&"info"), "{names:?}");
    }

    #[test]
    fn completion_offers_flags_when_one_is_being_typed() {
        let helper = ReplHelper;
        let ctx_history = rustyline::history::DefaultHistory::new();
        let ctx = Context::new(&ctx_history);

        let (_, pairs) = helper.complete("capture --", 10, &ctx).unwrap();
        let names: Vec<&str> = pairs.iter().map(|pair| pair.display.as_str()).collect();
        assert!(names.contains(&"--pcap"), "{names:?}");
        assert!(names.contains(&"--layers"), "{names:?}");
    }

    #[test]
    fn completion_offers_a_flags_possible_values() {
        let helper = ReplHelper;
        let ctx_history = rustyline::history::DefaultHistory::new();
        let ctx = Context::new(&ctx_history);

        let (_, pairs) = helper.complete("capture --layers ", 17, &ctx).unwrap();
        let names: Vec<&str> = pairs.iter().map(|pair| pair.display.as_str()).collect();
        assert!(names.contains(&"radio"), "{names:?}");
        assert!(names.contains(&"both"), "{names:?}");
    }
}
