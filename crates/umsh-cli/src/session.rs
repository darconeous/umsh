//! `CliSession` — the driver object that owns a clone of `LocalNode<M>`,
//! a `CliIo`, and a `CliLogger`, plus the in-session state tables.
//!
//! The session holds a *clone* of `LocalNode<M>`. Other firmware components
//! hold their own clones of the same underlying node state and continue to
//! function independently.
//!
//! ## Driver pattern
//!
//! ```text
//! tokio::select! {
//!     r = host.run()  => { r?; }   // existing loop over pump_once()
//!     r = cli.run()   => { r?; }   // loops read_line + service_events
//! }
//! ```
//!
//! Inside `cli.run()`:
//! ```text
//! loop {
//!     select(read_line(&mut buf), wake.wait()):
//!         Left(line)  → parse + execute (may call MAC-I/O directly)
//!         Right(wake) → service_events() only
//!     service_events() always runs after each select
//! }
//! ```

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt::Write as _;

use heapless::{Deque, FnvIndexMap, String as HString, Vec as HVec};
use umsh_core::PublicKey;
use umsh_mac::SendOptions;
use umsh_node::{LocalNode, MacBackend, NodeError, OwnedMacCommand, Subscription};
use umsh_text::UnicastTextChatWrapper;

use crate::commands::{Command, ParseError, parse};
use crate::events::{CliEvent, EVENT_LINE_MAX};
use crate::io::{CliInput, CliOutput};
use crate::logger::{CliLogger, LogLevel};
use crate::mac_cmd::encode_mac_command;
use crate::ping::PendingPing;
use crate::settings::SessionSettings;
use crate::stats::Stats;
use umsh_sync::AsyncCondition;

/// Errors surfaced from `CliSession::run`.
///
/// `Node` flattens any `NodeError<…>` to a `String` via `format!("{:?}", e)`
/// because the underlying error is generic over the `MacBackend`'s send and
/// capacity error types and exposing it would force the CLI's error type to
/// inherit those generics. Callers can read the message but cannot react
/// programmatically to specific node-layer failure modes.
///
/// TODO: revisit this if a CLI consumer needs to branch on node errors.
/// Options include adding a second generic parameter that carries the
/// underlying `NodeError<E, C>`, or replacing the loss with a richer
/// enum that mirrors the variants we actually care about at this layer.
#[derive(Debug)]
pub enum CliError<IoErr: core::fmt::Debug> {
    Io(IoErr),
    Node(String),
}

impl<IoErr: core::fmt::Debug> From<IoErr> for CliError<IoErr> {
    fn from(e: IoErr) -> Self {
        CliError::Io(e)
    }
}

type SharedQueue<T> = Rc<RefCell<T>>;

/// Entry in the CLI peer table.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    pub key: PublicKey,
    pub alias: Option<HString<16>>,
}

/// Entry in the CLI channel table. Stores the raw key bytes so the `Channel`
/// descriptor can be reconstructed for leave/bind operations.
#[derive(Debug, Clone)]
pub struct ChannelEntry {
    pub name: HString<16>,
    pub key_bytes: [u8; 32],
}

/// Outcome returned by `execute`. Not exposed outside this module.
#[derive(Debug, PartialEq, Eq)]
enum ExecOutcome {
    Continue,
    Quit,
}

/// The CLI driver. Owns the output half of the CLI transport; the input half
/// is passed to [`CliSession::run`] so the driver can hold a long-lived read
/// future across wake events without blocking writes to `out`.
pub struct CliSession<
    M,
    OUT,
    LOG,
    const N_PEERS: usize,
    const N_ALIASES: usize,
    const N_CHANNELS: usize,
    const N_EVENTS: usize,
    const N_PENDING_PINGS: usize,
    const LINE_MAX: usize,
> where
    M: MacBackend,
    M::SendError: core::fmt::Debug,
    M::CapacityError: core::fmt::Debug,
    OUT: CliOutput,
    LOG: CliLogger,
{
    pub(crate) node: LocalNode<M>,
    pub(crate) local_key: PublicKey,
    pub(crate) out: OUT,
    pub(crate) logger: LOG,
    pub(crate) peers: FnvIndexMap<PublicKey, PeerEntry, N_PEERS>,
    pub(crate) aliases: FnvIndexMap<HString<16>, PublicKey, N_ALIASES>,
    pub(crate) channels: FnvIndexMap<HString<16>, ChannelEntry, N_CHANNELS>,
    pub(crate) events: SharedQueue<Deque<CliEvent, N_EVENTS>>,
    pub(crate) events_dropped: SharedQueue<u64>,
    pub(crate) pending_pings: SharedQueue<HVec<PendingPing, N_PENDING_PINGS>>,
    pub(crate) stats: SharedQueue<Stats>,
    pub(crate) wake: Rc<AsyncCondition>,
    pub(crate) current_peer: Option<PublicKey>,
    pub(crate) settings: SessionSettings,
    /// Kept alive to prevent subscription teardown.
    _subs: Vec<Subscription>,
}

impl<
    M,
    OUT,
    LOG,
    const N_PEERS: usize,
    const N_ALIASES: usize,
    const N_CHANNELS: usize,
    const N_EVENTS: usize,
    const N_PENDING_PINGS: usize,
    const LINE_MAX: usize,
> CliSession<M, OUT, LOG, N_PEERS, N_ALIASES, N_CHANNELS, N_EVENTS, N_PENDING_PINGS, LINE_MAX>
where
    M: MacBackend,
    M::SendError: core::fmt::Debug,
    M::CapacityError: core::fmt::Debug,
    OUT: CliOutput,
    LOG: CliLogger,
{
    /// Construct a new session around a cloned `LocalNode<M>`. `local_key`
    /// is passed in because the caller already has it; no node-crate accessor
    /// for the local key is added. The session owns the `out` half of the
    /// CLI transport; the input half is supplied to [`Self::run`].
    pub fn new(node: LocalNode<M>, local_key: PublicKey, out: OUT, logger: LOG) -> Self {
        let events: SharedQueue<Deque<CliEvent, N_EVENTS>> = Rc::new(RefCell::new(Deque::new()));
        let events_dropped: SharedQueue<u64> = Rc::new(RefCell::new(0));
        let pending_pings: SharedQueue<HVec<PendingPing, N_PENDING_PINGS>> =
            Rc::new(RefCell::new(HVec::new()));
        let stats: SharedQueue<Stats> = Rc::new(RefCell::new(Stats::default()));
        let wake = Rc::new(AsyncCondition::new());

        let subs = register_subscriptions(
            &node,
            events.clone(),
            events_dropped.clone(),
            stats.clone(),
            wake.clone(),
        );

        Self {
            node,
            local_key,
            out,
            logger,
            peers: FnvIndexMap::new(),
            aliases: FnvIndexMap::new(),
            channels: FnvIndexMap::new(),
            events,
            events_dropped,
            pending_pings,
            stats,
            wake,
            current_peer: None,
            settings: SessionSettings::default(),
            _subs: subs,
        }
    }

    /// Resolve a `<peer-ref>` token to a `PublicKey`. Alias table first,
    /// then encoded forms (hex / base58 / base64).
    pub fn resolve_peer(&self, token: &str) -> Option<PublicKey> {
        if let Ok(s) = HString::<16>::try_from(token) {
            if let Some(k) = self.aliases.get(&s) {
                return Some(*k);
            }
        }
        crate::peer_ref::try_parse_pubkey(token)
    }

    /// Pre-register a peer at startup (e.g. from `--peer` CLI args).
    /// Returns `false` if either the peer or alias table is full, or if the
    /// MAC rejects the key (full peer table at the MAC layer).
    ///
    /// Also registers the peer in the MAC-layer peer table via `node.peer`
    /// so inbound frames from this peer can be validated before the user
    /// initiates any outbound traffic.
    pub async fn register_peer(&mut self, key: PublicKey, alias: Option<&str>) -> bool {
        if self.peers.contains_key(&key) {
            return true;
        }
        let alias_heap = alias.and_then(|a| HString::<16>::try_from(a).ok());
        if self
            .peers
            .insert(
                key,
                PeerEntry {
                    key,
                    alias: alias_heap.clone(),
                },
            )
            .is_err()
        {
            return false;
        }
        if let Some(a) = alias_heap {
            if self.aliases.insert(a, key).is_err() {
                let _ = self.peers.remove(&key);
                return false;
            }
        }
        // Register at the MAC layer too — otherwise inbound unicast/auth
        // packets from this peer would be dropped for missing keys.
        if self.node.peer(key).await.is_err() {
            let _ = self.peers.remove(&key);
            if let Some(a) = alias.and_then(|s| HString::<16>::try_from(s).ok()) {
                let _ = self.aliases.remove(&a);
            }
            return false;
        }
        true
    }

    /// Build `SendOptions` from current CLI preferences.
    fn send_opts(&self) -> SendOptions {
        SendOptions::default()
            .with_flood_hops(self.settings.flood_hops)
            .with_ack_requested(self.settings.ack_requested)
    }

    /// Drive the CLI until `/quit` or EOF.
    ///
    /// Each outer iteration arms one long-lived `read_line` future and races
    /// it against `wake` in an inner loop. The read future is only dropped
    /// when it completes — wake-driven iterations preserve it across
    /// `select!` rearms, so implementations of [`CliInput`] do not need to
    /// be cancel-safe.
    ///
    /// `input` is borrowed for the duration of each read; it's a separate
    /// parameter from `self` so the driver can continue writing to `self.out`
    /// while a read is outstanding.
    pub async fn run<IN>(&mut self, input: &mut IN) -> Result<(), CliError<OUT::Error>>
    where
        IN: CliInput<Error = OUT::Error>,
    {
        use futures::future::{Either, select};

        // Service any events that arrived before first user input
        // (e.g. from a previously started host).
        self.service_events().await?;

        let mut buf = [0u8; LINE_MAX];
        let wake = self.wake.clone();
        loop {
            // Arm a single read future and keep it alive across wake events.
            let read_fut = input.read_line(&mut buf);
            futures::pin_mut!(read_fut);
            let owned: Option<String> = loop {
                let wait_fut = wake.wait();
                futures::pin_mut!(wait_fut);
                match select(read_fut.as_mut(), wait_fut).await {
                    Either::Left((result, _)) => match result {
                        Ok(Some(s)) => break Some(String::from(s)),
                        Ok(None) => break None,
                        Err(e) => return Err(CliError::Io(e)),
                    },
                    Either::Right(((), _)) => {
                        // Wake fired; drain events without dropping read_fut.
                        self.service_events().await?;
                    }
                }
            };

            match owned {
                None => return Ok(()), // EOF
                Some(line) => match parse(&line) {
                    Err(ParseError::Empty) => {}
                    Err(e) => {
                        let msg = format_parse_error(&e);
                        self.write_err(&msg).await?;
                    }
                    Ok(cmd) => match self.execute(cmd).await? {
                        ExecOutcome::Continue => {}
                        ExecOutcome::Quit => return Ok(()),
                    },
                },
            }

            // Drain events queued by execute() (e.g. send receipts).
            self.service_events().await?;
        }
    }

    // ─── Event-queue drain ──────────────────────────────────────────────────

    async fn service_events(&mut self) -> Result<(), CliError<OUT::Error>> {
        loop {
            // Take one event per iteration (avoids holding RefCell across await).
            let event = self.events.borrow_mut().pop_front();
            let Some(event) = event else { break };
            self.handle_event(event).await?;
        }
        Ok(())
    }

    async fn handle_event(&mut self, event: CliEvent) -> Result<(), CliError<OUT::Error>> {
        match event {
            CliEvent::Received {
                from,
                hops: _,
                rssi,
                snr,
                prefix,
            } => {
                // Try to decode as text.
                if let Some([pt, rest @ ..]) = prefix.as_slice().get(0..) {
                    if *pt == umsh_core::PayloadType::TextMessage as u8 {
                        if let Ok(msg) = umsh_text::parse_text_message(rest) {
                            let alias = self.peer_alias_display(&from);
                            let mut line: HString<EVENT_LINE_MAX> = HString::new();
                            let _ = write!(&mut line, "<{}> {}", alias, msg.body);
                            self.out.write_line(&line).await?;
                            if self.settings.show_hex {
                                let mut hex: HString<EVENT_LINE_MAX> = HString::new();
                                let _ = write!(&mut hex, "  hex:");
                                for b in prefix.iter() {
                                    let _ = write!(&mut hex, " {:02x}", b);
                                }
                                self.out.write_line(&hex).await?;
                            }
                            return Ok(());
                        }
                    }
                }
                // Unknown payload — show origin + hint.
                let alias = self.peer_alias_display(&from);
                let mut line: HString<EVENT_LINE_MAX> = HString::new();
                let _ = write!(
                    &mut line,
                    "[pkt from {} rssi={:?} snr={:?}]",
                    alias, rssi, snr
                );
                self.out.write_line(&line).await?;
            }

            CliEvent::AckReceived { peer } => {
                let alias = self.peer_alias_display(&peer);
                let mut line: HString<EVENT_LINE_MAX> = HString::new();
                let _ = write!(&mut line, "[ack from {}]", alias);
                self.out.write_line(&line).await?;
            }

            CliEvent::AckTimeout { peer } => {
                let alias = self.peer_alias_display(&peer);
                let mut line: HString<EVENT_LINE_MAX> = HString::new();
                let _ = write!(&mut line, "[ack timeout → {}]", alias);
                self.out.write_line(&line).await?;
            }

            CliEvent::NodeDiscovered { from, name } => {
                let alias = self.peer_alias_display(&from);
                let mut line: HString<EVENT_LINE_MAX> = HString::new();
                let _ = write!(
                    &mut line,
                    "[node discovered: {}{}]",
                    alias,
                    name.as_deref().unwrap_or(""),
                );
                self.out.write_line(&line).await?;
            }

            CliEvent::Beacon { hint, from } => {
                let mut line: HString<EVENT_LINE_MAX> = HString::new();
                match from {
                    Some(key) => {
                        let alias = self.peer_alias_display(&key);
                        let _ = write!(&mut line, "[beacon from {}]", alias);
                    }
                    None => {
                        // Hint-only beacon (sender didn't include the full pubkey).
                        let _ = write!(
                            &mut line,
                            "[beacon hint:{:02x}{:02x}{:02x}]",
                            hint.0[0], hint.0[1], hint.0[2],
                        );
                    }
                }
                self.out.write_line(&line).await?;
            }

            CliEvent::PfsEstablished { peer } => {
                let alias = self.peer_alias_display(&peer);
                let mut line: HString<EVENT_LINE_MAX> = HString::new();
                let _ = write!(&mut line, "[pfs established with {}]", alias);
                self.out.write_line(&line).await?;
            }

            CliEvent::PfsEnded { peer } => {
                let alias = self.peer_alias_display(&peer);
                let mut line: HString<EVENT_LINE_MAX> = HString::new();
                let _ = write!(&mut line, "[pfs ended with {}]", alias);
                self.out.write_line(&line).await?;
            }

            CliEvent::EchoResponseIn { peer, data } => {
                // Match against a pending ping and compute RTT.
                let now_ms = self.node_now_ms();
                let nonce = if data.len() >= 2 {
                    u16::from_be_bytes([data[0], data[1]])
                } else {
                    0
                };
                let matched = {
                    let mut pings = self.pending_pings.borrow_mut();
                    if let Some(idx) = pings
                        .iter()
                        .position(|p| p.nonce == nonce && p.peer == peer)
                    {
                        Some(pings.swap_remove(idx))
                    } else {
                        None
                    }
                };
                let alias = self.peer_alias_display(&peer);
                let mut line: HString<EVENT_LINE_MAX> = HString::new();
                if let Some(ping) = matched {
                    let rtt = now_ms.saturating_sub(ping.sent_at_ms);
                    let _ = write!(&mut line, "pong {} rtt={} ms", alias, rtt);
                } else {
                    let _ = write!(&mut line, "pong {} (unmatched nonce {})", alias, nonce);
                }
                self.out.write_line(&line).await?;
            }

            CliEvent::UnknownMacCmdIn { peer, cmd_id } => {
                let alias = self.peer_alias_display(&peer);
                let mut line: HString<EVENT_LINE_MAX> = HString::new();
                let _ = write!(&mut line, "[mac cmd 0x{:02x} from {}]", cmd_id, alias);
                self.out.write_line(&line).await?;
            }

            CliEvent::OutputLine { line } => {
                self.out.write_line(&line).await?;
            }

            // Outbound variants are dead in this implementation — `execute()`
            // calls MAC I/O directly and never pushes these. See the TODO in
            // `events.rs` for context on the intended future model.
            CliEvent::SendText { .. }
            | CliEvent::SendPing { .. }
            | CliEvent::StartPfs { .. }
            | CliEvent::EndPfs { .. }
            | CliEvent::ChannelSend { .. }
            | CliEvent::SendBeacon
            | CliEvent::SendRaw { .. } => {}
        }
        Ok(())
    }

    // ─── Command dispatcher ──────────────────────────────────────────────────

    async fn execute(&mut self, cmd: Command<'_>) -> Result<ExecOutcome, CliError<OUT::Error>> {
        match cmd {
            Command::Quit => Ok(ExecOutcome::Quit),
            Command::Help(topic) => self.cmd_help(topic).await.map(|_| ExecOutcome::Continue),
            Command::WhoAmI => self.cmd_whoami().await.map(|_| ExecOutcome::Continue),
            Command::PeerAdd { pubkey, alias } => self
                .cmd_peer_add(pubkey, alias)
                .await
                .map(|_| ExecOutcome::Continue),
            Command::PeerRm { peer } => self.cmd_peer_rm(peer).await.map(|_| ExecOutcome::Continue),
            Command::Peers => self.cmd_peers().await.map(|_| ExecOutcome::Continue),
            Command::Query { peer } => self.cmd_query(peer).await.map(|_| ExecOutcome::Continue),
            Command::Set { var, val } => {
                self.cmd_set(var, val).await.map(|_| ExecOutcome::Continue)
            }
            Command::SetShow => self.cmd_set_show().await.map(|_| ExecOutcome::Continue),
            Command::Log { level } => self.cmd_log(level).await.map(|_| ExecOutcome::Continue),
            Command::Stats => self.cmd_stats().await.map(|_| ExecOutcome::Continue),
            Command::Channels => self.cmd_channels().await.map(|_| ExecOutcome::Continue),
            Command::PfsStatus { peer } => self
                .cmd_pfs_status(peer)
                .await
                .map(|_| ExecOutcome::Continue),
            Command::Msg { peer, text } => self
                .cmd_msg(peer, text)
                .await
                .map(|_| ExecOutcome::Continue),
            Command::Text { body } => self.cmd_text(body).await.map(|_| ExecOutcome::Continue),
            Command::Me { action } => self.cmd_me(action).await.map(|_| ExecOutcome::Continue),
            Command::Ping { peer, bytes } => self
                .cmd_ping(peer, bytes)
                .await
                .map(|_| ExecOutcome::Continue),
            Command::PfsStart { peer, minutes } => self
                .cmd_pfs_start(peer, minutes)
                .await
                .map(|_| ExecOutcome::Continue),
            Command::PfsEnd { peer } => self.cmd_pfs_end(peer).await.map(|_| ExecOutcome::Continue),
            Command::Beacon => self.cmd_beacon().await.map(|_| ExecOutcome::Continue),
            Command::ChannelJoin { name, key } => self
                .cmd_channel_join(name, key)
                .await
                .map(|_| ExecOutcome::Continue),
            Command::ChannelLeave { name } => self
                .cmd_channel_leave(name)
                .await
                .map(|_| ExecOutcome::Continue),
            Command::ChannelSend { name, text } => self
                .cmd_channel_send(name, text)
                .await
                .map(|_| ExecOutcome::Continue),
            Command::Raw { peer, hex } => {
                self.cmd_raw(peer, hex).await.map(|_| ExecOutcome::Continue)
            }
        }
    }

    // ─── Local-state commands ────────────────────────────────────────────────

    async fn cmd_help(&mut self, topic: Option<&str>) -> Result<(), CliError<OUT::Error>> {
        if let Some(t) = topic {
            return self.cmd_help_topic(t).await;
        }
        let lines: &[&str] = &[
            "session:",
            "  /help [command]             show help, or detailed help for <command>",
            "  /quit                       exit the CLI",
            "  /whoami                     print the local public key",
            "  /log <level>                set verbosity: error|warn|info|debug|trace",
            "",
            "peers:",
            "  /peer add <pubkey> [alias]  register a peer (base58/base64/hex, 32 bytes)",
            "  /peer rm <peer-ref>         remove a peer",
            "  /peers                      list registered peers",
            "  /query <peer-ref>           set the current peer for bare text",
            "",
            "messaging:",
            "  /msg <peer-ref> <text>      send text to peer",
            "  <text>                      bare text goes to the current peer",
            "  /me <action>                emote (e.g. /me waves)",
            "  /raw <peer-ref> <hex>       send raw hex payload bytes",
            "",
            "diagnostics:",
            "  /ping <peer-ref> [bytes]    send an EchoRequest (default 8 bytes)",
            "  /beacon                     broadcast a beacon",
            "  /stats                      show TX/RX counters, RSSI, queue depth",
            "",
            "pfs (perfect forward secrecy):",
            "  /pfs start <peer-ref> [min] request a PFS session (default 60 min)",
            "  /pfs end <peer-ref>         end a PFS session",
            "  /pfs status [peer-ref]      show PFS session state",
            "",
            "channels:",
            "  /channel join <name> <key>  join a channel (key is base58)",
            "  /channel leave <name>       leave a channel",
            "  /channel send <name> <txt>  send multicast text",
            "  /channels                   list joined channels",
            "",
            "settings:",
            "  /set                        show current settings",
            "  /set <var> <val>            flood_hops|ack_requested|show_hex",
        ];
        for l in lines {
            self.out.write_line(l).await?;
        }
        Ok(())
    }

    async fn cmd_help_topic(&mut self, topic: &str) -> Result<(), CliError<OUT::Error>> {
        let t = topic.trim().trim_start_matches('/');
        let detail: &[&str] = match t {
            "quit" => &["/quit — exit the CLI (EOF does the same)."],
            "help" => &[
                "/help [command] — list all commands, or show detailed help for one.",
                "  example: /help ping",
            ],
            "whoami" => &["/whoami — print the local public key as hex."],
            "log" => &[
                "/log <level> — set log verbosity.",
                "  levels: error, warn, info, debug, trace",
            ],
            "peer" => &[
                "/peer add <pubkey> [alias] — register a peer.",
                "  <pubkey> accepts base58, base64, or hex (32-byte Ed25519 key).",
                "  Also registers the peer at the MAC layer so inbound frames validate.",
                "/peer rm <peer-ref> — remove a peer. <peer-ref> is an alias or full key.",
            ],
            "peers" => &["/peers — list registered peers: alias and key hint."],
            "query" => &[
                "/query <peer-ref> — set the current peer for bare-text sends.",
                "  After /query bob, a bare line is sent to bob as a text message.",
            ],
            "msg" => &["/msg <peer-ref> <text> — send a text message to a peer."],
            "me" => &[
                "/me <action> — send an emote to the current peer.",
                "  example: /me waves  →  sent as \"* waves\"",
            ],
            "raw" => &[
                "/raw <peer-ref> <hex> — send raw payload bytes as a unicast packet.",
                "  <hex> is an even-length hex string (no 0x prefix, no spaces).",
            ],
            "ping" => &[
                "/ping <peer-ref> [bytes] — send a MAC-level EchoRequest.",
                "  [bytes] is the total payload size (2..=60, default 8).",
                "  The first 2 bytes are a nonce used to match the response.",
                "  Prints \"pong <peer> rtt=<ms>\" when the reply arrives.",
            ],
            "beacon" => &["/beacon — broadcast a beacon frame announcing this node."],
            "stats" => &[
                "/stats — print counters maintained by the CLI.",
                "  TX/RX packets, ACK outcomes, last RSSI/SNR, event-queue depth,",
                "  and events_dropped (non-zero if the inbound queue overflowed).",
            ],
            "pfs" => &[
                "/pfs start <peer-ref> [minutes] — request a PFS session.",
                "  [minutes] is the requested lifetime (default 60).",
                "/pfs end <peer-ref> — tear down an active PFS session.",
                "/pfs status [peer-ref] — show PFS state for one peer or all.",
            ],
            "channel" | "channels" => &[
                "/channel join <name> <key-b58> — bind a channel by name + shared key.",
                "/channel leave <name> — leave a channel.",
                "/channel send <name> <text> — send a multicast text message.",
                "/channels — list currently joined channels.",
            ],
            "set" => &[
                "/set — show current CLI-local settings.",
                "/set <var> <val> — change one setting (resets on exit).",
                "  flood_hops     u8 in 0..=15 (default 5) — FHOPS_REM on outbound sends",
                "  ack_requested  bool (default true)     — request MAC acks on unicast",
                "  show_hex       bool (default false)    — also print inbound bytes as hex",
            ],
            other => {
                let mut msg: HString<EVENT_LINE_MAX> = HString::new();
                let _ = write!(
                    &mut msg,
                    "no help for '{}' — try /help for the full list",
                    other
                );
                return self.write_err(&msg).await;
            }
        };
        for l in detail {
            self.out.write_line(l).await?;
        }
        Ok(())
    }

    async fn cmd_whoami(&mut self) -> Result<(), CliError<OUT::Error>> {
        let mut line: HString<EVENT_LINE_MAX> = HString::new();
        let _ = write!(&mut line, "local: ");
        for b in &self.local_key.0 {
            let _ = write!(&mut line, "{:02x}", b);
        }
        self.out.write_line(&line).await?;
        Ok(())
    }

    async fn cmd_peer_add(
        &mut self,
        pubkey: &str,
        alias: Option<&str>,
    ) -> Result<(), CliError<OUT::Error>> {
        let key = match crate::peer_ref::try_parse_pubkey(pubkey) {
            Some(k) => k,
            None => return self.write_err("invalid pubkey").await,
        };
        let alias_heap = match alias {
            Some(a) => match HString::<16>::try_from(a) {
                Ok(s) => Some(s),
                Err(_) => return self.write_err("alias too long (max 16 chars)").await,
            },
            None => None,
        };
        if self.peers.contains_key(&key) {
            return self.write_err("peer already registered").await;
        }
        if self
            .peers
            .insert(
                key,
                PeerEntry {
                    key,
                    alias: alias_heap.clone(),
                },
            )
            .is_err()
        {
            return self.write_err("peer table full").await;
        }
        if let Some(a) = alias_heap.clone() {
            if self.aliases.insert(a, key).is_err() {
                let _ = self.peers.remove(&key);
                return self.write_err("alias table full").await;
            }
        }
        // Register at MAC layer so inbound frames from this peer validate.
        if let Err(e) = self.node.peer(key).await {
            let _ = self.peers.remove(&key);
            if let Some(a) = alias_heap {
                let _ = self.aliases.remove(&a);
            }
            let msg = node_err_str(&e);
            return self.write_err(&msg).await;
        }
        self.out.write_line("ok").await?;
        Ok(())
    }

    async fn cmd_peer_rm(&mut self, peer: &str) -> Result<(), CliError<OUT::Error>> {
        let Some(key) = self.resolve_peer(peer) else {
            return self.write_err("unknown peer").await;
        };
        let entry = match self.peers.remove(&key) {
            Some(e) => e,
            None => return self.write_err("peer not in table").await,
        };
        if let Some(a) = entry.alias {
            let _ = self.aliases.remove(&a);
        }
        if self.current_peer == Some(key) {
            self.current_peer = None;
        }
        self.out.write_line("ok").await?;
        Ok(())
    }

    async fn cmd_peers(&mut self) -> Result<(), CliError<OUT::Error>> {
        if self.peers.is_empty() {
            self.out.write_line("(no peers)").await?;
            return Ok(());
        }
        let mut lines: Vec<String> = Vec::new();
        for (_k, entry) in self.peers.iter() {
            let mut line: HString<EVENT_LINE_MAX> = HString::new();
            let alias = entry.alias.as_deref().unwrap_or("-");
            let _ = write!(&mut line, "{:16} ", alias);
            for b in entry.key.0.iter().take(6) {
                let _ = write!(&mut line, "{:02x}", b);
            }
            lines.push(String::from(line.as_str()));
        }
        for l in lines {
            self.out.write_line(&l).await?;
        }
        Ok(())
    }

    async fn cmd_query(&mut self, peer: &str) -> Result<(), CliError<OUT::Error>> {
        let Some(key) = self.resolve_peer(peer) else {
            return self.write_err("unknown peer").await;
        };
        self.current_peer = Some(key);
        self.out.write_line("ok").await?;
        Ok(())
    }

    async fn cmd_set_show(&mut self) -> Result<(), CliError<OUT::Error>> {
        let mut line: HString<EVENT_LINE_MAX> = HString::new();
        let _ = write!(
            &mut line,
            "flood_hops={} ack_requested={} show_hex={}",
            self.settings.flood_hops, self.settings.ack_requested, self.settings.show_hex,
        );
        self.out.write_line(&line).await?;
        Ok(())
    }

    async fn cmd_set(&mut self, var: &str, val: &str) -> Result<(), CliError<OUT::Error>> {
        match var {
            "flood_hops" => match val.parse::<u8>() {
                Ok(v) if v <= 15 => {
                    self.settings.flood_hops = v;
                    self.out.write_line("ok").await?;
                }
                _ => self.write_err("flood_hops must be 0..=15").await?,
            },
            "ack_requested" => match parse_bool(val) {
                Some(b) => {
                    self.settings.ack_requested = b;
                    self.out.write_line("ok").await?;
                }
                None => self.write_err("ack_requested: expected true|false").await?,
            },
            "show_hex" => match parse_bool(val) {
                Some(b) => {
                    self.settings.show_hex = b;
                    self.out.write_line("ok").await?;
                }
                None => self.write_err("show_hex: expected true|false").await?,
            },
            _ => {
                self.write_err("unknown setting (flood_hops / ack_requested / show_hex)")
                    .await?
            }
        }
        Ok(())
    }

    async fn cmd_log(&mut self, level: &str) -> Result<(), CliError<OUT::Error>> {
        let lvl = match level {
            "error" => LogLevel::Error,
            "warn" => LogLevel::Warn,
            "info" => LogLevel::Info,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => return self.write_err("level: error|warn|info|debug|trace").await,
        };
        self.logger.set_level(lvl);
        self.out.write_line("ok").await?;
        Ok(())
    }

    async fn cmd_stats(&mut self) -> Result<(), CliError<OUT::Error>> {
        let s = self.stats.borrow().clone();
        let dropped = *self.events_dropped.borrow();
        let depth = self.events.borrow().len();
        let mut line: HString<EVENT_LINE_MAX> = HString::new();
        let _ = write!(
            &mut line,
            "rx={} tx={} ack_ok={} ack_timeout={} beacons={} discovered={} \
             event_depth={} dropped_events={}",
            s.packets_rx,
            s.packets_tx,
            s.acks_ok,
            s.acks_timeout,
            s.beacons_rx,
            s.nodes_discovered,
            depth,
            dropped,
        );
        self.out.write_line(&line).await?;
        if let Some(rssi) = s.last_rssi {
            let mut line: HString<EVENT_LINE_MAX> = HString::new();
            let _ = write!(&mut line, "last_rssi={} last_snr={:?}", rssi, s.last_snr);
            self.out.write_line(&line).await?;
        }
        Ok(())
    }

    async fn cmd_channels(&mut self) -> Result<(), CliError<OUT::Error>> {
        if self.channels.is_empty() {
            self.out.write_line("(no channels)").await?;
            return Ok(());
        }
        let mut lines: Vec<String> = Vec::new();
        for (_k, entry) in self.channels.iter() {
            lines.push(String::from(entry.name.as_str()));
        }
        for l in lines {
            self.out.write_line(&l).await?;
        }
        Ok(())
    }

    // ─── Async MAC-I/O commands ──────────────────────────────────────────────

    async fn cmd_msg(&mut self, peer: &str, text: &str) -> Result<(), CliError<OUT::Error>> {
        let Some(key) = self.resolve_peer(peer) else {
            return self.write_err("unknown peer").await;
        };
        let pc = match self.node.peer(key).await {
            Ok(p) => p,
            Err(e) => return self.write_err(&node_err_str(&e)).await,
        };
        let chat = UnicastTextChatWrapper::from_peer(&pc);
        let opts = self.send_opts();
        match chat.send_text(text, &opts).await {
            Ok(_) => {
                self.stats.borrow_mut().packets_tx += 1;
                self.out.write_line("ok").await?;
            }
            Err(e) => {
                self.write_err(&alloc::format!("{:?}", e)).await?;
            }
        }
        Ok(())
    }

    async fn cmd_text(&mut self, body: &str) -> Result<(), CliError<OUT::Error>> {
        let key = match self.current_peer {
            Some(k) => k,
            None => {
                return self
                    .write_err("no current peer — use /query <peer-ref> first")
                    .await;
            }
        };
        let pc = match self.node.peer(key).await {
            Ok(p) => p,
            Err(e) => return self.write_err(&node_err_str(&e)).await,
        };
        let chat = UnicastTextChatWrapper::from_peer(&pc);
        let opts = self.send_opts();
        match chat.send_text(body, &opts).await {
            Ok(_) => {
                self.stats.borrow_mut().packets_tx += 1;
            }
            Err(e) => {
                self.write_err(&alloc::format!("{:?}", e)).await?;
            }
        }
        Ok(())
    }

    async fn cmd_me(&mut self, action: &str) -> Result<(), CliError<OUT::Error>> {
        let mut body: HString<EVENT_LINE_MAX> = HString::new();
        let _ = write!(&mut body, "* {}", action);
        let owned = String::from(body.as_str());
        // Send as a bare text line directed at current peer.
        self.cmd_text(&owned).await
    }

    async fn cmd_ping(
        &mut self,
        peer: &str,
        bytes: Option<u16>,
    ) -> Result<(), CliError<OUT::Error>> {
        let Some(key) = self.resolve_peer(peer) else {
            return self.write_err("unknown peer").await;
        };
        let pc = match self.node.peer(key).await {
            Ok(p) => p,
            Err(e) => return self.write_err(&node_err_str(&e)).await,
        };
        // Generate nonce.
        let nonce: u16 = simple_nonce();
        let size = bytes.unwrap_or(8).min(60) as usize;
        let mut data: HVec<u8, 64> = HVec::new();
        let _ = data.extend_from_slice(&nonce.to_be_bytes());
        for _ in 2..size {
            let _ = data.push(0xA5);
        }

        // Record pending ping. Check capacity without holding the borrow
        // across the write_err call.
        if self.pending_pings.borrow().is_full() {
            return self.write_err("too many pings in flight").await;
        }
        let now_ms = self.node_now_ms();
        let alias = self.peers.get(&key).and_then(|e| e.alias.clone());
        let _ = self.pending_pings.borrow_mut().push(PendingPing {
            nonce,
            peer: key,
            alias,
            sent_at_ms: now_ms,
        });

        // Send EchoRequest. The EchoResponse itself is the logical ack, so
        // don't also request a MAC-layer ack — that would double-count and
        // would print spurious `[ack from ...]` lines alongside the pong.
        let mut out = [0u8; 128];
        let cmd = umsh_node::MacCommand::EchoRequest { data: &data };
        match encode_mac_command(&cmd, &mut out) {
            Ok(n) => {
                let opts = self.send_opts().with_ack_requested(false);
                match pc.send(&out[..n], &opts).await {
                    Ok(_) => {
                        self.stats.borrow_mut().packets_tx += 1;
                        let alias_str = self.peer_alias_display(&key);
                        let mut line: HString<EVENT_LINE_MAX> = HString::new();
                        let _ = write!(&mut line, "ping {} ({} bytes)", alias_str, data.len());
                        self.out.write_line(&line).await?;
                    }
                    Err(e) => {
                        // Remove the pending ping on send failure; drop borrow before write_err.
                        {
                            let mut pings = self.pending_pings.borrow_mut();
                            if let Some(idx) = pings.iter().position(|p| p.nonce == nonce) {
                                pings.swap_remove(idx);
                            }
                        }
                        let msg = node_err_str(&e);
                        self.write_err(&msg).await?;
                    }
                }
            }
            Err(e) => {
                {
                    let mut pings = self.pending_pings.borrow_mut();
                    if let Some(idx) = pings.iter().position(|p| p.nonce == nonce) {
                        pings.swap_remove(idx);
                    }
                }
                let msg = alloc::format!("{:?}", e);
                self.write_err(&msg).await?;
            }
        }
        Ok(())
    }

    async fn cmd_pfs_start(
        &mut self,
        peer: &str,
        minutes: Option<u16>,
    ) -> Result<(), CliError<OUT::Error>> {
        #[cfg(feature = "software-crypto")]
        {
            let Some(key) = self.resolve_peer(peer) else {
                return self.write_err("unknown peer").await;
            };
            let minutes = minutes.unwrap_or(60);
            let opts = self.send_opts();
            match self.node.request_pfs(&key, minutes, &opts).await {
                Ok(_) => self.out.write_line("pfs request sent").await?,
                Err(e) => self.write_err(&node_err_str(&e)).await?,
            }
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            let _ = (peer, minutes);
            self.write_err("pfs requires software-crypto feature")
                .await?;
        }
        Ok(())
    }

    async fn cmd_pfs_end(&mut self, peer: &str) -> Result<(), CliError<OUT::Error>> {
        #[cfg(feature = "software-crypto")]
        {
            let Some(key) = self.resolve_peer(peer) else {
                return self.write_err("unknown peer").await;
            };
            let opts = self.send_opts();
            match self.node.end_pfs(&key, &opts).await {
                Ok(_) => self.out.write_line("pfs ended").await?,
                Err(e) => self.write_err(&node_err_str(&e)).await?,
            }
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            let _ = peer;
            self.write_err("pfs requires software-crypto feature")
                .await?;
        }
        Ok(())
    }

    async fn cmd_pfs_status(&mut self, peer: Option<&str>) -> Result<(), CliError<OUT::Error>> {
        #[cfg(feature = "software-crypto")]
        {
            let targets: Vec<PublicKey> = match peer {
                Some(r) => match self.resolve_peer(r) {
                    Some(k) => alloc::vec![k],
                    None => return self.write_err("unknown peer").await,
                },
                None => self.peers.keys().copied().collect(),
            };
            for key in targets {
                // Compute owned values before write_line to avoid borrow conflicts.
                let result = self.node.pfs_status(&key).await;
                let alias = self.peer_alias_display(&key);
                match result {
                    Ok(s) => {
                        let mut line: HString<EVENT_LINE_MAX> = HString::new();
                        let _ = write!(&mut line, "{}: {:?}", alias, s);
                        self.out.write_line(&line).await?;
                    }
                    Err(e) => {
                        let msg = node_err_str(&e);
                        self.write_err(&msg).await?;
                    }
                }
            }
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            let _ = peer;
            self.write_err("pfs requires software-crypto feature")
                .await?;
        }
        Ok(())
    }

    async fn cmd_beacon(&mut self) -> Result<(), CliError<OUT::Error>> {
        // A beacon is an empty-payload broadcast. The MAC silently ignores
        // the `encrypted` / `ack_requested` flags for broadcasts, so reusing
        // `send_opts()` is fine.
        use umsh_node::Transport as _;
        let opts = self.send_opts();
        match self.node.send_all(&[], &opts).await {
            Ok(_) => {
                self.stats.borrow_mut().packets_tx += 1;
                self.out.write_line("beacon sent").await?;
            }
            Err(e) => self.write_err(&node_err_str(&e)).await?,
        }
        Ok(())
    }

    async fn cmd_channel_join(
        &mut self,
        name: &str,
        _key_b58: &str,
    ) -> Result<(), CliError<OUT::Error>> {
        #[cfg(feature = "software-crypto")]
        {
            let hname = match HString::<16>::try_from(name) {
                Ok(s) => s,
                Err(_) => return self.write_err("channel name too long (max 16 chars)").await,
            };
            if self.channels.contains_key(&hname) {
                return self.write_err("already joined").await;
            }
            // Decode the b58 channel key.
            let mut key_bytes = [0u8; 32];
            match bs58::decode(_key_b58).onto(&mut key_bytes[..]) {
                Ok(32) => {}
                _ => {
                    return self
                        .write_err("key must be base58-encoded 32-byte channel key")
                        .await;
                }
            }
            let channel_key = umsh_core::ChannelKey(key_bytes);
            let channel = umsh_node::Channel::private(channel_key, name);
            match self.node.join(&channel).await {
                Ok(_) => {
                    let entry = ChannelEntry {
                        name: HString::try_from(name).unwrap(),
                        key_bytes,
                    };
                    if self.channels.insert(hname, entry).is_err() {
                        let _ = self.node.leave(&channel);
                        return self.write_err("channel table full").await;
                    }
                    self.out.write_line("joined").await?;
                }
                Err(e) => self.write_err(&node_err_str(&e)).await?,
            }
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            let _ = (name, _key_b58);
            self.write_err("channels require software-crypto feature")
                .await?;
        }
        Ok(())
    }

    async fn cmd_channel_leave(&mut self, name: &str) -> Result<(), CliError<OUT::Error>> {
        #[cfg(feature = "software-crypto")]
        {
            let hname = match HString::<16>::try_from(name) {
                Ok(s) => s,
                Err(_) => return self.write_err("unknown channel").await,
            };
            let key_bytes = match self.channels.remove(&hname) {
                Some(e) => e.key_bytes,
                None => return self.write_err("not joined to that channel").await,
            };
            let channel_key = umsh_core::ChannelKey(key_bytes);
            let channel = umsh_node::Channel::private(channel_key, name);
            let _ = self.node.leave(&channel);
            self.out.write_line("left").await?;
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            let _ = name;
            self.write_err("channels require software-crypto feature")
                .await?;
        }
        Ok(())
    }

    async fn cmd_channel_send(
        &mut self,
        name: &str,
        text: &str,
    ) -> Result<(), CliError<OUT::Error>> {
        #[cfg(feature = "software-crypto")]
        {
            let hname = match HString::<16>::try_from(name) {
                Ok(s) => s,
                Err(_) => return self.write_err("unknown channel").await,
            };
            let key_bytes = match self.channels.get(&hname) {
                Some(e) => e.key_bytes,
                None => return self.write_err("not joined to that channel").await,
            };
            let channel_key = umsh_core::ChannelKey(key_bytes);
            let channel = umsh_node::Channel::private(channel_key, name);
            let bound = match self.node.bound_channel(&channel) {
                Some(b) => b,
                None => return self.write_err("channel no longer active").await,
            };
            let wrapper = umsh_text::MulticastTextChatWrapper::new(bound);
            let opts = self.send_opts();
            match wrapper.send_text(text, &opts).await {
                Ok(_) => {
                    self.stats.borrow_mut().packets_tx += 1;
                    self.out.write_line("ok").await?;
                }
                Err(e) => self.write_err(&alloc::format!("{:?}", e)).await?,
            }
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            let _ = (name, text);
            self.write_err("channels require software-crypto feature")
                .await?;
        }
        Ok(())
    }

    async fn cmd_raw(&mut self, peer: &str, hex: &str) -> Result<(), CliError<OUT::Error>> {
        let Some(key) = self.resolve_peer(peer) else {
            return self.write_err("unknown peer").await;
        };
        // Decode hex into a bounded buffer.
        let mut bytes: HVec<u8, 128> = HVec::new();
        let hex = hex.trim_start_matches("0x");
        if hex.len() % 2 != 0 {
            return self.write_err("hex must have even length").await;
        }
        for chunk in hex.as_bytes().chunks(2) {
            let hi = hex_nib(chunk[0]);
            let lo = hex_nib(chunk[1]);
            match (hi, lo) {
                (Some(h), Some(l)) => {
                    if bytes.push((h << 4) | l).is_err() {
                        return self.write_err("hex too long (max 128 bytes)").await;
                    }
                }
                _ => return self.write_err("invalid hex digit").await,
            }
        }
        let pc = match self.node.peer(key).await {
            Ok(p) => p,
            Err(e) => return self.write_err(&node_err_str(&e)).await,
        };
        let opts = self.send_opts();
        match pc.send(&bytes, &opts).await {
            Ok(_) => {
                self.stats.borrow_mut().packets_tx += 1;
                if self.settings.show_hex {
                    let mut line: HString<EVENT_LINE_MAX> = HString::new();
                    let _ = write!(&mut line, "sent {} bytes:", bytes.len());
                    for b in bytes.iter() {
                        let _ = write!(&mut line, " {:02x}", b);
                    }
                    self.out.write_line(&line).await?;
                } else {
                    self.out.write_line("ok").await?;
                }
            }
            Err(e) => self.write_err(&node_err_str(&e)).await?,
        }
        Ok(())
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    async fn write_err(&mut self, msg: &str) -> Result<(), CliError<OUT::Error>> {
        let mut line: HString<EVENT_LINE_MAX> = HString::new();
        let _ = write!(&mut line, "error: {}", msg);
        self.out.write_line(&line).await?;
        Ok(())
    }

    fn peer_alias_display(&self, key: &PublicKey) -> String {
        if let Some(entry) = self.peers.get(key) {
            if let Some(a) = &entry.alias {
                return String::from(a.as_str());
            }
        }
        // Fall back to 6-byte hex hint.
        let mut s = String::new();
        for b in key.0.iter().take(6) {
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    fn node_now_ms(&self) -> u64 {
        // LocalNode does not expose a clock accessor; use wall-clock on std
        // targets, or zero on bare-metal (RTT will be inaccurate but harmless).
        #[cfg(feature = "std")]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        }
        #[cfg(not(feature = "std"))]
        0
    }
}

// ─── Subscription wiring (free function to avoid borrow conflicts) ────────────

fn push_event<const N: usize>(
    events: &SharedQueue<Deque<CliEvent, N>>,
    dropped: &SharedQueue<u64>,
    wake: &Rc<AsyncCondition>,
    event: CliEvent,
) {
    let mut q = events.borrow_mut();
    if q.push_back(event).is_err() {
        *dropped.borrow_mut() += 1;
    }
    drop(q);
    wake.trigger();
}

fn register_subscriptions<M, const N: usize>(
    node: &LocalNode<M>,
    events: SharedQueue<Deque<CliEvent, N>>,
    dropped: SharedQueue<u64>,
    stats: SharedQueue<Stats>,
    wake: Rc<AsyncCondition>,
) -> Vec<Subscription>
where
    M: MacBackend,
{
    let mut subs: Vec<Subscription> = Vec::new();

    // on_receive — raw inbound packets
    {
        let ev = events.clone();
        let dr = dropped.clone();
        let st = stats.clone();
        let wk = wake.clone();
        subs.push(node.on_receive(move |pkt| {
            let from = match pkt.from_key() {
                Some(k) => k,
                None => return false,
            };
            let rssi = pkt.rssi().unwrap_or(0);
            let snr = pkt.snr().map(|s| s.as_centibels()).unwrap_or(0);
            let hops = pkt.flood_hops().map(|fh| fh.accumulated()).unwrap_or(0);
            {
                let mut s = st.borrow_mut();
                s.packets_rx += 1;
                s.last_rssi = pkt.rssi();
                s.last_snr = pkt.snr().map(|snr| snr.as_centibels());
            }
            let mut prefix: HVec<u8, 64> = HVec::new();
            let payload = pkt.payload_bytes();
            let n = payload.len().min(64);
            let _ = prefix.extend_from_slice(&payload[..n]);
            push_event(
                &ev,
                &dr,
                &wk,
                CliEvent::Received {
                    from,
                    hops,
                    rssi,
                    snr,
                    prefix,
                },
            );
            false // don't consume — let other handlers see it too
        }));
    }

    // on_ack_received
    {
        let ev = events.clone();
        let dr = dropped.clone();
        let st = stats.clone();
        let wk = wake.clone();
        subs.push(node.on_ack_received(move |peer, _token| {
            st.borrow_mut().acks_ok += 1;
            push_event(&ev, &dr, &wk, CliEvent::AckReceived { peer });
        }));
    }

    // on_ack_timeout
    {
        let ev = events.clone();
        let dr = dropped.clone();
        let st = stats.clone();
        let wk = wake.clone();
        subs.push(node.on_ack_timeout(move |peer, _token| {
            st.borrow_mut().acks_timeout += 1;
            push_event(&ev, &dr, &wk, CliEvent::AckTimeout { peer });
        }));
    }

    // on_node_discovered
    {
        let ev = events.clone();
        let dr = dropped.clone();
        let st = stats.clone();
        let wk = wake.clone();
        subs.push(node.on_node_discovered(move |peer, name| {
            st.borrow_mut().nodes_discovered += 1;
            let name_h = name.and_then(|n| HString::<32>::try_from(n).ok());
            push_event(
                &ev,
                &dr,
                &wk,
                CliEvent::NodeDiscovered {
                    from: peer,
                    name: name_h,
                },
            );
        }));
    }

    // on_beacon
    {
        let ev = events.clone();
        let dr = dropped.clone();
        let st = stats.clone();
        let wk = wake.clone();
        subs.push(node.on_beacon(move |hint, key| {
            st.borrow_mut().beacons_rx += 1;
            push_event(&ev, &dr, &wk, CliEvent::Beacon { hint, from: key });
        }));
    }

    // on_pfs_established
    {
        let ev = events.clone();
        let dr = dropped.clone();
        let wk = wake.clone();
        subs.push(node.on_pfs_established(move |peer| {
            push_event(&ev, &dr, &wk, CliEvent::PfsEstablished { peer });
        }));
    }

    // on_pfs_ended
    {
        let ev = events.clone();
        let dr = dropped.clone();
        let wk = wake.clone();
        subs.push(node.on_pfs_ended(move |peer| {
            push_event(&ev, &dr, &wk, CliEvent::PfsEnded { peer });
        }));
    }

    // on_mac_command — EchoResponse matching only. EchoRequest is auto-replied
    // at the MAC layer (see coordinator::process_received), so surfacing it
    // here would produce a duplicate EchoResponse.
    {
        let ev = events.clone();
        let dr = dropped.clone();
        let wk = wake.clone();
        subs.push(node.on_mac_command(move |peer, cmd| {
            let event = match cmd {
                OwnedMacCommand::EchoRequest { .. } => return,
                OwnedMacCommand::EchoResponse { data } => {
                    let mut v: HVec<u8, 64> = HVec::new();
                    let n = data.len().min(64);
                    let _ = v.extend_from_slice(&data[..n]);
                    CliEvent::EchoResponseIn { peer, data: v }
                }
                other => {
                    let cmd_id = mac_cmd_id(other);
                    CliEvent::UnknownMacCmdIn { peer, cmd_id }
                }
            };
            push_event(&ev, &dr, &wk, event);
        }));
    }

    subs
}

fn mac_cmd_id(cmd: &OwnedMacCommand) -> u8 {
    use umsh_node::CommandId;
    match cmd {
        OwnedMacCommand::BeaconRequest { .. } => CommandId::BeaconRequest as u8,
        OwnedMacCommand::IdentityRequest => CommandId::IdentityRequest as u8,
        OwnedMacCommand::SignalReportRequest => CommandId::SignalReportRequest as u8,
        OwnedMacCommand::SignalReportResponse { .. } => CommandId::SignalReportResponse as u8,
        OwnedMacCommand::EchoRequest { .. } => CommandId::EchoRequest as u8,
        OwnedMacCommand::EchoResponse { .. } => CommandId::EchoResponse as u8,
        OwnedMacCommand::PfsSessionRequest { .. } => CommandId::PfsSessionRequest as u8,
        OwnedMacCommand::PfsSessionResponse { .. } => CommandId::PfsSessionResponse as u8,
        OwnedMacCommand::EndPfsSession => CommandId::EndPfsSession as u8,
    }
}

fn node_err_str<M>(e: &NodeError<M>) -> String
where
    M: MacBackend,
    M::SendError: core::fmt::Debug,
    M::CapacityError: core::fmt::Debug,
{
    alloc::format!("{:?}", e)
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn format_parse_error(e: &ParseError) -> String {
    match e {
        ParseError::Empty => String::from("empty"),
        ParseError::UnknownCommand(name) => {
            let mut s = String::from("unknown command: ");
            s.push_str(name);
            s
        }
        ParseError::MissingArg(n) => {
            let mut s = String::from("missing argument: ");
            s.push_str(n);
            s
        }
        ParseError::BadNumber => String::from("bad number"),
    }
}

fn hex_nib(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

static NONCE_COUNTER: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(1);

fn simple_nonce() -> u16 {
    NONCE_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}
