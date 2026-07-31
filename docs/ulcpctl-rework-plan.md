# ulcpctl rework plan: clap + rustyline, capture folded in

Status: **LANDED (2026-07-30)**, with two departures from the plan as
written, both recorded in the decisions section below: the binary is
named `umshctl`, and the REPL's `provision` re-attach dance is done over
the open link rather than by reconnecting.

Everything below is retained as written — it is the reasoning, not a
checklist. Where the implementation diverged, the decision entry says
so.

## Why

`umsh-ulcpctl` and `umsh-capture` grew organically out of bringup. Both
hand-roll argv parsing (~450 lines of it in ulcpctl alone), each has its
own transport-selection grammar (`<port> <command>` vs `<port>
[options]`, `--ble=SEL` vs `--ble [SEL]`), help is a hand-maintained
`USAGE` string, and every invocation pays a fresh attach — which over
BLE means a discovery pass plus ~300 ms handshake *per command*. There
is no completion, no history, and no way to run several commands
against one session.

`msecretctl` (`../msecret/src/tool/main.rs`) demonstrates the shape we
want: a single clap `Subcommand` tree that is simultaneously

1. the one-shot argv grammar (`msecret ecc public p256`),
2. the REPL line grammar (each line re-parsed with
   `try_parse_from` after `shellwords::split`),
3. the source of `help` output at every level, and
4. the completion tree for rustyline tab completion (the completer
   walks `clap::Command` at runtime).

One definition, four surfaces. This plan transitions `umsh-ulcpctl` to
that shape and absorbs `umsh-capture` as a `capture` subcommand, ending
with **one host tool for ULCP devices**.

## Goals

- One clap-derived command tree; delete both hand parsers and both
  `USAGE` strings.
- `umsh-ulcpctl <connection> <command>` works one-shot exactly as
  today (modulo the grammar cleanups below).
- `umsh-ulcpctl <connection>` with no command drops into a rustyline
  REPL: **one attach, many commands**, tab completion, persistent
  history, `❌`-prefixed prompt after an error (msecretctl behavior).
- `umsh-capture` functionality becomes `umsh-ulcpctl capture`; the
  separate binary is deleted.
- Shared output layer: the key/value report style of `info`, the
  color discipline of capture (`--color=auto`, `NO_COLOR`, `TERM=dumb`)
  and the field-tinted hex dump all live in one module with one style.
- The non-negotiables survive intact: administrative (non-disturbing)
  attach for everything except `provision`; auto-save after mutating
  commands unless `--no-save`; `factory-reset` cannot run
  unconfirmed; secrets never echoed; capture stays promiscuous
  (session-scoped `PROP_MAC_PROMISCUOUS`, reverts on detach).

Non-goals: no ULCP protocol changes, no new device capabilities, no
changes to `umsh-cli`/`umsh-app-ulcp-cli` (the *on-device* console is a
different animal), no web-debugger changes.

## Command-line shape

### Connection selection (global args)

Today the transport is a magic first positional. Replace with proper
global flags so they work identically one-shot and when entering the
REPL, and so clap can generate help for them:

```
umsh-ulcpctl [-p PORT | -b[=SELECTOR]] [--baud N] [--trace] [--color WHEN] [COMMAND ...]
```

- `-p, --port <PORT>` — serial.
- `-b, --ble[=SELECTOR]` — BLE, selector optional (name or scan id).
  The selector **must** be declared `require_equals = true`
  (msecretctl does the same for `--passphrase`): a space-separated
  optional value would make clap eat the following subcommand as the
  selector (`--ble info` → selector `"info"`, no command, REPL). So:
  bare `--ble` = "BLE, discover/choose"; `--ble=T-Echo` = that radio.
- `UMSH_ULCPCTL_PORT` env fallback for `--port` (clap `env = ...`),
  so a bench session doesn't repeat the port on every invocation.
- `--baud`, `--trace` stay global. `--no-save` becomes global too (it
  applies uniformly to mutating commands; clap can't easily express
  "only on mutating subcommands" and the current per-command
  restriction buys little). `--color auto|always|never` is promoted
  from capture to global: the shared output layer consults it
  everywhere (`NO_COLOR` / `TERM=dumb` / non-TTY honored as today).
- `--scan-ble` becomes a first-class `scan` subcommand
  (`scan [--timeout SECS]`), shared verbatim between the old two tools
  today anyway.

### No connection specified: discover and choose

When neither `--port` nor `--ble` is given, the tool finds the device
itself. **Serial is never auto-detected or probed** — the bench has
plenty of `usbmodem`/`usbserial` devices that are not ULCP, the only
way to verify one is to open it and speak (and opening ports has side
effects: DTR toggles reset some boards, and a 1200-baud touch is this
very repo's DFU trigger). Serial happens only when explicitly named
via `--port`/env. BLE discovery, by contrast, is passive and filtered
to companion radios advertising the UMSH service, so it cannot land on
a foreign device. Precedence:

1. **Explicit flags / env var** — always win.
2. **Saved default device** (see the `default` command below): a
   targeted BLE scan that connects the moment the saved radio appears
   (typically well under the window). Not seen within ~5 s → print a
   note ("default 'T-Echo' not found") and fall through to general
   discovery; a stale preference costs one line, not a dead tool.
3. **General BLE discovery, 2 s window.** Evaluate at 2 s:
   - exactly one companion radio → connect to it;
   - more than one → interactive chooser;
   - none → keep scanning quietly up to ~5 s (power-conscious boards
     can straddle a 2 s advertising window), then give up: one-shot
     mode errors, REPL mode enters `(unattached)>`.
4. **Every automatic selection is announced** (name + id + transport,
   to stderr) before any command runs, so a mutating one-shot never
   acts on a silently-chosen device.

The saved default is set **explicitly, never implicitly** — a one-off
`connect` to a bench unit must not silently become tomorrow's default.
`default set` in an attached REPL saves the current device;
`default set <SELECTOR>`, `default show`, `default clear` work
anywhere. The preference stores the BLE id (primary) *and* the device
name (fallback + display — macOS peripheral UUIDs can churn on a
Bluetooth cache reset), in a config file beside the REPL history —
trivial `setting = value` lines parsed like the provision file, no new
dependency. A saved default also makes non-TTY scripting deterministic
without env vars.

Chooser rules: numbered list showing name, id, RSSI; **sorted stably
by name with id tiebreak — never by RSSI** (RSSI jitter reorders the
list between scans; this is the iOS RadioPicker sort-bug lesson).
Input is a plain number via rustyline. The chooser only appears when
stdin is a TTY; multiple candidates in a non-TTY one-shot invocation
are an error listing the candidates, so scripts fail loud instead of
hanging on a prompt. Scripts that need determinism pass `--port`/
`--ble` or set the env var, as ever.

`scan`, the launch flow, and the REPL's bare `connect` share one
scan/sort/render routine in `connection.rs` — but they end
differently: `scan` stops at the numbered listing (the REPL retains
that listing so a later `connect <N>` can reference it), while the
launch flow and bare `connect` continue into choose-and-attach.

### Command tree

Almost 1:1 with today's commands, expressed as nested
`#[derive(Subcommand)]` enums (each family gets its own module, like
msecretctl's `command/` directory):

```
info [--expect-host-key KEY]
provision [--host-key ... --channel-key ... --peer ... --filter ...
           --auto-ack on|off --file PATH --force]
identity [show | generate]           (bare `identity` = show)
name [NEW-NAME]                      (bare = show; replaces set-name)
save | restore | clear | reset
factory-reset [--yes]                (one-shot: --yes required;
                                      REPL: interactive y/N prompt)
pin <6-DIGITS | clear>
phy [show | on | off | freq KHZ | sf N | bw HZ | cr N | power DBM]
duty [show | limit <N|off>]
repeater [show | on | off | regions <LIST|none> |
          default-region <CODE|none> | min-rssi <DBM|none> |
          min-snr <DB|none>]
dev-channel [list | add KEY | remove KEY]
dev-peer    [list | add KEY | remove KEY]
alert [show | locate | none]
capture [...]                        (see below)
scan [--timeout SECS]
default [show | set [SELECTOR] | clear]
```

REPL-only: `exit`/`quit` (msecretctl pattern: a `Command::Exit`
variant that one-shot mode rejects — or simpler, only the REPL wrapper
enum carries it), plus `connect`/`disconnect` (below).

Grammar cleanups folded in (there is no installed base; no compat
shims): `set-name` → `name` (bare form shows the name, symmetric with
`phy`/`duty`/`repeater`); every report-or-mutate family gains an
explicit `show` alias for its bare form so `help phy` reads sensibly;
`--scan-ble`/`--ble-scan` → `scan`.

Value parsing moves to `FromStr`-backed clap value parsers:
`PublicKey`, `RegionCode`, `Filter`, `PeerKeyEntry`, the 6-digit PIN,
`<N|off>` duty limits, on/off booleans. The existing parse helpers
(`parse_key32`, `parse_peer`, `parse_filter`, …) survive as the
`FromStr`/`TypedValueParser` bodies; their error strings become clap
errors with the offending flag named for free. The `provision`
`--file` `setting = value` vocabulary is untouched (it deliberately
shares names with the flags).

## REPL design

Entered whenever no subcommand is given. Ported from msecretctl with
the serial numbers filed off:

- **Session**: attach once (administrative). Every line reuses the
  session. `provision` inside the REPL is the one command that wants a
  *tethered* attach; since the mode is fixed at attach time, the REPL
  runs `provision` by re-attaching tethered for that command and
  re-attaching administrative afterward — or more simply, the REPL
  attaches administratively and `provision` explains it needs a
  one-shot invocation. **Decision below.**
- **Prompt**: device name + transport, e.g. `T-Echo (ble)> `,
  `usbmodem101> `; `❌ ` prefix when the previous command failed
  (msecretctl's `last_command_did_err`).
- **Line handling**: `shlex::split` (maintained successor to the
  `shellwords` crate msecretctl uses) → prepend a program token →
  `ReplCommandLine::try_parse_from`. clap's error/help rendering does
  the rest; `help`, `help phy`, `phy --help` all work.
- **Completion**: port msecretctl's `ReplHelper` completer — it walks
  the `clap::Command` tree generically (subcommands, aliases,
  `--flags`, possible values). The msecret-specific
  `is_ecc_curve_position` hook generalizes into a small trait/callback
  for runtime value completion; first useful client: completing
  `on|off|none|show` (free via possible-values) — BLE names and serial
  ports later if ever worth it. This completer is candidate for
  extraction into a tiny shared module if msecret and umsh want to
  literally share it someday, but the plan is copy-adapt, not a new
  crate.
- **History**: persisted via rustyline (`~/.local/state` /
  `dirs`-style path, or `~/.umsh-ulcpctl-history`; pick one, not
  configurable). PINs and keys do appear on command lines; note in
  `--help` that history is stored in the clear, same posture as any
  shell.
- **Ctrl-C / Ctrl-D at prompt**: cancel line / exit, rustyline
  defaults.
- **Destructive confirms**: `factory-reset` prompts `y/N`
  interactively instead of demanding `--yes`; `provision` over a
  foreign host key likewise offers the `--force` decision
  interactively.
- **Attachment is a REPL-managed state, not a launch-time constant.**
  The REPL can be *unattached* (prompt `(unattached)> `) — that's
  where discovery-gives-up lands, and where `disconnect` goes.
  Session commands in that state get a one-line "not attached — try
  `scan` or `connect`" instead of a transport error.
  - `scan [--timeout SECS]` — works attached or unattached; numbered,
    name-sorted results (chooser rules above) that `connect` can
    reference by number or name.
  - `connect [SELECTOR | -p PORT | -b SEL]` — bare `connect` reruns
    the launch discovery-and-choose flow; with an argument it attaches
    to that device. While already attached it detaches cleanly first
    (which also reverts session-scoped state like promiscuous mode on
    the old device), then attaches to the new one; the prompt follows.
  - `disconnect` — drop to `(unattached)>`.
  This matches real bench flow with several boards on the desk: scan,
  pick, work, switch.

### Save semantics in the REPL

One-shot mode auto-saves after mutations *because* there is no later
"save before quitting?" moment. A REPL does have one, so the
alternative (dirty-flag + prompt on exit) exists. **Recommendation:
keep auto-save per mutating command in both modes**, with global
`--no-save` and the explicit `save` command as today. Reasons: the two
modes behaving identically is worth more than the flash-wear
optimization; a REPL session killed by a dropped BLE link would
otherwise silently lose everything since the last manual `save`; and
the device already treats save as cheap.

## Folding in capture

`capture` becomes a subcommand with today's options as clap args:

```
capture [--pcap PATH] [--layers radio|ulcp|both] [--pcap-raw
        --pcap-linktype N] [--umsh-only] [--idle-probe-secs N]
        [--no-reconnect] [--reconnect-delay-secs N]
        [RF overrides: --freq-khz --bw-hz --sf --cr --sync-word
         --tx-power]
```

(`--color` moved to the global args.)

The pcap writer, field map, colored hex dump, options decoder, and
stats/idle-probe loop move over essentially intact into
`command/capture/` (`mod.rs`, `pcap.rs`, `decode.rs`). Their unit
tests move with them.

**Semantic change — RF profile.** `umsh-capture` today always pushes
an RF profile at attach (`UlcpDevice::new` with the T-Echo bringup
defaults), which is exactly the "disturb the device" behavior ulcpctl
was designed to never do. Merged behavior: **`capture` with no RF
flags attaches administratively and listens on the device's current
RF configuration** (the common case: sniffing the network the device
is already on). Passing any RF flag writes those PHY properties as
live-only state for the session — never auto-saved — with a printed
note that the radio's live config was changed. The old
always-configure behavior is reachable by spelling out the profile.

**Promiscuous mode** is unchanged one-shot (session-scoped property,
reverts on detach). Run from the REPL, the session does *not* detach
when capture ends, so the REPL path must explicitly clear
`PROP_MAC_PROMISCUOUS` (and note if the device refuses, as today).

**Ctrl-C**: one-shot capture exits the process (today's behavior). In
the REPL, Ctrl-C during capture cancels the capture future
(`tokio::select!` against a signal/notify), flushes the pcap, clears
promiscuous, and returns to the prompt.

**BLE reconnect loop**: kept for one-shot capture (it owns the link
and can rediscover). In the REPL the *session* owns the link, so
capture there simply fails back to the prompt on link loss — the REPL
itself is then dead too and says so. No reconnect-inside-REPL
machinery in this plan.

**Follow-up (out of scope)**: `--pcap` as a *global* flag capturing
ULCP frames for any command would subsume `--trace`'s role for
Wireshark-grade debugging. Noted, not planned.

## Code structure

Multi-file binary directory, msecretctl-style:

```
umsh/src/bin/ulcpctl/
  main.rs         ToolArgs (clap Parser), one-shot vs REPL entry
  repl.rs         rustyline Editor + generic clap-tree completer
  connection.rs   BLE discovery + chooser, saved default,
                  serial/BLE open, scan
  output.rs       color/style helpers, key-value report formatting
  command/
    mod.rs        Command enum + dispatch (takes &mut UlcpDevice)
    info.rs  provision.rs  phy.rs  duty.rs  repeater.rs
    tables.rs     dev-channel / dev-peer
    lifecycle.rs  save restore clear reset factory-reset pin
                  identity name alert
    capture/
      mod.rs  pcap.rs  decode.rs
```

`[[bin]] umshctl` points at `src/bin/umshctl/main.rs`;
`umsh_capture.rs` and the `umsh-capture` `[[bin]]` entry are deleted
in phase 3. `required-features = ["tokio-support"]` is already in
place, so the new dependencies ride the same feature:

```toml
# Versions illustrative — check crates.io for current at implementation time.
clap      = { version = "4", optional = true, features = ["derive", "env", "wrap_help"] }
rustyline = { version = "*", optional = true }   # current major, derive helpers as in msecretctl
shlex     = { version = "1", optional = true }
anyhow    = { version = "1", optional = true }   # tool-only; replaces Box<dyn Error> + String
tokio-support = [..., "dep:clap", "dep:rustyline", "dep:shlex", "dep:anyhow"]
```

Default root `cargo build`/`check` (no `tokio-support`) is unaffected.
`anyhow` is scoped to the binary; library crates keep their error
types. Ctrl-C handling wants tokio's `signal` feature added to the
existing tokio dep.

## Testing

- `Command::command().debug_assert()` unit test — clap validates the
  whole tree (conflicting flags, bad defaults) at test time.
- Port the existing `parse_invocation` tests to `try_parse_from`
  equivalents; they already cover the interesting grammar (BLE
  selector ambiguity, provision flag/file vocabulary, repeater forms,
  factory-reset confirmation, misplaced options).
- REPL line-processing tests on the msecretctl `process_line` pattern
  (feed lines, assert dispatch/error), plus completer tests
  (msecret has `tool/tests.rs` to crib from).
- Capture's pcap/format/field-map tests move unchanged.
- Hardware smoke (bench, per the usual board-status discipline):
  serial + BLE attach, REPL sweep on T-1000E, `capture` against live
  RF with a pcap opened in Wireshark, Ctrl-C-in-REPL cleanup verified
  by a follow-up `info` showing promiscuous off.

## Phases

Each phase lands independently and leaves both modes working.

1. **Mechanical clap port (one-shot parity).** Module split, clap
   tree, value parsers, global connection flags + env fallback,
   `scan` subcommand, grammar cleanups (`name`, `show` aliases).
   Delete the hand parser and `USAGE`. Exit: every current
   `umsh-ulcpctl` invocation has an equivalent (capture waits for
   phase 3), tests ported and green.
2. **REPL + discovery.** rustyline editor, completer, history, prompt
   states, interactive confirms, error marker; the no-connection
   discovery-and-choose default (saved default fast-path, 2 s window,
   TTY-gated chooser, name-sorted); the `default` command + config
   file; `connect`/`disconnect` and the unattached state. Exit: with
   two boards live, launch bare, get the chooser, run a command sweep,
   `connect` to the other board mid-session, `default set`, relaunch
   and confirm the fast-path attach.
3. **Fold capture.** Move `umsh_capture.rs` into `command/capture/`,
   RF-profile semantic change, delete the `umsh-capture` binary,
   update the handful of live references (`docs/
   ulcp-web-debugger-design.md`; archived plans stay as history).
   Exit: one-shot `capture` parity incl. pcap + BLE reconnect.
4. **Capture-in-REPL + polish.** Ctrl-C cancellation with promiscuous
   cleanup, shared output styling pass, `clap_complete`
   shell-completion generation as a hidden `completions` subcommand
   (near-free with clap).

## Decisions taken (flag disagreement before phase 1)

- **Binary name: `umshctl`** (changed during implementation, at the
  user's direction — the plan had argued for keeping `umsh-ulcpctl`).
  The tool is still ULCP-device-scoped, so a future host-*node* CLI
  will have to find another name; that cost was accepted for the
  shorter one people actually type. Env var `UMSHCTL_PORT`; settings
  and history under `~/.local/state/umsh/umshctl.{conf,-history}`.
- **Auto-save stays per-mutation in the REPL** (rationale above).
- **Serial is explicit-only; discovery is BLE-only.** The bench hosts
  many non-ULCP serial devices, and identifying a ULCP one requires
  opening the port — which can reset or DFU-trigger foreign hardware.
  BLE scanning is passive and service-filtered, so it is the only safe
  discovery surface. (Supersedes the earlier "wired wins" auto-detect
  idea.)
- **Saved default is explicit (`default set`), not last-used.**
  Implicit stickiness turns a one-off `connect` into tomorrow's wrong
  default; explicit is one command once. Stored as BLE id + name;
  falls through to discovery with a printed note when absent.
- **`capture` defaults to the device's current RF config** rather
  than always pushing a profile (rationale above).
- **`provision` in the REPL**: the re-attach dance, done *over the open
  link*. `AttachMode` is host-side bookkeeping, so a new
  `UlcpDevice::into_link` recovers the transport and re-attaches
  tethered for the one command and administrative afterwards — four
  property reads, no reconnect, and the device never sees a detach (so
  session-scoped state survives). This is why the fallback the plan
  reserved was not needed; the fiddly part was the reconnect it
  assumed.
- `shlex` over `shellwords`, `anyhow` in the binary only,
  `set-name` → `name`.
