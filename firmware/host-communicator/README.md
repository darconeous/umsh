# host-communicator

`host-communicator` is a UMSH communicator that runs on your computer. Its screen
is a window showing the interface of a LILYGO T-Deck or T-LoRa Pager, and its
keyboard and mouse are yours. Behind the window is a real UMSH device: the Pager's own ULCP
session driver, radio multiplexer, and device node from `umsh-ulcp-runtime`, the
same code the firmware runs. Its radio is an IP multicast group, the
[UMSH over IP Multicast](https://darconeous.github.io/umsh/docs/protocol/ip-multicast.html)
medium, so it is a node on the mesh like any other: it has its own identity,
answers Identity Requests, beacons and advertises, exchanges contacts, and sends
and receives encrypted chats with acknowledgments.

Run two of them and they talk to each other. Run one on a network where a radio
has its LAN bearer enabled and it talks to the LoRa mesh beyond it.

> [!CAUTION]
> Where a radio on your network carries the group onto the air, so does
> everything the simulator sends: a post in a public channel is a post on the
> real mesh. Use `--host-local` to keep a test to this computer.

## Prerequisites

- A Rust toolchain. The workspace builds from the repository root.
- SDL2, for the window: `brew install sdl2` on macOS, `libsdl2-dev` on Debian
  and Ubuntu.
- On macOS, the first run may ask whether your terminal may find devices on the
  local network. Allow it, or the group cannot be joined.

## Quick start

From the repository root:

```sh
make run-simulator-communicator
```

That builds the release binary and runs the instance named `default`, a T-Deck.
The device boots locked, as the boards do: click it to unlock it.

To run two devices on one computer, give each a name:

```sh
make run-simulator-communicator NAME=alice
make run-simulator-communicator NAME=bob SIMULATOR_ARGS="--board pager"
```

The binary takes the same arguments directly:

```sh
target/release/host-communicator alice
target/release/host-communicator bob --board pager --host-local
```

`host-communicator --help` lists every option.

## Instances

Each instance is its own device, with its own identity, settings, and chats.
An instance is kept in `~/.config/umsh-host-communicator/NAME/` (under
`$XDG_CONFIG_HOME` when that is set), which is made on its first run. A new
instance is named after itself until you give it a name of your own.
`--data-dir DIR` keeps a device somewhere else instead.

| File | What it holds |
|---|---|
| `identity.key` | The device identity's secret key, readable only by you |
| `snapshot.bin` | The saved settings |
| `chats.flash` | The chat partition, as on the Pager: chats, peers, and the device's channel and peer lists |
| `counters/` | Frame-counter boundaries, so a restarted device never reuses a counter its peers have seen |
| `lock` | Held while the instance runs |

An instance runs in one process at a time. Starting a second copy of one that
is already running fails and says so. Two copies sharing an identity would
send under one key with two frame counters, and each would see the other's
frames as replays.

To start an instance over from nothing, run it with `--reset`: it erases
everything the device keeps before it boots, so it comes up with a new
identity, no settings, and no chats, as a new device does. Files of anyone
else's in its folder are left alone. A factory reset does the same from
inside, whether chosen under Device › Factory reset or sent by an
administrator over the mesh: the device erases everything it keeps, then
restarts with a new identity. A reboot restarts the process in place.

## Network

The device's radio is its `PROP_LAN_BEARER_GROUP`, by default
`239.255.134.121:15056`, the protocol's own. It joins the group while its radio
is switched on, which it is from the first boot. Switching the radio off in
Device settings leaves the group.

| Option | Joins the group |
|---|---|
| (none) | On the interface your routing table uses to reach the group, so every device on the network hears it |
| `--interface ADDRESS` | On the interface with this IPv4 address |
| `--host-local` | On the loopback interface, so only the other instances on this computer hear it |

A device hears the other instances on the same computer either way. Its own
frames coming back to it are recognized and dropped.

Receptions from the group are not measured: there is no signal strength or SNR
to report, and the device reports none.

The device's repeater is off. Leave it off: a node whose only medium is the
group should not repeat, because every node on the group already hears every
other.

## Controls

### T-Deck (`--board tdeck`, the default)

| Input | T-Deck control |
|---|---|
| Left mouse button | A finger on the touchscreen: click to tap, drag to scroll, hold to long-press; on the lock screen, the trackball press |
| Arrows, mouse wheel | Roll the trackball |
| Control, right mouse button | Press the trackball |
| Escape | Lock, as the screen going dark would |
| Letters, digits, Return, Backspace, Space | Type, with Shift as the T-Deck's own keyboard applies it |

The touchscreen takes no touches while the device is locked, as on the T-Deck,
so there a click presses the trackball instead.

### T-LoRa Pager (`--board pager`)

| Key | Pager control |
|---|---|
| Up, Down, mouse wheel | Turn the wheel |
| Right, left click | Press the wheel; hold it to open a menu |
| Left | Back, as Backspace is, except while typing in a field |
| Escape | The lock button |
| Return, Backspace, Space, letters | The same keys |
| Shift | CAP |
| Alt | The orange key |

The Pager's keyboard does not repeat, and neither does this one.

Sounds the device would play are printed on standard error, as `sound: …`.

## The demo

```sh
make run-simulator-communicator-demo
```

`--demo` shows made-up chats in place of a device: Juniper's, with a few
peers and channels and a conversation in progress. It is for looking at the
interface. Nothing in it is sent anywhere. Tab brings the demo's next message
in, as if it had arrived, and an identity asked for arrives two seconds later.
With `--long-history`, the public channel holds several hundred messages over
several days.

## Headless scripts

```sh
host-communicator --script steps.txt --out shots/
```

A script runs without a window and writes screenshots as PNG. It runs the demo
unless an instance or `--data-dir` is named. Then it runs that device without
ever joining its group, so what the screenshots show is only what the script
did.

Each line is one step, and `#` starts a comment. Each input takes 50 ms of the
board's clock.

| Step | What it does |
|---|---|
| `turn N` | Turns the wheel N detents; negative is up |
| `move up\|down\|left\|right [N]` | Rolls the trackball, N times |
| `press` | Presses and releases the wheel or the ball |
| `hold` | Holds it long enough to open a menu |
| `tap X Y` | Touches the screen at X, Y and lifts, on the T-Deck |
| `enter`, `backspace`, `space` | The keys |
| `type TEXT` | Types TEXT as it is |
| `keys TEXT` | Presses TEXT as Pager keys, so the modifiers and typing aids act on it |
| `shift`, `alt` | Taps the modifier |
| `alt-down`, `alt-up` | Holds or lets go of Alt |
| `lock` | The lock button |
| `dark`, `lit` | The panel goes dark, which locks it a second later, and lights again |
| `wait SECONDS` | The board's clock moves on, and the demo's with it |
| `battery PERCENT [charging]` | A battery reading |
| `battery-empty [off]` | The empty battery's blink; `off` is its dark half |
| `airtime SECONDS` | Airtime spent that returns in that long; 0 for none |
| `first-run` | Starts first-run setup |
| `arrive` | The demo's next message arrives (demo only) |
| `identify` | The identity asked for arrives at once (demo only) |
| `meet asks\|accepts\|declines\|same\|different\|leaves` | The demo's other party in a contact exchange (demo only) |
| `shot NAME` | Writes `NAME.png` once everything has settled |
| `peek MS NAME` | Writes `NAME.png` MS milliseconds into what the last steps started |

The scripts in [`tours/`](tours/) walk through the whole interface on the
Pager, so run one with `--board pager`. To run them all into `target/tours/`:

```sh
make simulator-communicator-tours
```

## With umshctl and the iOS app

`umshctl --lan` runs a virtual radio of its own on the group, so it reaches a
simulator that is on the network (not one with `--host-local`):

```sh
umshctl --lan discover            # every node that answers, the simulators among them
umshctl --lan send KEY hello      # a direct message, acknowledged by the device
umshctl --lan capture             # every frame on the group, decoded
```

To administer a simulator over the mesh with `umshctl --lan manage`, its device
must first list your administrator key (`umshctl admin-key`) in its
`PROP_DEV_ADMINS`.

The iOS app reaches the group the same way, through its LAN virtual radio.

## Other options

- `--verbose` prints the device's debug log on standard error: the node's
  bring-up, every frame it processes, and what the session does.
- `--bench N` turns the wheel N times over the demo and reports the mean layout
  and paint time of a frame, for timing and for a profiler to watch.

## Troubleshooting

- **Nothing is heard from other devices.** Check the radio is on (Device
  settings), and that macOS has allowed local-network access. Multicast often
  goes no further than one Wi-Fi network, and some access points drop it
  entirely. `--host-local` rules the network out.
- **"already running".** That instance is open in another window. Start a
  differently named one.
- **The window does not open.** The binary was built without SDL2, or SDL2 is
  not installed where the linker looks. Scripts still run.
