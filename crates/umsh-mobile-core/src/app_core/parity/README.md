# Read-mapping parity goldens

Golden output of the Swift read mapping (`ApplicationStateLoader`, the
transcript mapping in `AppRuntime`, and the cached repeater listing), which
`MobileAppCore`'s queries must reproduce. The Swift suite
`ReadMappingParityTests` (apps/ios/UMSHTests) writes them; the Rust test
`app_core::parity` compares against them. Both render to the text format
below, so the format is the contract and is changed on both sides at once.

## Files

| File | What it is |
|---|---|
| `seeded.sqlite` | `seed_staging` over an empty store, owner `owner`, `now_ms` 1790000000000. |
| `augmented.sqlite` | The v31 fixture (`store/swift_store_v31.sqlite`), migrated, plus the rows `generate_parity_stores` adds, owner `alice`. |
| `seeded.golden`, `augmented.golden` | What Swift produces from each store. |

The stores are written by the ignored Rust test `generate_parity_stores`;
the goldens by the Swift suite with `UMSH_WRITE_PARITY_GOLDENS=1` set in
its test process (through `xcodebuild`, as
`TEST_RUNNER_UMSH_WRITE_PARITY_GOLDENS=1`). Both open a copy, never the
committed file, since opening migrates in place.

## Text format

UTF-8, LF line endings, no trailing whitespace, a final newline.

A file is a sequence of sections, each a header line followed by its lines:

1. `## state`, whose lines are sorted bytewise (UTF-8 order).
2. One `## transcript <address>` per conversation address, sorted by
   address. Its first line is `page has_older=<bool> has_newer=<bool>`, then
   one `message` line per message, oldest first, as the page returns them.
3. One `## repeaters <address>` per peer whose cached listing exists,
   sorted by address. Its first line is `listing ...`, then one `entry`
   line per entry in listing order.

`<address>` in a header is the raw address, not quoted.

### Values

| Kind | Encoding |
|---|---|
| absent (`nil`, `None`) | `-` |
| bool | `true`, `false` |
| integer | decimal, with `-` sign when negative |
| float | fixed, seven decimals (`%.7f`, `{:.7}`) |
| string | `"` + escaped + `"`: `\` → `\\`, `"` → `\"`, LF → `\n`, CR → `\r`, TAB → `\t`, any other U+0000–U+001F → `\u{h}` (lowercase hex, no leading zeros); everything else verbatim |
| bytes | `x` then lowercase hex (`x` alone when empty) |
| list | `[` items joined by `,` `]` |
| enum | the case name, lowercased, with no separator: `companionradio`, `chatroom`, `privatekey`, `gappending`, `acknowledged` |
| record | `{` then `name=value` pairs joined by one space, then `}` |

A line is its kind followed by ` name=value` pairs in the order given.

### State lines

```
peer id=<int> address=<string> hint=<string> alias=<string|-> advertised_name=<string|-> system_role=<enum|-> node_kind=<enum|-> advertised=<identity|-> authenticated=<bool> received_at=<int|-> last_heard=<int|-> saved=<bool> favorite=<bool> on_device=<bool> notify_when_heard=<bool>
channel id=<string> kind=<enum> canonical_name=<string|-> name=<string|-> alias=<string|-> channel_id_hex=<string> tint=<bytes> region_code=<bytes|-> max_flood_hops=<int|-> joined_phone=<bool> joined_device=<bool> notifications=<bool> joined_at=<int|->
direct id=<int> peer=<string> draft=<string> unread=<int> created=<int> notifications=<bool> last=<preview|->
channel_conversation id=<int> channel=<string> address=<string> draft=<string> unread=<int> created=<int> last=<preview|->
report reporter=<string> neighbor=<neighbor>
```

- `peer.address` and `peer.hint`: the canonical address and node-hint text
  of the decoded public identity.
- `peer.node_kind`: the stored node kind; absent and `unknown` both encode
  as `-` (Swift's `storedRole` maps both to `.unknown`).
- Times are store milliseconds.
- `direct.peer` and `report.reporter`: the peer's canonical address.
- `channel.id`, `channel_conversation.channel`: the channel UUID, uppercase.
- The advertised name, unknown device channels, and a channel's
  conversation address are not compared: Swift reads them outside the
  loader.

```
identity  = {role=<int> capabilities=<int> forwards=<bool> name=<string|-> latitude=<float|-> longitude=<float|-> precision=<int|-> altitude=<int|-> timestamp=<int|-> signature=<enum>}
preview   = {created=<int> body=<string> outbound=<bool> deleted=<bool> sender_address=<string|-> sender_hint=<bytes|-> status=<bool> sender_node_hint=<string|->}
neighbor  = {hint=<bytes> hint_text=<string> name=<string|-> rssi=<int|-> snr=<int|-> last_heard_minutes=<int|-> latitude=<float|-> longitude=<float|-> precision=<int|-> regions=[<bytes>,...] reported_at=<int> peer=<string|->}
```

- `signature`: `unsigned`, `valid`, `invalid`.
- `preview.sender_node_hint`: the rendered node-hint text.
- `neighbor.hint_text`: Swift's `hintText`. Rust writes its rendered text,
  or, when it has none, the hint's bytes as uppercase hex (Swift's
  fallback).
- `neighbor.peer`: the matched peer's canonical address
  (`PeerRepeaterNeighbor.resolve(among:)` over the state's peers).

### Transcript lines

```
message id=<string> cursor=<int>/<int> created=<int> body=<string> outbound=<bool> delivery=<enum|-> deleted=<bool> edited=<bool> wire=<int|-> epoch=<int|-> presence=<enum> received_late=<bool> delivered_late=<bool> delivered_flooded=<bool> edit_of_unknown=<bool> status=<bool> forward_secret=<bool> original_body=<string|-> sender_address=<string|-> sender_hint=<bytes|-> sender_handle=<string|-> sender_node_hint=<string|-> reception=<reception|-> reactions=[<reaction>,...] quote=<quote|-> repeats=<repeats|->
```

- `id`: `"<session>:<handle>"`, a string.
- `cursor`: created milliseconds and row ID, unquoted, joined by `/`.
- `delivery`: `pending`, `sent`, `acknowledged`, `failed`, `undelivered`.
- `presence`: `present`, `gappending`, `gapidle`, `unavailable`. Swift
  splits it into three flags; `isGapIdle` gives `gapidle`, `isUnavailable`
  gives `unavailable`, `isGapPlaceholder` alone gives `gappending`.

```
reception = {rssi=<int|-> snr=<int|-> lqi=<int|-> hops=<int|-> routes=[<bytes>,...] authenticated=<bool>}
reaction  = {body=<string> mine=<bool> sender_address=<string|-> sender_hint=<bytes|-> target=<string> wire=<int|-> epoch=<int|-> failed=<bool> forward_secret=<bool>}
quote     = unavailable | {state=<enum> target=<string> body=<string> outbound=<bool> sender_address=<string|-> sender_handle=<string|-> sender_node_hint=<string|->}
repeats   = {anonymous=<int> progress_at=<int> repeaters=[{hint=<bytes> text=<string> peer=<string|->},...]}
```

- `reaction.target`: the reaction's own `"<session>:<handle>"`.
- `reaction.failed`: outbound, and its delivery state is `failed` or
  `undelivered`.
- `quote.state`: `present` or `deleted`; `body` is `""` when deleted.
- `repeats.repeaters[].text`: the rendered router-hint text, or, when it
  has none, the bytes as lowercase hex (Swift's fallback).
- `repeats.repeaters[].peer`: the matched peer's canonical address
  (`RouterHintNaming.match` over the state's peers).

### Repeater lines

```
listing total=<int|-> next_cursor=<bytes|-> as_of=<int>
entry <neighbor>
```

`entry` is followed by one space and the neighbor record.
