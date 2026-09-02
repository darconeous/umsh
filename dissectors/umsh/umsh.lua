-- UMSH Mesh Network — Wireshark Lua dissector (entry point)
-- Requires Wireshark 4.x / Lua 5.3+
-- Sibling files: options.lua, keystore.lua, crypto.lua, app.lua (optional)

-- ──────────────────────────────────────────────────────────────────────────
-- Module path setup: allow require("options") etc. to find sibling files
-- ──────────────────────────────────────────────────────────────────────────
local _src = debug.getinfo(1, "S").source
local _dir = (_src:match("^@(.+)[/\\][^/\\]+$") or ".") .. "/"
package.path = _dir .. "?.lua;" .. package.path

-- ──────────────────────────────────────────────────────────────────────────
-- Sibling modules
-- ──────────────────────────────────────────────────────────────────────────
local options  = require("options")
local keystore = require("keystore")
local base58   = require("base58")
local crypto; do local ok, m = pcall(require, "crypto"); if ok then crypto = m end end
local app;    do local ok, m = pcall(require, "app");    if ok then app    = m end end

-- Wire crypto into keystore (needed for channel ID precomputation)
if crypto then keystore.set_crypto(crypto) end

-- ──────────────────────────────────────────────────────────────────────────
-- Protocol definition
-- ──────────────────────────────────────────────────────────────────────────
local umsh = Proto("umsh", "UMSH Mesh Network")

-- ──────────────────────────────────────────────────────────────────────────
-- Value strings
-- ──────────────────────────────────────────────────────────────────────────
local VS_TYPE = {
  [0] = "BCST (Broadcast)",        [1] = "UACK (MAC Ack)",
  [2] = "UNIC (Unicast)",          [3] = "UNAR (Unicast Ack-Req)",
  [4] = "MCST (Multicast)",        [5] = "RSVD (Reserved)",
  [6] = "BUNI (Blind Unicast)",    [7] = "BUAR (Blind Unicast Ack-Req)",
}
local TYPE_SHORT = {"BCST","UACK","UNIC","UNAR","MCST","RSVD","BUNI","BUAR"}
local VS_MIC = {[0]="4 bytes",[1]="8 bytes",[2]="12 bytes",[3]="16 bytes"}
local VS_VER = {[3]="Valid (0b11)"}

-- ──────────────────────────────────────────────────────────────────────────
-- ProtoField declarations
-- ──────────────────────────────────────────────────────────────────────────
local f = {}

-- FCF (1 byte)
f.fcf          = ProtoField.uint8 ("umsh.fcf",         "Frame Control Field", base.HEX)
f.fcf_version  = ProtoField.uint8 ("umsh.fcf.version", "Version",             base.HEX, VS_VER,  0xC0)
f.fcf_type     = ProtoField.uint8 ("umsh.fcf.type",    "Packet Type",         base.DEC, VS_TYPE, 0x38)
f.fcf_full_src = ProtoField.bool  ("umsh.fcf.s",       "Full Source Key (S)", 8, nil, 0x04)
f.fcf_reserved = ProtoField.bool  ("umsh.fcf.r",       "Reserved (R)",        8, nil, 0x02)
f.fcf_fhops    = ProtoField.bool  ("umsh.fcf.h",       "Flood Hops (H)",      8, nil, 0x01)

-- FHOPS (1 byte, optional)
--
-- A string rather than the raw byte: the two nibbles are what the field
-- means, and "0x50" in a column says nothing a reader can act on. The
-- nibbles stay available as numbers below.
f.fhops        = ProtoField.string("umsh.fhops",       "Flood Hop Count")
f.fhops_rem    = ProtoField.uint8 ("umsh.fhops.rem",   "Remaining",           base.DEC, nil, 0xF0)
f.fhops_acc    = ProtoField.uint8 ("umsh.fhops.acc",   "Accumulated",         base.DEC, nil, 0x0F)

-- Options (variable)
f.options          = ProtoField.bytes  ("umsh.options",           "Options")
f.opt_region_code  = ProtoField.string ("umsh.opt.region_code",   "Region Code")
-- Route options carry their rendered path, not their bytes: the byte range
-- an option item covers starts at the delta-length header, so the hex form
-- is off by a byte from the hints a reader is looking for.
f.opt_traceroute   = ProtoField.string ("umsh.opt.trace_route",   "Trace Route")
f.opt_srcroute     = ProtoField.string ("umsh.opt.source_route",  "Source Route")
f.opt_router_hint  = ProtoField.string ("umsh.opt.route_repeater","Router Hint")
f.opt_op_callsign  = ProtoField.string ("umsh.opt.op_callsign",   "Operator Callsign")
f.opt_sta_callsign = ProtoField.string ("umsh.opt.sta_callsign",  "Station Callsign")
f.opt_min_rssi     = ProtoField.int8   ("umsh.opt.min_rssi",      "Min RSSI",         base.DEC)
f.opt_min_snr      = ProtoField.int8   ("umsh.opt.min_snr",       "Min SNR",          base.DEC)
f.opt_route_retry  = ProtoField.none   ("umsh.opt.route_retry",   "Route Retry")
f.opt_ack_mic      = ProtoField.bytes  ("umsh.opt.ack_mic",       "Ack MIC")
f.opt_trace_signal = ProtoField.bytes  ("umsh.opt.trace_signal",  "Trace Signal")
f.opt_signal_entry = ProtoField.string ("umsh.opt.signal_entry",  "Signal Quality")
f.opt_unknown      = ProtoField.bytes  ("umsh.opt.unknown",       "Unknown Option")
-- The piggy-backed ack names the frame it acknowledges, the same way a
-- standalone MAC ack does.
f.opt_ack_frame    = ProtoField.framenum("umsh.opt.ack_frame",    "Acknowledges packet in frame",
                                         base.NONE, frametype.ACK)

-- Addresses
f.dst_hint     = ProtoField.bytes  ("umsh.dst",          "Destination Hint")
f.src_hint     = ProtoField.bytes  ("umsh.src_hint",     "Source Hint")
f.src_key      = ProtoField.bytes  ("umsh.src_key",      "Source Public Key")
f.channel_id   = ProtoField.bytes  ("umsh.channel_id",   "Channel ID")
f.ack_mic      = ProtoField.bytes  ("umsh.ack_mic",      "ACK MIC")
f.ack_tag      = ProtoField.bytes  ("umsh.ack_tag",      "ACK Tag")

-- Keystore annotations (virtual string fields)
f.src_name     = ProtoField.string ("umsh.src_name",     "Source Name")
f.dst_name     = ProtoField.string ("umsh.dst_name",     "Destination Name")
f.channel_name = ProtoField.string ("umsh.channel_name", "Channel Name")

-- Canonical addresses, in the base58 forms from the addressing chapter.
--
-- Added hidden, the way `ip.addr` is: the address is already written on the
-- item covering the bytes it came from, so showing it again on a row of its
-- own says the same thing twice. These exist to be filtered on
-- (`umsh.src_addr == "GySV"`), not to be read.
f.src_addr     = ProtoField.string ("umsh.src_addr",     "Source Address")
f.dst_addr     = ProtoField.string ("umsh.dst_addr",     "Destination Address")

-- Protocol prohibitions. Carrying the text in a field rather than only in
-- expert info is what lets a coloring rule find these frames: see
-- umsh-colorfilters in this directory.
f.violation    = ProtoField.string ("umsh.violation",    "Protocol Violation")

-- SECINFO
f.secinfo      = ProtoField.bytes  ("umsh.secinfo",        "Security Information")
f.scf          = ProtoField.uint8  ("umsh.scf",            "Security Control",   base.HEX)
f.scf_enc      = ProtoField.bool   ("umsh.scf.e",          "Encrypted (E)",      8, nil, 0x80)
f.scf_mic_size = ProtoField.uint8  ("umsh.scf.mic_size",   "MIC Size",           base.DEC, VS_MIC, 0x60)
f.scf_salt_bit = ProtoField.bool   ("umsh.scf.s",          "Salt Present (S)",   8, nil, 0x10)
f.frame_ctr    = ProtoField.uint32 ("umsh.frame_counter",  "Frame Counter",      base.DEC)
f.salt         = ProtoField.uint16 ("umsh.salt",           "Salt",               base.HEX)
f.mic          = ProtoField.bytes  ("umsh.mic",            "MIC")

-- Payload / crypto results
f.payload_raw  = ProtoField.bytes  ("umsh.payload",           "Payload")
f.payload_dec  = ProtoField.bytes  ("umsh.payload_decrypted", "Decrypted Payload")
f.enc_body     = ProtoField.bytes  ("umsh.enc_body",          "Encrypted Body")
f.enc_addr     = ProtoField.bytes  ("umsh.enc_addr",          "Encrypted Addr Block (ENC_DST_SRC)")
f.dec_dst      = ProtoField.bytes  ("umsh.dec_dst",           "Decrypted DST Hint")
f.dec_src      = ProtoField.bytes  ("umsh.dec_src",           "Decrypted SRC")

-- ACK tracking (cross-frame references)
f.ack_req_frame = ProtoField.framenum("umsh.ack.request_frame", "Acknowledges packet in frame",
                                       base.NONE, frametype.ACK)
-- Public ack_mic correlated the ack to a request, but a configured key proved
-- the keyed tag wrong: a forensic link only, not a valid acknowledgement.
f.ack_correlate_frame = ProtoField.framenum("umsh.ack.correlate_frame",
                                       "Correlates with packet in frame (unverified)",
                                       base.NONE, frametype.NONE)
f.ack_rsp_frame = ProtoField.framenum("umsh.ack.response_frame","Acknowledged in frame",
                                       base.NONE, frametype.RESPONSE)
f.ack_rsp_time  = ProtoField.string  ("umsh.ack.response_time", "ACK Response Time")
f.ack_expected  = ProtoField.bytes   ("umsh.ack.expected_tag",  "Expected ACK Tag")
f.ack_verified  = ProtoField.bool    ("umsh.ack.verified",      "Keyed ACK Tag Verified")

umsh.fields = {
  f.fcf, f.fcf_version, f.fcf_type, f.fcf_full_src, f.fcf_reserved, f.fcf_fhops,
  f.fhops, f.fhops_rem, f.fhops_acc,
  f.options, f.opt_region_code, f.opt_traceroute, f.opt_srcroute, f.opt_router_hint,
  f.opt_op_callsign, f.opt_sta_callsign, f.opt_min_rssi, f.opt_min_snr,
  f.opt_route_retry, f.opt_ack_mic, f.opt_ack_frame,
  f.opt_trace_signal, f.opt_signal_entry, f.opt_unknown,
  f.dst_hint, f.src_hint, f.src_key, f.channel_id, f.ack_mic, f.ack_tag,
  f.src_name, f.dst_name, f.channel_name, f.src_addr, f.dst_addr, f.violation,
  f.secinfo, f.scf, f.scf_enc, f.scf_mic_size, f.scf_salt_bit,
  f.frame_ctr, f.salt, f.mic,
  f.payload_raw, f.payload_dec, f.enc_body, f.enc_addr, f.dec_dst, f.dec_src,
  f.ack_req_frame, f.ack_correlate_frame, f.ack_rsp_frame, f.ack_rsp_time,
  f.ack_expected, f.ack_verified,
}

-- ──────────────────────────────────────────────────────────────────────────
-- ProtoExpert declarations
-- ──────────────────────────────────────────────────────────────────────────
local ef = {}
ef.bad_version  = ProtoExpert.new("umsh.bad_version",  "Unsupported UMSH version", expert.group.MALFORMED,  expert.severity.ERROR)
ef.truncated    = ProtoExpert.new("umsh.truncated",    "Packet truncated",         expert.group.MALFORMED,  expert.severity.ERROR)
ef.mic_bad      = ProtoExpert.new("umsh.mic_bad",      "MIC verification failed",  expert.group.CHECKSUM,   expert.severity.WARN)
ef.mic_ok       = ProtoExpert.new("umsh.mic_ok",       "MIC verified OK",          expert.group.CHECKSUM,   expert.severity.NOTE)
ef.no_key       = ProtoExpert.new("umsh.no_key",       "No key for decryption",    expert.group.UNDECODED,  expert.severity.NOTE)
ef.unk_crit_opt = ProtoExpert.new("umsh.unknown_crit", "Unknown critical option",  expert.group.PROTOCOL,   expert.severity.WARN)
ef.rsvd_type    = ProtoExpert.new("umsh.reserved_type","Reserved packet type",     expert.group.PROTOCOL,   expert.severity.WARN)
-- Named apart from the `umsh.violation` field on purpose: an expert and a
-- field share one namespace, and giving both the same abbreviation makes
-- the filter match two things at once.
ef.violation    = ProtoExpert.new("umsh.prohibited",   "Protocol violation",       expert.group.PROTOCOL,   expert.severity.ERROR)

umsh.experts = {
  ef.bad_version, ef.truncated, ef.mic_bad, ef.mic_ok,
  ef.no_key, ef.unk_crit_opt, ef.rsvd_type, ef.violation,
}

-- ──────────────────────────────────────────────────────────────────────────
-- Preferences
-- ──────────────────────────────────────────────────────────────────────────

-- Key table via Pref.uat (Wireshark 4.6+), with string-pref fallback.
local _has_uat = pcall(function()
  umsh.prefs.keys = Pref.uat("Decryption Keys", {
    {"type",  "pubkey = name only (no decrypt), privkey = decrypt unicast, channel = decrypt multicast"},
    {"key",   "64 hex chars, 44 base58 chars, or a umsh:n:/umsh:ck:/umsh:cs: URI"},
    {"label", "Human-readable display name"},
  }, "Type: pubkey (Ed25519 public key, display name only), "
  .. "privkey (Ed25519 seed, enables unicast decryption), "
  .. "channel (symmetric key or umsh:cs:<name>, enables multicast decryption). "
  .. "Keys may be written as 64 hex characters or as the 44-character base58 "
  .. "address form, so an address copied from umshctl or the app pastes in "
  .. "directly.",
  "umsh_keys")
end)

if not _has_uat then
  -- Fallback for Wireshark < 4.6: three separate string preferences
  umsh.prefs.node_names   = Pref.string("Node names",   "",
    "One per line: <key>:<display-name>\n"
    .. "<key> is 64 hex chars, 44 base58 chars, or umsh:n:<base58>")
  umsh.prefs.privkeys     = Pref.string("Private keys", "",
    "One per line: <ed25519-seed>:<display-name>\n"
    .. "The seed is 64 hex chars or 44 base58 chars")
  umsh.prefs.channel_keys = Pref.string("Channel keys", "",
    "One per line:\n  <key>:<display-name>\n  umsh:ck:<base58>:<display-name>"
    .. "\n  umsh:cs:<name>:<display-name>")
end

umsh.prefs.udp_port     = Pref.uint  ("UDP Port", 0, "UDP port to dissect as UMSH (0 = disabled)")
umsh.prefs.keyfile      = Pref.string("Key File",  "",
  "Optional key file path (INI format with [nodes]/[privkeys]/[channels] sections)")

-- ──────────────────────────────────────────────────────────────────────────
-- Internal state
-- ──────────────────────────────────────────────────────────────────────────
local _udp_table       = DissectorTable.get("udp.port")
local _registered_port = 0

-- ACK tracking tables (cleared on each new capture via init)
--
-- Correlation is keyed by the public ack_mic (the first 4 bytes of the
-- acknowledged packet's on-wire MIC), so it works WITHOUT any keys: an
-- ack-requested packet exposes its MIC on the wire, and the returning MAC
-- ack echoes that prefix. When a private key is available the expected keyed
-- ack_tag is also recorded, letting a matched ack be cryptographically
-- verified (not just correlated).
--
-- _ack_by_mic:   ack_mic_hex → {frame=N, timestamp=T, src_label=S,
--                               dst_label=D, exp_tag_hex=<4B hex or nil>}
-- _ack_by_frame: frame_num → {ack_frame=N, rsp_time=delta_seconds} (back-annotation)
-- _ack_origin:   ack frame_num → the _ack_by_mic entry that ack resolved to
--
-- _ack_by_mic holds only the most recent packet published under a given
-- ack_mic, which is all a *new* ack needs. It is not what an already-seen
-- ack needs: a retransmission publishes the same MIC prefix and takes the
-- entry over, so an ack resolved against it once cannot resolve against it
-- again. Wireshark re-dissects a frame whenever it is selected, and the
-- packet list keeps the first pass's Info column — which is why the
-- symptom is a detail pane disagreeing with the summary line above it,
-- and a response time that runs backwards. _ack_origin records what each
-- ack actually resolved to, on the one pass where the answer is right.
local _ack_by_mic    = {}
local _ack_by_frame  = {}
local _ack_origin    = {}

-- Same story for a piggy-backed ack carried as an option rather than as a
-- packet of its own: what it resolved to has to be remembered, because
-- _ack_by_mic holds only the most recent packet under a given prefix and a
-- re-dissection must not answer differently from the first pass.
local _ack_opt_origin = {}

function umsh.init()
  _ack_by_mic     = {}
  _ack_by_frame   = {}
  _ack_origin     = {}
  _ack_opt_origin = {}
end

-- Resolve an Ack MIC option value to the frame it acknowledges. Needs no
-- keys: the acknowledged packet published this prefix on the wire.
local function resolve_piggyback_ack(pinfo, mic_hex)
  if not pinfo then return nil end
  if pinfo.visited then return _ack_opt_origin[pinfo.number] end
  local origin = _ack_by_mic[mic_hex]
  _ack_opt_origin[pinfo.number] = origin
  return origin
end

-- ──────────────────────────────────────────────────────────────────────────
-- Byte-string helpers
-- ──────────────────────────────────────────────────────────────────────────
local function tvb_bytes(buf, off, len)
  return buf(off, len):bytes():raw()
end

local function bytes_to_hex(s)
  return (s:gsub(".", function(c)
    return string.format("%02X", c:byte())
  end))
end

-- Canonical rendering, per docs/protocol/src/addressing.md: a 3-byte node
-- hint as its star-truncated base58 form, a full key as its 44 base58
-- digits.
--
-- Tree items carry the byte form alongside the hint, since that is what the
-- bytes they cover actually say. The address columns take the canonical
-- form alone — a keystore name displaces it whenever one is known, and the
-- detail pane is where the bytes belong.
local function hint_label(s)
  return base58.node_hint_full(s)
end

local function hint_short(s)
  return base58.node_hint(s) or bytes_to_hex(s)
end

local function addr_short(s)
  if #s == 32 then return base58.key_full(s) end
  return hint_short(s)
end

-- A route option's repeaters as canonical router hints, in the order they sit
-- on the wire, joined by an arrow pointing the way the packet travels. This is
-- what a route field is worth in a column: the raw bytes there include the
-- option header and read as noise.
--
-- The two route options are written in opposite directions. A repeater
-- prepends itself to a trace route, so hint 0 is the repeater nearest the
-- receiver and the packet moved right to left. A source route names the
-- next repeater first, so it moves left to right.
local function route_path(val, arrow)
  local count = #val // 2
  -- An empty route is a normal state, not a finding: a trace that no
  -- repeater has touched yet, or a source route the last named repeater
  -- emptied. A dash says so without competing with the rows that name
  -- repeaters.
  if count == 0 then return "—" end
  local out = {}
  for i = 1, count do
    local hint = val:sub(i * 2 - 1, i * 2)
    out[i] = base58.router_hint(hint) or bytes_to_hex(hint)
  end
  return table.concat(out, arrow)
end

-- A region code is two bytes of ARNCE/HAM-16. Anything that decodes to one to
-- three letters is a short code and is shown as one; everything else is shown
-- as hex. The two spaces cannot collide: the spec transforms any hash prefix
-- that would have decoded to nothing but letters out of the letter range,
-- which is what makes the all-letter test sufficient on its own. A short code
-- bearing a digit is deliberately not read back — it is not vacated, so the
-- code may equally have come from a hashed name.
local function region_label(val)
  if #val == 0 then return "(no value)" end
  if #val == 2 then
    local short = options.decode_arnce(val)
    if short:match("^%u%u?%u?$") then return short end
  end
  return "0x" .. bytes_to_hex(val)
end

-- ──────────────────────────────────────────────────────────────────────────
-- Protocol violations
--
-- Frames that break a prohibition the spec states as a sender MUST NOT, and
-- that a single frame is enough to prove. Each one lands in the tree as a
-- `umsh.violation` field (so a coloring rule can find the frame), as expert
-- info (so it is red in the detail pane and listed under Expert Information),
-- and in the Info column.
--
-- The Info column marker is appended once at the end of dissection: the
-- per-type dissectors overwrite that column after most checks have run, so
-- anything written here during the walk would be lost.
-- ──────────────────────────────────────────────────────────────────────────
local _violations = {}

-- Notes bound for the Info column from somewhere that runs before the
-- per-type dissectors, which own that column and rewrite it. Anything
-- written during the options walk would otherwise be overwritten.
local _info_notes = {}

-- What the application layer needs to know about the packet carrying it:
-- enough to apply the rules that span both layers (which payload types a
-- packet type may carry, what the well-known channels require). Rebuilt at
-- the top of each dissection and handed to app.dissect.
local _ctx = {}

local function flag_violation(tree, tvbr, text, expert_kind)
  local item = tree:add(f.violation, tvbr, text)
  item:set_generated()
  item:add_proto_expert_info(expert_kind or ef.violation, text)
  _violations[#_violations + 1] = text
end

-- A channel ID is a 2-byte hint of a key, and the spec allows collisions:
-- a frame belongs to whichever key authenticates it. A rule keyed on the
-- channel is therefore only proven once the MIC verifies under that
-- channel's key, and is qualified until then.
local function channel_caveat(mic_verified)
  if mic_verified then return "" end
  return " (channel identified by ID only)"
end

-- Rules the two well-known channels attach to their names. Only the ones a
-- MAC-layer view can decide are here; the ones that depend on the payload
-- type live in app.lua, which is the layer that can see it.
local function check_channel_rules(tree, tvbr, ch_entry, opts)
  if not ch_entry or not ch_entry.builtin then return end
  local caveat = channel_caveat(opts.mic_verified)

  if ch_entry.builtin == "emergency" and opts.is_enc then
    flag_violation(tree, tvbr,
      "Emergency channel traffic must not be encrypted — it must be " ..
      "readable by every node in range" .. caveat)

  elseif ch_entry.builtin == "public" and opts.blind then
    flag_violation(tree, tvbr,
      "Blind unicast on the public channel is forbidden" .. caveat)
  end
end

-- The destination shown for a packet addressed to everyone.
local BROADCAST_LABEL = "*"

-- Put the mesh's own addressing in the address columns.
--
-- These are set as strings rather than as `pinfo.src`/`pinfo.dst`
-- addresses because wslua only constructs the address types it knows
-- (ether, ip, ipv4, ipv6), and a 3-byte node hint is none of them.
-- Describing a hint as an Ethernet address to gain the Conversations and
-- Endpoints tables would put a fiction in every one of those rows, so the
-- tables stay empty instead.
--
-- Setting the columns as strings only reaches frames whose transport has
-- no addresses of its own: over LoRaTAP that is every frame, but under
-- the synthetic UDP encapsulation the IP layer's own addresses win, and
-- those rows keep showing the loopback pair the encapsulation invents.
--
-- A hint is three bytes and can collide, so what lands here is what the
-- packet claims rather than a proven identity — the same caveat the
-- names resolved from the keystore carry.
local function set_endpoints(pinfo, src, dst)
  if src then pinfo.cols.src = src end
  if dst then pinfo.cols.dst = dst end
end

-- ──────────────────────────────────────────────────────────────────────────
-- Address tree items
-- Each address lands three times: the bytes on the wire, the canonical form
-- as a filterable generated field, and the keystore name when one is known.
-- ──────────────────────────────────────────────────────────────────────────
local function add_dst_hint(tree, buf, off, dst_bytes)
  tree:add(f.dst_hint, buf(off, 3)):set_text(
    "Destination Hint: " .. hint_label(dst_bytes))
  tree:add(f.dst_addr, buf(off, 3), hint_short(dst_bytes)):set_hidden()
  local name = keystore.lookup_node(dst_bytes)
  if name and name ~= "" then tree:add(f.dst_name, buf(off, 3), name) end
  return name
end

-- SRC is a 3-byte hint or a full 32-byte key, per the FCF S flag.
local function add_src_addr(tree, buf, off, src_bytes, full_src)
  local name, pubkey
  if full_src then
    tree:add(f.src_key, buf(off, 32)):set_text(
      "Source Public Key: " .. base58.key_full(src_bytes))
    name   = keystore.lookup_node_by_key(src_bytes)
    pubkey = src_bytes
  else
    tree:add(f.src_hint, buf(off, 3)):set_text(
      "Source Hint: " .. hint_label(src_bytes))
    name, pubkey = keystore.lookup_node(src_bytes)
  end
  tree:add(f.src_addr, buf(off, #src_bytes), addr_short(src_bytes)):set_hidden()
  if name and name ~= "" then
    tree:add(f.src_name, buf(off, #src_bytes), name)
  end
  return name, pubkey
end

-- ──────────────────────────────────────────────────────────────────────────
-- parse_secinfo
-- Parses the SECINFO field starting at `off` in `buf` and adds to `tree`.
-- Returns: new_off, scf_byte, mic_len, secinfo_raw, is_enc
-- Returns nil (only) on truncation after adding ef.truncated.
-- ──────────────────────────────────────────────────────────────────────────
local function parse_secinfo(buf, off, tree)
  local buf_len = buf:len()
  if off >= buf_len then
    tree:add_proto_expert_info(ef.truncated)
    return nil
  end

  local scf      = buf(off, 1):uint()
  local has_salt = (scf & 0x10) ~= 0
  local si_len   = has_salt and 7 or 5

  if off + si_len > buf_len then
    tree:add_proto_expert_info(ef.truncated)
    return nil
  end

  local secinfo_raw = tvb_bytes(buf, off, si_len)
  local is_enc      = (scf & 0x80) ~= 0
  local mic_code    = (scf >> 5) & 0x03
  local mic_len     = ({[0]=4, [1]=8, [2]=12, [3]=16})[mic_code]

  local si_tree  = tree:add(f.secinfo, buf(off, si_len))
  local scf_tree = si_tree:add(f.scf, buf(off, 1))
  scf_tree:add(f.scf_enc,      buf(off, 1))
  scf_tree:add(f.scf_mic_size, buf(off, 1))
  scf_tree:add(f.scf_salt_bit, buf(off, 1))
  -- The low four SCF bits are reserved and must be zero; an unknown bit
  -- there could change how everything after SECINFO is read.
  if (scf & 0x0F) ~= 0 then
    flag_violation(scf_tree, buf(off, 1),
      string.format("SCF reserved bits must be zero (low nibble is 0x%X)", scf & 0x0F))
  end
  off = off + 1
  si_tree:add(f.frame_ctr, buf(off, 4))
  off = off + 4
  if has_salt then
    si_tree:add(f.salt, buf(off, 2))
    off = off + 2
  end

  return off, scf, mic_len, secinfo_raw, is_enc
end

-- ──────────────────────────────────────────────────────────────────────────
-- parse_options
-- Decodes the CoAP-style options block starting at `start_off` up to `bound`.
-- Populates `static_opts_out` with {number, value} pairs for AAD construction.
-- Returns the new offset (after the 0xFF terminator, or at `bound` if absent).
-- ──────────────────────────────────────────────────────────────────────────
local function parse_options(buf, start_off, bound, tree, static_opts_out, pinfo)
  if start_off >= bound then return start_off end

  local avail = bound - start_off
  local raw   = tvb_bytes(buf, start_off, avail)

  local total_len
  if not pcall(function() total_len = options.scan_length(raw, 1) end)
     or not total_len then
    tree:add_proto_expert_info(ef.truncated)
    return start_off
  end

  -- A block that is nothing but its terminator carries no options. Adding a
  -- subtree for it puts an `Options: ff` row in the majority of packets that
  -- says nothing at all, so it is left out; the byte itself is still visible
  -- in the bytes pane.
  if total_len == 1 and raw:byte(1) == 0xFF then
    return start_off + 1
  end

  local opts_tree = tree:add(f.options, buf(start_off, total_len))
  opts_tree:set_text(string.format("Options (%d byte%s)",
                                   total_len, total_len == 1 and "" or "s"))

  local seen = {}
  local raw_pos = 1  -- 1-indexed position in buf
  pcall(function()
    for num, val, consumed in options.decode(raw, 1) do
      local opt_off = start_off + raw_pos - 1   -- absolute offset in buf
      local val_len = #val
      local val_off = opt_off + consumed - val_len  -- offset of value bytes

      seen[num] = (seen[num] or 0) + 1

      if num == options.OPT_REGION_CODE then
        local cs   = region_label(val)
        local tvbr = (val_len > 0) and buf(val_off, val_len) or buf(opt_off, consumed)
        opts_tree:add(f.opt_region_code, tvbr, cs):set_text("Region Code: " .. cs)

      elseif num == options.OPT_TRACE_ROUTE or num == options.OPT_SOURCE_ROUTE then
        local is_trace = (num == options.OPT_TRACE_ROUTE)
        local label    = is_trace and "Trace Route" or "Source Route"
        -- The value is a run of 2-byte router hints, one per repeater. The
        -- repeater count is not the hop count: a route naming N repeaters
        -- describes N+1 transmissions, since the legs into the first
        -- repeater and out of the last one belong to no hint.
        local routers = val_len // 2
        local extra   = val_len % 2
        local path    = route_path(val, is_trace and " ← " or " → ")
        local item = opts_tree:add(is_trace and f.opt_traceroute or f.opt_srcroute,
                                   buf(opt_off, consumed), path)
        local note = ""
        if routers > 0 then
          note = string.format(" (%d repeater%s%s)", routers,
                               routers == 1 and "" or "s",
                               extra == 1 and ", 1 trailing byte" or "")
        elseif extra == 1 then
          note = " (1 trailing byte)"
        end
        item:set_text(label .. ": " .. path .. note)
        for i = 1, routers do
          local hint = val:sub(i * 2 - 1, i * 2)
          item:add(f.opt_router_hint, buf(val_off + (i - 1) * 2, 2),
                   base58.router_hint(hint) or ""):set_text(
            string.format("Repeater %d: %s", i, base58.router_hint_full(hint)))
        end

      elseif num == options.OPT_OP_CALLSIGN then
        opts_tree:add(f.opt_op_callsign, buf(opt_off, consumed)):set_text(
          "Operator Callsign: " .. options.decode_arnce(val))

      elseif num == options.OPT_STATION_CALLSIGN then
        opts_tree:add(f.opt_sta_callsign, buf(opt_off, consumed)):set_text(
          "Station Callsign: " .. options.decode_arnce(val))

      elseif num == options.OPT_MIN_RSSI then
        if val_len == 1 then
          opts_tree:add(f.opt_min_rssi, buf(val_off, 1))
        else
          opts_tree:add(f.opt_unknown, buf(opt_off, consumed)):set_text(
            "Min RSSI: (no value)")
        end

      elseif num == options.OPT_MIN_SNR then
        if val_len == 1 then
          opts_tree:add(f.opt_min_snr, buf(val_off, 1))
        else
          opts_tree:add(f.opt_unknown, buf(opt_off, consumed)):set_text(
            "Min SNR: (no value)")
        end

      elseif num == options.OPT_ROUTE_RETRY then
        -- A zero-length flag: the sender is re-attempting a route it had
        -- assumed and now considers failed.
        local item = opts_tree:add(f.opt_route_retry, buf(opt_off, consumed))
        if val_len ~= 0 then
          item:set_text(string.format("Route Retry (%d unexpected bytes)", val_len))
        end

      elseif num == options.OPT_ACK_MIC then
        -- A piggy-backed MAC ack. The value is the first 4 bytes of the
        -- acknowledged packet's on-wire MIC — the same public correlation
        -- handle a standalone ack echoes, so it resolves with no keys.
        local item = opts_tree:add(f.opt_ack_mic, buf(opt_off, consumed))
        if val_len == 4 then
          item:set_text("Ack MIC: " .. bytes_to_hex(val))
          local origin = resolve_piggyback_ack(pinfo, bytes_to_hex(val))
          if origin then
            item:add(f.opt_ack_frame, buf(val_off, 4), origin.frame)
            _info_notes[#_info_notes + 1] = "acks #" .. origin.frame
          end
        else
          item:set_text(string.format("Ack MIC: %d bytes (expected 4)", val_len))
        end

      elseif num == options.OPT_TRACE_SIGNAL then
        -- Like a trace route, but each repeater prepends what it heard:
        -- one byte of negative RSSI in dBm, one signed byte of SNR in
        -- centibels.
        local item = opts_tree:add(f.opt_trace_signal, buf(opt_off, consumed))
        if val_len == 0 then
          item:set_text("Trace Signal: (empty)")
        else
          -- One entry per repeater, paired index-for-index with the trace
          -- route. An entry measures the hop into that repeater; the hop
          -- out of the last one is measured by nobody, so the entries
          -- always number one short of the path's hops.
          local routers = val_len // 2
          local extra   = val_len % 2
          item:set_text(string.format("Trace Signal: %d repeater%s%s", routers,
                                      routers == 1 and "" or "s",
                                      extra == 1 and " + 1 trailing byte" or ""))
          for i = 1, routers do
            local rssi = val:byte(i * 2 - 1)
            local snr  = val:byte(i * 2)
            if snr >= 128 then snr = snr - 256 end
            local text = string.format("-%d dBm, %.1f dB SNR", rssi, snr / 10)
            item:add(f.opt_signal_entry, buf(val_off + (i - 1) * 2, 2), text)
              :set_text(string.format("Repeater %d heard: %s", i, text))
          end
        end

      else
        local crit = options.is_critical(num)
        local item = opts_tree:add(f.opt_unknown, buf(opt_off, consumed))
        item:set_text(string.format("Option %d (%d bytes)%s",
                                    num, val_len, crit and " [Critical]" or ""))
        if crit then item:add_proto_expert_info(ef.unk_crit_opt) end
      end

      -- Collect static options for AAD (in ascending option-number order)
      if options.is_static(num) then
        static_opts_out[#static_opts_out + 1] = {number = num, value = val}
      end

      raw_pos = raw_pos + consumed
    end
  end)

  -- Several options are defined as appearing at most once, and the spec
  -- says outright that a packet carrying two of them must be dropped.
  -- Region Code is not among them: several may legitimately be present.
  for num, count in pairs(seen) do
    if count > 1 and options.SINGLETON_OPTIONS[num] then
      flag_violation(opts_tree, buf(start_off, total_len), string.format(
        "%s option appears %d times; at most one is allowed",
        options.KNOWN_OPTION_NAMES[num] or ("Option " .. num), count))
    end
  end

  return start_off + total_len
end

-- ──────────────────────────────────────────────────────────────────────────
-- Broadcast / Beacon
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_broadcast(buf, pinfo, tree, off, full_src, fcf_byte, static_opts)
  local buf_len = buf:len()
  local src_len = full_src and 32 or 3

  if off + src_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end

  local src_bytes = tvb_bytes(buf, off, src_len)
  local src_name  = add_src_addr(tree, buf, off, src_bytes, full_src)
  off = off + src_len

  -- OPTIONS block (always present; 0xFF marker omitted for beacons with no payload)
  off = parse_options(buf, off, buf_len, tree, static_opts, pinfo)

  local payload_len = buf_len - off
  set_endpoints(pinfo, src_name or addr_short(src_bytes), BROADCAST_LABEL)
  if payload_len > 0 then
    local payload_bytes = tvb_bytes(buf, off, payload_len)
    tree:add(f.payload_raw, buf(off, payload_len))
    pinfo.cols.info = "UMSH BCST"
    if app then
      pcall(app.dissect, payload_bytes, tree, pinfo, keystore, crypto, _ctx)
    end
  else
    pinfo.cols.info = "UMSH BCST [Beacon]"
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- MAC Ack
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_uack(buf, pinfo, tree, off)
  local buf_len = buf:len()

  -- A MAC ack carries no destination hint: OPTIONS follow the header
  -- directly, then a fixed 8-byte trailer (ack_mic(4) || ack_tag(4)). No
  -- 0xFF terminator, since the trailer is at a fixed offset from the end.
  local dummy_opts = {}
  off = parse_options(buf, off, buf_len - 8, tree, dummy_opts, pinfo)

  -- Anything between an end-of-options marker and the trailer is not part
  -- of a MAC ack: there is no payload field for it to be.
  if off < buf_len - 8 then
    flag_violation(tree, buf(off, buf_len - 8 - off),
      string.format("%d byte%s between end of options and ack trailer",
                    buf_len - 8 - off, (buf_len - 8 - off) == 1 and "" or "s"))
  end

  if off + 8 > buf_len then tree:add_proto_expert_info(ef.truncated); return end
  local mic_bytes = tvb_bytes(buf, off, 4)      -- ack_mic (public correlation)
  local tag_bytes = tvb_bytes(buf, off + 4, 4)  -- ack_tag (keyed auth)
  tree:add(f.ack_mic, buf(off, 4))
  tree:add(f.ack_tag, buf(off + 4, 4))

  pinfo.cols.info = "UMSH UACK"

  -- ACK correlation: look up the public ack_mic. This needs no keys —
  -- the acknowledged packet's MIC prefix is visible on the wire.
  --
  -- The lookup is only meaningful while the capture is being read in
  -- order; afterwards the recorded answer stands in for it. Entries are
  -- replaced rather than mutated when a MIC prefix repeats, so holding
  -- the entry keeps this ack pointing at the packet it arrived for even
  -- once a later one has claimed the prefix.
  local mic_hex = bytes_to_hex(mic_bytes)
  local origin
  if pinfo.visited then
    origin = _ack_origin[pinfo.number]
  else
    origin = _ack_by_mic[mic_hex]
    _ack_origin[pinfo.number] = origin
  end
  if origin then
    -- If a key let us precompute the expected keyed tag, verify it. A public
    -- ack_mic match establishes only correlation; when a configured key proves
    -- the tag wrong the frame is NOT a valid acknowledgement, so we downgrade
    -- to a "correlates with" forensic link and suppress the ack/back-reference.
    local verified = nil
    if origin.exp_tag_hex then
      verified = (origin.exp_tag_hex == bytes_to_hex(tag_bytes))
      tree:add(f.ack_verified, buf(off + 4, 4), verified)
    end
    local rsp_time = pinfo.abs_ts - origin.timestamp
    tree:add(f.ack_rsp_time, buf(off, 8),
      string.format("%.6f seconds", rsp_time)):set_text(
      string.format("ACK Response Time: %.3f ms", rsp_time * 1000))
    if verified == false then
      -- Correlation only: link the frames but claim no acknowledgement.
      tree:add(f.ack_correlate_frame, buf(off, 4), origin.frame)
      pinfo.cols.info = "UMSH UACK (correlates with #" .. origin.frame .. ", TAG MISMATCH)"
    else
      tree:add(f.ack_req_frame, buf(off, 4), origin.frame)
      pinfo.cols.info = "UMSH UACK (ack for #" .. origin.frame .. ")"
      -- A MAC ack carries no addresses of its own. These are the
      -- acknowledged packet's endpoints, reversed: the ack travels back
      -- the way the packet came. Only filled once the ack is claimed as
      -- genuine, so a tag mismatch below leaves the columns empty rather
      -- than asserting a conversation that did not happen.
      set_endpoints(pinfo, origin.dst_label, origin.src_label)
      -- Store back-reference so the UNAR/BUAR frame can show "Acknowledged in frame N"
      if not pinfo.visited then
        _ack_by_frame[origin.frame] = {
          ack_frame = pinfo.number,
          rsp_time  = rsp_time,
        }
      end
    end
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- Unicast (UNIC and UNAR)
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_unicast(buf, pinfo, tree, off, full_src, fcf_byte, static_opts, ack_req)
  local buf_len = buf:len()

  -- DST hint (3 bytes)
  if off + 3 > buf_len then tree:add_proto_expert_info(ef.truncated); return end
  local dst_bytes = tvb_bytes(buf, off, 3)
  local dst_name  = add_dst_hint(tree, buf, off, dst_bytes)
  off = off + 3

  -- SRC (3 or 32 bytes)
  local src_len = full_src and 32 or 3
  if off + src_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end
  local src_bytes = tvb_bytes(buf, off, src_len)
  local src_name, src_pubkey = add_src_addr(tree, buf, off, src_bytes, full_src)
  off = off + src_len

  -- SECINFO
  local new_off, scf, mic_len, secinfo_raw, is_enc = parse_secinfo(buf, off, tree)
  if not new_off then return end
  off = new_off

  -- OPTIONS block (always present; 0xFF emitted iff payload follows)
  off = parse_options(buf, off, buf_len - mic_len, tree, static_opts, pinfo)

  -- Body (payload or ciphertext)
  local body_start = off
  local body_len   = buf_len - off - mic_len
  if body_len < 0 then tree:add_proto_expert_info(ef.truncated); return end
  local body_bytes = tvb_bytes(buf, off, body_len)
  tree:add(is_enc and f.enc_body or f.payload_raw, buf(off, body_len))
  off = off + body_len

  -- MIC
  local mic_bytes = tvb_bytes(buf, off, mic_len)
  tree:add(f.mic, buf(off, mic_len))

  -- Info column
  local sl = src_name or addr_short(src_bytes)
  local dl = dst_name or hint_short(dst_bytes)
  set_endpoints(pinfo, sl, dl)
  pinfo.cols.info = ack_req and "UMSH UNAR" or "UMSH UNIC"

  -- ACK correlation (keyless): an ack-requested packet publishes its MIC on
  -- the wire, and the returning MAC ack echoes the first 4 bytes as its
  -- ack_mic. Record that prefix now so the ack matches even with no keys.
  -- A keyed expected-tag (filled in below when we can decrypt) is preserved.
  if ack_req and mic_len >= 4 and not pinfo.visited then
    local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
    local prior = _ack_by_mic[mic_hex]
    _ack_by_mic[mic_hex] = {
      frame       = pinfo.number,
      timestamp   = pinfo.abs_ts,
      src_label   = sl,
      dst_label   = dl,
      exp_tag_hex = prior and prior.exp_tag_hex or nil,
    }
  end

  -- Crypto: try to decrypt / verify MIC
  if not crypto then return end
  local pkt_info = {
    fcf_byte                 = fcf_byte,
    static_opts              = static_opts,
    dst_hint                 = dst_bytes,
    src_bytes                = src_bytes,
    src_pubkey_from_keystore = src_pubkey,
    secinfo_raw              = secinfo_raw,
    body_bytes               = body_bytes,
    mic_bytes                = mic_bytes,
    is_encrypted             = is_enc,
  }
  local privkeys = keystore.get_all_privkeys()
  local ok, plain, status, dec_keys, full_cmac =
    pcall(crypto.try_decrypt_unicast, pkt_info, privkeys, full_src)
  if ok and plain then
    tree:add_proto_expert_info(ef.mic_ok)
    if is_enc then
      tree:add(f.payload_dec, buf(body_start, body_len)):set_text(
        "Decrypted Payload (" .. #plain .. " B): " .. bytes_to_hex(plain))
    end
    _ctx.mic_verified = true
    if app then pcall(app.dissect, plain, tree, pinfo, keystore, crypto, _ctx) end

    -- ACK tracking: compute the expected keyed ACK tag for UNAR packets and
    -- attach it to the (already recorded) ack_mic entry, so a matched ack can
    -- be cryptographically verified rather than merely correlated.
    if ack_req and dec_keys and full_cmac then
      local ack_tag = crypto.compute_ack_tag(full_cmac, dec_keys.k_enc)
      if ack_tag then
        local tag_hex = bytes_to_hex(ack_tag)
        tree:add(f.ack_expected, buf(off, mic_len), ack_tag)
          :set_text("Expected ACK Tag: " .. tag_hex)
        if not pinfo.visited and mic_len >= 4 then
          local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
          local entry = _ack_by_mic[mic_hex] or {
            frame     = pinfo.number,
            timestamp = pinfo.abs_ts,
            src_label = sl,
            dst_label = dl,
          }
          entry.exp_tag_hex = tag_hex
          _ack_by_mic[mic_hex] = entry
        end
        -- Back-annotation: show UACK frame if already matched
        local back = _ack_by_frame[pinfo.number]
        if back then
          tree:add(f.ack_rsp_frame, buf(0, 0), back.ack_frame)
          tree:add(f.ack_rsp_time, buf(0, 0),
            string.format("%.6f seconds", back.rsp_time)):set_text(
            string.format("ACK Response Time: %.3f ms", back.rsp_time * 1000))
        end
      end
    end
  else
    tree:add_proto_expert_info(ef.no_key)
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- Multicast (MCST)
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_multicast(buf, pinfo, tree, off, full_src, fcf_byte, static_opts)
  local buf_len = buf:len()

  -- CHANNEL (2 bytes)
  if off + 2 > buf_len then tree:add_proto_expert_info(ef.truncated); return end
  local chan_off   = off
  local chan_bytes = tvb_bytes(buf, off, 2)
  tree:add(f.channel_id, buf(off, 2))
  local ch_entry = keystore.get_channel_by_id(chan_bytes)
  if ch_entry and ch_entry.name ~= "" then
    tree:add(f.channel_name, buf(off, 2), ch_entry.name)
  end
  _ctx.channel   = ch_entry
  _ctx.chan_tvbr = buf(chan_off, 2)
  off = off + 2

  -- SECINFO
  local new_off, scf, mic_len, secinfo_raw, is_enc = parse_secinfo(buf, off, tree)
  if not new_off then return end
  off = new_off
  _ctx.is_enc = is_enc

  -- OPTIONS block (always present; 0xFF always present since body follows)
  off = parse_options(buf, off, buf_len - mic_len, tree, static_opts, pinfo)

  -- For E=0: SRC is in cleartext before the body
  local src_bytes, src_name
  if not is_enc then
    local src_len = full_src and 32 or 3
    if off + src_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end
    src_bytes = tvb_bytes(buf, off, src_len)
    src_name  = add_src_addr(tree, buf, off, src_bytes, full_src)
    off = off + src_len
  end

  -- Body + MIC
  local body_start = off
  local body_len   = buf_len - off - mic_len
  if body_len < 0 then tree:add_proto_expert_info(ef.truncated); return end
  local body_bytes = tvb_bytes(buf, off, body_len)
  tree:add(is_enc and f.enc_body or f.payload_raw, buf(off, body_len))
  off = off + body_len

  local mic_bytes = tvb_bytes(buf, off, mic_len)
  tree:add(f.mic, buf(off, mic_len))

  -- Info column
  local chan_hex = bytes_to_hex(chan_bytes)
  local ch_label = (ch_entry and ch_entry.name ~= "" and ch_entry.name) or chan_hex
  -- The channel is who the packet is addressed to.
  set_endpoints(pinfo, src_name, ch_label)
  pinfo.cols.info = "UMSH MCST"

  -- Crypto. Whether the MIC verifies decides how firmly the channel rules
  -- can be put: the 2-byte channel ID is a hint that may collide, but a MIC
  -- that verifies under the channel key proves which channel it is.
  if not crypto or not ch_entry or not ch_entry.derived_keys then
    if crypto then tree:add_proto_expert_info(ef.no_key) end

  elseif is_enc then
    -- E=1: body = ENCRYPT(SRC || PAYLOAD); use try_decrypt_multicast
    local pkt_info = {
      fcf_byte         = fcf_byte,
      static_opts      = static_opts,
      channel_id       = chan_bytes,
      dst_or_chan      = chan_bytes,
      src_bytes_or_nil = nil,   -- src is inside ciphertext
      secinfo_raw      = secinfo_raw,
      body_bytes       = body_bytes,
      mic_bytes        = mic_bytes,
      is_encrypted     = true,
    }
    local ok2, payload, dec_src, _, status =
      pcall(crypto.try_decrypt_multicast, pkt_info, keystore.get_all_channels(), full_src)
    if ok2 and payload then
      tree:add_proto_expert_info(ef.mic_ok)
      _ctx.mic_verified = true
      local src_len = full_src and 32 or 3
      if dec_src then
        local dec_name = full_src and keystore.lookup_node_by_key(dec_src)
                                   or keystore.lookup_node(dec_src)
        local dec_label = dec_name or addr_short(dec_src)
        tree:add(f.dec_src, buf(body_start, src_len)):set_text(
          "Decrypted SRC: " .. (dec_name or base58.addr(dec_src)))
        tree:add(f.src_addr, buf(body_start, src_len),
                 addr_short(dec_src)):set_hidden()
        -- The sender was inside the ciphertext; now that it is readable it
        -- belongs in the address column like any other.
        set_endpoints(pinfo, dec_label, nil)
      end
      if #payload > 0 then
        tree:add(f.payload_dec, buf(body_start + src_len, body_len - src_len)):set_text(
          "Decrypted Payload (" .. #payload .. " B): " .. bytes_to_hex(payload))
        if app then pcall(app.dissect, payload, tree, pinfo, keystore, crypto, _ctx) end
      end
    elseif ok2 and status == "mic_mismatch" then
      tree:add_proto_expert_info(ef.mic_bad)
    else
      tree:add_proto_expert_info(ef.no_key)
    end

  else
    -- E=0: SRC in cleartext; verify MIC directly with channel keys
    local pkt_info = {
      fcf_byte         = fcf_byte,
      static_opts      = static_opts,
      dst_or_chan      = chan_bytes,
      src_bytes_or_nil = src_bytes,   -- included in AAD
      secinfo_raw      = secinfo_raw,
      body_bytes       = body_bytes,
      mic_bytes        = mic_bytes,
      is_encrypted     = false,
    }
    local ok2, plain, status =
      pcall(crypto.verify_and_decrypt, ch_entry.derived_keys, pkt_info)
    if ok2 and plain then
      tree:add_proto_expert_info(ef.mic_ok)
      _ctx.mic_verified = true
      if app then pcall(app.dissect, plain, tree, pinfo, keystore, crypto, _ctx) end
    elseif ok2 and status == "mic_mismatch" then
      tree:add_proto_expert_info(ef.mic_bad)
    else
      tree:add_proto_expert_info(ef.no_key)
    end
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- Blind Unicast (BUNI and BUAR)
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_blind_unicast(buf, pinfo, tree, off, full_src, fcf_byte, static_opts, ack_req)
  local buf_len = buf:len()

  -- CHANNEL (2 bytes)
  if off + 2 > buf_len then tree:add_proto_expert_info(ef.truncated); return end
  local chan_off   = off
  local chan_bytes = tvb_bytes(buf, off, 2)
  tree:add(f.channel_id, buf(off, 2))
  local ch_entry = keystore.get_channel_by_id(chan_bytes)
  if ch_entry and ch_entry.name ~= "" then
    tree:add(f.channel_name, buf(off, 2), ch_entry.name)
  end
  _ctx.channel = ch_entry
  off = off + 2

  -- SECINFO
  local new_off, scf, mic_len, secinfo_raw, is_enc = parse_secinfo(buf, off, tree)
  if not new_off then return end
  off = new_off
  _ctx.is_enc = is_enc

  -- OPTIONS block (always present; 0xFF always present since body follows)
  off = parse_options(buf, off, buf_len - mic_len, tree, static_opts, pinfo)

  -- Info column base
  local chan_hex = bytes_to_hex(chan_bytes)
  local ch_label = (ch_entry and ch_entry.name ~= "" and ch_entry.name) or chan_hex
  local type_label = ack_req and "UMSH BUAR" or "UMSH BUNI"
  pinfo.cols.info = type_label .. " [" .. ch_label .. "]"

  -- The channel rules run once, from the main dissector, so that a packet
  -- truncated part way through still gets them.
  _ctx.chan_tvbr = buf(chan_off, 2)

  if is_enc then
    -- E=1: ENC_DST_SRC (6 or 35 bytes) | ENC_PAYLOAD | MIC
    local addr_len   = 3 + (full_src and 32 or 3)   -- DST_hint(3) + SRC(3/32)
    local addr_start = off
    if off + addr_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end
    local enc_addr_bytes = tvb_bytes(buf, off, addr_len)
    tree:add(f.enc_addr, buf(off, addr_len))
    off = off + addr_len

    local body_start = off
    local body_len   = buf_len - off - mic_len
    if body_len < 0 then tree:add_proto_expert_info(ef.truncated); return end
    local body_bytes = tvb_bytes(buf, off, body_len)
    tree:add(f.enc_body, buf(off, body_len))
    off = off + body_len

    local mic_bytes = tvb_bytes(buf, off, mic_len)
    tree:add(f.mic, buf(off, mic_len))

    -- ACK correlation (keyless): record the public ack_mic even though the
    -- endpoints are concealed — the ack echoes this MIC prefix regardless.
    if ack_req and mic_len >= 4 and not pinfo.visited then
      local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
      local prior = _ack_by_mic[mic_hex]
      _ack_by_mic[mic_hex] = {
        frame       = pinfo.number,
        timestamp   = pinfo.abs_ts,
        src_label   = prior and prior.src_label or "?",
        dst_label   = prior and prior.dst_label or "?",
        exp_tag_hex = prior and prior.exp_tag_hex or nil,
      }
    end

    -- Crypto (E=1)
    if not crypto then return end
    local pkt_info = {
      fcf_byte       = fcf_byte,
      static_opts    = static_opts,
      channel_id     = chan_bytes,
      dst_or_chan    = chan_bytes,
      enc_addr_bytes = enc_addr_bytes,
      secinfo_raw    = secinfo_raw,
      body_bytes     = body_bytes,
      mic_bytes      = mic_bytes,
      is_encrypted   = true,
    }
    local privkeys = keystore.get_all_privkeys()
    local ok2, payload, dst_hint, dec_src, status, dec_keys, full_cmac =
      pcall(crypto.try_decrypt_blind_unicast, pkt_info, privkeys,
            keystore.get_all_channels(), full_src)
    if ok2 and payload then
      tree:add_proto_expert_info(ef.mic_ok)
      local d_name, s_name
      if dst_hint then
        d_name = keystore.lookup_node(dst_hint)
        tree:add(f.dec_dst, buf(addr_start, 3)):set_text(
          "Decrypted DST: " .. (d_name or hint_label(dst_hint)))
        tree:add(f.dst_addr, buf(addr_start, 3),
                 hint_short(dst_hint)):set_hidden()
      end
      if dec_src then
        local src_disp_len = full_src and 32 or 3
        s_name = full_src and keystore.lookup_node_by_key(dec_src)
                            or keystore.lookup_node(dec_src)
        tree:add(f.dec_src, buf(addr_start + 3, src_disp_len)):set_text(
          "Decrypted SRC: " .. (s_name or base58.addr(dec_src)))
        tree:add(f.src_addr, buf(addr_start + 3, src_disp_len),
                 addr_short(dec_src)):set_hidden()
        set_endpoints(pinfo, s_name or addr_short(dec_src), nil)
      end
      if #payload > 0 then
        tree:add(f.payload_dec, buf(body_start, body_len)):set_text(
          "Decrypted Payload (" .. #payload .. " B): " .. bytes_to_hex(payload))
        if app then pcall(app.dissect, payload, tree, pinfo, keystore, crypto, _ctx) end
      end
      -- ACK tracking for BUAR
      if ack_req and dec_keys and full_cmac then
        local ack_tag = crypto.compute_ack_tag(full_cmac, dec_keys.k_enc)
        if ack_tag then
          local tag_hex = bytes_to_hex(ack_tag)
          tree:add(f.ack_expected, buf(off, mic_len), ack_tag)
            :set_text("Expected ACK Tag: " .. tag_hex)
          if not pinfo.visited and mic_len >= 4 then
            local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
            local entry = _ack_by_mic[mic_hex] or {
              frame     = pinfo.number,
              timestamp = pinfo.abs_ts,
            }
            entry.src_label   = s_name or (dec_src and addr_short(dec_src)) or "?"
            entry.dst_label   = d_name or (dst_hint and hint_short(dst_hint)) or "?"
            entry.exp_tag_hex = tag_hex
            _ack_by_mic[mic_hex] = entry
          end
          local back = _ack_by_frame[pinfo.number]
          if back then
            tree:add(f.ack_rsp_frame, buf(0, 0), back.ack_frame)
            tree:add(f.ack_rsp_time, buf(0, 0),
              string.format("%.6f seconds", back.rsp_time)):set_text(
              string.format("ACK Response Time: %.3f ms", back.rsp_time * 1000))
          end
        end
      end
    elseif ok2 and status == "mic_mismatch" then
      tree:add_proto_expert_info(ef.mic_bad)
    else
      tree:add_proto_expert_info(ef.no_key)
    end

  else
    -- E=0: DST(3) | SRC(3/32) | PAYLOAD | MIC — all in cleartext
    if off + 3 > buf_len then tree:add_proto_expert_info(ef.truncated); return end
    local dst_bytes = tvb_bytes(buf, off, 3)
    local dst_name  = add_dst_hint(tree, buf, off, dst_bytes)
    off = off + 3

    local src_len = full_src and 32 or 3
    if off + src_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end
    local src_bytes = tvb_bytes(buf, off, src_len)
    local src_name, src_pubkey = add_src_addr(tree, buf, off, src_bytes, full_src)
    off = off + src_len

    local body_len = buf_len - off - mic_len
    if body_len < 0 then tree:add_proto_expert_info(ef.truncated); return end
    local body_bytes = tvb_bytes(buf, off, body_len)
    tree:add(f.payload_raw, buf(off, body_len))
    local body_start = off
    off = off + body_len

    local mic_bytes = tvb_bytes(buf, off, mic_len)
    tree:add(f.mic, buf(off, mic_len))

    local sl = src_name or addr_short(src_bytes)
    local dl = dst_name or hint_short(dst_bytes)
    -- The channel stays in Info: for a blind unicast it is the envelope
    -- the packet was addressed under, not the endpoint it is bound for.
    set_endpoints(pinfo, sl, dl)
    pinfo.cols.info = type_label .. " [" .. ch_label .. "]"

    -- ACK correlation (keyless): endpoints are already in cleartext here.
    if ack_req and mic_len >= 4 and not pinfo.visited then
      local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
      local prior = _ack_by_mic[mic_hex]
      _ack_by_mic[mic_hex] = {
        frame       = pinfo.number,
        timestamp   = pinfo.abs_ts,
        src_label   = sl,
        dst_label   = dl,
        exp_tag_hex = prior and prior.exp_tag_hex or nil,
      }
    end

    -- Crypto (E=0): need channel key + privkey pair → derive blind keys
    if not crypto or not ch_entry or not ch_entry.derived_keys then
      if crypto then tree:add_proto_expert_info(ef.no_key) end
      return
    end

    local privkeys = keystore.get_all_privkeys()
    local pkt_info = {
      fcf_byte         = fcf_byte,
      static_opts      = static_opts,
      dst_or_chan      = chan_bytes,
      src_bytes_or_nil = src_bytes,
      secinfo_raw      = secinfo_raw,
      body_bytes       = body_bytes,
      mic_bytes        = mic_bytes,
      is_encrypted     = false,
    }
    local found = false
    for _, pk in ipairs(privkeys) do
      local ok_s, x25519_priv = pcall(crypto.ed25519_seed_to_x25519_scalar, pk.seed_bytes)
      if not (ok_s and x25519_priv) then goto continue end

      -- Try with known peer Ed25519 pubkey (S=1 or keystore lookup)
      local peer_ed_pubkey = src_pubkey or (full_src and src_bytes)
      local peer_x25519_list = {}
      if peer_ed_pubkey then
        local ok_p, xp = pcall(crypto.ed25519_pub_to_x25519_pub, peer_ed_pubkey)
        if ok_p and xp then peer_x25519_list[1] = xp end
      else
        -- Try other privkeys as potential peer
        for _, pk2 in ipairs(privkeys) do
          if pk2 ~= pk and pk2.x25519_pubkey then
            peer_x25519_list[#peer_x25519_list+1] = pk2.x25519_pubkey
          end
        end
      end

      for _, x25519_peer in ipairs(peer_x25519_list) do
        local ok2, plain, status, blind_keys, full_cmac = pcall(function()
          local ss    = crypto.x25519(x25519_priv, x25519_peer)
          local pw    = crypto.derive_pairwise_keys(ss)
          if not pw then return nil, "no_pw" end
          local blind = crypto.derive_blind_keys(pw, ch_entry.derived_keys)
          local b, s, fc = crypto.verify_and_decrypt(blind, pkt_info)
          if b then return b, s, blind, fc end
          return nil, s
        end)
        if ok2 and plain then
          tree:add_proto_expert_info(ef.mic_ok)
          _ctx.mic_verified = true
          if app then pcall(app.dissect, plain, tree, pinfo, keystore, crypto, _ctx) end
          -- ACK tracking for E=0 BUAR
          if ack_req and blind_keys and full_cmac then
            local ack_tag = crypto.compute_ack_tag(full_cmac, blind_keys.k_enc)
            if ack_tag then
              local tag_hex = bytes_to_hex(ack_tag)
              tree:add(f.ack_expected, buf(off, mic_len), ack_tag)
                :set_text("Expected ACK Tag: " .. tag_hex)
              if not pinfo.visited and mic_len >= 4 then
                local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
                local entry = _ack_by_mic[mic_hex] or {
                  frame     = pinfo.number,
                  timestamp = pinfo.abs_ts,
                  src_label = sl,
                  dst_label = dl,
                }
                entry.exp_tag_hex = tag_hex
                _ack_by_mic[mic_hex] = entry
              end
              local back = _ack_by_frame[pinfo.number]
              if back then
                tree:add(f.ack_rsp_frame, buf(0, 0), back.ack_frame)
                tree:add(f.ack_rsp_time, buf(0, 0),
                  string.format("%.6f seconds", back.rsp_time)):set_text(
                  string.format("ACK Response Time: %.3f ms", back.rsp_time * 1000))
              end
            end
          end
          found = true; break
        elseif ok2 and status == "mic_mismatch" then
          tree:add_proto_expert_info(ef.mic_bad)
          found = true; break
        end
      end
      if found then break end
      ::continue::
    end
    if not found then tree:add_proto_expert_info(ef.no_key) end
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- Main dissector
-- ──────────────────────────────────────────────────────────────────────────

-- Assigned below, once the packet-shape checks it needs are in scope.
-- Declared here so the dissector can decline a packet that is not ours:
-- the LoRa sync word UMSH runs under is shared with every other private
-- LoRa network, so being registered for it is not proof of ownership.
local looks_like_umsh

function umsh.dissector(buf, pinfo, tree)
  local buf_len = buf:len()
  if buf_len < 1 then return 0 end
  -- Returning zero leaves the payload to whoever else wants it.
  if not looks_like_umsh(buf) then return 0 end

  local fcf_val   = buf(0, 1):uint()
  local ver       = (fcf_val >> 6) & 0x03
  local pkt_type  = (fcf_val >> 3) & 0x07
  local full_src  = (fcf_val & 0x04) ~= 0
  local has_fhops = (fcf_val & 0x01) ~= 0
  local fcf_byte  = tvb_bytes(buf, 0, 1)

  pinfo.cols.protocol = "UMSH"

  local root = tree:add(umsh, buf())

  _violations = {}
  _info_notes = {}
  _ctx = {
    pkt_type     = pkt_type,
    full_src     = full_src,
    fhops        = nil,
    channel      = nil,
    is_enc       = false,
    mic_verified = false,
    flag         = flag_violation,
  }

  -- FCF subtree
  local fcf_tree = root:add(f.fcf, buf(0, 1))
  fcf_tree:add(f.fcf_version,  buf(0, 1))
  fcf_tree:add(f.fcf_type,     buf(0, 1))
  fcf_tree:add(f.fcf_full_src, buf(0, 1))
  fcf_tree:add(f.fcf_reserved, buf(0, 1))
  fcf_tree:add(f.fcf_fhops,    buf(0, 1))

  -- Version check
  if ver ~= 3 then
    root:add_proto_expert_info(ef.bad_version)
    return 1
  end

  -- The reserved FCF bit must be zero; a receiver drops a packet that sets it.
  if (fcf_val & 0x02) ~= 0 then
    flag_violation(fcf_tree, buf(0, 1), "FCF reserved bit (R) must be zero")
  end

  local off = 1
  local static_opts = {}

  -- FHOPS byte
  if has_fhops then
    if off >= buf_len then root:add_proto_expert_info(ef.truncated); return off end
    local fh_val = buf(off, 1):uint()
    local fh_rem = (fh_val >> 4) & 0x0F
    local fh_acc = fh_val & 0x0F
    -- The sum is the flood limit the sender set, except where a bridge has
    -- taken hops off the remaining nibble on its own—so a shrinking total
    -- across a capture is itself the interesting reading.
    local fh_tree = root:add(f.fhops, buf(off, 1),
                             string.format("%d of %d", fh_acc, fh_rem + fh_acc))
    fh_tree:add(f.fhops_rem, buf(off, 1))
    fh_tree:add(f.fhops_acc, buf(off, 1))
    _ctx.fhops = fh_val
    off = off + 1
  end

  -- Packet type name for info column default
  local type_name = TYPE_SHORT[pkt_type + 1] or ("TYPE" .. pkt_type)
  pinfo.cols.info = "UMSH " .. type_name

  -- Per-type dispatch
  if pkt_type == 0 then
    dissect_broadcast(buf, pinfo, root, off, full_src, fcf_byte, static_opts)
  elseif pkt_type == 1 then
    dissect_uack(buf, pinfo, root, off)
  elseif pkt_type == 2 or pkt_type == 3 then
    dissect_unicast(buf, pinfo, root, off, full_src, fcf_byte, static_opts, pkt_type == 3)
  elseif pkt_type == 4 then
    dissect_multicast(buf, pinfo, root, off, full_src, fcf_byte, static_opts)
  elseif pkt_type == 5 then
    flag_violation(root, buf(0, 1), "Packet type 5 is reserved", ef.rsvd_type)
  elseif pkt_type == 6 or pkt_type == 7 then
    dissect_blind_unicast(buf, pinfo, root, off, full_src, fcf_byte, static_opts, pkt_type == 7)
  end

  -- Rules attached to the well-known channel names. Run here rather than
  -- inside the per-type dissectors so that a packet truncated part way
  -- through still gets them, and so the MIC verdict is already known.
  if _ctx.channel then
    check_channel_rules(root, _ctx.chan_tvbr or buf(0, 1), _ctx.channel, {
      is_enc       = _ctx.is_enc,
      blind        = (pkt_type == 6 or pkt_type == 7),
      mic_verified = _ctx.mic_verified,
    })
  end

  -- The per-type dissectors own the Info column and rewrite it after most
  -- of the checks have run, so these go on last.
  if #_info_notes > 0 then
    pinfo.cols.info:append(" (" .. table.concat(_info_notes, ", ") .. ")")
  end
  if #_violations > 0 then
    pinfo.cols.info:append(
      #_violations == 1 and "  [VIOLATION]"
                        or string.format("  [%d VIOLATIONS]", #_violations))
  end

  return buf_len
end

-- ──────────────────────────────────────────────────────────────────────────
-- Heuristic helpers
-- ──────────────────────────────────────────────────────────────────────────

-- Returns true if the FCF byte looks like a valid UMSH FCF.
local function is_umsh_fcf(byte)
  if (byte >> 6) ~= 3 then return false end         -- version must be 0b11
  if ((byte >> 3) & 7) == 5 then return false end   -- type 5 is reserved/invalid
  return true
end

-- Minimum packet lengths by packet type (without optional OPTIONS/FHOPS).
-- FCF(1) + type-specific minimums.
local MIN_LEN = {
  [0] = 1 + 3,    -- BCST:  FCF + SRC_hint (beacon)
  [1] = 1 + 8,    -- UACK:  FCF + ACK trailer (ack_mic||ack_tag); no DST hint
  [2] = 1 + 3 + 3 + 5 + 4,  -- UNIC:  FCF+DST+SRC_hint+SECINFO+MIC4
  [3] = 1 + 3 + 3 + 5 + 4,  -- UNAR:  same
  [4] = 1 + 2 + 5 + 4,       -- MCST:  FCF+CHANNEL+SECINFO+MIC4
  [5] = 1,                    -- RSVD (will be rejected)
  [6] = 1 + 2 + 5 + 4,       -- BUNI:  FCF+CHANNEL+SECINFO+MIC4
  [7] = 1 + 2 + 5 + 4,       -- BUAR:  same
}

local function validate_min_length(fcf, buf_len)
  local pkt_type = (fcf >> 3) & 0x07
  local min = MIN_LEN[pkt_type] or 1
  -- If FHOPS present, add 1 byte
  if (fcf & 0x01) ~= 0 then min = min + 1 end
  return buf_len >= min
end

-- Fills the forward declaration made above the dissector.
looks_like_umsh = function(buf)
  if buf:len() < 4 then return false end
  local fcf = buf(0, 1):uint()
  if not is_umsh_fcf(fcf) then return false end
  return validate_min_length(fcf, buf:len())
end

local function heuristic(buf, pinfo, tree)
  if not looks_like_umsh(buf) then return false end
  umsh.dissector(buf, pinfo, tree)
  return true
end

-- ──────────────────────────────────────────────────────────────────────────
-- Preferences changed callback
-- (Also called once at startup to apply initial/default preference values.)
-- ──────────────────────────────────────────────────────────────────────────
local function apply_prefs()
  -- Rebuild keystore from preferences
  if _has_uat then
    local keys = umsh.prefs.keys
    keystore.rebuild_from_uat(keys)
  else
    keystore.rebuild(umsh.prefs.node_names, umsh.prefs.privkeys, umsh.prefs.channel_keys)
  end

  -- Merge optional key file (silently ignored if path is empty or file missing)
  keystore.load_keyfile(umsh.prefs.keyfile)

  -- The two well-known channels derive from names the spec fixes, so their
  -- keys are public knowledge and cost nothing to carry: emergency traffic
  -- verifies and public traffic decrypts with no configuration at all.
  -- Added after the key file, which rebuilds the tables from scratch.
  keystore.add_builtin_channels()

  -- Recompute channel crypto after rebuild
  if crypto then keystore.refresh_channel_crypto() end

  -- Update UDP port registration
  local new_port = umsh.prefs.udp_port
  if _registered_port ~= 0 and _registered_port ~= new_port then
    _udp_table:remove(_registered_port, umsh)
    _registered_port = 0
  end
  if new_port ~= 0 and new_port ~= _registered_port then
    _udp_table:add(new_port, umsh)
    _registered_port = new_port
  end
end

function umsh.prefs_changed() apply_prefs() end
apply_prefs()  -- apply initial preferences at load time

-- ──────────────────────────────────────────────────────────────────────────
-- Transport registrations
-- ──────────────────────────────────────────────────────────────────────────

-- Heuristic over UDP (always active; claims only validated packets)
umsh:register_heuristic("udp", heuristic)

-- LoRaTAP (DLT 270), which `umshctl`'s Wireshark extcap interface writes.
--
-- LoRaTAP hands its payload to a table keyed on the sync word rather than
-- offering a heuristic list, so this claims the private-LoRa sync word
-- UMSH runs under. That word is shared with other private networks, which
-- is why `umsh.dissector` declines a payload that is not shaped like a
-- UMSH packet instead of claiming everything under it. "Decode As" can
-- still point another sync word here.
local LORA_SYNCWORD_PRIVATE = 0x12
pcall(function()
  DissectorTable.get("loratap.syncword"):add(LORA_SYNCWORD_PRIVATE, umsh)
end)

-- Synthetic UDP encapsulation used by the `umshctl capture` command for raw
-- ULCP frames. Kept in a sibling module so the mesh dissector's
-- protocol logic remains independent of the host/device control plane.
pcall(function()
  require("ulcp").register()
end)
