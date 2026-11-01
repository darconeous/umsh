-- UMSH Mesh Network—Wireshark Lua dissector (entry point)
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
f.opt_trace        = ProtoField.string ("umsh.opt.trace",         "Trace")
f.opt_srcroute     = ProtoField.string ("umsh.opt.source_route",  "Source Route")
f.opt_router_hint  = ProtoField.string ("umsh.opt.route_repeater","Router Hint")
f.opt_op_callsign  = ProtoField.string ("umsh.opt.op_callsign",   "Operator Callsign")
f.opt_sta_callsign = ProtoField.string ("umsh.opt.sta_callsign",  "Station Callsign")
f.opt_min_rssi     = ProtoField.int8   ("umsh.opt.min_rssi",      "Min RSSI",         base.DEC)
f.opt_min_snr      = ProtoField.int8   ("umsh.opt.min_snr",       "Min SNR",          base.DEC)
f.opt_route_retry  = ProtoField.none   ("umsh.opt.route_retry",   "Route Retry")
f.opt_fence        = ProtoField.none   ("umsh.opt.fence",         "Fence")
f.opt_ack_mic      = ProtoField.bytes  ("umsh.opt.ack_mic",       "Ack MIC")
f.opt_frame_sig    = ProtoField.bytes  ("umsh.opt.frame_signature", "Frame Signature")
f.opt_frame_sig_ctr = ProtoField.uint32("umsh.opt.frame_signature.counter", "Frame Counter", base.DEC)
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
f.scf_signed   = ProtoField.bool   ("umsh.scf.d",          "Signed (D)",         8, nil, 0x08)
f.frame_ctr    = ProtoField.uint32 ("umsh.frame_counter",  "Frame Counter",      base.DEC)
f.salt         = ProtoField.uint16 ("umsh.salt",           "Salt",               base.HEX)
f.mic          = ProtoField.bytes  ("umsh.mic",            "MIC")
-- The frame signature, from the trailer (D set) or from a broadcast's
-- Frame Signature option. Shown, never checked: there is no Ed25519 here.
f.signature    = ProtoField.bytes  ("umsh.signature",      "Signature")

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
  f.options, f.opt_region_code, f.opt_trace, f.opt_srcroute, f.opt_router_hint,
  f.opt_op_callsign, f.opt_sta_callsign, f.opt_min_rssi, f.opt_min_snr,
  f.opt_route_retry, f.opt_fence, f.opt_ack_mic, f.opt_ack_frame,
  f.opt_frame_sig, f.opt_frame_sig_ctr,
  f.opt_signal_entry, f.opt_unknown,
  f.dst_hint, f.src_hint, f.src_key, f.channel_id, f.ack_mic, f.ack_tag,
  f.src_name, f.dst_name, f.channel_name, f.src_addr, f.dst_addr, f.violation,
  f.secinfo, f.scf, f.scf_enc, f.scf_mic_size, f.scf_salt_bit, f.scf_signed,
  f.frame_ctr, f.salt, f.mic, f.signature,
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
ef.no_peer_key  = ProtoExpert.new("umsh.no_peer_key",  "Unknown peer key",         expert.group.UNDECODED,  expert.severity.NOTE)
ef.unk_fwd_crit = ProtoExpert.new("umsh.unknown_fwd_crit", "Unknown forwarding-critical option", expert.group.PROTOCOL, expert.severity.WARN)
ef.unk_dlv_crit = ProtoExpert.new("umsh.unknown_dlv_crit", "Unknown delivery-critical option",   expert.group.PROTOCOL, expert.severity.WARN)
ef.bad_options  = ProtoExpert.new("umsh.malformed_options", "Malformed options block",          expert.group.MALFORMED, expert.severity.ERROR)
ef.bad_opt_value = ProtoExpert.new("umsh.malformed_option", "Malformed option value",           expert.group.MALFORMED, expert.severity.WARN)
ef.rsvd_type    = ProtoExpert.new("umsh.reserved_type","Reserved packet type",     expert.group.PROTOCOL,   expert.severity.WARN)
-- Named apart from the `umsh.violation` field on purpose: an expert and a
-- field share one namespace, and giving both the same abbreviation makes
-- the filter match two things at once.
ef.violation    = ProtoExpert.new("umsh.prohibited",   "Protocol violation",       expert.group.PROTOCOL,   expert.severity.ERROR)

umsh.experts = {
  ef.bad_version, ef.truncated, ef.mic_bad, ef.mic_ok,
  ef.no_key, ef.no_peer_key, ef.unk_fwd_crit, ef.unk_dlv_crit,
  ef.bad_options, ef.bad_opt_value, ef.rsvd_type, ef.violation,
}

-- ──────────────────────────────────────────────────────────────────────────
-- Preferences
-- ──────────────────────────────────────────────────────────────────────────

-- Keys are three string preferences, not a Pref.uat table. Merely calling
-- Pref.uat makes tshark and Wireshark crash on exit: libwireshark frees its
-- UAT list without clearing the pointer, then the Lua finalizer for the pref
-- walks the freed list. The crash lands before stdout is flushed, so piped
-- tshark output comes back truncated or empty. keystore.rebuild_from_uat
-- stays as the way back once upstream fixes it.
umsh.prefs.node_names   = Pref.string("Node names",   "",
  "One per line: <key>:<display-name>\n"
  .. "<key> is 64 hex chars, 44 base58 chars, or umsh:n:<base58>")
umsh.prefs.privkeys     = Pref.string("Private keys", "",
  "One per line: <ed25519-seed>:<display-name>\n"
  .. "The seed is 64 hex chars or 44 base58 chars")
umsh.prefs.channel_keys = Pref.string("Channel keys", "",
  "One per line:\n  <key>:<display-name>\n  umsh:ck:<base58>:<display-name>"
  .. "\n  umsh:cs:<name>:<display-name>")

umsh.prefs.udp_port     = Pref.uint  ("UDP Port", 15056, "UDP port to dissect as UMSH (0 = disabled)")
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
-- ack echoes that prefix. When a private key is available the packet's full
-- S2V output V and the keys that sealed it are also recorded, letting a
-- matched ack's keyed tag be cryptographically verified (not just
-- correlated).
--
-- _ack_by_mic:   ack_mic_hex → {frame=N, timestamp=T, src_label=S,
--                               dst_label=D, src_addr=A, dst_addr=A,
--                               src_name=N, dst_name=N,
--                               ack_v=<16B V or nil>,
--                               ack_keys=<{k_enc, k_mic} or nil>}
--                 The labels are what the columns show; the addresses are
--                 the canonical umsh.src_addr/umsh.dst_addr strings, and the
--                 names whatever the keystore resolved. Any of them is nil
--                 when the packet concealed it.
-- _ack_by_frame: frame_num → {ack_frame=N, rsp_time=delta_seconds} (back-annotation)
-- _ack_origin:   ack frame_num → the _ack_by_mic entry that ack resolved to
--
-- _ack_by_mic holds only the most recent packet published under a given
-- ack_mic, which is all a *new* ack needs. It is not what an already-seen
-- ack needs: a retransmission publishes the same MIC prefix and takes the
-- entry over, so an ack resolved against it once cannot resolve against it
-- again. Wireshark re-dissects a frame whenever it is selected, and the
-- packet list keeps the first pass's Info column—which is why the
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
-- form alone—a keystore name displaces it whenever one is known, and the
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
-- prepends itself to a trace, so hint 0 is the repeater nearest the
-- receiver and the packet moved right to left. A source route names the
-- next repeater first, so it moves left to right.
--
-- `hints` is a list of 2-byte router hints.
local function route_path(hints, arrow)
  -- An empty route is a normal state, not a finding: a trace that no
  -- repeater has touched yet, or a source route the last named repeater
  -- emptied. A dash says so without competing with the rows that name
  -- repeaters.
  if #hints == 0 then return "—" end
  local out = {}
  for i, hint in ipairs(hints) do
    out[i] = base58.router_hint(hint) or bytes_to_hex(hint)
  end
  return table.concat(out, arrow)
end

-- A run of 2-byte router hints as a list, and whether a byte is left over.
local function split_hints(val)
  local hints = {}
  for i = 1, #val // 2 do hints[i] = val:sub(i * 2 - 1, i * 2) end
  return hints, #val % 2 == 1
end

-- A trace record's signal, or nil for a bridged hop: an RSSI and SNR of zero
-- is what a hop that took the packet off a point-to-point link writes.
local function signal_text(rssi, snr)
  if rssi == 0 and snr == 0 then return nil end
  return string.format("-%d dBm, %.1f dB SNR", rssi, snr / 10)
end

-- A region code is two bytes of ARNCE/HAM-16. Anything that decodes to one to
-- three letters is a short code and is shown as one; everything else is shown
-- as hex. The two spaces cannot collide: the spec transforms any hash prefix
-- that would have decoded to nothing but letters out of the letter range,
-- which is what makes the all-letter test sufficient on its own. A short code
-- bearing a digit is deliberately not read back—it is not vacated, so the
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
      "Emergency channel traffic must not be encrypted—it must be " ..
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
-- packet claims rather than a proven identity—the same caveat the
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
  local name
  if full_src then
    tree:add(f.src_key, buf(off, 32)):set_text(
      "Source Public Key: " .. base58.key_full(src_bytes))
    name = keystore.lookup_node_by_key(src_bytes)
  else
    tree:add(f.src_hint, buf(off, 3)):set_text(
      "Source Hint: " .. hint_label(src_bytes))
    name = keystore.lookup_node(src_bytes)
  end
  tree:add(f.src_addr, buf(off, #src_bytes), addr_short(src_bytes)):set_hidden()
  if name and name ~= "" then
    tree:add(f.src_name, buf(off, #src_bytes), name)
  end
  return name
end

-- Why a pairwise frame did not verify, from crypto.try_pairwise's status:
-- a seed was the destination but the source's key is unknown, or a pairing
-- was tried and its MIC failed, or no seed is the destination at all.
local function add_pairwise_failure(tree, status)
  if status == "unknown peer key" then
    tree:add_proto_expert_info(ef.no_peer_key)
  elseif status == "mic_mismatch" then
    tree:add_proto_expert_info(ef.mic_bad)
  else
    tree:add_proto_expert_info(ef.no_key)
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- Frame signatures
--
-- With the SCF's D bit set, a 64-byte Ed25519 signature ends the protected
-- region, just ahead of the MIC: the MIC's S2 covers it, and with E set it
-- is encrypted along with the payload. A broadcast signs through option 0
-- instead. The dissector has no Ed25519, so a signature is shown but never
-- checked.
-- ──────────────────────────────────────────────────────────────────────────
local SIG_LEN = 64

local function add_signature(tree, tvbr, sig_bytes)
  tree:add(f.signature, tvbr, sig_bytes):set_text(
    "Signature (not verified): " .. bytes_to_hex(sig_bytes))
end

-- Split a recovered protected region into what precedes the signature and
-- the signature itself. With no signature, the region is all payload.
local function split_signature(region, sig_len)
  if sig_len == 0 then return region, nil end
  return region:sub(1, #region - sig_len), region:sub(-sig_len)
end

-- A cleartext body: the payload, then the signature when there is one.
-- A ciphertext body stays one item, since the boundary means nothing until
-- it is decrypted.
local function add_body(tree, buf, off, body_len, sig_len, is_enc)
  if is_enc then
    tree:add(f.enc_body, buf(off, body_len))
    return
  end
  local payload_len = body_len - sig_len
  tree:add(f.payload_raw, buf(off, payload_len))
  if sig_len > 0 then
    add_signature(tree, buf(off + payload_len, sig_len),
                  tvb_bytes(buf, off + payload_len, sig_len))
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- parse_secinfo
-- Parses the SECINFO field starting at `off` in `buf` and adds to `tree`.
-- Returns: new_off, scf_byte, mic_len, secinfo_raw, is_enc, sig_len
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
  scf_tree:add(f.scf_signed,   buf(off, 1))
  -- The low three SCF bits are reserved and must be zero; an unknown bit
  -- there could change how everything after SECINFO is read.
  if (scf & 0x07) ~= 0 then
    flag_violation(scf_tree, buf(off, 1),
      string.format("SCF reserved bits must be zero (low three bits are 0x%X)", scf & 0x07))
  end
  local signed = (scf & 0x08) ~= 0
  _ctx.signed = signed
  off = off + 1
  si_tree:add(f.frame_ctr, buf(off, 4))
  off = off + 4
  if has_salt then
    si_tree:add(f.salt, buf(off, 2))
    off = off + 2
  end

  return off, scf, mic_len, secinfo_raw, is_enc, signed and SIG_LEN or 0
end

-- ──────────────────────────────────────────────────────────────────────────
-- parse_options
-- Decodes the CoAP-style options block starting at `start_off` up to `bound`.
-- Populates `static_opts_out` with {number, value} pairs for AAD construction.
-- Returns the new offset (after the 0xFF terminator, or at `bound` if absent),
-- a table counting each option number seen, and the frame's one well-formed
-- Frame Signature as {counter, signature}, if it has one that counts.
-- ──────────────────────────────────────────────────────────────────────────
local SECINFO_TYPES = {[2] = true, [3] = true, [4] = true, [6] = true, [7] = true}

local function parse_options(buf, start_off, bound, tree, static_opts_out, pinfo)
  if start_off >= bound then return start_off, {} end

  local avail = bound - start_off
  local raw   = tvb_bytes(buf, start_off, avail)

  local total_len
  local scan_ok, scan_err = pcall(function() total_len = options.scan_length(raw, 1) end)
  if not scan_ok or not total_len then
    -- A block that frames correctly but breaks a numeric rule (an option
    -- number past 0xFFFF, say) is malformed rather than cut short.
    local msg = tostring(scan_err or "")
    if msg:sub(1, #options.MALFORMED_PREFIX) == options.MALFORMED_PREFIX then
      tree:add_proto_expert_info(ef.bad_options,
        "Malformed options block: " .. msg:sub(#options.MALFORMED_PREFIX + 1))
    else
      tree:add_proto_expert_info(ef.truncated)
    end
    return start_off, {}
  end

  -- A block that is nothing but its terminator carries no options. Adding a
  -- subtree for it puts an `Options: ff` row in the majority of packets that
  -- says nothing at all, so it is left out; the byte itself is still visible
  -- in the bytes pane.
  if total_len == 1 and raw:byte(1) == 0xFF then
    return start_off + 1, {}
  end

  local opts_tree = tree:add(f.options, buf(start_off, total_len))
  opts_tree:set_text(string.format("Options (%d byte%s)",
                                   total_len, total_len == 1 and "" or "s"))

  local seen = {}
  local frame_sigs, frame_sig = {}, nil
  local raw_pos = 1  -- 1-indexed position in buf
  pcall(function()
    for num, val, consumed in options.decode(raw, 1) do
      local opt_off = start_off + raw_pos - 1   -- absolute offset in buf
      local val_len = #val
      local val_off = opt_off + consumed - val_len  -- offset of value bytes

      seen[num] = (seen[num] or 0) + 1

      if num == options.OPT_FRAME_SIGNATURE then
        -- COUNTER(4) ‖ SIG(64). Any other length is handled as an
        -- unrecognized option, which a non-critical one makes harmless.
        local item = opts_tree:add(f.opt_frame_sig, buf(opt_off, consumed))
        frame_sigs[#frame_sigs + 1] = item
        if val_len == options.FRAME_SIGNATURE_LEN then
          local counter = buf(val_off, 4):uint()
          item:set_text(string.format("Frame Signature (not verified): counter %d", counter))
          item:add(f.opt_frame_sig_ctr, buf(val_off, 4))
          add_signature(item, buf(val_off + 4, SIG_LEN), val:sub(5))
          frame_sig = {counter = counter, signature = val:sub(5)}
        else
          item:set_text(string.format("Frame Signature: malformed (%d byte%s), ignored",
                                      val_len, val_len == 1 and "" or "s"))
          item:add_proto_expert_info(ef.bad_opt_value, string.format(
            "Frame Signature value must be %d bytes (has %d)",
            options.FRAME_SIGNATURE_LEN, val_len))
        end

      elseif num == options.OPT_REGION_CODE then
        local cs   = region_label(val)
        local tvbr = (val_len > 0) and buf(val_off, val_len) or buf(opt_off, consumed)
        opts_tree:add(f.opt_region_code, tvbr, cs):set_text("Region Code: " .. cs)

      elseif num == options.OPT_SOURCE_ROUTE then
        -- The value is a run of 2-byte router hints, one per repeater. The
        -- repeater count is not the hop count: a route naming N repeaters
        -- describes N+1 transmissions, since the legs into the first
        -- repeater and out of the last one belong to no hint.
        local hints, extra = split_hints(val)
        local routers = #hints
        local path    = route_path(hints, " → ")
        local item = opts_tree:add(f.opt_srcroute, buf(opt_off, consumed), path)
        local note = ""
        if routers > 0 then
          note = string.format(" (%d repeater%s%s)", routers,
                               routers == 1 and "" or "s",
                               extra and ", 1 trailing byte" or "")
        elseif extra then
          note = " (1 trailing byte)"
        end
        item:set_text("Source Route: " .. path .. note)
        for i, hint in ipairs(hints) do
          item:add(f.opt_router_hint, buf(val_off + (i - 1) * 2, 2),
                   base58.router_hint(hint) or ""):set_text(
            string.format("Repeater %d: %s", i, base58.router_hint_full(hint)))
        end

      elseif num == options.OPT_TRACE then
        -- Each forwarding hop prepends an entry, so entry 1 is the repeater
        -- nearest the receiver. With signal, an entry also carries what that
        -- hop heard: one byte of negative RSSI in dBm, one signed byte of
        -- SNR in centibels. The hints-only forms keep the path and drop the
        -- signal; a truncated one has also dropped its oldest hops.
        local trace = options.parse_trace(val)
        if not trace then
          -- Handled as unrecognized within its own class: a repeater does
          -- not forward the frame, a receiver ignores the trace.
          local item = opts_tree:add(f.opt_trace, buf(opt_off, consumed), "malformed")
          item:set_text(string.format("Trace: malformed (%d byte%s) %s", val_len,
                                      val_len == 1 and "" or "s",
                                      options.criticality_label(num)))
          item:add_proto_expert_info(ef.bad_opt_value,
            string.format("Malformed Trace value (%d bytes)", val_len))
        else
          local hints = {}
          for i, entry in ipairs(trace.entries) do hints[i] = entry.hint end
          local path = route_path(hints, " ← ")
          local count = #hints
          local label, noun = "Trace", "repeater"
          if trace.form == options.TRACE_HINTS_ONLY then
            label = "Trace (hints only)"
          elseif trace.form == options.TRACE_TRUNCATED then
            label, noun = "Trace (truncated)", "most recent repeater"
          end
          local note = ""
          if count > 0 then
            note = string.format(" (%d %s%s)", count, noun, count == 1 and "" or "s")
          end
          local item = opts_tree:add(f.opt_trace, buf(opt_off, consumed), path)
          item:set_text(label .. ": " .. path .. note)
          for i, entry in ipairs(trace.entries) do
            local hint_range = buf(val_off + entry.offset, 2)
            local text = string.format("Repeater %d: %s", i, base58.router_hint_full(entry.hint))
            local hint_item = item:add(f.opt_router_hint, hint_range,
                                       base58.router_hint(entry.hint) or "")
            if entry.rssi then
              local signal = signal_text(entry.rssi, entry.snr)
              local sig_range = buf(val_off + entry.offset + 2, 2)
              if signal then
                hint_item:set_text(text .. ", heard " .. signal)
                hint_item:add(f.opt_signal_entry, sig_range, signal)
              else
                hint_item:set_text(text .. ", bridged hop")
                hint_item:add(f.opt_signal_entry, sig_range, "bridged")
              end
            else
              hint_item:set_text(text)
            end
          end
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

      elseif num == options.OPT_FENCE then
        -- A zero-length flag that means nothing: forwarding-critical, so a
        -- repeater that does not know it does not forward the frame.
        local item = opts_tree:add(f.opt_fence, buf(opt_off, consumed))
        if val_len ~= 0 then
          item:set_text(string.format("Fence (%d unexpected bytes)", val_len))
        end

      elseif num == options.OPT_ACK_MIC then
        -- A piggy-backed MAC ack. The value is the first 4 bytes of the
        -- acknowledged packet's on-wire MIC—the same public correlation
        -- handle a standalone ack echoes, so it resolves with no keys.
        local item = opts_tree:add(f.opt_ack_mic, buf(opt_off, consumed))
        if val_len == 4 then
          item:set_text("Ack MIC: " .. bytes_to_hex(val))
          _ctx.ack_mic = bytes_to_hex(val)
          local origin = resolve_piggyback_ack(pinfo, bytes_to_hex(val))
          if origin then
            item:add(f.opt_ack_frame, buf(val_off, 4), origin.frame)
            _info_notes[#_info_notes + 1] = "acks #" .. origin.frame
          end
        else
          item:set_text(string.format("Ack MIC: %d bytes (expected 4)", val_len))
        end

      else
        -- The number alone says what an unknown option demands: a repeater
        -- does not forward past a forwarding-critical one, and an endpoint
        -- does not accept a frame carrying a delivery-critical one.
        local classes = options.criticality_label(num)
        local item = opts_tree:add(f.opt_unknown, buf(opt_off, consumed))
        item:set_text(string.format("Option %d (%d bytes)%s", num, val_len,
                                    classes ~= "" and " " .. classes or ""))
        if options.is_forwarding_critical(num) then
          item:add_proto_expert_info(ef.unk_fwd_crit)
        end
        if options.is_delivery_critical(num) then
          item:add_proto_expert_info(ef.unk_dlv_crit)
        end
      end

      -- Collect static options for AAD (in ascending option-number order)
      if options.is_static(num) then
        static_opts_out[#static_opts_out + 1] = {number = num, value = val}
      end

      raw_pos = raw_pos + consumed
    end
  end)

  -- Several options are defined as appearing at most once: a sender MUST
  -- NOT include a second. Region Code is not among them: several may
  -- legitimately be present.
  for num, count in pairs(seen) do
    if count > 1 and options.SINGLETON_OPTIONS[num] then
      flag_violation(opts_tree, buf(start_off, total_len), string.format(
        "%s option appears %d times; at most one is allowed",
        options.KNOWN_OPTION_NAMES[num] or ("Option " .. num), count))
    end
  end

  -- A frame carrying more than one Frame Signature is unsigned, and one
  -- with SECINFO signs through the SCF's D bit and ignores option 0.
  if #frame_sigs > 1 then
    for _, item in ipairs(frame_sigs) do
      item:append_text(string.format(" [ignored: the frame carries %d]", #frame_sigs))
    end
    frame_sig = nil
  end
  if #frame_sigs > 0 and SECINFO_TYPES[_ctx.pkt_type] then
    for _, item in ipairs(frame_sigs) do item:append_text(" [ignored: the frame has SECINFO]") end
    flag_violation(opts_tree, buf(start_off, total_len),
      "Frame Signature option on a packet type that carries SECINFO, which signs with the SCF's D bit")
    frame_sig = nil
  end

  return start_off + total_len, seen, frame_sig
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
  local _, frame_sig
  off, _, frame_sig = parse_options(buf, off, buf_len, tree, static_opts, pinfo)
  _ctx.signed = frame_sig ~= nil

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
local function dissect_uack(buf, pinfo, tree, off, fcf_byte, static_opts)
  local buf_len = buf:len()

  -- A MAC ack carries no destination hint: OPTIONS follow the header
  -- directly, then a fixed 8-byte trailer (ack_mic(4) || ack_tag(4)). No
  -- 0xFF terminator, since the trailer is at a fixed offset from the end.
  -- The static options enter the ack tag's AAD.
  off = parse_options(buf, off, buf_len - 8, tree, static_opts, pinfo)

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

  -- ACK correlation: look up the public ack_mic. This needs no keys—
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
    -- If a key recovered the request's V, verify the keyed tag. A public
    -- ack_mic match establishes only correlation; when a configured key proves
    -- the tag wrong the frame is NOT a valid acknowledgement, so we downgrade
    -- to a "correlates with" forensic link and suppress the ack/back-reference.
    local verified = nil
    if origin.ack_v and crypto then
      local tag_range = buf(off + 4, 4)
      local exp = crypto.ack_tag_mic(origin.ack_keys.k_mic, fcf_byte,
                                     static_opts, origin.ack_v)
      verified = exp == tag_bytes
      tree:add(f.ack_verified, tag_range, verified)
      if not verified then
        tree:add(f.ack_expected, tag_range, exp):set_text(
          "Expected ACK Tag: " .. bytes_to_hex(exp)):set_generated()
      end
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
      -- The same reversal for the filterable fields, so
      -- `umsh.src_addr == "GySV"` catches the acks GySV sent too. They
      -- are generated: the ack carries none of these bytes, and they
      -- hang off the ack_mic that names the packet they came from.
      local mic_range = buf(off, 4)
      if origin.dst_addr then
        tree:add(f.src_addr, mic_range, origin.dst_addr):set_generated():set_hidden()
      end
      if origin.src_addr then
        tree:add(f.dst_addr, mic_range, origin.src_addr):set_generated():set_hidden()
      end
      if origin.dst_name and origin.dst_name ~= "" then
        tree:add(f.src_name, mic_range, origin.dst_name):set_generated()
      end
      if origin.src_name and origin.src_name ~= "" then
        tree:add(f.dst_name, mic_range, origin.src_name):set_generated()
      end
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
  local src_name = add_src_addr(tree, buf, off, src_bytes, full_src)
  off = off + src_len

  -- SECINFO
  local new_off, scf, mic_len, secinfo_raw, is_enc, sig_len = parse_secinfo(buf, off, tree)
  if not new_off then return end
  off = new_off

  -- OPTIONS block (always present; 0xFF emitted iff payload follows). The
  -- trailer, SIG and MIC, is known before the options are walked.
  off = parse_options(buf, off, buf_len - mic_len - sig_len, tree, static_opts, pinfo)

  -- Body (payload or ciphertext), the signature included
  local body_start = off
  local body_len   = buf_len - off - mic_len
  if body_len < sig_len then tree:add_proto_expert_info(ef.truncated); return end
  local body_bytes = tvb_bytes(buf, off, body_len)
  add_body(tree, buf, off, body_len, sig_len, is_enc)
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
  -- V and the keys (filled in below when we can decrypt) are preserved.
  if ack_req and mic_len >= 4 and not pinfo.visited then
    local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
    local prior = _ack_by_mic[mic_hex]
    _ack_by_mic[mic_hex] = {
      frame       = pinfo.number,
      timestamp   = pinfo.abs_ts,
      src_label   = sl,
      dst_label   = dl,
      src_addr    = addr_short(src_bytes),
      dst_addr    = hint_short(dst_bytes),
      src_name    = src_name,
      dst_name    = dst_name,
      ack_v       = prior and prior.ack_v,
      ack_keys    = prior and prior.ack_keys,
    }
  end

  -- Crypto: try to decrypt / verify MIC
  if not crypto then return end
  local pkt_info = {
    fcf_byte     = fcf_byte,
    static_opts  = static_opts,
    dst_hint     = dst_bytes,
    src_bytes    = src_bytes,
    secinfo_raw  = secinfo_raw,
    body_bytes   = body_bytes,
    mic_bytes    = mic_bytes,
    is_encrypted = is_enc,
  }
  local privkeys = keystore.get_all_privkeys()
  local ok, plain, status, dec_keys, full_cmac =
    pcall(crypto.try_decrypt_unicast, pkt_info, privkeys, keystore.peer_keys)
  if ok and plain then
    tree:add_proto_expert_info(ef.mic_ok)
    local sig
    plain, sig = split_signature(plain, sig_len)
    if is_enc then
      tree:add(f.payload_dec, buf(body_start, #plain)):set_text(
        "Decrypted Payload (" .. #plain .. " B): " .. bytes_to_hex(plain))
      if sig then add_signature(tree, buf(body_start + #plain, sig_len), sig) end
    end
    _ctx.mic_verified = true
    if app then pcall(app.dissect, plain, tree, pinfo, keystore, crypto, _ctx) end

    -- ACK tracking: attach V and the keys to the (already recorded) ack_mic
    -- entry, so a matched ack can be cryptographically verified rather than
    -- merely correlated. Which tag construction to expect depends on the
    -- ack's own options, so the tag itself is computed when the ack arrives.
    if ack_req and dec_keys and full_cmac then
      if not pinfo.visited and mic_len >= 4 then
        local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
        local entry = _ack_by_mic[mic_hex] or {
          frame     = pinfo.number,
          timestamp = pinfo.abs_ts,
          src_label = sl,
          dst_label = dl,
          src_addr  = addr_short(src_bytes),
          dst_addr  = hint_short(dst_bytes),
          src_name  = src_name,
          dst_name  = dst_name,
        }
        entry.ack_v    = full_cmac
        entry.ack_keys = dec_keys
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
  else
    add_pairwise_failure(tree, ok and status)
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
  local new_off, scf, mic_len, secinfo_raw, is_enc, sig_len = parse_secinfo(buf, off, tree)
  if not new_off then return end
  off = new_off
  _ctx.is_enc = is_enc

  -- OPTIONS block (always present; 0xFF always present since body follows)
  off = parse_options(buf, off, buf_len - mic_len - sig_len, tree, static_opts, pinfo)

  -- For E=0: SRC is in cleartext before the body
  local src_bytes, src_name
  if not is_enc then
    local src_len = full_src and 32 or 3
    if off + src_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end
    src_bytes = tvb_bytes(buf, off, src_len)
    src_name  = add_src_addr(tree, buf, off, src_bytes, full_src)
    off = off + src_len
  end

  -- Body + MIC; the signature, if any, ends the body, and an encrypted SRC
  -- opens it
  local body_start = off
  local body_len   = buf_len - off - mic_len
  local enc_src    = is_enc and (full_src and 32 or 3) or 0
  if body_len < enc_src + sig_len then tree:add_proto_expert_info(ef.truncated); return end
  local body_bytes = tvb_bytes(buf, off, body_len)
  add_body(tree, buf, off, body_len, sig_len, is_enc)
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
    -- E=1: body = ENCRYPT(SRC || PAYLOAD || SIG); use try_decrypt_multicast
    local pkt_info = {
      fcf_byte         = fcf_byte,
      static_opts      = static_opts,
      channel_id       = chan_bytes,
      aad_fields       = {channel = chan_bytes},
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
      local sig
      payload, sig = split_signature(payload, sig_len)
      if #payload > 0 then
        tree:add(f.payload_dec, buf(body_start + src_len, #payload)):set_text(
          "Decrypted Payload (" .. #payload .. " B): " .. bytes_to_hex(payload))
      end
      if sig then
        add_signature(tree, buf(body_start + src_len + #payload, sig_len), sig)
      end
      if #payload > 0 and app then
        pcall(app.dissect, payload, tree, pinfo, keystore, crypto, _ctx)
      end
    elseif ok2 and status == "mic_mismatch" then
      tree:add_proto_expert_info(ef.mic_bad)
    else
      tree:add_proto_expert_info(ef.no_key)
    end

  else
    -- E=0: SRC in cleartext, but still the start of the protected region
    -- rather than part of the AAD, exactly as when it is encrypted.
    local pkt_info = {
      fcf_byte         = fcf_byte,
      static_opts      = static_opts,
      aad_fields       = {channel = chan_bytes},
      secinfo_raw      = secinfo_raw,
      body_bytes       = src_bytes .. body_bytes,
      mic_bytes        = mic_bytes,
      is_encrypted     = false,
    }
    local ok2, plain, status =
      pcall(crypto.verify_and_decrypt, ch_entry.derived_keys, pkt_info)
    if ok2 and plain then
      tree:add_proto_expert_info(ef.mic_ok)
      _ctx.mic_verified = true
      local payload = split_signature(plain:sub(#src_bytes + 1), sig_len)
      if app then pcall(app.dissect, payload, tree, pinfo, keystore, crypto, _ctx) end
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
  local new_off, scf, mic_len, secinfo_raw, is_enc, sig_len = parse_secinfo(buf, off, tree)
  if not new_off then return end
  off = new_off
  _ctx.is_enc = is_enc

  -- OPTIONS block (always present; 0xFF always present since body follows)
  off = parse_options(buf, off, buf_len - mic_len - sig_len, tree, static_opts, pinfo)

  -- Info column base
  local chan_hex = bytes_to_hex(chan_bytes)
  local ch_label = (ch_entry and ch_entry.name ~= "" and ch_entry.name) or chan_hex
  local type_label = ack_req and "UMSH BUAR" or "UMSH BUNI"
  pinfo.cols.info = type_label .. " [" .. ch_label .. "]"

  -- The channel rules run once, from the main dissector, so that a packet
  -- truncated part way through still gets them.
  _ctx.chan_tvbr = buf(chan_off, 2)

  if is_enc then
    -- E=1: ENC_DST_SRC (6 or 35 bytes) | ENC_PAYLOAD | MIC, where
    -- ENC_PAYLOAD covers the signature too
    local addr_len   = 3 + (full_src and 32 or 3)   -- DST_hint(3) + SRC(3/32)
    local addr_start = off
    if off + addr_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end
    local enc_addr_bytes = tvb_bytes(buf, off, addr_len)
    tree:add(f.enc_addr, buf(off, addr_len))
    off = off + addr_len

    local body_start = off
    local body_len   = buf_len - off - mic_len
    if body_len < sig_len then tree:add_proto_expert_info(ef.truncated); return end
    local body_bytes = tvb_bytes(buf, off, body_len)
    add_body(tree, buf, off, body_len, sig_len, true)
    off = off + body_len

    local mic_bytes = tvb_bytes(buf, off, mic_len)
    tree:add(f.mic, buf(off, mic_len))

    -- ACK correlation (keyless): record the public ack_mic even though the
    -- endpoints are concealed—the ack echoes this MIC prefix regardless.
    if ack_req and mic_len >= 4 and not pinfo.visited then
      local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
      local prior = _ack_by_mic[mic_hex]
      _ack_by_mic[mic_hex] = {
        frame       = pinfo.number,
        timestamp   = pinfo.abs_ts,
        src_label   = prior and prior.src_label or "?",
        dst_label   = prior and prior.dst_label or "?",
        src_addr    = prior and prior.src_addr,
        dst_addr    = prior and prior.dst_addr,
        src_name    = prior and prior.src_name,
        dst_name    = prior and prior.dst_name,
        ack_v       = prior and prior.ack_v,
        ack_keys    = prior and prior.ack_keys,
      }
    end

    -- Crypto (E=1)
    if not crypto then return end
    local pkt_info = {
      fcf_byte       = fcf_byte,
      static_opts    = static_opts,
      channel_id     = chan_bytes,
      enc_addr_bytes = enc_addr_bytes,
      secinfo_raw    = secinfo_raw,
      body_bytes     = body_bytes,
      mic_bytes      = mic_bytes,
      is_encrypted   = true,
    }
    local privkeys = keystore.get_all_privkeys()
    local ok2, payload, dst_hint, dec_src, status, dec_keys, full_cmac =
      pcall(crypto.try_decrypt_blind_unicast, pkt_info, privkeys,
            keystore.get_all_channels(), full_src, keystore.peer_keys)
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
      local sig
      payload, sig = split_signature(payload, sig_len)
      if #payload > 0 then
        tree:add(f.payload_dec, buf(body_start, #payload)):set_text(
          "Decrypted Payload (" .. #payload .. " B): " .. bytes_to_hex(payload))
      end
      if sig then add_signature(tree, buf(body_start + #payload, sig_len), sig) end
      if #payload > 0 and app then
        pcall(app.dissect, payload, tree, pinfo, keystore, crypto, _ctx)
      end
      -- ACK tracking for BUAR
      if ack_req and dec_keys and full_cmac then
        if not pinfo.visited and mic_len >= 4 then
          local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
          local entry = _ack_by_mic[mic_hex] or {
            frame     = pinfo.number,
            timestamp = pinfo.abs_ts,
          }
          entry.src_label = s_name or (dec_src and addr_short(dec_src)) or "?"
          entry.dst_label = d_name or (dst_hint and hint_short(dst_hint)) or "?"
          entry.src_addr  = dec_src and addr_short(dec_src)
          entry.dst_addr  = dst_hint and hint_short(dst_hint)
          entry.src_name  = s_name
          entry.dst_name  = d_name
          entry.ack_v     = full_cmac
          entry.ack_keys  = dec_keys
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
    else
      add_pairwise_failure(tree, ok2 and status)
    end

  else
    -- E=0: DST(3) | SRC(3/32) | PAYLOAD | SIG | MIC—all in cleartext
    if off + 3 > buf_len then tree:add_proto_expert_info(ef.truncated); return end
    local dst_bytes = tvb_bytes(buf, off, 3)
    local dst_name  = add_dst_hint(tree, buf, off, dst_bytes)
    off = off + 3

    local src_len = full_src and 32 or 3
    if off + src_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end
    local src_bytes = tvb_bytes(buf, off, src_len)
    local src_name = add_src_addr(tree, buf, off, src_bytes, full_src)
    off = off + src_len

    local body_len = buf_len - off - mic_len
    if body_len < sig_len then tree:add_proto_expert_info(ef.truncated); return end
    local body_bytes = tvb_bytes(buf, off, body_len)
    add_body(tree, buf, off, body_len, sig_len, false)
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
        src_addr    = addr_short(src_bytes),
        dst_addr    = hint_short(dst_bytes),
        src_name    = src_name,
        dst_name    = dst_name,
        ack_v       = prior and prior.ack_v,
        ack_keys    = prior and prior.ack_keys,
      }
    end

    -- Crypto (E=0): need channel key + privkey pair → derive blind keys
    if not crypto or not ch_entry or not ch_entry.derived_keys then
      if crypto then tree:add_proto_expert_info(ef.no_key) end
      return
    end

    local privkeys = keystore.get_all_privkeys()
    -- The address block follows the AAD's terminator, as it does when it
    -- is encrypted.
    local pkt_info = {
      fcf_byte         = fcf_byte,
      static_opts      = static_opts,
      aad_fields       = {channel = chan_bytes, dst = dst_bytes, src = src_bytes},
      secinfo_raw      = secinfo_raw,
      body_bytes       = body_bytes,
      mic_bytes        = mic_bytes,
      is_encrypted     = false,
    }
    local ok2, plain, status, blind_keys, full_cmac =
      pcall(crypto.try_pairwise, privkeys, dst_bytes, keystore.peer_keys(src_bytes),
            crypto.blind_attempt(ch_entry.derived_keys, pkt_info))
    if ok2 and plain then
      tree:add_proto_expert_info(ef.mic_ok)
      _ctx.mic_verified = true
      local payload = split_signature(plain, sig_len)
      if app then pcall(app.dissect, payload, tree, pinfo, keystore, crypto, _ctx) end
      -- ACK tracking for E=0 BUAR
      if ack_req and blind_keys and full_cmac then
        if not pinfo.visited and mic_len >= 4 then
          local mic_hex = bytes_to_hex(mic_bytes:sub(1, 4))
          local entry = _ack_by_mic[mic_hex] or {
            frame     = pinfo.number,
            timestamp = pinfo.abs_ts,
            src_label = sl,
            dst_label = dl,
            src_addr  = addr_short(src_bytes),
            dst_addr  = hint_short(dst_bytes),
            src_name  = src_name,
            dst_name  = dst_name,
          }
          entry.ack_v    = full_cmac
          entry.ack_keys = blind_keys
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
    else
      add_pairwise_failure(tree, ok2 and status)
    end
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
    signed       = false,
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
    dissect_uack(buf, pinfo, root, off, fcf_byte, static_opts)
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
  if _ctx.signed then table.insert(_info_notes, 1, "signed") end
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
  keystore.rebuild(umsh.prefs.node_names, umsh.prefs.privkeys, umsh.prefs.channel_keys)

  -- Merge optional key file (silently ignored if path is empty or file missing)
  keystore.load_keyfile(umsh.prefs.keyfile)

  -- The two well-known channels derive from names the spec fixes, so their
  -- keys are public knowledge and cost nothing to carry: emergency traffic
  -- verifies and public traffic decrypts with no configuration at all.
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
