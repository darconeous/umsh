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
  [0] = "BCST (Broadcast)",        [1] = "MACK (MAC Ack)",
  [2] = "UNIC (Unicast)",          [3] = "UACK (Unicast Ack-Req)",
  [4] = "MCST (Multicast)",        [5] = "RSVD (Reserved)",
  [6] = "BUNI (Blind Unicast)",    [7] = "BUAK (Blind Unicast Ack-Req)",
}
local TYPE_SHORT = {"BCST","MACK","UNIC","UACK","MCST","RSVD","BUNI","BUAK"}
local VS_MIC = {[0]="4 bytes",[1]="8 bytes",[2]="12 bytes",[3]="16 bytes"}
local VS_VER = {[3]="UMSH v3"}

-- ──────────────────────────────────────────────────────────────────────────
-- ProtoField declarations
-- ──────────────────────────────────────────────────────────────────────────
local f = {}

-- FCF (1 byte)
f.fcf          = ProtoField.uint8 ("umsh.fcf",         "Frame Control Field", base.HEX)
f.fcf_version  = ProtoField.uint8 ("umsh.fcf.version", "Version",             base.DEC, VS_VER,  0xC0)
f.fcf_type     = ProtoField.uint8 ("umsh.fcf.type",    "Packet Type",         base.DEC, VS_TYPE, 0x38)
f.fcf_full_src = ProtoField.bool  ("umsh.fcf.s",       "Full Source Key (S)", 8, nil, 0x04)
f.fcf_opts     = ProtoField.bool  ("umsh.fcf.o",       "Options Present (O)", 8, nil, 0x02)
f.fcf_fhops    = ProtoField.bool  ("umsh.fcf.h",       "Flood Hops (H)",      8, nil, 0x01)

-- FHOPS (1 byte, optional)
f.fhops        = ProtoField.uint8 ("umsh.fhops",       "Flood Hop Count",     base.HEX)
f.fhops_rem    = ProtoField.uint8 ("umsh.fhops.rem",   "Remaining",           base.DEC, nil, 0xF0)
f.fhops_acc    = ProtoField.uint8 ("umsh.fhops.acc",   "Accumulated",         base.DEC, nil, 0x0F)

-- Options (variable)
f.options          = ProtoField.bytes  ("umsh.options",           "Options")
f.opt_region_code  = ProtoField.bytes  ("umsh.opt.region_code",   "Region Code")
f.opt_traceroute   = ProtoField.bytes  ("umsh.opt.trace_route",   "Trace Route")
f.opt_srcroute     = ProtoField.bytes  ("umsh.opt.source_route",  "Source Route")
f.opt_op_callsign  = ProtoField.string ("umsh.opt.op_callsign",   "Operator Callsign")
f.opt_sta_callsign = ProtoField.string ("umsh.opt.sta_callsign",  "Station Callsign")
f.opt_min_rssi     = ProtoField.int8   ("umsh.opt.min_rssi",      "Min RSSI",         base.DEC)
f.opt_min_snr      = ProtoField.int8   ("umsh.opt.min_snr",       "Min SNR",          base.DEC)
f.opt_unknown      = ProtoField.bytes  ("umsh.opt.unknown",       "Unknown Option")

-- Addresses
f.dst_hint     = ProtoField.bytes  ("umsh.dst",          "Destination Hint")
f.ack_dst      = ProtoField.bytes  ("umsh.mack.dst",     "ACK Destination")
f.src_hint     = ProtoField.bytes  ("umsh.src_hint",     "Source Hint")
f.src_key      = ProtoField.bytes  ("umsh.src_key",      "Source Public Key")
f.channel_id   = ProtoField.bytes  ("umsh.channel_id",   "Channel ID")
f.ack_tag      = ProtoField.bytes  ("umsh.ack_tag",      "ACK Tag")

-- Keystore annotations (virtual string fields)
f.src_name     = ProtoField.string ("umsh.src_name",     "Source Name")
f.dst_name     = ProtoField.string ("umsh.dst_name",     "Destination Name")
f.channel_name = ProtoField.string ("umsh.channel_name", "Channel Name")

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

umsh.fields = {
  f.fcf, f.fcf_version, f.fcf_type, f.fcf_full_src, f.fcf_opts, f.fcf_fhops,
  f.fhops, f.fhops_rem, f.fhops_acc,
  f.options, f.opt_region_code, f.opt_traceroute, f.opt_srcroute,
  f.opt_op_callsign, f.opt_sta_callsign, f.opt_min_rssi, f.opt_min_snr, f.opt_unknown,
  f.dst_hint, f.ack_dst, f.src_hint, f.src_key, f.channel_id, f.ack_tag,
  f.src_name, f.dst_name, f.channel_name,
  f.secinfo, f.scf, f.scf_enc, f.scf_mic_size, f.scf_salt_bit,
  f.frame_ctr, f.salt, f.mic,
  f.payload_raw, f.payload_dec, f.enc_body, f.enc_addr, f.dec_dst, f.dec_src,
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

umsh.experts = {
  ef.bad_version, ef.truncated, ef.mic_bad, ef.mic_ok,
  ef.no_key, ef.unk_crit_opt, ef.rsvd_type,
}

-- ──────────────────────────────────────────────────────────────────────────
-- Preferences
-- ──────────────────────────────────────────────────────────────────────────

-- Key table via Pref.uat (Wireshark 4.6+), with string-pref fallback.
local _has_uat = pcall(function()
  umsh.prefs.keys = Pref.uat("Decryption Keys", {
    {"type",  "pubkey = name only (no decrypt), privkey = decrypt unicast, channel = decrypt multicast"},
    {"key",   "Hex key (64 hex chars), or umsh:cs:<name> for named channels"},
    {"label", "Human-readable display name"},
  }, "Type: pubkey (Ed25519 public key, display name only), "
  .. "privkey (Ed25519 seed, enables unicast decryption), "
  .. "channel (symmetric key or umsh:cs:<name>, enables multicast decryption)",
  "umsh_keys")
end)

if not _has_uat then
  -- Fallback for Wireshark < 4.6: three separate string preferences
  umsh.prefs.node_names   = Pref.string("Node names",   "",
    "One per line: <64-hex-pubkey>:<display-name>")
  umsh.prefs.privkeys     = Pref.string("Private keys", "",
    "One per line: <64-hex-ed25519-seed>:<display-name>")
  umsh.prefs.channel_keys = Pref.string("Channel keys", "",
    "One per line:\n  <64-hex-key>:<display-name>\n  umsh:cs:<name>:<display-name>")
end

umsh.prefs.udp_port     = Pref.uint  ("UDP Port", 0, "UDP port to dissect as UMSH (0 = disabled)")
umsh.prefs.keyfile      = Pref.string("Key File",  "",
  "Optional key file path (INI format with [nodes]/[privkeys]/[channels] sections)")

-- ──────────────────────────────────────────────────────────────────────────
-- Internal state
-- ──────────────────────────────────────────────────────────────────────────
local _udp_table       = DissectorTable.get("udp.port")
local _registered_port = 0

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

-- Format 3-byte hint as "XX:XX:XX"
local function hint_hex(s)
  return string.format("%02X:%02X:%02X", s:byte(1), s:byte(2), s:byte(3))
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
-- Decodes the CoAP-style options block starting at `start_off`.
-- Populates `static_opts_out` with {number, value} pairs for AAD construction.
-- Returns the new offset (after the 0xFF terminator).
-- ──────────────────────────────────────────────────────────────────────────
local function parse_options(buf, start_off, tree, static_opts_out)
  local buf_len = buf:len()
  if start_off >= buf_len then return start_off end

  local avail = buf_len - start_off
  local raw   = tvb_bytes(buf, start_off, avail)

  local total_len
  if not pcall(function() total_len = options.scan_length(raw, 1) end)
     or not total_len then
    tree:add_proto_expert_info(ef.truncated)
    return start_off
  end

  local opts_tree = tree:add(f.options, buf(start_off, total_len))

  local raw_pos = 1  -- 1-indexed position in raw string
  pcall(function()
    for num, val, consumed in options.decode(raw, 1) do
      local opt_off = start_off + raw_pos - 1   -- absolute offset in buf
      local val_len = #val
      local val_off = opt_off + consumed - val_len  -- offset of value bytes

      if num == options.OPT_REGION_CODE then
        local cs   = options.decode_arnce(val)
        local tvbr = (val_len > 0) and buf(val_off, val_len) or buf(opt_off, consumed)
        opts_tree:add(f.opt_region_code, tvbr):set_text("Region Code: " .. cs)

      elseif num == options.OPT_TRACE_ROUTE then
        local item = opts_tree:add(f.opt_traceroute, buf(opt_off, consumed))
        if val_len == 0 then item:set_text("Trace Route: (empty)") end

      elseif num == options.OPT_SOURCE_ROUTE then
        local item = opts_tree:add(f.opt_srcroute, buf(opt_off, consumed))
        if val_len == 0 then item:set_text("Source Route: (empty)") end

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
  local src_name
  if full_src then
    tree:add(f.src_key, buf(off, 32))
    src_name = keystore.lookup_node_by_key(src_bytes)
  else
    tree:add(f.src_hint, buf(off, 3))
    src_name = keystore.lookup_node(src_bytes)
  end
  if src_name and src_name ~= "" then
    tree:add(f.src_name, buf(off, src_len), src_name)
  end
  off = off + src_len

  local payload_len = buf_len - off
  local suffix = src_name and (" from " .. src_name)
              or (" from " .. hint_hex(src_bytes:sub(1, 3)))
  if payload_len > 0 then
    local payload_bytes = tvb_bytes(buf, off, payload_len)
    tree:add(f.payload_raw, buf(off, payload_len))
    pinfo.cols.info = "UMSH BCST" .. suffix
    if app then
      pcall(app.dissect, payload_bytes, tree, pinfo, keystore, crypto)
    end
  else
    pinfo.cols.info = "UMSH BCST [Beacon]" .. suffix
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- MAC Ack
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_mack(buf, pinfo, tree, off)
  local buf_len = buf:len()

  if off + 3 > buf_len then tree:add_proto_expert_info(ef.truncated); return end
  local dst_bytes = tvb_bytes(buf, off, 3)
  tree:add(f.ack_dst, buf(off, 3))
  local dst_name = keystore.lookup_node(dst_bytes)
  if dst_name and dst_name ~= "" then tree:add(f.dst_name, buf(off, 3), dst_name) end
  off = off + 3

  if off + 8 > buf_len then tree:add_proto_expert_info(ef.truncated); return end
  tree:add(f.ack_tag, buf(off, 8))

  local to_label = dst_name or hint_hex(dst_bytes)
  pinfo.cols.info = "UMSH MACK to " .. to_label
end

-- ──────────────────────────────────────────────────────────────────────────
-- Unicast (UNIC and UACK)
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_unicast(buf, pinfo, tree, off, full_src, fcf_byte, static_opts, ack_req)
  local buf_len = buf:len()

  -- DST hint (3 bytes)
  if off + 3 > buf_len then tree:add_proto_expert_info(ef.truncated); return end
  local dst_bytes = tvb_bytes(buf, off, 3)
  tree:add(f.dst_hint, buf(off, 3))
  local dst_name = keystore.lookup_node(dst_bytes)
  if dst_name and dst_name ~= "" then tree:add(f.dst_name, buf(off, 3), dst_name) end
  off = off + 3

  -- SRC (3 or 32 bytes)
  local src_len = full_src and 32 or 3
  if off + src_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end
  local src_bytes = tvb_bytes(buf, off, src_len)
  local src_name, src_pubkey
  if full_src then
    tree:add(f.src_key, buf(off, 32))
    src_name   = keystore.lookup_node_by_key(src_bytes)
    src_pubkey = src_bytes
  else
    tree:add(f.src_hint, buf(off, 3))
    src_name, src_pubkey = keystore.lookup_node(src_bytes)
  end
  if src_name and src_name ~= "" then
    tree:add(f.src_name, buf(off, src_len), src_name)
  end
  off = off + src_len

  -- SECINFO
  local new_off, scf, mic_len, secinfo_raw, is_enc = parse_secinfo(buf, off, tree)
  if not new_off then return end
  off = new_off

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
  local sl = src_name or hint_hex(src_bytes:sub(1, 3))
  local dl = dst_name or hint_hex(dst_bytes)
  pinfo.cols.info = (ack_req and "UMSH UACK" or "UMSH UNIC") .. " " .. sl .. " -> " .. dl

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
  local ok, plain, status = pcall(crypto.try_decrypt_unicast, pkt_info, privkeys, full_src)
  if ok and plain then
    tree:add_proto_expert_info(ef.mic_ok)
    if is_enc then
      tree:add(f.payload_dec, buf(body_start, body_len)):set_text(
        "Decrypted Payload (" .. #plain .. " B): " .. bytes_to_hex(plain))
    end
    if app then pcall(app.dissect, plain, tree, pinfo, keystore, crypto) end
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
  local chan_bytes = tvb_bytes(buf, off, 2)
  tree:add(f.channel_id, buf(off, 2))
  local ch_entry = keystore.get_channel_by_id(chan_bytes)
  if ch_entry and ch_entry.name ~= "" then
    tree:add(f.channel_name, buf(off, 2), ch_entry.name)
  end
  off = off + 2

  -- SECINFO
  local new_off, scf, mic_len, secinfo_raw, is_enc = parse_secinfo(buf, off, tree)
  if not new_off then return end
  off = new_off

  -- For E=0: SRC is in cleartext before the body
  local src_bytes, src_name
  if not is_enc then
    local src_len = full_src and 32 or 3
    if off + src_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end
    src_bytes = tvb_bytes(buf, off, src_len)
    if full_src then
      tree:add(f.src_key, buf(off, 32))
      src_name = keystore.lookup_node_by_key(src_bytes)
    else
      tree:add(f.src_hint, buf(off, 3))
      src_name = keystore.lookup_node(src_bytes)
    end
    if src_name and src_name ~= "" then
      tree:add(f.src_name, buf(off, src_len), src_name)
    end
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
  if src_name then
    pinfo.cols.info = "UMSH MCST [" .. ch_label .. "] from " .. src_name
  else
    pinfo.cols.info = "UMSH MCST [" .. ch_label .. "]"
  end

  -- Crypto
  if not crypto then return end

  if not ch_entry or not ch_entry.derived_keys then
    tree:add_proto_expert_info(ef.no_key)
    return
  end
  local dk = ch_entry.derived_keys

  if is_enc then
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
      local src_len = full_src and 32 or 3
      if dec_src then
        local dec_name = full_src and keystore.lookup_node_by_key(dec_src)
                                   or keystore.lookup_node(dec_src)
        local dec_label = dec_name or bytes_to_hex(dec_src)
        tree:add(f.dec_src, buf(body_start, src_len)):set_text(
          "Decrypted SRC: " .. dec_label)
        pinfo.cols.info = "UMSH MCST [" .. ch_label .. "] from " .. dec_label
      end
      if #payload > 0 then
        tree:add(f.payload_dec, buf(body_start + src_len, body_len - src_len)):set_text(
          "Decrypted Payload (" .. #payload .. " B): " .. bytes_to_hex(payload))
        if app then pcall(app.dissect, payload, tree, pinfo, keystore, crypto) end
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
    local ok2, plain, status = pcall(crypto.verify_and_decrypt, dk, pkt_info)
    if ok2 and plain then
      tree:add_proto_expert_info(ef.mic_ok)
      if app then pcall(app.dissect, plain, tree, pinfo, keystore, crypto) end
    elseif ok2 and status == "mic_mismatch" then
      tree:add_proto_expert_info(ef.mic_bad)
    else
      tree:add_proto_expert_info(ef.no_key)
    end
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- Blind Unicast (BUNI and BUAK)
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_blind_unicast(buf, pinfo, tree, off, full_src, fcf_byte, static_opts, ack_req)
  local buf_len = buf:len()

  -- CHANNEL (2 bytes)
  if off + 2 > buf_len then tree:add_proto_expert_info(ef.truncated); return end
  local chan_bytes = tvb_bytes(buf, off, 2)
  tree:add(f.channel_id, buf(off, 2))
  local ch_entry = keystore.get_channel_by_id(chan_bytes)
  if ch_entry and ch_entry.name ~= "" then
    tree:add(f.channel_name, buf(off, 2), ch_entry.name)
  end
  off = off + 2

  -- SECINFO
  local new_off, scf, mic_len, secinfo_raw, is_enc = parse_secinfo(buf, off, tree)
  if not new_off then return end
  off = new_off

  -- Info column base
  local chan_hex = bytes_to_hex(chan_bytes)
  local ch_label = (ch_entry and ch_entry.name ~= "" and ch_entry.name) or chan_hex
  local type_label = ack_req and "UMSH BUAK" or "UMSH BUNI"
  pinfo.cols.info = type_label .. " [" .. ch_label .. "]"

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
    local ok2, payload, dst_hint, dec_src, status =
      pcall(crypto.try_decrypt_blind_unicast, pkt_info, privkeys,
            keystore.get_all_channels(), full_src)
    if ok2 and payload then
      tree:add_proto_expert_info(ef.mic_ok)
      if dst_hint then
        local d_name = keystore.lookup_node(dst_hint)
        tree:add(f.dec_dst, buf(addr_start, 3)):set_text(
          "Decrypted DST: " .. (d_name or hint_hex(dst_hint)))
      end
      if dec_src then
        local src_disp_len = full_src and 32 or 3
        local s_name = full_src and keystore.lookup_node_by_key(dec_src)
                                 or keystore.lookup_node(dec_src)
        tree:add(f.dec_src, buf(addr_start + 3, src_disp_len)):set_text(
          "Decrypted SRC: " .. (s_name or bytes_to_hex(dec_src)))
        if s_name then pinfo.cols.info = type_label .. " [" .. ch_label .. "] from " .. s_name end
      end
      if #payload > 0 then
        tree:add(f.payload_dec, buf(body_start, body_len)):set_text(
          "Decrypted Payload (" .. #payload .. " B): " .. bytes_to_hex(payload))
        if app then pcall(app.dissect, payload, tree, pinfo, keystore, crypto) end
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
    tree:add(f.dst_hint, buf(off, 3))
    local dst_name = keystore.lookup_node(dst_bytes)
    if dst_name and dst_name ~= "" then tree:add(f.dst_name, buf(off, 3), dst_name) end
    off = off + 3

    local src_len = full_src and 32 or 3
    if off + src_len > buf_len then tree:add_proto_expert_info(ef.truncated); return end
    local src_bytes = tvb_bytes(buf, off, src_len)
    local src_name, src_pubkey
    if full_src then
      tree:add(f.src_key, buf(off, 32))
      src_name   = keystore.lookup_node_by_key(src_bytes)
      src_pubkey = src_bytes
    else
      tree:add(f.src_hint, buf(off, 3))
      src_name, src_pubkey = keystore.lookup_node(src_bytes)
    end
    if src_name and src_name ~= "" then
      tree:add(f.src_name, buf(off, src_len), src_name)
    end
    off = off + src_len

    local body_len = buf_len - off - mic_len
    if body_len < 0 then tree:add_proto_expert_info(ef.truncated); return end
    local body_bytes = tvb_bytes(buf, off, body_len)
    tree:add(f.payload_raw, buf(off, body_len))
    local body_start = off
    off = off + body_len

    local mic_bytes = tvb_bytes(buf, off, mic_len)
    tree:add(f.mic, buf(off, mic_len))

    local sl = src_name or hint_hex(src_bytes:sub(1, 3))
    local dl = dst_name or hint_hex(dst_bytes)
    pinfo.cols.info = type_label .. " [" .. ch_label .. "] " .. sl .. " -> " .. dl

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
        local ok2, plain, status = pcall(function()
          local ss    = crypto.x25519(x25519_priv, x25519_peer)
          local pw    = crypto.derive_pairwise_keys(ss)
          if not pw then return nil, "no_pw" end
          local blind = crypto.derive_blind_keys(pw, ch_entry.derived_keys)
          return crypto.verify_and_decrypt(blind, pkt_info)
        end)
        if ok2 and plain then
          tree:add_proto_expert_info(ef.mic_ok)
          if app then pcall(app.dissect, plain, tree, pinfo, keystore, crypto) end
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
function umsh.dissector(buf, pinfo, tree)
  local buf_len = buf:len()
  if buf_len < 1 then return 0 end

  local fcf_val   = buf(0, 1):uint()
  local ver       = (fcf_val >> 6) & 0x03
  local pkt_type  = (fcf_val >> 3) & 0x07
  local full_src  = (fcf_val & 0x04) ~= 0
  local has_opts  = (fcf_val & 0x02) ~= 0
  local has_fhops = (fcf_val & 0x01) ~= 0
  local fcf_byte  = tvb_bytes(buf, 0, 1)

  pinfo.cols.protocol = "UMSH"

  local root = tree:add(umsh, buf())

  -- FCF subtree
  local fcf_tree = root:add(f.fcf, buf(0, 1))
  fcf_tree:add(f.fcf_version,  buf(0, 1))
  fcf_tree:add(f.fcf_type,     buf(0, 1))
  fcf_tree:add(f.fcf_full_src, buf(0, 1))
  fcf_tree:add(f.fcf_opts,     buf(0, 1))
  fcf_tree:add(f.fcf_fhops,    buf(0, 1))

  -- Version check
  if ver ~= 3 then
    root:add_proto_expert_info(ef.bad_version)
    return 1
  end

  local off = 1
  local static_opts = {}

  -- OPTIONS block
  if has_opts then
    off = parse_options(buf, off, root, static_opts)
  end

  -- FHOPS byte
  if has_fhops then
    if off >= buf_len then root:add_proto_expert_info(ef.truncated); return off end
    local fh_tree = root:add(f.fhops, buf(off, 1))
    fh_tree:add(f.fhops_rem, buf(off, 1))
    fh_tree:add(f.fhops_acc, buf(off, 1))
    off = off + 1
  end

  -- Packet type name for info column default
  local type_name = TYPE_SHORT[pkt_type + 1] or ("TYPE" .. pkt_type)
  pinfo.cols.info = "UMSH " .. type_name

  -- Per-type dispatch
  if pkt_type == 0 then
    dissect_broadcast(buf, pinfo, root, off, full_src, fcf_byte, static_opts)
  elseif pkt_type == 1 then
    dissect_mack(buf, pinfo, root, off)
  elseif pkt_type == 2 or pkt_type == 3 then
    dissect_unicast(buf, pinfo, root, off, full_src, fcf_byte, static_opts, pkt_type == 3)
  elseif pkt_type == 4 then
    dissect_multicast(buf, pinfo, root, off, full_src, fcf_byte, static_opts)
  elseif pkt_type == 5 then
    root:add_proto_expert_info(ef.rsvd_type)
  elseif pkt_type == 6 or pkt_type == 7 then
    dissect_blind_unicast(buf, pinfo, root, off, full_src, fcf_byte, static_opts, pkt_type == 7)
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
  [1] = 1 + 3 + 8,-- MACK:  FCF + DST_hint + ACK_TAG
  [2] = 1 + 3 + 3 + 5 + 4,  -- UNIC:  FCF+DST+SRC_hint+SECINFO+MIC4
  [3] = 1 + 3 + 3 + 5 + 4,  -- UACK:  same
  [4] = 1 + 2 + 5 + 4,       -- MCST:  FCF+CHANNEL+SECINFO+MIC4
  [5] = 1,                    -- RSVD (will be rejected)
  [6] = 1 + 2 + 5 + 4,       -- BUNI:  FCF+CHANNEL+SECINFO+MIC4
  [7] = 1 + 2 + 5 + 4,       -- BUAK:  same
}

local function validate_min_length(fcf, buf_len)
  local pkt_type = (fcf >> 3) & 0x07
  local min = MIN_LEN[pkt_type] or 1
  -- If OPTIONS present, add at least 1 byte (the 0xFF end marker)
  if (fcf & 0x02) ~= 0 then min = min + 1 end
  -- If FHOPS present, add 1 byte
  if (fcf & 0x01) ~= 0 then min = min + 1 end
  return buf_len >= min
end

local function heuristic(buf, pinfo, tree)
  if buf:len() < 4 then return false end
  local fcf = buf(0, 1):uint()
  if not is_umsh_fcf(fcf) then return false end
  if not validate_min_length(fcf, buf:len()) then return false end
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

-- Heuristic over LoRaTAP (DLT 270 — standard LoRa capture encapsulation)
-- Use heuristic so non-UMSH LoRa frames fall through to other dissectors.
pcall(function()
  umsh:register_heuristic("loratap", heuristic)
end)
