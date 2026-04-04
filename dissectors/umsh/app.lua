-- UMSH application-layer sub-dissectors
-- Dispatches on the first byte of the (decrypted) payload.
-- Called from umsh.lua after MIC verification / decryption.

local M = {}

-- ──────────────────────────────────────────────────────────────────────────
-- Payload type registry
-- ──────────────────────────────────────────────────────────────────────────
local PAYLOAD_TYPES = {
  [0x01] = "Node Identity",
  [0x02] = "MAC Command",
  [0x03] = "Text Message",
  [0x07] = "CoAP",
  [0x08] = "Node Management",
}

-- ──────────────────────────────────────────────────────────────────────────
-- Protocol and fields — registered at load time (Wireshark requires all
-- Protos and their fields to be set up before any dissection begins).
-- ──────────────────────────────────────────────────────────────────────────
local proto = Proto("umsh.app", "UMSH Application Layer")
local f = {}

-- Common
f.type_byte    = ProtoField.uint8  ("umsh.app.type",        "Payload Type",   base.HEX, PAYLOAD_TYPES)

-- Node Identity
f.ni_timestamp = ProtoField.uint32 ("umsh.app.ni.timestamp","Timestamp",      base.DEC)
f.ni_role      = ProtoField.uint8  ("umsh.app.ni.role",     "Role",           base.DEC, {
  [0]="Unspecified", [1]="Repeater", [2]="Chat", [3]="Tracker",
  [4]="Sensor",      [5]="Bridge",  [6]="Chat Room", [7]="Temporary Session",
})
f.ni_caps      = ProtoField.uint8  ("umsh.app.ni.caps",     "Capabilities",   base.HEX)
f.ni_caps_rep  = ProtoField.bool   ("umsh.app.ni.caps.rep", "Repeater",       8, nil, 0x01)
f.ni_caps_mob  = ProtoField.bool   ("umsh.app.ni.caps.mob", "Mobile",         8, nil, 0x02)
f.ni_caps_txt  = ProtoField.bool   ("umsh.app.ni.caps.txt", "Text Messages",  8, nil, 0x04)
f.ni_caps_tel  = ProtoField.bool   ("umsh.app.ni.caps.tel", "Telemetry",      8, nil, 0x08)
f.ni_caps_room = ProtoField.bool   ("umsh.app.ni.caps.rm",  "Chat Room",      8, nil, 0x10)
f.ni_caps_coap = ProtoField.bool   ("umsh.app.ni.caps.coap","CoAP",           8, nil, 0x20)
f.ni_caps_name = ProtoField.bool   ("umsh.app.ni.caps.name","Name Included",  8, nil, 0x40)
f.ni_caps_opts = ProtoField.bool   ("umsh.app.ni.caps.opts","Options Included",8, nil, 0x80)
f.ni_name      = ProtoField.string ("umsh.app.ni.name",     "Node Name")
f.ni_sig       = ProtoField.bytes  ("umsh.app.ni.sig",      "EdDSA Signature")
f.ni_options   = ProtoField.bytes  ("umsh.app.ni.options",  "Identity Options")

-- MAC Command
f.mac_cmd_id   = ProtoField.uint8  ("umsh.app.mac.cmd",     "Command",        base.HEX, {
  [0]="Beacon Request",     [1]="Identity Request",
  [2]="Signal Report Req",  [3]="Signal Report Resp",
  [4]="Echo Request",       [5]="Echo Response",
  [6]="PFS Session Request",[7]="PFS Session Response",
  [8]="End PFS Session",
})
f.mac_nonce    = ProtoField.bytes  ("umsh.app.mac.nonce",   "Nonce")
f.mac_rssi     = ProtoField.int8   ("umsh.app.mac.rssi",    "RSSI",           base.DEC)
f.mac_snr      = ProtoField.int8   ("umsh.app.mac.snr",     "SNR",            base.DEC)
f.mac_echo     = ProtoField.bytes  ("umsh.app.mac.echo",    "Echo Data")
f.mac_pfs_key  = ProtoField.bytes  ("umsh.app.mac.pfs_key", "Ephemeral Address")
f.mac_duration = ProtoField.uint16 ("umsh.app.mac.dur",     "Session Duration (min)", base.DEC)

-- Text Message
f.txt_opts     = ProtoField.bytes  ("umsh.app.txt.opts",    "Message Options")
f.txt_opt_type = ProtoField.uint8  ("umsh.app.txt.type",    "Message Type",   base.DEC, {
  [0]="Basic text", [1]="Status text", [2]="Resend Request",
})
f.txt_handle   = ProtoField.string ("umsh.app.txt.handle",  "Sender Handle")
f.txt_seq      = ProtoField.bytes  ("umsh.app.txt.seq",     "Message Sequence")
f.txt_regarding= ProtoField.bytes  ("umsh.app.txt.re",      "Regarding")
f.txt_edit     = ProtoField.uint8  ("umsh.app.txt.edit",    "Editing Msg ID", base.DEC)
f.txt_bg_color = ProtoField.bytes  ("umsh.app.txt.bg",      "Background Color")
f.txt_fg_color = ProtoField.bytes  ("umsh.app.txt.fg",      "Text Color")
f.txt_unknown  = ProtoField.bytes  ("umsh.app.txt.unk",     "Unknown Option")
f.txt_body     = ProtoField.string ("umsh.app.txt.body",    "Message Body")

proto.fields = {
  f.type_byte,
  f.ni_timestamp, f.ni_role, f.ni_caps,
  f.ni_caps_rep, f.ni_caps_mob, f.ni_caps_txt, f.ni_caps_tel,
  f.ni_caps_room, f.ni_caps_coap, f.ni_caps_name, f.ni_caps_opts,
  f.ni_name, f.ni_sig, f.ni_options,
  f.mac_cmd_id, f.mac_nonce, f.mac_rssi, f.mac_snr,
  f.mac_echo, f.mac_pfs_key, f.mac_duration,
  f.txt_opts, f.txt_opt_type, f.txt_handle, f.txt_seq,
  f.txt_regarding, f.txt_edit, f.txt_bg_color, f.txt_fg_color,
  f.txt_unknown, f.txt_body,
}

-- ──────────────────────────────────────────────────────────────────────────
-- Helpers: work on raw Lua strings (not Tvb) since this module receives
-- the payload as a Lua string from the decryption path.
-- ──────────────────────────────────────────────────────────────────────────
local function byte_at(s, i)   return s:byte(i) end
local function sub(s, i, j)    return s:sub(i, j) end
local function uint16_be(s, i) return s:byte(i) * 256 + s:byte(i+1) end
local function uint32_be(s, i)
  return ((s:byte(i) * 0x1000000) + (s:byte(i+1) * 0x10000)
        + (s:byte(i+2) * 0x100)   +  s:byte(i+3))
end

-- ──────────────────────────────────────────────────────────────────────────
-- ByteArray builder: assembles a fake Tvb from raw bytes so we can pass
-- TvbRanges to tree:add().  Falls back to adding strings when not in
-- a real Wireshark dissect context.
-- ──────────────────────────────────────────────────────────────────────────
local function make_tvb(raw_str, name)
  -- ByteArray.new(hex_string) — available in all Wireshark Lua versions
  local ba = ByteArray.new(raw_str:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
  return ba:tvb(name or "UMSH App Payload")
end

-- ──────────────────────────────────────────────────────────────────────────
-- Node Identity dissector (called with raw payload starting after type byte)
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_node_identity(payload, subtree, tvb)
  local len = #payload
  local off = 1  -- 1-indexed in Lua string

  -- Timestamp (4 bytes)
  if off + 3 > len then return end
  subtree:add(f.ni_timestamp, tvb(off - 1, 4), uint32_be(payload, off))
  off = off + 4

  -- Role (1 byte)
  if off > len then return end
  subtree:add(f.ni_role, tvb(off - 1, 1), byte_at(payload, off))
  off = off + 1

  -- Capabilities (1 byte)
  if off > len then return end
  local caps = byte_at(payload, off)
  local caps_tree = subtree:add(f.ni_caps, tvb(off - 1, 1), caps)
  caps_tree:add(f.ni_caps_opts, tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_name, tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_coap, tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_room, tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_tel,  tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_txt,  tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_mob,  tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_rep,  tvb(off - 1, 1))
  off = off + 1

  -- Optional NUL-terminated name (bit 6 of caps)
  if (caps & 0x40) ~= 0 then
    local name_start = off
    while off <= len and byte_at(payload, off) ~= 0 do off = off + 1 end
    local name_len = off - name_start
    if name_len > 0 then
      subtree:add(f.ni_name, tvb(name_start - 1, name_len),
                  sub(payload, name_start, name_start + name_len - 1))
    end
    if off <= len then off = off + 1 end  -- skip NUL
  end

  -- Optional CoAP options block (bit 7 of caps)
  if (caps & 0x80) ~= 0 and off <= len then
    -- Find the 0xFF terminator
    local opts_start = off
    while off <= len and byte_at(payload, off) ~= 0xFF do
      off = off + 1
    end
    if off <= len and byte_at(payload, off) == 0xFF then
      off = off + 1  -- consume 0xFF
    end
    local opts_len = off - opts_start
    if opts_len > 0 then
      subtree:add(f.ni_options, tvb(opts_start - 1, opts_len))
        :set_text("Identity Options (" .. opts_len .. " bytes)")
    end
  end

  -- Optional EdDSA signature (64 bytes, only if enough bytes remain)
  if len - off + 1 == 64 then
    subtree:add(f.ni_sig, tvb(off - 1, 64))
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- MAC Command dissector
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_mac_command(payload, subtree, tvb)
  local len = #payload
  if len < 1 then return end

  local cmd = byte_at(payload, 1)
  subtree:add(f.mac_cmd_id, tvb(0, 1), cmd)
  local rest = len - 1

  if cmd == 0 then
    -- Beacon Request: optional 4-byte nonce
    if rest == 4 then
      subtree:add(f.mac_nonce, tvb(1, 4))
    end

  elseif cmd == 1 then
    -- Identity Request: no payload
    subtree:set_text("MAC Command: Identity Request")

  elseif cmd == 2 then
    -- Signal Report Request: no payload
    subtree:set_text("MAC Command: Signal Report Request")

  elseif cmd == 3 then
    -- Signal Report Response: RSSI (u8 as negative dBm) + SNR (s8)
    if rest >= 2 then
      local rssi_raw = byte_at(payload, 2)
      local snr_raw  = byte_at(payload, 3)
      -- RSSI stored as unsigned negative dBm: display as negative
      subtree:add(f.mac_rssi, tvb(1, 1)):set_text(
        "RSSI: -" .. rssi_raw .. " dBm")
      subtree:add(f.mac_snr, tvb(2, 1), (snr_raw >= 128) and (snr_raw - 256) or snr_raw)
    end

  elseif cmd == 4 then
    -- Echo Request
    if rest > 0 then subtree:add(f.mac_echo, tvb(1, rest)) end

  elseif cmd == 5 then
    -- Echo Response
    if rest > 0 then subtree:add(f.mac_echo, tvb(1, rest)) end

  elseif cmd == 6 or cmd == 7 then
    -- PFS Session Request / Response
    if rest >= 32 then
      subtree:add(f.mac_pfs_key, tvb(1, 32))
    end
    if rest >= 34 then
      subtree:add(f.mac_duration, tvb(33, 2), uint16_be(payload, 34))
    end

  elseif cmd == 8 then
    -- End PFS Session: no payload
    subtree:set_text("MAC Command: End PFS Session")
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- Text Message dissector
-- Text option numbers (separate namespace from MAC options):
--   0=Message Type, 1=Sender Handle, 2=Message Sequence, 3=Sequence Reset,
--   4=Regarding, 5=Editing, 6=Background Color, 7=Text Color
-- ──────────────────────────────────────────────────────────────────────────
local TXT_OPT_NAMES = {
  [0]="Message Type", [1]="Sender Handle", [2]="Message Sequence",
  [3]="Sequence Reset", [4]="Regarding", [5]="Editing",
  [6]="Background Color", [7]="Text Color",
}

local function dissect_text_message(payload, subtree, tvb, pinfo)
  local len  = #payload
  if len < 1 then return end

  -- Parse CoAP-style options (same codec, separate namespace)
  -- We need the options module; load it lazily.
  local opts_module
  pcall(function() opts_module = require("options") end)

  local off = 1  -- 1-indexed

  -- Scan to find the 0xFF terminator that ends the options block
  local opts_end = off
  if opts_module then
    local scan_ok = pcall(function()
      local total = opts_module.scan_length(payload, off)
      opts_end = off + total  -- first byte after 0xFF
    end)
    if not scan_ok then opts_end = off end  -- no valid options; treat as bare body
  else
    -- Fallback: scan manually for 0xFF
    local p = off
    while p <= len and byte_at(payload, p) ~= 0xFF do p = p + 1 end
    if p <= len then opts_end = p + 1 else opts_end = off end
  end

  -- Show options subtree if there are any options
  local opts_len = opts_end - off
  local opts_tree
  if opts_len > 0 then
    opts_tree = subtree:add(f.txt_opts, tvb(off - 1, opts_len))
    opts_tree:set_text("Message Options (" .. opts_len .. " bytes)")
  end

  -- Decode individual options
  if opts_module and opts_tree and opts_len > 0 then
    pcall(function()
      local raw_pos = 1
      for num, val, consumed in opts_module.decode(payload, off) do
        local v_len   = #val
        local opt_tvb = tvb(off - 1 + raw_pos - 1, consumed)

        if num == 0 then
          local msg_type = (v_len >= 1) and byte_at(val, 1) or 0
          opts_tree:add(f.txt_opt_type, opt_tvb, msg_type)
        elseif num == 1 then
          opts_tree:add(f.txt_handle, opt_tvb, val)
        elseif num == 2 then
          opts_tree:add(f.txt_seq, opt_tvb)
            :set_text("Message Sequence: " .. (v_len > 0 and
              string.format("id=%d", byte_at(val, 1)) ..
              (v_len >= 3 and string.format(" frag=%d/%d", byte_at(val,2)+1, byte_at(val,3)) or "")
              or "(empty)"))
        elseif num == 3 then
          opts_tree:add(f.txt_seq, opt_tvb):set_text("Sequence Reset")
        elseif num == 4 then
          opts_tree:add(f.txt_regarding, opt_tvb)
        elseif num == 5 then
          if v_len >= 1 then opts_tree:add(f.txt_edit, opt_tvb, byte_at(val, 1)) end
        elseif num == 6 then
          opts_tree:add(f.txt_bg_color, opt_tvb)
        elseif num == 7 then
          opts_tree:add(f.txt_fg_color, opt_tvb)
        else
          opts_tree:add(f.txt_unknown, opt_tvb)
            :set_text(string.format("Unknown Option %d (%d bytes)", num, v_len))
        end
        raw_pos = raw_pos + consumed
      end
    end)
  end

  -- Message body (UTF-8 text after 0xFF terminator)
  if opts_end <= len then
    local body_len = len - opts_end + 1
    local body = sub(payload, opts_end, len)
    subtree:add(f.txt_body, tvb(opts_end - 1, body_len), body)
    -- Update info column
    if pinfo then
      local display = body:sub(1, 60)
      if #body > 60 then display = display .. "…" end
      pinfo.cols.info:append(" \"" .. display .. "\"")
    end
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- Public entry point: dissect(payload_bytes, parent_tree, pinfo, ks, crypto)
-- Called from umsh.lua with the decrypted/raw payload as a Lua string.
-- ──────────────────────────────────────────────────────────────────────────
function M.dissect(payload_bytes, parent_tree, pinfo, ks, crypto_mod)
  if not payload_bytes or #payload_bytes < 1 then return end

  local len  = #payload_bytes
  local ptype = payload_bytes:byte(1)
  local type_name = PAYLOAD_TYPES[ptype] or string.format("Unknown (0x%02X)", ptype)

  -- Build a fake Tvb so we can hand TvbRanges to tree:add()
  local tvb = make_tvb(payload_bytes, "UMSH Payload")

  -- Top-level subtree
  local subtree = parent_tree:add(proto, tvb(0))
  subtree:set_text(type_name .. " (" .. len .. " bytes)")
  subtree:add(f.type_byte, tvb(0, 1))

  -- Slice payload after the type byte
  local inner = payload_bytes:sub(2)
  local inner_len = #inner
  local inner_tvb = (inner_len > 0) and tvb(1) or nil

  if ptype == 0x01 then
    -- Node Identity
    if inner_len >= 6 then
      dissect_node_identity(inner, subtree, tvb(1))
    end

  elseif ptype == 0x02 then
    -- MAC Command
    dissect_mac_command(inner, subtree, inner_len > 0 and tvb(1) or tvb(0, 0))

  elseif ptype == 0x03 then
    -- Text Message
    dissect_text_message(inner, subtree, inner_len > 0 and tvb(1) or tvb(0, 0), pinfo)

  elseif ptype == 0x07 then
    -- CoAP: hand off to the built-in CoAP dissector
    local coap_dissector = Dissector.get("coap")
    if coap_dissector and inner_len > 0 then
      pcall(coap_dissector.call, coap_dissector, tvb(1):tvb(), pinfo, parent_tree)
    else
      if inner_len > 0 then
        subtree:add(tvb(1)):set_text("CoAP payload (" .. inner_len .. " bytes)")
      end
    end

  else
    -- Unknown / Node Management / raw
    if inner_len > 0 then
      subtree:add(tvb(1)):set_text(type_name .. " data (" .. inner_len .. " bytes)")
    end
  end
end

return M
