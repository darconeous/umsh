-- UMSH application-layer sub-dissectors
-- Dispatches on the first byte of the (decrypted) payload.
-- Called from umsh.lua after MIC verification / decryption.

local M = {}

local base58 = require("base58")

-- ──────────────────────────────────────────────────────────────────────────
-- Payload type registry
-- ──────────────────────────────────────────────────────────────────────────
local PAYLOAD_TYPES = {
  [0x00] = "Unspecified",
  [0x01] = "Node Identity",
  [0x02] = "MAC Command",
  [0x03] = "Text Message",
  [0x05] = "Chat-Room Message",
  [0x07] = "CoAP",
  [0x08] = "Node Management",
}

-- The protocol column names the application protocol the packet actually
-- carries. CoAP is absent on purpose: the built-in CoAP dissector sets the
-- column itself when the payload is handed to it.
local PROTO_COLUMN = {
  [0x01] = "UMSH-ID",
  [0x02] = "UMSH-MC",
  [0x03] = "UMSH-TC",
  [0x05] = "UMSH-CR",
  [0x08] = "UMSH-NM",
}

-- Which payload types each packet type may carry.
-- docs/protocol/src/payload-format.md, mirrored from
-- PayloadType::allowed_for in crates/umsh-core/src/packet.rs.
local BCST, UACK, UNIC, UNAR, MCST, BUNI, BUAR = 0, 1, 2, 3, 4, 6, 7
local ALLOWED_IN = {
  [0x00] = {[BCST]=true, [UNIC]=true, [UNAR]=true, [MCST]=true, [BUNI]=true, [BUAR]=true},
  [0x01] = {[BCST]=true, [UNIC]=true, [UNAR]=true, [MCST]=true, [BUNI]=true, [BUAR]=true},
  [0x02] = {[BCST]=true, [UNIC]=true, [UNAR]=true, [MCST]=true, [BUNI]=true, [BUAR]=true},
  [0x03] = {           [UNIC]=true, [UNAR]=true, [MCST]=true, [BUNI]=true, [BUAR]=true},
  [0x05] = {           [UNIC]=true, [UNAR]=true,              [BUNI]=true, [BUAR]=true},
  [0x07] = {           [UNIC]=true, [UNAR]=true, [MCST]=true, [BUNI]=true, [BUAR]=true},
  [0x08] = {           [UNIC]=true, [UNAR]=true,              [BUNI]=true, [BUAR]=true},
}
local PKT_TYPE_NAME = {
  [0]="broadcast", [1]="MAC ack", [2]="unicast", [3]="unicast",
  [4]="multicast", [6]="blind unicast", [7]="blind unicast",
}

-- Holes in the registry, alongside everything from 128 up.
local RESERVED_PAYLOAD_TYPES = {[0x04] = true, [0x06] = true}

-- ──────────────────────────────────────────────────────────────────────────
-- Protocol and fields — registered at load time (Wireshark requires all
-- Protos and their fields to be set up before any dissection begins).
-- ──────────────────────────────────────────────────────────────────────────
local proto = Proto("umsh.app", "UMSH Application Layer")
local f = {}

-- Common
f.type_byte    = ProtoField.uint8  ("umsh.app.type",        "Payload Type",   base.HEX, PAYLOAD_TYPES)
-- Bytes we can name but not decode. A tree item always needs a field of its
-- own: adding a bare TvbRange is rejected as a dissector bug.
f.opaque       = ProtoField.bytes  ("umsh.app.data",        "Payload Data")

-- Node Identity
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
f.ni_options   = ProtoField.bytes  ("umsh.app.ni.options",  "Identity Options")
f.ni_name      = ProtoField.string ("umsh.app.ni.name",     "Node Name")
f.ni_location  = ProtoField.bytes  ("umsh.app.ni.location", "Node Location")
f.ni_altitude  = ProtoField.int32  ("umsh.app.ni.altitude", "Altitude (m)",   base.DEC)
f.ni_timestamp = ProtoField.uint32 ("umsh.app.ni.timestamp","Unix Timestamp", base.DEC)
f.ni_regions   = ProtoField.bytes  ("umsh.app.ni.regions",  "Supported Regions")
f.ni_nonce     = ProtoField.bytes  ("umsh.app.ni.nonce",    "Nonce")
f.ni_unknown   = ProtoField.bytes  ("umsh.app.ni.unk",      "Unknown Option")
f.ni_sig       = ProtoField.bytes  ("umsh.app.ni.sig",      "EdDSA Signature")

-- MAC Command
local MAC_COMMANDS = {
  [0]="Unallocated",        [1]="Identity Request",
  [2]="Signal Report Req",  [3]="Signal Report Resp",
  [4]="Echo Request",       [5]="Echo Response",
  [6]="PFS Session Request",[7]="PFS Session Response",
  [8]="End PFS Session",    [9]="No-op",
}
f.mac_cmd_id   = ProtoField.uint8  ("umsh.app.mac.cmd",     "Command",        base.HEX, MAC_COMMANDS)
f.mac_nonce    = ProtoField.bytes  ("umsh.app.mac.nonce",   "Nonce")
f.mac_filt_hint= ProtoField.string ("umsh.app.mac.filter_hint", "Filter: Node Hint Prefix")
f.mac_filt_role= ProtoField.uint8  ("umsh.app.mac.filter_role", "Filter: Node Role", base.DEC)
f.mac_filt_caps= ProtoField.uint8  ("umsh.app.mac.filter_caps", "Filter: Capabilities", base.HEX)
f.mac_unknown  = ProtoField.bytes  ("umsh.app.mac.unk",     "Unknown Option")
f.mac_rssi     = ProtoField.int8   ("umsh.app.mac.rssi",    "RSSI",           base.DEC)
f.mac_snr      = ProtoField.int8   ("umsh.app.mac.snr",     "SNR",            base.DEC)
f.mac_echo     = ProtoField.bytes  ("umsh.app.mac.echo",    "Echo Data")
f.mac_pfs_key  = ProtoField.bytes  ("umsh.app.mac.pfs_key", "Ephemeral Address")
f.mac_duration = ProtoField.uint16 ("umsh.app.mac.dur",     "Session Duration (min)", base.DEC)

-- Text Message
f.txt_opts     = ProtoField.bytes  ("umsh.app.txt.opts",    "Message Options")
f.txt_opt_type = ProtoField.uint8  ("umsh.app.txt.type",    "Message Type",   base.DEC, {
  [0]="Basic text", [1]="Status text", [2]="Resend Request",
  [3]="Message Unavailable",
  [32]="User Joined", [33]="User Left", [34]="Admin Message",
})
f.txt_handle   = ProtoField.string ("umsh.app.txt.handle",  "Sender Handle")
f.txt_seq      = ProtoField.bytes  ("umsh.app.txt.seq",     "Message Sequence")
f.txt_regarding= ProtoField.bytes  ("umsh.app.txt.re",      "Regarding")
f.txt_edit     = ProtoField.uint8  ("umsh.app.txt.edit",    "Editing Msg ID", base.DEC)
f.txt_bg_color = ProtoField.bytes  ("umsh.app.txt.bg",      "Background Color")
f.txt_fg_color = ProtoField.bytes  ("umsh.app.txt.fg",      "Text Color")
f.txt_unknown  = ProtoField.bytes  ("umsh.app.txt.unk",     "Unknown Option")
f.txt_body     = ProtoField.string ("umsh.app.txt.body",    "Message Body")

-- Chat-Room Message
local CHAT_ACTIONS = {
  [0]="Get Room Info", [1]="Room Info", [2]="Login", [3]="Logout",
  [5]="Fetch Messages", [6]="Fetch Users", [7]="Admin Command",
  [8]="Room Update",
}
f.cr_action    = ProtoField.uint8  ("umsh.app.cr.action",   "Action",         base.DEC, CHAT_ACTIONS)
f.cr_opts      = ProtoField.bytes  ("umsh.app.cr.opts",     "Action Options")
f.cr_opt_str   = ProtoField.string ("umsh.app.cr.opt_str",  "Option")
f.cr_opt_uint  = ProtoField.uint32 ("umsh.app.cr.opt_uint", "Option",         base.DEC)
f.cr_opt_bytes = ProtoField.bytes  ("umsh.app.cr.opt_bytes","Option")
f.cr_desc      = ProtoField.string ("umsh.app.cr.desc",     "Room Description")
f.cr_timestamp = ProtoField.uint32 ("umsh.app.cr.timestamp","Timestamp",      base.DEC)
f.cr_max_count = ProtoField.uint8  ("umsh.app.cr.max_count","Max Count",      base.DEC)
f.cr_body      = ProtoField.bytes  ("umsh.app.cr.body",     "Action Body")

-- Node Management (ULCP over UMSH)
f.nm_flags     = ProtoField.uint8  ("umsh.app.nm.flags",    "Flags",          base.HEX)
f.nm_flag_r    = ProtoField.bool   ("umsh.app.nm.flags.r",  "Response (R)",   8, nil, 0x80)
f.nm_flag_rsvd = ProtoField.uint8  ("umsh.app.nm.flags.rsvd","Reserved",      base.HEX, nil, 0x7F)
f.nm_token     = ProtoField.uint16 ("umsh.app.nm.token",    "Token",          base.HEX)
f.nm_opts      = ProtoField.bytes  ("umsh.app.nm.opts",     "Options")
f.nm_cursor    = ProtoField.bytes  ("umsh.app.nm.cursor",   "Cursor")
f.nm_remaining = ProtoField.uint32 ("umsh.app.nm.remaining","Remaining",      base.DEC)
f.nm_unknown   = ProtoField.bytes  ("umsh.app.nm.unk",      "Unknown Option")
f.nm_frames    = ProtoField.bytes  ("umsh.app.nm.frames",   "Frame List")
f.nm_frame_len = ProtoField.uint32 ("umsh.app.nm.frame_len","Frame Length",   base.DEC)

proto.fields = {
  f.type_byte, f.opaque,
  f.ni_role, f.ni_caps,
  f.ni_caps_rep, f.ni_caps_mob, f.ni_caps_txt, f.ni_caps_tel,
  f.ni_caps_room, f.ni_caps_coap,
  f.ni_options, f.ni_name, f.ni_location, f.ni_altitude,
  f.ni_timestamp, f.ni_regions, f.ni_nonce, f.ni_unknown, f.ni_sig,
  f.mac_cmd_id, f.mac_nonce, f.mac_rssi, f.mac_snr,
  f.mac_echo, f.mac_pfs_key, f.mac_duration,
  f.mac_filt_hint, f.mac_filt_role, f.mac_filt_caps, f.mac_unknown,
  f.txt_opts, f.txt_opt_type, f.txt_handle, f.txt_seq,
  f.txt_regarding, f.txt_edit, f.txt_bg_color, f.txt_fg_color,
  f.txt_unknown, f.txt_body,
  f.cr_action, f.cr_opts, f.cr_opt_str, f.cr_opt_uint, f.cr_opt_bytes,
  f.cr_desc, f.cr_timestamp, f.cr_max_count, f.cr_body,
  f.nm_flags, f.nm_flag_r, f.nm_flag_rsvd, f.nm_token, f.nm_opts,
  f.nm_cursor, f.nm_remaining, f.nm_unknown, f.nm_frames, f.nm_frame_len,
}

-- ──────────────────────────────────────────────────────────────────────────
-- Helpers: work on raw Lua strings (not Tvb) since this module receives
-- the payload as a Lua string from the decryption path.
-- ──────────────────────────────────────────────────────────────────────────
local function byte_at(s, i)   return s:byte(i) end
local function sub(s, i, j)    return s:sub(i, j) end
local function uint16_be(s, i) return s:byte(i) * 256 + s:byte(i+1) end

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
--
-- Wire layout (see docs/protocol/src/node-identity.md):
--   [ROLE:1] [CAPS:1] [CoAP options...] [0xFF]? [SIG:64]?
--
-- Bits 6-7 of CAPS are reserved and have no field. The 0xFF marker is
-- required when a signature follows, omitted otherwise. Option numbers:
-- 0=Name, 1=Location, 2=Altitude, 3=Timestamp, 4=Supported Regions, 5=Nonce.
-- ──────────────────────────────────────────────────────────────────────────
local ROLE_NAMES = {
  [0]="Unspecified", [1]="Repeater", [2]="Chat", [3]="Tracker",
  [4]="Sensor",      [5]="Bridge",   [6]="Chat Room", [7]="Temporary Session",
}

-- Short capability tags for the Info column, low bit first.
local CAPS_TAGS = {"REP", "MOB", "TXT", "TLM", "CHR", "CoAP"}

local function caps_summary(caps)
  local tags = {}
  for i, tag in ipairs(CAPS_TAGS) do
    if (caps & (1 << (i - 1))) ~= 0 then tags[#tags + 1] = tag end
  end
  return table.concat(tags, ",")
end

local function dissect_node_identity(payload, subtree, tvb, ctx, pinfo)
  local len = #payload
  local off = 1  -- 1-indexed in Lua string
  local role, node_name

  -- Role (1 byte)
  if off > len then return end
  role = byte_at(payload, off)
  subtree:add(f.ni_role, tvb(off - 1, 1), role)
  off = off + 1

  -- Capabilities (1 byte)
  if off > len then return end
  local caps = byte_at(payload, off)
  local caps_tree = subtree:add(f.ni_caps, tvb(off - 1, 1), caps)
  caps_tree:add(f.ni_caps_coap, tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_room, tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_tel,  tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_txt,  tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_mob,  tvb(off - 1, 1))
  caps_tree:add(f.ni_caps_rep,  tvb(off - 1, 1))
  off = off + 1

  -- CoAP options block.
  local opts_module
  pcall(function() opts_module = require("options") end)

  local opts_start = off
  local opts_end = off
  if opts_module and off <= len then
    local scan_ok = pcall(function()
      local total = opts_module.scan_length(payload, off)
      opts_end = off + total  -- first byte after the 0xFF (or end of region)
    end)
    if not scan_ok then opts_end = off end
  end

  -- A block holding nothing but its terminator has no options to show.
  local opts_len = opts_end - opts_start
  local opts_tree
  if opts_len > 1 or (opts_len == 1 and byte_at(payload, opts_start) ~= 0xFF) then
    opts_tree = subtree:add(f.ni_options, tvb(opts_start - 1, opts_len))
    opts_tree:set_text("Identity Options (" .. opts_len .. " bytes)")
  end

  if opts_module and opts_tree and opts_len > 0 then
    pcall(function()
      local raw_pos = 1
      for num, val, consumed in opts_module.decode(payload, opts_start) do
        local v_len   = #val
        local opt_tvb = tvb(opts_start - 1 + raw_pos - 1, consumed)

        if num == 0 then
          node_name = val
          opts_tree:add(f.ni_name, opt_tvb, val)
        elseif num == 1 then
          local item = opts_tree:add(f.ni_location, opt_tvb)
          item:set_text(string.format("Node Location (%d bytes)", v_len))
          -- A location encodes at most 7 bytes of precision; anything
          -- beyond the seventh is ignored on read.
          if v_len > 7 and ctx and ctx.flag then
            ctx.flag(item, opt_tvb,
              string.format("Node location must not encode more than 7 bytes (has %d)", v_len))
          end
        elseif num == 2 then
          if v_len == 0 then
            opts_tree:add(f.ni_altitude, opt_tvb, 0)
          else
            -- Minimal big-endian signed integer (up to 4 bytes)
            local first = byte_at(val, 1)
            local v = 0
            if (first & 0x80) ~= 0 then v = -1 end
            for i = 1, v_len do
              v = ((v * 256) + byte_at(val, i)) & 0xFFFFFFFF
              if v >= 0x80000000 then v = v - 0x100000000 end
            end
            opts_tree:add(f.ni_altitude, opt_tvb, v)
          end
        elseif num == 3 then
          -- Minimal big-endian unsigned integer (up to 4 bytes)
          local v = 0
          for i = 1, v_len do v = v * 256 + byte_at(val, i) end
          opts_tree:add(f.ni_timestamp, opt_tvb, v)
        elseif num == 4 then
          opts_tree:add(f.ni_regions, opt_tvb)
            :set_text(string.format("Supported Regions (%d region%s)",
                                     v_len / 2,
                                     (v_len == 2) and "" or "s"))
        elseif num == 5 then
          -- Echoed from the Identity Request that solicited this payload.
          opts_tree:add(f.ni_nonce, tvb(opts_start - 1 + raw_pos - 1 + consumed - v_len, v_len))
        else
          opts_tree:add(f.ni_unknown, opt_tvb)
            :set_text(string.format("Unknown Option %d (%d bytes)", num, v_len))
        end
        raw_pos = raw_pos + consumed
      end
    end)
  end

  off = opts_end

  -- Optional EdDSA signature (64 bytes after the options block).
  local signed = (len - off + 1 == 64)
  if signed then
    subtree:add(f.ni_sig, tvb(off - 1, 64))
  end

  -- Summarise the identity in the Info column: who it is, what it says it
  -- does, and whether it stands on its own signature.
  if pinfo then
    local parts = {}
    if node_name and node_name ~= "" then
      parts[#parts + 1] = '"' .. node_name .. '"'
    end
    parts[#parts + 1] = ROLE_NAMES[role] or string.format("Role %d", role or 0)
    local tags = caps_summary(caps)
    if tags ~= "" then parts[#parts + 1] = "[" .. tags .. "]" end
    if signed then parts[#parts + 1] = "signed" end
    pinfo.cols.info:append(" Identity: " .. table.concat(parts, " "))
  end

  if not (ctx and ctx.flag) then return end

  -- A signature is checkable only against the sending node's key, so a
  -- signed broadcast advertisement has to carry that key in full.
  if signed and ctx.pkt_type == 0 and ctx.full_src == false then
    ctx.flag(subtree, tvb(off - 1, 64),
      "Signed broadcast advertisement must carry its source address in full-key form (S=1)")
  end

  -- Not checked here: "the response MUST NOT carry a FHOPS field". That
  -- rule holds for a response to a request confined to its requester's
  -- neighbourhood, and a response frame does not record which kind of
  -- request drew it — the echoed nonce marks it as a response but says
  -- nothing about how the request was addressed or filtered.
end

-- ──────────────────────────────────────────────────────────────────────────
-- MAC Command dissector
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_mac_command(payload, subtree, tvb, ctx, pinfo)
  local len = #payload
  if len < 1 then return end

  local cmd = byte_at(payload, 1)
  subtree:add(f.mac_cmd_id, tvb(0, 1), cmd)
  local rest = len - 1

  local cmd_name = MAC_COMMANDS[cmd] or string.format("Unknown (0x%02X)", cmd)
  -- Detail worth a place on the summary line, filled in per command below.
  local detail

  -- Only the Identity Request is admitted to broadcast; a receiver drops
  -- any other MAC command that arrives that way.
  if ctx and ctx.flag and ctx.pkt_type == 0 and cmd ~= 1 then
    ctx.flag(subtree, tvb(0, 1), string.format(
      "%s must not be carried in a broadcast — only the Identity Request may be",
      MAC_COMMANDS[cmd] or string.format("MAC command %d", cmd)))
  end

  if cmd == 1 then
    -- Identity Request: CoAP-encoded filter options select who answers.
    local opts_module
    pcall(function() opts_module = require("options") end)

    local n_filters = 0
    local saw_hint_filter = false
    if opts_module and rest > 0 then
      pcall(function()
        local pos = 1  -- offset within the option block, 1-indexed
        for num, val, consumed in opts_module.decode(payload, 2) do
          local v_len   = #val
          local opt_tvb = tvb(pos, consumed)
          -- The value sits at the tail of the option, after the header and
          -- any extension bytes; a pure-value field should cover only that.
          local val_tvb = tvb(pos + consumed - v_len, v_len)
          if num == 1 then
            subtree:add(f.mac_nonce, val_tvb)
          elseif num == 3 then
            n_filters = n_filters + 1
            saw_hint_filter = true
            -- The filter matches a leading part of the node hint, so the
            -- value may be shorter than one: two bytes is a router hint,
            -- which is all a route reveals about the hops it names.
            local shown
            if v_len == 2 then
              shown = base58.router_hint_full(val) .. " (router hint)"
            elseif v_len == 3 then
              shown = base58.node_hint_full(val)
            else
              shown = base58.hex_bytes(val)
            end
            subtree:add(f.mac_filt_hint, opt_tvb, shown)
            if v_len < 1 or v_len > 3 then
              if ctx and ctx.flag then
                ctx.flag(subtree, opt_tvb, string.format(
                  "FILTER_NODE_HINT must be 1 to 3 bytes (is %d)", v_len))
              end
            end
          elseif num == 5 then
            n_filters = n_filters + 1
            if v_len >= 1 then subtree:add(f.mac_filt_role, opt_tvb, byte_at(val, 1)) end
          elseif num == 7 then
            n_filters = n_filters + 1
            if v_len >= 1 then subtree:add(f.mac_filt_caps, opt_tvb, byte_at(val, 1)) end
          else
            subtree:add(f.mac_unknown, opt_tvb):set_text(
              string.format("Unknown Option %d (%d bytes)", num, v_len))
          end
          pos = pos + consumed
        end
      end)
    end

    if n_filters > 0 then
      detail = string.format("%d filter%s", n_filters, n_filters == 1 and "" or "s")
    end

    if ctx and ctx.flag and (ctx.pkt_type == 0 or ctx.pkt_type == 4) then
      -- A request that is not aimed at one node reaches everyone it
      -- touches, so a flooded one has to narrow the field.
      if n_filters == 0 then
        ctx.flag(subtree, tvb(0, 1),
          "Broadcast or multicast Identity Request must carry at least one filter option")
      end
      -- The hop limit is confined only for a request that selects by role
      -- or capability, since every node it reaches may answer. One naming
      -- a node by hint draws a single reply however far it travels — a few
      -- at most, where the hint is partial — so its hop count is its own
      -- business.
      if not saw_hint_filter and ctx.fhops ~= nil and ctx.fhops ~= 0 then
        ctx.flag(subtree, tvb(0, 1), string.format(
          "Identity Request without a node-hint filter must have FHOPS absent or 0x00 (is 0x%02X)",
          ctx.fhops))
      end
    end

  elseif cmd == 2 then
    -- Signal Report Request: no payload
    subtree:set_text("MAC Command: Signal Report Request")

  elseif cmd == 3 then
    -- Signal Report Response: RSSI (u8 as negative dBm) + SNR (s8)
    if rest >= 2 then
      local rssi_raw = byte_at(payload, 2)
      local snr_raw  = byte_at(payload, 3)
      local snr      = (snr_raw >= 128) and (snr_raw - 256) or snr_raw
      -- RSSI stored as unsigned negative dBm: display as negative
      subtree:add(f.mac_rssi, tvb(1, 1)):set_text(
        "RSSI: -" .. rssi_raw .. " dBm")
      subtree:add(f.mac_snr, tvb(2, 1), snr)
      detail = string.format("RSSI -%d dBm, SNR %d dB", rssi_raw, snr)
    end

  elseif cmd == 4 or cmd == 5 then
    -- Echo Request / Response
    if rest > 0 then
      subtree:add(f.mac_echo, tvb(1, rest))
      detail = string.format("%d byte%s", rest, rest == 1 and "" or "s")
    end

  elseif cmd == 6 or cmd == 7 then
    -- PFS Session Request / Response
    if rest >= 32 then
      subtree:add(f.mac_pfs_key, tvb(1, 32))
    end
    if rest >= 34 then
      local minutes = uint16_be(payload, 34)
      subtree:add(f.mac_duration, tvb(33, 2), minutes)
      detail = (minutes == 0) and "no expiry"
                              or string.format("%d min", minutes)
    end

  elseif cmd == 8 then
    -- End PFS Session: no payload
    subtree:set_text("MAC Command: End PFS Session")

  elseif cmd == 9 then
    -- No-op: no payload. Sent to draw a MAC ack and nothing else.
    subtree:set_text("MAC Command: No-op")
  end

  -- Name the command on the summary line. Which command it is is the whole
  -- content of most of these payloads, so it belongs where it can be read
  -- without opening the frame.
  if pinfo then
    pinfo.cols.info:append(" MAC Command: " .. cmd_name ..
                           (detail and (" (" .. detail .. ")") or ""))
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

local function dissect_text_message(payload, subtree, tvb, pinfo, ctx)
  local len  = #payload
  if len < 1 then return end

  -- What the well-known channels require of a chat message. Both rules are
  -- about what a conformant interface will show, so a frame flagged here is
  -- one that no receiver is going to display.
  if ctx and ctx.flag and ctx.channel and ctx.channel.builtin and
     ctx.full_src == false then
    local caveat = ctx.mic_verified and "" or " (channel identified by ID only)"
    ctx.flag(subtree, tvb(0, math.min(1, len)), string.format(
      "%s channel chat without the full source key (S=1) must not be displayed%s",
      ctx.channel.builtin == "emergency" and "Emergency" or "Public", caveat))
  end

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

  -- Show options subtree if there are any options; a lone 0xFF is not one.
  local opts_len = opts_end - off
  local opts_tree
  if opts_len > 1 or (opts_len == 1 and byte_at(payload, off) ~= 0xFF) then
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
-- Chat-Room Message dissector
--
-- Wire layout (docs/protocol/src/app-chat-rooms.md):
--   [ACTION:1] [action-specific body]
-- Most actions carry a CoAP-option-encoded body in their own namespace.
-- ──────────────────────────────────────────────────────────────────────────

-- Option names per action, keyed by action number.
local CR_OPT_NAMES = {
  [1] = {[0]="Room Name", [1]="Owner Information", [2]="Administrator",
         [3]="Active User Count", [4]="Max User Count", [5]="Message Queue Depth",
         [6]="Most Recent Message Timestamp", [7]="Oldest Retrievable Message Timestamp"},
  [2] = {[0]="Handle", [1]="Last Message Timestamp", [2]="Session Timeout",
         [3]="Password"},
}
-- Options whose value reads as a string rather than a number.
local CR_OPT_STRING = {
  [1] = {[0]=true, [1]=true},
  [2] = {[0]=true},
}

local function dissect_chat_options(payload, start, subtree, tvb, action)
  local opts_module
  pcall(function() opts_module = require("options") end)
  if not opts_module then return start end

  local opts_end = start
  local scan_ok = pcall(function()
    opts_end = start + opts_module.scan_length(payload, start)
  end)
  if not scan_ok then return start end

  local opts_len = opts_end - start
  if opts_len < 1 or (opts_len == 1 and byte_at(payload, start) == 0xFF) then
    return opts_end
  end

  local opts_tree = subtree:add(f.cr_opts, tvb(start - 1, opts_len))
  opts_tree:set_text("Action Options (" .. opts_len .. " bytes)")

  local names   = CR_OPT_NAMES[action] or {}
  local strings = CR_OPT_STRING[action] or {}
  pcall(function()
    local pos = 1
    for num, val, consumed in opts_module.decode(payload, start) do
      local v_len   = #val
      local opt_tvb = tvb(start - 1 + pos - 1, consumed)
      local name    = names[num] or string.format("Option %d", num)

      if strings[num] then
        opts_tree:add(f.cr_opt_str, opt_tvb, val):set_text(name .. ": " .. val)
      elseif v_len >= 1 and v_len <= 4 then
        local v = 0
        for i = 1, v_len do v = v * 256 + byte_at(val, i) end
        opts_tree:add(f.cr_opt_uint, opt_tvb, v):set_text(
          string.format("%s: %d", name, v))
      else
        opts_tree:add(f.cr_opt_bytes, opt_tvb):set_text(
          string.format("%s (%d bytes)", name, v_len))
      end
      pos = pos + consumed
    end
  end)

  return opts_end
end

local function dissect_chat_room(payload, subtree, tvb, pinfo)
  local len = #payload
  if len < 1 then return end

  local action = byte_at(payload, 1)
  subtree:add(f.cr_action, tvb(0, 1), action)
  local rest = len - 1
  local name = CHAT_ACTIONS[action] or string.format("Action %d", action)
  if pinfo then pinfo.cols.info:append(" Chat Room: " .. name) end

  if action == 1 or action == 2 then
    -- Room Info / Login: CoAP options, and for Room Info an optional
    -- UTF-8 description after the terminator.
    local opts_end = dissect_chat_options(payload, 2, subtree, tvb, action)
    if action == 1 and opts_end <= len then
      subtree:add(f.cr_desc, tvb(opts_end - 1, len - opts_end + 1),
                  sub(payload, opts_end, len))
    end

  elseif action == 5 then
    -- Fetch Messages: 4-byte timestamp + 1-byte max count.
    if rest >= 5 then
      local ts = 0
      for i = 2, 5 do ts = ts * 256 + byte_at(payload, i) end
      subtree:add(f.cr_timestamp, tvb(1, 4), ts)
      subtree:add(f.cr_max_count, tvb(5, 1), byte_at(payload, 6))
    end

  elseif rest > 0 then
    -- Admin Command and Room Update carry bodies the spec leaves opaque,
    -- as does the reference implementation.
    subtree:add(f.cr_body, tvb(1, rest)):set_text(
      string.format("%s body (%d bytes)", name, rest))
  end
end

-- ──────────────────────────────────────────────────────────────────────────
-- Node Management dissector (ULCP frames carried over the mesh)
--
-- Wire layout (docs/protocol/src/app-node-management.md):
--   [FLAGS:1] [TOKEN:2] [OPTIONS] [0xFF] [FRAME LIST]
-- Each frame in the list is preceded by its length as a packed unsigned
-- integer.
-- ──────────────────────────────────────────────────────────────────────────
local function dissect_node_management(payload, subtree, tvb, pinfo, ctx)
  local len = #payload
  if len < 3 then return end

  local flags = byte_at(payload, 1)
  local is_response = (flags & 0x80) ~= 0
  local flags_tree = subtree:add(f.nm_flags, tvb(0, 1), flags)
  flags_tree:add(f.nm_flag_r,    tvb(0, 1))
  flags_tree:add(f.nm_flag_rsvd, tvb(0, 1))

  -- An unknown flag may change the meaning of everything that follows,
  -- including the token, so a receiver cannot even form a response.
  if (flags & 0x7F) ~= 0 and ctx and ctx.flag then
    ctx.flag(flags_tree, tvb(0, 1), string.format(
      "Node Management reserved flag bits must be zero (is 0x%02X)", flags & 0x7F))
  end

  local token = uint16_be(payload, 2)
  subtree:add(f.nm_token, tvb(1, 2), token)
  if pinfo then
    pinfo.cols.info:append(string.format(" Node Mgmt: %s (token 0x%04X)",
                                         is_response and "response" or "request",
                                         token))
  end

  -- Options block, then the frame list after the terminator.
  local opts_module
  pcall(function() opts_module = require("options") end)

  local off = 4  -- 1-indexed: after FLAGS(1) + TOKEN(2)
  local opts_end = off
  if opts_module and off <= len then
    local scan_ok = pcall(function()
      opts_end = off + opts_module.scan_length(payload, off)
    end)
    if not scan_ok then opts_end = off end
  end

  local opts_len = opts_end - off
  if opts_len > 1 or (opts_len == 1 and byte_at(payload, off) ~= 0xFF) then
    local opts_tree = subtree:add(f.nm_opts, tvb(off - 1, opts_len))
    opts_tree:set_text("Options (" .. opts_len .. " bytes)")
    pcall(function()
      local pos = 1
      for num, val, consumed in opts_module.decode(payload, off) do
        local v_len   = #val
        local opt_tvb = tvb(off - 1 + pos - 1, consumed)
        if num == 1 then
          opts_tree:add(f.nm_cursor, tvb(off - 1 + pos - 1 + consumed - v_len, v_len))
        elseif num == 2 then
          local v = 0
          for i = 1, v_len do v = v * 256 + byte_at(val, i) end
          opts_tree:add(f.nm_remaining, opt_tvb, v)
        else
          opts_tree:add(f.nm_unknown, opt_tvb):set_text(
            string.format("Unknown Option %d (%d bytes)", num, v_len))
        end
        pos = pos + consumed
      end
    end)
  end

  if opts_end > len then return end

  -- Frame list: each ULCP frame preceded by its length as a PUI.
  local list_len  = len - opts_end + 1
  local list_tree = subtree:add(f.nm_frames, tvb(opts_end - 1, list_len))

  local ulcp
  pcall(function() ulcp = require("ulcp") end)

  local pos    = opts_end
  local frames = 0
  while pos <= len do
    local flen, consumed = nil, 0
    if ulcp and ulcp.decode_pui_str then
      flen, consumed = ulcp.decode_pui_str(payload, pos)
    end
    if not flen or consumed == 0 then break end
    local body_start = pos + consumed
    if body_start + flen - 1 > len then
      list_tree:add(f.nm_frame_len, tvb(pos - 1, consumed), flen):set_text(
        string.format("Frame Length: %d (exceeds the payload)", flen))
      break
    end

    frames = frames + 1
    local frame_tree = list_tree:add(f.nm_frames,
                                     tvb(pos - 1, consumed + flen))
    frame_tree:set_text(string.format("Frame %d (%d bytes)", frames, flen))
    frame_tree:add(f.nm_frame_len, tvb(pos - 1, consumed), flen)

    if flen > 0 and ulcp and ulcp.dissect_frame then
      pcall(ulcp.dissect_frame, tvb(body_start - 1, flen):tvb(), pinfo, frame_tree,
            is_response and "Device → Administrator" or "Administrator → Device")
    end
    pos = body_start + flen
  end

  list_tree:set_text(string.format("Frame List (%d frame%s, %d bytes)",
                                   frames, frames == 1 and "" or "s", list_len))
end

-- ──────────────────────────────────────────────────────────────────────────
-- Public entry point: dissect(payload_bytes, parent_tree, pinfo, ks, crypto)
-- Called from umsh.lua with the decrypted/raw payload as a Lua string.
-- ──────────────────────────────────────────────────────────────────────────
function M.dissect(payload_bytes, parent_tree, pinfo, ks, crypto_mod, ctx)
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

  -- Name the application protocol in the protocol column. CoAP sets its own
  -- when the payload reaches it.
  if pinfo and PROTO_COLUMN[ptype] then
    pinfo.cols.protocol = PROTO_COLUMN[ptype]
  end

  -- Not every payload type may ride every packet type.
  if ctx and ctx.flag and ctx.pkt_type then
    if ptype >= 0x80 or RESERVED_PAYLOAD_TYPES[ptype] then
      ctx.flag(subtree, tvb(0, 1), string.format(
        "Payload type 0x%02X is reserved", ptype))
    elseif ALLOWED_IN[ptype] and not ALLOWED_IN[ptype][ctx.pkt_type] then
      ctx.flag(subtree, tvb(0, 1), string.format(
        "%s payload must not be carried in a %s packet",
        type_name, PKT_TYPE_NAME[ctx.pkt_type] or "?"))
    end
  end

  -- Slice payload after the type byte
  local inner = payload_bytes:sub(2)
  local inner_len = #inner

  if ptype == 0x01 then
    -- Node Identity
    if inner_len >= 2 then
      dissect_node_identity(inner, subtree, tvb(1), ctx, pinfo)
    end

  elseif ptype == 0x02 then
    -- MAC Command
    dissect_mac_command(inner, subtree, inner_len > 0 and tvb(1) or tvb(0, 0), ctx, pinfo)

  elseif ptype == 0x03 then
    -- Text Message
    dissect_text_message(inner, subtree, inner_len > 0 and tvb(1) or tvb(0, 0), pinfo, ctx)

  elseif ptype == 0x05 then
    -- Chat-Room Message
    dissect_chat_room(inner, subtree, inner_len > 0 and tvb(1) or tvb(0, 0), pinfo)

  elseif ptype == 0x07 then
    -- CoAP: hand off to the built-in CoAP dissector
    local coap_dissector = Dissector.get("coap")
    if coap_dissector and inner_len > 0 then
      pcall(coap_dissector.call, coap_dissector, tvb(1):tvb(), pinfo, parent_tree)
    else
      if inner_len > 0 then
        subtree:add(f.opaque, tvb(1)):set_text(
          "CoAP payload (" .. inner_len .. " bytes)")
      end
    end

  elseif ptype == 0x08 then
    -- Node Management
    if inner_len > 0 then
      dissect_node_management(inner, subtree, tvb(1), pinfo, ctx)
    end

  else
    -- Unspecified / unknown / raw
    if inner_len > 0 then
      subtree:add(f.opaque, tvb(1)):set_text(
        type_name .. " data (" .. inner_len .. " bytes)")
    end
  end
end

return M
