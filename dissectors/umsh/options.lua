-- UMSH option codec: CoAP-style delta/length encoding + ARNCE/HAM-64 decode
-- Reference: crates/umsh-core/src/options.rs

local M = {}

-- ---------------------------------------------------------------------------
-- ARNCE / HAM-64 decode
-- Spec: https://github.com/darconeous/ham-addr/raw/refs/heads/main/n6drc-arnce.md
--
-- Base-40 alphabet: NUL(0), A-Z(1-26), 0-9(27-36), /(37), -(38), ESC(39)
-- Three characters packed into one big-endian 16-bit chunk:
--   val = c0*1600 + c1*40 + c2
-- Input bytes must come in pairs (2, 4, 6, or 8 bytes).
-- ---------------------------------------------------------------------------

local ARNCE_CHARS = {
  [0]  = "",    -- NUL (padding/terminator, yields empty string → stops here)
  [1]  = "A",  [2]  = "B",  [3]  = "C",  [4]  = "D",  [5]  = "E",
  [6]  = "F",  [7]  = "G",  [8]  = "H",  [9]  = "I",  [10] = "J",
  [11] = "K",  [12] = "L",  [13] = "M",  [14] = "N",  [15] = "O",
  [16] = "P",  [17] = "Q",  [18] = "R",  [19] = "S",  [20] = "T",
  [21] = "U",  [22] = "V",  [23] = "W",  [24] = "X",  [25] = "Y",
  [26] = "Z",  [27] = "0",  [28] = "1",  [29] = "2",  [30] = "3",
  [31] = "4",  [32] = "5",  [33] = "6",  [34] = "7",  [35] = "8",
  [36] = "9",  [37] = "/",  [38] = "-",  [39] = "^",  -- ^ = ESC/reserved
}

-- Decode an ARNCE/HAM-64 byte string (2, 4, 6, or 8 bytes) to a callsign.
-- bytes_str: raw Lua string of byte data (big-endian 16-bit chunks).
-- Returns a human-readable string, or a hex fallback on bad input.
function M.decode_arnce(bytes_str)
  local len = #bytes_str
  if len == 0 or len % 2 ~= 0 or len > 8 then
    return bytes_str:gsub(".", function(c) return string.format("%02X", c:byte()) end)
  end

  local result = {}
  local done = false
  for i = 1, len, 2 do
    if done then break end
    local hi = bytes_str:byte(i)
    local lo = bytes_str:byte(i + 1)
    local chunk = hi * 256 + lo
    if chunk == 0 then
      done = true  -- All-zero chunk = end of callsign
    else
      local c0 = math.floor(chunk / 1600) % 40
      local c1 = math.floor(chunk / 40) % 40
      local c2 = chunk % 40
      for _, cv in ipairs({c0, c1, c2}) do
        if cv == 0 then
          done = true; break
        end
        result[#result + 1] = ARNCE_CHARS[cv] or ("\\x" .. string.format("%02x", cv))
      end
    end
  end
  return table.concat(result)
end

-- ---------------------------------------------------------------------------
-- CoAP-style delta/length option codec
--
-- Wire format per option:
--   byte[0]: high nibble = delta, low nibble = length
--   Optional extended delta: 1 byte if delta_nibble==13; 2 bytes if 14
--   Optional extended length: 1 byte if len_nibble==13; 2 bytes if 14
--   Option value: `length` bytes
-- Terminated by 0xFF (delta nibble = 15, which is otherwise reserved).
--
-- Returns an iterator.  Each call yields:
--   number   (absolute option number, uint)
--   value    (raw Lua string, may be "")
--   consumed (bytes consumed including header, extensions, value)
-- After the 0xFF end marker the iterator returns nil.
-- On malformed input the iterator raises an error string.
-- ---------------------------------------------------------------------------

-- Errors raised for a well-framed option block that breaks a numeric rule
-- start with this prefix, so a caller can tell "malformed" from "truncated".
M.MALFORMED_PREFIX = "malformed option: "

-- Decode one nibble field (delta or length).
-- Returns (value, extra_bytes_needed, error_string).
local function decode_nibble(nib, data, pos)
  if nib <= 12 then
    return nib, 0, nil
  elseif nib == 13 then
    if pos > #data then return nil, 0, "truncated extended byte" end
    return data:byte(pos) + 13, 1, nil
  elseif nib == 14 then
    if pos + 1 > #data then return nil, 0, "truncated extended uint16" end
    local hi = data:byte(pos)
    local lo = data:byte(pos + 1)
    local value = hi * 256 + lo + 269
    -- The field is a 16-bit quantity; an extension that carries it past
    -- 0xFFFF encodes nothing.
    if value > 0xFFFF then
      return nil, 0, M.MALFORMED_PREFIX .. "extended field exceeds 0xFFFF"
    end
    return value, 2, nil
  else -- 15
    return nil, 0, "reserved nibble 15 (expected 0xFF marker?)"
  end
end

-- Returns an iterator over options in `data` starting at byte `offset` (1-based).
-- `data` is the full packet as a Lua string.
-- The iterator stops at 0xFF or end of `data`.
function M.decode(data, offset)
  local pos = offset or 1
  local last_number = 0
  local finished = false

  return function()
    if finished then return nil end
    if pos > #data then return nil end  -- No end marker, treat as done

    local header = data:byte(pos)
    -- End-of-options marker
    if header == 0xFF then
      finished = true
      return nil
    end

    local start_pos = pos
    pos = pos + 1

    local delta_nib = (header >> 4) & 0x0F
    local len_nib   = header & 0x0F

    -- Delta nibble 15 without 0xFF is malformed (caught above for 0xFF)
    if delta_nib == 15 then
      error(M.MALFORMED_PREFIX .. "delta nibble=15 but byte is not 0xFF", 0)
    end

    -- Decode delta
    local delta, delta_ext, err = decode_nibble(delta_nib, data, pos)
    if err then error(err, 0) end
    pos = pos + delta_ext

    -- Decode length
    local len, len_ext
    if len_nib == 15 then
      error(M.MALFORMED_PREFIX .. "length nibble=15", 0)
    end
    len, len_ext, err = decode_nibble(len_nib, data, pos)
    if err then error(err, 0) end
    pos = pos + len_ext

    -- Read value
    if pos + len - 1 > #data then
      error("option value truncated: need " .. len .. " bytes, only " ..
            (#data - pos + 1) .. " remain", 0)
    end
    local value = data:sub(pos, pos + len - 1)
    pos = pos + len

    -- Option numbers are 16 bits; a running total past 0xFFFF names no
    -- option at all.
    local number = last_number + delta
    if number > 0xFFFF then
      error(string.format("%soption number %d exceeds 0xFFFF",
                          M.MALFORMED_PREFIX, number), 0)
    end
    last_number = number

    return number, value, (pos - start_pos)
  end
end

-- Scan an options block (starting at `offset` in `data`) and return the
-- total byte length consumed including the 0xFF terminator.
-- Raises on malformed input.
function M.scan_length(data, offset)
  local start = offset or 1
  local iter = M.decode(data, start)
  while iter() do end
  -- After the iterator is exhausted, find where 0xFF is
  -- Re-scan to find the exact end position
  local pos = start
  while pos <= #data do
    local b = data:byte(pos)
    if b == 0xFF then return pos - start + 1, true end
    -- Skip the option header + extensions + value
    local delta_nib = (b >> 4) & 0x0F
    local len_nib   = b & 0x0F
    pos = pos + 1
    -- Skip extended delta
    if delta_nib == 13 then pos = pos + 1
    elseif delta_nib == 14 then pos = pos + 2
    end
    -- Skip extended length
    local actual_len = len_nib
    if len_nib == 13 then
      actual_len = data:byte(pos) + 13; pos = pos + 1
    elseif len_nib == 14 then
      actual_len = data:byte(pos) * 256 + data:byte(pos+1) + 269; pos = pos + 2
    end
    pos = pos + actual_len
  end
  return #data - start + 1, false  -- no 0xFF marker; options consumed all remaining bytes
end

-- ---------------------------------------------------------------------------
-- Option attribute helpers (based on option number bit patterns)
-- Bit 0 set = Forwarding-Critical; bit 1 set = Dynamic; a static option with
-- bits 2 and 3 set (low nibble 12 or 13) = Delivery-Critical. The two
-- critical classes are independent, and a dynamic option is never
-- delivery-critical.
-- ---------------------------------------------------------------------------

function M.is_static(number)
  return (number & 2) == 0
end

function M.is_dynamic(number)
  return (number & 2) ~= 0
end

-- A repeater that does not recognize the option does not forward the frame.
function M.is_forwarding_critical(number)
  return (number & 1) ~= 0
end

-- An endpoint that does not recognize the option does not accept, deliver,
-- or acknowledge the frame.
function M.is_delivery_critical(number)
  return (number & 0xE) == 0xC
end

-- The classes an option number carries, as a label: "[Forwarding-Critical]",
-- "[Delivery-Critical]", both, or "" for a non-critical option.
function M.criticality_label(number)
  local classes = {}
  if M.is_forwarding_critical(number) then classes[#classes + 1] = "Forwarding-Critical" end
  if M.is_delivery_critical(number)   then classes[#classes + 1] = "Delivery-Critical" end
  if #classes == 0 then return "" end
  return "[" .. table.concat(classes, ", ") .. "]"
end

-- ---------------------------------------------------------------------------
-- Known MAC-layer option numbers
-- ---------------------------------------------------------------------------

M.OPT_FRAME_SIGNATURE  = 0   -- Non-Critical,        Static,  68 bytes
M.OPT_SOURCE_ROUTE     = 3   -- Forwarding-Critical, Dynamic, 0+ bytes
M.OPT_OP_CALLSIGN      = 4   -- Non-Critical,        Static,  ARNCE
M.OPT_MIN_RSSI         = 5   -- Forwarding-Critical, Static,  0-1 bytes
M.OPT_ROUTE_RETRY      = 6   -- Non-Critical,        Dynamic, 0 bytes (flag)
M.OPT_TRACE            = 7   -- Forwarding-Critical, Dynamic, 0+ bytes
M.OPT_ACK_MIC          = 8   -- Non-Critical,        Static,  4 bytes
M.OPT_MIN_SNR          = 9   -- Forwarding-Critical, Static,  0-1 bytes
M.OPT_REGION_CODE      = 11  -- Forwarding-Critical, Dynamic, 2 bytes
M.OPT_STATION_CALLSIGN = 15  -- Forwarding-Critical, Dynamic, ARNCE

-- A broadcast's Frame Signature: FRAME COUNTER(4, BE) ‖ SIG(64).
M.FRAME_SIGNATURE_LEN  = 68

M.KNOWN_OPTION_NAMES = {
  [0] = "Frame Signature",
  [1] = "Unassigned",
  [2] = "Unassigned",
  [3] = "Source Route",
  [4] = "Operator Callsign",
  [5] = "Min RSSI",
  [6] = "Route Retry",
  [7] = "Trace",
  [8] = "Ack MIC",
  [9] = "Min SNR",
  [10] = "Unassigned",
  [11] = "Region Code",
  [15] = "Station Callsign",
}

-- Options a sender MUST NOT include more than one of. Region Code is
-- deliberately absent: several may legitimately appear on one packet, and
-- the rule that a repeater must not *add* a second is about an action no
-- single frame records.
M.SINGLETON_OPTIONS = {
  [M.OPT_FRAME_SIGNATURE] = true,
  [M.OPT_SOURCE_ROUTE] = true,
  [M.OPT_MIN_RSSI]     = true,
  [M.OPT_ROUTE_RETRY]  = true,
  [M.OPT_TRACE]        = true,
  [M.OPT_MIN_SNR]      = true,
}

-- ---------------------------------------------------------------------------
-- Trace option value (packet-options.md § Trace Option Value)
--
--   Complete, with signal:  length a multiple of 4, records of
--                           RH(2) ‖ RSSI(1) ‖ SNR(1)
--   Complete, hints only:   0xFE, then 2-byte router hints (odd length)
--   Truncated, hints only:  0xFF, then 2-byte router hints (odd length),
--                           oldest dropped
--
-- Every other value is malformed: a length of 2 modulo 4, or an odd length
-- that begins with any other byte. Entries are most recent first.
-- ---------------------------------------------------------------------------

M.TRACE_SIGNAL     = "signal"
M.TRACE_HINTS_ONLY = "hints"
M.TRACE_TRUNCATED  = "truncated"

-- Parse a Trace value. Returns nil for a malformed one, otherwise
-- {form = ..., entries = {{hint = 2B, rssi = n|nil, snr = n|nil,
-- offset = 0-based offset of the entry within the value}, ...}}.
-- rssi is the raw byte (negative dBm), snr the signed byte (centibels).
function M.parse_trace(value)
  local len = #value
  local form, start, step
  if len % 4 == 0 then
    form, start, step = M.TRACE_SIGNAL, 1, 4
  elseif len % 2 == 0 then
    return nil
  elseif value:byte(1) == 0xFE then
    form, start, step = M.TRACE_HINTS_ONLY, 2, 2
  elseif value:byte(1) == 0xFF then
    form, start, step = M.TRACE_TRUNCATED, 2, 2
  else
    return nil
  end
  local entries = {}
  for pos = start, len, step do
    local entry = {hint = value:sub(pos, pos + 1), offset = pos - 1}
    if form == M.TRACE_SIGNAL then
      entry.rssi = value:byte(pos + 2)
      local snr = value:byte(pos + 3)
      entry.snr = snr >= 128 and snr - 256 or snr
    end
    entries[#entries + 1] = entry
  end
  return {form = form, entries = entries}
end

return M
