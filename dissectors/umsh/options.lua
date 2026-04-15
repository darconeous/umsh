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
    return hi * 256 + lo + 269, 2, nil
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
      error("malformed option: delta nibble=15 but byte is not 0xFF")
    end

    -- Decode delta
    local delta, delta_ext, err = decode_nibble(delta_nib, data, pos)
    if err then error("option delta: " .. err) end
    pos = pos + delta_ext

    -- Decode length
    local len, len_ext
    if len_nib == 15 then
      error("malformed option: length nibble=15")
    end
    len, len_ext, err = decode_nibble(len_nib, data, pos)
    if err then error("option length: " .. err) end
    pos = pos + len_ext

    -- Read value
    if pos + len - 1 > #data then
      error("option value truncated: need " .. len .. " bytes, only " ..
            (#data - pos + 1) .. " remain")
    end
    local value = data:sub(pos, pos + len - 1)
    pos = pos + len

    local number = last_number + delta
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
    if b == 0xFF then return pos - start + 1 end
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
  error("options block missing 0xFF terminator")
end

-- ---------------------------------------------------------------------------
-- Option attribute helpers (based on option number bit patterns)
-- Bit 1 set = Dynamic; Bit 0 set = Critical
-- ---------------------------------------------------------------------------

function M.is_static(number)
  return (number & 2) == 0
end

function M.is_critical(number)
  return (number & 1) ~= 0
end

-- ---------------------------------------------------------------------------
-- Known MAC-layer option numbers
-- ---------------------------------------------------------------------------

M.OPT_REGION_CODE      = 11  -- Critical, Dynamic, 2 bytes
M.OPT_TRACE_ROUTE      = 2   -- Non-Critical, Dynamic
M.OPT_SOURCE_ROUTE     = 3   -- Critical, Dynamic
M.OPT_OP_CALLSIGN      = 4   -- Non-Critical, Static, ARNCE
M.OPT_MIN_RSSI         = 5   -- Critical, Static,  0-1 bytes
M.OPT_STATION_CALLSIGN = 7   -- Critical, Dynamic, ARNCE
M.OPT_MIN_SNR          = 9   -- Critical, Static,  0-1 bytes

M.KNOWN_OPTION_NAMES = {
  [2] = "Trace Route",
  [3] = "Source Route",
  [4] = "Operator Callsign",
  [5] = "Min RSSI",
  [7] = "Station Callsign",
  [9] = "Min SNR",
  [11] = "Region Code",
}

return M
