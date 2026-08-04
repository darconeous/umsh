-- Canonical UMSH address presentation.
-- Reference: crates/umsh-core/src/base58.rs, docs/protocol/src/addressing.md

local M = {}

-- Base58 digit alphabet (Bitcoin variant: no 0, O, I or l).
local ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

-- A 32-byte address is always exactly this many digits, left-padded with the
-- zero digit "1", so character positions are stable across all key values.
M.ENCODED_LEN = 44

-- Encode a 32-byte string as exactly ENCODED_LEN base58 digits.
-- Digits are produced least-significant first by repeated division of the
-- byte array by 58, so they fill the output right to left.
function M.encode32(bytes)
  if type(bytes) ~= "string" or #bytes ~= 32 then return nil end

  local num = {}
  for i = 1, 32 do num[i] = bytes:byte(i) end

  local out = {}
  for slot = M.ENCODED_LEN, 1, -1 do
    local rem = 0
    for i = 1, 32 do
      local acc = (rem << 8) | num[i]
      num[i] = acc // 58
      rem    = acc % 58
    end
    out[slot] = ALPHABET:sub(rem + 1, rem + 1)
  end
  return table.concat(out)
end

-- Digit → value, built once from the alphabet above.
local DIGIT_VALUE = {}
for i = 1, #ALPHABET do DIGIT_VALUE[ALPHABET:sub(i, i)] = i - 1 end

-- Decode exactly ENCODED_LEN base58 digits back into 32 bytes.
-- Returns nil on a wrong length, an out-of-alphabet character, or a value
-- too large to fit — the alphabet excludes 0/O/I/l precisely so that the
-- characters people confuse are never silently accepted as something else.
function M.decode32(digits)
  if type(digits) ~= "string" or #digits ~= M.ENCODED_LEN then return nil end

  local num = {}
  for i = 1, 32 do num[i] = 0 end

  for i = 1, #digits do
    local carry = DIGIT_VALUE[digits:sub(i, i)]
    if not carry then return nil end
    for j = 32, 1, -1 do
      local acc = num[j] * 58 + carry
      num[j] = acc & 0xFF
      carry  = acc >> 8
    end
    if carry ~= 0 then return nil end
  end

  local out = {}
  for i = 1, 32 do out[i] = string.char(num[i]) end
  return table.concat(out)
end

-- Star-truncated rendering of a hint (a leading prefix of a public key).
--
-- The hint is encoded twice — padded to 32 bytes with 0x00 and with 0xFF —
-- and the common prefix of the two encodings is emitted, up to `budget`
-- characters, followed by a single `*` at the first divergence. Every
-- character emitted before the star is one that every key matching the hint
-- shares, so the rendering never claims more than the hint proves.
function M.hint(bytes, budget)
  if type(bytes) ~= "string" or #bytes == 0 or #bytes > 32 then return nil end

  local pad_len = 32 - #bytes
  local lo = M.encode32(bytes .. string.rep("\x00", pad_len))
  local hi = M.encode32(bytes .. string.rep("\xFF", pad_len))
  if not lo or not hi then return nil end

  local out = {}
  for i = 1, budget do
    local a = lo:sub(i, i)
    if a ~= hi:sub(i, i) then
      out[#out + 1] = "*"
      return table.concat(out)
    end
    out[#out + 1] = a
  end
  return table.concat(out)
end

-- A 3-byte node hint renders within 4 characters, a 2-byte router hint
-- within 3. The budgets come from the addressing chapter.
function M.node_hint(bytes)   return M.hint(bytes, 4) end
function M.router_hint(bytes) return M.hint(bytes, 3) end

-- Colon-separated hex, the byte form shown alongside a canonical hint.
function M.hex_bytes(bytes)
  local parts = {}
  for i = 1, #bytes do parts[i] = string.format("%02X", bytes:byte(i)) end
  return table.concat(parts, ":")
end

-- The rendering used everywhere a hint appears: canonical form first, with
-- the bytes it was read from in parentheses.
function M.node_hint_full(bytes)
  local canon = M.node_hint(bytes)
  if not canon then return M.hex_bytes(bytes) end
  return canon .. " (" .. M.hex_bytes(bytes) .. ")"
end

function M.router_hint_full(bytes)
  local canon = M.router_hint(bytes)
  if not canon then return M.hex_bytes(bytes) end
  return canon .. " (" .. M.hex_bytes(bytes) .. ")"
end

-- A full 32-byte key needs no byte form: the 44 digits are the address.
function M.key_full(bytes)
  return M.encode32(bytes) or M.hex_bytes(bytes)
end

-- Whichever of the two applies, chosen by length. Used where a source
-- address is 3 or 32 bytes depending on the S flag.
function M.addr(bytes)
  if #bytes == 32 then return M.key_full(bytes) end
  if #bytes == 2  then return M.router_hint_full(bytes) end
  return M.node_hint_full(bytes)
end

return M
