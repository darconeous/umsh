-- UMSH key and node-name registry
-- Parses Wireshark preference strings; precomputes channel IDs when crypto is available.

local M = {}

local base58 = require("base58")

-- Forward reference to crypto module (set after crypto.lua is loaded)
local crypto_ref = nil
function M.set_crypto(c) crypto_ref = c end

-- ---------------------------------------------------------------------------
-- Internal state
-- ---------------------------------------------------------------------------

local nodes    = {}   -- list of {pubkey_hex, pubkey_bytes, hint3_bytes, name}
local privkeys = {}   -- list of {seed_bytes, seed_hex, name, x25519_pubkey}
local channels = {}   -- list of {raw_key_bytes, name, channel_id, derived_keys}

-- ---------------------------------------------------------------------------
-- Hex helpers
-- ---------------------------------------------------------------------------

local function hex_to_bytes(hex_str)
  hex_str = hex_str:gsub("%s+", ""):lower()
  if #hex_str % 2 ~= 0 then return nil, "odd hex length" end
  local bytes = {}
  for i = 1, #hex_str, 2 do
    local byte = tonumber(hex_str:sub(i, i+1), 16)
    if not byte then return nil, "invalid hex character at position " .. i end
    bytes[#bytes+1] = string.char(byte)
  end
  return table.concat(bytes)
end

local function bytes_to_hex(bytes_str)
  return (bytes_str:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end

-- ---------------------------------------------------------------------------
-- Channel key derivation
-- ---------------------------------------------------------------------------

-- Named channels: key = HKDF-Extract(salt="UMSH-CHANNEL-V1", ikm=UTF-8(name))
-- This matches the spec formula for well-known named channels like "umsh:cs:public"
local function derive_named_channel_key(name)
  if not crypto_ref then return nil end
  -- Per spec: HMAC-SHA256(key="UMSH-CHANNEL-V1", data=name)
  return crypto_ref.hmac_sha256("UMSH-CHANNEL-V1", name)
end

local function compute_channel_entry(raw_key_bytes, name, builtin)
  local entry = {
    raw_key_bytes = raw_key_bytes,
    name          = name or "",
    channel_id    = nil,
    derived_keys  = nil,
    -- Set for the well-known channels, whose names carry protocol rules a
    -- 2-byte channel ID cannot be trusted to identify on its own.
    builtin       = builtin,
  }
  if crypto_ref then
    local ok, cid = pcall(crypto_ref.derive_channel_id, raw_key_bytes)
    if ok then
      entry.channel_id = cid
      local ok2, dk = pcall(crypto_ref.derive_channel_keys, raw_key_bytes)
      if ok2 then entry.derived_keys = dk end
    end
  end
  return entry
end

-- ---------------------------------------------------------------------------
-- Parsing helpers
-- ---------------------------------------------------------------------------

-- Decode a 32-byte key written in any of the forms the rest of the project
-- hands out, so an address copied from umshctl, the phone, or this
-- dissector's own display can be pasted straight in.
--
--   64 hex characters                  the historical form
--   44 base58 characters               what an address looks like everywhere else
--   umsh:n:<44>  / umsh:ck:<44>        node and channel-key URIs
--
-- Hex and base58 are told apart by length, the same rule PublicKey::FromStr
-- uses in crates/umsh-core/src/packet.rs. `scheme` names the URI prefix this
-- kind of key accepts, if any; a URI of any other kind is refused rather
-- than quietly read as the wrong sort of key.
local function parse_key_material(str, scheme)
  if not str then return nil end
  str = str:gsub("%s+", "")
  if str == "" then return nil end

  local uri_scheme, body = str:match("^umsh:(%a+):(.+)$")
  if uri_scheme then
    if uri_scheme ~= scheme then return nil end
    -- URIs may carry `?k=v` parameters; the key is what precedes them.
    str = body:match("^([^?]+)") or body
  end

  if #str == 64 and str:match("^[0-9a-fA-F]+$") then
    return hex_to_bytes(str)
  end
  if #str == base58.ENCODED_LEN then
    return base58.decode32(str)
  end
  return nil
end

-- Split a configuration line into its key part and its label.
--
-- The key may itself be a URI containing colons, so the split cannot simply
-- be at the first one.
local function split_key_label(line)
  local uri, label = line:match("^(umsh:%a+:[^:]+):(.*)$")
  if uri then return uri, label end
  if line:match("^umsh:%a+:") then return line, "" end

  local key, lbl = line:match("^([^:]+):(.*)$")
  if key then return key, lbl end
  return line, ""
end

-- Iterate the non-blank, non-comment lines of a preference string, yielding
-- the key text and its label.
local function parse_key_name_lines(pref_str)
  if not pref_str or pref_str == "" then return {} end
  local result = {}
  for line in (pref_str .. "\n"):gmatch("([^\n]*)\n") do
    line = line:match("^%s*(.-)%s*$")  -- trim
    if line ~= "" and line:sub(1,1) ~= "#" then
      local key, name = split_key_label(line)
      result[#result+1] = {key=key, name=(name or ""):match("^%s*(.-)%s*$")}
    end
  end
  return result
end

-- Parse a multi-line channel preference string. Lines are either a key in
-- any form parse_key_material accepts, or a channel *name* to derive from:
--   <key>:<label>                           raw 32-byte channel key
--   umsh:ck:<44-base58>:<label>             channel-key URI
--   umsh:cs:<channel-name>:<display-name>   named channel derivation
--   umsh:cs:<channel-name>                  named channel, no display name
local function parse_channel_lines(pref_str)
  if not pref_str or pref_str == "" then return {} end
  local result = {}
  for line in (pref_str .. "\n"):gmatch("([^\n]*)\n") do
    line = line:match("^%s*(.-)%s*$")
    if line ~= "" and line:sub(1,1) ~= "#" then
      -- Named channel: umsh:cs:<name> or umsh:cs:<name>:<display>
      local chan_name, display = line:match("^umsh:cs:([^:]+):(.+)$")
      if not chan_name then
        chan_name = line:match("^umsh:cs:(.+)$")
        display   = chan_name
      end
      if chan_name then
        result[#result+1] = {kind="named", chan_name=chan_name,
                             name=(display or chan_name):match("^%s*(.-)%s*$")}
      else
        local key, name = split_key_label(line)
        local bytes = parse_key_material(key, "ck")
        if bytes then
          result[#result+1] = {kind="raw", bytes=bytes,
                               name=(name or ""):match("^%s*(.-)%s*$")}
        end
      end
    end
  end
  return result
end

-- ---------------------------------------------------------------------------
-- Public: rebuild all tables from preference strings
-- ---------------------------------------------------------------------------

function M.rebuild(node_pref, privkey_pref, channel_pref)
  nodes    = {}
  privkeys = {}
  channels = {}

  -- Node name mappings (public key : name)
  for _, item in ipairs(parse_key_name_lines(node_pref or "")) do
    local b = parse_key_material(item.key, "n")
    if b then
      nodes[#nodes+1] = {
        pubkey_hex   = bytes_to_hex(b),
        pubkey_bytes = b,
        hint3_bytes  = b:sub(1, 3),
        name         = item.name,
      }
    end
  end

  -- Private keys (Ed25519 seed : name)
  -- We store only seeds; X25519 public keys are derived for cross-pair decryption.
  for _, item in ipairs(parse_key_name_lines(privkey_pref or "")) do
    local b = parse_key_material(item.key)
    if b then
      local x25519_pub = nil
      if crypto_ref then
        local ok, p = pcall(crypto_ref.x25519_pubkey_from_seed, b)
        if ok then x25519_pub = p end
      end
      privkeys[#privkeys+1] = {
        seed_bytes    = b,
        seed_hex      = bytes_to_hex(b),
        name          = item.name,
        x25519_pubkey = x25519_pub,
      }
    end
  end

  -- Channel keys
  for _, item in ipairs(parse_channel_lines(channel_pref or "")) do
    if item.kind == "raw" then
      channels[#channels+1] = compute_channel_entry(item.bytes, item.name)
    elseif item.kind == "named" then
      if crypto_ref then
        local key = derive_named_channel_key(item.chan_name)
        if key then
          channels[#channels+1] = compute_channel_entry(key, item.name)
        end
      end
    end
  end
end

-- ---------------------------------------------------------------------------
-- Public: rebuild from UAT table (Pref.uat rows: {type, key, label})
-- ---------------------------------------------------------------------------

function M.rebuild_from_uat(uat_rows)
  nodes    = {}
  privkeys = {}
  channels = {}

  if not uat_rows then return end
  for _, row in ipairs(uat_rows) do
    local ktype = (row[1] or ""):match("^%s*(.-)%s*$"):lower()
    local key   = (row[2] or ""):match("^%s*(.-)%s*$")
    local label = (row[3] or ""):match("^%s*(.-)%s*$")

    if ktype == "pubkey" or ktype == "node" then
      local b = parse_key_material(key, "n")
      if b then
        nodes[#nodes+1] = {
          pubkey_hex   = bytes_to_hex(b),
          pubkey_bytes = b,
          hint3_bytes  = b:sub(1, 3),
          name         = label,
        }
      end

    elseif ktype == "privkey" then
      local b = parse_key_material(key)
      if b then
        local x25519_pub = nil
        if crypto_ref then
          local ok, p = pcall(crypto_ref.x25519_pubkey_from_seed, b)
          if ok then x25519_pub = p end
        end
        privkeys[#privkeys+1] = {
          seed_bytes    = b,
          seed_hex      = bytes_to_hex(b),
          name          = label,
          x25519_pubkey = x25519_pub,
        }
      end

    elseif ktype == "channel" then
      -- Named channel: umsh:cs:<name>
      local chan_name = key:match("^umsh:cs:(.+)$")
      if chan_name then
        if crypto_ref then
          local ck = derive_named_channel_key(chan_name)
          if ck then
            channels[#channels+1] = compute_channel_entry(ck, label ~= "" and label or chan_name)
          end
        end
      else
        local b = parse_key_material(key, "ck")
        if b then
          channels[#channels+1] = compute_channel_entry(b, label)
        end
      end
    end
  end
end

-- ---------------------------------------------------------------------------
-- Well-known channels
--
-- `public` and `emergency` are derived from names the spec fixes, so their
-- keys are known to everyone by construction. Adding them unconditionally
-- means emergency traffic verifies and public traffic decrypts with no
-- configuration at all — which is the point of a channel whose key is
-- public knowledge.
-- ---------------------------------------------------------------------------

local BUILTIN_CHANNELS = {"public", "emergency"}

function M.add_builtin_channels()
  if not crypto_ref then return end
  for _, chan_name in ipairs(BUILTIN_CHANNELS) do
    local key = derive_named_channel_key(chan_name)
    if key then
      local existing
      for _, ch in ipairs(channels) do
        if ch.raw_key_bytes == key then existing = ch; break end
      end
      if existing then
        -- Already configured by hand: keep the operator's own label, but
        -- tag it so the rules attached to the name still apply.
        existing.builtin = chan_name
      else
        channels[#channels+1] = compute_channel_entry(key, chan_name, chan_name)
      end
    end
  end
end

-- Recompute channel IDs/keys when crypto becomes available (called after crypto loads)
function M.refresh_channel_crypto()
  for i, entry in ipairs(channels) do
    if not entry.channel_id and crypto_ref then
      local ok, cid = pcall(crypto_ref.derive_channel_id, entry.raw_key_bytes)
      if ok then
        entry.channel_id = cid
        local ok2, dk = pcall(crypto_ref.derive_channel_keys, entry.raw_key_bytes)
        if ok2 then entry.derived_keys = dk end
      end
    end
  end
  -- Also compute X25519 pubkeys for privkeys that are missing them
  for _, pk in ipairs(privkeys) do
    if not pk.x25519_pubkey and crypto_ref then
      local ok, pub = pcall(crypto_ref.x25519_pubkey_from_seed, pk.seed_bytes)
      if ok then pk.x25519_pubkey = pub end
    end
  end
end

-- ---------------------------------------------------------------------------
-- Public: lookups
-- ---------------------------------------------------------------------------

-- Find a node by its 3-byte hint prefix.
-- Returns name (string), pubkey_bytes (string or nil), or nil, nil if not found.
function M.lookup_node(hint3_bytes)
  for _, n in ipairs(nodes) do
    if n.hint3_bytes == hint3_bytes then
      return n.name, n.pubkey_bytes
    end
  end
  return nil, nil
end

-- Find a node by its full 32-byte public key.
function M.lookup_node_by_key(pubkey_bytes)
  for _, n in ipairs(nodes) do
    if n.pubkey_bytes == pubkey_bytes then
      return n.name
    end
  end
  return nil
end

-- Find a channel entry by its 2-byte channel ID.
function M.get_channel_by_id(channel_id_bytes)
  for _, ch in ipairs(channels) do
    if ch.channel_id == channel_id_bytes then
      return ch
    end
  end
  return nil
end

-- Return all private key entries (for trying unicast decryption).
function M.get_all_privkeys()
  return privkeys
end

-- Return all channel entries (for trying multicast/blind-unicast decryption).
function M.get_all_channels()
  return channels
end

-- ---------------------------------------------------------------------------
-- Key-file loading (optional secondary source, same format as preferences)
-- ---------------------------------------------------------------------------

function M.load_keyfile(path)
  if not path or path == "" then return end
  local f, err = io.open(path, "r")
  if not f then return end  -- Silently ignore missing files

  local node_lines, priv_lines, chan_lines = {}, {}, {}
  local section = nil

  for line in f:lines() do
    line = line:match("^%s*(.-)%s*$")
    if line == "" or line:sub(1,1) == "#" then
      -- skip
    elseif line:match("^%[nodes%]") then section = "nodes"
    elseif line:match("^%[privkeys%]") then section = "privkeys"
    elseif line:match("^%[channels%]") then section = "channels"
    elseif section == "nodes"    then node_lines[#node_lines+1] = line
    elseif section == "privkeys" then priv_lines[#priv_lines+1] = line
    elseif section == "channels" then chan_lines[#chan_lines+1] = line
    else
      -- Flat file without sections: anything that reads as a key is a node.
      local key = split_key_label(line)
      if parse_key_material(key, "n") then
        node_lines[#node_lines+1] = line
      end
    end
  end
  f:close()

  -- Merge into existing tables by calling rebuild with concatenated strings
  local function join(t) return table.concat(t, "\n") end
  M.rebuild(join(node_lines), join(priv_lines), join(chan_lines))
end

-- ---------------------------------------------------------------------------
-- Utility: format a bytes string as colon-separated hex (for display)
-- ---------------------------------------------------------------------------
function M.bytes_to_display_hex(bytes_str)
  local parts = {}
  for i = 1, #bytes_str do
    parts[i] = string.format("%02X", bytes_str:byte(i))
  end
  return table.concat(parts, ":")
end

return M
