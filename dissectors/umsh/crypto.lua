-- UMSH cryptographic operations
-- Symmetric crypto: layered backend (luagcrypt > Wireshark GcryptCipher + pure-Lua SHA)
-- Curve25519: pure-Lua field arithmetic for Ed25519→X25519 and ECDH

local M = {}

-- ---------------------------------------------------------------------------
-- Byte-string helpers
-- ---------------------------------------------------------------------------

local function xor_bytes(a, b)
  assert(#a == #b, "xor_bytes: lengths differ")
  local out = {}
  for i = 1, #a do
    out[i] = string.char(a:byte(i) ~ b:byte(i))
  end
  return table.concat(out)
end

local function uint16_be(n)
  return string.char((n >> 8) & 0xFF, n & 0xFF)
end

local function uint32_be(n)
  return string.char((n >> 24) & 0xFF, (n >> 16) & 0xFF,
                     (n >>  8) & 0xFF,  n         & 0xFF)
end

-- ---------------------------------------------------------------------------
-- Backend detection — primitives: sha256, sha512, aes_ecb, aes_ctr
-- Priority: luagcrypt > Wireshark GcryptCipher + pure-Lua SHA > nothing
-- ---------------------------------------------------------------------------

-- Pure-Lua SHA-256/SHA-512 (always available, Lua 5.3+)
local sha2 = require("sha2")

-- Low-level primitives (set by backend detection below)
local sha256_fn  = sha2.sha256   -- always available (pure Lua)
local sha512_fn  = sha2.sha512   -- always available (pure Lua)
local aes_ecb_fn = nil            -- set by backend
local aes_ctr_fn = nil            -- set by backend

local gcrypt_ok, gcrypt = pcall(require, "luagcrypt")
local gcrypt_err = nil
if not gcrypt_ok then
  gcrypt_err = tostring(gcrypt)
  gcrypt = nil
end

if gcrypt then
  -- ── Backend A: luagcrypt (full native crypto) ──
  aes_ecb_fn = function(key, block)
    local c = gcrypt.cipher.open(gcrypt.CIPHER_AES128,
                                  gcrypt.CIPHER_MODE_ECB, 0)
    c:setkey(key)
    return c:encrypt(block)
  end
  aes_ctr_fn = function(key, iv, data)
    local c = gcrypt.cipher.open(gcrypt.CIPHER_AES128,
                                  gcrypt.CIPHER_MODE_CTR, 0)
    c:setkey(key); c:setctr(iv)
    return c:decrypt(data)
  end
elseif GcryptCipher then
  -- ── Backend B: Wireshark 4.6+ native GcryptCipher ──
  -- ByteArray conversion helpers
  local function str_to_ba(s)
    local hex = s:gsub(".", function(c) return string.format("%02x", c:byte()) end)
    return ByteArray.new(hex)
  end

  aes_ecb_fn = function(key, block)
    local c = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0)
    c:setkey(str_to_ba(key))
    local ba = str_to_ba(block)
    c:encrypt(ba)
    return ba:raw()
  end
  -- GcryptCipher CTR mode has a broken setctr binding in some Wireshark
  -- versions, so implement CTR manually using ECB (which works correctly).
  aes_ctr_fn = function(key, iv, data)
    local counter = {iv:byte(1, 16)}
    local out = {}
    local pos = 1
    while pos <= #data do
      local block = string.char(table.unpack(counter))
      local ks = aes_ecb_fn(key, block)
      local take = math.min(16, #data - pos + 1)
      for i = 1, take do
        out[#out + 1] = string.char(data:byte(pos) ~ ks:byte(i))
        pos = pos + 1
      end
      -- Increment counter (big-endian)
      for j = 16, 1, -1 do
        counter[j] = (counter[j] + 1) & 0xFF
        if counter[j] ~= 0 then break end
      end
    end
    return table.concat(out)
  end
end

local _has_aes = (aes_ecb_fn ~= nil)
function M.available() return _has_aes end
function M.crypto_error()
  if _has_aes then return nil end
  return gcrypt_err or "no AES backend (need luagcrypt or Wireshark 4.6+)"
end

-- ---------------------------------------------------------------------------
-- HMAC-SHA256 (pure Lua, built on sha256_fn)
-- ---------------------------------------------------------------------------

function M.hmac_sha256(key, data)
  local block_size = 64
  if #key > block_size then key = sha256_fn(key) end
  if #key < block_size then key = key .. string.rep("\0", block_size - #key) end
  local ipad, opad = {}, {}
  for i = 1, block_size do
    ipad[i] = string.char(key:byte(i) ~ 0x36)
    opad[i] = string.char(key:byte(i) ~ 0x5c)
  end
  return sha256_fn(table.concat(opad) .. sha256_fn(table.concat(ipad) .. data))
end

-- ---------------------------------------------------------------------------
-- HKDF-SHA256 (RFC 5869)
-- ---------------------------------------------------------------------------

function M.hkdf(ikm, salt, info, out_len)
  if not _has_aes then return nil, "no crypto" end
  local prk = M.hmac_sha256(salt, ikm)
  local t_prev = ""
  local okm_parts = {}
  local i = 1
  local produced = 0
  while produced < out_len do
    t_prev = M.hmac_sha256(prk, t_prev .. info .. string.char(i))
    okm_parts[#okm_parts + 1] = t_prev
    produced = produced + #t_prev
    i = i + 1
  end
  return table.concat(okm_parts):sub(1, out_len)
end

-- ---------------------------------------------------------------------------
-- AES-CMAC (RFC 4493, built on aes_ecb_fn)
-- ---------------------------------------------------------------------------

-- Double a 16-byte block in GF(2^128) with Rb = 0x87
local function cmac_dbl(block)
  local carry = (block:byte(1) >> 7) & 1
  local r = {}
  for i = 1, 15 do
    r[i] = ((block:byte(i) << 1) | (block:byte(i + 1) >> 7)) & 0xFF
  end
  r[16] = (block:byte(16) << 1) & 0xFF
  if carry == 1 then r[16] = r[16] ~ 0x87 end
  return string.char(table.unpack(r))
end

function M.aes_cmac(key, data_chunks)
  if not _has_aes then return nil, "no crypto" end
  -- Subkey generation
  local L  = aes_ecb_fn(key, string.rep("\0", 16))
  local K1 = cmac_dbl(L)
  local K2 = cmac_dbl(K1)

  local data = table.concat(data_chunks)
  local n = math.ceil(#data / 16)
  if n == 0 then n = 1 end

  local last_complete = (#data > 0) and (#data % 16 == 0)
  local last_block
  if last_complete then
    last_block = xor_bytes(data:sub((n - 1) * 16 + 1, n * 16), K1)
  else
    local partial = data:sub((n - 1) * 16 + 1)
    local padded  = partial .. "\x80" .. string.rep("\0", 16 - #partial - 1)
    last_block = xor_bytes(padded, K2)
  end

  local X = string.rep("\0", 16)
  for i = 1, n - 1 do
    X = aes_ecb_fn(key, xor_bytes(X, data:sub((i - 1) * 16 + 1, i * 16)))
  end
  return aes_ecb_fn(key, xor_bytes(X, last_block))
end

-- ---------------------------------------------------------------------------
-- AES-128-CTR / AES-128-ECB — thin wrappers around backend
-- ---------------------------------------------------------------------------

function M.aes_ctr(key, iv, data)
  if not _has_aes then return nil, "no crypto" end
  return aes_ctr_fn(key, iv, data)
end

function M.aes_ecb(key, block_16)
  if not _has_aes then return nil, "no crypto" end
  return aes_ecb_fn(key, block_16)
end

-- ---------------------------------------------------------------------------
-- CTR IV construction
-- IV = truncate_or_pad_to_16(MIC || SECINFO)
-- ---------------------------------------------------------------------------

function M.build_ctr_iv(mic_bytes, secinfo_bytes)
  local combined = mic_bytes .. secinfo_bytes
  if #combined >= 16 then
    return combined:sub(1, 16)
  else
    return combined .. string.rep("\0", 16 - #combined)
  end
end

-- ---------------------------------------------------------------------------
-- AAD construction
-- fcf_byte:             1-byte string (raw FCF)
-- has_opts:             boolean — true if O flag was set in FCF
-- static_opts:          ordered list of {number=N, value=bytes_str}
-- dst_or_chan_bytes:     2-byte channel OR 3-byte dst hint
-- src_bytes_or_nil:     3-byte hint, 32-byte key, or nil (when encrypted)
-- secinfo_bytes:        5-or-7 byte string
-- ---------------------------------------------------------------------------

function M.build_aad(fcf_byte, has_opts, static_opts, dst_or_chan_bytes,
                     src_bytes_or_nil, secinfo_bytes)
  local parts = {fcf_byte}
  -- NOTE: The reference implementation's feed_aad early-returns when no
  -- options field is present (O=0), producing AAD = FCF-only.  Match that
  -- behaviour here so that MICs verify against real packets.
  if not has_opts then
    return table.concat(parts)
  end
  for _, opt in ipairs(static_opts or {}) do
    parts[#parts+1] = uint16_be(opt.number)
    parts[#parts+1] = uint16_be(#opt.value)
    parts[#parts+1] = opt.value
  end
  parts[#parts+1] = dst_or_chan_bytes
  if src_bytes_or_nil then
    parts[#parts+1] = src_bytes_or_nil
  end
  parts[#parts+1] = secinfo_bytes
  return table.concat(parts)
end

-- ---------------------------------------------------------------------------
-- Key derivation
-- ---------------------------------------------------------------------------

function M.derive_channel_id(channel_key)
  -- channel_id = first 2 bytes of HKDF(ikm=channel_key, salt="UMSH-CHAN-ID", info="", L=2)
  local okm, err = M.hkdf(channel_key, "UMSH-CHAN-ID", "", 2)
  if not okm then return nil, err end
  return okm
end

function M.derive_channel_keys(channel_key)
  local channel_id, err = M.derive_channel_id(channel_key)
  if not channel_id then return nil, err end
  local info = "UMSH-MCAST-V1" .. channel_id
  local okm, err2 = M.hkdf(channel_key, "UMSH-MCAST-SALT", info, 32)
  if not okm then return nil, err2 end
  return {
    k_enc      = okm:sub(1,  16),
    k_mic      = okm:sub(17, 32),
    channel_id = channel_id,
  }
end

function M.derive_pairwise_keys(shared_secret)
  local okm, err = M.hkdf(shared_secret, "UMSH-PAIRWISE-SALT", "UMSH-UNICAST-V1", 32)
  if not okm then return nil, err end
  return {k_enc = okm:sub(1, 16), k_mic = okm:sub(17, 32)}
end

function M.derive_blind_keys(pairwise_keys, channel_keys)
  return {
    k_enc = xor_bytes(pairwise_keys.k_enc, channel_keys.k_enc),
    k_mic = xor_bytes(pairwise_keys.k_mic, channel_keys.k_mic),
  }
end

-- ---------------------------------------------------------------------------
-- MIC size decode (SCF bits 6-5)
-- ---------------------------------------------------------------------------

local MIC_SIZES = {[0]=4, [1]=8, [2]=12, [3]=16}
function M.mic_size_bytes(scf_mic_code)
  return MIC_SIZES[scf_mic_code] or 16
end

-- ---------------------------------------------------------------------------
-- Packet verify + decrypt (shared core logic)
-- keys:       {k_enc, k_mic}
-- pkt:        {fcf_byte, static_opts, dst_or_chan, src_bytes_or_nil,
--              secinfo_raw, scf, body_bytes, mic_bytes, is_encrypted}
-- Returns plaintext string on success, nil + reason on failure.
-- ---------------------------------------------------------------------------

function M.verify_and_decrypt(keys, pkt)
  local mic_len  = #pkt.mic_bytes
  local has_opts = (pkt.fcf_byte:byte(1) & 0x02) ~= 0
  local aad      = M.build_aad(pkt.fcf_byte, has_opts, pkt.static_opts,
                                pkt.dst_or_chan, pkt.src_bytes_or_nil,
                                pkt.secinfo_raw)

  -- SIV-style: MAC covers the plaintext, not the ciphertext.
  -- When encrypted, decrypt first, then verify MIC on the plaintext.
  local body = pkt.body_bytes
  if pkt.is_encrypted then
    local iv = M.build_ctr_iv(pkt.mic_bytes, pkt.secinfo_raw)
    local plain, e = M.aes_ctr(keys.k_enc, iv, body)
    if not plain then return nil, "ctr failed: " .. (e or "?") end
    body = plain
  end

  local full_cmac = M.aes_cmac(keys.k_mic, {aad, body})
  if not full_cmac then return nil, "cmac failed" end

  if full_cmac:sub(1, mic_len) ~= pkt.mic_bytes then
    return nil, "mic_mismatch"
  end

  return body, "ok"
end

-- ---------------------------------------------------------------------------
-- Phase A: Multicast try-decrypt
-- Tries each channel in `channel_list` whose channel_id matches.
-- Returns plaintext, src_bytes_or_nil, channel_entry, or nil + status.
-- For E=1, the first (3 or 32) bytes of the decrypted body are the source.
-- full_src_flag: true if S flag set (32-byte source), false for 3-byte hint
-- ---------------------------------------------------------------------------

function M.try_decrypt_multicast(pkt_info, channel_list, full_src_flag)
  if not _has_aes then return nil, nil, nil, "no crypto" end
  for _, ch in ipairs(channel_list) do
    if ch.channel_id == pkt_info.channel_id and ch.derived_keys then
      local dk = ch.derived_keys
      local status
      local plain
      plain, status = M.verify_and_decrypt(dk, pkt_info)
      if plain then
        -- Peel off the SRC field from the front of the decrypted body
        local src_len = full_src_flag and 32 or 3
        if #plain < src_len then
          return nil, nil, ch, "decrypted too short for src"
        end
        local src_bytes = plain:sub(1, src_len)
        local payload   = plain:sub(src_len + 1)
        return payload, src_bytes, ch, "ok"
      end
    end
  end
  return nil, nil, nil, "no matching channel key"
end

-- ---------------------------------------------------------------------------
-- Phase A: Blind-unicast address block decrypt
-- Decrypts ENC_DST_SRC using channel k_enc with MIC as the IV.
-- Returns dst_hint (3 bytes), src (3 or 32 bytes), or nil + status.
-- ---------------------------------------------------------------------------

function M.decrypt_blind_addr(channel_keys, mic_bytes, enc_addr_bytes, full_src_flag, secinfo_bytes)
  if not _has_aes then return nil, nil, "no crypto" end
  -- Per spec: IV = truncate_or_pad_to_16(MIC || SECINFO)
  -- secinfo_bytes is optional; passing "" is equivalent for 16-byte MIC (IV = MIC).
  local iv = M.build_ctr_iv(mic_bytes, secinfo_bytes or "")
  local plain, err = M.aes_ctr(channel_keys.k_enc, iv, enc_addr_bytes)
  if not plain then return nil, nil, "ctr failed: " .. (err or "?") end
  local src_len = full_src_flag and 32 or 3
  if #plain < 3 + src_len then
    return nil, nil, "decrypted addr too short"
  end
  local dst_hint = plain:sub(1, 3)
  local src      = plain:sub(4, 3 + src_len)
  return dst_hint, src, "ok"
end

-- ---------------------------------------------------------------------------
-- Phase B: Ed25519 seed → X25519 private scalar
-- h = SHA-512(seed); scalar = h[1..32] with clamping
-- ---------------------------------------------------------------------------

function M.ed25519_seed_to_x25519_scalar(seed_32bytes)
  local digest = sha512_fn(seed_32bytes)   -- 64 bytes
  -- Take first 32 bytes as the scalar
  local b = {digest:byte(1, 32)}
  -- Clamp (little-endian)
  b[1]  = b[1]  & 0xF8
  b[32] = (b[32] & 0x7F) | 0x40
  return string.char(table.unpack(b))
end

-- ---------------------------------------------------------------------------
-- Phase B: Pure-Lua Curve25519 / Ed25519 field arithmetic
--
-- Field: GF(2^255 - 19), 10-limb representation with alternating 26/25-bit
-- limbs (TweetNaCl-style). Limb widths: 26,25,26,25,26,25,26,25,26,25.
-- Multiplication uses Lua floats (53-bit mantissa) for intermediate products
-- to avoid 64-bit integer overflow.
-- ---------------------------------------------------------------------------

local LIMB_BITS = {[0]=26,25,26,25,26,25,26,25,26,25}
local LIMB_MASK = {}
for i = 0, 9 do LIMB_MASK[i] = (1 << LIMB_BITS[i]) - 1 end

-- Load 32-byte little-endian string into 10-limb field element
local function fe_from_bytes(s)
  assert(#s == 32)
  local b = {s:byte(1, 32)}
  local h = {}
  -- Bit cursor
  local bitpos = 0
  for i = 0, 9 do
    local bits = LIMB_BITS[i]
    local v = 0
    for j = 0, bits - 1 do
      local bi = bitpos + j
      local byte_idx = (bi >> 3) + 1
      local bit_idx  = bi & 7
      if ((b[byte_idx] or 0) >> bit_idx & 1) == 1 then
        v = v | (1 << j)
      end
    end
    h[i] = v
    bitpos = bitpos + bits
  end
  return h
end

-- Store 10-limb field element to 32-byte little-endian string
local function fe_to_bytes(h)
  -- Copy and fully reduce
  local q = {}
  for i = 0, 9 do q[i] = h[i] end
  -- Carry chain (3 rounds to ensure full reduction)
  for _ = 1, 3 do
    for i = 0, 8 do
      local c = q[i] >> LIMB_BITS[i]
      q[i+1] = q[i+1] + c
      q[i]   = q[i] & LIMB_MASK[i]
    end
    local c = q[9] >> 25
    q[0] = q[0] + c * 19
    q[9] = q[9] & LIMB_MASK[9]
  end
  -- Final carry
  local c = q[0] >> 26; q[1] = q[1] + c; q[0] = q[0] & LIMB_MASK[0]

  -- Conditional subtract of p
  -- p in 10-limb: {0x3FFFFED,0x1FFFFFF,0x3FFFFFF,0x1FFFFFF,0x3FFFFFF,
  --                0x1FFFFFF,0x3FFFFFF,0x1FFFFFF,0x3FFFFFF,0x1FFFFFF}
  local p = {[0]=0x3FFFFED,0x1FFFFFF,0x3FFFFFF,0x1FFFFFF,0x3FFFFFF,
                  0x1FFFFFF,0x3FFFFFF,0x1FFFFFF,0x3FFFFFF,0x1FFFFFF}
  local t = {}
  for i = 0, 9 do t[i] = q[i] - p[i] end
  for i = 0, 8 do
    if t[i] < 0 then
      t[i+1] = t[i+1] - 1
      t[i] = t[i] + (1 << LIMB_BITS[i])
    end
  end
  if t[9] >= 0 then
    for i = 0, 9 do q[i] = t[i] & LIMB_MASK[i] end
  end

  -- Pack limbs into 256 bits → 32 bytes (little-endian)
  local bits = {}
  local bitpos = 0
  for i = 0, 9 do
    for j = 0, LIMB_BITS[i] - 1 do
      bits[bitpos + j] = (q[i] >> j) & 1
    end
    bitpos = bitpos + LIMB_BITS[i]
  end
  local bytes = {}
  for i = 0, 31 do
    local v = 0
    for j = 0, 7 do
      v = v | ((bits[i*8+j] or 0) << j)
    end
    bytes[i+1] = v
  end
  return string.char(table.unpack(bytes))
end

local function fe_add(a, b)
  local r = {}
  for i = 0, 9 do r[i] = a[i] + b[i] end
  return r
end

local function fe_sub(a, b)
  -- Add 2p to stay positive. 2p limbs:
  -- {0x7FFFFDA,0x3FFFFFE,0x7FFFFFE,0x3FFFFFE,0x7FFFFFE,
  --  0x3FFFFFE,0x7FFFFFE,0x3FFFFFE,0x7FFFFFE,0x3FFFFFE}
  local tp = {[0]=0x7FFFFDA,0x3FFFFFE,0x7FFFFFE,0x3FFFFFE,0x7FFFFFE,
                   0x3FFFFFE,0x7FFFFFE,0x3FFFFFE,0x7FFFFFE,0x3FFFFFE}
  local r = {}
  for i = 0, 9 do r[i] = a[i] - b[i] + tp[i] end
  return r
end

local function fe_carry(h)
  for i = 0, 8 do
    local c = h[i] >> LIMB_BITS[i]
    h[i+1] = h[i+1] + c
    h[i]   = h[i] & LIMB_MASK[i]
  end
  local c = h[9] >> 25
  h[0] = h[0] + c * 19
  h[9] = h[9] & LIMB_MASK[9]
  c = h[0] >> 26
  h[1] = h[1] + c
  h[0] = h[0] & LIMB_MASK[0]
end

local function fe_mul(a, b)
  -- 10x10 schoolbook multiply with reduction mod 2^255-19.
  -- In the alternating 26/25-bit representation, when both i and j are odd,
  -- offset(i)+offset(j) = offset(i+j)+1, so the product needs an extra *2.
  -- For wraparound (i+j >= 10), the base factor is 19 (from 2^255 ≡ 19),
  -- becoming 38 when both indices are odd.
  local c = {}
  for i = 0, 9 do c[i] = 0 end
  for i = 0, 9 do
    local ai = a[i]
    local i_odd = (i & 1) == 1
    for j = 0, 9 do
      local k = i + j
      local both_odd = i_odd and ((j & 1) == 1)
      if k < 10 then
        if both_odd then
          c[k] = c[k] + ai * b[j] * 2
        else
          c[k] = c[k] + ai * b[j]
        end
      else
        if both_odd then
          c[k-10] = c[k-10] + ai * b[j] * 38
        else
          c[k-10] = c[k-10] + ai * b[j] * 19
        end
      end
    end
  end
  fe_carry(c)
  fe_carry(c)
  return c
end

local function fe_sq(a)
  return fe_mul(a, a)
end

-- Compute a^((p-5)/8) = a^(2^252 - 3) for use in square root / inversion
local function fe_pow22523(a)
  local t0, t1, t2

  t0 = fe_sq(a)
  t1 = fe_sq(t0); t1 = fe_sq(t1)
  t1 = fe_mul(a, t1)
  t0 = fe_mul(t0, t1)
  t0 = fe_sq(t0)
  t0 = fe_mul(t1, t0)
  t1 = fe_sq(t0)
  for _ = 1,  4 do t1 = fe_sq(t1) end
  t1 = fe_mul(t0, t1)
  t2 = fe_sq(t1)
  for _ = 1,  9 do t2 = fe_sq(t2) end
  t2 = fe_mul(t1, t2)
  local t3 = fe_sq(t2)
  for _ = 1, 19 do t3 = fe_sq(t3) end
  t2 = fe_mul(t2, t3)
  for _ = 1, 10 do t2 = fe_sq(t2) end
  t1 = fe_mul(t1, t2)
  t2 = fe_sq(t1)
  for _ = 1, 49 do t2 = fe_sq(t2) end
  t2 = fe_mul(t1, t2)
  t3 = fe_sq(t2)
  for _ = 1, 99 do t3 = fe_sq(t3) end
  t2 = fe_mul(t2, t3)
  for _ = 1, 50 do t2 = fe_sq(t2) end
  t1 = fe_mul(t1, t2)
  t1 = fe_sq(t1)
  t1 = fe_sq(t1)
  return fe_mul(a, t1)
end

-- Field inversion: a^(p-2) via Fermat's little theorem
local function fe_invert(a)
  local t0, t1, t2, t3

  t0 = fe_sq(a)
  t1 = fe_sq(t0); t1 = fe_sq(t1)
  t1 = fe_mul(a, t1)
  t0 = fe_mul(t0, t1)
  t2 = fe_sq(t0)
  t1 = fe_mul(t1, t2)
  t2 = fe_sq(t1)
  for _ = 1, 4  do t2 = fe_sq(t2) end
  t1 = fe_mul(t1, t2)

  t2 = fe_sq(t1)
  for _ = 1,  9 do t2 = fe_sq(t2) end
  t2 = fe_mul(t1, t2)
  t3 = fe_sq(t2)
  for _ = 1, 19 do t3 = fe_sq(t3) end
  t2 = fe_mul(t2, t3)
  for _ = 1, 10 do t2 = fe_sq(t2) end
  t1 = fe_mul(t1, t2)

  t2 = fe_sq(t1)
  for _ = 1, 49 do t2 = fe_sq(t2) end
  t2 = fe_mul(t1, t2)
  t3 = fe_sq(t2)
  for _ = 1, 99 do t3 = fe_sq(t3) end
  t2 = fe_mul(t2, t3)
  for _ = 1, 50 do t2 = fe_sq(t2) end
  t1 = fe_mul(t1, t2)
  for _ = 1,  5 do t1 = fe_sq(t1) end
  return fe_mul(t0, t1)
end

local FE_ONE  = fe_from_bytes(string.char(1) .. string.rep("\0", 31))
local FE_ZERO = fe_from_bytes(string.rep("\0", 32))

-- ---------------------------------------------------------------------------
-- Ed25519 compressed public key → X25519 Montgomery u-coordinate
-- Formula: u = (1 + y) / (1 - y) mod p
-- Input: 32-byte LE Ed25519 compressed point (sign bit of x in bit 255)
-- Output: 32-byte LE X25519 u-coordinate
-- ---------------------------------------------------------------------------

function M.ed25519_pub_to_x25519_pub(ed_pub_32bytes)
  if not ed_pub_32bytes or #ed_pub_32bytes ~= 32 then
    return nil, "invalid pubkey length"
  end
  -- Clear the sign bit (bit 255) to extract y
  local b = {ed_pub_32bytes:byte(1, 32)}
  b[32] = b[32] & 0x7F

  local y = fe_from_bytes(string.char(table.unpack(b)))
  local one = FE_ONE

  -- u = (1+y) / (1-y)
  local num   = fe_add(one, y)          -- 1 + y
  local denom = fe_sub(one, y)          -- 1 - y
  local inv   = fe_invert(denom)
  local u     = fe_mul(num, inv)

  fe_carry(u)
  fe_carry(u)
  return fe_to_bytes(u)
end

-- ---------------------------------------------------------------------------
-- X25519 Diffie-Hellman (Montgomery ladder)
-- scalar: 32-byte LE clamped scalar
-- u_in:   32-byte LE u-coordinate of base point
-- Returns 32-byte LE shared secret.
-- ---------------------------------------------------------------------------

function M.x25519(scalar_bytes, u_bytes)
  -- Load and clamp scalar
  local k = {scalar_bytes:byte(1, 32)}
  k[1]  = k[1]  & 0xF8
  k[32] = (k[32] & 0x7F) | 0x40

  -- Load u, clear high bit
  local u_b = {u_bytes:byte(1, 32)}
  u_b[32] = u_b[32] & 0x7F
  local u = fe_from_bytes(string.char(table.unpack(u_b)))

  -- Montgomery ladder
  local function fe_copy(src)
    local d = {}; for i = 0, 9 do d[i] = src[i] end; return d
  end
  local x_1 = fe_copy(u)
  local x_2 = fe_copy(FE_ONE)
  local z_2 = fe_copy(FE_ZERO)
  local x_3 = fe_copy(u)
  local z_3 = fe_copy(FE_ONE)

  -- A24 = 121665
  local A24 = fe_from_bytes(string.char(121665 & 0xFF, (121665 >> 8) & 0xFF,
                            (121665 >> 16) & 0xFF, 0,0,0,0,0,0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))

  local swap = 0

  -- Bit 255 is always 0 after clamping; bit 254 is always 1.
  for bit_pos = 254, 0, -1 do
    local byte_idx = bit_pos >> 3   -- 0-indexed
    local bit_idx  = bit_pos & 7
    local k_bit    = (k[byte_idx + 1] >> bit_idx) & 1

    swap = swap ~ k_bit
    -- Conditional swap (branchless in real code; Lua uses branching)
    if swap == 1 then
      x_2, x_3 = x_3, x_2
      z_2, z_3 = z_3, z_2
    end
    swap = k_bit

    -- Montgomery step
    local A  = fe_add(x_2, z_2)
    local AA = fe_sq(A)
    local B  = fe_sub(x_2, z_2)
    local BB = fe_sq(B)
    local E  = fe_sub(AA, BB)
    local C  = fe_add(x_3, z_3)
    local D  = fe_sub(x_3, z_3)
    local DA = fe_mul(D, A)
    local CB = fe_mul(C, B)
    x_3 = fe_sq(fe_add(DA, CB))
    z_3 = fe_mul(x_1, fe_sq(fe_sub(DA, CB)))
    x_2 = fe_mul(AA, BB)
    z_2 = fe_mul(E, fe_add(AA, fe_mul(A24, E)))

    fe_carry(x_2); fe_carry(z_2)
    fe_carry(x_3); fe_carry(z_3)
  end

  -- Final conditional swap
  if swap == 1 then x_2, x_3 = x_3, x_2; z_2, z_3 = z_3, z_2 end

  local result = fe_mul(x_2, fe_invert(z_2))
  fe_carry(result); fe_carry(result)
  return fe_to_bytes(result)
end

-- ---------------------------------------------------------------------------
-- Ed25519 public key from seed (requires gcrypt SHA-512)
-- Used by keystore to precompute pubkeys for display.
-- NOTE: This computes only the scalar, not the full Ed25519 scalar mult.
-- For the dissector, we only need the X25519 public key for ECDH;
-- the Ed25519 public key displayed in the packet is taken directly from
-- the packet bytes when S=1 is set.
-- ---------------------------------------------------------------------------

-- Placeholder: computes X25519 public key from seed for node identification.
-- The "Ed25519 public key" stored in nodes is the actual Ed25519 pubkey;
-- this derives the X25519 pubkey for ECDH. For display annotations we use
-- the full key directly.
function M.x25519_pubkey_from_seed(seed_32bytes)
  local scalar, err = M.ed25519_seed_to_x25519_scalar(seed_32bytes)
  if not scalar then return nil, err end
  -- X25519 base point u-coordinate = 9
  local base = string.char(9) .. string.rep("\0", 31)
  return M.x25519(scalar, base)
end

-- ---------------------------------------------------------------------------
-- Phase B: Unicast try-decrypt
-- pkt_info: {fcf_byte, static_opts, dst_hint (3B), src_hint_or_key,
--            secinfo_raw, is_encrypted, body_bytes, mic_bytes}
-- full_src: whether src is 32-byte key (true) or 3-byte hint (false)
-- Returns plaintext, or nil + status.
-- ---------------------------------------------------------------------------

function M.try_decrypt_unicast(pkt_info, privkey_list, full_src_flag)
  if not _has_aes then return nil, "no crypto" end

  -- Build the verify_and_decrypt packet table once
  local vpkt = {
    fcf_byte         = pkt_info.fcf_byte,
    static_opts      = pkt_info.static_opts,
    dst_or_chan      = pkt_info.dst_hint,
    src_bytes_or_nil = pkt_info.src_bytes,
    secinfo_raw      = pkt_info.secinfo_raw,
    body_bytes       = pkt_info.body_bytes,
    mic_bytes        = pkt_info.mic_bytes,
    is_encrypted     = pkt_info.is_encrypted,
  }

  -- Helper: try ECDH with a given X25519 scalar and peer X25519 pubkey
  local function try_with_x25519(x25519_priv, x25519_peer_pub)
    local shared_secret = M.x25519(x25519_priv, x25519_peer_pub)
    local keys, kerr = M.derive_pairwise_keys(shared_secret)
    if not keys then return nil end
    local plain, status = M.verify_and_decrypt(keys, vpkt)
    if plain then return plain, keys end
    return nil
  end

  for idx, pk in ipairs(privkey_list) do
    local x25519_priv = M.ed25519_seed_to_x25519_scalar(pk.seed_bytes)
    if not x25519_priv then goto continue end

    -- Path 1: peer's Ed25519 pubkey is known (S=1 or keystore lookup)
    local peer_ed_pubkey
    if full_src_flag and #pkt_info.src_bytes == 32 then
      peer_ed_pubkey = pkt_info.src_bytes
    elseif pkt_info.src_pubkey_from_keystore then
      peer_ed_pubkey = pkt_info.src_pubkey_from_keystore
    end

    if peer_ed_pubkey then
      local x25519_peer = M.ed25519_pub_to_x25519_pub(peer_ed_pubkey)
      if x25519_peer then
        local plain, keys = try_with_x25519(x25519_priv, x25519_peer)
        if plain then return plain, "ok", keys end
      end
    else
      -- Path 2: peer's Ed25519 pubkey unknown — try all other privkeys as
      -- potential peer using their precomputed X25519 pubkeys.
      for idx2, pk2 in ipairs(privkey_list) do
        if pk2 ~= pk and pk2.x25519_pubkey then
          local ok_try, plain, keys = pcall(try_with_x25519, x25519_priv, pk2.x25519_pubkey)
          if ok_try and plain then
            return plain, "ok", keys
          end
        end
      end
    end

    ::continue::
  end
  return nil, "no matching private key"
end

-- ---------------------------------------------------------------------------
-- Phase B: Blind unicast try-decrypt
-- Returns payload_plaintext, dst_hint, src, or nil + status.
-- ---------------------------------------------------------------------------

function M.try_decrypt_blind_unicast(pkt_info, privkey_list, channel_list, full_src_flag)
  if not _has_aes then return nil, nil, nil, "no crypto" end

  -- First find the channel
  local channel_entry
  for _, ch in ipairs(channel_list) do
    if ch.channel_id == pkt_info.channel_id then
      channel_entry = ch; break
    end
  end
  if not channel_entry or not channel_entry.derived_keys then
    return nil, nil, nil, "no matching channel"
  end

  -- Phase 1: decrypt address block using channel K_enc
  local dst_hint, src_bytes, addr_err = M.decrypt_blind_addr(
    channel_entry.derived_keys, pkt_info.mic_bytes,
    pkt_info.enc_addr_bytes, full_src_flag, pkt_info.secinfo_raw)
  if not dst_hint then
    return nil, nil, nil, "addr decrypt failed: " .. (addr_err or "?")
  end

  -- Phase 2: try each privkey as potential destination, with peer derived from
  -- decrypted src (full key if S=1) or from other privkeys' X25519 pubkeys.
  local vpkt = {
    fcf_byte         = pkt_info.fcf_byte,
    static_opts      = pkt_info.static_opts,
    dst_or_chan      = pkt_info.channel_id,
    src_bytes_or_nil = nil,  -- src was encrypted; not in AAD
    secinfo_raw      = pkt_info.secinfo_raw,
    body_bytes       = pkt_info.body_bytes,
    mic_bytes        = pkt_info.mic_bytes,
    is_encrypted     = pkt_info.is_encrypted,
  }

  local function try_blind_ecdh(x25519_priv, x25519_peer_pub)
    local shared_secret = M.x25519(x25519_priv, x25519_peer_pub)
    local pairwise_keys = M.derive_pairwise_keys(shared_secret)
    if not pairwise_keys then return nil end
    local blind_keys = M.derive_blind_keys(pairwise_keys, channel_entry.derived_keys)
    local plain, status = M.verify_and_decrypt(blind_keys, vpkt)
    if plain then return plain end
    return nil
  end

  for _, pk in ipairs(privkey_list) do
    local x25519_priv = M.ed25519_seed_to_x25519_scalar(pk.seed_bytes)
    if not x25519_priv then goto continue end

    -- If decrypted src is a full Ed25519 pubkey, convert and try
    if full_src_flag and #src_bytes == 32 then
      local x25519_peer = M.ed25519_pub_to_x25519_pub(src_bytes)
      if x25519_peer then
        local plain = try_blind_ecdh(x25519_priv, x25519_peer)
        if plain then return plain, dst_hint, src_bytes, "ok" end
      end
    else
      -- Try all other privkeys as potential peer
      for _, pk2 in ipairs(privkey_list) do
        if pk2 ~= pk and pk2.x25519_pubkey then
          local plain = try_blind_ecdh(x25519_priv, pk2.x25519_pubkey)
          if plain then return plain, dst_hint, src_bytes, "ok" end
        end
      end
    end

    ::continue::
  end
  return nil, dst_hint, src_bytes, "no matching private key for dst"
end

return M
