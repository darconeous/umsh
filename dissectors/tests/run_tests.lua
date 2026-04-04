-- Standalone Lua unit tests for UMSH Wireshark dissector modules.
-- Run with: lua run_tests.lua
-- Requires Lua 5.3+ (uses bitwise operators).
-- Does NOT require Wireshark.

-- ─────────────────────────────────────────────────────────────────────────────
-- Minimal Wireshark API stubs (just enough for modules to load without errors)
-- ─────────────────────────────────────────────────────────────────────────────
-- options.lua and keystore.lua have no Wireshark API dependencies.
-- crypto.lua requires luagcrypt; tests skip crypto-level checks when unavailable.

-- ─────────────────────────────────────────────────────────────────────────────
-- Module path setup
-- ─────────────────────────────────────────────────────────────────────────────
local _dir = debug.getinfo(1, "S").source:match("^@(.+/)")
              or debug.getinfo(1, "S").source:match("^@(.+\\)") or "./"
package.path = _dir .. "../umsh/?.lua;" .. package.path

-- ─────────────────────────────────────────────────────────────────────────────
-- Test harness
-- ─────────────────────────────────────────────────────────────────────────────
local passed = 0
local failed = 0

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02X", c:byte()) end))
end

local function from_hex(h)
  h = h:gsub("%s+", "")
  local b = {}
  for i = 1, #h, 2 do
    b[#b+1] = string.char(tonumber(h:sub(i, i+1), 16))
  end
  return table.concat(b)
end

local function check(name, got, expected)
  if got == expected then
    passed = passed + 1
    io.write(string.format("  PASS  %s\n", name))
  else
    failed = failed + 1
    io.write(string.format("  FAIL  %s\n       got:      %s\n       expected: %s\n",
                           name,
                           type(got)=="string" and hex(got) or tostring(got),
                           type(expected)=="string" and hex(expected) or tostring(expected)))
  end
end

local function section(title)
  io.write(string.format("\n── %s ──\n", title))
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Load modules
-- ─────────────────────────────────────────────────────────────────────────────
local options  = require("options")
local keystore = require("keystore")
local crypto_ok, crypto = pcall(require, "crypto")
if crypto_ok then
  keystore.set_crypto(crypto)
  io.write("crypto.lua loaded: luagcrypt " ..
           (crypto.available() and "AVAILABLE" or "NOT AVAILABLE") .. "\n")
else
  io.write("crypto.lua failed to load: " .. tostring(crypto) .. "\n")
  crypto = nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- ARNCE / HAM-64 decode tests
-- ─────────────────────────────────────────────────────────────────────────────
section("ARNCE decode")

-- "SJC" — from Example 7 Region Code option value 78 53
-- chunk = 0x7853 = 30803
-- c0 = floor(30803/1600)%40 = floor(19.25)%40 = 19 → S
-- c1 = floor(30803/40)%40  = floor(770.075)%40 = 770%40 = 10 → J
-- c2 = 30803%40 = 3 → C
check("ARNCE 0x7853 = SJC",  options.decode_arnce(from_hex("7853")), "SJC")

-- All-zero chunk = end of callsign → empty string
check("ARNCE 0x0000 = ''",   options.decode_arnce(from_hex("0000")), "")

-- Single letter A: c0=1, val = 1*1600+0*40+0 = 1600 = 0x0640
check("ARNCE 0x0640 = A",    options.decode_arnce(from_hex("0640")), "A")

-- ─────────────────────────────────────────────────────────────────────────────
-- Options codec tests
-- ─────────────────────────────────────────────────────────────────────────────
section("Options codec")

-- Example 7 options block: 12 78 53 10 FF
-- Option 1 (Region Code), delta=1, len=2, value=78 53
-- Option 2 (Trace Route), delta=1, len=0
-- End marker FF
local opts7 = from_hex("127853 10FF")

local nums, vals = {}, {}
for num, val, consumed in options.decode(opts7, 1) do
  nums[#nums+1] = num
  vals[#vals+1] = val
end
check("options Example7: count",    #nums, 2)
check("options Example7: opt[1] num", nums[1], 1)
check("options Example7: opt[1] val", vals[1], from_hex("7853"))
check("options Example7: opt[2] num", nums[2], 2)
check("options Example7: opt[2] val", vals[2], "")

-- scan_length should return 5 (3 + 1 + 1 for FF)
check("options Example7: scan_length", options.scan_length(opts7, 1), 5)

-- Static-option flag (bit 1 of option number)
check("is_static(1)",  options.is_static(1),  true)   -- Region Code = 1 = 0b001 → bit1=0 → static
check("is_static(2)",  options.is_static(2),  false)  -- Trace Route = 2 = 0b010 → bit1=1 → dynamic
check("is_critical(1)", options.is_critical(1), true)  -- bit0=1 → critical
check("is_critical(2)", options.is_critical(2), false) -- bit0=0 → non-critical

-- ─────────────────────────────────────────────────────────────────────────────
-- Keystore rebuild / lookup tests
-- ─────────────────────────────────────────────────────────────────────────────
section("Keystore")

local NODE_A_PUB = ("ED54A59FB1AC3A5123935136294 1B868E85A60E3D7B2485D828821DC7A69C279"):gsub("%s","")
local NODE_B_PUB = "6C28FD058C18C88C6CCE2AF981D2D11C851B123ED5B69B7876773ED099EA3F83"
local CHAN_KEY   = ("5A"):rep(64)

keystore.rebuild(
  NODE_A_PUB .. ":NodeA\n" .. NODE_B_PUB .. ":NodeB",
  "",  -- no privkeys
  CHAN_KEY .. ":TestChannel"
)

-- Hint lookups
check("lookup NodeA by hint",
      keystore.lookup_node(from_hex("ED54A5")), "NodeA")
check("lookup NodeB by hint",
      keystore.lookup_node(from_hex("6C28FD")), "NodeB")
check("lookup unknown hint",
      keystore.lookup_node(from_hex("000000")), nil)

-- Full-key lookup
check("lookup NodeA by full key",
      keystore.lookup_node_by_key(from_hex(NODE_A_PUB)), "NodeA")

-- ─────────────────────────────────────────────────────────────────────────────
-- Keystore rebuild_from_uat tests
-- ─────────────────────────────────────────────────────────────────────────────
section("Keystore UAT")

keystore.rebuild_from_uat({
  {"pubkey",  NODE_A_PUB, "UatNodeA"},
  {"pubkey",  NODE_B_PUB, "UatNodeB"},
  {"channel", CHAN_KEY,    "UatChannel"},
})

check("UAT lookup NodeA by hint",
      keystore.lookup_node(from_hex("ED54A5")), "UatNodeA")
check("UAT lookup NodeB by hint",
      keystore.lookup_node(from_hex("6C28FD")), "UatNodeB")
check("UAT lookup NodeA by full key",
      keystore.lookup_node_by_key(from_hex(NODE_A_PUB)), "UatNodeA")

-- Restore original keystore state for crypto tests
keystore.rebuild(
  NODE_A_PUB .. ":NodeA\n" .. NODE_B_PUB .. ":NodeB",
  "",
  CHAN_KEY .. ":TestChannel"
)

-- ─────────────────────────────────────────────────────────────────────────────
-- Pure-Lua Curve25519 tests (no luagcrypt required)
-- ─────────────────────────────────────────────────────────────────────────────
section("Curve25519 field arithmetic (pure Lua)")

if not crypto then
  io.write("  SKIP  (crypto module not loaded)\n")
else
  local NODE_A_PUB_BYTES = from_hex(NODE_A_PUB)
  local NODE_B_PUB_BYTES = from_hex(NODE_B_PUB)

  -- Ed25519 pubkey → X25519 pubkey via birational map u=(1+y)/(1-y)
  local ok_a, x25519_pub_a = pcall(crypto.ed25519_pub_to_x25519_pub, NODE_A_PUB_BYTES)
  if ok_a and x25519_pub_a then
    check("Node A Ed25519→X25519 pub",
          x25519_pub_a,
          from_hex("C2317931C46F852F8FA27414BDCB38427BC0F64403FC91625970AE5E90BB4C47"))
  else
    io.write("  FAIL  Node A Ed25519→X25519 (error: " .. tostring(x25519_pub_a) .. ")\n")
    failed = failed + 1
  end

  local ok_b, x25519_pub_b = pcall(crypto.ed25519_pub_to_x25519_pub, NODE_B_PUB_BYTES)
  if ok_b and x25519_pub_b then
    check("Node B Ed25519→X25519 pub",
          x25519_pub_b,
          from_hex("EFD41284A068945CFEB2AF55C3387B20D5D64DFD50F5A610FF02E74DDF5D315C"))
  else
    io.write("  FAIL  Node B Ed25519→X25519 (error: " .. tostring(x25519_pub_b) .. ")\n")
    failed = failed + 1
  end

  -- X25519 DH with known scalar (hardcoded, no SHA-512 needed)
  local known_scalar = from_hex(
    "704699DC8006747306EBB5B84383B885056F9335D18790AC82CAA132BDE7E14B")
  if ok_b and x25519_pub_b then
    local ok_s, ss = pcall(crypto.x25519, known_scalar, x25519_pub_b)
    if ok_s and ss then
      check("X25519 DH shared secret",
            ss, from_hex("5ADD834FC109FAD52F041C5AF84A7966526D364D1895AFFCD794E044F3A9DB14"))
    else
      io.write("  FAIL  X25519 DH (error: " .. tostring(ss) .. ")\n")
      failed = failed + 1
    end
  end

  -- X25519 pubkey from scalar * basepoint should match birational result
  if ok_a then
    local base = string.char(9) .. string.rep("\0", 31)
    local ok_xp, x25519_self = pcall(crypto.x25519, known_scalar, base)
    if ok_xp and x25519_self then
      check("X25519 scalar*base matches birational",
            x25519_self,
            from_hex("C2317931C46F852F8FA27414BDCB38427BC0F64403FC91625970AE5E90BB4C47"))
    else
      io.write("  FAIL  X25519 scalar*base (error: " .. tostring(x25519_self) .. ")\n")
      failed = failed + 1
    end
  end

  -- Seed → X25519 scalar (uses pure-Lua SHA-512, no luagcrypt needed)
  local NODE_A_SEED = from_hex(
    "1112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30")
  local ok_sc, scalar = pcall(crypto.ed25519_seed_to_x25519_scalar, NODE_A_SEED)
  if ok_sc and scalar then
    check("Seed→X25519 scalar (pure-Lua SHA-512)",
          scalar,
          from_hex("704699DC8006747306EBB5B84383B885056F9335D18790AC82CAA132BDE7E14B"))
  else
    io.write("  FAIL  Seed→scalar (error: " .. tostring(scalar) .. ")\n")
    failed = failed + 1
  end

  -- Full seed → X25519 pubkey (SHA-512 + Montgomery ladder, no luagcrypt)
  if ok_sc then
    local ok_xp2, xpub = pcall(crypto.x25519_pubkey_from_seed, NODE_A_SEED)
    if ok_xp2 and xpub then
      check("Seed→X25519 pubkey (pure Lua end-to-end)",
            xpub,
            from_hex("C2317931C46F852F8FA27414BDCB38427BC0F64403FC91625970AE5E90BB4C47"))
    else
      io.write("  FAIL  Seed→X25519 pubkey (error: " .. tostring(xpub) .. ")\n")
      failed = failed + 1
    end
  end

  -- HMAC-SHA256 test (RFC 4231 test case 2)
  local hmac_key  = from_hex("4a656665")  -- "Jefe"
  local hmac_data = "what do ya want for nothing?"
  local hmac_out  = crypto.hmac_sha256(hmac_key, hmac_data)
  check("HMAC-SHA256 (RFC 4231 #2)",
        hmac_out,
        from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))

  -- HKDF test: derive channel ID for all-5A key → B08D
  -- (HKDF requires AES backend for the guard, but the HMAC part is pure Lua.
  -- This test verifies the HMAC/HKDF chain; it will SKIP if no AES backend.)
  if crypto.available() then
    local chan_id = crypto.derive_channel_id(from_hex(CHAN_KEY))
    check("HKDF derive_channel_id(5A*32) = B08D", chan_id, from_hex("B08D"))
  else
    io.write("  SKIP  HKDF (no AES backend in test environment)\n")
  end
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Crypto tests (requires luagcrypt for HKDF, AES-CMAC, AES-CTR, SHA-512)
-- ─────────────────────────────────────────────────────────────────────────────
section("Crypto (requires luagcrypt)")

if not (crypto and crypto.available()) then
  io.write("  SKIP  (luagcrypt not available)\n")
else
  -- HKDF: channel ID derivation for all-5A channel key → B0 8D
  local chan_key_bytes = from_hex(CHAN_KEY)
  local chan_id = crypto.derive_channel_id(chan_key_bytes)
  check("derive_channel_id(5A*32) = B08D",
        chan_id, from_hex("B08D"))

  -- Channel keys derivation
  local dk = crypto.derive_channel_keys(chan_key_bytes)
  check("derive_channel_keys: got k_enc", dk and #dk.k_enc == 16, true)
  check("derive_channel_keys: got k_mic", dk and #dk.k_mic == 16, true)
  check("derive_channel_keys: channel_id", dk and dk.channel_id, from_hex("B08D"))

  -- Keystore channel entry should now have channel_id after rebuild+refresh
  keystore.refresh_channel_crypto()
  local ch = keystore.get_channel_by_id(from_hex("B08D"))
  check("keystore channel lookup by B08D",
        ch and ch.name, "TestChannel")
  check("keystore channel has derived_keys",
        ch and ch.derived_keys ~= nil, true)

  -- CTR IV construction
  local mic_16 = from_hex(("EA32F49109E8D4E60116 73C15B3184F0"):gsub("%s",""))
  local secinfo = from_hex(("E000000 02A"):gsub("%s",""))
  local iv = crypto.build_ctr_iv(mic_16, secinfo)
  -- 16-byte MIC → IV = MIC (SECINFO truncated away)
  check("build_ctr_iv(16B mic) = mic", iv, mic_16)

  local mic_4 = from_hex("EA32F491")
  local iv4 = crypto.build_ctr_iv(mic_4, secinfo)
  -- 4-byte MIC + 5-byte SECINFO = 9 bytes → pad to 16
  check("build_ctr_iv(4B mic) len=16", #iv4, 16)
  check("build_ctr_iv(4B mic) prefix", iv4:sub(1,4), mic_4)
  check("build_ctr_iv(4B mic) secinfo", iv4:sub(5,9), secinfo)
  check("build_ctr_iv(4B mic) padding", iv4:sub(10,16), string.rep("\0", 7))

  -- ── Pairwise key derivation ──
  local SHARED_SECRET = from_hex(
    "5ADD834FC109FAD52F041C5AF84A7966526D364D1895AFFCD794E044F3A9DB14")
  local pw = crypto.derive_pairwise_keys(SHARED_SECRET)
  check("pairwise keys: k_enc len=16", pw and #pw.k_enc, 16)
  check("pairwise keys: k_mic len=16", pw and #pw.k_mic, 16)

  -- ── Example 3: encrypted unicast verify+decrypt ──
  -- Packet: D0 6C28FD ED54A5 E0 0000002A 4FA084B292 EA32F49109E8D4E601 1673C15B3184F0
  -- FCF=D0, DST=6C28FD, SRC=ED54A5, SCF=E0 (enc, 16B MIC, no salt), FC=42
  -- Plaintext should be "Hello" = 48 65 6C 6C 6F
  local fcf_byte  = from_hex("D0")
  local dst_bytes = from_hex("6C28FD")
  local src_bytes = from_hex("ED54A5")
  local secinfo_e3 = from_hex(("E000000 02A"):gsub("%s",""))
  local body_e3   = from_hex("4FA084B292")
  local mic_e3    = from_hex(("EA32F49109E8D4E60116 73C15B3184F0"):gsub("%s",""))

  local aad_e3 = crypto.build_aad(fcf_byte, {}, dst_bytes, src_bytes, secinfo_e3)
  check("Example3 AAD len=12", #aad_e3, 12)  -- 1+3+3+5=12

  local pkt_e3 = {
    fcf_byte         = fcf_byte,
    static_opts      = {},
    dst_or_chan      = dst_bytes,
    src_bytes_or_nil = src_bytes,
    secinfo_raw      = secinfo_e3,
    body_bytes       = body_e3,
    mic_bytes        = mic_e3,
    is_encrypted     = true,
  }
  local plain_e3, status_e3 = crypto.verify_and_decrypt(pw, pkt_e3)
  check("Example3 MIC OK",         status_e3, "ok")
  check("Example3 plaintext=Hello", plain_e3, "Hello")

  -- ── Example 6: authenticated multicast (E=0) verify ──
  -- FCF=E0, CHANNEL=B08D, SCF=60 (E=0, 16B MIC), FC=3, SRC=ED54A5
  -- Payload=03 48656C6C6F, MIC=7C9A9C4BC0DDB496656A9DF15F5B9CC4
  local fcf_e6    = from_hex("E0")
  local chan_e6   = from_hex("B08D")
  local src_e6    = from_hex("ED54A5")
  local secinfo_e6 = from_hex(("60 00000003"):gsub("%s",""))
  local body_e6   = from_hex("0348656C6C6F")
  local mic_e6    = from_hex("7C9A9C4BC0DDB496656A9DF15F5B9CC4")

  local pkt_e6 = {
    fcf_byte         = fcf_e6,
    static_opts      = {},
    dst_or_chan      = chan_e6,
    src_bytes_or_nil = src_e6,  -- E=0: src in cleartext, included in AAD
    secinfo_raw      = secinfo_e6,
    body_bytes       = body_e6,
    mic_bytes        = mic_e6,
    is_encrypted     = false,
  }
  local plain_e6, status_e6 = crypto.verify_and_decrypt(dk, pkt_e6)
  check("Example6 MIC OK",    status_e6, "ok")
  check("Example6 body returned", plain_e6, body_e6)  -- unencrypted, body returned as-is

  -- ── Example 5: encrypted multicast (E=1) ──
  -- FCF=E0, CHANNEL=B08D, SCF=E0, FC=5
  -- body=9BB6F25EC7DA95D2 (encrypted SRC+payload), MIC=3035 87B001F217987A081CF56EDC8536
  local fcf_e5    = from_hex("E0")
  local secinfo_e5 = from_hex("E000000005")
  local body_e5   = from_hex("9BB6F25EC7DA95D2")
  local mic_e5    = from_hex("303587B001F217987A081CF56EDC8536")

  local pkt_e5 = {
    fcf_byte         = fcf_e5,
    static_opts      = {},
    dst_or_chan      = chan_e6,   -- same channel B08D
    src_bytes_or_nil = nil,      -- E=1: src in ciphertext
    secinfo_raw      = secinfo_e5,
    body_bytes       = body_e5,
    mic_bytes        = mic_e5,
    is_encrypted     = true,
  }
  local plain_e5, status_e5 = crypto.verify_and_decrypt(dk, pkt_e5)
  check("Example5 MIC OK", status_e5, "ok")
  -- Decrypted = SRC_hint(3) + "Hello"(5) = 8 bytes
  check("Example5 decrypted len=8", plain_e5 and #plain_e5, 8)
  check("Example5 decrypted SRC=ED54A5",
        plain_e5 and plain_e5:sub(1,3), from_hex("ED54A5"))
  check("Example5 decrypted payload=Hello",
        plain_e5 and plain_e5:sub(4), "Hello")

  -- ── NIST SP 800-38A AES-128-CTR test vectors (Section F.5.1) ──
  -- Non-zero IV — this is what broke under GcryptCipher:setctr().
  local nist_key = from_hex("2b7e151628aed2a6abf7158809cf4f3c")
  local nist_iv  = from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

  -- Verify AES-ECB primitive first: ECB(key, iv_block) = first keystream block
  local ecb_out = crypto.aes_ecb(nist_key, nist_iv)
  check("NIST AES-ECB(key, ctr0)",
        ecb_out, from_hex("ec8cdf7398607cb0f2d21675ea9ea1e4"))

  -- Single-block CTR encrypt (plaintext → ciphertext)
  local nist_pt1 = from_hex("6bc1bee22e409f96e93d7e117393172a")
  local nist_ct1 = crypto.aes_ctr(nist_key, nist_iv, nist_pt1)
  check("NIST AES-CTR block 1 encrypt",
        nist_ct1, from_hex("874d6191b620e3261bef6864990db6ce"))

  -- Single-block CTR decrypt (ciphertext → plaintext)
  local nist_dec1 = crypto.aes_ctr(nist_key, nist_iv, from_hex("874d6191b620e3261bef6864990db6ce"))
  check("NIST AES-CTR block 1 decrypt",
        nist_dec1, nist_pt1)

  -- Multi-block (4 blocks = 64 bytes) — tests counter increment across blocks
  local nist_pt_all = from_hex(
    "6bc1bee22e409f96e93d7e117393172a"
 .. "ae2d8a571e03ac9c9eb76fac45af8e51"
 .. "30c81c46a35ce411e5fbc1191a0a52ef"
 .. "f69f2445df4f9b17ad2b417be66c3710")
  local nist_ct_all = from_hex(
    "874d6191b620e3261bef6864990db6ce"
 .. "9806f66b7970fdff8617187bb9fffdff"
 .. "5ae4df3edbd5d35e5b4f09020db03eab"
 .. "1e031dda2fbe03d1792170a0f3009cee")
  local ctr_enc = crypto.aes_ctr(nist_key, nist_iv, nist_pt_all)
  check("NIST AES-CTR 4-block encrypt", ctr_enc, nist_ct_all)
  local ctr_dec = crypto.aes_ctr(nist_key, nist_iv, nist_ct_all)
  check("NIST AES-CTR 4-block decrypt", ctr_dec, nist_pt_all)

  -- ── RFC 4493 AES-CMAC test vectors ──
  local cmac_key = from_hex("2b7e151628aed2a6abf7158809cf4f3c")
  -- Example 1: empty message
  local cmac_empty = crypto.aes_cmac(cmac_key, {""})
  check("RFC4493 AES-CMAC Example 1 (empty)",
        cmac_empty, from_hex("bb1d6929e95937287fa37d129b756746"))
  -- Example 3: 64-byte message
  local cmac_m64 = from_hex(
    "6bc1bee22e409f96e93d7e117393172a"
 .. "ae2d8a571e03ac9c9eb76fac45af8e51"
 .. "30c81c46a35ce411e5fbc1191a0a52ef"
 .. "f69f2445df4f9b17ad2b417be66c3710")
  local cmac_64 = crypto.aes_cmac(cmac_key, {cmac_m64})
  check("RFC4493 AES-CMAC Example 3 (64B)",
        cmac_64, from_hex("51f0bebf7e3b9d92fc49741779363cfe"))

  -- ── Ed25519 → X25519 conversion and ECDH (intermediate test vectors) ──
  local NODE_A_SEED = from_hex(
    "1112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30")
  local NODE_A_PUB_BYTES = from_hex(NODE_A_PUB)
  local NODE_B_PUB_BYTES = from_hex(NODE_B_PUB)

  -- Step 1: seed → X25519 scalar (SHA-512, take first 32 bytes, clamp)
  local ok_x, x25519_scalar = pcall(crypto.ed25519_seed_to_x25519_scalar, NODE_A_SEED)
  if ok_x and x25519_scalar then
    check("X25519 scalar from seed",
          x25519_scalar,
          from_hex("704699DC8006747306EBB5B84383B885056F9335D18790AC82CAA132BDE7E14B"))
  else
    io.write("  SKIP  X25519 scalar (error: " .. tostring(x25519_scalar) .. ")\n")
  end

  -- Step 2: Ed25519 pubkey → X25519 pubkey via birational map u=(1+y)/(1-y)
  local ok_a, x25519_pub_a = pcall(crypto.ed25519_pub_to_x25519_pub, NODE_A_PUB_BYTES)
  if ok_a and x25519_pub_a then
    check("Node A Ed25519→X25519 pub",
          x25519_pub_a,
          from_hex("C2317931C46F852F8FA27414BDCB38427BC0F64403FC91625970AE5E90BB4C47"))
  else
    io.write("  SKIP  Node A Ed25519→X25519 (error: " .. tostring(x25519_pub_a) .. ")\n")
  end

  local ok_b, x25519_pub_b = pcall(crypto.ed25519_pub_to_x25519_pub, NODE_B_PUB_BYTES)
  if ok_b and x25519_pub_b then
    check("Node B Ed25519→X25519 pub",
          x25519_pub_b,
          from_hex("EFD41284A068945CFEB2AF55C3387B20D5D64DFD50F5A610FF02E74DDF5D315C"))
  else
    io.write("  SKIP  Node B Ed25519→X25519 (error: " .. tostring(x25519_pub_b) .. ")\n")
  end

  -- Step 3: X25519 DH → shared secret
  if ok_x and x25519_scalar and ok_b and x25519_pub_b then
    local ok_s, ss = pcall(crypto.x25519, x25519_scalar, x25519_pub_b)
    if ok_s and ss then
      check("ECDH shared secret",
            ss, from_hex("5ADD834FC109FAD52F041C5AF84A7966526D364D1895AFFCD794E044F3A9DB14"))
    else
      io.write("  SKIP  ECDH (x25519 error: " .. tostring(ss) .. ")\n")
    end
  else
    io.write("  SKIP  ECDH (missing scalar or peer pubkey)\n")
  end

  -- Step 4: X25519 pubkey from seed (scalar * basepoint) should match step 2
  if ok_x then
    local ok_xp, x25519_self = pcall(crypto.x25519_pubkey_from_seed, NODE_A_SEED)
    if ok_xp and x25519_self then
      check("X25519 pubkey from seed matches birational",
            x25519_self,
            from_hex("C2317931C46F852F8FA27414BDCB38427BC0F64403FC91625970AE5E90BB4C47"))
    else
      io.write("  SKIP  X25519 pubkey from seed (error: " .. tostring(x25519_self) .. ")\n")
    end
  end
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Results
-- ─────────────────────────────────────────────────────────────────────────────
io.write(string.format(
  "\n─── Results: %d passed, %d failed ───\n", passed, failed))
os.exit(failed > 0 and 1 or 0)
