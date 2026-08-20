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

-- Two-letter short codes pad with NUL, which terminates the reading:
-- "US" = 21*1600 + 19*40 = 0x8638, "WA" = 23*1600 + 1*40 = 0x8FE8.
check("ARNCE 0x8638 = US",   options.decode_arnce(from_hex("8638")), "US")
check("ARNCE 0x8FE8 = WA",   options.decode_arnce(from_hex("8FE8")), "WA")

-- A short code may bear digits; it simply has no reading the dissector will
-- show. "W7" = 23*1600 + 34*40 = 0x9510, digits starting at index 27.
check("ARNCE 0x9510 = W7",   options.decode_arnce(from_hex("9510")), "W7")

-- ─────────────────────────────────────────────────────────────────────────────
-- Options codec tests
-- ─────────────────────────────────────────────────────────────────────────────
section("Options codec")

-- Example 7 options block: 20 92 78 53 FF
-- Option 2 (Trace Route), delta=2, len=0
-- Option 11 (Region Code), delta=9, len=2, value=78 53
-- End marker FF
local opts7 = from_hex("20 927853 FF")

local nums, vals = {}, {}
for num, val, consumed in options.decode(opts7, 1) do
  nums[#nums+1] = num
  vals[#vals+1] = val
end
check("options Example7: count",    #nums, 2)
check("options Example7: opt[1] num", nums[1], 2)
check("options Example7: opt[1] val", vals[1], "")
check("options Example7: opt[2] num", nums[2], 11)
check("options Example7: opt[2] val", vals[2], from_hex("7853"))

-- scan_length should return 5 (3 + 1 + 1 for FF)
check("options Example7: scan_length", options.scan_length(opts7, 1), 5)

-- Static-option flag (bit 1 of option number)
check("is_static(11)", options.is_static(11), false)  -- Region Code = 11 = 0b1011 → bit1=1 → dynamic
check("is_static(2)",  options.is_static(2),  false)  -- Trace Route = 2 = 0b010 → bit1=1 → dynamic
check("is_critical(11)", options.is_critical(11), true)  -- bit0=1 → critical
check("is_critical(2)", options.is_critical(2), false) -- bit0=0 → non-critical

-- ─────────────────────────────────────────────────────────────────────────────
-- Keystore rebuild / lookup tests
-- ─────────────────────────────────────────────────────────────────────────────
section("Keystore")

local NODE_A_PUB = ("ED54A59FB1AC3A5123935136294 1B868E85A60E3D7B2485D828821DC7A69C279"):gsub("%s","")
local NODE_B_PUB = "6C28FD058C18C88C6CCE2AF981D2D11C851B123ED5B69B7876773ED099EA3F83"
-- 32 bytes: the all-0x5A channel key from docs/protocol/src/test-vectors.md,
-- whose channel ID is B0 8D.
local CHAN_KEY   = ("5A"):rep(32)

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
-- Option registry
-- Every option the spec defines should be named; a gap here is an option
-- the dissector renders as a bare "Option N" with its value undecoded.
-- See the Defined Options table in docs/protocol/src/packet-options.md.
-- ─────────────────────────────────────────────────────────────────────────────
section("Option registry")

local SPEC_OPTIONS = {
  [0]  = "Reserved",          [1]  = "Unassigned",
  [2]  = "Trace Route",       [3]  = "Source Route",
  [4]  = "Operator Callsign", [5]  = "Min RSSI",
  [6]  = "Route Retry",       [7]  = "Station Callsign",
  [8]  = "Ack MIC",           [9]  = "Min SNR",
  [10] = "Trace Signal",      [11] = "Region Code",
}

for num = 0, 11 do
  check(string.format("option %d (%s) is named", num, SPEC_OPTIONS[num]),
        options.KNOWN_OPTION_NAMES[num], SPEC_OPTIONS[num])
end

-- Options the spec says a packet must be dropped for carrying twice.
check("trace route is single-occurrence",
      options.SINGLETON_OPTIONS[options.OPT_TRACE_ROUTE], true)
check("route retry is single-occurrence",
      options.SINGLETON_OPTIONS[options.OPT_ROUTE_RETRY], true)
-- Several region codes may legitimately ride one packet; the rule that a
-- repeater must not add a second binds an action no frame records.
check("region code is NOT single-occurrence",
      options.SINGLETON_OPTIONS[options.OPT_REGION_CODE], nil)

-- Classification comes from the option number's low two bits.
check("trace route is non-critical", options.is_critical(2), false)
check("source route is critical",    options.is_critical(3), true)
check("route retry is dynamic",      options.is_static(6),   false)
check("ack mic is static",           options.is_static(8),   true)

-- ─────────────────────────────────────────────────────────────────────────────
-- Canonical address presentation
-- Vectors from crates/umsh-core/src/base58.rs, which is the definition.
-- ─────────────────────────────────────────────────────────────────────────────
section("Base58 addresses")

local base58 = require("base58")

check("encode32 all-zero = 44 ones",
      base58.encode32(string.rep("\x00", 32)), ("1"):rep(44))
check("encode32 all-FF",
      base58.encode32(string.rep("\xFF", 32)),
      "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG")
check("encode32 value 1 (fixed width, left-padded)",
      base58.encode32(string.rep("\x00", 31) .. "\x01"), ("1"):rep(43) .. "2")

local seq = {}
for i = 0, 31 do seq[#seq+1] = string.char(i) end
check("encode32 00..1F",
      base58.encode32(table.concat(seq)),
      "111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE")

check("encode32 rejects wrong length", base58.encode32("\x00"), nil)

-- Star truncation: characters are emitted only while every key matching the
-- hint would produce them, so the star marks where the hint stops proving.
check("node hint ED54A5",   base58.node_hint(from_hex("ED54A5")),   "GySV")
check("node hint 6C28FD",   base58.node_hint(from_hex("6C28FD")),   "8HDH")
check("router hint ED54",   base58.router_hint(from_hex("ED54")),   "Gy*")
check("router hint 6C28",   base58.router_hint(from_hex("6C28")),   "8H*")
check("node hint never exceeds its budget",
      #base58.node_hint(from_hex("000000")) <= 4, true)
check("hint agrees with the full key it came from",
      base58.encode32(from_hex(NODE_A_PUB)):sub(1, 4),
      base58.node_hint(from_hex("ED54A5")))

check("node hint carries the byte form",
      base58.node_hint_full(from_hex("ED54A5")), "GySV (ED:54:A5)")
check("router hint carries the byte form",
      base58.router_hint_full(from_hex("ED54")), "Gy* (ED:54)")
check("addr picks the full key form by length",
      base58.addr(from_hex(NODE_A_PUB)),
      "GySVDr1omr3GTodgWFH7qD1ZKav9C5NMPFjdpwb33LvU")

-- Decoding, so an address can be pasted back in wherever one is displayed.
check("decode32 round-trips Node A",
      base58.decode32(base58.encode32(from_hex(NODE_A_PUB))), from_hex(NODE_A_PUB))
check("decode32 all-zero", base58.decode32(("1"):rep(44)), string.rep("\0", 32))
check("decode32 all-FF",
      base58.decode32("JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"),
      string.rep("\xFF", 32))
-- The alphabet leaves out 0/O/I/l so the characters people misread are
-- rejected outright rather than decoded as something else.
check("decode32 rejects '0'", base58.decode32(("1"):rep(43) .. "0"), nil)
check("decode32 rejects 'O'", base58.decode32(("1"):rep(43) .. "O"), nil)
check("decode32 rejects a short string", base58.decode32("111"), nil)
check("decode32 rejects a value over 32 bytes", base58.decode32(("z"):rep(44)), nil)

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

-- ─────────────────────────────────────────────────────────────────────────────
-- Key input forms
-- Anywhere a key is configured, it may be written the way the rest of the
-- project writes one: hex, base58, or the matching URI.
-- ─────────────────────────────────────────────────────────────────────────────
section("Key input forms")

local NODE_A_B58 = "GySVDr1omr3GTodgWFH7qD1ZKav9C5NMPFjdpwb33LvU"

keystore.rebuild(NODE_A_B58 .. ":FromBase58", "", "")
check("node key as base58",
      keystore.lookup_node_by_key(from_hex(NODE_A_PUB)), "FromBase58")

keystore.rebuild("umsh:n:" .. NODE_A_B58 .. ":FromUri", "", "")
check("node key as umsh:n: URI",
      keystore.lookup_node_by_key(from_hex(NODE_A_PUB)), "FromUri")

-- URIs carry `?k=v` parameters; the key is what precedes them.
keystore.rebuild("umsh:n:" .. NODE_A_B58 .. "?n=Base%20Camp:WithParams", "", "")
check("node URI with parameters",
      keystore.lookup_node_by_key(from_hex(NODE_A_PUB)), "WithParams")

keystore.rebuild(NODE_A_PUB .. ":FromHex", "", "")
check("node key as hex still works",
      keystore.lookup_node_by_key(from_hex(NODE_A_PUB)), "FromHex")

-- A label is optional, and a key with none still lands.
keystore.rebuild(NODE_A_B58, "", "")
check("base58 key with no label",
      keystore.lookup_node_by_key(from_hex(NODE_A_PUB)), "")

-- Garbage is dropped rather than half-read.
keystore.rebuild("not-a-key:Nope\n" .. NODE_A_B58 .. ":Good", "", "")
check("malformed key line is skipped",
      keystore.lookup_node_by_key(from_hex(NODE_A_PUB)), "Good")

-- A URI of the wrong kind is refused rather than read as this kind of key.
keystore.rebuild("umsh:ck:" .. NODE_A_B58 .. ":WrongScheme", "", "")
check("channel-key URI is not accepted as a node",
      keystore.lookup_node_by_key(from_hex(NODE_A_PUB)), nil)

-- Channel keys take the same forms, and the ID derives either way.
if crypto then
  local CHAN_B58 = base58.encode32(from_hex(CHAN_KEY))
  keystore.rebuild("", "", CHAN_B58 .. ":ChanFromBase58")
  local ch = keystore.get_channel_by_id(from_hex("B08D"))
  check("channel key as base58", ch and ch.name, "ChanFromBase58")

  keystore.rebuild("", "", "umsh:ck:" .. CHAN_B58 .. ":ChanFromUri")
  ch = keystore.get_channel_by_id(from_hex("B08D"))
  check("channel key as umsh:ck: URI", ch and ch.name, "ChanFromUri")

  -- Private keys too, checked through the X25519 public key they derive.
  keystore.rebuild("", NODE_A_B58 .. ":SeedFromBase58", "")
  local pks = keystore.get_all_privkeys()
  check("private key as base58", #pks == 1 and pks[1].seed_bytes, from_hex(NODE_A_PUB))
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Well-known channels
-- The keys derive from names the spec fixes, so both the keys and the
-- channel IDs they hash to are constants a capture can rely on.
-- ─────────────────────────────────────────────────────────────────────────────
section("Well-known channels")

if not crypto then
  io.write("  SKIP  (crypto module not loaded)\n")
else
  check("public channel key",
        crypto.hmac_sha256("UMSH-CHANNEL-V1", "public"),
        from_hex("fb9b7adddc36e25d01f4c90e6babd20212536985dbcd8e5c3971375b6d511b51"))
  check("emergency channel key",
        crypto.hmac_sha256("UMSH-CHANNEL-V1", "emergency"),
        from_hex("a11c5e7491f9622ba7c05ae417e47135b9b392d5939b338849cd6fc2b4ba9cf2"))

  -- Added on top of whatever the operator configured, and findable by the
  -- 2-byte channel ID that appears on the wire.
  keystore.rebuild("", "", "")
  keystore.add_builtin_channels()

  local pub = keystore.get_channel_by_id(from_hex("0AD6"))
  check("public channel ID 0AD6 resolves",     pub and pub.builtin, "public")
  local emg = keystore.get_channel_by_id(from_hex("26C7"))
  check("emergency channel ID 26C7 resolves",  emg and emg.builtin, "emergency")
  check("built-in channels carry transport keys",
        pub and pub.derived_keys and #pub.derived_keys.k_enc, 32)
  check("built-in channel count", #keystore.get_all_channels(), 2)

  -- A hand-configured well-known channel keeps its own label rather than
  -- gaining a second entry under the same key.
  keystore.rebuild("", "", "umsh:cs:public:MyPublic")
  keystore.add_builtin_channels()
  check("configured well-known channel is not duplicated",
        #keystore.get_all_channels(), 2)
  local mine = keystore.get_channel_by_id(from_hex("0AD6"))
  check("configured label wins", mine and mine.name, "MyPublic")
  check("configured entry still tagged built-in", mine and mine.builtin, "public")
end

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

  -- HKDF test: derive channel ID for all-5A key → B08D.
  -- HKDF is HMAC-SHA256 all the way down, so this runs with no AES backend.
  local chan_id = crypto.derive_channel_id(from_hex(CHAN_KEY))
  check("HKDF derive_channel_id(5A*32) = B08D", chan_id, from_hex("B08D"))
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

  -- Channel keys derivation (64-byte HKDF output, S2V key first)
  local dk = crypto.derive_channel_keys(chan_key_bytes)
  check("derive_channel_keys: got k_enc", dk and #dk.k_enc == 32, true)
  check("derive_channel_keys: got k_mic", dk and #dk.k_mic == 32, true)
  check("derive_channel_keys: channel_id", dk and dk.channel_id, from_hex("B08D"))

  -- Keystore channel entry should now have channel_id after rebuild+refresh
  keystore.refresh_channel_crypto()
  local ch = keystore.get_channel_by_id(from_hex("B08D"))
  check("keystore channel lookup by B08D",
        ch and ch.name, "TestChannel")
  check("keystore channel has derived_keys",
        ch and ch.derived_keys ~= nil, true)

  -- CTR IV construction (RFC 5297 §2.6: top bit of bytes 9 and 13 cleared)
  local mic_ff = string.rep("\xFF", 16)
  local iv_ff = crypto.build_ctr_iv(mic_ff, "")
  check("build_ctr_iv masks byte 9",  iv_ff:byte(9),  0x7F)
  check("build_ctr_iv masks byte 13", iv_ff:byte(13), 0x7F)
  check("build_ctr_iv leaves other bytes", iv_ff:sub(1, 8), string.rep("\xFF", 8))

  local mic_16 = from_hex(("EA32F49109E8D4E60116 73C15B3184F0"):gsub("%s",""))
  local secinfo = from_hex(("E000000 02A"):gsub("%s",""))
  local iv = crypto.build_ctr_iv(mic_16, secinfo)
  -- 16-byte MIC → IV = masked MIC (SECINFO truncated away; this MIC's
  -- bytes 9 and 13 already have clear top bits, so the mask is identity)
  check("build_ctr_iv(16B mic) = masked mic", iv, mic_16)

  local mic_4 = from_hex("EA32F491")
  local iv4 = crypto.build_ctr_iv(mic_4, secinfo)
  -- 4-byte MIC + 5-byte SECINFO = 9 bytes → pad to 16 (secinfo byte at
  -- position 9 is 0x2A, top bit already clear)
  check("build_ctr_iv(4B mic) len=16", #iv4, 16)
  check("build_ctr_iv(4B mic) prefix", iv4:sub(1,4), mic_4)
  check("build_ctr_iv(4B mic) secinfo", iv4:sub(5,9), secinfo)
  check("build_ctr_iv(4B mic) padding", iv4:sub(10,16), string.rep("\0", 7))

  -- ── Pairwise key derivation ──
  local SHARED_SECRET = from_hex(
    "5ADD834FC109FAD52F041C5AF84A7966526D364D1895AFFCD794E044F3A9DB14")
  local pw = crypto.derive_pairwise_keys(SHARED_SECRET)
  check("pairwise keys: k_enc len=32", pw and #pw.k_enc, 32)
  check("pairwise keys: k_mic len=32", pw and #pw.k_mic, 32)

  -- ── Example 3: encrypted unicast verify+decrypt ──
  -- Packet: D0 6C28FD ED54A5 E0 0000002A FF AE71DC3872 618E9638FE4D9AE834331DE8E0DD063E
  -- FCF=D0, DST=6C28FD, SRC=ED54A5, SCF=E0 (enc, 16B MIC, no salt), FC=42
  -- Plaintext should be "Hello" = 48 65 6C 6C 6F
  local fcf_byte  = from_hex("D0")
  local dst_bytes = from_hex("6C28FD")
  local src_bytes = from_hex("ED54A5")
  local secinfo_e3 = from_hex(("E000000 02A"):gsub("%s",""))
  local body_e3   = from_hex("AE71DC3872")
  local mic_e3    = from_hex("618E9638FE4D9AE834331DE8E0DD063E")

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
  -- Payload=03 48656C6C6F, MIC=9A4BFCDE3942FEB225B8D3D4BCE79FDB
  local fcf_e6    = from_hex("E0")
  local chan_e6   = from_hex("B08D")
  local src_e6    = from_hex("ED54A5")
  local secinfo_e6 = from_hex(("60 00000003"):gsub("%s",""))
  local body_e6   = from_hex("0348656C6C6F")
  local mic_e6    = from_hex("9A4BFCDE3942FEB225B8D3D4BCE79FDB")

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
  -- body=7C16CCCF27324878 (encrypted SRC+payload), MIC=ACBF20014205B104175EA68F66477883
  local fcf_e5    = from_hex("E0")
  local secinfo_e5 = from_hex("E000000005")
  local body_e5   = from_hex("7C16CCCF27324878")
  local mic_e5    = from_hex("ACBF20014205B104175EA68F66477883")

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

  -- ── NIST SP 800-38A AES-256-CTR test vectors (Section F.5.5/F.5.6) ──
  -- Non-zero IV — this is what broke under GcryptCipher:setctr().
  local nist_key = from_hex(
    "603deb1015ca71be2b73aef0857d7781"
 .. "1f352c073b6108d72d9810a30914dff4")
  local nist_iv  = from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

  -- Verify AES-ECB primitive first: ECB(key, iv_block) = first keystream block
  local ecb_out = crypto.aes_ecb(nist_key, nist_iv)
  check("NIST AES-ECB(key, ctr0)",
        ecb_out, from_hex("0bdf7df1591716335e9a8b15c860c502"))

  -- Single-block CTR encrypt (plaintext → ciphertext)
  local nist_pt1 = from_hex("6bc1bee22e409f96e93d7e117393172a")
  local nist_ct1 = crypto.aes_ctr(nist_key, nist_iv, nist_pt1)
  check("NIST AES-CTR block 1 encrypt",
        nist_ct1, from_hex("601ec313775789a5b7a7f504bbf3d228"))

  -- Single-block CTR decrypt (ciphertext → plaintext)
  local nist_dec1 = crypto.aes_ctr(nist_key, nist_iv, from_hex("601ec313775789a5b7a7f504bbf3d228"))
  check("NIST AES-CTR block 1 decrypt",
        nist_dec1, nist_pt1)

  -- Multi-block (4 blocks = 64 bytes) — tests counter increment across blocks
  local nist_pt_all = from_hex(
    "6bc1bee22e409f96e93d7e117393172a"
 .. "ae2d8a571e03ac9c9eb76fac45af8e51"
 .. "30c81c46a35ce411e5fbc1191a0a52ef"
 .. "f69f2445df4f9b17ad2b417be66c3710")
  local nist_ct_all = from_hex(
    "601ec313775789a5b7a7f504bbf3d228"
 .. "f443e3ca4d62b59aca84e990cacaf5c5"
 .. "2b0930daa23de94ce87017ba2d84988d"
 .. "dfc9c58db67aada613c2dd08457941a6")
  local ctr_enc = crypto.aes_ctr(nist_key, nist_iv, nist_pt_all)
  check("NIST AES-CTR 4-block encrypt", ctr_enc, nist_ct_all)
  local ctr_dec = crypto.aes_ctr(nist_key, nist_iv, nist_ct_all)
  check("NIST AES-CTR 4-block decrypt", ctr_dec, nist_pt_all)

  -- ── NIST SP 800-38B AES-256 CMAC example vectors ──
  local cmac_key = nist_key
  -- Mlen = 0: empty message
  local cmac_empty = crypto.aes_cmac(cmac_key, {""})
  check("NIST CMAC-AES256 example 1 (empty)",
        cmac_empty, from_hex("028962f61b7bf89efc6b551f4667d983"))
  -- Mlen = 512: 64-byte message
  local cmac_m64 = from_hex(
    "6bc1bee22e409f96e93d7e117393172a"
 .. "ae2d8a571e03ac9c9eb76fac45af8e51"
 .. "30c81c46a35ce411e5fbc1191a0a52ef"
 .. "f69f2445df4f9b17ad2b417be66c3710")
  local cmac_64 = crypto.aes_cmac(cmac_key, {cmac_m64})
  check("NIST CMAC-AES256 example 4 (64B)",
        cmac_64, from_hex("e1992190549f6ed5696a2c056c315410"))

  -- ── S2V (RFC 5297 §2.4) structural checks ──
  -- With the AES-256 backend the RFC's own AES-128 appendix vectors
  -- cannot run here; the Example 3/5/6 decrypts above pin s2v against
  -- golden packet bytes that the Rust side cross-checks byte-for-byte
  -- against the RustCrypto aes-siv crate (AEAD_AES_SIV_CMAC_512).
  local s2v_empty = crypto.s2v(cmac_key, {}, "")
  check("s2v: empty-string component yields a 16-byte tag", #s2v_empty, 16)
  local s2v_ad = crypto.s2v(cmac_key, {"header"}, "payload longer than a block....")
  check("s2v: tag is 16 bytes", #s2v_ad, 16)
  check("s2v: AD changes the tag",
        s2v_ad ~= crypto.s2v(cmac_key, {"tampered"}, "payload longer than a block...."),
        true)

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
-- Wireshark API stubs
--
-- app.lua and ulcp.lua build their output through Wireshark's dissection API,
-- so exercising them outside Wireshark means standing in for the parts they
-- touch: fields, tree items, expert info, and a byte range that can be
-- sliced. The stub records the text of every item added, which is what the
-- assertions below read.
-- ─────────────────────────────────────────────────────────────────────────────

-- Display bases and expert enums are only ever compared or stored, so a
-- table that answers any key with its own name is enough.
local function enum_table()
  return setmetatable({}, {__index = function(_, k) return k end})
end

base   = enum_table()
expert = {group = enum_table(), severity = enum_table()}

local function field_ctor(kind, size)
  return function(abbrev, name, disp, valuestring, mask)
    return {kind = kind, size = size, abbrev = abbrev, name = name,
            disp = disp, valuestring = valuestring, mask = mask}
  end
end

ProtoField = {
  uint8  = field_ctor("uint", 1), uint16 = field_ctor("uint", 2),
  uint24 = field_ctor("uint", 3), uint32 = field_ctor("uint", 4),
  int8   = field_ctor("int",  1), int16  = field_ctor("int",  2),
  int32  = field_ctor("int",  4),
  bytes  = field_ctor("bytes"),   string = field_ctor("string"),
  bool   = field_ctor("bool"),    none   = field_ctor("none"),
}

ProtoExpert = {new = function(abbrev, name) return {abbrev = abbrev, name = name} end}
Dissector   = {get = function() return nil end}

function Proto(abbrev, desc) return {abbrev = abbrev, name = desc} end

-- A byte range, callable to slice itself the way a Tvb or TvbRange is.
local Range = {}
Range.__index = Range

local function new_range(data) return setmetatable({data = data}, Range) end

Range.__call = function(self, off, len)
  if off == nil then return self end
  local avail = #self.data - off
  if off < 0 or avail < 0 then error("range offset out of bounds") end
  if len == nil then len = avail end
  if len < 0 or len > avail then error("range length out of bounds") end
  return new_range(self.data:sub(off + 1, off + len))
end

function Range:len()   return #self.data end
function Range:raw()   return self.data end
function Range:tvb()   return self end
function Range:bytes() return self end
function Range:uint()
  local v = 0
  for i = 1, #self.data do v = v * 256 + self.data:byte(i) end
  return v
end
function Range:le_uint()
  local v = 0
  for i = #self.data, 1, -1 do v = v * 256 + self.data:byte(i) end
  return v
end
local function signed(v, nbytes)
  local half = 1 << (nbytes * 8 - 1)
  return v >= half and v - (half * 2) or v
end
function Range:int()    return signed(self:uint(),    #self.data) end
function Range:le_int() return signed(self:le_uint(), #self.data) end

ByteArray = {
  new = function(hexstr)
    local raw = from_hex(hexstr)
    return {tvb = function(_, _name) return new_range(raw) end}
  end,
}

local tree_log = {}

local function mask_shift(mask)
  local n = 0
  while mask ~= 0 and (mask & 1) == 0 do mask = mask >> 1; n = n + 1 end
  return n
end

-- Render an item the way Wireshark's default formatting would: a value
-- string wins, a hex display base shows hex, and a field with no explicit
-- value takes it from the range it covers.
local function render(field, range, value, little_endian)
  local kind = field.kind
  if kind == nil then return field.name end  -- a Proto, not a field
  if value == nil and range then
    if kind == "uint" or kind == "bool" then
      value = little_endian and range:le_uint() or range:uint()
    elseif kind == "int" then
      value = little_endian and range:le_int() or range:int()
    elseif kind == "bytes" then
      value = hex(range:raw())
    elseif kind == "string" then
      value = range:raw()
    end
  end
  if field.mask and type(value) == "number" then
    value = (value & field.mask) >> mask_shift(field.mask)
  end
  if value == nil then return field.name end
  if type(value) == "number" then
    if field.valuestring and field.valuestring[value] then
      return string.format("%s: %s (%d)", field.name, field.valuestring[value], value)
    elseif field.disp == "HEX" then
      return string.format("%s: 0x%0" .. ((field.size or 1) * 2) .. "X",
                           field.name, value)
    end
  end
  return field.name .. ": " .. tostring(value)
end

local TreeItem = {}
TreeItem.__index = TreeItem

local function record(text)
  tree_log[#tree_log + 1] = text
  return setmetatable({index = #tree_log}, TreeItem)
end

local function add_item(field, a, b, little_endian)
  local range, value
  if getmetatable(a) == Range then range, value = a, b else value = a end
  return record(render(field, range, value, little_endian))
end

function TreeItem:add(field, a, b)    return add_item(field, a, b, false) end
function TreeItem:add_le(field, a, b) return add_item(field, a, b, true)  end
function TreeItem:set_text(text)      tree_log[self.index] = text; return self end
function TreeItem:append_text(text)
  tree_log[self.index] = tree_log[self.index] .. text
  return self
end
function TreeItem:add_proto_expert_info(e, message)
  tree_log[#tree_log + 1] = "EXPERT: " .. tostring(message or (e and e.name))
  return self
end

local function new_pinfo()
  local info = {text = ""}
  function info:append(s)  self.text = self.text .. s end
  function info:prepend(s) self.text = s .. self.text end
  function info:set(s)     self.text = s end
  return {cols = {protocol = "", info = info}}
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Node Management payloads (docs/protocol/src/app-node-management.md)
--
-- [TOKEN:2][OPTIONS][0xFF][FRAME]: direction is the payload type, 8 for a
-- request and 9 for a response, and exactly one unprefixed ULCP frame runs
-- to the end of the payload.
-- ─────────────────────────────────────────────────────────────────────────────
section("Node Management")

local app = require("app")

-- Dissect a whole payload, type byte included, and return what the tree,
-- the columns, and the violation sink ended up holding.
local function dissect_payload(payload_hex, pkt_type)
  tree_log = {}
  local violations = {}
  local pinfo = new_pinfo()
  local root  = record("Frame")
  local ctx   = {
    pkt_type = pkt_type or 2,  -- unicast unless the test says otherwise
    full_src = true,
    flag     = function(_tree, _range, text) violations[#violations + 1] = text end,
  }
  app.dissect(from_hex(payload_hex), root, pinfo, nil, nil, ctx)
  return {
    items      = tree_log,
    info       = pinfo.cols.info.text,
    protocol   = pinfo.cols.protocol,
    violations = violations,
  }
end

local function has(result, text)
  for _, item in ipairs(result.items) do
    if item:find(text, 1, true) then return true end
  end
  return false
end

-- A request carrying CMD_PROP_MULTI_GET of PROP_CAPS and PROP_DEV_NAME.
local req = dissect_payload("08 1234 FF 8015 05 44")
check("request names its payload type",  has(req, "Node Management Request"), true)
check("request sets the protocol column", req.protocol, "UMSH-NM")
check("request info line",
      req.info, " Node Mgmt: request (token 0x1234)")
check("request token",                   has(req, "Token: 0x1234"), true)
check("no FLAGS byte is parsed",         has(req, "Flags"), false)
check("embedded frame decodes",
      has(req, "Command: CMD_PROP_MULTI_GET (21)"), true)
check("multi-get first key",             has(req, "Property: PROP_CAPS (5)"), true)
check("multi-get second key",            has(req, "Property: PROP_DEV_NAME (68)"), true)
check("clean request has no violations", #req.violations, 0)

-- The response to it: CMD_PROP_ARE with one entry per property.
local resp = dissect_payload("09 1234 FF 8017 020541 034468 69")
check("response names its payload type", has(resp, "Node Management Response"), true)
check("response info line",
      resp.info, " Node Mgmt: response (token 0x1234)")
check("response frame decodes",   has(resp, "Command: CMD_PROP_ARE (23)"), true)
check("first entry",  has(resp, "Entry 1: PROP_CAPS (1 byte value)"), true)
check("second entry", has(resp, "Entry 2: PROP_DEV_NAME (2 byte value)"), true)
check("clean response has no violations", #resp.violations, 0)

-- The frame runs to the end of the payload, so a length prefix would be
-- read as part of the frame—here as a header with the wrong flag bits.
local prefixed = dissect_payload("08 1234 FF 03 800205")
check("a length-prefixed frame no longer parses",
      has(prefixed, "EXPERT: invalid ULCP header flag/reserved bits"), true)

-- Cursor and remaining options on a continued read.
local cursored = dissect_payload("09 1234 14AABBCCDD 1140 FF 800605")
check("cursor option",    has(cursored, "Cursor: AABBCCDD"), true)
check("remaining option", has(cursored, "Remaining: 64"), true)
check("options carry no violations", #cursored.violations, 0)

-- Correlation is by token, so the frame's TID has to be zero.
local tid = dissect_payload("08 0001 FF 830205")
check("non-zero TID is flagged", #tid.violations, 1)
check("non-zero TID names the rule",
      tid.violations[1] and tid.violations[1]:find("TID bits set to zero", 1, true) ~= nil,
      true)

-- The payload type fixes the direction, so a command going the other way
-- is one the receiver cannot act on.
local backwards = dissect_payload("08 0001 FF 800605")
check("Device→Host command in a request is flagged", #backwards.violations, 1)
check("the flagged command is named",
      backwards.violations[1] and
        backwards.violations[1]:find("CMD_PROP_IS", 1, true) ~= nil,
      true)

-- A payload that stops at the end-of-options marker carries no frame.
local no_frame = dissect_payload("08 0001 FF")
check("missing frame is flagged", #no_frame.violations, 1)
check("missing frame names the rule",
      no_frame.violations[1] and
        no_frame.violations[1]:find("one ULCP frame", 1, true) ~= nil,
      true)

-- An entry claiming more bytes than the frame holds. The list is broken,
-- not empty, so it is reported once and not also as carrying nothing.
local overrun = dissect_payload("08 0001 FF 8016 05 0541")
check("over-long entry is flagged",
      has(overrun, "EXPERT: entry length exceeds frame"), true)
check("a broken entry list is not also called empty",
      has(overrun, "carries no entries"), false)

-- A multi-set with nothing to set, on the other hand, is empty.
local empty = dissect_payload("08 0001 FF 8016")
check("empty entry list is flagged",
      has(empty, "EXPERT: CMD_PROP_MULTI_SET carries no entries"), true)
local empty_get = dissect_payload("08 0001 FF 8015")
check("empty key list is flagged",
      has(empty_get, "EXPERT: CMD_PROP_MULTI_GET carries no property keys"), true)

-- Both directions ride unicast only.
local mcast = dissect_payload("09 1234 FF 800605", 4)
check("a response must not be multicast", #mcast.violations, 1)
check("the multicast rule names the payload type",
      mcast.violations[1] and
        mcast.violations[1]:find("Node Management Response payload must not", 1, true) ~= nil,
      true)

-- ─────────────────────────────────────────────────────────────────────────────
-- Node Identity regions (docs/protocol/src/node-identity.md)
--
-- Option 4 is repeated: one region name per option, as UTF-8. The 2-octet
-- forwarding code is derived from the name rather than carried.
-- ─────────────────────────────────────────────────────────────────────────────
section("Node Identity regions")

-- A repeater forwarding for two named regions, one an airport code and one
-- a name with a space in it.
local ni_regions = dissect_payload(
  "01 01 01 43 534A43 0C 526F6775652056616C6C6579")
check("first region",  has(ni_regions, "Supported Region: SJC"), true)
check("second region", has(ni_regions, "Supported Region: Rogue Valley"), true)
check("clean regions carry no violations", #ni_regions.violations, 0)

-- The cap is on the octets, not the characters.
local ni_long = dissect_payload(
  "01 01 01 4D 0C 41414141414141414141414141414141414141414141414141")
check("an over-long region is flagged",
      ni_long.violations[1] and
        ni_long.violations[1]:find("1 to 24 octets", 1, true) ~= nil,
      true)

-- ─────────────────────────────────────────────────────────────────────────────
-- Peer Repeaters (docs/protocol/src/mac-commands.md)
--
-- Command 10 is a CoAP option block and nothing else; command 11 follows its
-- own option block with a list of entries, each an option list terminated by
-- its own 0xFF that the last entry may leave off.
-- ─────────────────────────────────────────────────────────────────────────────
section("Peer Repeaters")

-- A first ask: a nonce to correlate the answer with, no cursor to resume from.
local pr_req = dissect_payload("02 0A 02BEEF")
check("request names the command",
      has(pr_req, "Command: Peer Repeaters Req (10)"), true)
check("request info line carries the nonce",
      pr_req.info, " MAC Command: Peer Repeaters Req (nonce 0xBEEF)")
check("a cursorless request says nothing about resuming",
      pr_req.info:find("resuming", 1, true), nil)
check("a unicast request is not flagged", #pr_req.violations, 0)

-- The follow-up page: the same ask with the cursor the last answer gave back.
local pr_resume = dissect_payload("02 0A 02BEEF 13AABBCC")
check("request cursor",  has(pr_resume, "Cursor: AABBCC"), true)
check("a resumed request says so",
      pr_resume.info:find("resuming", 1, true) ~= nil, true)

-- One page holding the whole listing: Total, no cursor, one full entry.
local pr_resp = dissect_payload(
  "02 0B 02BEEF 2101 FF 03AABBCC 155269646765 125F08 1105 227853")
check("response names the command",
      has(pr_resp, "Command: Peer Repeaters Resp (11)"), true)
check("response reports the listing size", has(pr_resp, "Total Entries: 1"), true)
check("entry names the peer",  has(pr_resp, "Peer Repeater: Ridge"), true)
check("entry node hint",       has(pr_resp, "Node Hint: "), true)
check("entry hint bytes",      has(pr_resp, "AA:BB:CC"), true)
check("entry node name",       has(pr_resp, "Node Name: Ridge"), true)
-- RSSI is unsigned negative dBm and SNR is quarter-decibel steps, so 0x5F
-- and 0x08 read as -95 dBm and 2 dB.
check("entry RSSI",            has(pr_resp, "RSSI: -95 dBm"), true)
check("entry SNR",             has(pr_resp, "SNR: 2.00 dB"), true)
check("entry last heard",      has(pr_resp, "Last Heard (min): 5"), true)
check("entry region code reads as its airport code",
      has(pr_resp, "Supported Flood Regions: SJC"), true)
check("response info line",
      pr_resp.info, " MAC Command: Peer Repeaters Resp (nonce 0xBEEF, 1 of 1 entries)")
check("a clean response has no violations", #pr_resp.violations, 0)

-- Two entries, the first terminated and the last not, and a peer known only
-- from a route: a two-byte hint, signal, and nothing else.
local pr_pages = dissect_payload(
  "02 0B 13AABBCC 1102 FF 021122 2264F8 FF 03DDEEFF 3105")
check("both entries are walked",
      has(pr_pages, "Peer Repeater"), true)
check("the observation-only entry names a router hint",
      has(pr_pages, "router hint"), true)
check("its signal is still reported", has(pr_pages, "RSSI: -100 dBm"), true)
check("a negative SNR reads as one",  has(pr_pages, "SNR: -2.00 dB"), true)
check("the unterminated final entry is still counted",
      pr_pages.info:find("2 of 2 entries", 1, true) ~= nil, true)
check("a cursored response says more follow",
      pr_pages.info:find("more follow", 1, true) ~= nil, true)
check("a nonceless response says nothing about a nonce",
      pr_pages.info:find("nonce", 1, true), nil)

-- Both commands are addressed to one node, so neither may be flooded.
local pr_bcast = dissect_payload("02 0A 02BEEF", 0)
check("a broadcast Peer Repeaters Request is flagged", #pr_bcast.violations, 1)
check("the rule names the command",
      pr_bcast.violations[1] and
        pr_bcast.violations[1]:find("Peer Repeaters Req", 1, true) ~= nil,
      true)

-- A hint the spec does not allow: a receiver has to make sense of the rest
-- of the entry anyway.
local pr_badhint = dissect_payload("02 0B 2101 FF 0555667788 99 15526964 6765")
check("an out-of-range hint length is flagged",
      pr_badhint.violations[1] and
        pr_badhint.violations[1]:find("must be 2 or 3 bytes", 1, true) ~= nil,
      true)

-- Field widths the spec fixes: Total is one byte, last heard one or two,
-- RSSI/SNR exactly two. Off-size values are flagged, not rendered.
local pr_fat_total = dissect_payload("02 0B 220100")
check("an oversize total is flagged",
      pr_fat_total.violations[1] and
        pr_fat_total.violations[1]:find("total must be 1 byte", 1, true) ~= nil,
      true)
check("an oversize total is not rendered",
      has(pr_fat_total, "Total Entries"), false)

local pr_fat_heard = dissect_payload("02 0B FF 03AABBCC 33010203")
check("an oversize last heard is flagged",
      pr_fat_heard.violations[1] and
        pr_fat_heard.violations[1]:find("must be 1 or 2 bytes", 1, true) ~= nil,
      true)
check("an oversize last heard is not rendered",
      has(pr_fat_heard, "Last Heard"), false)

local pr_thin_signal = dissect_payload("02 0B FF 03AABBCC 215F")
check("a one-byte RSSI/SNR is flagged",
      pr_thin_signal.violations[1] and
        pr_thin_signal.violations[1]:find("must be 2 bytes", 1, true) ~= nil,
      true)

-- ─────────────────────────────────────────────────────────────────────────────
-- Results
-- ─────────────────────────────────────────────────────────────────────────────
io.write(string.format(
  "\n─── Results: %d passed, %d failed ───\n", passed, failed))
os.exit(failed > 0 and 1 or 0)
