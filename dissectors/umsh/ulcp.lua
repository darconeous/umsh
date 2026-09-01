-- UMSH Spinel-inspired local control protocol (ULCP) over capture UDP ports.

local M = {}

local COMMANDS = {
  [0] = "CMD_NOP",
  [1] = "CMD_RST",
  [2] = "CMD_PROP_GET",
  [3] = "CMD_PROP_SET",
  [4] = "CMD_PROP_INSERT",
  [5] = "CMD_PROP_REMOVE",
  [6] = "CMD_PROP_IS",
  [7] = "CMD_PROP_INSERTED",
  [8] = "CMD_PROP_REMOVED",
  [9] = "CMD_STR_SEND",
  [10] = "CMD_STR_RECV",
  [11] = "CMD_QUEUE_DRAIN",
  [12] = "CMD_SAVE",
  [13] = "CMD_CLEAR",
  [14] = "CMD_RESTORE",
  [15] = "CMD_FACTORY_RESET",
  [16] = "CMD_REBOOT",
  [17] = "CMD_BLE_CLEAR_BONDS",
  [21] = "CMD_PROP_MULTI_GET",
  [22] = "CMD_PROP_MULTI_SET",
  [23] = "CMD_PROP_ARE",
}

M.COMMANDS = COMMANDS

-- Which way each command travels. Node Management carries the same grammar
-- over the mesh, where the payload type fixes the direction, so a frame
-- going the wrong way is a violation the dissector can name.
M.COMMAND_TO_DEVICE = {
  [0] = true, [1] = true, [2] = true, [3] = true, [4] = true, [5] = true,
  [9] = true, [11] = true, [12] = true, [13] = true, [14] = true,
  [15] = true, [16] = true, [17] = true,
  [21] = true, [22] = true,
}
M.COMMAND_TO_HOST = {
  [6] = true, [7] = true, [8] = true, [10] = true, [23] = true,
}

-- Commands whose payload is a property key followed by a value or item.
local KEYED_COMMANDS = {
  [2] = true, [3] = true, [4] = true, [5] = true,
  [6] = true, [7] = true, [8] = true,
}

-- Commands whose payload is a list of length-prefixed key-and-value entries.
local ENTRY_LIST_COMMANDS = {[22] = true, [23] = true}

local PROPERTIES = {
  [0] = "PROP_LAST_STATUS",
  [1] = "PROP_PROTOCOL_VERSION",
  [2] = "PROP_DEV_VERSION",
  [4] = "PROP_DEV_MODEL",
  [3] = "PROP_INTERFACE_TYPE",
  [5] = "PROP_CAPS",
  [6] = "PROP_UPTIME",
  [32] = "PROP_PHY_ENABLED",
  [35] = "PROP_PHY_FREQ",
  [37] = "PROP_PHY_TX_POWER",
  [38] = "PROP_PHY_RSSI",
  [39] = "PROP_PHY_LORA_BW",
  [40] = "PROP_PHY_LORA_SF",
  [41] = "PROP_PHY_LORA_CR",
  [42] = "PROP_PHY_MTU",
  [43] = "PROP_PHY_LORA_SW",
  [48] = "PROP_MAC_PROMISCUOUS",
  [50] = "PROP_MAC_BACKHAUL",
  [68] = "PROP_DEV_NAME",
  [4820] = "PROP_PHY_DUTY_NOW",
  [4822] = "PROP_PHY_DUTY_LIMIT",
  [4832] = "PROP_STAT_TX_PACKETS",
  [4833] = "PROP_STAT_TX_CHANNEL_BUSY",
  [4834] = "PROP_STAT_RX_PACKETS",
  [4835] = "PROP_STAT_RX_BAD_CRC",
  [4836] = "PROP_STAT_RX_NON_UMSH",
  [4837] = "PROP_STAT_RX_ACCEPTED",
  [4838] = "PROP_STAT_FORWARDED",
  [4839] = "PROP_STAT_FORWARD_DROPPED",
  [4840] = "PROP_STAT_FORWARD_CANCELLED",
  [4864] = "PROP_BLE_PAIRING_PIN",
  [4865] = "PROP_DEV_ADMINS",
  [4871] = "PROP_BLE_ENABLED",
  [4872] = "PROP_BLE_BOND_COUNT",
  [4873] = "PROP_BLE_LINK",
  [4874] = "PROP_BLE_PAIRING",
}

local STREAMS = {[113] = "STR_PHY_RAW"}

local proto = Proto("umsh.ulcp", "UMSH ULCP")
local f = {}
f.direction = ProtoField.string("umsh.ulcp.direction", "Direction")
f.header = ProtoField.uint8("umsh.ulcp.header", "Header", base.HEX)
f.flag = ProtoField.uint8("umsh.ulcp.flag", "Flag", base.DEC, nil, 0xc0)
f.reserved = ProtoField.uint8("umsh.ulcp.reserved", "Reserved", base.HEX, nil, 0x38)
f.tid = ProtoField.uint8("umsh.ulcp.tid", "Transaction ID", base.DEC, nil, 0x07)
f.command = ProtoField.uint8("umsh.ulcp.command", "Command", base.DEC, COMMANDS)
f.property = ProtoField.uint32("umsh.ulcp.property", "Property", base.DEC, PROPERTIES)
f.property_value = ProtoField.bytes("umsh.ulcp.property_value", "Property Value")
f.entry = ProtoField.bytes("umsh.ulcp.entry", "Entry")
f.entry_length = ProtoField.uint32("umsh.ulcp.entry_length", "Entry Length", base.DEC)
f.stream = ProtoField.uint32("umsh.ulcp.stream", "Stream", base.DEC, STREAMS)
f.data_length = ProtoField.uint16("umsh.ulcp.data_length", "Data Length", base.DEC)
f.stream_data = ProtoField.bytes("umsh.ulcp.stream_data", "Stream Data")
f.metadata = ProtoField.bytes("umsh.ulcp.metadata", "Metadata")
f.rx_rssi = ProtoField.int16("umsh.ulcp.rx.rssi", "RX RSSI (dBm)", base.DEC)
f.rx_lqi = ProtoField.uint8("umsh.ulcp.rx.lqi", "RX LQI", base.DEC)
f.rx_snr = ProtoField.int16("umsh.ulcp.rx.snr_cb", "RX SNR (centibels)", base.DEC)
f.rx_flags = ProtoField.uint8("umsh.ulcp.rx.flags", "RX Flags", base.HEX)
f.rx_flag_buffered = ProtoField.bool("umsh.ulcp.rx.flags.buffered", "Buffered", 8, nil, 0x01)
f.rx_flag_acked = ProtoField.bool("umsh.ulcp.rx.flags.acked", "Acknowledged", 8, nil, 0x02)
f.rx_flag_self_tx = ProtoField.bool("umsh.ulcp.rx.flags.self_tx", "Self-transmitted", 8, nil, 0x04)
f.rx_age = ProtoField.uint32("umsh.ulcp.rx.age_s", "RX Age (seconds)", base.DEC)
f.tx_power = ProtoField.int8("umsh.ulcp.tx.power", "TX Power (dBm)", base.DEC)
f.tx_flags = ProtoField.uint8("umsh.ulcp.tx.flags", "TX Flags", base.HEX)
f.payload = ProtoField.bytes("umsh.ulcp.payload", "Payload")
proto.fields = f

local malformed = ProtoExpert.new(
  "umsh.ulcp.malformed", "Malformed ULCP frame",
  expert.group.MALFORMED, expert.severity.ERROR)
proto.experts = {malformed}

local function decode_pui(buf, offset)
  local value, shift = 0, 0
  for i = 0, 2 do
    if offset + i >= buf:len() then return nil, 0 end
    local byte = buf(offset + i, 1):uint()
    value = value | ((byte & 0x7f) << shift)
    if (byte & 0x80) == 0 then return value, i + 1 end
    shift = shift + 7
  end
  return nil, 0
end

local function add_malformed(item, message)
  item:add_proto_expert_info(malformed, message)
end

-- Dissect one ULCP frame into `tree`, returning the summary line.
--
-- Split out from proto.dissector so that Node Management payloads can reuse
-- it over the mesh, where the direction comes from the payload type rather
-- than from a UDP port, and the protocol column belongs to whoever called us.
local function dissect_frame(buf, pinfo, tree, direction)
  local root = tree:add(proto, buf())
  root:add(f.direction, direction)

  if buf:len() < 2 then
    add_malformed(root, "frame is shorter than header + command")
    return
  end
  local header = buf(0, 1):uint()
  root:add(f.header, buf(0, 1))
  root:add(f.flag, buf(0, 1))
  root:add(f.reserved, buf(0, 1))
  root:add(f.tid, buf(0, 1))
  if (header & 0xc0) ~= 0x80 or (header & 0x38) ~= 0 then
    add_malformed(root, "invalid ULCP header flag/reserved bits")
  end

  local command = buf(1, 1):uint()
  root:add(f.command, buf(1, 1))
  local command_name = COMMANDS[command] or string.format("CMD_%d", command)
  local info = string.format("%s %s TID=%d", direction, command_name, header & 0x07)

  if KEYED_COMMANDS[command] then
    local key, consumed = decode_pui(buf, 2)
    if not key then
      add_malformed(root, "truncated or malformed property key")
    else
      root:add(f.property, buf(2, consumed), key)
      info = info .. " " .. (PROPERTIES[key] or string.format("PROP_%d", key))
      local value_offset = 2 + consumed
      if value_offset < buf:len() then
        root:add(f.property_value, buf(value_offset))
      end
    end
  elseif command == 21 then
    -- CMD_PROP_MULTI_GET: property keys one after another, no delimiters.
    local pos, names, stopped = 2, {}, false
    while pos < buf:len() do
      local key, consumed = decode_pui(buf, pos)
      if not key then
        add_malformed(root, "truncated or malformed property key")
        stopped = true
        break
      end
      root:add(f.property, buf(pos, consumed), key)
      names[#names + 1] = PROPERTIES[key] or string.format("PROP_%d", key)
      pos = pos + consumed
    end
    if #names > 0 then
      info = info .. " " .. table.concat(names, ", ")
    elseif not stopped then
      -- The list is empty rather than broken: nothing was asked for.
      add_malformed(root, "CMD_PROP_MULTI_GET carries no property keys")
    end
  elseif ENTRY_LIST_COMMANDS[command] then
    -- CMD_PROP_MULTI_SET / CMD_PROP_ARE: entries of the combined key and
    -- value length as a PUI, the property key as a PUI, then the value.
    local pos, count, names, stopped = 2, 0, {}, false
    while pos < buf:len() do
      local entry_len, consumed = decode_pui(buf, pos)
      if not entry_len then
        add_malformed(root, "truncated or malformed entry length")
        stopped = true
        break
      end
      local body = pos + consumed
      if body + entry_len > buf:len() then
        add_malformed(root:add(f.entry_length, buf(pos, consumed), entry_len),
                      "entry length exceeds frame")
        stopped = true
        break
      end

      count = count + 1
      local entry = root:add(f.entry, buf(pos, consumed + entry_len))
      entry:add(f.entry_length, buf(pos, consumed), entry_len)

      local key, key_consumed = decode_pui(buf, body)
      if not key or key_consumed > entry_len then
        entry:set_text(string.format("Entry %d (%d bytes)", count, entry_len))
        add_malformed(entry, "truncated or malformed property key")
      else
        local name = PROPERTIES[key] or string.format("PROP_%d", key)
        entry:add(f.property, buf(body, key_consumed), key)
        entry:set_text(string.format("Entry %d: %s (%d byte value)",
                                     count, name, entry_len - key_consumed))
        if key_consumed < entry_len then
          entry:add(f.property_value, buf(body + key_consumed, entry_len - key_consumed))
        end
        names[#names + 1] = name
      end
      pos = body + entry_len
    end
    if #names > 0 then
      info = info .. " " .. table.concat(names, ", ")
    elseif count == 0 and not stopped then
      add_malformed(root, string.format("%s carries no entries", command_name))
    end
  elseif command == 9 or command == 10 then
    local stream, consumed = decode_pui(buf, 2)
    if not stream or 2 + consumed + 2 > buf:len() then
      add_malformed(root, "truncated or malformed stream envelope")
    else
      root:add(f.stream, buf(2, consumed), stream)
      local length_offset = 2 + consumed
      local data_length = buf(length_offset, 2):le_uint()
      root:add_le(f.data_length, buf(length_offset, 2))
      local data_offset = length_offset + 2
      if data_offset + data_length > buf:len() then
        add_malformed(root, "stream data length exceeds frame")
      else
        local data = buf(data_offset, data_length)
        local data_item = root:add(f.stream_data, data)
        local metadata_offset = data_offset + data_length
        if metadata_offset < buf:len() then
          local metadata = buf(metadata_offset)
          local metadata_item = root:add(f.metadata, metadata)
          if command == 10 and metadata:len() >= 4 then
            local encoded_rssi = metadata(0, 1):uint()
            if encoded_rssi ~= 0xff then
              metadata_item:add(f.rx_rssi, metadata(0, 1), -encoded_rssi)
            end
            if metadata(1, 1):uint() ~= 0 then
              metadata_item:add(f.rx_lqi, metadata(1, 1))
            end
            if metadata(2, 2):le_int() ~= -32768 then
              metadata_item:add_le(f.rx_snr, metadata(2, 2))
            end
            if metadata:len() >= 5 then
              local flags_item = metadata_item:add(f.rx_flags, metadata(4, 1))
              flags_item:add(f.rx_flag_buffered, metadata(4, 1))
              flags_item:add(f.rx_flag_acked, metadata(4, 1))
              flags_item:add(f.rx_flag_self_tx, metadata(4, 1))
            end
            if metadata:len() >= 9 then
              metadata_item:add_le(f.rx_age, metadata(5, 4))
            end
          elseif command == 9 and metadata:len() >= 2 then
            metadata_item:add(f.tx_power, metadata(0, 1))
            metadata_item:add(f.tx_flags, metadata(1, 1))
          end
        end
        info = info .. " " .. (STREAMS[stream] or string.format("STR_%d", stream))
        if stream == 113 and data_length > 0 then
          local umsh = Dissector.get("umsh")
          if umsh then pcall(umsh.call, umsh, data:tvb(), pinfo, data_item) end
          pinfo.cols.protocol = "UMSH-ULCP"
        end
      end
    end
  elseif buf:len() > 2 then
    root:add(f.payload, buf(2))
  end

  return info
end

M.dissect_frame = dissect_frame

function proto.dissector(buf, pinfo, tree)
  pinfo.cols.protocol = "UMSH-ULCP"
  local src_port = tonumber(tostring(pinfo.src_port)) or 0
  local direction = src_port == 4243 and "Host → Device" or "Device → Host"
  local info = dissect_frame(buf, pinfo, tree, direction)
  if info then pinfo.cols.info = info end
end

function M.register()
  local udp = DissectorTable.get("udp.port")
  udp:add(4243, proto)
  udp:add(4244, proto)
end

return M
