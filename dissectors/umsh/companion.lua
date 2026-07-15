-- UMSH Spinel-inspired companion-radio protocol over capture UDP ports.

local M = {}

local COMMANDS = {
  [0] = "CMD_NOP",
  [1] = "CMD_RST",
  [2] = "CMD_PROP_GET",
  [3] = "CMD_PROP_SET",
  [6] = "CMD_PROP_IS",
  [9] = "CMD_STR_SEND",
  [10] = "CMD_STR_RECV",
}

local PROPERTIES = {
  [0] = "PROP_LAST_STATUS",
  [1] = "PROP_PROTOCOL_VERSION",
  [2] = "PROP_NCP_VERSION",
  [3] = "PROP_INTERFACE_TYPE",
  [5] = "PROP_CAPS",
  [32] = "PROP_PHY_ENABLED",
  [35] = "PROP_PHY_FREQ",
  [37] = "PROP_PHY_TX_POWER",
  [38] = "PROP_PHY_RSSI",
  [39] = "PROP_PHY_LORA_BW",
  [40] = "PROP_PHY_LORA_SF",
  [41] = "PROP_PHY_LORA_CR",
  [42] = "PROP_PHY_MTU",
  [43] = "PROP_PHY_LORA_SW",
  [68] = "PROP_DEV_NAME",
  [4820] = "PROP_PHY_DUTY_NOW",
  [4822] = "PROP_PHY_DUTY_LIMIT",
  [4864] = "PROP_BLE_PAIRING_PIN",
}

local STREAMS = {[113] = "STR_PHY_RAW"}

local proto = Proto("umsh.companion", "UMSH Companion Radio")
local f = {}
f.direction = ProtoField.string("umsh.companion.direction", "Direction")
f.header = ProtoField.uint8("umsh.companion.header", "Header", base.HEX)
f.flag = ProtoField.uint8("umsh.companion.flag", "Flag", base.DEC, nil, 0xc0)
f.reserved = ProtoField.uint8("umsh.companion.reserved", "Reserved", base.HEX, nil, 0x38)
f.tid = ProtoField.uint8("umsh.companion.tid", "Transaction ID", base.DEC, nil, 0x07)
f.command = ProtoField.uint8("umsh.companion.command", "Command", base.DEC, COMMANDS)
f.property = ProtoField.uint32("umsh.companion.property", "Property", base.DEC, PROPERTIES)
f.property_value = ProtoField.bytes("umsh.companion.property_value", "Property Value")
f.stream = ProtoField.uint32("umsh.companion.stream", "Stream", base.DEC, STREAMS)
f.data_length = ProtoField.uint16("umsh.companion.data_length", "Data Length", base.DEC)
f.stream_data = ProtoField.bytes("umsh.companion.stream_data", "Stream Data")
f.metadata = ProtoField.bytes("umsh.companion.metadata", "Metadata")
f.rx_rssi = ProtoField.int16("umsh.companion.rx.rssi", "RX RSSI (dBm)", base.DEC)
f.rx_lqi = ProtoField.uint8("umsh.companion.rx.lqi", "RX LQI", base.DEC)
f.rx_snr = ProtoField.int16("umsh.companion.rx.snr_cb", "RX SNR (centibels)", base.DEC)
f.tx_power = ProtoField.int8("umsh.companion.tx.power", "TX Power (dBm)", base.DEC)
f.tx_flags = ProtoField.uint8("umsh.companion.tx.flags", "TX Flags", base.HEX)
f.payload = ProtoField.bytes("umsh.companion.payload", "Payload")
proto.fields = f

local malformed = ProtoExpert.new(
  "umsh.companion.malformed", "Malformed companion frame",
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

function proto.dissector(buf, pinfo, tree)
  pinfo.cols.protocol = "UMSH-COMP"
  local root = tree:add(proto, buf())
  local src_port = tonumber(tostring(pinfo.src_port)) or 0
  local direction = src_port == 4243 and "Host → NCP" or "NCP → Host"
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
    add_malformed(root, "invalid companion header flag/reserved bits")
  end

  local command = buf(1, 1):uint()
  root:add(f.command, buf(1, 1))
  local command_name = COMMANDS[command] or string.format("CMD_%d", command)
  local info = string.format("%s %s TID=%d", direction, command_name, header & 0x07)

  if command == 2 or command == 3 or command == 6 then
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
          elseif command == 9 and metadata:len() >= 2 then
            metadata_item:add(f.tx_power, metadata(0, 1))
            metadata_item:add(f.tx_flags, metadata(1, 1))
          end
        end
        info = info .. " " .. (STREAMS[stream] or string.format("STR_%d", stream))
        if stream == 113 and data_length > 0 then
          local umsh = Dissector.get("umsh")
          if umsh then pcall(umsh.call, umsh, data:tvb(), pinfo, data_item) end
          pinfo.cols.protocol = "UMSH-COMP"
        end
      end
    end
  elseif buf:len() > 2 then
    root:add(f.payload, buf(2))
  end

  pinfo.cols.info = info
end

function M.register()
  local udp = DissectorTable.get("udp.port")
  udp:add(4243, proto)
  udp:add(4244, proto)
end

return M
