local cluster_base = require "st.matter.cluster_base"
local data_types = require "st.matter.data_types"
local TLVParser = require "st.matter.TLV.TLVParser"

local RMSCurrent = {
  ID = 0x000C,
  NAME = "RMSCurrent",
  base_type = require "st.matter.data_types.Int64",
}

function RMSCurrent:new_value(...)
  local o = self.base_type(table.unpack({...}))

  return o
end

function RMSCurrent:read(device, endpoint_id)
  return cluster_base.read(
    device,
    endpoint_id,
    self._cluster.ID,
    self.ID,
    nil
  )
end

function RMSCurrent:subscribe(device, endpoint_id)
  return cluster_base.subscribe(
    device,
    endpoint_id,
    self._cluster.ID,
    self.ID,
    nil
  )
end

function RMSCurrent:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

function RMSCurrent:build_test_report_data(
  device,
  endpoint_id,
  value,
  status
)
  local data = data_types.validate_or_build_type(value, self.base_type)

  return cluster_base.build_test_report_data(
    device,
    endpoint_id,
    self._cluster.ID,
    self.ID,
    data,
    status
  )
end

function RMSCurrent:deserialize(tlv_buf)
  local data = TLVParser.decode_tlv(tlv_buf)

  return data
end

setmetatable(RMSCurrent, {__call = RMSCurrent.new_value, __index = RMSCurrent.base_type})
return RMSCurrent
