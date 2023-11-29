
local data_types = require "st.matter.data_types"
local log = require "log"
local TLVParser = require "st.matter.TLV.TLVParser"
local cluster_base = require "st.matter.cluster_base"
local utils = require "st.utils"
local im = require "st.matter.interaction_model"

-----------------------------------------------------------
-- Command builder for bypass
-----------------------------------------------------------

--- @class Command: builder for command request.
--- @alias Command
local Command = {}

Command.NAME = ""
Command.ID = nil

--- Initialize the matter Command
--- @return st.matter.interaction_model.InteractionRequest of type INVOKE
function Command:init(device, endpoint_id, cluster_id, command)
  local out = {}
  local cluster = {ID = cluster_id}
  setmetatable(cluster, {__index = cluster_base})
  self._cluster = cluster

  self.NAME = command.name or "BypassedMatterCommand"
  self.ID = command.id
  local args = command.args
  for i,arg in ipairs(args) do
      local arg_type =  require ("st.matter.data_types."..arg.data_type)
      out[arg.name] = data_types.validate_or_build_type(arg.value, arg_type, arg.name)
      out[arg.name].field_id = arg.id
  end
  setmetatable(out, {
    __index = Command,
  })

  log.info_with({hub_logs=true},string.format("Bypass Invoke args = %s", utils.stringify_table(out)))

  return self._cluster:build_cluster_command(
    device,
    out,
    endpoint_id,
    cluster_id,
    self.ID --command-id
  )
end

--builds a command interaction request with tlv only
function Command:build_command_with_tlv(device, endpoint_id, cluster_id, command)
  local cluster = {ID = cluster_id}
  local tlv_encoded = command.tlv_encoded

  setmetatable(cluster, {__index = cluster_base})
  self._cluster = cluster
  local interaction_info_block = im.InteractionInfoBlock(
    endpoint_id, cluster_id, nil, nil, command.id,
    tlv_encoded
    )
  local interaction_info_blocks = {interaction_info_block}
  local command_request = im.InteractionRequest(
    im.InteractionRequest.RequestType.INVOKE, interaction_info_blocks, timed_invoke
  )
  return command_request
end

function Command:deserialize(tlv_buf)
  return TLVParser.decode_tlv(tlv_buf)
end

setmetatable(Command, {__call = Command.init})

return Command