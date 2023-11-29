local json = require"st.json"
local utils = require "st.utils"
local im = require  "st.matter.interaction_model"
local capabilities = require "st.capabilities"
local log = require "log"



local SUBSCRIBED_ATTRIBUTE_LIST = "__subscribed_attr_list_bypass" --store in db to persist subscriptions
local report_allow_list = {ID="REPORT_ALLOW_LIST"}
local bypassCapability = capabilities["scalebrook41259.bypassRoute"]

local function logI(message)
  log.info_with({hub_logs=true},string.format("Bypass: %s",utils.stringify_table(message)))
end

local function logD(message)
  log.debug_with({hub_logs=true},string.format("Bypass Debug: %s", utils.stringify_table(message)))
end

--Interaction Response status
local STATUS = {
  SUCCESS = 0x00,
  FAILURE = 0x01,
  INVALID_SUBSCRIPTION = 0x7D,
  UNSUPPORTED_ACCESS = 0x7E,
  UNSUPPORTED_ENDPOINT = 0x7F,
  INVALID_ACTION = 0x80,
  UNSUPPPORTED_COMMAND = 0x81,
  INVALID_COMMAND = 0x85,
  UNSUPPORTED_ATTRIBUTE = 0x86,
  CONSTRAINT_ERROR = 0x87,
  UNSUPPPORTED_WRITE = 0x88,
  RESOURCE_EXHAUSTED = 0x89,
  NOT_FOUND = 0x8B,
  UNREPORTABLE_ATTRIBUTE = 0x8C,
  INVALID_DATA_TYPE = 0x8D,
  UNSUPPORTED_READ = 0x8F,
  TIMEOUT = 0x94,
  BUSY = 0x9C,
  UNSUPPORTED_CLUSTER = 0xC3,
  NO_UPSTREAM_SUBSCRIPTION = 0xC5,
  NEEDS_TIMED_INTERACTION = 0xC6,
  UNSUPPORTED_EVENT = 0xC7,
  PATHS_EXHAUSTED = 0xC8,
  TIMED_REQUEST_MISMATCH = 0xC9,
  FAILSAFE_REQUIRED = 0xCA,
}
local STATUS_STRINGS = {
  [STATUS.SUCCESS] = "SUCCESS",
  [STATUS.FAILURE] = "FAILURE",
  [STATUS.INVALID_SUBSCRIPTION] = "INVALID_SUBSCRIPTION",
  [STATUS.UNSUPPORTED_ACCESS] = "UNSUPPORTED_ACCESS",
  [STATUS.UNSUPPORTED_ENDPOINT] = "UNSUPPORTED_ENDPOINT",
  [STATUS.INVALID_ACTION] = "INVALID_ACTION",
  [STATUS.UNSUPPPORTED_COMMAND] = "UNSUPPPORTED_COMMAND",
  [STATUS.INVALID_COMMAND] = "INVALID_COMMAND",
  [STATUS.UNSUPPORTED_ATTRIBUTE] = "UNSUPPORTED_ATTRIBUTE",
  [STATUS.CONSTRAINT_ERROR] = "CONSTRAINT_ERROR",
  [STATUS.UNSUPPPORTED_WRITE] = "UNSUPPPORTED_WRITE",
  [STATUS.RESOURCE_EXHAUSTED] = "RESOURCE_EXHAUSTED",
  [STATUS.NOT_FOUND] = "NOT_FOUND",
  [STATUS.UNREPORTABLE_ATTRIBUTE] = "UNREPORTABLE_ATTRIBUTE",
  [STATUS.INVALID_DATA_TYPE] = "INVALID_DATA_TYPE",
  [STATUS.UNSUPPORTED_READ] = "UNSUPPORTED_READ",
  [STATUS.TIMEOUT] = "TIMEOUT",
  [STATUS.BUSY] = "BUSY",
  [STATUS.UNSUPPORTED_CLUSTER] = "UNSUPPORTED_CLUSTER",
  [STATUS.NO_UPSTREAM_SUBSCRIPTION] = "NO_UPSTREAM_SUBSCRIPTION",
  [STATUS.NEEDS_TIMED_INTERACTION] = "NEEDS_TIMED_INTERACTION",
  [STATUS.UNSUPPORTED_EVENT] = "UNSUPPORTED_EVENT",
  [STATUS.PATHS_EXHAUSTED] = "PATHS_EXHAUSTED",
  [STATUS.TIMED_REQUEST_MISMATCH] = "TIMED_REQUEST_MISMATCH",
  [STATUS.FAILSAFE_REQUIRED] = "FAILSAFE_REQUIRED",
}

local RESPONSE_TYPES = {
  REPORT_DATA = 0,
  INVOKE_RESPONSE = 1,
  WRITE_RESPONSE = 2,
  SUBSCRIBE_RESPONSE = 3
}

local RESPONSE_TO_STRING = {
    [0] = "REPORT_DATA",
    [1] = "INVOKE_RESPONSE",
    [2] = "WRITE_RESPONSE",
    [3] = "SUBSCRIBE_RESPONSE",
}

-----------------------------
--matter-bypass-handler utils
-----------------------------

--Takes tlv string and builds an array of hex strings representing the tlv elements.
local build_tlv_array = function(tlv)
  local out = {}
  for i = 1, #tlv do
    local hex_val = string.format("%02X", string.byte(tlv, i))
    table.insert(out, hex_val)
  end
  return out
end

--Matter event is bypassed as json string capability event only if the ib is valid
local function emit_if_valid_ib(device, ib, list, response_type, list_id)
  logD(string.format("Response type = %s", response_type))
  logD(string.format("IB Report %s", utils.stringify_table(ib)))

  local cluster_id = ib.info_block.cluster_id
  local reqs_for_cluster = list[string.format(cluster_id)] or {attribute_ids={}, command_ids={}}

  --response object
  local response = {
    id = os.time(),
    type = RESPONSE_TO_STRING[response_type],
    cluster_id = cluster_id,
    endpoint_id = ib.info_block.endpoint_id,
    status = STATUS_STRINGS[ib.status]  or "NULL"
  }

  if response_type == RESPONSE_TYPES.INVOKE_RESPONSE then
    local command_id = ib.info_block.command_id
    if reqs_for_cluster.command_ids[string.format(command_id)] then

      reqs_for_cluster.command_ids[string.format(command_id)] = reqs_for_cluster.command_ids[string.format(command_id)] - 1
      reqs_for_cluster.command_ids[string.format(command_id)] = (reqs_for_cluster.command_ids[string.format(command_id)] == 0) and nil
      response["command_id"] = command_id
      response = json.encode(response)

      logI(string.format("Emitting capability with response : %s", response))
      device:emit_event_for_endpoint(ib.info_block.endpoint_id, bypassCapability.receiveData(response, {visibility = {displayed = false}}))
      list[string.format(cluster_id)] = reqs_for_cluster
      return list
    end
  end

  if response_type == RESPONSE_TYPES.REPORT_DATA or response_type == RESPONSE_TYPES.WRITE_RESPONSE then
    local attr_id = ib.info_block.attribute_id
    if reqs_for_cluster.attribute_ids[string.format(attr_id)] then

      if list_id ~= "SUBSCRIBED_ATTRIBUTE_LIST" and reqs_for_cluster.attribute_ids[string.format(attr_id)] then
        reqs_for_cluster.attribute_ids[string.format(attr_id)] = reqs_for_cluster.attribute_ids[string.format(attr_id)] - 1
        reqs_for_cluster.attribute_ids[string.format(attr_id)] = (reqs_for_cluster.attribute_ids[string.format(attr_id)] == 0) and nil
      end

      response["attribute_id"] = attr_id
      local tlv = ib.info_block.tlv or ""
      local tlv_array = build_tlv_array(tlv)
      response["tlv"] = tlv_array
      response = json.encode(response)

      logI(string.format("Emitting capability with response : %s",response))
      device:emit_event_for_endpoint(ib.info_block.endpoint_id, bypassCapability.receiveData(response, {visibility = {displayed = false}}))
      list[string.format(cluster_id)] = reqs_for_cluster
      return list
    end
  end
  return false
end

--This method is invoked as a fallback handler of the base driver or as a part of sub_driver's matter handlers.
--Bypasses matter events through bypass capability as a json string.
local function matter_bypass_handler(driver, device, ib, response)
  logI("Invoked matter_bypass_handler")
  if ib~=nil then
    if (response.type ~= nil) then

      --read allow list check
      local list = emit_if_valid_ib(device, ib, report_allow_list, response.type, report_allow_list.ID)
      if list then
        --assign list with updated info.
        report_allow_list = list
        return
      end

      --subscribe allow list check
      local subscribed_attr_list = device:get_field(SUBSCRIBED_ATTRIBUTE_LIST) or {ID="SUBSCRIBED_ATTRIBUTE_LIST"}
      if emit_if_valid_ib(device, ib, subscribed_attr_list, response.type, subscribed_attr_list.ID) then return end
    end

    --Not an anticipated response
    logI("Invalid response, dropping Info Block.")
  end
end

---------------------------------
--bypass capability handler utils
---------------------------------

--Checks whether subscription for an attribute exists
local subscribe_request_exists = function(list, cluster_id, attr_id)
    local reqs_for_cluster = list[string.format(cluster_id)]
    if reqs_for_cluster and reqs_for_cluster.attribute_ids[string.format(attr_id)] then return true end
    return false
end

--Updates list with an entry for an appropriate response that is anticipated as result of some operation.
local add_to_list = function(cluster_id, id, list, req_type)
  local cluster_req_obj = list[string.format(cluster_id)] or {attribute_ids = {}, command_ids={}}
  logD(string.format("Inserting %s request to %s", req_type, list.ID))
  if req_type == "INVOKE_WITH_TYPE" or req_type == "INVOKE"then
    cluster_req_obj.command_ids[string.format(id)] = (cluster_req_obj.command_ids[string.format(id)] or 0) + 1
  else
    if list.ID == "SUBSCRIBED_ATTRIBUTE_LIST" then
      cluster_req_obj.attribute_ids[string.format(id)] = id
    else
      cluster_req_obj.attribute_ids[string.format(id)] = (cluster_req_obj.attribute_ids[id] or 0) + 1
    end
  end

  list[string.format(cluster_id)] = cluster_req_obj
  return list
end

--used as a metatable to validate request fields, throws appropriate error incase request fields
--for an operation is missing.
local validate_json_mt = {}
validate_json_mt.__index = function(self, key)
  return error(string.format("Invalid Request, '%s' not found.", key))
end

--Takes an array of hex strings and builds tlv string representing the tlv elements.
local build_tlv_string = function(tlv_array)
  local tlv = ""
  for _, hex in ipairs(tlv_array) do
    tlv = tlv..string.char(tonumber(hex, 16))
  end
  return tlv
end

--parses json string request and builds appropriate interaction request perataining to the operation.
--SUBSCRIBE operation does not return a request as it uses lua-libs convenience methods.
local function build_interaction_request(device, cmd)
  local cluster_base = require "st.matter.cluster_base"
  local status = 1
  local data = {}

  data = json.decode(cmd.args.data)

  --validate json request and raise error in return.
  setmetatable(data, validate_json_mt)

  local operation = data.op
  local ops = {
    --Performs SUBSCRIBE interaction Request
    ['SUBSCRIBE'] = function()
      logI("Received SUBSCRIBE request.")

      local cluster_id = data.cluster_id
      local attr_id = data.attribute_id
      local subscribed_attr_list = device:get_field(SUBSCRIBED_ATTRIBUTE_LIST) or {ID="SUBSCRIBED_ATTRIBUTE_LIST"}

      if not subscribe_request_exists(subscribed_attr_list, cluster_id, attr_id) then
        subscribed_attr_list = add_to_list(cluster_id, attr_id, subscribed_attr_list, operation)
        device:set_field(SUBSCRIBED_ATTRIBUTE_LIST, subscribed_attr_list, {persist = true})
      end
      local attr = {
        ID = attr_id,
        cluster = cluster_id,
      }
      device:add_subscribed_attribute(attr)
      device:subscribe()
      return
    end,

    ['READ'] = function()
      --Performs READ interaction Request
      logI("Received READ request.")

      local cluster_id = data.cluster_id
      local attr_id = data.attribute_id

      local req = cluster_base.read(device, device.MATTER_DEFAULT_ENDPOINT,cluster_id, attr_id, nil)
      report_allow_list = add_to_list(cluster_id, attr_id, report_allow_list, operation)
      return req
    end,

    ['WRITE'] = function()
      --Performs WRITE Interaction Request
      logI("Received WRITE request.")

      local payload_data = {
        info_blocks = {
          {
            attribute_id = data.attribute_id,
            cluster_id = data.cluster_id,
            endpoint_id = device.MATTER_DEFAULT_ENDPOINT,
            tlv = build_tlv_string(data.tlv)
          },
        },
        type="2"
      }

      --set metatables to enable serialize methods.
      local req = payload_data
      local iib_mt = im.InteractionInfoBlock
      setmetatable(req.info_blocks[1], iib_mt)
      local ir_mt = im.InteractionRequest
      setmetatable(req, ir_mt)

      report_allow_list = add_to_list(data.cluster_id, data.attribute_id, report_allow_list, operation)
      return req
    end,

    ['WRITE_WITH_TYPE'] = function()
      --Performs WRITE_WITH_TYPE Interaction Request
      logI("Receive WRITE_WITH_TYPE request.")

      local cluster_id = data.cluster_id
      local attr_id = data.attribute_id
      local data_types = require "st.matter.data_types"
      local TLVParser = require "st.matter.TLV.TLVParser"
      local payload_data = data.data
      local attr_type = data.attribute_type

      attr_type = require ("st.matter.data_types."..attr_type)
      payload_data = data_types.validate_or_build_type(payload_data, attr_type)
      local req = cluster_base.write(device, device.MATTER_DEFAULT_ENDPOINT, cluster_id, attr_id, nil, payload_data)
      report_allow_list = add_to_list(cluster_id, attr_id, report_allow_list, operation)
      return req
    end,

    ['INVOKE'] = function()
      logI("Received INVOKE request.")
      local cluster_id = data.cluster_id
      local endpoint_id = device.MATTER_DEFAULT_ENDPOINT
      local command_id = data.command_id
      local tlv_encoded = build_tlv_string(data.tlv)

      local command_info = {
        id = command_id,
        name = "BypassedMatterCommand",
        tlv_encoded = tlv_encoded
      }

      --helps raise error in case of missing fields.
      setmetatable(command_info, validate_json_mt)

      local command_builder = require "bypass.commandbuilder"

      local req = command_builder:build_command_with_tlv(device, endpoint_id, cluster_id, command_info)
      report_allow_list = add_to_list(cluster_id, command_info.id, report_allow_list, operation)
      return req
    end,

    ['INVOKE_WITH_TYPE'] = function()
      logI("Received INVOKE_WITH_TYPE request.")
      local cluster_id = data.cluster_id
      local endpoint_id = device.MATTER_DEFAULT_ENDPOINT
      local command_id = data.command_id
      local args = data.args
      local command_info = {
        name = "BypassedMatterCommand",
        id = command_id,
        args = {}
      }
      for _, arg in ipairs(args) do
        local new_arg = {
          id = arg.id,
          name = string.format(arg.id),
          data_type = arg.data_type,
          value = arg.value
        }
        table.insert(command_info.args, new_arg)
      end

      --helps raise error in case of missing fields.
      setmetatable(command_info, validate_json_mt)

      local command_builder = require "bypass.commandbuilder"

      local req = command_builder(device, endpoint_id, cluster_id, command_info)
      report_allow_list = add_to_list(cluster_id, command_info.id, report_allow_list, operation)
      return req
    end
  }
  if ops[operation] then return ops[operation]() end
  return error(string.format("Invalid request, %s is not a valid operation.", operation))
end

--Sends appropriate interaction request to device or appropriate failure message
--incase building the interaction request fails
local function handle_bypass_capability(driver, device, cmd)
  local status, res = pcall(build_interaction_request, device, cmd)
  local req = res
  if not status then
    local error_block = {
      id = os.time(),
      status = "FAILURE",
      message = "Faced error performing operation."..res
    }
    error_block = json.encode(error_block)
    device:emit_event_for_endpoint(device.MATTER_DEFAULT_ENDPOINT, bypassCapability.receiveData(error_block, {visibility = {displayed = false}}))
    log.error_with({hub_logs=true},string.format("Bypass: Faced following error while building request : %s", utils.stringify_table(res)))
    return
  else
    if req ~= nil then
      logI(string.format("Sending interaction request : %s", utils.stringify_table(req)))
      logD("Map contents post req builder")
      logD(report_allow_list)
      device:send(req)
    end
  end
end

--bypass template with handlers
local bypass = {
    matter_handlers = {
        fallback = matter_bypass_handler,
    },
    capability_handlers = {
        [bypassCapability.ID] = {
            [bypassCapability.commands.sendData.NAME] = handle_bypass_capability,
        }
    },
    supported_capabilities = {
        bypassCapability
    }
}


-- Injects matter_bypass_handler to sub_driver's matter handlers.
--TODO: Include a flag in sub-driver to consider for bypass?
local inject_bypass_handlers = function(cls, driver_template)
    utils.merge(driver_template, bypass)
    utils.update(driver_template.matter_handlers, bypass.matter_handlers)

    for index, sub_driver in ipairs(driver_template.sub_drivers) do
        logI("Injecting bypass handlers for "..(sub_driver.NAME or string.format("sub driver %s", index)))
        for clus, attrs in pairs(sub_driver.matter_handlers.attr) do
            for attr_id, handler in pairs(attrs) do
                --wrap matter handler and bypass handler
                driver_template.sub_drivers[index].matter_handlers.attr[clus][attr_id] = function(driver, device, ib, response)
                    handler(driver, device, ib, response)
                    ib = {info_block = ib, status=0, endpoint_id = ib.endpoint_id}
                    matter_bypass_handler(driver, device, ib, response)
                end
            end
        end
    end
    return driver_template
end

setmetatable(bypass, {__call = inject_bypass_handlers})

return bypass