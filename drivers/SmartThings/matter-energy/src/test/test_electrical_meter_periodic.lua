-- Copyright 2025 SmartThings
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local test = require "integration_test"
local clusters = require "st.matter.clusters"
local capabilities = require "st.capabilities"
local t_utils = require "integration_test.utils"
local version = require "version"

-- A meter that only reports periodically, wired up alongside sub-sensors that do support cumulative
-- reports. The cumulative-vs-periodic decision has to be made from the endpoints the driver actually
-- reads, so the sub-sensors' CumulativeEnergy feature must not make the driver discard the meter's
-- periodic reports, which are the only energy this device would ever report.
local ELECTRICAL_METER_EP = 20
local SUB_SENSOR_EP_ONE = 21
local SUB_SENSOR_EP_TWO = 22

local ELECTRICAL_METER_DEVICE_TYPE_ID = 0x0514
local ELECTRICAL_SENSOR_DEVICE_TYPE_ID = 0x0510

local IMPORTED_EXPORTED_PERIODIC = 0x0B -- IMPE | EXPE | PERE
local ALL_ENERGY_FEATURES = 0x0F        -- IMPE | EXPE | CUME | PERE

if version.api < 11 then
clusters.ElectricalEnergyMeasurement = require "ElectricalEnergyMeasurement"
clusters.ElectricalPowerMeasurement = require "ElectricalPowerMeasurement"
end

local function energy_measurement(energy_mWh)
  return clusters.ElectricalEnergyMeasurement.types.EnergyMeasurementStruct({
    energy = energy_mWh,
    start_timestamp = 0,
    end_timestamp = 0,
    start_systime = 0,
    end_systime = 0,
    apparent_energy = 0,
    reactive_energy = 0
  })
end

local function electrical_sensor_endpoint(endpoint_id, feature_map, device_types)
  local endpoint_device_types = {
    { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID, device_type_revision = 1 } -- ELECTRICAL_SENSOR
  }
  for _, device_type_id in ipairs(device_types or {}) do
    table.insert(endpoint_device_types, { device_type_id = device_type_id, device_type_revision = 1 })
  end
  return {
    endpoint_id = endpoint_id,
    clusters = {
      { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = feature_map },
      { cluster_id = clusters.ElectricalPowerMeasurement.ID, cluster_type = "SERVER" },
    },
    device_types = endpoint_device_types
  }
end

local mock_device = test.mock_device.build_test_matter_device({
  profile = t_utils.get_profile_definition("electrical-meter.yml"),
  manufacturer_info = {
    vendor_id = 0x0000,
    product_id = 0x0000,
  },
  endpoints = {
    {
      endpoint_id = 0,
      clusters = {
        { cluster_id = clusters.Basic.ID, cluster_type = "SERVER" },
      },
      device_types = {
        { device_type_id = 0x0016, device_type_revision = 1 }, -- RootNode
      }
    },
    electrical_sensor_endpoint(ELECTRICAL_METER_EP, IMPORTED_EXPORTED_PERIODIC, { ELECTRICAL_METER_DEVICE_TYPE_ID }),
    electrical_sensor_endpoint(SUB_SENSOR_EP_ONE, ALL_ENERGY_FEATURES),
    electrical_sensor_endpoint(SUB_SENSOR_EP_TWO, ALL_ENERGY_FEATURES)
  }
})

local function build_subscribe_request()
  local cluster_subscribe_list = {
    clusters.ElectricalPowerMeasurement.attributes.ActivePower,
    clusters.ElectricalPowerMeasurement.attributes.RMSVoltage,
    clusters.ElectricalPowerMeasurement.attributes.RMSCurrent,
    clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyImported,
    clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyExported,
    clusters.ElectricalEnergyMeasurement.attributes.PeriodicEnergyImported,
    clusters.ElectricalEnergyMeasurement.attributes.PeriodicEnergyExported
  }
  local subscribe_request = cluster_subscribe_list[1]:subscribe(mock_device)
  for i, cluster in ipairs(cluster_subscribe_list) do
    if i > 1 then
      subscribe_request:merge(cluster:subscribe(mock_device))
    end
  end
  return subscribe_request
end

local function test_init()
  test.disable_startup_messages()
  test.mock_device.add_test_device(mock_device)
  test.socket.device_lifecycle:__queue_receive({ mock_device.id, "added" })
  test.socket.device_lifecycle:__queue_receive({ mock_device.id, "init" })
  test.socket.matter:__expect_send({ mock_device.id, build_subscribe_request() })

  test.socket.device_lifecycle:__queue_receive({ mock_device.id, "doConfigure"})
  mock_device:expect_metadata_update({ profile = "electrical-meter" })
  mock_device:expect_metadata_update({ provisioning_state = "PROVISIONED" })
end
test.set_test_init_function(test_init)

test.register_coroutine_test(
  "Periodic imports from the meter endpoint accumulate when only the sub-sensors support cumulative reports",
  function()
    test.mock_time.advance_time(901) -- move time 15 minutes past 0 so that powerConsumption is reported

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .PeriodicEnergyImported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(1000000)) }) --1000Wh
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy", capabilities.energyMeter.energy({ value = 1000, unit = "Wh" }))
    )
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy", capabilities.powerConsumptionReport.powerConsumption({
        start = "1970-01-01T00:00:00Z",
        ["end"] = "1970-01-01T00:15:00Z",
        deltaEnergy = 0.0,
        energy = 1000
      }))
    )

    -- periodic reports are added to the running total rather than replacing it
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .PeriodicEnergyImported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(500000)) }) --500Wh
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy", capabilities.energyMeter.energy({ value = 1500, unit = "Wh" }))
    )

    -- a sub-sensor's cumulative report is still discarded, cumulative or not
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyImported:build_test_report_data(mock_device, SUB_SENSOR_EP_ONE, energy_measurement(8500000)) })
    test.wait_for_events()

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .PeriodicEnergyImported:build_test_report_data(mock_device, SUB_SENSOR_EP_TWO, energy_measurement(2000000)) })
    test.wait_for_events()
  end,
  {
    test_init = function()
      test_init()
    end,
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "Periodic exports from the meter endpoint accumulate when only the sub-sensors support cumulative reports",
  function()
    test.mock_time.advance_time(901) -- move time 15 minutes past 0 so that powerConsumption is reported

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .PeriodicEnergyExported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(400000)) }) --400Wh
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("exportedEnergy", capabilities.energyMeter.energy({ value = 400, unit = "Wh" }))
    )
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("exportedEnergy", capabilities.powerConsumptionReport.powerConsumption({
        start = "1970-01-01T00:00:00Z",
        ["end"] = "1970-01-01T00:15:00Z",
        deltaEnergy = 0.0,
        energy = 400
      }))
    )

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .PeriodicEnergyExported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(100000)) }) --100Wh
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("exportedEnergy", capabilities.energyMeter.energy({ value = 500, unit = "Wh" }))
    )

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyExported:build_test_report_data(mock_device, SUB_SENSOR_EP_ONE, energy_measurement(4000000)) })
    test.wait_for_events()
  end,
  {
    test_init = function()
      test_init()
    end,
    min_api_version = 17
  }
)

test.run_registered_tests()
