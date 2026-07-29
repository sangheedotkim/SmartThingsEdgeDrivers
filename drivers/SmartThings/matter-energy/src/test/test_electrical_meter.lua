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

local ELECTRICAL_METER_EP = 20

local ELECTRICAL_METER_DEVICE_TYPE_ID = 0x0514
local ELECTRICAL_SENSOR_DEVICE_TYPE_ID = 0x0510

if version.api < 11 then
  clusters.ElectricalEnergyMeasurement = require "ElectricalEnergyMeasurement"
  clusters.ElectricalPowerMeasurement = require "ElectricalPowerMeasurement"
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
    {
      endpoint_id = ELECTRICAL_METER_EP,
      clusters = {
        { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = 15 }, -- ALL
        { cluster_id = clusters.ElectricalPowerMeasurement.ID,  cluster_type = "SERVER" },
      },
      device_types = {
        { device_type_id = ELECTRICAL_METER_DEVICE_TYPE_ID,   device_type_revision = 1 },
        { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID,   device_type_revision = 1 },
      }
    }
  }
})

local function test_init()
  test.disable_startup_messages()
  test.mock_device.add_test_device(mock_device)
  local cluster_subscribe_list = {
    clusters.ElectricalPowerMeasurement.attributes.ActivePower,
    clusters.ElectricalPowerMeasurement.attributes.RMSVoltage,
    clusters.ElectricalPowerMeasurement.attributes.RMSCurrent,
    clusters.ElectricalEnergyMeasurement.attributes.PeriodicEnergyExported,
    clusters.ElectricalEnergyMeasurement.attributes.PeriodicEnergyImported,
  }
  local subscribe_request = cluster_subscribe_list[1]:subscribe(mock_device)
  for i, cluster in ipairs(cluster_subscribe_list) do
    if i > 1 then
      subscribe_request:merge(cluster:subscribe(mock_device))
    end
  end
  test.socket.device_lifecycle:__queue_receive({ mock_device.id, "added" })
  test.socket.device_lifecycle:__queue_receive({ mock_device.id, "init" })
  test.socket.matter:__expect_send({ mock_device.id, subscribe_request })

  test.socket.device_lifecycle:__queue_receive({ mock_device.id, "doConfigure"})
  mock_device:expect_metadata_update({ provisioning_state = "PROVISIONED" })
end
test.set_test_init_function(test_init)

test.register_coroutine_test(
  "Appropriate powerMeter capability events must be sent in 'W' on receiving ActivePower events",
  function()
    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalPowerMeasurement.attributes.ActivePower:build_test_report_data(mock_device,
        ELECTRICAL_METER_EP,
        30000)
    })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.powerMeter.power({ value = 30.0, unit = "W" })))
  end,
  {
     min_api_version = 17
  }
)

test.register_coroutine_test(
  "Appropriate voltageMeasurement capability events must be sent in 'V' on receiving RMSVoltage events",
  function()
    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalPowerMeasurement.attributes.RMSVoltage:build_test_report_data(mock_device,
        ELECTRICAL_METER_EP,
        230000)
    })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.voltageMeasurement.voltage({ value = 230.0, unit = "V" })))
  end,
  {
     min_api_version = 17
  }
)

test.register_coroutine_test(
  "Appropriate currentMeasurement capability events must be sent in 'A' on receiving RMSCurrent events",
  function()
    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalPowerMeasurement.attributes.RMSCurrent:build_test_report_data(mock_device,
        ELECTRICAL_METER_EP,
        15000)
    })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.currentMeasurement.current({ value = 15.0, unit = "A" })))
  end,
  {
     min_api_version = 17
  }
)

test.register_coroutine_test(
  "Ensure the cumulative energy imported powerConsumption is reported every 15 minutes",
  function()
    test.mock_time.advance_time(901) -- move time 15 minutes past 0

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
        .CumulativeEnergyImported:build_test_report_data(mock_device,
      ELECTRICAL_METER_EP,
      clusters.ElectricalEnergyMeasurement.types.EnergyMeasurementStruct({ energy = 100000, start_timestamp = 0, end_timestamp = 0, start_systime = 0, end_systime = 0, apparent_energy = 0, reactive_energy = 0 })) }) --100Wh

    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy",
        capabilities.energyMeter.energy({
          value = 100, unit = "Wh"
        }))
    )

    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy",
        capabilities.powerConsumptionReport.powerConsumption({
          start = "1970-01-01T00:00:00Z",
          ["end"] = "1970-01-01T00:15:00Z",
          deltaEnergy = 0.0,
          energy = 100
        })
      )
    )

    test.wait_for_events()
    test.mock_time.advance_time(2000)

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
        .CumulativeEnergyImported:build_test_report_data(mock_device,
      ELECTRICAL_METER_EP,
      clusters.ElectricalEnergyMeasurement.types.EnergyMeasurementStruct({ energy = 200000, start_timestamp = 0, end_timestamp = 0, start_systime = 0, end_systime = 0, apparent_energy = 0, reactive_energy = 0 })) }) --200Wh

    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy",
        capabilities.energyMeter.energy({
          value = 200, unit = "Wh"
        })))

    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy",
        capabilities.powerConsumptionReport.powerConsumption({
          energy = 200,
          deltaEnergy = 100,
          start = "1970-01-01T00:15:01Z",
          ["end"] = "1970-01-01T00:48:20Z"
        }))
    )
  end,
  {
    test_init = function()
      test_init()
    end,
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "Ensure the cumulative energy exported powerConsumption is reported every 15 minutes",
  function()
    test.mock_time.advance_time(901) -- move time 15 minutes past 0

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
        .CumulativeEnergyExported:build_test_report_data(mock_device,
      ELECTRICAL_METER_EP,
      clusters.ElectricalEnergyMeasurement.types.EnergyMeasurementStruct({ energy = 400000, start_timestamp = 0, end_timestamp = 0, start_systime = 0, end_systime = 0, apparent_energy = 0, reactive_energy = 0 })) }) --400Wh

    test.socket.capability:__expect_send(
      mock_device:generate_test_message("exportedEnergy",
        capabilities.energyMeter.energy({
          value = 400, unit = "Wh"
        }))
    )

    test.socket.capability:__expect_send(
      mock_device:generate_test_message("exportedEnergy",
        capabilities.powerConsumptionReport.powerConsumption({
          start = "1970-01-01T00:00:00Z",
          ["end"] = "1970-01-01T00:15:00Z",
          deltaEnergy = 0.0,
          energy = 400
        })
      )
    )

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
