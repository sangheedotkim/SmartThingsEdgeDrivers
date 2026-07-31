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

-- The Electrical Meter endpoint meters the grid connection point, so it is the source of truth for
-- import and export. The sub-sensors measure individual circuits downstream of it, so their energy
-- has already been metered and must be left out of the totals.
local ELECTRICAL_METER_EP = 20
local SUB_SENSOR_EP_ONE = 21
local SUB_SENSOR_EP_TWO = 22

local ELECTRICAL_METER_DEVICE_TYPE_ID = 0x0514
local ELECTRICAL_SENSOR_DEVICE_TYPE_ID = 0x0510

local TOTAL_CUMULATIVE_ENERGY_IMPORTED = "__total_cumulative_energy_imported"

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
        { cluster_id = clusters.ElectricalPowerMeasurement.ID, cluster_type = "SERVER" },
      },
      device_types = {
        { device_type_id = ELECTRICAL_METER_DEVICE_TYPE_ID, device_type_revision = 1 }, -- ELECTRICAL_METER
        { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID, device_type_revision = 1 } -- ELECTRICAL_SENSOR
      }
    },
    {
      endpoint_id = SUB_SENSOR_EP_ONE,
      clusters = {
        { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = 15 }, -- ALL
        { cluster_id = clusters.ElectricalPowerMeasurement.ID, cluster_type = "SERVER" },
      },
      device_types = {
        { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID, device_type_revision = 1 } -- ELECTRICAL_SENSOR
      }
    },
    {
      endpoint_id = SUB_SENSOR_EP_TWO,
      clusters = {
        { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = 15 }, -- ALL
        { cluster_id = clusters.ElectricalPowerMeasurement.ID, cluster_type = "SERVER" },
      },
      device_types = {
        { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID, device_type_revision = 1 } -- ELECTRICAL_SENSOR
      }
    }
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
  "Assert profile applied over doConfigure",
  function()
    test.socket.device_lifecycle:__queue_receive({ mock_device.id, "doConfigure" })
    mock_device:expect_metadata_update({ profile = "electrical-meter" })
    mock_device:expect_metadata_update({ provisioning_state = "PROVISIONED" })
  end,
  {
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "Imported energy is taken from the meter endpoint while the sub-sensor endpoints are ignored",
  function()
    test.mock_time.advance_time(901) -- move time 15 minutes past 0 so that powerConsumption is reported

    -- summing the sub-sensors in would double count the energy the meter has already metered
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyImported:build_test_report_data(mock_device, SUB_SENSOR_EP_ONE, energy_measurement(8500000)) }) --8500Wh
    test.wait_for_events()

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyImported:build_test_report_data(mock_device, SUB_SENSOR_EP_TWO, energy_measurement(2000000)) }) --2000Wh
    test.wait_for_events()

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyImported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(5000000)) }) --5000Wh
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy", capabilities.energyMeter.energy({ value = 5000, unit = "Wh" }))
    )
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy", capabilities.powerConsumptionReport.powerConsumption({
        start = "1970-01-01T00:00:00Z",
        ["end"] = "1970-01-01T00:15:00Z",
        deltaEnergy = 0.0,
        energy = 5000
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
  "Exported energy is taken from the meter endpoint while the sub-sensor endpoints are ignored",
  function()
    test.mock_time.advance_time(901) -- move time 15 minutes past 0 so that powerConsumption is reported

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyExported:build_test_report_data(mock_device, SUB_SENSOR_EP_ONE, energy_measurement(4000000)) }) --4000Wh
    test.wait_for_events()

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyExported:build_test_report_data(mock_device, SUB_SENSOR_EP_TWO, energy_measurement(3000000)) }) --3000Wh
    test.wait_for_events()

    -- export keeps its own 15 minute window, tracked separately from the imported reports
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyExported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(2000000)) }) --2000Wh
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("exportedEnergy", capabilities.energyMeter.energy({ value = 2000, unit = "Wh" }))
    )
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("exportedEnergy", capabilities.powerConsumptionReport.powerConsumption({
        start = "1970-01-01T00:00:00Z",
        ["end"] = "1970-01-01T00:15:00Z",
        deltaEnergy = 0.0,
        energy = 2000
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
  "RMSVoltage and RMSCurrent are only reported from the meter endpoint",
  function()
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .RMSVoltage:build_test_report_data(mock_device, SUB_SENSOR_EP_ONE, 120000) })
    test.wait_for_events()

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .RMSVoltage:build_test_report_data(mock_device, ELECTRICAL_METER_EP, 230000) })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.voltageMeasurement.voltage({ value = 230.0, unit = "V" })))

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .RMSCurrent:build_test_report_data(mock_device, SUB_SENSOR_EP_TWO, 1000) })
    test.wait_for_events()

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .RMSCurrent:build_test_report_data(mock_device, ELECTRICAL_METER_EP, 5500) })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.currentMeasurement.current({ value = 5.5, unit = "A" })))
  end,
  {
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "ActivePower is only reported from the meter endpoint",
  function()
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .ActivePower:build_test_report_data(mock_device, SUB_SENSOR_EP_ONE, 99000) })
    test.wait_for_events()

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .ActivePower:build_test_report_data(mock_device, ELECTRICAL_METER_EP, 15000) })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.powerMeter.power({ value = 15.0, unit = "W" })))
  end,
  {
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "Energy persisted for the sub-sensor endpoints by a previous driver version is pruned on init",
  function()
    -- 8500Wh and 2000Wh were left over on the sub-sensors. If they were still counted the total
    -- would be 15500Wh rather than the 5000Wh the meter endpoint reports.
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyImported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(5000000)) }) --5000Wh
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy", capabilities.energyMeter.energy({ value = 5000, unit = "Wh" }))
    )
  end,
  {
    test_init = function()
      test.disable_startup_messages()
      test.mock_device.add_test_device(mock_device)
      mock_device:set_field(TOTAL_CUMULATIVE_ENERGY_IMPORTED,
        { [tostring(SUB_SENSOR_EP_ONE)] = 8500, [tostring(SUB_SENSOR_EP_TWO)] = 2000 }, { persist = true })
      test.socket.device_lifecycle:__queue_receive({ mock_device.id, "added" })
      test.socket.device_lifecycle:__queue_receive({ mock_device.id, "init" })
      test.socket.matter:__expect_send({ mock_device.id, build_subscribe_request() })

      test.socket.device_lifecycle:__queue_receive({ mock_device.id, "doConfigure"})
      mock_device:expect_metadata_update({ profile = "electrical-meter" })
      mock_device:expect_metadata_update({ provisioning_state = "PROVISIONED" })
    end,
    min_api_version = 17
  }
)

test.run_registered_tests()
