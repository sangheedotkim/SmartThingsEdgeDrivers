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

-- A whole home energy monitor: an Electrical Meter at the grid connection point plus one
-- Electrical Sensor per monitored circuit. Every circuit sits downstream of the meter, so the
-- meter endpoint alone must feed the energy totals. Summing all seven endpoints would report
-- 18000Wh of import for a home that only drew 5000Wh from the grid.
local ELECTRICAL_METER_EP = 32
local HOUSEHOLD_EP = 33
local SOLAR_EP_ONE = 34
local SOLAR_EP_TWO = 35
local ESS_EP = 36
local EV_CHARGER_EP = 37
local HEAT_PUMP_EP = 38

local SUB_SENSOR_EPS = { HOUSEHOLD_EP, SOLAR_EP_ONE, SOLAR_EP_TWO, ESS_EP, EV_CHARGER_EP, HEAT_PUMP_EP }

local ELECTRICAL_METER_DEVICE_TYPE_ID = 0x0514
local ELECTRICAL_SENSOR_DEVICE_TYPE_ID = 0x0510
local BATTERY_STORAGE_DEVICE_TYPE_ID = 0x0018

local TOTAL_CUMULATIVE_ENERGY_IMPORTED = "__total_cumulative_energy_imported"
local TOTAL_CUMULATIVE_ENERGY_EXPORTED = "__total_cumulative_energy_exported"

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

local function electrical_sensor_endpoint(endpoint_id, device_types)
  local endpoint_device_types = {
    { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID, device_type_revision = 1 } -- ELECTRICAL_SENSOR
  }
  for _, device_type_id in ipairs(device_types or {}) do
    table.insert(endpoint_device_types, { device_type_id = device_type_id, device_type_revision = 1 })
  end
  return {
    endpoint_id = endpoint_id,
    clusters = {
      { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = 15 }, -- ALL
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
    electrical_sensor_endpoint(ELECTRICAL_METER_EP, { ELECTRICAL_METER_DEVICE_TYPE_ID }),
    electrical_sensor_endpoint(HOUSEHOLD_EP),
    electrical_sensor_endpoint(SOLAR_EP_ONE),
    electrical_sensor_endpoint(SOLAR_EP_TWO),
    -- the ESS also carries a Battery Storage device type, which on its own would have its
    -- ActivePower added to the total. The meter endpoint takes precedence over it.
    electrical_sensor_endpoint(ESS_EP, { BATTERY_STORAGE_DEVICE_TYPE_ID }),
    electrical_sensor_endpoint(EV_CHARGER_EP),
    electrical_sensor_endpoint(HEAT_PUMP_EP)
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

-- Queues a report for every sub-sensor endpoint and asserts nothing is emitted for any of them.
local function expect_sub_sensor_reports_ignored(attribute, energy_by_endpoint)
  for _, endpoint_id in ipairs(SUB_SENSOR_EPS) do
    test.socket.matter:__queue_receive({ mock_device.id,
      attribute:build_test_report_data(mock_device, endpoint_id, energy_measurement(energy_by_endpoint[endpoint_id])) })
    test.wait_for_events()
  end
end

test.register_coroutine_test(
  "Imported energy is taken from the meter endpoint alone across every sub-sensor endpoint",
  function()
    test.mock_time.advance_time(901) -- move time 15 minutes past 0 so that powerConsumption is reported

    -- 13000Wh of consumption spread over the monitored circuits, all of it already metered by EP32
    expect_sub_sensor_reports_ignored(clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyImported, {
      [HOUSEHOLD_EP] = 8500000,   --8500Wh
      [SOLAR_EP_ONE] = 0,
      [SOLAR_EP_TWO] = 0,
      [ESS_EP] = 1000000,         --1000Wh
      [EV_CHARGER_EP] = 2000000,  --2000Wh
      [HEAT_PUMP_EP] = 1500000    --1500Wh
    })

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

    -- a later sub-sensor report must not be added on top of the meter's total either
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyImported:build_test_report_data(mock_device, HOUSEHOLD_EP, energy_measurement(9000000)) }) --9000Wh
    test.wait_for_events()

    -- the next meter reading replaces the previous one rather than accumulating with anything else
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyImported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(5100000)) }) --5100Wh
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy", capabilities.energyMeter.energy({ value = 5100, unit = "Wh" }))
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
  "Exported energy is taken from the meter endpoint alone across every sub-sensor endpoint",
  function()
    test.mock_time.advance_time(901) -- move time 15 minutes past 0 so that powerConsumption is reported

    -- 7800Wh of generation, of which only 2000Wh actually reached the grid
    expect_sub_sensor_reports_ignored(clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyExported, {
      [HOUSEHOLD_EP] = 0,
      [SOLAR_EP_ONE] = 4000000,   --4000Wh
      [SOLAR_EP_TWO] = 3000000,   --3000Wh
      [ESS_EP] = 800000,          --800Wh
      [EV_CHARGER_EP] = 0,
      [HEAT_PUMP_EP] = 0
    })

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
  "Periodic reports are ignored while the meter endpoint supports cumulative reports",
  function()
    test.mock_time.advance_time(901)

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .PeriodicEnergyImported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(700000)) })
    test.wait_for_events()

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .PeriodicEnergyExported:build_test_report_data(mock_device, HOUSEHOLD_EP, energy_measurement(700000)) })
    test.wait_for_events()

    -- the cumulative reading is the only thing that reaches the total
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
  "ActivePower is reported from the meter endpoint only, including for a Battery Storage sub-sensor",
  function()
    -- a Battery Storage device type on its own would contribute to the total, but the meter
    -- endpoint already accounts for the power flowing through the ESS
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .ActivePower:build_test_report_data(mock_device, ESS_EP, 1200000) })
    test.wait_for_events()

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .ActivePower:build_test_report_data(mock_device, HOUSEHOLD_EP, 8500000) })
    test.wait_for_events()

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .ActivePower:build_test_report_data(mock_device, ELECTRICAL_METER_EP, 5200000) })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.powerMeter.power({ value = 5200.0, unit = "W" })))
  end,
  {
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "RMSVoltage and RMSCurrent are reported from the meter endpoint only",
  function()
    for _, endpoint_id in ipairs(SUB_SENSOR_EPS) do
      test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
        .RMSVoltage:build_test_report_data(mock_device, endpoint_id, 120000) })
      test.wait_for_events()

      test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
        .RMSCurrent:build_test_report_data(mock_device, endpoint_id, 1000) })
      test.wait_for_events()
    end

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .RMSVoltage:build_test_report_data(mock_device, ELECTRICAL_METER_EP, 230000) })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.voltageMeasurement.voltage({ value = 230.0, unit = "V" })))

    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalPowerMeasurement.attributes
      .RMSCurrent:build_test_report_data(mock_device, ELECTRICAL_METER_EP, 22600) })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.currentMeasurement.current({ value = 22.6, unit = "A" })))
  end,
  {
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "Energy persisted for every sub-sensor endpoint by a previous driver version is pruned on init",
  function()
    -- Without pruning the leftover 13000Wh of imports would be added to the meter's own reading
    -- forever, reporting 18000Wh for a home that imported 5000Wh.
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyImported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(5000000)) }) --5000Wh
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy", capabilities.energyMeter.energy({ value = 5000, unit = "Wh" }))
    )

    -- the meter's own persisted export survived the prune, so 2000Wh is reported rather than 9800Wh
    test.socket.matter:__queue_receive({ mock_device.id, clusters.ElectricalEnergyMeasurement.attributes
      .CumulativeEnergyExported:build_test_report_data(mock_device, ELECTRICAL_METER_EP, energy_measurement(2000000)) }) --2000Wh
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("exportedEnergy", capabilities.energyMeter.energy({ value = 2000, unit = "Wh" }))
    )
  end,
  {
    test_init = function()
      test.disable_startup_messages()
      test.mock_device.add_test_device(mock_device)
      mock_device:set_field(TOTAL_CUMULATIVE_ENERGY_IMPORTED, {
        [tostring(ELECTRICAL_METER_EP)] = 4000,
        [tostring(HOUSEHOLD_EP)] = 8500,
        [tostring(ESS_EP)] = 1000,
        [tostring(EV_CHARGER_EP)] = 2000,
        [tostring(HEAT_PUMP_EP)] = 1500
      }, { persist = true })
      mock_device:set_field(TOTAL_CUMULATIVE_ENERGY_EXPORTED, {
        [tostring(ELECTRICAL_METER_EP)] = 1800,
        [tostring(SOLAR_EP_ONE)] = 4000,
        [tostring(SOLAR_EP_TWO)] = 3000,
        [tostring(ESS_EP)] = 800
      }, { persist = true })
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
