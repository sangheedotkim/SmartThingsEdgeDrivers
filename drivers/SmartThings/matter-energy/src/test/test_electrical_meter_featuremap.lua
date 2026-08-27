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
local t_utils = require "integration_test.utils"
local version = require "version"

local ELECTRICAL_METER_EP = 32

local ELECTRICAL_METER_DEVICE_TYPE_ID = 0x0514
local ELECTRICAL_SENSOR_DEVICE_TYPE_ID = 0x0510

-- ElectricalEnergyMeasurement feature map combinations. As per spec at least one of IMPE or
-- EXPE, and at least one of CUME or PERE, must be supported.
local IMPE_EXPE_CUME = 7
local IMPE_CUME = 5
local EXPE_CUME = 6
local CUME_ONLY = 4 -- non-conformant: neither direction advertised
-- ElectricalPowerMeasurement: ALTC
local POWER_FEATURE_MAP = 2

if version.api < 11 then
  clusters.ElectricalEnergyMeasurement = require "ElectricalEnergyMeasurement"
  clusters.ElectricalPowerMeasurement = require "ElectricalPowerMeasurement"
end

local function build_mock_meter(profile_name, energy_feature_map)
  return test.mock_device.build_test_matter_device({
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
          { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = energy_feature_map },
          { cluster_id = clusters.ElectricalPowerMeasurement.ID,  cluster_type = "SERVER", feature_map = POWER_FEATURE_MAP },
        },
        device_types = {
          { device_type_id = ELECTRICAL_METER_DEVICE_TYPE_ID,  device_type_revision = 1 },
          { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID, device_type_revision = 1 },
        }
      }
    }
  })
end

-- The fingerprint profile is the bidirectional one, so each device starts from it and
-- doConfigure narrows it down to the directions the meter endpoint actually supports.
local mock_device_bidirectional = build_mock_meter("electrical-meter", IMPE_EXPE_CUME)
local mock_device_imported_only = build_mock_meter("electrical-meter", IMPE_CUME)
local mock_device_exported_only = build_mock_meter("electrical-meter", EXPE_CUME)
local mock_device_no_direction = build_mock_meter("electrical-meter", CUME_ONLY)
-- For the imported-only test, use the static profile directly to avoid optional_component_capabilities complexity
local mock_device_imported_profile = test.mock_device.build_test_matter_device({
  profile = t_utils.get_profile_definition("electrical-meter-imported.yml"),
  manufacturer_info = { vendor_id = 0x0000, product_id = 0x0000 },
  endpoints = {
    {
      endpoint_id = 0,
      clusters = { { cluster_id = clusters.Basic.ID, cluster_type = "SERVER" } },
      device_types = { { device_type_id = 0x0016, device_type_revision = 1 } }
    },
    {
      endpoint_id = ELECTRICAL_METER_EP,
      clusters = {
        { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = IMPE_CUME },
        { cluster_id = clusters.ElectricalPowerMeasurement.ID,  cluster_type = "SERVER", feature_map = POWER_FEATURE_MAP },
      },
      device_types = {
        { device_type_id = ELECTRICAL_METER_DEVICE_TYPE_ID,  device_type_revision = 1 },
        { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID, device_type_revision = 1 },
      }
    }
  }
})

local cluster_subscribe_list = {
  clusters.ElectricalPowerMeasurement.attributes.ActivePower,
  clusters.ElectricalPowerMeasurement.attributes.RMSVoltage,
  clusters.ElectricalPowerMeasurement.attributes.RMSCurrent,
  clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyImported,
  clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyExported,
  clusters.ElectricalEnergyMeasurement.attributes.PeriodicEnergyImported,
  clusters.ElectricalEnergyMeasurement.attributes.PeriodicEnergyExported,
}

local function build_energy_measurement_struct(energy_mwh)
  return clusters.ElectricalEnergyMeasurement.types.EnergyMeasurementStruct({
    energy = energy_mwh,
    start_timestamp = 0,
    end_timestamp = 0,
    start_systime = 0,
    end_systime = 0,
    apparent_energy = 0,
    reactive_energy = 0
  })
end

local function build_test_init(mock_device, expected_profile, optional_component_capabilities)
  return function()
    test.disable_startup_messages()
    test.mock_device.add_test_device(mock_device)
    local subscribe_request = cluster_subscribe_list[1]:subscribe(mock_device)
    for i, cluster in ipairs(cluster_subscribe_list) do
      if i > 1 then
        subscribe_request:merge(cluster:subscribe(mock_device))
      end
    end
    test.socket.device_lifecycle:__queue_receive({ mock_device.id, "added" })
    test.socket.device_lifecycle:__queue_receive({ mock_device.id, "init" })
    test.socket.matter:__expect_send({ mock_device.id, subscribe_request })

    test.socket.device_lifecycle:__queue_receive({ mock_device.id, "doConfigure" })
    if optional_component_capabilities then
      mock_device:expect_metadata_update({ profile = expected_profile, optional_component_capabilities = optional_component_capabilities })
      -- reflect the profile change in the mock device so subsequent events route correctly
      local updated_device_profile = t_utils.get_profile_definition(expected_profile .. ".yml", {
        enabled_optional_capabilities = optional_component_capabilities
      })
      test.socket.device_lifecycle:__queue_receive(mock_device:generate_info_changed({ profile = updated_device_profile }))
      -- info_changed triggers a re-subscribe with updated component capabilities
      local resubscribe_request = cluster_subscribe_list[1]:subscribe(mock_device)
      for i, cluster in ipairs(cluster_subscribe_list) do
        if i > 1 then
          resubscribe_request:merge(cluster:subscribe(mock_device))
        end
      end
      test.socket.matter:__expect_send({ mock_device.id, resubscribe_request })
    else
      mock_device:expect_metadata_update({ profile = expected_profile })
    end
    mock_device:expect_metadata_update({ provisioning_state = "PROVISIONED" })
  end
end

test.register_coroutine_test(
  "A meter supporting both directions must keep the imported and exported components",
  function() end,
  {
    test_init = build_test_init(mock_device_bidirectional, "electrical-meter-modular",
      { { "importedEnergy", { "energyMeter", "powerConsumptionReport" } },
        { "exportedEnergy", { "energyMeter", "powerConsumptionReport" } } }),
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "A meter supporting imported energy only must drop the exported component",
  function() end,
  {
    test_init = build_test_init(mock_device_imported_only, "electrical-meter-modular",
      { { "importedEnergy", { "energyMeter", "powerConsumptionReport" } } }),
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "A meter supporting exported energy only must drop the imported component",
  function() end,
  {
    test_init = build_test_init(mock_device_exported_only, "electrical-meter-modular",
      { { "exportedEnergy", { "energyMeter", "powerConsumptionReport" } } }),
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "A meter advertising neither direction must keep both components",
  function() end,
  {
    test_init = build_test_init(mock_device_no_direction, "electrical-meter-modular",
      { { "importedEnergy", { "energyMeter", "powerConsumptionReport" } },
        { "exportedEnergy", { "energyMeter", "powerConsumptionReport" } } }),
    min_api_version = 17
  }
)

test.run_registered_tests()
