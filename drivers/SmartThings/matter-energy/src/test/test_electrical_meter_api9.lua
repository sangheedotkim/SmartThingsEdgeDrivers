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

-- Below API 11 the driver swaps ElectricalPowerMeasurement and ElectricalEnergyMeasurement for its
-- own definitions, so the paths the Electrical Meter depends on must be covered against those as
-- well: the RMSVoltage and RMSCurrent attributes added for this device type, the feature map lookup
-- that picks the profile, and the EnergyMeasurementStruct augment_type call that only runs on these
-- older API versions. Referencing an attribute the embedded cluster does not define would otherwise
-- fail at driver startup only, and only on a hub old enough that the rest of the suite never
-- reaches it.
version.api = 9

clusters.ElectricalPowerMeasurement = require "ElectricalPowerMeasurement"
clusters.ElectricalEnergyMeasurement = require "ElectricalEnergyMeasurement"

local ELECTRICAL_METER_EP = 32

local ELECTRICAL_METER_DEVICE_TYPE_ID = 0x0514
local ELECTRICAL_SENSOR_DEVICE_TYPE_ID = 0x0510

-- ElectricalEnergyMeasurement: IMPE | EXPE | CUME
local METER_ENERGY_FEATURE_MAP = 7
-- ElectricalPowerMeasurement: ALTC
local POWER_FEATURE_MAP = 2

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
        { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = METER_ENERGY_FEATURE_MAP },
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

-- The embedded EnergyMeasurementStruct predates the apparent_energy and reactive_energy fields
local function build_energy_measurement_struct(energy_mwh)
  return clusters.ElectricalEnergyMeasurement.types.EnergyMeasurementStruct({
    energy = energy_mwh,
    start_timestamp = 0,
    end_timestamp = 0,
    start_systime = 0,
    end_systime = 0
  })
end

local function test_init()
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

  -- the feature map is read through the embedded cluster's are_features_supported
  test.socket.device_lifecycle:__queue_receive({ mock_device.id, "doConfigure" })
  mock_device:expect_metadata_update({ profile = "electrical-meter" })
  mock_device:expect_metadata_update({ provisioning_state = "PROVISIONED" })
end
test.set_test_init_function(test_init)

test.register_coroutine_test(
  "The embedded RMSVoltage and RMSCurrent attributes must deserialize and convert to 'V' and 'A'",
  function()
    test.socket.matter:__set_channel_ordering("strict")
    test.socket.capability:__set_channel_ordering("strict")
    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalPowerMeasurement.attributes.RMSVoltage:build_test_report_data(
        mock_device, ELECTRICAL_METER_EP, 230123
      )
    })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.voltageMeasurement.voltage({ value = 230.12, unit = "V" })))

    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalPowerMeasurement.attributes.RMSCurrent:build_test_report_data(
        mock_device, ELECTRICAL_METER_EP, 4567
      )
    })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.currentMeasurement.current({ value = 4.57, unit = "A" })))
  end
)

test.register_coroutine_test(
  "The embedded EnergyMeasurementStruct must be augmented before the energy is read",
  function()
    test.mock_time.advance_time(901)

    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyImported:build_test_report_data(
        mock_device, ELECTRICAL_METER_EP, build_energy_measurement_struct(5000000)
      )
    }) -- 5000 Wh imported from the grid

    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy",
        capabilities.energyMeter.energy({ value = 5000, unit = "Wh" }))
    )
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy",
        capabilities.powerConsumptionReport.powerConsumption({
          start = "1970-01-01T00:00:00Z",
          ["end"] = "1970-01-01T00:15:00Z",
          deltaEnergy = 0.0,
          energy = 5000
        }))
    )
  end
)

test.register_coroutine_test(
  "Refresh must read every subscribed attribute of the embedded clusters",
  function()
    test.socket.capability:__queue_receive(
      { mock_device.id, { capability = "refresh", component = "main", command = "refresh", args = {} } }
    )
    local read_request = cluster_subscribe_list[1]:read(mock_device)
    for i, attr in ipairs(cluster_subscribe_list) do
      if i > 1 then read_request:merge(attr:read(mock_device)) end
    end
    test.socket.matter:__expect_send({ mock_device.id, read_request })
    test.wait_for_events()
  end
)

test.run_registered_tests()
