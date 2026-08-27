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
local cluster_base = require "st.matter.cluster_base"
local data_types = require "st.matter.data_types"
local t_utils = require "integration_test.utils"
local version = require "version"

-- The Electrical Meter meters the grid connection point. It is composed of at least one
-- Electrical Sensor endpoint, which measures the same energy again further into the system,
-- so only the meter endpoint's reports may be surfaced.
local ELECTRICAL_METER_EP = 32
local ELECTRICAL_SENSOR_EP = 33

local ELECTRICAL_METER_DEVICE_TYPE_ID = 0x0514
local ELECTRICAL_SENSOR_DEVICE_TYPE_ID = 0x0510

-- ElectricalEnergyMeasurement: IMPE | EXPE | CUME
local METER_ENERGY_FEATURE_MAP = 7
-- ElectricalEnergyMeasurement: IMPE | EXPE
local METER_PERIODIC_ONLY_ENERGY_FEATURE_MAP = 3
-- ElectricalEnergyMeasurement: IMPE | CUME
local SENSOR_ENERGY_FEATURE_MAP = 5
-- ElectricalPowerMeasurement: ALTC
local POWER_FEATURE_MAP = 2

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
        { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = METER_ENERGY_FEATURE_MAP },
        { cluster_id = clusters.ElectricalPowerMeasurement.ID,  cluster_type = "SERVER", feature_map = POWER_FEATURE_MAP },
      },
      device_types = {
        { device_type_id = ELECTRICAL_METER_DEVICE_TYPE_ID,  device_type_revision = 1 },
        { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID, device_type_revision = 1 },
      }
    },
    {
      endpoint_id = ELECTRICAL_SENSOR_EP,
      clusters = {
        { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = SENSOR_ENERGY_FEATURE_MAP },
        { cluster_id = clusters.ElectricalPowerMeasurement.ID,  cluster_type = "SERVER", feature_map = POWER_FEATURE_MAP },
      },
      device_types = {
        { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID, device_type_revision = 1 },
      }
    }
  }
})

-- A meter endpoint that only supports periodic energy reporting, while a sibling Electrical
-- Sensor endpoint does support cumulative reporting. Only the meter endpoint's feature map may
-- decide which kind of report is handled, otherwise the sibling would suppress the meter's
-- periodic reports and no energy would be reported at all.
local mock_device_periodic_only_meter = test.mock_device.build_test_matter_device({
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
        { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = METER_PERIODIC_ONLY_ENERGY_FEATURE_MAP },
        { cluster_id = clusters.ElectricalPowerMeasurement.ID,  cluster_type = "SERVER", feature_map = POWER_FEATURE_MAP },
      },
      device_types = {
        { device_type_id = ELECTRICAL_METER_DEVICE_TYPE_ID,  device_type_revision = 1 },
        { device_type_id = ELECTRICAL_SENSOR_DEVICE_TYPE_ID, device_type_revision = 1 },
      }
    },
    {
      endpoint_id = ELECTRICAL_SENSOR_EP,
      clusters = {
        { cluster_id = clusters.ElectricalEnergyMeasurement.ID, cluster_type = "SERVER", feature_map = SENSOR_ENERGY_FEATURE_MAP },
        { cluster_id = clusters.ElectricalPowerMeasurement.ID,  cluster_type = "SERVER", feature_map = POWER_FEATURE_MAP },
      },
      device_types = {
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

  test.socket.device_lifecycle:__queue_receive({ mock_device.id, "doConfigure" })
  mock_device:expect_metadata_update({ profile = "electrical-meter-modular", optional_component_capabilities = { {"importedEnergy", {"energyMeter", "powerConsumptionReport"}}, {"exportedEnergy", {"energyMeter", "powerConsumptionReport"}} } })
  mock_device:expect_metadata_update({ provisioning_state = "PROVISIONED" })
end
test.set_test_init_function(test_init)

local function test_init_periodic_only_meter()
  test.disable_startup_messages()
  test.mock_device.add_test_device(mock_device_periodic_only_meter)
  local subscribe_request = cluster_subscribe_list[1]:subscribe(mock_device_periodic_only_meter)
  for i, cluster in ipairs(cluster_subscribe_list) do
    if i > 1 then
      subscribe_request:merge(cluster:subscribe(mock_device_periodic_only_meter))
    end
  end
  test.socket.device_lifecycle:__queue_receive({ mock_device_periodic_only_meter.id, "added" })
  test.socket.device_lifecycle:__queue_receive({ mock_device_periodic_only_meter.id, "init" })
  test.socket.matter:__expect_send({ mock_device_periodic_only_meter.id, subscribe_request })

  test.socket.device_lifecycle:__queue_receive({ mock_device_periodic_only_meter.id, "doConfigure" })
  mock_device_periodic_only_meter:expect_metadata_update({ profile = "electrical-meter-modular", optional_component_capabilities = { {"importedEnergy", {"energyMeter", "powerConsumptionReport"}}, {"exportedEnergy", {"energyMeter", "powerConsumptionReport"}} } })
  mock_device_periodic_only_meter:expect_metadata_update({ provisioning_state = "PROVISIONED" })
end

test.register_coroutine_test(
  "ActivePower from the meter endpoint must be reported in 'W' on the main component",
  function()
    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalPowerMeasurement.attributes.ActivePower:build_test_report_data(
        mock_device, ELECTRICAL_METER_EP, 240000
      )
    })
    test.socket.capability:__expect_send(mock_device:generate_test_message("main",
      capabilities.powerMeter.power({ value = 240.0, unit = "W" })))
  end,
  {
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "ActivePower from a sibling Electrical Sensor endpoint must not be reported",
  function()
    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalPowerMeasurement.attributes.ActivePower:build_test_report_data(
        mock_device, ELECTRICAL_SENSOR_EP, 8500000
      )
    })
    test.wait_for_events()
  end,
  {
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "RMSVoltage and RMSCurrent must be converted from milli-units to 'V' and 'A'",
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
  end,
  {
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "A null RMSVoltage must not be reported",
  function()
    test.socket.matter:__queue_receive({
      mock_device.id,
      cluster_base.build_test_report_data(
        mock_device,
        ELECTRICAL_METER_EP,
        clusters.ElectricalPowerMeasurement.ID,
        clusters.ElectricalPowerMeasurement.attributes.RMSVoltage.ID,
        data_types.validate_or_build_type(nil, data_types.Null)
      )
    })
    test.wait_for_events()
  end,
  {
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "RMSVoltage from a sibling Electrical Sensor endpoint must not be reported",
  function()
    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalPowerMeasurement.attributes.RMSVoltage:build_test_report_data(
        mock_device, ELECTRICAL_SENSOR_EP, 229000
      )
    })
    test.wait_for_events()
  end,
  {
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "Cumulative imported and exported energy must be reported to the matching components every 15 minutes",
  function()
    test.mock_time.advance_time(901) -- move time 15 minutes past 0

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

    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyExported:build_test_report_data(
        mock_device, ELECTRICAL_METER_EP, build_energy_measurement_struct(2000000)
      )
    }) -- 2000 Wh exported to the grid

    test.socket.capability:__expect_send(
      mock_device:generate_test_message("exportedEnergy",
        capabilities.energyMeter.energy({ value = 2000, unit = "Wh" }))
    )
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("exportedEnergy",
        capabilities.powerConsumptionReport.powerConsumption({
          start = "1970-01-01T00:00:00Z",
          ["end"] = "1970-01-01T00:15:00Z",
          deltaEnergy = 0.0,
          energy = 2000
        }))
    )

    test.wait_for_events()
    test.mock_time.advance_time(2000)

    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyImported:build_test_report_data(
        mock_device, ELECTRICAL_METER_EP, build_energy_measurement_struct(5500000)
      )
    }) -- 5500 Wh imported from the grid

    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy",
        capabilities.energyMeter.energy({ value = 5500, unit = "Wh" }))
    )
    test.socket.capability:__expect_send(
      mock_device:generate_test_message("importedEnergy",
        capabilities.powerConsumptionReport.powerConsumption({
          start = "1970-01-01T00:15:01Z",
          ["end"] = "1970-01-01T00:48:20Z",
          deltaEnergy = 500,
          energy = 5500
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
  "Periodic energy reports must be ignored while the meter endpoint supports cumulative reporting",
  function()
    test.mock_time.advance_time(901)

    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalEnergyMeasurement.attributes.PeriodicEnergyImported:build_test_report_data(
        mock_device, ELECTRICAL_METER_EP, build_energy_measurement_struct(100000)
      )
    })
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
  "Periodic energy reports must be accumulated while only a sibling endpoint supports cumulative reporting",
  function()
    test.mock_time.advance_time(901)

    test.socket.matter:__queue_receive({
      mock_device_periodic_only_meter.id,
      clusters.ElectricalEnergyMeasurement.attributes.PeriodicEnergyImported:build_test_report_data(
        mock_device_periodic_only_meter, ELECTRICAL_METER_EP, build_energy_measurement_struct(1000000)
      )
    }) -- 1000 Wh imported from the grid since the previous periodic report

    test.socket.capability:__expect_send(
      mock_device_periodic_only_meter:generate_test_message("importedEnergy",
        capabilities.energyMeter.energy({ value = 1000, unit = "Wh" }))
    )
    test.socket.capability:__expect_send(
      mock_device_periodic_only_meter:generate_test_message("importedEnergy",
        capabilities.powerConsumptionReport.powerConsumption({
          start = "1970-01-01T00:00:00Z",
          ["end"] = "1970-01-01T00:15:00Z",
          deltaEnergy = 0.0,
          energy = 1000
        }))
    )

    test.wait_for_events()
    test.mock_time.advance_time(2000)

    test.socket.matter:__queue_receive({
      mock_device_periodic_only_meter.id,
      clusters.ElectricalEnergyMeasurement.attributes.PeriodicEnergyImported:build_test_report_data(
        mock_device_periodic_only_meter, ELECTRICAL_METER_EP, build_energy_measurement_struct(500000)
      )
    }) -- 500 Wh more, so the running total becomes 1500 Wh

    test.socket.capability:__expect_send(
      mock_device_periodic_only_meter:generate_test_message("importedEnergy",
        capabilities.energyMeter.energy({ value = 1500, unit = "Wh" }))
    )
    test.socket.capability:__expect_send(
      mock_device_periodic_only_meter:generate_test_message("importedEnergy",
        capabilities.powerConsumptionReport.powerConsumption({
          start = "1970-01-01T00:15:01Z",
          ["end"] = "1970-01-01T00:48:20Z",
          deltaEnergy = 500,
          energy = 1500
        }))
    )
  end,
  {
    test_init = test_init_periodic_only_meter,
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "Energy reports from a sibling Electrical Sensor endpoint must not be added to the meter totals",
  function()
    test.mock_time.advance_time(901)

    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyImported:build_test_report_data(
        mock_device, ELECTRICAL_SENSOR_EP, build_energy_measurement_struct(8500000)
      )
    }) -- 8500 Wh of household consumption, already metered by the meter endpoint
    test.wait_for_events()

    test.socket.matter:__queue_receive({
      mock_device.id,
      clusters.ElectricalEnergyMeasurement.attributes.CumulativeEnergyImported:build_test_report_data(
        mock_device, ELECTRICAL_METER_EP, build_energy_measurement_struct(5000000)
      )
    }) -- only the 5000 Wh measured at the grid connection point is reported

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
  end,
  {
    test_init = function()
      test_init()
    end,
    min_api_version = 17
  }
)

test.register_coroutine_test(
  "Refresh must read every subscribed attribute",
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
  end,
  {
    min_api_version = 17
  }
)

test.run_registered_tests()
