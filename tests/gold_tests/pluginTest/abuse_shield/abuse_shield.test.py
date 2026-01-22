"""
Verify abuse_shield plugin functionality.
"""
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

Test.Summary = '''
Verify abuse_shield plugin initialization and message handling via traffic_ctl.
'''

Test.SkipUnless(Condition.PluginExists('abuse_shield.so'),)

# Define ATS and configure it.
ts = Test.MakeATSProcess("ts")

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'abuse_shield',
})

# Create the plugin config file
ts.Disk.File(ts.Variables.CONFIGDIR + "/abuse_shield.yaml", id="abuse_shield_yaml", typename="ats:config")
ts.Disk.abuse_shield_yaml.AddLines(
    [
        "tracker:",
        "  slots: 1000",
        "  partitions: 8",
        "",
        "blocking:",
        "  duration_seconds: 60",
        "",
        "rules:",
        "  - name: \"test_error_rule\"",
        "    filter:",
        "      h2_error: 0x01",
        "      min_count: 5",
        "    action: [log, block]",
        "",
        "  - name: \"pure_attack_rule\"",
        "    filter:",
        "      min_client_errors: 10",
        "      max_successes: 0",
        "    action: [log, block, close]",
        "",
        "enabled: true",
    ])

# Create empty trusted IPs file
ts.Disk.File(ts.Variables.CONFIGDIR + "/abuse_shield_trusted.txt", id="trusted_txt", typename="ats:config")
ts.Disk.trusted_txt.AddLines([
    "# Trusted IPs",
    "127.0.0.1",
])

# Configure abuse_shield plugin
ts.Disk.plugin_config.AddLine('abuse_shield.so abuse_shield.yaml')

# Verify the plugin loads
ts.Disk.traffic_out.Content = Testers.ContainsExpression(
    r"abuse_shield.*Plugin initialized with 1000 slots, 2 rules", "Verify the abuse_shield plugin loaded successfully.")

#
# Test 1: Verify the plugin starts with configured values
#
tr = Test.AddTestRun("Verify plugin starts with configured values.")
tr.Processes.Default.Command = "echo verifying plugin starts with configured values"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts)
tr.StillRunningAfter = ts

ts.Disk.traffic_out.Content += Testers.ContainsExpression(
    "Created IP tracker with 1000 slots and 8 partitions", "Verify abuse_shield created tracker with correct slots and partitions.")

#
# Test 2: Verify the 'enabled' setting can be changed via traffic_ctl
#
tr = Test.AddTestRun("Verify changing 'enabled' via traffic_ctl.")
tr.Processes.Default.Command = "traffic_ctl plugin msg abuse_shield.enabled 0"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Env = ts.Env
tr.StillRunningAfter = ts

tr = Test.AddTestRun("Await the enabled change.")
tr.Processes.Default.Command = "echo awaiting enabled change"
tr.Processes.Default.ReturnCode = 0
await_enabled = tr.Processes.Process('await_enabled', 'sleep 30')
await_enabled.Ready = When.FileContains(ts.Disk.traffic_out.Name, "Plugin disabled")
tr.Processes.Default.StartBefore(await_enabled)

ts.Disk.traffic_out.Content += Testers.ContainsExpression("Plugin disabled", "Verify abuse_shield received the disabled command.")

#
# Test 3: Re-enable the plugin
#
tr = Test.AddTestRun("Re-enable the plugin via traffic_ctl.")
tr.Processes.Default.Command = "traffic_ctl plugin msg abuse_shield.enabled 1"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Env = ts.Env
tr.StillRunningAfter = ts

tr = Test.AddTestRun("Await the re-enable.")
tr.Processes.Default.Command = "echo awaiting re-enable"
tr.Processes.Default.ReturnCode = 0
await_reenable = tr.Processes.Process('await_reenable', 'sleep 30')
await_reenable.Ready = When.FileContains(ts.Disk.traffic_out.Name, "Plugin enabled")
tr.Processes.Default.StartBefore(await_reenable)

ts.Disk.traffic_out.Content += Testers.ContainsExpression("Plugin enabled", "Verify abuse_shield received the enabled command.")

#
# Test 4: Verify dump command (should show empty table initially)
#
tr = Test.AddTestRun("Verify dump command via traffic_ctl.")
tr.Processes.Default.Command = "traffic_ctl plugin msg abuse_shield.dump"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Env = ts.Env
tr.StillRunningAfter = ts

tr = Test.AddTestRun("Await the dump output.")
tr.Processes.Default.Command = "echo awaiting dump output"
tr.Processes.Default.ReturnCode = 0
await_dump = tr.Processes.Process('await_dump', 'sleep 30')
await_dump.Ready = When.FileContains(ts.Disk.traffic_out.Name, "# abuse_shield dump")
tr.Processes.Default.StartBefore(await_dump)

ts.Disk.traffic_out.Content += Testers.ContainsExpression("# abuse_shield dump", "Verify abuse_shield dump command works.")

#
# Test 5: Verify reload command
#
tr = Test.AddTestRun("Verify reload command via traffic_ctl.")
tr.Processes.Default.Command = "traffic_ctl plugin msg abuse_shield.reload"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Env = ts.Env
tr.StillRunningAfter = ts

tr = Test.AddTestRun("Await the reload.")
tr.Processes.Default.Command = "echo awaiting reload"
tr.Processes.Default.ReturnCode = 0
await_reload = tr.Processes.Process('await_reload', 'sleep 30')
await_reload.Ready = When.FileContains(ts.Disk.traffic_out.Name, "Configuration reloaded successfully")
tr.Processes.Default.StartBefore(await_reload)

ts.Disk.traffic_out.Content += Testers.ContainsExpression(
    "Configuration reloaded successfully", "Verify abuse_shield reload command works.")
