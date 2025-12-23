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
"""
Test that crash logs are generated with backtraces when traffic_server crashes.

This test intentionally crashes traffic_server using a plugin that dereferences
a null pointer when it receives a specific header. It then verifies that:
1. A crash log file was created
2. The crash log contains thread information
"""

import glob
import os
import time

Test.Summary = '''
Test crash log generation with backtrace.
'''

# Create an origin server for the test.
server = Test.MakeOriginServer("server")

request_header = {"headers": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "Hello"}
server.addResponse("sessionlog.json", request_header, response_header)

# Create the ATS process. We set block_for_debug=False so the test doesn't
# wait for a debugger.
ts = Test.MakeATSProcess("ts", block_for_debug=False)

# We expect the server to crash with SIGSEGV (signal 11), so set expected
# return code to -11 (negative signal number).
ts.ReturnCode = -11

ts.Disk.records_config.update(
    {
        'proxy.config.proxy_name': 'test_proxy',
        'proxy.config.url_remap.remap_required': 0,
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'crash_test',
        # Enable the crash log helper.
        'proxy.config.crash_log_helper': 'traffic_crashlog',
    })

# Copy the crash_test plugin.
plugin_path = os.path.join(Test.Variables.AtsBuildGoldTestsDir, 'pluginTest', 'crash_test', '.libs', 'crash_test.so')
ts.Setup.Copy(plugin_path, ts.Env['PROXY_CONFIG_PLUGIN_PLUGIN_DIR'])

ts.Disk.plugin_config.AddLine("crash_test.so")

ts.Disk.remap_config.AddLine(f"map / http://127.0.0.1:{server.Variables.Port}/")

ts.Disk.diags_log.Content += Testers.ContainsExpression(
    "Received crash trigger header - crashing now!", "Expect the log indicating the intentional crash.")
ts.Disk.diags_log.Content += Testers.ExcludesExpression(
    "This should never be reached.", "Expect to not see the log after the crash.")

# Test 1: Make a normal request to verify the server is running.
tr = Test.AddTestRun("Verify server is running")
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Command = (f'curl -s -o /dev/null -w "%{{http_code}}" '
                                f'http://127.0.0.1:{ts.Variables.port}/')
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("200", "Expected 200 OK response")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Test 2: Send the crash trigger header.
tr = Test.AddTestRun("Trigger crash")
# Give the server a moment to be fully ready.
tr.Processes.Default.Command = (
    f'sleep 1 && curl -s -o /dev/null '
    f'-H "X-Crash-Test: now" '
    f'http://127.0.0.1:{ts.Variables.port}/ || true')
tr.Processes.Default.ReturnCode = 0
# The server will crash, so we don't expect it to be running after.
tr.StillRunningAfter = server

# Test 3: Check that a crash log was created.
tr = Test.AddTestRun("Check for crash log")
# Wait a moment for the crash log to be written.
tr.Processes.Default.Command = (f'sleep 2 && ls -la {ts.Variables.LOGDIR}/crash-*.log 2>&1')
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("crash-", "Expected crash log file to exist")

# Test 4: Verify crash log contains expected content.
tr = Test.AddTestRun("Check crash log content")
tr.Processes.Default.Command = (f'cat {ts.Variables.LOGDIR}/crash-*.log 2>&1')
tr.Processes.Default.ReturnCode = 0
# The crash log should contain signal information (always present).
tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "Segmentation fault", "Expected crash log to show segmentation fault signal")
# The crash log should contain the crashing thread information first.
# The crashing thread should be listed first.
tr.Processes.Default.Streams.stdout += Testers.ContainsExpression("Crashing Thread", "Expected crashing thread backtrace first")
# The other threads should be listed after.
tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "Other Non-Crashing Threads:", "Expected other non-crashing threads section")
