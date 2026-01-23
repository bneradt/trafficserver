"""
Verify abuse_shield plugin functionality.
"""
import sys

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


class AbuseShieldMessageTest:
    """Verify abuse_shield plugin message handling."""

    def __init__(self):
        """Set up the test environment and run all test scenarios."""
        self._setup_ts()
        self._test_plugin_initialization()
        self._test_disable_plugin()
        self._test_enable_plugin()
        self._test_dump_command()
        self._test_reload_command()

    def _setup_ts(self) -> None:
        """Configure ATS with the abuse_shield plugin."""
        self._ts = Test.MakeATSProcess("ts")

        self._ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'abuse_shield',
            })

        # Create the plugin config file.
        self._ts.Disk.File(self._ts.Variables.CONFIGDIR + "/abuse_shield.yaml", id="abuse_shield_yaml", typename="ats:config")
        self._ts.Disk.abuse_shield_yaml.AddLines(
            '''
ip_reputation:
  slots: 1000

blocking:
  duration_seconds: 60

rules:
  - name: "test_error_rule"
    filter:
      h2_error: 0x01
      min_count: 5
    action: [log, block]

  - name: "pure_attack_rule"
    filter:
      min_client_errors: 10
      max_successes: 0
    action: [log, block, close]

enabled: true
'''.strip().split('\n'))

        # Create trusted IPs file.
        self._ts.Disk.File(self._ts.Variables.CONFIGDIR + "/abuse_shield_trusted.txt", id="trusted_txt", typename="ats:config")
        self._ts.Disk.trusted_txt.AddLines('''
# Trusted IPs
127.0.0.1
'''.strip().split('\n'))

        # Configure abuse_shield plugin.
        self._ts.Disk.plugin_config.AddLine('abuse_shield.so abuse_shield.yaml')

        # Verify the plugin loads. The plugin logs to diags.log via TSError.
        self._ts.Disk.diags_log.Content = Testers.ContainsExpression(
            r"abuse_shield.*Plugin initialized with 1000 slots, 2 rules", "Verify the abuse_shield plugin loaded successfully.")

    def _test_plugin_initialization(self) -> None:
        """Verify the plugin starts with configured values."""
        tr = Test.AddTestRun("Verify plugin starts with configured values.")
        tr.Processes.Default.Command = "echo verifying plugin starts with configured values"
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.StartBefore(self._ts)
        tr.StillRunningAfter = self._ts

        self._ts.Disk.traffic_out.Content = Testers.ContainsExpression(
            "Created IP tracker with 1000 slots", "Verify abuse_shield created tracker with correct slots.")

    def _test_disable_plugin(self) -> None:
        """Verify the 'enabled' setting can be changed via traffic_ctl."""
        tr = Test.AddTestRun("Verify changing 'enabled' via traffic_ctl.")
        tr.Processes.Default.Command = "traffic_ctl plugin msg abuse_shield.enabled 0"
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Env = self._ts.Env
        tr.StillRunningAfter = self._ts

        tr = Test.AddTestRun("Await the enabled change.")
        tr.Processes.Default.Command = "echo awaiting enabled change"
        tr.Processes.Default.ReturnCode = 0
        await_enabled = tr.Processes.Process('await_enabled', 'sleep 30')
        await_enabled.Ready = When.FileContains(self._ts.Disk.diags_log.Name, "Plugin disabled")
        tr.Processes.Default.StartBefore(await_enabled)

        self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
            "Plugin disabled", "Verify abuse_shield received the disabled command.")

    def _test_enable_plugin(self) -> None:
        """Re-enable the plugin via traffic_ctl."""
        tr = Test.AddTestRun("Re-enable the plugin via traffic_ctl.")
        tr.Processes.Default.Command = "traffic_ctl plugin msg abuse_shield.enabled 1"
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Env = self._ts.Env
        tr.StillRunningAfter = self._ts

        tr = Test.AddTestRun("Await the re-enable.")
        tr.Processes.Default.Command = "echo awaiting re-enable"
        tr.Processes.Default.ReturnCode = 0
        await_reenable = tr.Processes.Process('await_reenable', 'sleep 30')
        await_reenable.Ready = When.FileContains(self._ts.Disk.diags_log.Name, "Plugin enabled")
        tr.Processes.Default.StartBefore(await_reenable)

        self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
            "Plugin enabled", "Verify abuse_shield received the enabled command.")

    def _test_dump_command(self) -> None:
        """Verify dump command via traffic_ctl."""
        tr = Test.AddTestRun("Verify dump command via traffic_ctl.")
        tr.Processes.Default.Command = "traffic_ctl plugin msg abuse_shield.dump"
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Env = self._ts.Env
        tr.StillRunningAfter = self._ts

        tr = Test.AddTestRun("Await the dump output.")
        tr.Processes.Default.Command = "echo awaiting dump output"
        tr.Processes.Default.ReturnCode = 0
        await_dump = tr.Processes.Process('await_dump', 'sleep 30')
        await_dump.Ready = When.FileContains(self._ts.Disk.diags_log.Name, "abuse_shield dump")
        tr.Processes.Default.StartBefore(await_dump)

        self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
            "abuse_shield.*Dump:", "Verify abuse_shield dump command works.")

    def _test_reload_command(self) -> None:
        """Verify reload command via traffic_ctl."""
        tr = Test.AddTestRun("Verify reload command via traffic_ctl.")
        tr.Processes.Default.Command = "traffic_ctl plugin msg abuse_shield.reload"
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Env = self._ts.Env
        tr.StillRunningAfter = self._ts

        tr = Test.AddTestRun("Await the reload.")
        tr.Processes.Default.Command = "echo awaiting reload"
        tr.Processes.Default.ReturnCode = 0
        await_reload = tr.Processes.Process('await_reload', 'sleep 30')
        await_reload.Ready = When.FileContains(self._ts.Disk.diags_log.Name, "Configuration reloaded successfully")
        tr.Processes.Default.StartBefore(await_reload)

        self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
            "Configuration reloaded successfully", "Verify abuse_shield reload command works.")


class AbuseShieldRateLimitTest:
    """Verify abuse_shield plugin can detect and block request rate floods.

    This test sends HTTP/2 requests at a rate exceeding the configured
    max_req_rate threshold and verifies that the plugin detects this and
    blocks the offending IP.
    """

    _server_counter: int = 0
    _ts_counter: int = 0

    def __init__(self):
        """Set up the test environment and run rate limit test scenarios."""
        self._setup_origin_server()
        self._setup_ts()
        self._test_rate_limit_exceeded()

    def _setup_origin_server(self) -> None:
        """Configure a simple HTTP/1.1 origin server."""
        name = f'origin{AbuseShieldRateLimitTest._server_counter}'
        AbuseShieldRateLimitTest._server_counter += 1

        self._origin = Test.MakeOriginServer(name)

        # Add a simple response for GET requests.
        self._origin.addResponse(
            "sessionlog.json", {
                "headers": "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "timestamp": "1469733493.993",
                "body": ""
            }, {
                "headers":
                    "HTTP/1.1 200 OK\r\nServer: origin\r\nCache-Control: max-age=300\r\nConnection: close\r\nContent-Length: 2\r\n\r\n",
                "timestamp": "1469733493.993",
                "body": "OK"
            })

    def _setup_ts(self) -> None:
        """Configure ATS with TLS and the abuse_shield plugin for rate limiting."""
        name = f'ts_rate{AbuseShieldRateLimitTest._ts_counter}'
        AbuseShieldRateLimitTest._ts_counter += 1

        self._ts = Test.MakeATSProcess(name, enable_tls=True, enable_cache=True)
        self._ts.addDefaultSSLFiles()

        # Configure SSL for ATS.
        self._ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

        # Remap to the origin server.
        self._ts.Disk.remap_config.AddLine(f'map / http://127.0.0.1:{self._origin.Variables.Port}/')

        # Configure records.
        self._ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'abuse_shield',
                'proxy.config.http.insert_response_via_str': 2,
                'proxy.config.ssl.server.cert.path': self._ts.Variables.SSLDir,
                'proxy.config.ssl.server.private_key.path': self._ts.Variables.SSLDir,
            })

        # Create the plugin config file with a low max_req_rate for testing.
        # With max_req_rate: 20, sending 50 requests should trigger the rule.
        self._ts.Disk.File(self._ts.Variables.CONFIGDIR + "/abuse_shield.yaml", id="abuse_shield_yaml", typename="ats:config")
        self._ts.Disk.abuse_shield_yaml.AddLines(
            '''
ip_reputation:
  slots: 1000

blocking:
  duration_seconds: 60

rules:
  - name: "req_rate_flood"
    filter:
      max_req_rate: 20
    action: [log, block]

enabled: true
'''.strip().split('\n'))

        # Configure abuse_shield plugin.
        self._ts.Disk.plugin_config.AddLine('abuse_shield.so abuse_shield.yaml')

        # Verify the plugin loads.
        self._ts.Disk.diags_log.Content = Testers.ContainsExpression(
            r"abuse_shield.*Plugin initialized with 1000 slots, 1 rules",
            "Verify the abuse_shield plugin loaded with rate limit rule.")

    def _test_rate_limit_exceeded(self) -> None:
        """Send requests exceeding the rate threshold and verify blocking.

        This test sends 50 requests at 100 req/sec, which should exceed the
        max_req_rate of 20 and trigger the req_rate_flood rule.
        """
        tr = Test.AddTestRun("Send excessive H2 requests to trigger rate limit")

        # Send 50 requests at high rate - this should exceed max_req_rate of 20.
        client_cmd = (
            f'{sys.executable} {Test.TestDirectory}/h2_rate_client.py '
            f'--host localhost --port {self._ts.Variables.ssl_port} '
            f'--num-requests 50 --rate 100 --path /')
        tr.Processes.Default.Command = client_cmd
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.StartBefore(self._origin)
        tr.Processes.Default.StartBefore(self._ts)
        tr.StillRunningAfter = self._ts

        # Verify the rate limit rule was triggered.
        # The plugin logs via TSError to diags.log when a rule matches.
        self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
            r'Rule "req_rate_flood" matched for IP=',
            "Verify the req_rate_flood rule was triggered when request rate exceeded threshold.")

        # Verify the IP was blocked.
        # The plugin logs "Blocking IP ... for N seconds (rule: ...)" via TSError.
        self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
            r"Blocking IP.*for.*seconds", "Verify the offending IP was blocked after exceeding rate limit.")


#
# Main: Run the tests.
#
AbuseShieldMessageTest()
AbuseShieldRateLimitTest()
