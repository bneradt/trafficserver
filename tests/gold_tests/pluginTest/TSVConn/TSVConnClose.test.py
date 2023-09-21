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

import os


Test.Summary = '''
Test the TSVConnClose() TS API call.
'''


class TestTSVConnClose:
    """Test TSVConnClose()."""

    replay_file: str = "replay/killed_session.replay.yaml"
    plugin_name: str = "TSVConnClose"

    def __init__(self):
        """Initialize the test."""
        self._tr = Test.AddTestRun("Test TSVConnClose()")
        self._dns = self._configure_dns(self._tr)
        self._server = self._configure_server(self._tr)
        self._ts = self._configure_ts(
            self._tr,
            self._dns.Variables.Port,
            self._server.Variables.http_port)
        self._configure_client(self._tr, self._ts.Variables.port)

    def _configure_dns(self, tr: 'TestRun') -> 'Process':
        """Configure DNS for the TestRun.

        :param tr: The TestRun to associate the DNS with.
        :return: The DNS Process.
        """
        return tr.MakeDNServer("dns", default='127.0.0.1')

    def _configure_server(self, tr: 'TestRun') -> 'Process':
        """Configure the server for the TestRun.

        :param tr: The TestRun to associate the server with.
        :return: The server Process.
        """
        server = tr.AddVerifierServerProcess("server", self.replay_file)
        return server

    def _configure_ts(self, tr: 'TestRun', dns_port: int, server_port: int) -> 'Process':
        """Configure the TS for the TestRun.

        :param tr: The TestRun to associate the TS with.
        :param dns_port: The DNS port to use.
        :param server_port: The server port to use.
        :return: The TS Process.
        """
        ts = tr.MakeATSProcess("ts", enable_cache=False)
        ts.Disk.records_config.update({
            'proxy.config.dns.nameservers': f'127.0.0.1:{dns_port}',
            'proxy.config.dns.resolv_conf': 'NULL',

            'proxy.config.diags.debug.enabled': 3,
            'proxy.config.diags.debug.tags': f'http|{self.plugin_name}',
        })
        rp = os.path.join(Test.Variables.AtsBuildGoldTestsDir, 'pluginTest', 'TSVConn', '.libs', f'{self.plugin_name}.so')
        ts.Setup.Copy(rp, ts.Env['PROXY_CONFIG_PLUGIN_PLUGIN_DIR'])
        ts.Disk.plugin_config.AddLine(f"{self.plugin_name}.so")
        ts.Disk.remap_config.AddLine(
            f"map http://www.example.com http://backend.example.com:{server_port}"
        )
        return ts

    def _configure_client(self, tr: 'TestRun', ts_port: int):
        """Configure the client for the TestRun.

        :param tr: The TestRun to associate the client with.
        """
        client = tr.AddVerifierClientProcess(
            "client",
            self.replay_file,
            http_ports=[ts_port])

        self._server.StartBefore(self._dns)
        self._ts.StartBefore(self._server)
        client.StartBefore(self._ts)


TestTSVConnClose()
