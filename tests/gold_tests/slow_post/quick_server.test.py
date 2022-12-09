"""Verify ATS handles a server that replies before receiving a full request."""

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
from ports import get_port
import sys


class QuickServerTest:
    """Verify that ATS doesn't delay respnses behind slow posts."""

    def __init__(self):
        Test.Summary = 'Test how ATS handles the slow-post attack'
        self._slow_post_client = 'slow_post_client.py'
        self._quick_server = 'quick_server.py'
        self._configure_dns()
        self._configure_server()
        self._configure_traffic_server()

    def _configure_dns(self) -> 'Process':
        """Configure the DNS."""
        dns = Test.MakeDNServer('dns')
        self._dns = dns

    def _configure_server(self):
        """Configure the origin server.

        This server replies with a response immediately after receiving the
        request headers."""
        server = Test.Processes.Process("server")
        port = get_port(server, "https_port")
        ssl_cert = os.path.join(Test.Variables["AtsTestToolsDir"],
                                "ssl", "server.pem")
        server.Command = (
            f'{sys.executable} {self._quick_server} '
            f'0.0.0.0 {port} '
            f'{ssl_cert} {ssl_cert}')
        server.Ready = When.PortOpenv4(port)
        self._server = server

    def _configure_traffic_server(self):
        """Configure ATS."""
        self._ts = Test.MakeATSProcess("ts", enable_tls=True)
        self._ts.addDefaultSSLFiles()
        self._ts.Disk.remap_config.AddLine(
            f'map / https://127.0.0.1:{self._server.Variables.https_port}'
        )
        self._ts.Disk.records_config.update({
            'proxy.config.diags.debug.enabled': 1,
            'proxy.config.diags.debug.tags': 'http',
            'proxy.config.dns.nameservers': f'127.0.0.1:{self._dns.Variables.Port}',
            'proxy.config.dns.resolv_conf': 'NULL',

            'proxy.config.ssl.server.cert.path': self._ts.Variables.SSLDir,
            'proxy.config.ssl.server.private_key.path': self._ts.Variables.SSLDir,
            'proxy.config.ssl.client.verify.server.policy': 'PERMISSIVE',
        })

        self._ts.Disk.ssl_multicert_config.AddLine(
            'dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key'
        )

    def run(self):
        """Run the test."""
        tr = Test.AddTestRun()
        tr.Setup.CopyAs(self._slow_post_client, Test.RunDirectory)
        tr.Setup.CopyAs(self._quick_server, Test.RunDirectory)

        tr.Processes.Default.Command = (
            f'{sys.executable} {self._slow_post_client} '
            f'{self._ts.Variables.port}')
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.StartBefore(self._dns)
        tr.Processes.Default.StartBefore(self._server)
        tr.Processes.Default.StartBefore(self._ts)


Test.Summary = __doc__
slowPostAttack = QuickServerTest()
slowPostAttack.run()
