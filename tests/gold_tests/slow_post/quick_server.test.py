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

from ports import get_port
import sys

Test.Summary = __doc__


class QuickServerTest:
    """Verify that ATS doesn't delay respnses behind slow posts."""

    _slow_post_client = 'slow_post_client.py'
    _quick_server = 'quick_server.py'

    def __init__(self):
        pass

    def _configure_dns(self, tr: 'TestRun') -> None:
        """Configure the DNS.

        :param tr: The test run to associate with the DNS process with.
        """
        self._dns = tr.MakeDNServer('dns')

    def _configure_server(self, tr: 'TestRun'):
        """Configure the origin server.

        This server replies with a response immediately after receiving the
        request headers.

        :param tr: The test run to associate with the server process with.
        """
        server = tr.Processes.Process("server")
        port = get_port(server, "http_port")
        server.Command = \
            f'{sys.executable} {self._quick_server} 0.0.0.0 {port}'
        server.Ready = When.PortOpenv4(port)
        self._server = server

    def _configure_traffic_server(self, tr: 'TestRun'):
        """Configure ATS.

        :param tr: The test run to associate with the ATS process with.
        """
        self._ts = tr.MakeATSProcess("ts")
        self._ts.Disk.remap_config.AddLine(
            f'map / http://127.0.0.1:{self._server.Variables.http_port}'
        )
        self._ts.Disk.records_config.update({
            'proxy.config.diags.debug.enabled': 1,
            'proxy.config.diags.debug.tags': 'http',
            'proxy.config.dns.nameservers': f'127.0.0.1:{self._dns.Variables.Port}',
            'proxy.config.dns.resolv_conf': 'NULL',
        })

    def run(self):
        """Run the test."""
        tr = Test.AddTestRun()

        self._configure_dns(tr)
        self._configure_server(tr)
        self._configure_traffic_server(tr)

        tr.Setup.CopyAs(self._slow_post_client, Test.RunDirectory)
        tr.Setup.CopyAs(self._quick_server, Test.RunDirectory)

        tr.Processes.Default.Command = (
            f'{sys.executable} {self._slow_post_client} '
            f'{self._ts.Variables.port}')
        tr.Processes.Default.ReturnCode = 0
        self._ts.StartBefore(self._dns)
        tr.Processes.Default.StartBefore(self._server)
        tr.Processes.Default.StartBefore(self._ts)
        tr.Timeout = 10


Test.Summary = __doc__
slowPostAttack = QuickServerTest()
slowPostAttack.run()
