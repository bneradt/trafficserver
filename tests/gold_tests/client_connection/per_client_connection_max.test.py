'''
Verify the behavior of proxy.config.net.per_client.connection.max.
'''
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


Test.Summary = __doc__


class PerClientConnectionMaxTest:
    """Define an object to test our max client connection behavior."""

    _replay_file: str = 'slow_origins.replay.yaml'
    _origin_max_connections: int = 3

    def __init__(self) -> None:
        """Configure the test processes in preparation for the TestRun."""
        tr = Test.AddTestRun(
            'Verify we enforce proxy.config.net.per_client.connection.max')
        self._configure_dns(tr)
        self._configure_server(tr)
        self._configure_trafficserver()
        self._configure_client(tr)
        self._verify_metrics()

    def _configure_dns(self, tr: 'TestRun') -> None:
        """Configure a nameserver for the test.

        :param tr: The TestRun to add the nameserver to.
        """
        self._dns = tr.MakeDNServer("dns1", default='127.0.0.1')

    def _configure_server(self, tr: 'TestRun') -> None:
        """Configure the server to be used in the test.

        :param tr: The TestRun to add the server to.
        """
        self._server = tr.AddVerifierServerProcess('server1', self._replay_file)
        self._server.Streams.All += Testers.ContainsExpression(
            "first-request",
            "Verify the first request should have been received.")
        self._server.Streams.All += Testers.ContainsExpression(
            "second-request",
            "Verify the second request should have been received.")
        self._server.Streams.All += Testers.ContainsExpression(
            "third-request",
            "Verify the third request should have been received.")
        self._server.Streams.All += Testers.ContainsExpression(
            "fifth-request",
            "Verify the fifth request should have been received.")

        # The fourth request should be blocked due to too many connections.
        self._server.Streams.All += Testers.ExcludesExpression(
            "fourth-request",
            "Verify the fourth request should not be received.")

    def _configure_trafficserver(self) -> None:
        """Configure Traffic Server to be used in the test."""
        # Associate ATS with the Test so that metrics can be verified.
        self._ts = Test.MakeATSProcess("ts1", enable_cache=False)
        self._ts.Disk.remap_config.AddLine(
            f'map / http://127.0.0.1:{self._server.Variables.http_port}'
        )
        self._ts.Disk.records_config.update({
            'proxy.config.dns.nameservers': f"127.0.0.1:{self._dns.Variables.Port}",
            'proxy.config.dns.resolv_conf': 'NULL',

            'proxy.config.diags.debug.enabled': 1,
            'proxy.config.diags.debug.tags': 'socket|http|net_queue|iocore_net|conn_track',

            'proxy.config.net.per_client.max_connections_in': self._origin_max_connections,
            # Disable keep-alive so we close the client connections when the
            # transactions are done. This allows us to verify cleanup is working
            # per the ConnectionTracker metrics.
            'proxy.config.http.keep_alive_enabled_in': 0,
        })
        self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
            f'WARNING:.*too many connections:.*limit={self._origin_max_connections}',
            'Verify the user is warned about the connection limit being hit.')

    def _configure_client(self, tr: 'TestRun') -> None:
        """Configure the TestRun.

        :param tr: The TestRun to add the client to.
        """
        p = tr.AddVerifierClientProcess(
            'client',
            self._replay_file,
            http_ports=[self._ts.Variables.port])

        p.StartBefore(self._dns)
        p.StartBefore(self._server)
        p.StartBefore(self._ts)

        # Because the fourth connection will be aborted, the client will have a
        # non-zero return code.
        p.ReturnCode = 1
        p.Streams.All += Testers.ContainsExpression(
            "The peer closed the connection while reading.",
            "A connection should be closed due to too many client connections.")
        p.Streams.All += Testers.ContainsExpression(
            "Failed HTTP/1 transaction with key: fourth-request",
            "The fourth request should fail.")

    def _verify_metrics(self) -> None:
        """Verify the per client connection metrics."""
        tr = Test.AddTestRun("Verify the per client connection metrics.")
        tr.Processes.Default.Env = self._ts.Env
        tr.Processes.Default.Command = (
            'traffic_ctl metric get '
            'proxy.process.net.per_client.connections_throttled_in '
            'proxy.process.net.connection_tracker_table_size'
        )
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.All += Testers.ContainsExpression(
            'proxy.process.net.per_client.connections_throttled_in 1',
            'Verify the per client throttled metric is correct.')
        tr.Processes.Default.Streams.All += Testers.ContainsExpression(
            'proxy.process.net.connection_tracker_table_size 0',
            'Verify the table was cleaned up correctly.')


PerClientConnectionMaxTest()
