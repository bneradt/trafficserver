'''
Test that transform plugins receive all chunks of a chunked response.

This test verifies that when a server sends a chunked response with multiple
chunks arriving in separate TCP segments, a transform plugin receives all
the data, not just the last chunk.

See GitHub issue #12816.
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

from ports import get_port
import sys

Test.Summary = '''
Test that transform plugins receive all chunks of a chunked response.
'''

Test.SkipUnless(Condition.PluginExists('null_transform.so'))


class TransformChunkedTest:
    """Test transform plugin with multi-chunk chunked responses."""

    _server_script: str = 'chunked_server.py'
    _dns_counter: int = 0
    _server_counter: int = 0
    _ts_counter: int = 0

    def __init__(self) -> None:
        """Configure and run the test."""
        tr = Test.AddTestRun('Test transform with multi-chunk chunked response.')
        tr.TimeOut = 5
        self._configure_dns(tr)
        self._configure_server(tr)
        self._configure_traffic_server(tr)
        self._configure_client(tr)

    def _configure_dns(self, tr: 'TestRun') -> 'Process':
        """Configure the DNS.

        :param tr: The test run to associate with the DNS process.
        :return: The DNS process.
        """
        name = f'dns_{self._dns_counter}'
        TransformChunkedTest._dns_counter += 1
        dns = tr.MakeDNServer(name, default='127.0.0.1')
        self._dns = dns
        return dns

    def _configure_server(self, tr: 'TestRun') -> 'Process':
        """Configure the origin server that sends chunked responses.

        :param tr: The test run to associate with the origin server.
        :return: The origin server process.
        """
        name = f'server_{self._server_counter}'
        TransformChunkedTest._server_counter += 1
        server = tr.Processes.Process(name)
        tr.Setup.Copy(self._server_script)
        port = get_port(server, "http_port")
        # Use a delay between chunks to ensure they arrive separately.
        server.Command = f'{sys.executable} {self._server_script} 127.0.0.1 {port} --chunk-delay 0.1'
        server.ReturnCode = 0
        server.Ready = When.PortOpenv4(port)
        server.Streams.All += Testers.ContainsExpression('Response complete', 'Server should complete sending the response.')
        self._server = server
        return server

    def _configure_traffic_server(self, tr: 'TestRun') -> 'Process':
        """Configure ATS with the null_transform plugin.

        :param tr: The test run to associate with the ATS process.
        :return: The ATS process.
        """
        name = f'ts_{self._ts_counter}'
        TransformChunkedTest._ts_counter += 1
        ts = tr.MakeATSProcess(name, enable_cache=False)
        self._ts = ts

        ts.Disk.remap_config.AddLine(f'map / http://backend.server.com:{self._server.Variables.http_port}')

        ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http|null_transform',
                'proxy.config.dns.nameservers': f'127.0.0.1:{self._dns.Variables.Port}',
                'proxy.config.dns.resolv_conf': 'NULL',
            })

        # Load the null_transform plugin which will transform all 200 responses.
        Test.PrepareInstalledPlugin('null_transform.so', ts)

        # Verify the transform plugin logs that it processes data.
        ts.Disk.traffic_out.Content += Testers.ContainsExpression('null_transform', 'The null_transform plugin should be active.')

        return ts

    def _configure_client(self, tr: 'TestRun') -> 'Process':
        """Configure the client to make a request through ATS.

        :param tr: The test run to associate with the client process.
        :return: The client process.
        """
        tr.MakeCurlCommand(
            f'--proxy 127.0.0.1:{self._ts.Variables.port} '
            f'-H "Host: backend.server.com" '
            f'http://backend.server.com/test',
            ts=self._ts)

        client = tr.Processes.Default
        client.ReturnCode = 0

        # The server sends three chunks with the following content:
        # - "CHUNK_ONE_DATA_"
        # - "CHUNK_TWO_DATA_"
        # - "CHUNK_THREE_END"
        # The client should receive all of them concatenated.
        client.Streams.All += Testers.ContainsExpression('CHUNK_ONE_DATA_', 'Client should receive data from the first chunk.')
        client.Streams.All += Testers.ContainsExpression('CHUNK_TWO_DATA_', 'Client should receive data from the second chunk.')
        client.Streams.All += Testers.ContainsExpression('CHUNK_THREE_END', 'Client should receive data from the third chunk.')

        # The complete body should be the concatenation of all chunks.
        client.Streams.All += Testers.ContainsExpression(
            'CHUNK_ONE_DATA_CHUNK_TWO_DATA_CHUNK_THREE_END', 'Client should receive the complete body with all chunks.')

        client.StartBefore(self._dns)
        client.StartBefore(self._server)
        client.StartBefore(self._ts)

        return client


TransformChunkedTest()
