'''
Verify caching of chunked responses.
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


class TestChunkedResponseCaching:
    '''Verify caching of chunked responses.'''

    replay_file: str = "replay/cache-chunked-response.replay.yaml"

    def __init__(self):
        '''Configure the test run to verify caching of chunked responses.'''

        tr = Test.AddTestRun("Verify caching of chunked responses.")
        self._setup_dns(tr)
        self._setup_server(tr)
        self._setup_traffic_server(tr)
        self._setup_client(tr)

    def _setup_dns(self, tr: 'TestRun') -> 'Process':
        '''Configure the DNS for the test run.

        :param tr: The test run to which to add the DNS.
        :return: The DNS process.
        '''
        dns = tr.MakeDNServer('dns', default='127.0.0.1')
        self._dns = dns
        return dns

    def _setup_server(self, tr: 'TestRun') -> 'Process':
        '''Configure the server for the test run.

        :param tr: The test run to which to add the server.
        :return: The server process.
        '''
        server = tr.AddVerifierServerProcess('server', self.replay_file)
        self._server = server
        return server

    def _setup_traffic_server(self, tr: 'TestRun') -> 'Process':
        '''Configure the traffic server for the test run.

        :param tr: The test run to which to add the traffic server.
        :return: The traffic server process.
        '''
        ts = tr.MakeATSProcess('ts')
        self._ts = ts
        ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http|cache',
                'proxy.config.http.insert_age_in_response': 0,
                'proxy.config.dns.nameservers': f"127.0.0.1:{self._dns.Variables.Port}",
                'proxy.config.dns.resolv_conf': 'NULL',
            })
        server_port = self._server.Variables.http_port
        ts.Disk.remap_config.AddLine(f'map / http://backend.server:{server_port}')
        return ts

    def _setup_client(self, tr: 'TestRun') -> 'Process':
        '''Configure the client for the test run.

        :param tr: The test run to which to add the client.
        :return: The client process.
        '''
        client = tr.AddVerifierClientProcess('client', self.replay_file, http_ports=[self._ts.Variables.port])
        self._client = client
        client.StartBefore(self._dns)
        client.StartBefore(self._server)
        client.StartBefore(self._ts)


TestChunkedResponseCaching()
