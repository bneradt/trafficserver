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
Test the ability for data sink plugins to close the connection.
'''


class TestDataSinkClose:
    """Test data sink close."""

    plugin_name: str = "filter_body"
    dns_counter: int = 0
    server_counter: int = 0
    ts_counter: int = 0
    client_counter: int = 0

    # Create an enumeration for the different types of tests: HTTP, HTTPS, HTTP/2.
    HTTP: int = 0
    HTTPS: int = 1
    HTTP2: int = 2

    def __init__(self, type: int, replay_file: str) -> None:
        """Initialize the test.

        :param description: The description of the test run.
        :param replay_file: The replay file to use.
        """
        self._type = type

        if type == TestDataSinkClose.HTTP:
            description = "HTTP"
        elif type == TestDataSinkClose.HTTPS:
            description = "HTTPS"
        else:
            description = "HTTP/2"

        self._replay_file = replay_file
        self._tr = Test.AddTestRun(f"Test Data Sink Close: {description}")

        self._dns = self._configure_dns(self._tr)

        self._server = self._configure_server(self._tr)
        if type == TestDataSinkClose.HTTP:
            server_port = self._server.Variables.http_port
        else:
            server_port = self._server.Variables.https_port

        self._ts = self._configure_ts(
            self._tr,
            self._dns.Variables.Port,
            server_port)
        if type == TestDataSinkClose.HTTP:
            ts_port = self._ts.Variables.port
        else:
            ts_port = self._ts.Variables.ssl_port

        self._configure_client(self._tr, ts_port)

    def _configure_dns(self, tr: 'TestRun') -> 'Process':
        """Configure DNS for the TestRun.

        :param tr: The TestRun to associate the DNS with.
        :return: The DNS Process.
        """
        name = f"dns_{TestDataSinkClose.dns_counter}"
        TestDataSinkClose.dns_counter += 1
        return tr.MakeDNServer(name, default='127.0.0.1')

    def _configure_server(self, tr: 'TestRun') -> 'Process':
        """Configure the server for the TestRun.

        :param tr: The TestRun to associate the server with.
        :return: The server Process.
        """
        name = f"server_{TestDataSinkClose.server_counter}"
        TestDataSinkClose.server_counter += 1
        server = tr.AddVerifierServerProcess(name, self._replay_file)
        return server

    def _configure_ts(self, tr: 'TestRun', dns_port: int, server_port: int) -> 'Process':
        """Configure the TS for the TestRun.

        :param tr: The TestRun to associate the TS with.
        :param dns_port: The DNS port to use.
        :param server_port: The server port to use.
        :return: The TS Process.
        """
        name = f"ts_{TestDataSinkClose.ts_counter}"
        TestDataSinkClose.ts_counter += 1
        ts = tr.MakeATSProcess(name, enable_tls=True, enable_cache=False)
        ts.addDefaultSSLFiles()
        ts.Disk.records_config.update({
            "proxy.config.ssl.server.cert.path": ts.Variables.SSLDir,
            "proxy.config.ssl.server.private_key.path": ts.Variables.SSLDir,
            "proxy.config.ssl.client.verify.server.policy": 'PERMISSIVE',

            'proxy.config.dns.nameservers': f'127.0.0.1:{dns_port}',
            'proxy.config.dns.resolv_conf': 'NULL',

            'proxy.config.diags.debug.enabled': 3,
            'proxy.config.diags.debug.tags': f'http|{self.plugin_name}',
        })
        ts.Disk.ssl_multicert_config.AddLine("dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key")
        pp = os.path.join(Test.Variables.AtsBuildGoldTestsDir, 'pluginTest', 'filter_body', '.libs', f'{self.plugin_name}.so')
        ts.Setup.Copy(pp, ts.Env['PROXY_CONFIG_PLUGIN_PLUGIN_DIR'])
        ts.Disk.plugin_config.AddLine(f"{self.plugin_name}.so")
        if self._type == TestDataSinkClose.HTTP:
            scheme = "http"
        else:
            scheme = "https"
        ts.Disk.remap_config.AddLine(
            f"map / {scheme}://backend.example.com:{server_port}"
        )
        return ts

    def _configure_client(self, tr: 'TestRun', ts_port: int):
        """Configure the client for the TestRun.

        :param tr: The TestRun to associate the client with.
        """
        name = f"client_{TestDataSinkClose.client_counter}"
        TestDataSinkClose.client_counter += 1
        if self._type == TestDataSinkClose.HTTP:
            client = tr.AddVerifierClientProcess(
                name,
                self._replay_file,
                http_ports=[ts_port],
                other_args='--thread-limit 1')
        else:
            # Note, https_ports instead of http_ports.
            client = tr.AddVerifierClientProcess(
                name,
                self._replay_file,
                https_ports=[ts_port],
                other_args='--thread-limit 1')

        # Verify that the client has a non-zero return code because the sesssion
        # gets dropped before the response is received by ATS.
        if self._type == TestDataSinkClose.HTTP2:
            # Proxy Verifier doesn't propagate the nghttp2 read error as a
            # non-zero return code.
            client.ReturnCode = 0
        else:
            client.ReturnCode = 1
        client.Streams.All += Testers.ExcludesExpression(
            "rejected-response",
            "Client should not receive the response from the dropped connection.")

        self._server.StartBefore(self._dns)
        self._ts.StartBefore(self._server)
        client.StartBefore(self._ts)


TestDataSinkClose(TestDataSinkClose.HTTP, "replay/killed_session.replay.yaml")
TestDataSinkClose(TestDataSinkClose.HTTPS, "replay/killed_session_tls.replay.yaml")
TestDataSinkClose(TestDataSinkClose.HTTP2, "replay/killed_session_h2.replay.yaml")
