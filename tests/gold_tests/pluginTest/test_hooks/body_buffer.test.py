'''
Verify HTTP body buffering.
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

Test.SkipUnless(Condition.PluginExists('request_buffer.so'))


def int_to_hex_string(int_value):
    '''
    Convert the given int value to a hex string with no '0x' prefix.

    >>> int_to_hex_string(0)
    '0'
    >>> int_to_hex_string(1)
    '1'
    >>> int_to_hex_string(10)
    'a'
    >>> int_to_hex_string(16)
    '10'
    >>> int_to_hex_string(17)
    'f1'
    '''
    if not isinstance(int_value, int):
        raise ValueError("Input should be an int type.")
    return hex(int_value).split('x')[1]


class BodyBufferTest:

    def __init__(cls, description):
        Test.Summary = description
        cls._origin_max_connections = 3
        cls.setupOriginServer()
        cls.setupTS()

    def setupOriginServer(self):
        self._server = Test.MakeOriginServer("server")
        self.content_length_request_body = "content-length request"
        self.content_length_size = len(self.content_length_request_body)
        request_header = {
            "headers":
                "POST /contentlength HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                f"Content-Length: {self.content_length_size}\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": self.content_length_request_body
        }
        content_length_response_body = "content-length response"
        content_length_response_size = len(content_length_response_body)
        response_header = {
            "headers":
                "HTTP/1.1 200 OK\r\n"
                "Server: microserver\r\n"
                f"Content-Length: {content_length_response_size}\r\n\r\n"
                "Connection: close\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": content_length_response_body
        }
        self._server.addResponse("sessionlog.json", request_header, response_header)

        self.chunked_request_body = "chunked request"
        hex_size = int_to_hex_string(len(self.chunked_request_body))
        self.encoded_chunked_request = f"{hex_size}\r\n{self.chunked_request_body}\r\n0\r\n\r\n"
        self.encoded_chunked_size = len(self.content_length_request_body)
        request_header2 = {
            "headers":
                "POST /chunked HTTP/1.1\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": self.encoded_chunked_request
        }
        self.chunked_response_body = "chunked response"
        hex_size = int_to_hex_string(len(self.chunked_response_body))
        self.encoded_chunked_response = f"{hex_size}\r\n{self.chunked_response_body}\r\n0\r\n\r\n"
        response_header2 = {
            "headers": "HTTP/1.1 200 OK\r\n"
                       "Transfer-Encoding: chunked\r\n"
                       "Server: microserver\r\n"
                       "Connection: close\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": self.encoded_chunked_response
        }
        self._server.addResponse("sessionlog.json", request_header2, response_header2)

    def setupTS(self):
        self._ts = Test.MakeATSProcess("ts", select_ports=False)
        self._ts.Disk.remap_config.AddLine(f'map / http://127.0.0.1:{self._server.Variables.Port}')
        Test.PrepareInstalledPlugin('request_buffer.so', self._ts)
        self._ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'request_buffer',
                'proxy.config.http.server_ports': str(self._ts.Variables.port) + f" {self._ts.Variables.uds_path}",
            })

        self._ts.Disk.traffic_out.Content = Testers.ContainsExpression(
            rf"request_buffer_plugin gets the request body with length\[{self.content_length_size}\]",
            "Verify that the plugin parsed the content-length request body data.")
        self._ts.Disk.traffic_out.Content += Testers.ContainsExpression(
            rf"request_buffer_plugin gets the request body with length\[{self.encoded_chunked_size}\]",
            "Verify that the plugin parsed the chunked request body.")

    def run(self):
        tr = Test.AddTestRun()
        # Send both a Content-Length request and a chunked-encoded request.
        tr.MakeCurlCommand(
            f'-v http://127.0.0.1:{self._ts.Variables.port}/contentlength -d "{self.content_length_request_body}" --next '
            f'-v http://127.0.0.1:{self._ts.Variables.port}/chunked -H "Transfer-Encoding: chunked" -d "{self.chunked_request_body}"',
            ts=self._ts)
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.StartBefore(self._server)
        tr.Processes.Default.StartBefore(Test.Processes.ts)
        tr.Processes.Default.Streams.stderr = "200.gold"


class ZeroPostCopySizeTest:
    '''
    Test for issue #6900: Verify that post_copy_size=0 with request_buffer_enabled=1
    does not cause 403 errors. When post_copy_size is 0, request buffering should be
    disabled and POST requests should proceed normally.
    '''

    def __init__(self):
        self.setupOriginServer()
        self.setupTS()

    def setupOriginServer(self):
        self._server = Test.MakeOriginServer("server_zero_copy")
        # Empty body POST
        request_header_empty = {
            "headers": "POST /empty HTTP/1.1\r\n"
                       "Host: www.example.com\r\n"
                       "Content-Length: 0\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": ""
        }
        response_header_empty = {
            "headers": "HTTP/1.1 200 OK\r\n"
                       "Server: microserver\r\n"
                       "Content-Length: 2\r\n"
                       "Connection: close\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": "OK"
        }
        self._server.addResponse("sessionlog.json", request_header_empty, response_header_empty)

        # Small body POST
        self.small_body = "small"
        request_header_small = {
            "headers": "POST /small HTTP/1.1\r\n"
                       "Host: www.example.com\r\n"
                       f"Content-Length: {len(self.small_body)}\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": self.small_body
        }
        response_header_small = {
            "headers": "HTTP/1.1 200 OK\r\n"
                       "Server: microserver\r\n"
                       "Content-Length: 2\r\n"
                       "Connection: close\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": "OK"
        }
        self._server.addResponse("sessionlog.json", request_header_small, response_header_small)

    def setupTS(self):
        # Use default port selection (not select_ports=False) to avoid port conflicts
        self._ts = Test.MakeATSProcess("ts_zero_copy")
        self._ts.Disk.remap_config.AddLine(f'map / http://127.0.0.1:{self._server.Variables.Port}')
        # Install the request_buffer plugin to enable per-request buffering
        Test.PrepareInstalledPlugin('request_buffer.so', self._ts)
        self._ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http|request_buffer',
                # The key configuration: post_copy_size=0 with request_buffer_enabled=1
                # This should NOT cause 403 errors (issue #6900 fix)
                # The plugin will enable buffering per-request, but with post_copy_size=0
                # buffering should be disabled and the request should proceed normally
                'proxy.config.http.post_copy_size': 0,
                'proxy.config.http.request_buffer_enabled': 1,
            })

    def run(self):
        tr = Test.AddTestRun()
        # Send POST with empty body and small body.
        # These should return 200, not 403, verifying the fix for issue #6900.
        tr.MakeCurlCommand(
            f'-v -X POST -H "Content-Length: 0" http://127.0.0.1:{self._ts.Variables.port}/empty --next '
            f'-v http://127.0.0.1:{self._ts.Variables.port}/small -d {self.small_body}',
            ts=self._ts)
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.StartBefore(self._server)
        tr.Processes.Default.StartBefore(self._ts)
        # Verify we get 200 OK, not 403 Forbidden
        tr.Processes.Default.Streams.stderr += Testers.ContainsExpression(
            "< HTTP/1.1 200 OK", "Verify POST with empty body returns 200")
        tr.Processes.Default.Streams.stderr += Testers.ExcludesExpression("< HTTP/1.1 403", "Verify no 403 Forbidden errors")


bodyBufferTest = BodyBufferTest("Test request body buffering.")
bodyBufferTest.run()

# Test for issue #6900: post_copy_size=0 should not cause 403 errors
zeroCopySizeTest = ZeroPostCopySizeTest()
zeroCopySizeTest.run()
