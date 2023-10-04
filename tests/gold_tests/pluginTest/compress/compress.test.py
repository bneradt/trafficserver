'''
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

import os
import re

Test.Summary = '''
Test compress plugin
'''

# This test case is very bare-bones.  It only covers a few scenarios that have caused problems.

# Skip if plugins not present.
#
Test.SkipUnless(
    Condition.PluginExists('compress.so'),
    Condition.PluginExists('conf_remap.so'),
    Condition.HasATSFeature('TS_HAS_BROTLI')
)

#server = Test.MakeOriginServer("server", options={'--load': '{}/compress_observer.py'.format(Test.TestDirectory)})
#
#
# def repeat(str, count):
#    result = ""
#    while count > 0:
#        result += str
#        count -= 1
#    return result
#
#
# Need a fairly big body, otherwise the plugin will refuse to compress
#body = repeat("lets go surfin now everybodys learnin how\n", 24)
#body = body + "lets go surfin now everybodys learnin how"
#
# expected response from the origin server
# response_header = {
#    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n" +
#    'Etag: "359670651"\r\n' +
#    "Cache-Control: public, max-age=31536000\r\n" +
#    "Accept-Ranges: bytes\r\n" +
#    "Content-Type: text/javascript\r\n" +
#    "\r\n",
#    "timestamp": "1469733493.993",
#    "body": body
# }
# for i in range(3):
#    # add request/response to the server dictionary
#    request_header = {
#        "headers": "GET /obj{} HTTP/1.1\r\nHost: just.any.thing\r\n\r\n".format(i), "timestamp": "1469733493.993", "body": ""
#    }
#    server.addResponse("sessionfile.log", request_header, response_header)
#
#
# post for the origin server
# post_request_header = {
#    "headers": "POST /obj3 HTTP/1.1\r\nHost: just.any.thing\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\n",
#    "timestamp": "1469733493.993",
#    "body": "knock knock"}
#server.addResponse("sessionfile.log", post_request_header, response_header)
#
#
# def curl(ts, idx, encodingList):
#    return (
#        "curl --verbose --proxy http://127.0.0.1:{}".format(ts.Variables.port) +
#        " --header 'X-Ats-Compress-Test: {}/{}'".format(idx, encodingList) +
#        " --header 'Accept-Encoding: {0}' 'http://ae-{1}/obj{1}'".format(encodingList, idx) +
#        " 2>> compress_long.log ; printf '\n===\n' >> compress_long.log"
#    )
#
#
# def curl_post(ts, idx, encodingList):
#    return (
#        "curl --verbose -d 'knock knock' --proxy http://127.0.0.1:{}".format(ts.Variables.port) +
#        " --header 'X-Ats-Compress-Test: {}/{}'".format(idx, encodingList) +
#        " --header 'Accept-Encoding: {0}' 'http://ae-{1}/obj{1}'".format(encodingList, idx) +
#        " 2>> compress_long.log ; printf '\n===\n' >> compress_long.log"
#    )
#
#
#waitForServer = True
#
#waitForTs = True
#
#ts = Test.MakeATSProcess("ts", enable_cache=False)
#
# ts.Disk.records_config.update({
#    'proxy.config.diags.debug.enabled': 1,
#    'proxy.config.diags.debug.tags': 'compress',
#    'proxy.config.http.normalize_ae': 0,
# })
#
# ts.Setup.Copy("compress.config")
# ts.Setup.Copy("compress2.config")
#
# ts.Disk.remap_config.AddLine(
#    'map http://ae-0/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
#    ' @plugin=compress.so @pparam={}/compress.config'.format(Test.RunDirectory)
# )
# ts.Disk.remap_config.AddLine(
#    'map http://ae-1/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
#    ' @plugin=conf_remap.so @pparam=proxy.config.http.normalize_ae=1' +
#    ' @plugin=compress.so @pparam={}/compress.config'.format(Test.RunDirectory)
# )
# ts.Disk.remap_config.AddLine(
#    'map http://ae-2/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
#    ' @plugin=conf_remap.so @pparam=proxy.config.http.normalize_ae=2' +
#    ' @plugin=compress.so @pparam={}/compress2.config'.format(Test.RunDirectory)
# )
# ts.Disk.remap_config.AddLine(
#    'map http://ae-3/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
#    ' @plugin=compress.so @pparam={}/compress.config'.format(Test.RunDirectory)
# )
#
# for i in range(3):
#
#    tr = Test.AddTestRun()
#    if (waitForTs):
#        tr.Processes.Default.StartBefore(ts)
#    waitForTs = False
#    if (waitForServer):
#        tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
#    waitForServer = False
#    tr.Processes.Default.ReturnCode = 0
#    tr.Processes.Default.Command = curl(ts, i, 'gzip, deflate, sdch, br')
#
#    tr = Test.AddTestRun()
#    tr.Processes.Default.ReturnCode = 0
#    tr.Processes.Default.Command = curl(ts, i, "gzip")
#
#    tr = Test.AddTestRun()
#    tr.Processes.Default.ReturnCode = 0
#    tr.Processes.Default.Command = curl(ts, i, "br")
#
#    tr = Test.AddTestRun()
#    tr.Processes.Default.ReturnCode = 0
#    tr.Processes.Default.Command = curl(ts, i, "deflate")
#
# Test Accept-Encoding normalization.
#
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
#tr.Processes.Default.Command = curl(ts, 0, "gzip;q=0.666")
#
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
#tr.Processes.Default.Command = curl(ts, 0, "gzip;q=0.666x")
#
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
# tr.Processes.Default.Command = curl(ts, 0, "gzip;q=#0.666")
#
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
#tr.Processes.Default.Command = curl(ts, 0, "gzip; Q = 0.666")
#
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
#tr.Processes.Default.Command = curl(ts, 0, "gzip;q=0.0")
#
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
#tr.Processes.Default.Command = curl(ts, 0, "gzip;q=-0.1")
#
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
#tr.Processes.Default.Command = curl(ts, 0, "aaa, gzip;q=0.666, bbb")
#
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
#tr.Processes.Default.Command = curl(ts, 0, " br ; q=0.666, bbb")
#
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
#tr.Processes.Default.Command = curl(ts, 0, "aaa, gzip;q=0.666 , ")
#
# post
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
#tr.Processes.Default.Command = curl_post(ts, 3, "gzip")
#
# compress_long.log contains all the output from the curl commands.  The tr removes the carriage returns for easier
# readability.  Curl seems to have a bug, where it will neglect to output an end of line before outputting an HTTP
# message header line.  The sed command is a work-around for this problem.  greplog.sh uses the grep command to
# select HTTP request/response line that should be consistent every time the test runs.
##
#tr = Test.AddTestRun()
#tr.Processes.Default.ReturnCode = 0
# tr.Processes.Default.Command = (
#    r"tr -d '\r' < compress_long.log | sed 's/\(..*\)\([<>]\)/\1\n\2/' | {0}/greplog.sh > compress_short.log"
# ).format(Test.TestDirectory)
#f = tr.Disk.File("compress_short.log")
#f.Content = "compress.gold"
#
#tr = Test.AddTestRun()
#tr.Processes.Default.Command = "echo"
#f = tr.Disk.File("compress_userver.log")
#f.Content = "compress_userver.gold"


class TestClChunk:
    """Test compress handling of Content-Length and chunked encoded responses. """

    _replay_file: str = 'replay/test_cl_chunk.replay.yaml'

    def __init__(self) -> None:
        """Configure the test runs for the test."""
        tr = Test.AddTestRun("Verify Content-Length and chunked encoding")

        self._dns = self._configure_dns(tr)
        self._server = self._configure_server(tr)
        self._ts = self._configure_ts(tr, self._dns.Variables.Port, self._server.Variables.http_port)
        self._configure_client(tr, self._ts.Variables.port)

    def _configure_dns(self, tr: 'TestRun') -> 'Process':
        """Configure a DNS for the test.

        :param tr: A TestRun for the process to be associated with.
        :return: A DNS Process for the test.
        """
        return tr.MakeDNS("dns", default='127.0.0.1')

    def _configure_server(self, tr: 'TestRun') -> 'Process':
        """Configure an origin server for the test.

        :param tr: A TestRun for the process to be associated with.
        :return: An origin server Process for the test.
        """
        return tr.AddVerifierServerProcess('server', TestClChunk._replay_file)

    def _configure_ts(self, tr: 'TestRun', dns_port: int, server_port: int) -> 'Process':
        """Configure a Traffic Server for the test.

        :param tr: A TestRun for the process to be associated with.
        :param dns_port: The port number of the DNS.
        :param server_port: The port number of the origin server.
        :return: A Traffic Server Process for the test.
        """

        ts = Test.MakeATSProcess("ts")

        ts.Disk.records_config.update({
            'proxy.config.diags.debug.enabled': 1,
            'proxy.config.diags.debug.tags': 'http|compress|cache',

            # Make caching easier.
            "proxy.config.http.cache.required_headers": 0,
            "proxy.config.http.insert_response_via_str": 2,

            'proxy.config.dns.nameservers': f"127.0.0.1:{dns_port}",
            'proxy.config.dns.resolv_conf': "NULL",

            'proxy.config.http.cache.ignore_client_cc_max_age': 1,
            'proxy.config.http.normalize_ae': 1,
            'proxy.config.http.cache.cache_responses_to_cookies': 1,
            'proxy.config.http.cache.cache_urls_that_look_dynamic': 1,
            'proxy.config.http.cache.when_to_revalidate': 0,
            'proxy.config.http.cache.required_headers': 1,



            'proxy.config.http.cache.heuristic_min_lifetime': 3600,
            'proxy.config.http.cache.heuristic_max_lifetime': 86400,
            'proxy.config.http.cache.heuristic_lm_factor': 0.1,
            'proxy.config.net.connections_throttle': 0,
            'proxy.config.net.max_connections_in': 0,
            'proxy.config.net.max_requests_in': 0,
            'proxy.config.cache.ram_cache.size': 32000000000,
            'proxy.config.cache.ram_cache_cutoff': 16777216,
            'proxy.config.cache.limits.http.max_alts': 4,
            'proxy.config.cache.log.alternate.eviction': 0,
            'proxy.config.cache.max_doc_size': 0,
            'proxy.config.cache.min_average_object_size': 12000,

            'proxy.config.http.wait_for_cache': 2,
            'proxy.config.http.cache.ignore_client_no_cache': 1,
            'proxy.config.http.cache.ims_on_client_no_cache': 1,
            'proxy.config.http.cache.ignore_server_no_cache': 0,
            'proxy.config.http.cache.open_write_fail_action': 0,
            'proxy.config.http.cache.ignore_authentication': 1,
            'proxy.config.http.cache.max_stale_age': 604800,
            'proxy.config.http.cache.range.lookup': 1,
            'proxy.config.http.cache.range.write': 0,
            'proxy.config.cache.enable_checksum': 0,
            'proxy.config.http_ui_enabled': 2,
            'proxy.config.http.enable_http_stats': 1,
            'proxy.config.websocket.no_activity_timeout': 600,
            'proxy.config.websocket.active_timeout': 3600,
            'proxy.config.body_factory.enable_customizations': 1,
            'proxy.config.body_factory.enable_logging': 0,
            'proxy.config.body_factory.response_suppression_mode': 0,
            'proxy.config.net.defer_accept': 45,
            'proxy.config.cache.permit.pinning': 0,
            'proxy.config.cache.ram_cache.algorithm': 1,
            'proxy.config.cache.ram_cache.use_seen_filter': 0,
            'proxy.config.cache.ram_cache.compress': 0,
            'proxy.config.cache.select_alternate': 1,
            'proxy.config.cache.target_fragment_size': 1048576,
            'proxy.config.cache.enable_read_while_writer': 1,
            'proxy.config.cache.read_while_writer.max_retries': 10,
            'proxy.config.cache.mutex_retry_delay': 2,

            'proxy.config.ssl.client.sni_policy STRING remap': 'remap',
        })
        tr.Setup.Copy("compress3.config")
        config_path = os.path.join(tr.TestDirectory, 'compress3.config')
        ts.Disk.remap_config.AddLine(
            f'map / http://127.0.0.1:{server_port}/ @plugin=compress.so @pparam={config_path}'
        )
        return ts

    def _configure_client(self, tr: 'TestRun', port: int) -> None:
        """Configure a client for the test.

        :param tr: A TestRun for the process to be associated with.
        :param port: The port number of the Traffic Server.
        """
        client = tr.AddVerifierClientProcess("client", TestClChunk._replay_file, http_ports=[port])
        self._server.StartBefore(self._dns)
        self._ts.StartBefore(self._server)
        client.StartBefore(self._ts)

        # 'x-response: first-miss' should be received first by the origin as a
        # miss, then by ATS from its cache.
        client.Streams.All += Testers.ContainsExpression(
            'x-response: first-miss.*x-response: first-miss',
            'Verify the first response was received twice by the client',
            reflags=re.DOTALL | re.MULTILINE)


TestClChunk()
