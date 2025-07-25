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

Test.Summary = '''
Test tunneling and forwarding based on SNI
'''

# Define default ATS
ts = Test.MakeATSProcess("ts", enable_tls=True)
server_foo = Test.MakeOriginServer("server_foo", ssl=True)
server_bar = Test.MakeOriginServer("server_bar", ssl=False)
server_random = Test.MakeOriginServer("server_random", ssl=False)
nameserver = Test.MakeDNServer("dns", default='127.0.0.1')

request_foo_header = {"headers": "GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
request_bar_header = {"headers": "GET / HTTP/1.1\r\nHost: bar.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
request_random_header = {"headers": "GET / HTTP/1.1\r\nHost: random.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_foo_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "ok foo"}
response_bar_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "ok bar"}
response_random_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "ok random"
}
server_foo.addResponse("sessionlog_foo.json", request_foo_header, response_foo_header)
server_bar.addResponse("sessionlog_bar.json", request_bar_header, response_bar_header)
server_random.addResponse("sessionlog_random.json", request_random_header, response_random_header)

# add ssl materials like key, certificates for the server
ts.addSSLfile("ssl/signed-foo.pem")
ts.addSSLfile("ssl/signed-foo.key")
ts.addSSLfile("ssl/signed-bar.pem")
ts.addSSLfile("ssl/signed-bar.key")
ts.addSSLfile("ssl/server.pem")
ts.addSSLfile("ssl/server.key")
ts.addSSLfile("ssl/signer.pem")
ts.addSSLfile("ssl/signer.key")

# Need no remap rules.  Everything should be processed by sni

# Make sure the TS server certs are different from the origin certs
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=signed-foo.pem ssl_key_name=signed-foo.key')

# Case 1, global config policy=permissive properties=signature
#         override for foo.com policy=enforced properties=all
ts.Disk.records_config.update(
    {
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.http.connect_ports':
            '{0} {1} {2} {3}'.format(
                ts.Variables.ssl_port, server_foo.Variables.SSL_Port, server_bar.Variables.Port, server_random.Variables.Port),
        'proxy.config.ssl.client.CA.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.client.CA.cert.filename': 'signer.pem',
        'proxy.config.exec_thread.autoconfig.scale': 1.0,
        'proxy.config.url_remap.pristine_host_hdr': 1,
        'proxy.config.dns.nameservers': f"127.0.0.1:{nameserver.Variables.Port}",
        'proxy.config.dns.resolv_conf': 'NULL'
    })

# foo.com should not terminate.  Just tunnel to server_foo
# bar.com should terminate.  Forward its tcp stream to server_bar
ts.Disk.sni_yaml.AddLines(
    [
        "sni:",
        "- fqdn: 'foo.com'",
        "  tunnel_route: 'localhost:{0}'".format(server_foo.Variables.SSL_Port),
        "- fqdn: 'bar.com'",
        "  forward_route: 'localhost:{0}'".format(server_bar.Variables.Port),
        "- fqdn: ''",  # default case
        "  forward_route: 'localhost:{0}'".format(server_random.Variables.Port),
    ])

tr = Test.AddTestRun("Tunnel-test")
tr.MakeCurlCommand("-v  --resolve 'foo.com:{0}:127.0.0.1' -k  https://foo.com:{0}".format(ts.Variables.ssl_port), ts=ts)
tr.ReturnCode = 0
tr.Processes.Default.StartBefore(server_foo)
tr.Processes.Default.StartBefore(server_bar)
tr.Processes.Default.StartBefore(server_random)
tr.Processes.Default.StartBefore(nameserver)
tr.Processes.Default.StartBefore(Test.Processes.ts)
tr.StillRunningAfter = ts
tr.Processes.Default.Streams.All += Testers.ExcludesExpression("Could Not Connect", "Curl attempt should have succeeded")
tr.Processes.Default.Streams.All += Testers.ExcludesExpression(
    "Not Found on Accelerato", "Should not try to remap on Traffic Server")
tr.Processes.Default.Streams.All += Testers.ExcludesExpression("CN=foo.com", "Should not TLS terminate on Traffic Server")
tr.Processes.Default.Streams.All += Testers.ContainsExpression("HTTP/1.1 200 OK", "Should get a successful response")
tr.Processes.Default.Streams.All += Testers.ContainsExpression("ok foo", "Body is expected")

tr2 = Test.AddTestRun("Forward-test")
tr2.MakeCurlCommand(
    "-v --http1.1  -H 'host:bar.com' --resolve 'bar.com:{0}:127.0.0.1' -k https://bar.com:{0}".format(ts.Variables.ssl_port), ts=ts)
tr2.ReturnCode = 0
tr2.StillRunningAfter = server_bar
tr2.StillRunningAfter = ts
tr2.Processes.Default.Streams.All += Testers.ExcludesExpression("Could Not Connect", "Curl attempt should have succeeded")
tr2.Processes.Default.Streams.All += Testers.ExcludesExpression(
    "Not Found on Accelerato", "Should not try to remap on Traffic Server")
tr2.Processes.Default.Streams.All += Testers.ContainsExpression("CN=foo.com", "Should TLS terminate on Traffic Server")
tr2.Processes.Default.Streams.All += Testers.ContainsExpression("HTTP/1.1 200 OK", "Should get a successful response")
tr2.Processes.Default.Streams.All += Testers.ContainsExpression("ok bar", "Body is expected")

tr3 = Test.AddTestRun("no-sni-forward-test")
tr3.MakeCurlCommand("--http1.1 -v -k -H 'host:random.com' https://127.0.0.1:{0}".format(ts.Variables.ssl_port), ts=ts)
tr3.ReturnCode = 0
tr3.StillRunningAfter = server_random
tr3.StillRunningAfter = ts
tr3.Processes.Default.Streams.All += Testers.ExcludesExpression("Could Not Connect", "Curl attempt should have succeeded")
tr3.Processes.Default.Streams.All += Testers.ExcludesExpression(
    "Not Found on Accelerato", "Should not try to remap on Traffic Server")
tr3.Processes.Default.Streams.All += Testers.ContainsExpression("CN=foo.com", "Should TLS terminate on Traffic Server")
tr3.Processes.Default.Streams.All += Testers.ContainsExpression("HTTP/1.1 200 OK", "Should get a successful response")
tr3.Processes.Default.Streams.All += Testers.ContainsExpression("ok random", "Body is expected")

tr = Test.AddTestRun("Test Metrics")
tr.Processes.Default.Command = (
    f"{Test.Variables.AtsTestToolsDir}/stdout_wait" + " 'traffic_ctl metric get" +
    " proxy.process.http.total_incoming_connections" + " proxy.process.http.total_client_connections" +
    " proxy.process.http.total_client_connections_ipv4" + " proxy.process.http.total_client_connections_ipv6" +
    " proxy.process.http.total_server_connections" + " proxy.process.http2.total_client_connections" +
    " proxy.process.http.connect_requests" + " proxy.process.tunnel.total_client_connections_blind_tcp" +
    " proxy.process.tunnel.current_client_connections_blind_tcp" + " proxy.process.tunnel.total_server_connections_blind_tcp" +
    " proxy.process.tunnel.current_server_connections_blind_tcp" + " proxy.process.tunnel.total_client_connections_tls_tunnel" +
    " proxy.process.tunnel.current_client_connections_tls_tunnel" + " proxy.process.tunnel.total_client_connections_tls_forward" +
    " proxy.process.tunnel.current_client_connections_tls_forward" +
    " proxy.process.tunnel.total_client_connections_tls_partial_blind" +
    " proxy.process.tunnel.current_client_connections_tls_partial_blind" +
    " proxy.process.tunnel.total_client_connections_tls_http" + " proxy.process.tunnel.current_client_connections_tls_http" +
    " proxy.process.tunnel.total_server_connections_tls" + " proxy.process.tunnel.current_server_connections_tls'" +
    f" {Test.TestDirectory}/gold/tls-tunnel-forward-metrics.gold")
# Need to copy over the environment so traffic_ctl knows where to find the unix domain socket
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = ts
