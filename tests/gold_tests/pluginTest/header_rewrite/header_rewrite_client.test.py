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
Test header_rewrite and CLIENT-URL
'''

Test.ContinueOnFail = True
# Define default ATS
ts = Test.MakeATSProcess("ts", enable_tls=True)
server = Test.MakeOriginServer("server")
dns = Test.MakeDNServer("dns")

Test.testName = ""
request_header = {"headers": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
server.addResponse("sessionfile.log", request_header, response_header)
request_header = {"headers": "GET / HTTP/1.1\r\nHost: no_path.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
server.addResponse("sessionfile.log", request_header, response_header)

ts.addSSLfile("ssl/server.pem")
ts.addSSLfile("ssl/server.key")
ts.addSSLfile("ssl/signer.pem")

ts.Setup.Copy("ssl/signed-foo.pem")
ts.Setup.Copy("ssl/signed-foo.key")

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'header.*',

    'proxy.config.dns.nameservers': '127.0.0.1:{0}'.format(dns.Variables.Port),
    'proxy.config.dns.resolv_conf': 'NULL',

    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.client.verify.server': 0,
    'proxy.config.url_remap.pristine_host_hdr': 1,
    'proxy.config.ssl.CA.cert.filename': '{0}/signer.pem'.format(ts.Variables.SSLDir),
    'proxy.config.exec_thread.autoconfig.scale': 1.0,
    'proxy.config.http.host_sni_policy': 2,
    'proxy.config.ssl.TLSv1_3': 0,
})

ts.Disk.ssl_multicert_config.AddLine(
    'dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key'
)
# The following rule changes the status code returned from origin server to 303
ts.Setup.CopyAs('rules/rule_client.conf', Test.RunDirectory)
ts.Setup.CopyAs('rules/set_redirect.conf', Test.RunDirectory)

ts.Disk.remap_config.AddLine(
    'map http://www.example.com/from_path/ https://127.0.0.1:{0}/to_path/ @plugin=header_rewrite.so @pparam={1}/rule_client.conf'.format(
        server.Variables.Port, Test.RunDirectory))
ts.Disk.remap_config.AddLine(
    'map http://www.example.com:8080/from_path/ https://127.0.0.1:{0}/to_path/ @plugin=header_rewrite.so @pparam={1}/rule_client.conf'.format(
        server.Variables.Port, Test.RunDirectory))
ts.Disk.remap_config.AddLine(
        'regex_map https://^(?:www\.)?no_path\.com$ https://no_path.com:{0}?ncid=mbr_rusacqad00000080/ @plugin=header_rewrite.so @pparam={1}/set_redirect.conf'.format(
        server.Variables.Port, Test.RunDirectory))
dns.addRecords(records={"no_path.com": ["127.0.0.1"]})

# call localhost straight
# tr = Test.AddTestRun()
# tr.Processes.Default.Command = 'curl --proxy 127.0.0.1:{0} "http://www.example.com/from_path/hello?=foo=bar" -H "Proxy-Connection: keep-alive" --verbose'.format(
#     ts.Variables.port)
# tr.Processes.Default.ReturnCode = 0
# # time delay as proxy.config.http.wait_for_cache could be broken
# tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
# tr.Processes.Default.StartBefore(Test.Processes.ts)
# tr.Processes.Default.Streams.stderr = "gold/header_rewrite-client.gold"
# tr.StillRunningAfter = server
# ts.Streams.All = "gold/header_rewrite-tag.gold"

# Verify header_rewrite can handle URLs without a path.
tr = Test.AddTestRun()

# Remove when above is uncommented...
tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(Test.Processes.ts)

tr.Processes.Default.Command = \
    ('curl --http1.1 -k -H"Host: no_path.com" '
     '--resolve "no_path.com:{0}:127.0.0.1" '
     '--cert ./signed-foo.pem --key ./signed-foo.key '
     '--verbose https://no_path.com:{0}'.format(
         ts.Variables.ssl_port))
tr.Processes.Default.ReturnCode = 0
# time delay as proxy.config.http.wait_for_cache could be broken
tr.Processes.Default.Streams.stderr = "gold/set-redirect.gold"
tr.StillRunningAfter = server
ts.Streams.All = "gold/header_rewrite-tag.gold"
