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
Test TS API.
'''

Test.SkipUnless(Condition.HasCurlFeature('http2'),)
Test.ContinueOnFail = True

plugin_name = "test_tsapi"

server = Test.MakeOriginServer("server")

request_header = {"headers": "GET / HTTP/1.1\r\nHost: doesnotmatter\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "112233"}
server.addResponse("sessionlog.json", request_header, response_header)

request_header = {"headers": "GET /xYz HTTP/1.1\r\nHost: doesnotmatter\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "445566"}
server.addResponse("sessionlog.json", request_header, response_header)

# Disable the cache to make sure each request is forwarded to the origin
# server.
ts = Test.MakeATSProcess("ts", enable_tls=True, enable_cache=False)

# The test plugin will output test logging to this file.
log_file_name = os.path.join(ts.Variables.LOGDIR, "log.txt")
Test.Env["OUTPUT_FILE"] = log_file_name

ts.addDefaultSSLFiles()

ts.Disk.records_config.update(
    {
        'proxy.config.proxy_name': 'Poxy_Proxy',  # This will be the server name.
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.url_remap.remap_required': 1,
        'proxy.config.diags.debug.enabled': 3,
        'proxy.config.diags.debug.tags': f'http|{plugin_name}',
    })

ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

rp = os.path.join(Test.Variables.AtsBuildGoldTestsDir, 'pluginTest', 'tsapi', '.libs', f'{plugin_name}.so')
ts.Setup.Copy(rp, ts.Env['PROXY_CONFIG_PLUGIN_PLUGIN_DIR'])

ts.Disk.remap_config.AddLine(
    "map http://myhost.test http://127.0.0.1:{0} @plugin={1} @plugin={1}".format(server.Variables.Port, f"{plugin_name}.so"))
ts.Disk.remap_config.AddLine(
    "map https://myhost.test:123 http://127.0.0.1:{0} @plugin={1} @plugin={1}".format(server.Variables.Port, f"{plugin_name}.so"))

ipv4flag = ""
if not Condition.CurlUsingUnixDomainSocket():
    ipv4flag = "--ipv4"

# For some reason, without this delay, traffic_server cannot reliably open the cleartext port for listening without an
# error.
#
tr = Test.AddTestRun()
tr.Processes.Default.Command = "sleep 3"
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun()
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
#
tr.MakeCurlCommand('--verbose {0} --header "Host: mYhOsT.teSt" hTtP://loCalhOst:{1}/'.format(ipv4flag, ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun()
tr.MakeCurlCommand('--verbose {0} --proxy localhost:{1} http://mYhOsT.teSt/xYz'.format(ipv4flag, ts.Variables.port), ts=ts)

if not Condition.CurlUsingUnixDomainSocket():
    tr = Test.AddTestRun()
    tr.MakeCurlCommand(
        '--verbose --ipv4 --http2 --insecure --header ' +
        '"Host: myhost.test:123" HttPs://LocalHost:{}/'.format(ts.Variables.ssl_port),
        ts=ts)
    tr.Processes.Default.ReturnCode = 0

tr = Test.AddTestRun()
# Change server port number (which can vary) to a fixed string for compare to gold file.
second_log_file_name = os.path.join(ts.Variables.LOGDIR, "log2.txt")
tr.Processes.Default.Command = f"sed 's/{server.Variables.Port}/SERVER_PORT/' < {log_file_name} > {second_log_file_name}"
tr.Processes.Default.ReturnCode = 0
f = tr.Disk.File(second_log_file_name)
if Condition.CurlUsingUnixDomainSocket():
    f.Content = "log_uds.gold"
else:
    f.Content = "log.gold"
