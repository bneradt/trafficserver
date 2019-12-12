"""
Verify traffic_dump functionality.
"""
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
Verify traffic_dump functionality.
'''

Test.SkipUnless(
    Condition.PluginExists('traffic_dump.so'),
)

# Configure the origin server.
server = Test.MakeOriginServer("server")

request_header = {"headers": "GET /empty HTTP/1.1\r\n"
                  "Host: www.example.com\r\n"
                  "Content-Length: 0\r\n\r\n",
                  "timestamp": "1469733493.993", "body": ""}
response_header = {"headers": "HTTP/1.1 200 OK\r\n"
                   "Connection: close\r\n"
                   "Content-Length: 0\r\n\r\n",
                   "timestamp": "1469733493.993", "body": ""}
server.addResponse("sessionfile.log", request_header, response_header)

request_header = {"headers": "POST /with_content_length HTTP/1.1\r\n"
                  "Host: www.example.com\r\n"
                  "Content-Length: 4\r\n\r\n",
                  "timestamp": "1469733493.993", "body": "1234"}
response_header = {"headers": "HTTP/1.1 200 OK\r\n"
                   "Connection: close\r\n"
                   "Content-Length: 4\r\n\r\n",
                   "timestamp": "1469733493.993", "body": "1234"}
server.addResponse("sessionfile.log", request_header, response_header)

# Define ATS and configure it.
ts1 = Test.MakeATSProcess("ts1")
replay_ts1_dir = os.path.join(ts1.RunDirectory, "ts1", "log")
ts1.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'traffic_dump',
})
ts1.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}'.format(server.Variables.Port)
)
# Configure traffic_dump.
ts1.Disk.plugin_config.AddLine(
    'traffic_dump.so --logdir {0} --sample 1 --limit 1000000000'.format(replay_ts1_dir)
)

# Set up trafficserver expectations.
ts1.Disk.diags_log.Content = Testers.ContainsExpression(
        "loading plugin.*traffic_dump.so",
        "Verify the traffic_dump plugin got loaded.")
ts1.Streams.stderr = Testers.ContainsExpression(
        "Initialized with log directory: {0}".format(replay_ts1_dir),
        "Verify traffic_dump initialized with the configured directory.")
ts1.Streams.stderr += Testers.ContainsExpression(
        "Initialized with sample pool size 1 bytes and disk limit 1000000000 bytes",
        "Verify traffic_dump initialized with the configured disk limit.")
ts1.Streams.stderr += Testers.ContainsExpression(
        "dumping body bytes: false",
        "Verify that dumping body bytes is enabled.")

# Set up the json replay file expectations.
ts1_replay_file_session_1 = os.path.join(replay_ts1_dir, "127", "0000000000000000")
ts1.Disk.File(ts1_replay_file_session_1, exists=True)
ts1_replay_file_session_2 = os.path.join(replay_ts1_dir, "127", "0000000000000001")
ts1.Disk.File(ts1_replay_file_session_2, exists=True)

#
# TEST 1: Verify that two replay files are made from two sessions.
#
# Execute the first transaction.
tr = Test.AddTestRun("First transaction")

tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(ts1)
tr.Processes.Default.Command = 'curl http://127.0.0.1:{0}/empty -H\'Host: www.example.com\' --verbose'.format(
    ts1.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = "gold/200_get.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts1

# Execute the second transaction.
tr = Test.AddTestRun("Second transaction")
tr.Processes.Default.Command = 'curl http://127.0.0.1:{0}/empty -H\'Host: www.example.com\' --verbose'.format(
    ts1.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = "gold/200_get.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts1

# Verify the properties of the replay file for the first transaction.
tr = Test.AddTestRun("Verify the json content of the first session")
verify_replay = "verify_replay.py"
tr.Setup.CopyAs(verify_replay, Test.RunDirectory)
tr.Processes.Default.Command = "python3 {0} {1} {2}".format(
        verify_replay,
        os.path.join(Test.Variables.AtsTestToolsDir, 'lib', 'replay_schema.json'),
        ts1_replay_file_session_1)
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = server
tr.StillRunningAfter = ts1

# Verify the properties of the replay file for the second transaction.
tr = Test.AddTestRun("Verify the json content of the second session")
tr.Setup.CopyAs(verify_replay, Test.RunDirectory)
tr.Processes.Default.Command = "python3 {0} {1} {2}".format(
        verify_replay,
        os.path.join(Test.Variables.AtsTestToolsDir, 'lib', 'replay_schema.json'),
        ts1_replay_file_session_2)
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = server
tr.StillRunningAfter = ts1

#
# TEST 2: Verify request body can be dumped.
#
tr = Test.AddTestRun("Verify body bytes can be dumped")

ts2 = Test.MakeATSProcess("ts2")
replay_ts2_dir = os.path.join(ts2.RunDirectory, "ts2", "log")
ts2.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'traffic_dump',
})
ts2.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}'.format(server.Variables.Port)
)
# Configure traffic_dump to dump body bytes (-b).
ts2.Disk.plugin_config.AddLine(
    'traffic_dump.so --logdir {0} --sample 1 --limit 1000000000 -b'.format(replay_ts2_dir)
)
ts2_replay_file_session_1 = os.path.join(replay_ts2_dir, "127", "0000000000000000")
ts2.Disk.File(ts2_replay_file_session_1, exists=True)

ts2.Streams.stderr = Testers.ContainsExpression(
        "dumping body bytes: true",
        "Verify that dumping body bytes is enabled.")
ts2.Streams.stderr += Testers.ContainsExpression(
        "got the request body of size 4 bytes",
        "Verify logging of the dumped body bytes.")

request_body = "1234"

tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(ts2)
tr.Processes.Default.Command = 'curl http://127.0.0.1:{0}/with_content_length -H\'Host: www.example.com\' --verbose -d "{1}"'.format(
    ts2.Variables.port,
    request_body)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = "gold/200_post.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts2

# Verify that the expected request body was recorded.
tr = Test.AddTestRun("Verify that the expected request body was recorded.")
tr.Setup.CopyAs(verify_replay, Test.RunDirectory)
tr.Processes.Default.Command = "python3 {0} {1} {2} --request_body {3}".format(
        verify_replay,
        os.path.join(Test.Variables.AtsTestToolsDir, 'lib', 'replay_schema.json'),
        ts2_replay_file_session_1,
        request_body)
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = server
tr.StillRunningAfter = ts2

#
# TEST 3: Verify request body bytes are escaped.
#
tr = Test.AddTestRun("Verify body bytes are dumped")

ts3 = Test.MakeATSProcess("ts3")
replay_ts3_dir = os.path.join(ts3.RunDirectory, "ts3", "log")
ts3.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'traffic_dump',
})
ts3.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}'.format(server.Variables.Port)
)
# Configure traffic_dump to dump body bytes (-b).
ts3.Disk.plugin_config.AddLine(
    'traffic_dump.so --logdir {0} --sample 1 --limit 1000000000 -b'.format(replay_ts3_dir)
)
ts3_replay_file_session_1 = os.path.join(replay_ts3_dir, "127", "0000000000000000")
ts3.Disk.File(ts3_replay_file_session_1, exists=True)

ts3.Streams.stderr = Testers.ContainsExpression(
        "dumping body bytes: true",
        "Verify that dumping body bytes is enabled.")
ts3.Streams.stderr += Testers.ContainsExpression(
        "got the request body of size 5 bytes",
        "Verify logging of the dumped body bytes.")

request_body = '12"34'

tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(ts3)
tr.Processes.Default.Command = 'curl http://127.0.0.1:{0}/with_content_length -H\'Host: www.example.com\' --verbose -d \'{1}\''.format(
    ts3.Variables.port,
    request_body)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = "gold/200_post.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts3

# Verify that the expected request body was recorded.
tr = Test.AddTestRun("Verify that the expected request body was recorded.")
tr.Setup.CopyAs(verify_replay, Test.RunDirectory)
tr.Processes.Default.Command = "python3 {0} {1} {2} --request_body {3}".format(
        verify_replay,
        os.path.join(Test.Variables.AtsTestToolsDir, 'lib', 'replay_schema.json'),
        ts3_replay_file_session_1,
        r'12\"34')
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = server
tr.StillRunningAfter = ts3

#
# TEST 5: Verify -4 works for a specified address.
#
tr = Test.AddTestRun("Verify that -4 matches 127.0.0.1 as expected")

ts4 = Test.MakeATSProcess("ts4")
replay_ts4_dir = os.path.join(ts4.RunDirectory, "ts4", "log")
ts4.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'traffic_dump',
})
ts4.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}'.format(server.Variables.Port)
)
# Configure traffic_dump to only print content for the client address 127.0.0.1.
ts4.Disk.plugin_config.AddLine(
    'traffic_dump.so --logdir {0} --sample 1 --limit 1000000000 -b -4 127.0.0.1'.format(replay_ts4_dir)
)
ts4_replay_file_session_1 = os.path.join(replay_ts4_dir, "127", "0000000000000000")
ts4.Disk.File(ts4_replay_file_session_1, exists=True)

request_body = '1234'

tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(ts4)
tr.Processes.Default.Command = 'curl http://127.0.0.1:{0}/with_content_length -H\'Host: www.example.com\' --verbose -d "{1}"'.format(
    ts4.Variables.port,
    request_body)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = "gold/200_post.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts4

# Verify that the expected request body was recorded.
tr = Test.AddTestRun("Verify that the expected request body was recorded.")
tr.Setup.CopyAs(verify_replay, Test.RunDirectory)
tr.Processes.Default.Command = "python3 {0} {1} {2} --request_body {3}".format(
        verify_replay,
        os.path.join(Test.Variables.AtsTestToolsDir, 'lib', 'replay_schema.json'),
        ts4_replay_file_session_1,
        request_body)
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = server
tr.StillRunningAfter = ts4

#
# TEST 6: Verify -4 filters out other addresses.
#
tr = Test.AddTestRun("Verify that -4 filters out our 127.0.0.1 as expected")

ts5 = Test.MakeATSProcess("ts5")
replay_ts5_dir = os.path.join(ts5.RunDirectory, "ts5", "log")
ts5.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'traffic_dump',
})
ts5.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}'.format(server.Variables.Port)
)
# Configure traffic_dump to only print content for a non-127.0.0.1 addresss.
ts5.Disk.plugin_config.AddLine(
    'traffic_dump.so --logdir {0} --sample 1 --limit 1000000000 -b -4 1.2.3.4'.format(replay_ts5_dir)
)
ts5_replay_file_session_1 = os.path.join(replay_ts5_dir, "127", "0000000000000000")
ts5.Disk.File(ts5_replay_file_session_1, exists=False)

tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(ts5)
tr.Processes.Default.Command = 'curl http://127.0.0.1:{0}/with_content_length -H\'Host: www.example.com\' --verbose -d "{1}"'.format(
    ts5.Variables.port,
    request_body)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = "gold/200_post.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts5

#
# TEST 7: Verify -4 recognizes an invalid IP address string.
#
tr = Test.AddTestRun("Verify that -4 detects an invalid IP string")
ts6 = Test.MakeATSProcess("ts6")
replay_ts6_dir = os.path.join(ts6.RunDirectory, "ts6", "log")
ts6.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'traffic_dump',
})
ts6.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}'.format(server.Variables.Port)
)

invalid_ip = "this_is_not_a_valid_ip_string"

ts6.Disk.diags_log.Content = Testers.ContainsExpression(
        "Problems parsing IPv4 filter address: {}".format(invalid_ip),
        "Verify traffic_dump detects an invalid IPv4 address.")

# Configure traffic_dump with an invalid IPv4 string.
ts6.Disk.plugin_config.AddLine(
    'traffic_dump.so --logdir {0} --sample 1 --limit 1000000000 -b -4 this_is_not_a_valid_ip_string'.format(replay_ts6_dir)
)
ts6_replay_file_session_1 = os.path.join(replay_ts6_dir, "127", "0000000000000000")
ts6.Disk.File(ts6_replay_file_session_1, exists=False)

request_body = '1234'

tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(ts6)
tr.Processes.Default.Command = 'curl http://127.0.0.1:{0}/with_content_length -H\'Host: www.example.com\' --verbose -d "{1}"'.format(
    ts6.Variables.port,
    request_body)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stderr = "gold/200_post.gold"
tr.StillRunningAfter = server
tr.StillRunningAfter = ts6
