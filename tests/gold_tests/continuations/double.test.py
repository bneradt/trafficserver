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
Test.Summary = '''
Test transactions and sessions, making sure two continuations catch the same number of hooks.
'''
Test.SkipUnless(
    Condition.HasProgram("curl", "Curl needs to be installed on system for this test to work")
)
Test.ContinueOnFail = True
# Define default ATS
ts = Test.MakeATSProcess("ts", command="traffic_manager")

server = Test.MakeOriginServer("server")

Test.testName = ""
request_header = {"headers": "GET / HTTP/1.1\r\nHost: double.test\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
# expected response from the origin server
response_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": ""}

Test.PreparePlugin(os.path.join(Test.Variables.AtsTestToolsDir, 'plugins', 'continuations_verify.cc'), ts)

# add response to the server dictionary
server.addResponse("sessionfile.log", request_header, response_header)
ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'continuations_verify.*',
})
ts.Disk.remap_config.AddLine(
    'map http://double.test:{0} http://127.0.0.1:{1}'.format(ts.Variables.port, server.Variables.Port)
)

cmd = 'curl -vs http://127.0.0.1:{0}'.format(ts.Variables.port)
numberOfRequests = 25

tr = Test.AddTestRun()

# Create a bunch of curl commands to be executed in parallel. Default.Process is set in SpawnCommands.
ps = tr.SpawnCommands(cmdstr=cmd,  count=numberOfRequests)
tr.Processes.Default.Env = ts.Env

# Execution order is: ts/server, ps(curl cmds), Default Process.
tr.Processes.Default.StartBefore(
    server, ready=When.PortOpen(server.Variables.Port))
# Adds a delay once the ts port is ready. This is because we cannot test the ts state.
tr.Processes.Default.StartBefore(ts, ready=10)
ts.StartAfter(*ps)
server.StartAfter(*ps)
tr.StillRunningAfter = ts

<<<<<<< HEAD
comparator_command = '''
if test "`traffic_ctl metric get continuations_verify.{0}.close.1 | cut -d ' ' -f 2`" -eq "`traffic_ctl metric get continuations_verify.{0}.close.2 | cut -d ' ' -f 2`" ; then\
     echo yes;\
    else \
    echo no; \
    fi;
    '''

records = ts.Disk.File(os.path.join(ts.Variables.RUNTIMEDIR, "records.snap"))

||||||| parent of 55482d4c8... Make double Au test more reliable. (#7294)
# Signal that all the curl processes have completed
tr = Test.AddTestRun("Curl Done")
tr.Processes.Default.Command = "traffic_ctl plugin msg done done"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Env = ts.Env
tr.StillRunningAfter = ts

# Parking this as a ready tester on a meaningless process
# To stall the test runs that check for the stats until the
# stats have propagated and are ready to read.


def make_done_stat_ready(tsenv):
    def done_stat_ready(process, hasRunFor, **kw):
        retval = subprocess.run("traffic_ctl metric get continuations_verify.test.done > done  2> /dev/null", shell=True, env=tsenv)
        if retval.returncode == 0:
            retval = subprocess.run("grep 1 done > /dev/null", shell=True, env=tsenv)
        return retval.returncode == 0

    return done_stat_ready


=======
# Signal that all the curl processes have completed and poll for done metric
tr = Test.AddTestRun("Curl Done")
tr.Processes.Default.Command = (
    "traffic_ctl plugin msg done done ; "
    "N=60 ; "
    "while (( N > 0 )) ; "
    "do "
    "sleep 1 ; "
    'if [[ "$$( traffic_ctl metric get continuations_verify.test.done )" = '
    '"continuations_verify.test.done 1" ]] ; then exit 0 ; '
    "fi ; "
    "let N=N-1 ; "
    "done ; "
    "echo TIMEOUT ; "
    "exit 1"
)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Env = ts.Env
tr.StillRunningAfter = ts

>>>>>>> 55482d4c8... Make double Au test more reliable. (#7294)
# number of sessions/transactions opened and closed are equal
<<<<<<< HEAD
tr = Test.AddTestRun()
tr.DelayStart = 10 # wait for stats to be updated
||||||| parent of 55482d4c8... Make double Au test more reliable. (#7294)
tr = Test.AddTestRun("Check Ssn")
server2.StartupTimeout = 60
# Again, here the imporant thing is the ready function not the server2 process
tr.Processes.Default.StartBefore(server2, ready=make_done_stat_ready(ts.Env))
=======
tr = Test.AddTestRun("Check Ssn")
>>>>>>> 55482d4c8... Make double Au test more reliable. (#7294)
tr.Processes.Default.Command = comparator_command.format('ssn')
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("yes", 'should verify contents')
tr.StillRunningAfter = ts
<<<<<<< HEAD
# for debugging session number
ssn1 = tr.Processes.Process("session1", 'traffic_ctl metric get continuations_verify.ssn.close.1 > ssn1')
ssn2 = tr.Processes.Process("session2", 'traffic_ctl metric get continuations_verify.ssn.close.2 > ssn2')
ssn1.Env = ts.Env
ssn2.Env = ts.Env
tr.Processes.Default.StartBefore(ssn1)
tr.Processes.Default.StartBefore(ssn2)
||||||| parent of 55482d4c8... Make double Au test more reliable. (#7294)
tr.StillRunningAfter = server2
=======
>>>>>>> 55482d4c8... Make double Au test more reliable. (#7294)

tr = Test.AddTestRun()
tr.DelayStart = 10 # wait for stats to be updated
tr.Processes.Default.Command = comparator_command.format('txn')
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("yes", 'should verify contents')
tr.StillRunningAfter = ts
<<<<<<< HEAD
# for debugging transaction number
txn1 = tr.Processes.Process("transaction1", 'traffic_ctl metric get continuations_verify.txn.close.1 > txn1')
txn2 = tr.Processes.Process("transaction2", 'traffic_ctl metric get continuations_verify.txn.close.2 > txn2')
txn1.Env = ts.Env
txn2.Env = ts.Env
tr.Processes.Default.StartBefore(txn1)
tr.Processes.Default.StartBefore(txn2)

# session count is positive,
tr = Test.AddTestRun()
tr.DelayStart = 10 # wait for stats to be updated
tr.Processes.Default.Command = "traffic_ctl metric get continuations_verify.ssn.close.1"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.Streams.stdout = Testers.ExcludesExpression(" 0", 'should be nonzero')
tr.StillRunningAfter = ts

# and we receive the same number of transactions as we asked it to make
tr = Test.AddTestRun()
tr.DelayStart = 10 # wait for stats to be updated
tr.Processes.Default.Command = "traffic_ctl metric get continuations_verify.txn.close.1"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "continuations_verify.txn.close.1 {}".format(numberOfRequests), 'should be the number of transactions we made')
tr.StillRunningAfter = ts
||||||| parent of 55482d4c8... Make double Au test more reliable. (#7294)
tr.StillRunningAfter = server2
=======
>>>>>>> 55482d4c8... Make double Au test more reliable. (#7294)
