'''
Test origin_server_auth config parsing
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

Test.testName = "origin_server_auth: config parsing"
Test.Summary = '''
Test for successful authentication to origin server
'''
Test.ContinueOnFail = True


class OriginServerAuthTest:

    def __init__(self):
        self.setUpOriginServer()
        self.setUpTS()

    def setUpOriginServer(self):
        self.server = Test.MakeOriginServer("server")
        # define the s3 request header and the desired response header
        request_header = {
            "headers": "GET /s3-bucket HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "timestamp": "1469733493.993",
            "x-amz-security-token":
                "hkMsi6/bfHyBKrSeM/H0hoXeyx8z1yZ/mJ0c+B/TqYx=tTJDjnQWtul38Z9iVJjeH1HB4VT2c=2o3yE3o=I9kmFs/lJDR85qWjB8e5asY/WbjyRpbAzmDipQpboIcYnUYg55bxrQFidV/q8gZa5A9MpR3n=op1C0lWjeBqcEJxpevNZxteSQTQfeGsi98Cdf+On=/SINVlKrNhMnmMsDOLMGx1YYt9d4UsRg1jtVrwxL4Vd/F7aHCZySAXKv+1rkhACR023wpa3dhp+xirGJxSO9LWwvcrTdM4xJo4RS8B40tGENOJ1NKixUJxwN/6og58Oft/u==uleR89Ja=7zszK2H7tX3DqmEYNvNDYQh/7VBRe5otghQtPwJzWpXAGk+Vme4hPPM5K6axH2LxipXzRiIV=oxNs0upKNu1FvuzbCQmkQdKQVmXl0344vngngrgN7wkEfrYtmKwICmpAS0cbW9jdSClgziVo4NaFc/hsIfok=4UA3hVtxIdw74lFNXD0RR7HKXkFPLIn85M7peOZsqMUCfO4gxr7KCfabszQQf0YcP/mt79XK50=WrSJG7oUyn+clUySPhlegqHAfT9a50uSK5WiQmOnGNGLF4wDO10sqKN1xRgQbYHPtwL+Ye0EMisvmYA3==kScorTSGaQWyibSWXAvxq9+IVGBYShVJ6S7DmTT=u/2d/fGEge+Xmbxlftza=cxJ=Md=k1Q71Lp6Boa56d7wtYRpK6tXHJ9I/2r7rN1E4OtwkFqb7SfWV3UXwyUrXyaaNPTIbqnAHnbgUGtuU6pgICpfREiIxVqvKBf6ErbxHRmMmAuYKxk5E9Mn6nnbxR4WTniweKYeDv2w39zge/tss+36Moeuio9d2eoyRFqXhq=rUGtDwX3fzXV0wV+dUojxOYQ57GQDl7+68PwHPcX794OIXuGOxBk83lNIYIcYz3Vc7qnGy6tFTz7f6S9+EZuSGN7TY5VKkT2eWye46DebrDF9Nwzs/FVpTzbPD/KGDIBtFIbazglhKoWe9txqb1QW8vFNNVOEhYa+cViO3g8ZmY1wG960US2zsnX5Eg8Q5a4h3+sxaJSJ4ONiXZWJuAgKRQzcrszu+M5C0ZVoCOv1goEgfNJeSm/yFc/3rx8wmeWLIJFtq65B7zF72HRKq1nthHAguaxXr20nguHpKkDpNBDVa=WwuJsbeGI",
            "body": ""
        }

        # desired response from the origin server
        response_header = {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": "success!"
        }
        self.server.addResponse("sessionlog.log", request_header, response_header)

        # define the GCP request header and the desired response header
        request_header = {
            "headers": "GET /gcp HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "timestamp": "1469733493.993",
            "Authorization":
                "Bearer hkMsi6/bfHyBKrSeM/H0hoXeyx8z1yZ/mJ0c+B/TqYx=tTJDjnQWtul38Z9iVJjeH1HB4VT2c=2o3yE3o=I9kmFs/lJDR85qWjB8e5asY/WbjyRpbAzmDipQpboIcYnUYg55bxrQFidV/q8gZa5A9MpR3n=op1C0lWjeBqcEJxpevNZxteSQTQfeGsi98Cdf+On=/SINVlKrNhMnmMsDOLMGx1YYt9d4UsRg1jtVrwxL4Vd/F7aHCZySAXKv+1rkhACR023wpa3dhp+xirGJxSO9LWwvcrTdM4xJo4RS8B40tGENOJ1NKixUJxwN/6og58Oft/u==uleR89Ja=7zszK2H7tX3DqmEYNvNDYQh/7VBRe5otghQtPwJzWpXAGk+Vme4hPPM5K6axH2LxipXzRiIV=oxNs0upKNu1FvuzbCQmkQdKQVmXl0344vngngrgN7wkEfrYtmKwICmpAS0cbW9jdSClgziVo4NaFc/hsIfok=4UA3hVtxIdw74lFNXD0RR7HKXkFPLIn85M7peOZsqMUCfO4gxr7KCfabszQQf0YcP/mt79XK50=WrSJG7oUyn+clUySPhlegqHAfT9a50uSK5WiQmOnGNGLF4wDO10sqKN1xRgQbYHPtwL+Ye0EMisvmYA3==kScorTSGaQWyibSWXAvxq9+IVGBYShVJ6S7DmTT=u/2d/fGEge+Xmbxlftza=cxJ=Md=k1Q71Lp6Boa56d7wtYRpK6tXHJ9I/2r7rN1E4OtwkFqb7SfWV3UXwyUrXyaaNPTIbqnAHnbgUGtuU6pgICpfREiIxVqvKBf6ErbxHRmMmAuYKxk5E9Mn6nnbxR4WTniweKYeDv2w39zge/tss+36Moeuio9d2eoyRFqXhq=rUGtDwX3fzXV0wV+dUojxOYQ57GQDl7+68PwHPcX794OIXuGOxBk83lNIYIcYz3Vc7qnGy6tFTz7f6S9+EZuSGN7TY5VKkT2eWye46DebrDF9Nwzs/FVpTzbPD/KGDIBtFIbazglhKoWe9txqb1QW8vFNNVOEhYa+cViO3g8ZmY1wG960US2zsnX5Eg8Q5a4h3+sxaJSJ4ONiXZWJuAgKRQzcrszu+M5C0ZVoCOv1goEgfNJeSm/yFc/3rx8wmeWLIJFtq65B7zF72HRKq1nthHAguaxXr20nguHpKkDpNBDVa=WwuJsbeGI",
            "body": ""
        }

        # desired response from the origin server
        response_header = {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            "timestamp": "1469733493.993",
            "body": "success!"
        }

        # add request/response
        self.server.addResponse("sessionlog.log", request_header, response_header)

    def setUpTS(self):
        self.ts = Test.MakeATSProcess("ts")

        self.ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.show_location': 0,
                'proxy.config.diags.debug.tags': 'origin_server_auth',
            })

        self.ts.Setup.CopyAs('rules/v4-parse-test.test_input', Test.RunDirectory)

        self.ts.Disk.remap_config.AddLine(
            f'map http://www.example.com/s3-bucket http://127.0.0.1:{self.server.Variables.Port}/s3-bucket \
                @plugin=origin_server_auth.so \
                    @pparam=--config @pparam={Test.RunDirectory}/v4-parse-test.test_input')

        self.ts.Disk.remap_config.AddLine(
            f'map http://www.example.com/gcp http://127.0.0.1:{self.server.Variables.Port}/gcp \
                @plugin=origin_server_auth.so \
                @pparam=--access_key @pparam=1234567 \
                @pparam=--session_token @pparam=hkMsi6/bfHyBKrSeM/H0hoXeyx8z1yZ/mJ0c+B/TqYx=tTJDjnQWtul38Z9iVJjeH1HB4VT2c=2o3yE3o=I9kmFs/lJDR85qWjB8e5asY/WbjyRpbAzmDipQpboIcYnUYg55bxrQFidV/q8gZa5A9MpR3n=op1C0lWjeBqcEJxpevNZxteSQTQfeGsi98Cdf+On=/SINVlKrNhMnmMsDOLMGx1YYt9d4UsRg1jtVrwxL4Vd/F7aHCZySAXKv+1rkhACR023wpa3dhp+xirGJxSO9LWwvcrTdM4xJo4RS8B40tGENOJ1NKixUJxwN/6og58Oft/u==uleR89Ja=7zszK2H7tX3DqmEYNvNDYQh/7VBRe5otghQtPwJzWpXAGk+Vme4hPPM5K6axH2LxipXzRiIV=oxNs0upKNu1FvuzbCQmkQdKQVmXl0344vngngrgN7wkEfrYtmKwICmpAS0cbW9jdSClgziVo4NaFc/hsIfok=4UA3hVtxIdw74lFNXD0RR7HKXkFPLIn85M7peOZsqMUCfO4gxr7KCfabszQQf0YcP/mt79XK50=WrSJG7oUyn+clUySPhlegqHAfT9a50uSK5WiQmOnGNGLF4wDO10sqKN1xRgQbYHPtwL+Ye0EMisvmYA3==kScorTSGaQWyibSWXAvxq9+IVGBYShVJ6S7DmTT=u/2d/fGEge+Xmbxlftza=cxJ=Md=k1Q71Lp6Boa56d7wtYRpK6tXHJ9I/2r7rN1E4OtwkFqb7SfWV3UXwyUrXyaaNPTIbqnAHnbgUGtuU6pgICpfREiIxVqvKBf6ErbxHRmMmAuYKxk5E9Mn6nnbxR4WTniweKYeDv2w39zge/tss+36Moeuio9d2eoyRFqXhq=rUGtDwX3fzXV0wV+dUojxOYQ57GQDl7+68PwHPcX794OIXuGOxBk83lNIYIcYz3Vc7qnGy6tFTz7f6S9+EZuSGN7TY5VKkT2eWye46DebrDF9Nwzs/FVpTzbPD/KGDIBtFIbazglhKoWe9txqb1QW8vFNNVOEhYa+cViO3g8ZmY1wG960US2zsnX5Eg8Q5a4h3+sxaJSJ4ONiXZWJuAgKRQzcrszu+M5C0ZVoCOv1goEgfNJeSm/yFc/3rx8wmeWLIJFtq65B7zF72HRKq1nthHAguaxXr20nguHpKkDpNBDVa=WwuJsbeGI \
                @pparam=--version @pparam=gcpv1')

    def test_s3_origin_remap(self):
        '''
        Test s3 v4 origin server
        '''
        tr = Test.AddTestRun()
        tr.MakeCurlCommand(f'-s -v -H "Host: www.example.com" http://127.0.0.1:{self.ts.Variables.port}/s3-bucket;', ts=self.ts)
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.StartBefore(self.server)
        tr.Processes.Default.StartBefore(self.ts)
        tr.Processes.Default.Streams.stderr.Content = Testers.ContainsExpression("200 OK", "expected 200 response")
        tr.Processes.Default.Streams.stderr.Content += Testers.ContainsExpression("Content-Length: 8", "expected content-length 8")
        tr.StillRunningAfter = self.server

    def test_gcp_origin_remap(self):
        '''
        Test GCP origin server
        '''
        tr = Test.AddTestRun()
        tr.MakeCurlCommand(f'-s -v -H "Host: www.example.com" http://127.0.0.1:{self.ts.Variables.port}/gcp;', ts=self.ts)
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stderr.Content = Testers.ContainsExpression("200 OK", "expected 200 response")
        tr.Processes.Default.Streams.stderr.Content += Testers.ContainsExpression("Content-Length: 8", "expected content-length 8")
        tr.StillRunningAfter = self.server

    def checkLogOutput(self):
        self.ts.Disk.traffic_out.Content = "gold/origin_server_auth_parsing_ts.gold"
        self.ts.ReturnCode = 0

    def runTraffic(self):
        self.test_s3_origin_remap()
        self.test_gcp_origin_remap()
        self.checkLogOutput()

    def run(self):
        self.runTraffic()


OriginServerAuthTest().run()
