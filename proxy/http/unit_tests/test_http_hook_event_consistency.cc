/** @file

  Catch-based tests of hook and event consistency.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "catch.hpp"
#include "ts/apidefs.h"

/**
 * HttpSim.cc invocation logic relies upon TS_HTTP hooks being in the same
 * order as TS_EVENT values. This unit test verifies this invariant.
 */
TEST_CASE("verify HTTP hook and event consistency", "[http]")
{
  // Alert the developer of the need to consider this test if the TS_HTTP
  // hooks are changed. Developer of the future: if the following line is
  // failing, then you probably changed the TS_HTTP hooks. Add any CHECK
  // calls below as appropriate for new hooks and then update the below
  // value for the sum of all TS_HTTP hooks.
  REQUIRE(18 == TS_SSL_FIRST_HOOK - TS_HTTP_READ_REQUEST_HDR_HOOK);

  CHECK(TS_EVENT_HTTP_READ_REQUEST_HDR == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_READ_REQUEST_HDR_HOOK);
  CHECK(TS_EVENT_HTTP_OS_DNS == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_OS_DNS_HOOK);
  CHECK(TS_EVENT_HTTP_SEND_REQUEST_HDR == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_SEND_REQUEST_HDR_HOOK);
  CHECK(TS_EVENT_HTTP_READ_CACHE_HDR == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_READ_CACHE_HDR_HOOK);
  CHECK(TS_EVENT_HTTP_READ_RESPONSE_HDR == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_READ_RESPONSE_HDR_HOOK);
  CHECK(TS_EVENT_HTTP_SEND_RESPONSE_HDR == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_SEND_RESPONSE_HDR_HOOK);
  CHECK(TS_EVENT_HTTP_REQUEST_TRANSFORM == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_REQUEST_TRANSFORM_HOOK);
  CHECK(TS_EVENT_HTTP_RESPONSE_TRANSFORM == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_RESPONSE_TRANSFORM_HOOK);
  CHECK(TS_EVENT_HTTP_SELECT_ALT == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_SELECT_ALT_HOOK);
  CHECK(TS_EVENT_HTTP_TXN_START == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_TXN_START_HOOK);
  CHECK(TS_EVENT_HTTP_TXN_CLOSE == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_TXN_CLOSE_HOOK);
  CHECK(TS_EVENT_HTTP_SSN_START == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_SSN_START_HOOK);
  CHECK(TS_EVENT_HTTP_SSN_CLOSE == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_SSN_CLOSE_HOOK);
  CHECK(TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK);
  CHECK(TS_EVENT_HTTP_PRE_REMAP == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_PRE_REMAP_HOOK);
  CHECK(TS_EVENT_HTTP_POST_REMAP == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_POST_REMAP_HOOK);
  CHECK(TS_EVENT_HTTP_REQUEST_BUFFER_READ_COMPLETE == TS_EVENT_HTTP_READ_REQUEST_HDR + TS_HTTP_REQUEST_BUFFER_READ_COMPLETE_HOOK);
}
