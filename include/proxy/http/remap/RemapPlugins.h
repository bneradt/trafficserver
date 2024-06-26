/** @file

  Declarations for the RemapPlugins class.

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

#pragma once

#include "tscore/ink_platform.h"
#include "iocore/eventsystem/EventSystem.h"
#include "proxy/http/remap/RemapProcessor.h"
#include "proxy/http/remap/RemapPluginInfo.h"
#include "proxy/http/HttpTransact.h"
#include "proxy/ReverseProxy.h"

/**
 * A class that represents a queue of plugins to run
 **/
struct RemapPlugins : public Continuation {
  RemapPlugins() = default;
  RemapPlugins(HttpTransact::State *s, URL *u, HTTPHdr *h, host_hdr_info * /* hi ATS_UNUSED */)
    : _s(s), _request_url(u), _request_header(h)
  {
  }

  // Some basic setters
  void
  setState(HttpTransact::State *state)
  {
    _s = state;
  }
  void
  setRequestUrl(URL *u)
  {
    _request_url = u;
  }
  void
  setRequestHeader(HTTPHdr *h)
  {
    _request_header = h;
  }

  bool          run_single_remap();
  TSRemapStatus run_plugin(RemapPluginInst *plugin);

  Action action;

private:
  unsigned             _cur            = 0;
  unsigned             _rewritten      = 0;
  HttpTransact::State *_s              = nullptr;
  URL                 *_request_url    = nullptr;
  HTTPHdr             *_request_header = nullptr;
};
