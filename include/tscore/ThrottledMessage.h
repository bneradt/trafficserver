/** @file

  ThrottledMessage declaration.

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

#include "SourceLocation.h"
#include "Throttler.h"

#include <chrono>

/** Represents a set of log messages for which throttling is desired. */
class ThrottledMessage
{
public:
  /**
   * @param[in] seconds_between The minimum number of desired seconds between
   * log events.
   *
   * TODO: Add proxy.config.log.throttle_delay? We'll have to be clear that
   * this would only throttle the subset of programmatically registered log
   * messages.
   */
  ThrottledMessage(std::chrono::seconds seconds_between = std::chrono::seconds{60});

  /* TODO: Add BufferWriter overloads for these. */
  void status(SourceLocation const &loc, const char *fmt, ...);
  void note(SourceLocation const &loc, const char *fmt, ...);
  void warning(SourceLocation const &loc, const char *fmt, ...);
  void error(SourceLocation const &loc, const char *fmt, ...);

private:
  /** Used to throttle the log messages to the specified periodicity. */
  Throttler _throttler;
};
