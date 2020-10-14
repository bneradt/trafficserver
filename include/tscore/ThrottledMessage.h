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

#include "Diags.h"

#include <atomic>
#include <chrono>
#include <cstdint>

/** Represents a set of log messages for which throttling is desired. */
class ThrottledMessage
{
public:
  /**
   * @param[in] seconds_between The minimum number of seconds between log
   * events.
   *
   * TODO: Add proxy.config.log.throttle_delay? We'll have to be clear that
   * this would only throttle the subset of programmatically registered log
   * messages.
   */
  ThrottledMessage(std::chrono::seconds seconds_between = std::chrono::seconds{60});

  /* TODO: Add BufferWriter overloads for these. */
  void status(const char *fmt, ...);
  void note(const char *fmt, ...);
  void warning(const char *fmt, ...);
  void error(const char *fmt, ...);

private:
  /// Base clock.
  using Clock = std::chrono::system_clock;
  /// Time point type, based on the clock to be used.
  using TimePoint = Clock::time_point;

  /** Whether enough time has passed that a new message can be emitted.
   *
   * This also handles message counting and recording of the last time a log
   * event occurred.
   *
   * @param[out] count_since_last_log If the log should be emitted, this is
   * populated with the approximate number of times the log message was not
   * printed since before this function was called. Otherwise the value is not
   * set.
   *
   * @return True if the message can be emitted, false otherwise.
   */
  inline bool
  should_emit_log(uint32_t &count_since_last_log)
  {
    TimePoint const now = Clock::now();
    TimePoint last_log_time{_last_log_time};
    if ((last_log_time + _seconds_between) <= now) {
      if (_last_log_time.compare_exchange_strong(last_log_time, now)) {
        count_since_last_log  = _count_since_last_log;
        _count_since_last_log = 0;
        return true;
      }
    }
    ++_count_since_last_log;
    return false;
  }

private:
  /// Absolute time of the last emitted log.
  std::atomic<TimePoint> _last_log_time;

  /// The minimum number of seconds between log messages.
  std::chrono::seconds const _seconds_between{0};

  /// The number of messages not logged since the last time a log was emitted.
  uint32_t _count_since_last_log = 0;
};
