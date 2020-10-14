/** @file

  Implement Throttler.

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

#include "tscore/Throttler.h"

Throttler::Throttler(std::chrono::milliseconds periodicity) : _periodicity{periodicity} {}

bool
Throttler::operator()(uint64_t &skipped_count)
{
  TimePoint const now = Clock::now();
  TimePoint last_allowed_time{_last_allowed_time};
  if ((last_allowed_time + _periodicity) <= now) {
    if (_last_allowed_time.compare_exchange_strong(last_allowed_time, now)) {
      skipped_count  = _skipped_count;
      _skipped_count = 0;
      return true;
    }
  }
  ++_skipped_count;
  return false;
}
