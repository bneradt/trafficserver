/** @file

  A class for generic throttling.

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

#include <atomic>
#include <chrono>
#include <cstdint>

/** A class that exposes an interface for generic throttling of some action
 * against a certain periodicity.
 *
 * To use:
 *
 * 1. Create an instance of this class specifying the periodicity for which
 * something should be throttled.
 *
 * 2. Prepend each decision for a given throttled action with a boolean call
 * against the instance created in step one.
 *
 *   2a. If the boolean operation returns true, then at least the configured
 *   number of milliseconds has elapsed since the last time the operation
 *   returned true. The number of times the check has been called is provided
 *   in the skipped_count output parameter.
 *
 *   2b. If the boolean operation returns false, then not enough time has
 *   elapsed since the last time the operation returned true.
 *
 * For instance:
 *
 *    void foo()
 *    {
 *      using namespace std::chrono_literals;
 *      static Throttler t(300ms);
 *      uint64_t skipped_count;
 *      if (t(skipped_count)) {
 *        std::printf("Alan bought another monitor\n");
 *        std::printf("We ignored Alan buying a monitor %llu times\n", skipped_count);
 *      }
 *    }
 */
class Throttler
{
public:
  /**
   * @param[in] periodicity The minimum number of milliseconds between
   * calls to Throttler which should return true.
   */
  Throttler(std::chrono::milliseconds periodicity);

  /** Whether enough time has passed since the last allowed action.
   *
   * @param[out] skipped_count If the return of this call is true,
   * this is populated with the approximate number of times the operator has
   * been queried since before this function was called. Otherwise the value is
   * not set.
   *
   * @return True if the action is emitted per the configured periodicity,
   * false otherwise.
   */
  bool operator()(uint64_t &skipped_count);

private:
  /// Base clock.
  using Clock = std::chrono::system_clock;
  /// Time point type, based on the clock to be used.
  using TimePoint = Clock::time_point;

  /// Time that the last item was emitted.
  // It is strange that we need to explicitly default construct this with a
  // default constructed TimePoint. Without it, however, I get a compiler error
  // in gcc 8.x and 9.x.  Playing around in godbolt I notice that neither clang
  // nor gcc versions starting from 10.x require this, so I suspect it is a
  // compiler bug.
  std::atomic<TimePoint> _last_allowed_time{TimePoint{}};

  /// The minimum number of milliseconds desired between actions.
  std::chrono::milliseconds const _periodicity{0};

  /// The number of calls to Throttler since the last
  uint64_t _skipped_count = 0;
};
