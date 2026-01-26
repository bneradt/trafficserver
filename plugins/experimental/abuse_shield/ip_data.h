/** @file

  IP Tracker using Udi "King of the Hill" algorithm for abuse detection.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
  agreements.  See the NOTICE file distributed with this work for additional information regarding
  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with the License.  You may obtain
  a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed under the License
  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
  or implied. See the License for the specific language governing permissions and limitations under
  the License.
*/

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>

#include "swoc/swoc_ip.h"
#include "tsutil/UdiTable.h"

namespace abuse_shield
{

// Number of HTTP/2 error codes to track (0x00-0x0f)
constexpr size_t NUM_H2_ERROR_CODES = 16;

/** The data stored for each IP address in the UdiTable.
 *
 * The IP address (key) and score are managed by UdiTable internally.  This
 * struct contains the tracking data used to determine whether an IP identified
 * as "hot" by the Udi algorithm requires action (e.g. blocking).
 */
struct IPData {
  // Error tracking.
  std::atomic<uint32_t> client_errors{0}; ///< Client-caused HTTP/2 errors
  std::atomic<uint32_t> server_errors{0}; ///< Server-caused HTTP/2 errors
  std::atomic<uint32_t> successes{0};     ///< Successful requests (2xx)

  // Per HTTP/2 error code counts
  std::atomic<uint16_t> h2_error_counts[NUM_H2_ERROR_CODES]{};

  // Rate limiting counters.
  std::atomic<uint32_t> conn_count{0}; ///< Connections in current window
  std::atomic<uint32_t> req_count{0};  ///< Requests in current window

  // Timing for rate determination.
  std::atomic<uint64_t> window_start{0};  ///< Start of rate window (epoch ms)
  std::atomic<uint64_t> last_seen{0};     ///< Last activity timestamp (epoch ms)
  std::atomic<uint64_t> blocked_until{0}; ///< Block expiration (epoch ms, 0 = not blocked)

  /// Record an HTTP/2 error.
  void record_h2_error(uint8_t error_code, bool is_client_error);

  /// Record a successful request.
  void record_success();

  /// Record a new connection.
  void record_connection();

  /// Record a new request.
  void record_request();

  /// Check if this IP is currently blocked
  bool is_blocked() const;

  /// Block this IP until the given timestamp
  void block_until(uint64_t until_ms);
};

/// The UdiTable type used for IP tracking.
using IPTable = ts::UdiTable<swoc::IPAddr, IPData, std::hash<swoc::IPAddr>>;

} // namespace abuse_shield
