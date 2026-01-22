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

#include <array>
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

// Default number of partitions for the hash table
constexpr size_t DEFAULT_NUM_PARTITIONS = 64;

/**
 * IPSlot - Stores tracking data for a single IP address.
 *
 * All counters are atomic for lock-free updates.
 * Size is approximately 128 bytes per slot.
 */
struct IPSlot {
  // Identity - only modified during contest (under lock)
  swoc::IPAddr addr;

  // Counters - lock-free atomic operations
  std::atomic<uint32_t> client_errors{0}; ///< Client-caused HTTP/2 errors
  std::atomic<uint32_t> server_errors{0}; ///< Server-caused HTTP/2 errors
  std::atomic<uint32_t> successes{0};     ///< Successful requests (2xx)
  std::atomic<uint32_t> score{0};         ///< Udi algorithm contest score

  // Per HTTP/2 error code counts
  std::atomic<uint16_t> h2_error_counts[NUM_H2_ERROR_CODES]{};

  // Rate limiting counters
  std::atomic<uint32_t> conn_count{0}; ///< Connections in current window
  std::atomic<uint32_t> req_count{0};  ///< Requests in current window

  // Timing
  std::atomic<uint64_t> window_start{0};  ///< Start of rate window (epoch ms)
  std::atomic<uint64_t> last_seen{0};     ///< Last activity timestamp (epoch ms)
  std::atomic<uint64_t> blocked_until{0}; ///< Block expiration (epoch ms, 0 = not blocked)

  /// Clear all data in this slot
  void clear();

  /// Check if this slot is empty (no IP assigned)
  bool
  empty() const
  {
    return !addr.is_valid();
  }

  /// Record an HTTP/2 error (lock-free)
  void record_h2_error(uint8_t error_code, bool is_client_error);

  /// Record a successful request (lock-free)
  void record_success();

  /// Record a new connection (lock-free)
  void record_connection();

  /// Record a new request (lock-free)
  void record_request();

  /// Check if this IP is currently blocked
  bool is_blocked() const;

  /// Block this IP until the given timestamp
  void block_until(uint64_t until_ms);
};

/**
 * IPTracker - Tracks IP addresses using the Udi "King of the Hill" algorithm.
 *
 * This is a thin wrapper around ts::UdiTable providing IP-specific functionality.
 *
 * Uses partitioned locking to minimize contention:
 * - Hash table is divided into N partitions, each with its own lock
 * - Slot updates use atomic operations (lock-free)
 * - Contest operations only lock one partition
 *
 * Thread-safe for concurrent access from multiple ATS threads.
 */
class IPTracker
{
public:
  // UdiTable type for IP tracking
  using Table = ts::UdiTable<swoc::IPAddr, IPSlot, std::hash<swoc::IPAddr>, DEFAULT_NUM_PARTITIONS>;

  /**
   * Construct an IPTracker with the specified number of slots.
   *
   * @param num_slots Total number of IP slots to allocate
   */
  explicit IPTracker(size_t num_slots);

  // No copying
  IPTracker(const IPTracker &)            = delete;
  IPTracker &operator=(const IPTracker &) = delete;

  /**
   * Find an IP in the tracker.
   *
   * @param ip The IP address to look up
   * @return Pointer to the slot if found, nullptr otherwise
   *
   * Thread-safe: Uses shared lock on the relevant partition.
   */
  IPSlot       *find(const swoc::IPAddr &ip);
  const IPSlot *find(const swoc::IPAddr &ip) const;

  /**
   * Record an event for an IP, creating a slot if needed.
   *
   * If the IP is already tracked, returns the existing slot.
   * If not, attempts to contest a slot using the Udi algorithm.
   *
   * @param ip The IP address
   * @param score_delta Score to add (typically 1 for errors)
   * @return Pointer to the slot (may be nullptr if contest failed)
   *
   * Thread-safe: Uses exclusive lock on the relevant partition.
   */
  IPSlot *record_event(const swoc::IPAddr &ip, int score_delta = 1);

  /**
   * Record a success for an IP (decrements score).
   *
   * If the score reaches 0, the IP may be evicted.
   *
   * @param ip The IP address
   *
   * Thread-safe: Uses exclusive lock on the relevant partition.
   */
  void record_success(const swoc::IPAddr &ip);

  /**
   * Get statistics about the tracker.
   */
  size_t
  num_slots() const
  {
    return table_->num_slots();
  }

  size_t
  slots_used() const
  {
    return table_->slots_used();
  }

  uint64_t
  contests() const
  {
    return table_->contests();
  }

  uint64_t
  contests_won() const
  {
    return table_->contests_won();
  }

  uint64_t
  evictions() const
  {
    return table_->evictions();
  }

  /**
   * Reset table-level metrics to zero.
   *
   * This resets the metrics (contests, contests_won, evictions) and updates
   * the reset timestamp. It does NOT modify any tracked IPs or their counters.
   */
  void
  reset_metrics()
  {
    table_->reset_metrics();
  }

  /**
   * Get the timestamp of the last reset (or tracker creation).
   *
   * @return Time point of last reset or construction
   */
  std::chrono::system_clock::time_point
  last_reset_time() const
  {
    return table_->last_reset_time();
  }

  /**
   * Get the number of seconds since last reset (or tracker creation).
   *
   * @return Seconds since last reset
   */
  uint64_t
  seconds_since_reset() const
  {
    return table_->seconds_since_reset();
  }

  /**
   * Dump all tracked IPs to a string (for debugging).
   */
  std::string dump() const;

private:
  std::unique_ptr<Table> table_;
};

} // namespace abuse_shield
