/** @file

  IP Tracker implementation using Udi "King of the Hill" algorithm.

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

#include "ip_tracker.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "swoc/BufferWriter.h"
#include "swoc/bwf_ip.h"

namespace abuse_shield
{

namespace
{
  uint64_t
  now_ms()
  {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
  }
} // namespace

// ============================================================================
// IPSlot implementation
// ============================================================================

void
IPSlot::clear()
{
  addr = swoc::IPAddr{};
  client_errors.store(0, std::memory_order_relaxed);
  server_errors.store(0, std::memory_order_relaxed);
  successes.store(0, std::memory_order_relaxed);
  score.store(0, std::memory_order_relaxed);

  for (auto &count : h2_error_counts) {
    count.store(0, std::memory_order_relaxed);
  }

  conn_count.store(0, std::memory_order_relaxed);
  req_count.store(0, std::memory_order_relaxed);
  window_start.store(0, std::memory_order_relaxed);
  last_seen.store(0, std::memory_order_relaxed);
  blocked_until.store(0, std::memory_order_relaxed);
}

void
IPSlot::record_h2_error(uint8_t error_code, bool is_client_error)
{
  if (is_client_error) {
    client_errors.fetch_add(1, std::memory_order_relaxed);
  } else {
    server_errors.fetch_add(1, std::memory_order_relaxed);
  }

  if (error_code < NUM_H2_ERROR_CODES) {
    h2_error_counts[error_code].fetch_add(1, std::memory_order_relaxed);
  }

  score.fetch_add(1, std::memory_order_relaxed);
  last_seen.store(now_ms(), std::memory_order_relaxed);
}

void
IPSlot::record_success()
{
  successes.fetch_add(1, std::memory_order_relaxed);

  // Decrement score (but don't go below 0)
  uint32_t current = score.load(std::memory_order_relaxed);
  while (current > 0) {
    if (score.compare_exchange_weak(current, current - 1, std::memory_order_relaxed)) {
      break;
    }
  }

  last_seen.store(now_ms(), std::memory_order_relaxed);
}

void
IPSlot::record_connection()
{
  conn_count.fetch_add(1, std::memory_order_relaxed);
  last_seen.store(now_ms(), std::memory_order_relaxed);
}

void
IPSlot::record_request()
{
  req_count.fetch_add(1, std::memory_order_relaxed);
  last_seen.store(now_ms(), std::memory_order_relaxed);
}

bool
IPSlot::is_blocked() const
{
  uint64_t until = blocked_until.load(std::memory_order_relaxed);
  return until > 0 && now_ms() < until;
}

void
IPSlot::block_until(uint64_t until_ms)
{
  blocked_until.store(until_ms, std::memory_order_relaxed);
}

// ============================================================================
// IPTracker implementation
// ============================================================================

IPTracker::IPTracker(size_t num_slots)
{
  // Define accessor functions for UdiTable
  auto get_key = [](const IPSlot &slot) -> const swoc::IPAddr & { return slot.addr; };

  auto set_key = [](IPSlot &slot, const swoc::IPAddr &ip) { slot.addr = ip; };

  auto get_score = [](const IPSlot &slot) -> uint32_t { return slot.score.load(std::memory_order_relaxed); };

  auto set_score = [](IPSlot &slot, uint32_t value) { slot.score.store(value, std::memory_order_relaxed); };

  auto is_empty = [](const IPSlot &slot) -> bool { return slot.empty(); };

  auto clear_slot = [](IPSlot &slot) { slot.clear(); };

  table_ = std::make_unique<Table>(num_slots, get_key, set_key, get_score, set_score, is_empty, clear_slot);
}

IPSlot *
IPTracker::find(const swoc::IPAddr &ip)
{
  return table_->find(ip);
}

const IPSlot *
IPTracker::find(const swoc::IPAddr &ip) const
{
  return table_->find(ip);
}

IPSlot *
IPTracker::record_event(const swoc::IPAddr &ip, int score_delta)
{
  IPSlot *slot = table_->record(ip, static_cast<uint32_t>(score_delta));
  if (slot) {
    slot->last_seen.store(now_ms(), std::memory_order_relaxed);
  }
  return slot;
}

void
IPTracker::record_success(const swoc::IPAddr &ip)
{
  // Use decrement which will evict if score reaches 0
  table_->decrement(ip, 1);
}

namespace
{
  // Format duration as human-readable string (e.g., "2h 15m 30s" or "45s")
  std::string
  format_duration(uint64_t total_seconds)
  {
    if (total_seconds == 0) {
      return "0s";
    }

    uint64_t hours   = total_seconds / 3600;
    uint64_t minutes = (total_seconds % 3600) / 60;
    uint64_t seconds = total_seconds % 60;

    std::ostringstream oss;
    if (hours > 0) {
      oss << hours << "h ";
    }
    if (minutes > 0 || hours > 0) {
      oss << minutes << "m ";
    }
    oss << seconds << "s";
    return oss.str();
  }

  // Format time_point as ISO-like timestamp string
  std::string
  format_timestamp(std::chrono::system_clock::time_point tp)
  {
    auto    time_t_val = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_val;
    localtime_r(&time_t_val, &tm_val);

    std::ostringstream oss;
    oss << std::put_time(&tm_val, "%Y-%m-%d %H:%M:%S");
    return oss.str();
  }
} // namespace

std::string
IPTracker::dump() const
{
  auto format_slot = [](const IPSlot &slot) -> std::string {
    if (slot.empty()) {
      return "";
    }

    swoc::LocalBufferWriter<64> ip_str;
    ip_str.print("{}", slot.addr);

    std::ostringstream oss;
    oss << ip_str.view() << "\t" << slot.client_errors.load(std::memory_order_relaxed) << "\t"
        << slot.server_errors.load(std::memory_order_relaxed) << "\t" << slot.successes.load(std::memory_order_relaxed) << "\t"
        << slot.score.load(std::memory_order_relaxed) << "\t" << slot.blocked_until.load(std::memory_order_relaxed) << "\n";
    return oss.str();
  };

  uint64_t    age_seconds    = seconds_since_reset();
  auto        reset_time     = last_reset_time();
  std::string reset_time_str = format_timestamp(reset_time);
  std::string age_str        = format_duration(age_seconds);

  std::ostringstream header;
  header << "# abuse_shield dump\n";
  header << "# last_reset: " << reset_time_str << " (" << age_str << " ago)\n";
  header << "# slots_used: " << slots_used() << " / " << num_slots() << "\n";
  header << "# contests: " << contests() << " (won: " << contests_won() << ")\n";
  header << "# evictions: " << evictions() << "\n";
  header << "# IP\tCLIENT_ERR\tSERVER_ERR\tSUCCESS\tSCORE\tBLOCKED_UNTIL\n";

  return header.str() + table_->dump(format_slot);
}

} // namespace abuse_shield
