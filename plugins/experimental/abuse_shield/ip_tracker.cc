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
// IPData implementation
// ============================================================================

void
IPData::record_h2_error(uint8_t error_code, bool is_client_error)
{
  if (is_client_error) {
    client_errors.fetch_add(1, std::memory_order_relaxed);
  } else {
    server_errors.fetch_add(1, std::memory_order_relaxed);
  }

  if (error_code < NUM_H2_ERROR_CODES) {
    h2_error_counts[error_code].fetch_add(1, std::memory_order_relaxed);
  }

  last_seen.store(now_ms(), std::memory_order_relaxed);
}

void
IPData::record_success()
{
  successes.fetch_add(1, std::memory_order_relaxed);
  last_seen.store(now_ms(), std::memory_order_relaxed);
}

void
IPData::record_connection()
{
  conn_count.fetch_add(1, std::memory_order_relaxed);
  last_seen.store(now_ms(), std::memory_order_relaxed);
}

void
IPData::record_request()
{
  req_count.fetch_add(1, std::memory_order_relaxed);
  last_seen.store(now_ms(), std::memory_order_relaxed);
}

bool
IPData::is_blocked() const
{
  uint64_t until = blocked_until.load(std::memory_order_relaxed);
  return until > 0 && now_ms() < until;
}

void
IPData::block_until(uint64_t until_ms)
{
  blocked_until.store(until_ms, std::memory_order_relaxed);
}

// ============================================================================
// IPTracker implementation
// ============================================================================

IPTracker::IPTracker(size_t num_slots) : table_(std::make_unique<Table>(num_slots)) {}

IPTracker::IPDataPtr
IPTracker::find(const swoc::IPAddr &ip)
{
  return table_->find(ip);
}

std::shared_ptr<const IPData>
IPTracker::find(const swoc::IPAddr &ip) const
{
  return table_->find(ip);
}

IPTracker::IPDataPtr
IPTracker::record_event(const swoc::IPAddr &ip, int score_delta)
{
  auto data = table_->process_event(ip, static_cast<uint32_t>(score_delta));
  if (data) {
    data->last_seen.store(now_ms(), std::memory_order_relaxed);
  }
  return data;
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
  auto format_entry = [](const swoc::IPAddr &ip, uint32_t score, const IPDataPtr &data) -> std::string {
    swoc::LocalBufferWriter<64> ip_str;
    ip_str.print("{}", ip);

    std::ostringstream oss;
    oss << ip_str.view() << "\t" << data->client_errors.load(std::memory_order_relaxed) << "\t"
        << data->server_errors.load(std::memory_order_relaxed) << "\t" << data->successes.load(std::memory_order_relaxed) << "\t"
        << score << "\t" << data->blocked_until.load(std::memory_order_relaxed) << "\n";
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

  return header.str() + table_->dump(format_entry);
}

} // namespace abuse_shield
