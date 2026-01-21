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

#include <algorithm>
#include <chrono>
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
}  // namespace

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

IPTracker::IPTracker(size_t num_slots, size_t num_partitions)
  : partitions_(num_partitions), slots_(num_slots), slots_per_partition_(num_slots / num_partitions)
{
  // Initialize contest pointers for each partition
  for (size_t i = 0; i < num_partitions; ++i) {
    // Each partition contests within its range of slots
    partitions_[i].contest_ptr.store(i * slots_per_partition_, std::memory_order_relaxed);
  }
}

IPSlot *
IPTracker::find(const swoc::IPAddr &ip)
{
  size_t part_idx = partition_for(ip);
  Partition &part = partitions_[part_idx];

  std::shared_lock lock(part.mutex);
  auto it = part.lookup.find(ip);
  if (it != part.lookup.end()) {
    return &slots_[it->second];
  }
  return nullptr;
}

const IPSlot *
IPTracker::find(const swoc::IPAddr &ip) const
{
  return const_cast<IPTracker *>(this)->find(ip);
}

IPSlot *
IPTracker::record_event(const swoc::IPAddr &ip, int score_delta)
{
  size_t part_idx = partition_for(ip);
  Partition &part = partitions_[part_idx];

  // First try with a shared lock to see if IP is already tracked
  {
    std::shared_lock lock(part.mutex);
    auto it = part.lookup.find(ip);
    if (it != part.lookup.end()) {
      IPSlot *slot = &slots_[it->second];
      slot->score.fetch_add(score_delta, std::memory_order_relaxed);
      slot->last_seen.store(now_ms(), std::memory_order_relaxed);
      return slot;
    }
  }

  // Not found - need exclusive lock to contest
  std::unique_lock lock(part.mutex);

  // Double-check after acquiring exclusive lock
  auto it = part.lookup.find(ip);
  if (it != part.lookup.end()) {
    IPSlot *slot = &slots_[it->second];
    slot->score.fetch_add(score_delta, std::memory_order_relaxed);
    slot->last_seen.store(now_ms(), std::memory_order_relaxed);
    return slot;
  }

  // Contest for a slot
  size_t slot_idx = contest(part, ip, score_delta);
  if (slot_idx < slots_.size()) {
    return &slots_[slot_idx];
  }

  return nullptr;
}

void
IPTracker::record_success(const swoc::IPAddr &ip)
{
  size_t part_idx = partition_for(ip);
  Partition &part = partitions_[part_idx];

  std::unique_lock lock(part.mutex);
  auto it = part.lookup.find(ip);
  if (it != part.lookup.end()) {
    IPSlot &slot = slots_[it->second];
    slot.record_success();

    // If score reached 0, evict the IP
    if (slot.score.load(std::memory_order_relaxed) == 0) {
      part.lookup.erase(it);
      slot.clear();
    }
  }
}

size_t
IPTracker::contest(Partition &part, const swoc::IPAddr &ip, int incoming_score)
{
  // Calculate the range of slots this partition can contest
  size_t part_idx   = &part - partitions_.data();
  size_t slot_start = part_idx * slots_per_partition_;

  // Get current contest pointer and advance it
  size_t contest_idx = part.contest_ptr.fetch_add(1, std::memory_order_relaxed);
  contest_idx        = slot_start + ((contest_idx - slot_start) % slots_per_partition_);

  IPSlot &slot      = slots_[contest_idx];
  uint32_t slot_score = slot.score.load(std::memory_order_relaxed);

  if (static_cast<uint32_t>(incoming_score) > slot_score) {
    // Incoming IP wins - take the slot
    if (slot.addr.is_valid()) {
      // Remove old IP from lookup
      part.lookup.erase(slot.addr);
    }

    // Initialize slot with new IP
    slot.clear();
    slot.addr = ip;
    slot.score.store(incoming_score, std::memory_order_relaxed);
    slot.last_seen.store(now_ms(), std::memory_order_relaxed);

    // Add new IP to lookup
    part.lookup[ip] = contest_idx;

    return contest_idx;
  } else {
    // Existing slot survives but is weakened
    if (slot_score > 0) {
      slot.score.fetch_sub(1, std::memory_order_relaxed);
    }
    return slots_.size();  // Invalid index indicates contest lost
  }
}

size_t
IPTracker::slots_used() const
{
  size_t count = 0;
  for (const auto &slot : slots_) {
    if (!slot.empty()) {
      ++count;
    }
  }
  return count;
}

std::string
IPTracker::dump() const
{
  std::ostringstream oss;

  oss << "# abuse_shield dump\n";
  oss << "# slots_used: " << slots_used() << " / " << slots_.size() << "\n";
  oss << "# IP\tCLIENT_ERR\tSERVER_ERR\tSUCCESS\tSCORE\tBLOCKED_UNTIL\n";

  // Collect all non-empty slots
  std::vector<const IPSlot *> active_slots;
  for (const auto &slot : slots_) {
    if (!slot.empty()) {
      active_slots.push_back(&slot);
    }
  }

  // Sort by score (highest first)
  std::sort(active_slots.begin(), active_slots.end(), [](const IPSlot *a, const IPSlot *b) {
    return a->score.load(std::memory_order_relaxed) > b->score.load(std::memory_order_relaxed);
  });

  for (const auto *slot : active_slots) {
    swoc::LocalBufferWriter<64> ip_str;
    ip_str.print("{}", slot->addr);
    oss << ip_str.view() << "\t" << slot->client_errors.load(std::memory_order_relaxed) << "\t"
        << slot->server_errors.load(std::memory_order_relaxed) << "\t" << slot->successes.load(std::memory_order_relaxed) << "\t"
        << slot->score.load(std::memory_order_relaxed) << "\t" << slot->blocked_until.load(std::memory_order_relaxed) << "\n";
  }

  return oss.str();
}

}  // namespace abuse_shield
