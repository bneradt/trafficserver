/** @file

  Udi "King of the Hill" Table - A fixed-size, self-cleaning hash table.

  This implements the Udi algorithm (Patent 7533414) for tracking entities
  (IPs, URLs, etc.) with bounded memory. When the table is full, new entries
  compete with existing entries based on a score - the higher score wins the slot.

  Key properties:
  - Fixed memory: N slots = bounded memory, no unbounded growth
  - Self-cleaning: No cleanup thread needed, table manages itself
  - Hot tracking: High-score entries naturally stay in the table
  - Lock-efficient: Uses partitioned locking to minimize contention

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
#include <cstdint>
#include <functional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "tsutil/TsSharedMutex.h"

namespace ts
{

/**
 * UdiTable - A fixed-size hash table using the Udi "King of the Hill" algorithm.
 *
 * @tparam Key The key type (e.g., IP address, URL)
 * @tparam Slot The slot type - must have:
 *   - A way to get/set the key (via KeyAccessor)
 *   - A way to get/set the score (via ScoreAccessor)
 *   - A clear() method to reset the slot
 * @tparam KeyAccessor Functor to get the key from a slot
 * @tparam ScoreAccessor Functor to get/set the score from a slot
 * @tparam Hash Hash function for keys (defaults to std::hash)
 * @tparam NumPartitions Number of hash table partitions (default 64)
 *
 * Thread Safety:
 * - find() uses a shared lock on one partition
 * - record() uses an exclusive lock on one partition
 * - Slot updates after find() should use atomic operations
 *
 * Example usage:
 * @code
 * struct MySlot {
 *   std::string key;
 *   std::atomic<uint32_t> score{0};
 *   std::atomic<uint32_t> count{0};
 *   void clear() { key.clear(); score = 0; count = 0; }
 * };
 *
 * auto get_key = [](const MySlot& s) -> const std::string& { return s.key; };
 * auto set_key = [](MySlot& s, const std::string& k) { s.key = k; };
 * auto get_score = [](const MySlot& s) { return s.score.load(); };
 * auto set_score = [](MySlot& s, uint32_t v) { s.score.store(v); };
 *
 * ts::UdiTable<std::string, MySlot> table(10000, get_key, set_key, get_score, set_score);
 *
 * MySlot* slot = table.record("some_key", 1);
 * if (slot) {
 *   slot->count.fetch_add(1);
 * }
 * @endcode
 */
template <typename Key, typename Slot, typename Hash = std::hash<Key>, size_t NumPartitions = 64> class UdiTable
{
public:
  using key_type       = Key;
  using slot_type      = Slot;
  using get_key_fn     = std::function<Key const &(Slot const &)>;
  using set_key_fn     = std::function<void(Slot &, Key const &)>;
  using get_score_fn   = std::function<uint32_t(Slot const &)>;
  using set_score_fn   = std::function<void(Slot &, uint32_t)>;
  using slot_empty_fn  = std::function<bool(Slot const &)>;
  using slot_clear_fn  = std::function<void(Slot &)>;
  using slot_format_fn = std::function<std::string(Slot const &)>;

  /**
   * Construct a UdiTable.
   *
   * @param num_slots Total number of slots to allocate
   * @param get_key Function to get the key from a slot
   * @param set_key Function to set the key in a slot
   * @param get_score Function to get the score from a slot
   * @param set_score Function to set the score in a slot
   * @param is_empty Function to check if a slot is empty (optional, defaults to score == 0)
   * @param clear_slot Function to clear a slot (optional, calls slot.clear())
   */
  UdiTable(size_t num_slots, get_key_fn get_key, set_key_fn set_key, get_score_fn get_score, set_score_fn set_score,
           slot_empty_fn is_empty = nullptr, slot_clear_fn clear_slot = nullptr)
    : slots_(num_slots),
      slots_per_partition_((num_slots + NumPartitions - 1) / NumPartitions),
      get_key_(std::move(get_key)),
      set_key_(std::move(set_key)),
      get_score_(std::move(get_score)),
      set_score_(std::move(set_score)),
      is_empty_(is_empty ? std::move(is_empty) : [this](Slot const &s) { return get_score_(s) == 0; }),
      clear_slot_(clear_slot ? std::move(clear_slot) : [](Slot &s) { s.clear(); })
  {
  }

  // No copying or moving
  UdiTable(UdiTable const &)            = delete;
  UdiTable &operator=(UdiTable const &) = delete;
  UdiTable(UdiTable &&)                 = delete;
  UdiTable &operator=(UdiTable &&)      = delete;

  /**
   * Find a key in the table.
   *
   * @param key The key to look up
   * @return Pointer to the slot if found, nullptr otherwise
   *
   * Thread-safe: Uses shared lock on the relevant partition.
   */
  Slot *
  find(Key const &key)
  {
    size_t part_idx = partition_for(key);
    auto  &part     = partitions_[part_idx];

    std::shared_lock lock(part.mutex);
    auto             it = part.lookup.find(key);
    if (it != part.lookup.end()) {
      return &slots_[it->second];
    }
    return nullptr;
  }

  Slot const *
  find(Key const &key) const
  {
    return const_cast<UdiTable *>(this)->find(key);
  }

  /**
   * Record an event for a key, creating a slot if needed.
   *
   * If the key is already tracked, returns the existing slot.
   * If not, attempts to contest a slot using the Udi algorithm.
   *
   * @param key The key
   * @param score_delta Score to add (typically 1 for events)
   * @return Pointer to the slot (may be nullptr if contest failed and table is full)
   *
   * Thread-safe: Uses exclusive lock on the relevant partition.
   */
  Slot *
  record(Key const &key, uint32_t score_delta = 1)
  {
    size_t part_idx = partition_for(key);
    auto  &part     = partitions_[part_idx];

    std::unique_lock lock(part.mutex);

    // Check if already tracked
    auto it = part.lookup.find(key);
    if (it != part.lookup.end()) {
      Slot    &slot      = slots_[it->second];
      uint32_t new_score = get_score_(slot) + score_delta;
      set_score_(slot, new_score);
      return &slot;
    }

    // Not tracked - contest for a slot
    return contest(part, part_idx, key, score_delta);
  }

  /**
   * Decrement score for a key (e.g., on success events).
   *
   * If score reaches 0, the key is evicted from the table.
   *
   * @param key The key
   * @return true if key was found and score decremented, false if not found
   *
   * Thread-safe: Uses exclusive lock on the relevant partition.
   */
  bool
  decrement(Key const &key, uint32_t amount = 1)
  {
    size_t part_idx = partition_for(key);
    auto  &part     = partitions_[part_idx];

    std::unique_lock lock(part.mutex);

    auto it = part.lookup.find(key);
    if (it == part.lookup.end()) {
      return false;
    }

    Slot    &slot  = slots_[it->second];
    uint32_t score = get_score_(slot);
    if (score <= amount) {
      // Evict - score reached 0
      clear_slot_(slot);
      part.lookup.erase(it);
      metric_evictions_.fetch_add(1, std::memory_order_relaxed);
    } else {
      set_score_(slot, score - amount);
    }
    return true;
  }

  /**
   * Remove a key from the table.
   *
   * @param key The key to remove
   * @return true if key was found and removed, false if not found
   */
  bool
  remove(Key const &key)
  {
    size_t part_idx = partition_for(key);
    auto  &part     = partitions_[part_idx];

    std::unique_lock lock(part.mutex);

    auto it = part.lookup.find(key);
    if (it == part.lookup.end()) {
      return false;
    }

    clear_slot_(slots_[it->second]);
    part.lookup.erase(it);
    return true;
  }

  // Statistics
  size_t
  num_slots() const
  {
    return slots_.size();
  }

  size_t
  num_partitions() const
  {
    return NumPartitions;
  }

  size_t
  slots_used() const
  {
    size_t count = 0;
    for (auto const &part : partitions_) {
      std::shared_lock lock(part.mutex);
      count += part.lookup.size();
    }
    return count;
  }

  uint64_t
  contests() const
  {
    return metric_contests_.load(std::memory_order_relaxed);
  }

  uint64_t
  contests_won() const
  {
    return metric_contests_won_.load(std::memory_order_relaxed);
  }

  uint64_t
  evictions() const
  {
    return metric_evictions_.load(std::memory_order_relaxed);
  }

  /**
   * Dump all entries to a string (for debugging).
   *
   * @param format_slot Optional function to format each slot
   */
  std::string
  dump(slot_format_fn format_slot = nullptr) const
  {
    std::string result;
    result.reserve(slots_.size() * 64);

    for (size_t part_idx = 0; part_idx < NumPartitions; ++part_idx) {
      auto const      &part = partitions_[part_idx];
      std::shared_lock lock(part.mutex);

      for (auto const &[key, slot_idx] : part.lookup) {
        Slot const &slot = slots_[slot_idx];
        if (format_slot) {
          result += format_slot(slot);
        } else {
          result += "slot[" + std::to_string(slot_idx) + "] score=" + std::to_string(get_score_(slot)) + "\n";
        }
      }
    }
    return result;
  }

private:
  /**
   * Partition - Contains a portion of the hash table with its own lock.
   */
  struct Partition {
    std::unordered_map<Key, size_t, Hash> lookup;       ///< Key -> slot index
    mutable ts::shared_mutex              mutex;        ///< Partition lock
    std::atomic<size_t>                   contest_ptr;  ///< Contest pointer for this partition

    Partition() : contest_ptr(0) {}
  };

  /**
   * Get the partition index for a key.
   */
  size_t
  partition_for(Key const &key) const
  {
    return Hash{}(key) % NumPartitions;
  }

  /**
   * Get the slot range for a partition.
   */
  std::pair<size_t, size_t>
  slot_range_for_partition(size_t part_idx) const
  {
    size_t start = part_idx * slots_per_partition_;
    size_t end   = std::min(start + slots_per_partition_, slots_.size());
    return {start, end};
  }

  /**
   * Perform the Udi contest algorithm.
   *
   * Called with exclusive lock on partition already held.
   *
   * @param part The partition
   * @param part_idx The partition index
   * @param key The key trying to enter
   * @param incoming_score The score of the incoming key
   * @return Pointer to slot if contest won, nullptr otherwise
   */
  Slot *
  contest(Partition &part, size_t part_idx, Key const &key, uint32_t incoming_score)
  {
    metric_contests_.fetch_add(1, std::memory_order_relaxed);

    auto [slot_start, slot_end] = slot_range_for_partition(part_idx);
    if (slot_start >= slot_end) {
      return nullptr;  // No slots for this partition
    }

    size_t num_slots_in_partition = slot_end - slot_start;

    // Get current contest position and advance it
    size_t contest_offset = part.contest_ptr.fetch_add(1, std::memory_order_relaxed) % num_slots_in_partition;
    size_t slot_idx       = slot_start + contest_offset;

    Slot    &slot          = slots_[slot_idx];
    uint32_t current_score = get_score_(slot);

    if (is_empty_(slot) || incoming_score > current_score) {
      // New key wins - takes the slot
      if (!is_empty_(slot)) {
        // Evict the old key from the lookup
        Key const &old_key = get_key_(slot);
        part.lookup.erase(old_key);
      }

      // Initialize the slot with new key
      clear_slot_(slot);
      set_key_(slot, key);
      set_score_(slot, incoming_score);
      part.lookup[key] = slot_idx;

      metric_contests_won_.fetch_add(1, std::memory_order_relaxed);
      return &slot;
    } else {
      // New key loses - existing slot survives but is weakened
      if (current_score > 0) {
        set_score_(slot, current_score - 1);
      }
      return nullptr;
    }
  }

  std::vector<Slot>                    slots_;                ///< Fixed-size slot array
  std::array<Partition, NumPartitions> partitions_;           ///< Partitioned hash table
  size_t                               slots_per_partition_;  ///< Slots per partition

  // Accessors
  get_key_fn    get_key_;
  set_key_fn    set_key_;
  get_score_fn  get_score_;
  set_score_fn  set_score_;
  slot_empty_fn is_empty_;
  slot_clear_fn clear_slot_;

  // Metrics
  std::atomic<uint64_t> metric_contests_{0};
  std::atomic<uint64_t> metric_contests_won_{0};
  std::atomic<uint64_t> metric_evictions_{0};
};

}  // namespace ts
