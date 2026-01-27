/** @file

  Udi "King of the Hill" Table - A fixed-size, self-cleaning hash table.

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
#include <cmath>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "tsutil/Xoroshiro128Plus.h"

namespace ts
{

/** A fixed-size hash table using the Udi "King of the Hill" algorithm.
 *
 * Instantiations of this table track the keys/entities (IPs, URLs, etc.) with
 * the highest rates of events (e.g. number of requests, number of errors, etc.).
 *
 * This implements the Udi algorithm (US Patent 7533414) for tracking entities
 * (IPs, URLs, etc.) and their events with bounded memory. The algorithm was
 * developed to address abuse detection where a "screening list" identifies
 * potential abuse events.
 *
 * From the patent: "A screening list includes event IDs and associated count values.
 * A pointer cyclically selects entries in the table, advancing as events are received.
 * An incoming event ID is compared with the event IDs in the table. If the incoming
 * event ID matches an event ID in the screening list, the associated count is
 * incremented. Otherwise, the count of a selected table entry is decremented. If the
 * count value of the selected entry falls to zero, it is replaced with the incoming
 * event and the count is reset to one."
 *
 * Thus the table serves as a "screening list" - the "hot" items to investigate. Each slot
 * can be investigated using the templated @a Data to determine which top talkers require
 * action.
 *
 * Key properties:
 * - Fixed memory: N slots = bounded memory, no unbounded growth
 * - Self-cleaning: No cleanup thread needed, table manages itself
 * - Hot tracking: High-score entries naturally stay in the table
 * - Simple locking: Single mutex for all operations
 * - Safe references: Returns shared_ptr so data survives eviction
 *
 * @tparam Key The entity type (e.g., IP address, URL)
 * @tparam Data User's custom data type to associate with each entry
 * @tparam Hash Hash function for keys (defaults to std::hash)
 *
 * The table owns the key and score for each entry. Users provide only their custom
 * Data type which is stored in a shared_ptr for safe access.
 *
 * Thread Safety:
 * All operations are protected by a single mutex and are serialized.
 * Returned shared_ptr<Data> remains valid even after the slot is evicted.
 *
 * Example usage:
 * @code
 * struct MyData {
 *   std::atomic<uint32_t> error_count{0};
 *   std::atomic<uint32_t> success_count{0};
 * };
 *
 * ts::UdiTable<std::string, MyData> table(10000);
 *
 * auto data = table.process_event("some_key", 1);
 * if (data) {
 *   data->error_count.fetch_add(1);
 * }
 * @endcode
 */
template <typename Key, typename Data, typename Hash = std::hash<Key>> class UdiTable
{
public:
  using key_type  = Key;
  using data_type = Data;
  using data_ptr  = std::shared_ptr<Data>;

  using data_format_fn = std::function<std::string(Key const &, double, data_ptr const &)>;

  // =========================================================================
  // Public API - Declarations
  // =========================================================================

  /** Construct a UdiTable with EWMA scoring and multi-probe eviction.
   *
   * @param[in] num_slots Total number of slots to allocate.
   * @param[in] window_decay_seconds Time window for EWMA decay (default: 60 seconds).
   *            Controls how quickly scores decay over time. After this many seconds,
   *            an inactive entry's score decays to approximately 37% (1/e) of original.
   * @param[in] window_expiration_seconds Time window for staleness expiration (default: 60 seconds).
   *            Entries not updated within this window are considered stale and can be
   *            evicted without score comparison.
   * @param[in] num_probes Number of random slots to probe during eviction (default: 4).
   */
  explicit UdiTable(size_t num_slots, double window_decay_seconds = 60.0, double window_expiration_seconds = 60.0,
                    size_t num_probes = 4);

  // No copying or moving
  UdiTable(UdiTable const &)            = delete;
  UdiTable &operator=(UdiTable const &) = delete;
  UdiTable(UdiTable &&)                 = delete;
  UdiTable &operator=(UdiTable &&)      = delete;

  /** Retrieve the configured data for a given key.
   *
   * @param[in] key The key to look up.
   * @return The data associated with @a key if found, nullptr otherwise.
   *
   * Thread-safe: Uses mutex lock.
   * The returned shared_ptr remains valid even if the slot is later evicted.
   */
  data_ptr                    find(Key const &key);
  std::shared_ptr<Data const> find(Key const &key) const;

  /** Process an event for a key, creating a slot if needed via @a contest.
   *
   * If the key is already tracked, increments its score and returns the Data.
   * If not, a call to @a contest is made to see whether the @a key should evict
   * an entry and take its place.
   *
   * @param[in] key The key for which an event is being processed.
   * @param[in] score_delta Score to add (typically 1 for events).
   * @return The data for @a key if tracked or contest won, nullptr if contest lost.
   *
   * Thread-safe: Uses mutex lock.
   * The returned shared_ptr remains valid even if the slot is later evicted.
   */
  data_ptr process_event(Key const &key, uint32_t score_delta = 1);

  /** Remove a key from the table.
   *
   * @param[in] key The key to remove.
   * @return Whether @a key was found and removed.
   *
   * Note: Existing shared_ptr references to the removed Data remain valid.
   */
  bool remove(Key const &key);

  // Statistics
  size_t   num_slots() const;
  size_t   slots_used() const;
  uint64_t contests() const;
  uint64_t contests_won() const;
  uint64_t evictions() const;

  /** Reset table-level metrics to zero.
   *
   * Does NOT modify any entries in the table.
   */
  void reset_metrics();

  /** Get the timestamp of the last reset (or table creation).
   */
  std::chrono::system_clock::time_point last_reset_time() const;

  /** Get the number of seconds since last reset (or table creation).
   */
  uint64_t seconds_since_reset() const;

  /** Dump all entries to a string.
   *
   * This may be useful to evaluate the behavior of the table for debugging or
   * diagnostic purposes.
   *
   * @param[in] format_data Optional function to format each entry (key, score, data).
   * @return A string representation of all table entries.
   */
  std::string dump(data_format_fn format_data = nullptr) const;

private:
  /** The data used to track the key and score used to determine eviction.
   *
   * Uses EWMA (Exponential Weighted Moving Average) scoring where scores
   * decay naturally over time. This allows stale entries to be evicted
   * more easily than active entries.
   */
  struct Slot {
    Key      key{};
    double   ewma_score{0.0};       ///< Decaying score (undecayed accumulator)
    double   last_update_time{0.0}; ///< Seconds (monotonic clock) of last update
    data_ptr data;

    /** Check whether there is an entity associated with this slot.
     *
     * @return Whether the slot has no entity assigned.
     */
    bool
    is_empty() const
    {
      return !data;
    }

    /** Calculate decayed score at current time for eviction comparison.
     *
     * Applies exponential decay based on time since last update.
     *
     * @param[in] now Current time in seconds (monotonic).
     * @param[in] window_inverse Pre-computed 1.0 / window_seconds.
     * @return The time-decayed score.
     */
    double
    decayed_score(double now, double window_inverse) const
    {
      double delta_t = now - last_update_time;
      return ewma_score * std::exp(-delta_t * window_inverse) * window_inverse;
    }

    /** Remove the entity associated with this slot.
     */
    void
    clear()
    {
      key              = Key{};
      ewma_score       = 0.0;
      last_update_time = 0.0;
      data.reset();
    }
  };

  /** Determine whether the given key should evict a slot.
   *
   * Assumes @a mutex_ already held exclusively.
   *
   * @param[in] key The key trying to enter.
   * @param[in] incoming_score The score of the incoming key.
   * @return The data for @a key if contest won, nullptr if contest lost.
   */
  data_ptr contest(Key const &key, uint32_t incoming_score);

  /** Get current monotonic time in seconds.
   *
   * Uses std::chrono::steady_clock for monotonic time, similar to
   * SafeT-Span's use of CLOCK_MONOTONIC_RAW.
   *
   * @return Current time in seconds as a double.
   */
  static double
  current_time()
  {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
  }

  /// Single global mutex for all operations
  mutable std::mutex mutex_;

  /// Lookup map: key -> slot index
  std::unordered_map<Key, size_t, Hash> lookup_;

  /// The slots representing the table.
  std::vector<Slot> slots_;

  /// EWMA window parameters
  double window_decay_inverse_;      ///< 1.0 / window_decay_seconds (pre-computed for EWMA)
  double window_expiration_seconds_; ///< Window for staleness expiration check

  /// Number of random slots to probe during eviction
  size_t num_probes_;

  /// Per-table fast PRNG for eviction candidate selection
  mutable Xoroshiro128Plus rng_;

  /// Metrics.
  std::atomic<uint64_t> metric_contests_{0};
  std::atomic<uint64_t> metric_contests_won_{0};
  std::atomic<uint64_t> metric_evictions_{0};

  /// Timestamp of last reset (or construction)
  std::chrono::system_clock::time_point last_reset_time_;
};

// ===========================================================================
// Implementation
// ===========================================================================

template <typename Key, typename Data, typename Hash>
UdiTable<Key, Data, Hash>::UdiTable(size_t num_slots, double window_decay_seconds, double window_expiration_seconds,
                                    size_t num_probes)
  : slots_(num_slots),
    window_decay_inverse_(1.0 / window_decay_seconds),
    window_expiration_seconds_(window_expiration_seconds),
    num_probes_(num_probes),
    last_reset_time_(std::chrono::system_clock::now())
{
  slots_.reserve(num_slots);
  lookup_.reserve(num_slots);
}

template <typename Key, typename Data, typename Hash>
std::shared_ptr<Data>
UdiTable<Key, Data, Hash>::find(Key const &key)
{
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = lookup_.find(key);
  if (it != lookup_.end()) {
    return slots_[it->second].data;
  }
  return nullptr;
}

template <typename Key, typename Data, typename Hash>
std::shared_ptr<Data const>
UdiTable<Key, Data, Hash>::find(Key const &key) const
{
  return const_cast<UdiTable *>(this)->find(key);
}

template <typename Key, typename Data, typename Hash>
std::shared_ptr<Data>
UdiTable<Key, Data, Hash>::process_event(Key const &key, uint32_t score_delta)
{
  std::lock_guard<std::mutex> lock(mutex_);

  double now = current_time();

  // Check if already tracked
  auto it = lookup_.find(key);
  if (it != lookup_.end()) {
    Slot  &slot    = slots_[it->second];
    double delta_t = now - slot.last_update_time;
    double factor  = std::exp(-delta_t * window_decay_inverse_);

    // Apply EWMA: decay existing score then add new input
    slot.ewma_score       = factor * slot.ewma_score + static_cast<double>(score_delta);
    slot.last_update_time = now;
    return slot.data;
  }

  // Not tracked - contest for a slot
  return contest(key, score_delta);
}

template <typename Key, typename Data, typename Hash>
bool
UdiTable<Key, Data, Hash>::remove(Key const &key)
{
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = lookup_.find(key);
  if (it == lookup_.end()) {
    return false;
  }

  slots_[it->second].clear();
  lookup_.erase(it);
  return true;
}

template <typename Key, typename Data, typename Hash>
size_t
UdiTable<Key, Data, Hash>::num_slots() const
{
  return slots_.size();
}

template <typename Key, typename Data, typename Hash>
size_t
UdiTable<Key, Data, Hash>::slots_used() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  return lookup_.size();
}

template <typename Key, typename Data, typename Hash>
uint64_t
UdiTable<Key, Data, Hash>::contests() const
{
  return metric_contests_.load(std::memory_order_relaxed);
}

template <typename Key, typename Data, typename Hash>
uint64_t
UdiTable<Key, Data, Hash>::contests_won() const
{
  return metric_contests_won_.load(std::memory_order_relaxed);
}

template <typename Key, typename Data, typename Hash>
uint64_t
UdiTable<Key, Data, Hash>::evictions() const
{
  return metric_evictions_.load(std::memory_order_relaxed);
}

template <typename Key, typename Data, typename Hash>
void
UdiTable<Key, Data, Hash>::reset_metrics()
{
  std::lock_guard<std::mutex> lock(mutex_);
  metric_contests_.store(0, std::memory_order_relaxed);
  metric_contests_won_.store(0, std::memory_order_relaxed);
  metric_evictions_.store(0, std::memory_order_relaxed);
  last_reset_time_ = std::chrono::system_clock::now();
}

template <typename Key, typename Data, typename Hash>
std::chrono::system_clock::time_point
UdiTable<Key, Data, Hash>::last_reset_time() const
{
  return last_reset_time_;
}

template <typename Key, typename Data, typename Hash>
uint64_t
UdiTable<Key, Data, Hash>::seconds_since_reset() const
{
  auto now     = std::chrono::system_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_reset_time_);
  return static_cast<uint64_t>(elapsed.count());
}

template <typename Key, typename Data, typename Hash>
std::string
UdiTable<Key, Data, Hash>::dump(data_format_fn format_data) const
{
  std::string result;
  result.reserve(slots_.size() * 64);

  std::lock_guard<std::mutex> lock(mutex_);

  double now = current_time();
  for (auto const &[key, slot_idx] : lookup_) {
    Slot const &slot          = slots_[slot_idx];
    double      decayed_score = slot.decayed_score(now, window_decay_inverse_);
    if (format_data) {
      result += format_data(slot.key, decayed_score, slot.data);
    } else {
      result += "slot[" + std::to_string(slot_idx) + "] score=" + std::to_string(decayed_score) + "\n";
    }
  }
  return result;
}

template <typename Key, typename Data, typename Hash>
std::shared_ptr<Data>
UdiTable<Key, Data, Hash>::contest(Key const &key, uint32_t incoming_score)
{
  // Called with mutex_ already held exclusively

  metric_contests_.fetch_add(1, std::memory_order_relaxed);

  if (slots_.empty()) {
    return nullptr;
  }

  double now            = current_time();
  Slot  *best_candidate = nullptr;
  double best_score     = std::numeric_limits<double>::max();
  size_t best_idx       = 0;

  // If table isn't full, find an empty slot directly (guaranteed to exist).
  if (lookup_.size() < slots_.size()) {
    for (size_t idx = 0; idx < slots_.size(); ++idx) {
      if (slots_[idx].is_empty()) {
        best_candidate = &slots_[idx];
        best_idx       = idx;
        best_score     = 0.0;
        break;
      }
    }
  } else {
    // Table is full - probe random slots to find best eviction candidate.
    for (size_t probe = 0; probe < num_probes_; ++probe) {
      size_t idx  = rng_() % slots_.size();
      Slot  &slot = slots_[idx];

      // Window-based expiration: if entry is older than window, it's stale
      if (slot.last_update_time + window_expiration_seconds_ <= now) {
        // Stale entry - can be evicted without score comparison
        best_candidate = &slot;
        best_idx       = idx;
        best_score     = 0.0;
        break;
      }

      double score = slot.decayed_score(now, window_decay_inverse_);
      if (score < best_score) {
        best_candidate = &slot;
        best_idx       = idx;
        best_score     = score;
      }
    }
  }

  // Compare incoming score against best candidate's decayed score
  if (static_cast<double>(incoming_score) > best_score) {
    // Evict and take the slot
    if (best_candidate != nullptr && !best_candidate->is_empty()) {
      lookup_.erase(best_candidate->key);
      metric_evictions_.fetch_add(1, std::memory_order_relaxed);
    }

    // Initialize the slot with new key and fresh Data
    best_candidate->key              = key;
    best_candidate->ewma_score       = static_cast<double>(incoming_score);
    best_candidate->last_update_time = now;
    best_candidate->data             = std::make_shared<Data>();
    lookup_[key]                     = best_idx;

    metric_contests_won_.fetch_add(1, std::memory_order_relaxed);
    return best_candidate->data;
  }

  // No eviction candidate found.
  return nullptr;
}

} // namespace ts
