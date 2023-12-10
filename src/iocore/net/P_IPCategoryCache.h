/** @file

  Declarations for LRU caching for IPCategory.

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

#include <chrono>
#include <list>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <unordered_map>
#include <vector>

#include "iocore/net/IPCategory.h"
#include "swoc/IPAddr.h"

/** A cached value holding the item and its last used timestamp. */
struct CacheItem {
  /// The categories associated with an IP address.
  Categories_t categories;

  /// The timestamp when the item was last used.
  std::chrono::steady_clock::time_point timestamp;

  /// A pointer to the item's position in the LRU list.
  std::list<swoc::IPAddr>::iterator lru_pos;
};

/** Implement a segment of least recently used caching for IP categories.
 */
class LRUCacheSegment
{
public:
  LRUCacheSegment()                                   = delete;
  LRUCacheSegment(LRUCacheSegment const &)            = delete;
  LRUCacheSegment(LRUCacheSegment &&)                 = delete;
  LRUCacheSegment &operator=(LRUCacheSegment const &) = delete;

  /** Construct a new LRU Cache object.
   *
   * @param max_size The maximum size of the cache.
   * @param timeout The timeout for each item in the cache.
   */
  LRUCacheSegment(size_t max_size, std::chrono::seconds timeout);

  /** Get the categories associated with the given IP address.
   *
   * @param addr The IP address to look up.
   * @return The categories associated with the IP address, or std::nullopt if
   * the address is not in the cache.
   */
  std::optional<Categories_t> get(swoc::IPAddr const &addr);

  /** Add a new item to the cache, or update an existing item.
   *
   * @param addr The IP address.
   * @param categories The categories associated with the IP address.
   */
  void put(swoc::IPAddr const &addr, Categories_t const &categories);

  /**
   * Remove items from the cache that have been there for longer than the timeout.
   */
  void cleanup();

private:
  std::unordered_map<swoc::IPAddr, CacheItem> _cache;      ///< The cache, mapping IP addresses to CacheItems.
  std::list<swoc::IPAddr> _lru;                            ///< A list of IP addresses, used to implement the LRU policy.
  size_t _max_size              = 0;                       ///< The maximum size of the cache.
  std::chrono::seconds _timeout = std::chrono::seconds{0}; ///< The timeout for each item in the cache.
  std::mutex _mutex;                                       ///< A mutex to protect the cache.
};

/** A wrapper around the set of IP category caching segments.
 *
 * The cache is segmented for efficiency since accessing the cache requires a
 * lot of locking.
 */
class IPCategoryCache
{
public:
  /** Initialize the LRUCache with the specified number of segments and timeout.
   *
   * @param[in] max_segment_size The maximum size of each segment.
   * @param[in] num_segments The number of segments to divide the cache into.
   * @param[in] timeout The timeout duration for cache entries.
   */
  static void initialize(size_t max_segment_size, size_t num_segments, std::chrono::seconds timeout);

  /** Get the categories associated with the given IP address.
   *
   * @param[in] addr The IP address to look up.
   * @return The categories associated with the IP address, or std::nullopt if
   * the address is not in the cache.
   */
  static std::optional<Categories_t> get(sockaddr const &addr);

  /** Add a new item to the cache, or update an existing item.
   *
   * @param[in] addr The IP address.
   * @param[in] categories The categories associated with the IP address.
   */
  static void put(sockaddr const &addr, Categories_t const &categories);

private:
  static std::vector<std::unique_ptr<LRUCacheSegment>> _segments; ///< The segments of the cache.
};
