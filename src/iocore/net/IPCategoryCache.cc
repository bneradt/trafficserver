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

#include "P_IPCategoryCache.h"
#include "swoc/IPAddr.h"

LRUCacheSegment::LRUCacheSegment(size_t max_size, std::chrono::seconds timeout) : _max_size(max_size), _timeout(timeout) {}

std::optional<Categories_t>
LRUCacheSegment::get(swoc::IPAddr const &addr)
{
  std::lock_guard<std::mutex> lock(_mutex);
  auto it = _cache.find(addr);
  if (it == _cache.end()) {
    return std::nullopt;
  }
  // Update timestamp and move to front of LRU list
  auto &item     = it->second;
  item.timestamp = std::chrono::steady_clock::now();
  _lru.erase(item.lru_pos);
  _lru.push_front(addr);
  item.lru_pos = _lru.begin();

  return it->second.categories;
}

void
LRUCacheSegment::put(swoc::IPAddr const &addr, Categories_t const &categories)
{
  std::lock_guard<std::mutex> lock(_mutex);
  // If already in cache, just update the categories and timestamp
  if (auto it = _cache.find(addr); it != _cache.end()) {
    auto &item      = it->second;
    item.categories = categories;
    item.timestamp  = std::chrono::steady_clock::now();
    _lru.erase(item.lru_pos);
    _lru.push_front(addr);
    item.lru_pos = _lru.begin();
  } else {
    // The entry needs to be added. If cache is full, remove least recently used
    // item.
    if (_cache.size() >= _max_size) {
      _cache.erase(_lru.back());
      _lru.pop_back();
    }

    // Add new item to cache and LRU list
    _lru.push_front(addr);
    _cache[addr] = CacheItem{categories, std::chrono::steady_clock::now(), _lru.begin()};
  }
}

void
LRUCacheSegment::cleanup()
{
  std::lock_guard<std::mutex> lock(_mutex);
  auto now = std::chrono::steady_clock::now();

  for (auto it = _cache.begin(); it != _cache.end(); /* no increment */) {
    auto &item = it->second;
    if (now - item.timestamp > _timeout) {
      _lru.remove(it->first);
      it = _cache.erase(it);
    } else {
      ++it;
    }
  }
}

// Initialize static member
std::vector<std::unique_ptr<LRUCacheSegment>> IPCategoryCache::_segments;

void
IPCategoryCache::initialize(size_t max_segment_size, size_t num_segments, std::chrono::seconds timeout)
{
  for (size_t i = 0; i < num_segments; ++i) {
    _segments.emplace_back(std::make_unique<LRUCacheSegment>(max_segment_size, timeout));
  }
}

std::optional<Categories_t>
IPCategoryCache::get(sockaddr const &addr)
{
  swoc::IPAddr ip_addr{&addr};
  size_t segment_index = std::hash<swoc::IPAddr>{}(ip_addr) % _segments.size();
  return _segments[segment_index]->get(ip_addr);
}

void
IPCategoryCache::put(sockaddr const &addr, Categories_t const &categories)
{
  swoc::IPAddr ip_addr{&addr};
  size_t segment_index = std::hash<swoc::IPAddr>{}(ip_addr) % _segments.size();
  _segments[segment_index]->put(ip_addr, categories);
}
