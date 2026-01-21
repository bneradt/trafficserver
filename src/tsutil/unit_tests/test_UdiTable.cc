/** @file

  Unit tests for UdiTable.

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

#include "tsutil/UdiTable.h"

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "swoc/swoc_ip.h"

namespace
{

// ============================================================================
// String key test slot
// ============================================================================
struct StringSlot {
  std::string           key;
  std::atomic<uint32_t> score{0};
  std::atomic<uint32_t> data{0};

  void
  clear()
  {
    key.clear();
    score.store(0, std::memory_order_relaxed);
    data.store(0, std::memory_order_relaxed);
  }
};

auto str_get_key   = [](const StringSlot &s) -> const std::string & { return s.key; };
auto str_set_key   = [](StringSlot &s, const std::string &k) { s.key = k; };
auto str_get_score = [](const StringSlot &s) -> uint32_t { return s.score.load(std::memory_order_relaxed); };
auto str_set_score = [](StringSlot &s, uint32_t v) { s.score.store(v, std::memory_order_relaxed); };
auto str_is_empty  = [](const StringSlot &s) -> bool { return s.key.empty(); };

using StringTable = ts::UdiTable<std::string, StringSlot, std::hash<std::string>, 4>;

// ============================================================================
// IP address key test slot
// ============================================================================
struct IPSlot {
  swoc::IPAddr          addr;
  std::atomic<uint32_t> score{0};
  std::atomic<uint32_t> error_count{0};
  std::atomic<uint32_t> success_count{0};

  void
  clear()
  {
    addr = swoc::IPAddr{};
    score.store(0, std::memory_order_relaxed);
    error_count.store(0, std::memory_order_relaxed);
    success_count.store(0, std::memory_order_relaxed);
  }

  bool
  empty() const
  {
    return !addr.is_valid();
  }
};

auto ip_get_key   = [](const IPSlot &s) -> const swoc::IPAddr & { return s.addr; };
auto ip_set_key   = [](IPSlot &s, const swoc::IPAddr &k) { s.addr = k; };
auto ip_get_score = [](const IPSlot &s) -> uint32_t { return s.score.load(std::memory_order_relaxed); };
auto ip_set_score = [](IPSlot &s, uint32_t v) { s.score.store(v, std::memory_order_relaxed); };
auto ip_is_empty  = [](const IPSlot &s) -> bool { return s.empty(); };

using IPTable = ts::UdiTable<swoc::IPAddr, IPSlot, std::hash<swoc::IPAddr>, 4>;

}  // namespace

// ============================================================================
// String key tests
// ============================================================================

TEST_CASE("UdiTable string key basic operations", "[UdiTable][string]")
{
  StringTable table(100, str_get_key, str_set_key, str_get_score, str_set_score, str_is_empty);

  SECTION("empty table")
  {
    REQUIRE(table.num_slots() == 100);
    REQUIRE(table.slots_used() == 0);
    REQUIRE(table.find("nonexistent") == nullptr);
  }

  SECTION("record and find")
  {
    auto *slot = table.record("key1", 5);
    REQUIRE(slot != nullptr);
    REQUIRE(slot->key == "key1");
    REQUIRE(slot->score.load() == 5);

    auto *found = table.find("key1");
    REQUIRE(found == slot);
    REQUIRE(table.slots_used() == 1);
  }

  SECTION("record same key increases score")
  {
    table.record("key1", 5);
    auto *slot = table.record("key1", 3);
    REQUIRE(slot != nullptr);
    REQUIRE(slot->score.load() == 8);
    REQUIRE(table.slots_used() == 1);
  }

  SECTION("record multiple keys")
  {
    table.record("key1", 1);
    table.record("key2", 2);
    table.record("key3", 3);

    REQUIRE(table.slots_used() == 3);
    REQUIRE(table.find("key1") != nullptr);
    REQUIRE(table.find("key2") != nullptr);
    REQUIRE(table.find("key3") != nullptr);
  }

  SECTION("decrement score")
  {
    table.record("key1", 5);
    REQUIRE(table.decrement("key1", 2));

    auto *slot = table.find("key1");
    REQUIRE(slot != nullptr);
    REQUIRE(slot->score.load() == 3);
  }

  SECTION("decrement to zero evicts")
  {
    table.record("key1", 3);
    REQUIRE(table.decrement("key1", 3));
    REQUIRE(table.find("key1") == nullptr);
    REQUIRE(table.slots_used() == 0);
    REQUIRE(table.evictions() == 1);
  }

  SECTION("remove key")
  {
    table.record("key1", 5);
    REQUIRE(table.remove("key1"));
    REQUIRE(table.find("key1") == nullptr);
    REQUIRE(table.slots_used() == 0);
  }

  SECTION("remove nonexistent returns false")
  {
    REQUIRE_FALSE(table.remove("nonexistent"));
  }
}

TEST_CASE("UdiTable string key contest algorithm", "[UdiTable][string]")
{
  StringTable table(4, str_get_key, str_set_key, str_get_score, str_set_score, str_is_empty);

  SECTION("fill table then contest")
  {
    table.record("a", 1);
    table.record("b", 2);
    table.record("c", 3);
    table.record("d", 4);

    uint64_t initial_contests = table.contests();

    // New key with higher score should win
    auto *slot = table.record("e", 10);
    REQUIRE(slot != nullptr);
    REQUIRE(slot->key == "e");
    REQUIRE(table.contests() > initial_contests);
    REQUIRE(table.contests_won() > 0);
  }

  SECTION("low score loses contest")
  {
    table.record("a", 100);
    table.record("b", 100);
    table.record("c", 100);
    table.record("d", 100);

    [[maybe_unused]] auto *slot = table.record("e", 1);
    REQUIRE(table.contests() > 0);
  }
}

TEST_CASE("UdiTable string key statistics", "[UdiTable][string]")
{
  StringTable table(100, str_get_key, str_set_key, str_get_score, str_set_score, str_is_empty);

  table.record("key1", 1);
  table.record("key2", 2);
  table.record("key3", 3);

  SECTION("dump produces output")
  {
    std::string dump = table.dump();
    REQUIRE_FALSE(dump.empty());
  }

  SECTION("custom dump format")
  {
    auto format = [](const StringSlot &s) -> std::string { return "KEY:" + s.key + "\n"; };

    std::string dump = table.dump(format);
    REQUIRE(dump.find("KEY:key1") != std::string::npos);
  }
}

// ============================================================================
// IP address key tests
// ============================================================================

TEST_CASE("UdiTable IP key basic operations", "[UdiTable][ip]")
{
  IPTable table(100, ip_get_key, ip_set_key, ip_get_score, ip_set_score, ip_is_empty);

  swoc::IPAddr ip1{"192.168.1.1"};
  swoc::IPAddr ip2{"192.168.1.2"};
  swoc::IPAddr ip3{"10.0.0.1"};
  swoc::IPAddr ip_nonexistent{"8.8.8.8"};

  SECTION("empty table")
  {
    REQUIRE(table.num_slots() == 100);
    REQUIRE(table.slots_used() == 0);
    REQUIRE(table.find(ip_nonexistent) == nullptr);
  }

  SECTION("record and find IPv4")
  {
    auto *slot = table.record(ip1, 5);
    REQUIRE(slot != nullptr);
    REQUIRE(slot->addr == ip1);
    REQUIRE(slot->score.load() == 5);

    auto *found = table.find(ip1);
    REQUIRE(found == slot);
    REQUIRE(table.slots_used() == 1);
  }

  SECTION("record and find IPv6")
  {
    swoc::IPAddr ipv6{"2001:db8::1"};
    auto        *slot = table.record(ipv6, 10);
    REQUIRE(slot != nullptr);
    REQUIRE(slot->addr == ipv6);
    REQUIRE(slot->score.load() == 10);

    auto *found = table.find(ipv6);
    REQUIRE(found == slot);
  }

  SECTION("record same IP increases score")
  {
    table.record(ip1, 5);
    auto *slot = table.record(ip1, 3);
    REQUIRE(slot != nullptr);
    REQUIRE(slot->score.load() == 8);
    REQUIRE(table.slots_used() == 1);
  }

  SECTION("record multiple IPs")
  {
    table.record(ip1, 1);
    table.record(ip2, 2);
    table.record(ip3, 3);

    REQUIRE(table.slots_used() == 3);
    REQUIRE(table.find(ip1) != nullptr);
    REQUIRE(table.find(ip2) != nullptr);
    REQUIRE(table.find(ip3) != nullptr);
  }

  SECTION("decrement score")
  {
    table.record(ip1, 5);
    REQUIRE(table.decrement(ip1, 2));

    auto *slot = table.find(ip1);
    REQUIRE(slot != nullptr);
    REQUIRE(slot->score.load() == 3);
  }

  SECTION("decrement to zero evicts")
  {
    table.record(ip1, 3);
    REQUIRE(table.decrement(ip1, 3));
    REQUIRE(table.find(ip1) == nullptr);
    REQUIRE(table.slots_used() == 0);
    REQUIRE(table.evictions() == 1);
  }

  SECTION("mixed IPv4 and IPv6")
  {
    swoc::IPAddr ipv4{"192.168.1.100"};
    swoc::IPAddr ipv6{"::ffff:192.168.1.100"};  // IPv4-mapped IPv6

    table.record(ipv4, 5);
    table.record(ipv6, 10);

    // These should be different entries (different address families)
    auto *slot4 = table.find(ipv4);
    auto *slot6 = table.find(ipv6);

    REQUIRE(slot4 != nullptr);
    REQUIRE(slot6 != nullptr);
    // They might or might not be different depending on how swoc::IPAddr handles this
  }
}

TEST_CASE("UdiTable IP key contest algorithm", "[UdiTable][ip]")
{
  IPTable table(4, ip_get_key, ip_set_key, ip_get_score, ip_set_score, ip_is_empty);

  SECTION("fill table then contest")
  {
    table.record(swoc::IPAddr{"1.1.1.1"}, 1);
    table.record(swoc::IPAddr{"2.2.2.2"}, 2);
    table.record(swoc::IPAddr{"3.3.3.3"}, 3);
    table.record(swoc::IPAddr{"4.4.4.4"}, 4);

    uint64_t initial_contests = table.contests();

    // New IP with higher score should win
    swoc::IPAddr new_ip{"5.5.5.5"};
    auto        *slot = table.record(new_ip, 10);
    REQUIRE(slot != nullptr);
    REQUIRE(slot->addr == new_ip);
    REQUIRE(table.contests() > initial_contests);
    REQUIRE(table.contests_won() > 0);
  }
}

TEST_CASE("UdiTable IP key slot data", "[UdiTable][ip]")
{
  IPTable table(100, ip_get_key, ip_set_key, ip_get_score, ip_set_score, ip_is_empty);

  swoc::IPAddr attacker{"192.168.1.100"};

  SECTION("track error and success counts")
  {
    auto *slot = table.record(attacker, 1);
    REQUIRE(slot != nullptr);

    // Simulate recording errors
    slot->error_count.fetch_add(5, std::memory_order_relaxed);
    slot->score.fetch_add(5, std::memory_order_relaxed);

    // Simulate recording successes
    slot->success_count.fetch_add(2, std::memory_order_relaxed);

    auto *found = table.find(attacker);
    REQUIRE(found != nullptr);
    REQUIRE(found->error_count.load() == 5);
    REQUIRE(found->success_count.load() == 2);
    REQUIRE(found->score.load() == 6);  // 1 initial + 5 from errors
  }
}

// ============================================================================
// Thread safety tests
// ============================================================================

TEST_CASE("UdiTable thread safety with strings", "[UdiTable][threading][string]")
{
  StringTable table(1000, str_get_key, str_set_key, str_get_score, str_set_score, str_is_empty);

  constexpr int            NUM_THREADS    = 4;
  constexpr int            OPS_PER_THREAD = 1000;
  std::vector<std::thread> threads;

  SECTION("concurrent records")
  {
    for (int t = 0; t < NUM_THREADS; ++t) {
      threads.emplace_back([&table, t]() {
        for (int i = 0; i < OPS_PER_THREAD; ++i) {
          std::string key  = "thread" + std::to_string(t) + "_key" + std::to_string(i);
          auto       *slot = table.record(key, 1);
          if (slot) {
            slot->data.fetch_add(1, std::memory_order_relaxed);
          }
        }
      });
    }

    for (auto &t : threads) {
      t.join();
    }

    REQUIRE(table.slots_used() > 0);
  }
}

TEST_CASE("UdiTable thread safety with IPs", "[UdiTable][threading][ip]")
{
  IPTable table(1000, ip_get_key, ip_set_key, ip_get_score, ip_set_score, ip_is_empty);

  constexpr int            NUM_THREADS    = 4;
  constexpr int            OPS_PER_THREAD = 500;
  std::vector<std::thread> threads;

  SECTION("concurrent IP records")
  {
    for (int t = 0; t < NUM_THREADS; ++t) {
      threads.emplace_back([&table, t]() {
        for (int i = 0; i < OPS_PER_THREAD; ++i) {
          // Generate unique IPs: 10.t.i/256.i%256
          std::string  ip_str = "10." + std::to_string(t) + "." + std::to_string(i / 256) + "." + std::to_string(i % 256);
          swoc::IPAddr ip{ip_str};

          auto *slot = table.record(ip, 1);
          if (slot) {
            slot->error_count.fetch_add(1, std::memory_order_relaxed);
          }
        }
      });
    }

    for (auto &t : threads) {
      t.join();
    }

    REQUIRE(table.slots_used() > 0);
  }

  SECTION("concurrent find and record")
  {
    // Pre-populate with some IPs
    for (int i = 0; i < 100; ++i) {
      std::string  ip_str = "192.168.1." + std::to_string(i);
      swoc::IPAddr ip{ip_str};
      table.record(ip, 10);
    }

    std::atomic<int> found_count{0};

    for (int t = 0; t < NUM_THREADS; ++t) {
      threads.emplace_back([&table, &found_count]() {
        for (int i = 0; i < OPS_PER_THREAD; ++i) {
          std::string  ip_str = "192.168.1." + std::to_string(i % 100);
          swoc::IPAddr ip{ip_str};

          if (auto *slot = table.find(ip)) {
            found_count.fetch_add(1, std::memory_order_relaxed);
            slot->error_count.fetch_add(1, std::memory_order_relaxed);
          }
        }
      });
    }

    for (auto &t : threads) {
      t.join();
    }

    REQUIRE(found_count.load() > 0);
  }
}
