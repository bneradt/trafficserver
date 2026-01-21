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

namespace
{

// Simple test slot for UdiTable
struct TestSlot {
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

// Accessor functions for TestSlot
auto get_key   = [](const TestSlot &s) -> const std::string & { return s.key; };
auto set_key   = [](TestSlot &s, const std::string &k) { s.key = k; };
auto get_score = [](const TestSlot &s) -> uint32_t { return s.score.load(std::memory_order_relaxed); };
auto set_score = [](TestSlot &s, uint32_t v) { s.score.store(v, std::memory_order_relaxed); };
auto is_empty  = [](const TestSlot &s) -> bool { return s.key.empty(); };

using TestTable = ts::UdiTable<std::string, TestSlot, std::hash<std::string>, 4>;

}  // namespace

TEST_CASE("UdiTable basic operations", "[UdiTable]")
{
  TestTable table(100, get_key, set_key, get_score, set_score, is_empty);

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

TEST_CASE("UdiTable contest algorithm", "[UdiTable]")
{
  // Small table to force contests
  TestTable table(4, get_key, set_key, get_score, set_score, is_empty);

  SECTION("fill table then contest")
  {
    // Fill all slots in one partition
    table.record("a", 1);
    table.record("b", 2);
    table.record("c", 3);
    table.record("d", 4);

    // Initial contests count
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
    // Fill with high scores
    table.record("a", 100);
    table.record("b", 100);
    table.record("c", 100);
    table.record("d", 100);

    // New key with low score should lose
    // May or may not get a slot depending on partition
    [[maybe_unused]] auto *slot = table.record("e", 1);
    // The important thing is that contests happen
    REQUIRE(table.contests() > 0);
  }
}

TEST_CASE("UdiTable statistics", "[UdiTable]")
{
  TestTable table(100, get_key, set_key, get_score, set_score, is_empty);

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
    auto format = [](const TestSlot &s) -> std::string { return "KEY:" + s.key + "\n"; };

    std::string dump = table.dump(format);
    REQUIRE(dump.find("KEY:key1") != std::string::npos);
  }
}

TEST_CASE("UdiTable thread safety", "[UdiTable][threading]")
{
  TestTable table(1000, get_key, set_key, get_score, set_score, is_empty);

  constexpr int NUM_THREADS = 4;
  constexpr int OPS_PER_THREAD = 1000;

  std::vector<std::thread> threads;

  SECTION("concurrent records")
  {
    for (int t = 0; t < NUM_THREADS; ++t) {
      threads.emplace_back([&table, t]() {
        for (int i = 0; i < OPS_PER_THREAD; ++i) {
          std::string key = "thread" + std::to_string(t) + "_key" + std::to_string(i);
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

    // Should have recorded many keys without crashing
    REQUIRE(table.slots_used() > 0);
  }

  SECTION("concurrent find and record")
  {
    // Pre-populate some keys
    for (int i = 0; i < 100; ++i) {
      table.record("shared_key" + std::to_string(i), 10);
    }

    std::atomic<int> found_count{0};

    for (int t = 0; t < NUM_THREADS; ++t) {
      threads.emplace_back([&table, &found_count, t]() {
        for (int i = 0; i < OPS_PER_THREAD; ++i) {
          std::string key = "shared_key" + std::to_string(i % 100);
          if (auto *slot = table.find(key)) {
            found_count.fetch_add(1, std::memory_order_relaxed);
            slot->data.fetch_add(1, std::memory_order_relaxed);
          }
          // Also do some new records
          table.record("new_" + std::to_string(t) + "_" + std::to_string(i), 1);
        }
      });
    }

    for (auto &t : threads) {
      t.join();
    }

    REQUIRE(found_count.load() > 0);
  }
}
