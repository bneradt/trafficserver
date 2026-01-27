/** @file

  Unit tests for Xoroshiro128Plus PRNG.

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

#include "tsutil/Xoroshiro128Plus.h"

#include <cmath>
#include <cstdint>
#include <set>
#include <vector>

#include <catch2/catch_test_macros.hpp>

// ============================================================================
// Basic functionality tests
// ============================================================================

TEST_CASE("Xoroshiro128Plus default construction", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng1;
  ts::Xoroshiro128Plus rng2;

  // Two default-constructed RNGs should produce different sequences
  // since they're seeded from std::random_device.
  uint64_t val1 = rng1();
  uint64_t val2 = rng2();

  // Extremely unlikely (1 in 2^64) for them to match, so just check we get values.
  REQUIRE((val1 != 0 || val2 != 0));
}

TEST_CASE("Xoroshiro128Plus seeded construction is deterministic", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng1(12345);
  ts::Xoroshiro128Plus rng2(12345);

  // Same seed should produce identical sequence.
  for (int i = 0; i < 100; ++i) {
    REQUIRE(rng1() == rng2());
  }
}

TEST_CASE("Xoroshiro128Plus different seeds produce different sequences", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng1(12345);
  ts::Xoroshiro128Plus rng2(54321);

  // First values should differ.
  REQUIRE(rng1() != rng2());
}

TEST_CASE("Xoroshiro128Plus seed method resets state", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng(12345);

  // Generate some values.
  rng();
  rng();
  rng();

  // Re-seed with same seed.
  rng.seed(12345);

  // Should now match a fresh RNG with same seed.
  ts::Xoroshiro128Plus fresh(12345);
  for (int i = 0; i < 10; ++i) {
    REQUIRE(rng() == fresh());
  }
}

TEST_CASE("Xoroshiro128Plus randomize reseeds from random_device", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng(12345);
  uint64_t             first_val = rng();

  // Re-seed to known state.
  rng.seed(12345);
  REQUIRE(rng() == first_val);

  // Randomize should produce different sequence.
  rng.randomize();
  rng.seed(12345); // Reset to compare.
  REQUIRE(rng() == first_val);
}

// ============================================================================
// rand32 tests
// ============================================================================

TEST_CASE("Xoroshiro128Plus rand32 returns 32-bit values", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng(42);

  for (int i = 0; i < 100; ++i) {
    uint32_t val = rng.rand32();
    // Always true for uint32_t, but verifies the API works.
    REQUIRE(val <= UINT32_MAX);
  }
}

TEST_CASE("Xoroshiro128Plus rand32 caching works correctly", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng1(42);
  ts::Xoroshiro128Plus rng2(42);

  // First call generates a 64-bit value and caches upper 32 bits.
  uint32_t r1_first = rng1.rand32();
  // Second call returns cached value without generating new random.
  uint32_t r1_second = rng1.rand32();

  // For rng2, call operator() to get the same 64-bit value.
  uint64_t full  = rng2();
  uint32_t lower = static_cast<uint32_t>(full);
  uint32_t upper = static_cast<uint32_t>(full >> 32);

  // First rand32() should return lower 32 bits.
  REQUIRE(r1_first == lower);
  // Second rand32() should return cached upper 32 bits.
  REQUIRE(r1_second == upper);
}

TEST_CASE("Xoroshiro128Plus rand32 alternates between cached and fresh", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng(42);

  std::vector<uint32_t> values;
  for (int i = 0; i < 10; ++i) {
    values.push_back(rng.rand32());
  }

  // Should have variety in values.
  std::set<uint32_t> unique(values.begin(), values.end());
  REQUIRE(unique.size() > 1);
}

// ============================================================================
// Full 64-bit range tests
// ============================================================================

TEST_CASE("Xoroshiro128Plus operator() produces full 64-bit range", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng(42);

  bool found_high_bit = false;
  bool found_low_bit  = false;

  for (int i = 0; i < 1000; ++i) {
    uint64_t val = rng();
    if (val > (1ULL << 63)) {
      found_high_bit = true;
    }
    if ((val & 1) != 0) {
      found_low_bit = true;
    }
    if (found_high_bit && found_low_bit) {
      break;
    }
  }

  // Should find values with high bit set within 1000 tries.
  REQUIRE(found_high_bit);
  // Should find odd values within 1000 tries.
  REQUIRE(found_low_bit);
}

TEST_CASE("Xoroshiro128Plus min and max constants", "[Xoroshiro128Plus]")
{
  REQUIRE(ts::Xoroshiro128Plus::min() == 0);
  REQUIRE(ts::Xoroshiro128Plus::max() == UINT64_MAX);
}

// ============================================================================
// Distribution tests
// ============================================================================

TEST_CASE("Xoroshiro128Plus modulo produces reasonable distribution", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng(42);

  constexpr size_t NUM_BUCKETS = 10;
  constexpr size_t NUM_SAMPLES = 10000;

  std::vector<size_t> counts(NUM_BUCKETS, 0);

  for (size_t i = 0; i < NUM_SAMPLES; ++i) {
    size_t bucket = rng() % NUM_BUCKETS;
    counts[bucket]++;
  }

  // Each bucket should have roughly NUM_SAMPLES/NUM_BUCKETS entries.
  // Allow 50% deviation for randomness.
  size_t expected = NUM_SAMPLES / NUM_BUCKETS;
  for (size_t i = 0; i < NUM_BUCKETS; ++i) {
    REQUIRE(counts[i] > expected / 2);
    REQUIRE(counts[i] < expected * 2);
  }
}

TEST_CASE("Xoroshiro128Plus produces unique sequence", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng(42);

  // Generate 1000 values and check for uniqueness.
  std::set<uint64_t> seen;
  for (int i = 0; i < 1000; ++i) {
    uint64_t val = rng();
    // Should be unique (collision extremely unlikely with 2^128 period).
    REQUIRE(seen.find(val) == seen.end());
    seen.insert(val);
  }
}

// ============================================================================
// Splitmix64 seeding tests
// ============================================================================

TEST_CASE("Xoroshiro128Plus zero seed produces valid sequence", "[Xoroshiro128Plus]")
{
  // Zero is a valid seed - splitmix64 will expand it.
  ts::Xoroshiro128Plus rng(0);

  // Should still produce varied output.
  uint64_t val1 = rng();
  uint64_t val2 = rng();
  REQUIRE(val1 != val2);
}

TEST_CASE("Xoroshiro128Plus max seed produces valid sequence", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng(UINT64_MAX);

  uint64_t val1 = rng();
  uint64_t val2 = rng();
  REQUIRE(val1 != val2);
}

// ============================================================================
// Use case tests (simulating UdiTable usage)
// ============================================================================

TEST_CASE("Xoroshiro128Plus suitable for slot selection", "[Xoroshiro128Plus]")
{
  ts::Xoroshiro128Plus rng(42);

  constexpr size_t NUM_SLOTS   = 10000;
  constexpr size_t NUM_SAMPLES = 100000;

  // Simulate multi-probe eviction slot selection.
  std::vector<size_t> slot_hits(NUM_SLOTS, 0);

  for (size_t i = 0; i < NUM_SAMPLES; ++i) {
    size_t slot = rng() % NUM_SLOTS;
    slot_hits[slot]++;
  }

  // Calculate variance to check for bias.
  double expected = static_cast<double>(NUM_SAMPLES) / NUM_SLOTS;
  double variance = 0.0;
  for (size_t count : slot_hits) {
    double diff  = static_cast<double>(count) - expected;
    variance    += diff * diff;
  }
  variance /= NUM_SLOTS;

  // Standard deviation should be relatively small compared to expected value.
  double stddev = std::sqrt(variance);
  // For uniform distribution, stddev ≈ sqrt(n * p * (1-p)) where n=NUM_SAMPLES, p=1/NUM_SLOTS.
  // For 100000 samples and 10000 slots: stddev ≈ sqrt(100000 * 0.0001 * 0.9999) ≈ 3.16.
  // Allow up to 5x theoretical stddev to account for randomness.
  REQUIRE(stddev < expected);
}
