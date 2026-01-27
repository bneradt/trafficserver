/** @file

  Fast non-cryptographic PRNG using xoroshiro128+ algorithm.

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

#include <cstdint>

namespace ts
{

/** Fast non-cryptographic PRNG using xoroshiro128+ algorithm.
 *
 * Based on: http://xoroshiro.di.unimi.it/xoroshiro128plus.c
 *
 * This is a very fast 64-bit RNG with a period of 2^128 - 1. It's suitable for
 * **NON-CRYPTOGRAPHIC** purposes like eviction candidate selection.
 *
 * Note: The 4 lower bits have a shorter cycle than the rest of the bits.
 * If you need fewer bits and want the best result possible, shift instead
 * of masking. The rand32() method uses the upper 32 bits for this reason.
 *
 * Thread Safety: NOT thread-safe. Each thread or table should have its own instance.
 */
class Xoroshiro128Plus
{
public:
  using result_type = uint64_t;

  /** Construct with random seed from std::random_device.
   */
  Xoroshiro128Plus() { randomize(); }

  /** Construct with explicit seed.
   *
   * @param[in] seed The seed value.
   */
  explicit Xoroshiro128Plus(uint64_t seed) { this->seed(seed); }

  /** Seed using splitmix64 (as recommended by xoroshiro authors).
   *
   * Two rounds of splitmix64 are used to create the 128-bit state from
   * the 64-bit seed, as suggested by the algorithm authors.
   *
   * @param[in] x The seed value.
   */
  void seed(uint64_t x);

  /** Seed from std::random_device for better entropy.
   */
  void randomize();

  /** Generate 64-bit random value.
   *
   * @return A random 64-bit value.
   */
  uint64_t operator()();

  /** Generate 32-bit random value.
   *
   * This is efficient: it caches half of each 64-bit result for the next call.
   *
   * @return A random 32-bit value.
   */
  uint32_t rand32();

  // C++11 UniformRandomBitGenerator requirements.
  static constexpr result_type
  min()
  {
    return 0;
  }
  static constexpr result_type
  max()
  {
    return UINT64_MAX;
  }

private:
  static uint64_t
  rotl(uint64_t x, int k)
  {
    return (x << k) | (x >> (64 - k));
  }

  uint64_t s_[2];
  uint32_t cached_{0};
  bool     have_cached_{false};
};

} // namespace ts
