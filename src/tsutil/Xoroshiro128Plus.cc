/** @file

  Xoroshiro128Plus PRNG implementation.

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

#include <random>

namespace ts
{

void
Xoroshiro128Plus::seed(uint64_t x)
{
  // Use two rounds of splitmix64 RNG to create the seed.
  auto splitmix = [](uint64_t &z) {
    z += 0x9e3779b97f4a7c15;
    z  = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z  = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return z ^ (z >> 31);
  };
  s_[0] = splitmix(x);
  s_[1] = splitmix(x);
}

void
Xoroshiro128Plus::randomize()
{
  std::random_device rd;
  s_[0] = (static_cast<uint64_t>(rd()) << 32) | rd();
  s_[1] = (static_cast<uint64_t>(rd()) << 32) | rd();
}

uint64_t
Xoroshiro128Plus::operator()()
{
  uint64_t const s0     = s_[0];
  uint64_t       s1     = s_[1];
  uint64_t const result = s0 + s1;

  s1    ^= s0;
  s_[0]  = rotl(s0, 24) ^ s1 ^ (s1 << 16);
  s_[1]  = rotl(s1, 37);

  return result;
}

uint32_t
Xoroshiro128Plus::rand32()
{
  if (have_cached_) {
    have_cached_ = false;
    return cached_;
  }
  uint64_t x   = (*this)();
  cached_      = static_cast<uint32_t>(x >> 32); // Use upper bits (better quality)
  have_cached_ = true;
  return static_cast<uint32_t>(x);
}

} // namespace ts
