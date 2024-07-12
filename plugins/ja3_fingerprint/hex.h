/** @file ja3_fingerprint.cc
 *
  Bitset to hex conversions for JAWS.

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

#include <algorithm>
#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace JAWS::hex
{
inline constexpr std::array<char, 16> lowercase_hex_digits{'0', '1', '2', '3', '4', '5', '6', '7',
                                                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
inline constexpr std::size_t          bitset_npos = std::numeric_limits<std::size_t>::max();

template <std::size_t N>
std::size_t
rfind_set_bit(std::bitset<N> const &bits)
{
  std::size_t i{N - 1};
  while (i > std::size_t{0} && !bits.test(i)) {
    --i;
  }
  if (i == 0 && !bits.test(i)) {
    return bitset_npos;
  } else {
    return i + 1;
  }
}

template <std::size_t N>
std::string
hexify_bitset_impl(std::bitset<N> const &bits, std::size_t highest_set_bit)
{
  std::string result;
  for (std::size_t i{0}; i < highest_set_bit;) {
    std::uint_fast8_t val{0};
    for (std::size_t j{0}; j < 4 && i < highest_set_bit; ++j, ++i) {
      val |= bits[i] << j;
    }
    result.insert(0, 1, lowercase_hex_digits[val]);
  }
  return result;
}

/** Convert a std::bitset into a lowercase hexadecimal string.
 *
 * @param bits: A bitset of any size.
 * @return Returns the hexadecimal string representing the bits in the input.
 */
template <std::size_t N>
std::string
hexify_bitset(std::bitset<N> const &bits)
{
  if (std::size_t const highest_set_bit{rfind_set_bit(bits)}; highest_set_bit != bitset_npos) {
    return hexify_bitset_impl(bits, highest_set_bit);
  } else {
    return "0";
  }
}

} // namespace JAWS::hex
