/** @file ja3_fingerprint.cc
 *
  Implementation of the JAWS algorithm for undoing permutations.

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

#include "hex.h"
#include "jaws.h"

#include <algorithm>
#include <array>
#include <bitset>
#include <cstddef>
#include <iterator>
#include <stdexcept>
#include <utility>

#include "token_stream.h"

// In the following implementation, the term "JA3 part" is used to refer to
// one hypen delimited subsection of a raw JA3 string.
//
// For example, in the JA3 string "771,49172-29171,,,", the JA3 parts would be
// "771", "49172-29171", "", and "".
//
// The term "JA3 item" is used to refer to the individual elements within a
// JA3 part.
//
// For example, in the JA3 part "49172-29171", "49172" and "29171" are items.
//
//
// Similarly, the term "JAWS part" is used to refer to the JAWS encoding of
// the same information stored in a JA3 part. The only parts relevant to
// JAWS are the second, third, and fourth JA3 parts: the cipher suites,
// the TLS extensions, and the elliptic curves, respectively.
// Each JAWS part consists of the number of items in the JA3 part
// and a hexadecimal hash, separated by a '-'.
//
// For example, the JAWS part "1:2" means that there was only one item in the
// JA3 part, and it corresponds to the item with ID #0x2.

using namespace std::literals;

namespace
{
constexpr char JA3_part_item_delimiter{'-'};
constexpr char JA3_part_delimiter{','};
constexpr char JAWS_part_delimiter{'|'};
// The '-' symbol is used as a delimiter because it is unlikely to intefere
// with parsing JSON structures.
constexpr char JAWS_part_size_delimiter{'-'};

// The order of the anchor arrays is defined by the reference implementation
// and happened to be the order of most frequent appearance at the time of
// specification. Each one begins with a "_" which is a dummy placeholder;
// index 0 is used to represent all values not found in the rest of the
// array.
namespace anchor_order
{
  constexpr std::array<std::string_view, 130> cipher_suites{
    "_"sv,     "49172"sv, "49171"sv, "49196"sv, "49195"sv, "53"sv,    "47"sv,    "49200"sv, "49199"sv, "157"sv,   "156"sv,
    "49162"sv, "49161"sv, "49191"sv, "49188"sv, "49187"sv, "52393"sv, "52392"sv, "49192"sv, "61"sv,    "60"sv,    "4866"sv,
    "4865"sv,  "159"sv,   "158"sv,   "4867"sv,  "10"sv,    "56"sv,    "50"sv,    "255"sv,   "57"sv,    "51"sv,    "64"sv,
    "106"sv,   "107"sv,   "103"sv,   "52394"sv, "163"sv,   "162"sv,   "19"sv,    "49202"sv, "49201"sv, "49198"sv, "49197"sv,
    "49194"sv, "49193"sv, "49190"sv, "49189"sv, "49167"sv, "49166"sv, "49157"sv, "49156"sv, "49170"sv, "5"sv,     "49160"sv,
    "49327"sv, "49326"sv, "49325"sv, "49324"sv, "49315"sv, "49314"sv, "49313"sv, "49312"sv, "49311"sv, "49310"sv, "49309"sv,
    "49308"sv, "4"sv,     "22"sv,    "49169"sv, "69"sv,    "65"sv,    "49165"sv, "49159"sv, "49155"sv, "136"sv,   "132"sv,
    "68"sv,    "154"sv,   "153"sv,   "150"sv,   "135"sv,   "67"sv,    "66"sv,    "63"sv,    "62"sv,    "55"sv,    "54"sv,
    "49249"sv, "49248"sv, "49245"sv, "49244"sv, "49239"sv, "49238"sv, "49235"sv, "49234"sv, "49233"sv, "49232"sv, "49"sv,
    "48"sv,    "165"sv,   "164"sv,   "161"sv,   "160"sv,   "152"sv,   "151"sv,   "134"sv,   "133"sv,   "105"sv,   "104"sv,
    "7"sv,     "196"sv,   "192"sv,   "190"sv,   "186"sv,   "16"sv,    "13"sv,    "9"sv,     "65413"sv, "49271"sv, "49270"sv,
    "49267"sv, "49266"sv, "49164"sv, "49154"sv, "4868"sv,  "21"sv,    "195"sv,   "189"sv,   "129"sv};
  constexpr std::array<std::string_view, 46> extensions{
    "_"sv,     "23"sv,  "24"sv, "25"sv, "22"sv,    "9"sv,  "14"sv, "13"sv,  "12"sv,  "11"sv,  "10"sv,  "21"sv,
    "19"sv,    "20"sv,  "18"sv, "1"sv,  "16"sv,    "17"sv, "15"sv, "8"sv,   "7"sv,   "6"sv,   "5"sv,   "4"sv,
    "3"sv,     "2"sv,   "29"sv, "30"sv, "26"sv,    "28"sv, "27"sv, "257"sv, "256"sv, "260"sv, "259"sv, "258"sv,
    "16696"sv, "249"sv, "0"sv,  "35"sv, "65281"sv, "50"sv, "43"sv, "51"sv,  "45"sv,  "41"sv};
  constexpr std::array<std::string_view, 37> elliptic_curves{
    "_"sv,   "23"sv,  "24"sv, "25"sv, "29"sv, "22"sv, "30"sv, "9"sv,   "14"sv,  "13"sv,  "12"sv,   "11"sv, "10"sv,
    "257"sv, "256"sv, "28"sv, "27"sv, "26"sv, "21"sv, "19"sv, "16"sv,  "8"sv,   "7"sv,   "6"sv,    "5"sv,  "4"sv,
    "3"sv,   "20"sv,  "2"sv,  "18"sv, "17"sv, "15"sv, "1"sv,  "260"sv, "259"sv, "258"sv, "16696"sv};

  // Anchor indexes are 1-based; a return value of 0 indicates not found.
  template <typename T>
  std::ptrdiff_t
  find_anchor_index(T const &anchor_arr, std::string_view sv)
  {
    // The first element of an anchor array is a dummy placeholder so we skip it.
    if (auto const it{std::find(anchor_arr.begin() + 1, anchor_arr.end(), sv)}; it != anchor_arr.end()) {
      return std::distance(anchor_arr.begin(), it);
    } else {
      return std::ptrdiff_t{0};
    }
  }

} // end namespace anchor_order

} // end anonymous namespace

using namespace anchor_order;

/**
 * Convert a JA3 part to its JAWS bitfield representation.
 *
 * For each item in @a JA3_part, the bit corresponding to its index in
 * @a anchor_arr will be set.
 *
 * @param anchor_arr: An array specifying an anchor order for the possible
 *  items in @a JA3_part.
 * @param JA3_part A hypen delimited subsection of a JA3 string.
 * @return Returns a bitset which each set bit corresponding to the index of
 *  one of the JA3 items in the anchor-order array.
 */
template <std::size_t N>
std::bitset<N>
reduce_JA3_part_to_bitfield(std::array<std::string_view, N> const &anchor_arr, std::string_view JA3_part)
{
  std::bitset<N> result;
  TokenStream    tokens{JA3_part, JA3_part_item_delimiter};
  while (!tokens.empty()) {
    // When find_anchor_index() returns a 0 for 'not found', we set the first
    // bit to indicate an anomaly - a value not in the anchor order.
    result.set(find_anchor_index(anchor_arr, tokens.consume()));
  }
  return result;
}

/** Convert a JA3 part to a JAWS part.
 *
 * The part is converted to a bitfield and then hex-encoded.
 *
 * @param anchor_arr An array specifying an anchor order for the possible
 *  items in @a JA3_part.
 * @param JA3_part A hyphen delimited subsection of a JA3 string.
 * @return Returns a string of hexadecimal characters, with no leading zeroes.
 * @see reduce_JA3_part_to_bitfield
 */
template <std::size_t N>
static std::string
encode_score(std::array<std::string_view, N> const &anchor_arr, std::string_view JA3_part)
{
  auto const  bits{reduce_JA3_part_to_bitfield(anchor_arr, JA3_part)};
  std::string result{std::to_string(bits.count())};
  result.push_back(JAWS_part_size_delimiter);
  result.append(JAWS::hex::hexify_bitset(bits));
  return result;
}

/**
 * Represents the three parts of a JAWS score; each of these are hex-encoded
 * strings.
 *
 * @see encode_score
 */
struct JAWSParts {
  std::string ciphers_score;
  std::string extensions_score;
  std::string elliptic_curves_score;
};

static JAWSParts   get_JAWS_parts(std::string_view JA3_string);
static std::string get_ciphers_score(std::string_view ciphers_string);
static std::string get_extensions_score(std::string_view extensions_string);
static std::string get_elliptic_curves_score(std::string_view elliptic_curves_string);
static std::string join_JAWS_parts(JAWSParts const &parts, char delimiter);

std::string
JAWS::score(std::string_view JA3_string)
{
  return join_JAWS_parts(get_JAWS_parts(JA3_string), JAWS_part_delimiter);
}

static JAWSParts
get_JAWS_parts(std::string_view JA3_string)
{
  TokenStream tokens{JA3_string, JA3_part_delimiter};
  // The first JA3 token is the TLS version.
  tokens.skip();
  return JAWSParts{std::move(get_ciphers_score(tokens.consume())), std::move(get_extensions_score(tokens.consume())),
                   std::move(get_elliptic_curves_score(tokens.consume()))};
}

static std::string
get_ciphers_score(std::string_view ciphers_string)
{
  return encode_score(cipher_suites, ciphers_string);
}

static std::string
get_extensions_score(std::string_view extensions_string)
{
  return encode_score(extensions, extensions_string);
}

static std::string
get_elliptic_curves_score(std::string_view elliptic_curves_string)
{
  return encode_score(elliptic_curves, elliptic_curves_string);
}

/**
 * Join the parts of a JAWS score together.
 *
 * The parts are joined in the order: ciphers, extensions, elliptic curves.
 * The '|' character is used to separate the three parts.
 */
static std::string
join_JAWS_parts(JAWSParts const &parts, char delimiter)
{
  std::string result;
  result.append(parts.ciphers_score);
  result.push_back(delimiter);
  result.append(parts.extensions_score);
  result.push_back(delimiter);
  result.append(parts.elliptic_curves_score);
  return result;
}
