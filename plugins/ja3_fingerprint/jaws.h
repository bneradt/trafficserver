/** @file ja3_fingerprint.cc
 *
  JAWS algorithm for undoing permutations - header file.

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

#include <string>
#include <string_view>

namespace JAWS
{
/** Calculate a JAWS score.
 *
 * The JAWS algorithm by William Salusky of the Paranoids undoes permutations
 * of the cipher, extension, and elliptic curve lists sent in a TLS Client
 * Hello. A drawback of JA3 is that you can fool the hash by permuting the
 * order of these lists, but JAWS will generate the same hash for all
 * these permutations.
 *
 * The cipher, extension, and elliptic curve lists are sorted according
 * to a statically-ordered distinct set of values that functions as an anchor;
 * the order was determined by frequencies of values at the time of writing.
 * It converts incoming raw (unhashed) JA3 strings by hashing presented values
 * against an anchor-order binary bitfield. See the JAWS::anchor_order
 * namespace in jaws.cc for the set definitions. Values may be appended to the
 * sets, but the order and position of values already in the set can not be
 * changed without breaking compatability with existing data.
 *
 * Scores are returned in the format
 * "<ciphers_score>|<extensions_score>|<elliptic_curves_score>".
 *
 * Each of `ciphers_score`, `extensions_score`, and `elliptic_curves_score`
 * is in the format "<count>|<hash>".
 *
 * Example:
 * "1-2|1-400|1-1000000000" == JAWS::score("771,49172,10,16696,")
 *
 * @param ja3_string A raw (unhashed) JA3 string.
 * @return Returns the JAWS score string for the provided input.
 */
std::string score(std::string_view ja3_string);
} // end namespace JAWS
