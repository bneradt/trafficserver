/** @file

  A custom, internal type for an IP category.

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

#include <cstddef>
#include <functional>
#include <optional>
#include <sys/socket.h>
#include <unordered_set>

/** A custom type representing an IP Category. */
class IPCategory
{
public:
  IPCategory() = default;
  explicit IPCategory(int value) : value_(value) {}

  /// Explicit conversion function to int.
  explicit
  operator int() const
  {
    return value_;
  }

  /// Define equality operator.
  bool
  operator==(IPCategory const &rhs) const
  {
    return value_ == rhs.value_;
  }

private:
  /// The underlying IP Category value.
  int value_;
};

namespace std
{

// Define hash function for IPCategory. This is to satisfy std::unordered_set.
template <> struct hash<IPCategory> {
  size_t
  operator()(IPCategory const &ip_category) const
  {
    return hash<int>()(static_cast<int>(ip_category));
  }
};

} // namespace std

using Categories_t = std::unordered_set<IPCategory>;

/** Retrieve the categories for the given IP.
 *
 * This is a helper function for the various VConnection::get_ip_categories
 * implementations that asssumes that @a categories has the cached categories if
 * the optional is not empty. Otherwise it dispatches to the
 * TS_EVENT_CONNECTION_IP_CATEGORY handlers to populate categories with those
 * appropriate for @a addr.
 *
 * @param[in] addr The IP address to get the categories for.
 * @param[in,out] categories The optional to populate with the categories.
 *
 * @return @c true if the categories were populated, @c false if an error was
 * encountered.
 */
bool populate_ip_categories(sockaddr const &addr, std::optional<Categories_t> &categories);
