/**
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

#include <cstring>
#include <sstream>
#include "address.h"

Address::Address(int family, const std::string &address) : family_(family)
{
  int ret = 0;
  switch (family_) {
  case AF_INET:
    ret = inet_pton(family_, address.c_str(), &ipv4_address_);
    break;
  case AF_INET6:
    ret = inet_pton(family_, address.c_str(), &ipv6_address_);
    break;
  default: {
    std::ostringstream os;
    os << "Unrecognized address family: " << family;
    throw InvalidAddress(os.str());
  }
  }
  if (ret == 0) {
    std::ostringstream os;
    os << "Unrecognized network address: " << address;
    throw InvalidAddress(os.str());
  }
}

Address::Address(const sockaddr &address) : family_(address.sa_family)
{
  switch (family_) {
  case AF_INET: {
    const auto *addr     = reinterpret_cast<const sockaddr_in *>(&address);
    ipv4_address_.s_addr = addr->sin_addr.s_addr;
    break;
  }
  case AF_INET6: {
    const auto *addr = reinterpret_cast<const sockaddr_in6 *>(&address);
    memcpy(&ipv6_address_, &addr->sin6_addr, sizeof(ipv6_address_));
    break;
  }
  default: {
    std::ostringstream os;
    os << "Unrecognized address family: " << family_;
    throw InvalidAddress(os.str());
  }
  }
}

bool
Address::operator==(const Address &other) const
{
  if (family_ != other.family_) {
    return false;
  }
  switch (family_) {
  case AF_INET:
    return ipv4_address_.s_addr == other.ipv4_address_.s_addr;
  case AF_INET6:
    return memcmp(&ipv6_address_, &other.ipv6_address_, sizeof(ipv6_address_)) == 0;
  }
  return false;
}

bool
Address::operator!=(const Address &other) const
{
  return !(*this == other);
}
