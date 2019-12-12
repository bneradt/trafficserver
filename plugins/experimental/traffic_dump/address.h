/**
  A class to encapsulate network addresses.

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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>

/** An invalid address was provided. */
class InvalidAddress : public std::logic_error
{
public:
  /**
   * @param[in] message The message describing why the address was invalid.
   */
  InvalidAddress(const std::string &message) : std::logic_error(message) {}
};

/** Encapsulate an IP address.
 *
 * This class exposes a convient interface to compare addresses.
 */
class Address
{
public:
  /**
   * @param[in] family The address family (AF_INET or AF_INET6) of the provided
   * address.
   *
   * @param[in] address The string represention of an address.
   *
   * @throw InvalidAddress if the family was not AF_INET or AF_INET6 or if the
   * string did not represent a valid network address.
   */
  Address(int family, const std::string &address);

  /**
   * @param[in] address The address to store. This can be either a sockaddr_in
   * or sockaddr_in6.
   *
   * @throw InvalidAddress if the address's family was not AF_INET or AF_INET6.
   */
  Address(const sockaddr &address);

  bool operator==(const Address &other) const;
  bool operator!=(const Address &other) const;

private:
  /** The family (AF_INET or AF_INET6) associated with this address. */
  const int family_;

  /** One of the following two will be populated based upon family_. */
  in_addr ipv4_address_;
  in6_addr ipv6_address_;
};
