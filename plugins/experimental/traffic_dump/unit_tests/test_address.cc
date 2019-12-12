/*
  Verify correct Address behavior.

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

#include <sys/un.h>
#include "address.h"
#include "catch.hpp"

TEST_CASE("Verify construction from a string", "[Address]")
{
  SECTION("Invalid family for string constructor throws an exception")
  {
    CHECK_THROWS_AS(Address(AF_UNIX, "this is not an ipv4 address"), InvalidAddress);
  }

  SECTION("Invalid IPv4 string throws an exception")
  {
    CHECK_THROWS_AS(Address(AF_INET, "this is not an ipv4 address"), InvalidAddress);
  }

  SECTION("A valid IPv4 string does not throw an exception") { CHECK_NOTHROW(Address(AF_INET, "127.0.0.1")); }
}

TEST_CASE("Verify address comparison", "[Address]")
{
  SECTION("IPv4 Addresses that are equal compare equal")
  {
    Address a(AF_INET, "1.2.3.4");
    Address b(AF_INET, "1.2.3.4");
    CHECK(a == b);
    CHECK_FALSE(a != b);
  }

  SECTION("IPv4 Addresses that are not equal compare not equal")
  {
    Address a(AF_INET, "1.2.3.4");
    Address b(AF_INET, "5.6.7.8");
    CHECK_FALSE(a == b);
    CHECK(a != b);
  }

  SECTION("IPv6 Addresses that are equal compare equal")
  {
    Address a(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:1234");
    Address b(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:1234");
    CHECK(a == b);
    CHECK_FALSE(a != b);
  }

  SECTION("IPv6 Addresses that are not equal compare not equal")
  {
    Address a(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:1234");
    Address b(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:5678");
    CHECK_FALSE(a == b);
    CHECK(a != b);
  }
}

TEST_CASE("Verify construction from a sockaddr", "[Address]")
{
  SECTION("An invalid family for the sockaddr constructor throws an exception")
  {
    sockaddr_un address;
    address.sun_family = AF_LOCAL;
    CHECK_THROWS_AS(Address(*(sockaddr *)&address), InvalidAddress);
  }

  SECTION("A valid Address can be constructed from a sockadr_in")
  {
    sockaddr_in address;
    address.sin_family          = AF_INET;
    address.sin_port            = htons(3490); // The port value is arbitrary.
    constexpr auto *ipv4_string = "63.161.169.137";
    inet_pton(AF_INET, ipv4_string, &address.sin_addr);

    CHECK_NOTHROW([address]() {
      Address address_from_socket(*(sockaddr *)&address);
      Address address_from_string(AF_INET, ipv4_string);
      CHECK(address_from_socket == address_from_string);
    });
  }

  SECTION("A valid Address can be constructed from a sockadr_in6")
  {
    struct sockaddr_in6 address;
    address.sin6_family         = AF_INET6;
    address.sin6_flowinfo       = 0;
    address.sin6_port           = htons(23); // The port value is arbitrary.
    constexpr auto *ipv6_string = "2001:0db8:85a3:0000:0000:8a2e:0370:1234";
    inet_pton(AF_INET6, ipv6_string, &address.sin6_addr);

    CHECK_NOTHROW([address]() {
      Address address_from_socket(*(sockaddr *)&address);
      Address address_from_string(AF_INET6, ipv6_string);
      CHECK(address_from_socket == address_from_string);
    });
  }
}
