/** @file

  Demonstrate a TS_CONNECTION_IP_CATEGORY_HOOK plugin.

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

/** A plugin that demnstrates implementing ACME_INTERNAL, ACME_EXTERNAL, and
 * ACME_ALL IP categories.
 *
 *
 *   Usage:
 *     # Place the following in plugin.config:
 *     ip_category.so
 */

#include <string>
#include <string_view>
#include <sys/socket.h>

#include "swoc/BufferWriter.h"
#include "swoc/IPAddr.h"
#include "swoc/IPRange.h"
#include "ts/apidefs.h"
#include "ts/ts.h"

namespace
{

std::string const PLUGIN_NAME = "ip_category";
DbgCtl dbg_ctl{"ip_category"};

enum Category {
  ALL = 1,       // Literaly all addresses.
  ACME_INTERNAL, // ACME's internal network (work stations, printers, etc.).
  ACME_EXTERNAL, // ACME's external network (web servers, VPN gateways, etc.).
  ACME_ALL,      // All ACME addresses.
};

std::unordered_map<std::string, int> const global_category_map = {
  {"ALL",           ALL          }, // Literaly all addresses.
  {"ACME_INTERNAL", ACME_INTERNAL}, // ACME's internal network (work stations, printers, etc.).
  {"ACME_EXTERNAL", ACME_EXTERNAL}, // ACME's external network (web servers, VPN gateways, etc.).
  {"ACME_ALL",      ACME_ALL     }, // All ACME addresses.
};

swoc::IPSpace<int> global_internal_space;
swoc::IPSpace<int> global_external_space;

/** Return the IP cagories associated with the given address.
 *
 * @param addr The address to check.
 * @return The categories associated with the address.
 */
std::unordered_set<int>
get_ip_categories(sockaddr const &addr)
{
  std::unordered_set<int> categories;
  // The following implementation provides a simple stub for this example. In a
  // real environment, this function could perform a library call to a database,
  // parse a configuration file, or the like.
  swoc::IPAddr ip_addr{&addr};
  if (global_internal_space.find(ip_addr) != global_internal_space.end()) {
    categories.emplace(ACME_INTERNAL);
    categories.emplace(ACME_ALL);
  } else if (global_external_space.find(ip_addr) != global_external_space.end()) {
    categories.emplace(ACME_EXTERNAL);
    categories.emplace(ACME_ALL);
  }
  categories.emplace(ALL);
  return categories;
}

void
handle_ip_category(TSHttpIpAllowInfo infop)
{
  sockaddr address;
  TSHttpIpAllowInfoAddrGet(infop, address);

  std::unordered_set<int> categories = get_ip_categories(address);
  TSHttpIpAllowInfoCategoriesSet(infop, categories);

  swoc::LocalBufferWriter<500> w;
  w.print("Address {} is in categories: {}", swoc::IPAddr{&address}, categories);
  Dbg(dbg_ctl, "%s", w.data());
}

int
ip_category_callback(TSCont contp, TSEvent event, void *edata)
{
  switch (event) {
  case tsapi::c::TS_EVENT_CONNECTION_IP_CATEGORY: {
    TSHttpIpAllowInfo infop = static_cast<TSHttpIpAllowInfo>(edata);
    handle_ip_category(infop);
    break;
  }

  default:
    TSError("[%s] Unknown event %d", PLUGIN_NAME.c_str(), event);
    break;
  }

  return TS_SUCCESS;
}

/** Populate our relevant IP spaces with their associated IP ranges. */
void
populate_ip_spaces()
{
  swoc::IPRange internal_range{"172.27.0.0/16"};
  global_internal_space.mark(internal_range, 1);

  swoc::IPRange external_range{"10.1.0.0/24"};
  global_external_space.mark(external_range, 1);
}

} // anonymous namespace

void
TSPluginInit(int argc, const char *argv[])
{
  // Inform the core what the categories are.
  TSHttpIpAllowTableSet(global_category_map);

  populate_ip_spaces();

  // Populate the callback for dynamic category queries from the core.
  auto cont = TSContCreate(ip_category_callback, nullptr);
  TSConnectionHookAdd(TS_CONNECTION_IP_CATEGORY_HOOK, cont);
}
