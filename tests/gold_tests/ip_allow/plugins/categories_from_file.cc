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

#include <getopt.h>
#include <string>
#include <sys/socket.h>
#include <system_error>

#include "swoc/bwf_ip.h"
#include "swoc/BufferWriter.h"
#include "swoc/IPAddr.h"
#include "swoc/IPRange.h"
#include "swoc/TextView.h"
#include "swoc/swoc_file.h"

#include "ts/apidefs.h"
#include "ts/ts.h"

namespace
{

std::string const PLUGIN_NAME = "categories_from_file";
DbgCtl dbg_ctl{"categories_from_file"};

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

std::string global_category_file;
const std::string TS_CONFIG_DIR{TSConfigDirGet()};

/** Return the IP cagories associated with the given address.
 *
 * @param addr The address to check.
 * @return The categories associated with the address.
 */
std::unordered_set<int>
get_ip_categories(sockaddr const &addr)
{
  std::unordered_set<int> categories;
  swoc::file::path fp{global_category_file};
  if (!fp.is_absolute()) {
    fp = swoc::file::path{TS_CONFIG_DIR} / fp; // slap the config dir on it to make it absolute.
  }
  // bulk load the file.
  std::error_code ec;
  std::string content{swoc::file::load(fp, ec)};
  if (ec) {
    TSError("[%s] unable to read file '%s' : %s.", PLUGIN_NAME.c_str(), fp.c_str(), ec.message().c_str());
    return categories;
  }
  // walk the lines.
  int line_no = 0;
  swoc::TextView src{content};
  while (!src.empty()) {
    swoc::TextView line{src.take_prefix_at('\n').trim_if(&isspace)};
    ++line_no;
    if (line.empty() || '#' == *line) {
      continue; // empty or comment, ignore.
    }

    std::string category{line};
    // Check that the category is in our map.
    if (global_category_map.find(category) == global_category_map.end()) {
      TSError("[%s] In '%s', unknown category '%.*s' on line %d.", PLUGIN_NAME.c_str(), fp.c_str(),
              static_cast<int>(category.size()), category.data(), line_no);
      continue;
    }
    categories.emplace(global_category_map.at(category));
  }
  return categories;
}

void
handle_ip_category(TSIpCategoryInfo infop)
{
  sockaddr address;
  TSIpCategoryInfoAddrGet(infop, address);

  std::unordered_set<int> categories = get_ip_categories(address);
  TSIpCategoryInfoCategoriesSet(infop, categories);

  swoc::LocalBufferWriter<500> w;
  w.print("Address {} is in categories:", swoc::IPAddr{&address});
  // for (auto &&category : categories) {
  // w.print(" {}", category);
  //}
  Dbg(dbg_ctl, "%s", w.data());
}

int
ip_category_callback(TSCont contp, TSEvent event, void *edata)
{
  switch (event) {
  case tsapi::c::TS_EVENT_CONNECTION_IP_CATEGORY: {
    TSIpCategoryInfo infop = static_cast<TSIpCategoryInfo>(edata);
    handle_ip_category(infop);
    break;
  }

  default:
    TSError("[%s] Unknown event %d", PLUGIN_NAME.c_str(), event);
    break;
  }

  return TS_SUCCESS;
}

bool
parse_arguments(int argc, const char *argv[], std::string &category_file)
{
  // Construct longopts for a single option that takes a filename.
  const struct option longopts[] = {
    {"category_file", required_argument, nullptr, 1},
    {nullptr,         0,                 nullptr, 0}
  };

  int opt = 0;
  std::string local_category_file;
  while ((opt = getopt_long(argc, const_cast<char *const *>(argv), "", longopts, nullptr)) >= 0) {
    switch (opt) {
    case 1:
      local_category_file = optarg;
      break;
    case '?':
      TSError("[%s] Unknown option '%c'", PLUGIN_NAME.c_str(), optopt);
    case 0:
    case -1:
      break;
    default:
      TSError("[%s] Unexpected option parsing error", PLUGIN_NAME.c_str());
      return false;
    }
  }

  if (local_category_file.empty()) {
    TSError("[%s] Missing required option @param=--category_file", PLUGIN_NAME.c_str());
    return false;
  }
  category_file = local_category_file;

  Dbg(dbg_ctl, "parse_arguments(): category_file: %s", category_file.c_str());
  return true;
}

} // anonymous namespace

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;
  info.plugin_name   = PLUGIN_NAME.c_str();
  info.vendor_name   = "apache";
  info.support_email = "edge@yahooinc.com";
  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s]: failure calling TSPluginRegister.", PLUGIN_NAME.c_str());
    return;
  }

  if (!parse_arguments(argc, argv, global_category_file)) {
    TSError("[%s] Unable to parse arguments, plugin not engaged.", PLUGIN_NAME.c_str());
    return;
  }

  // Inform the core what the categories are.
  TSHttpIpAllowTableSet(global_category_map);

  // Populate the callback for dynamic category queries from the core.
  auto cont = TSContCreate(ip_category_callback, nullptr);
  TSConnectionHookAdd(TS_CONNECTION_IP_CATEGORY_HOOK, cont);
}
