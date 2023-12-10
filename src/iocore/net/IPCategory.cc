/** @file

  Implements IPCategory functionality.

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

#include "iocore/net/IPCategory.h"

#include "api/APIHook.h"
#include "api/InkAPIInternal.h"
#include "iocore/net/ConnectionAPIHooks.h"

#include "P_IPCategoryCache.h"

void
IPCategory::initialize()
{
  // TOO: Make these values configurable.
  IPCategoryCache::initialize(1'000, 10, std::chrono::seconds{60});
}

bool
populate_ip_categories(sockaddr const &addr, std::optional<Categories_t> &categories)
{
  if (categories.has_value()) {
    // Nothing to do. The VConnection's categories cache is already set.
    return true;
  }

  // Do we have any plugins registered to set categories?
  APIHook *hook = global_connection_hooks->get(TS_CONNECTION_IP_CATEGORY_HOOK);
  if (hook == nullptr) {
    // No plugins registered setting categories. Thus there are none to set.
    categories = std::unordered_set<IPCategory>{};
    return true;
  }

  // We have to retrieve the categories. First try the cache.
  std::optional<Categories_t> cached_categories = IPCategoryCache::get(addr);
  if (cached_categories.has_value()) {
    categories = cached_categories.value();
    return true;
  }

  // Not in the cache. Resort to calling the plugins.
  std::unordered_set<int> local_categories;
  swoc::IPAddr ip_addr{&addr};
  IpCategoryInfo info{ip_addr, local_categories};
  for (; hook != nullptr; hook = hook->next()) {
    hook->invoke(TS_EVENT_CONNECTION_IP_CATEGORY, &info);
  }

  categories = std::unordered_set<IPCategory>{};
  // Now convert the int types to IPCategory for set.
  for (auto &&category : local_categories) {
    categories.value().emplace(category);
  }

  // Populate the cache for next time.
  IPCategoryCache::put(addr, categories.value());
  return true;
}
