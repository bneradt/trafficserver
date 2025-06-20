/** @file

  Implementation of nexthop consistent hash selections strategies.

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

#include <yaml-cpp/yaml.h>

#include "proxy/http/HttpSM.h"
#include "iocore/utils/Machine.h"
#include "tsutil/YamlCfg.h"
#include "proxy/http/remap/NextHopConsistentHash.h"

// hash_key strings.
constexpr std::string_view hash_key_url           = "url";
constexpr std::string_view hash_key_hostname      = "hostname";
constexpr std::string_view hash_key_path          = "path";
constexpr std::string_view hash_key_path_query    = "path+query";
constexpr std::string_view hash_key_path_fragment = "path+fragment";
constexpr std::string_view hash_key_cache         = "cache_key";

// hash_url strings
constexpr std::string_view hash_url_request = "request";
constexpr std::string_view hash_url_cache   = "cache";
constexpr std::string_view hash_url_parent  = "parent";

static bool
isWrapped(std::vector<bool> &wrap_around, uint32_t groups)
{
  bool all_wrapped = true;
  for (uint32_t c = 0; c < groups; c++) {
    if (wrap_around[c] == false) {
      all_wrapped = false;
    }
  }
  return all_wrapped;
}

std::shared_ptr<HostRecord>
NextHopConsistentHash::chashLookup(const std::shared_ptr<ATSConsistentHash> &ring, uint32_t cur_ring, ParentResult &result,
                                   HttpRequestData &request_info, bool *wrapped, uint64_t sm_id)
{
  uint64_t               hash_key = 0;
  ATSHash64Sip24         hash;
  HostRecord            *host_rec = nullptr;
  ATSConsistentHashIter *iter     = &result.chashIter[cur_ring];

  if (result.chash_init[cur_ring] == false) {
    hash_key                    = getHashKey(sm_id, request_info, &hash);
    host_rec                    = static_cast<HostRecord *>(ring->lookup_by_hashval(hash_key, iter, wrapped));
    result.chash_init[cur_ring] = true;
  } else {
    host_rec = static_cast<HostRecord *>(ring->lookup(nullptr, iter, wrapped, &hash));
  }
  bool wrap_around = *wrapped;
  *wrapped         = (result.mapWrapped[cur_ring] && *wrapped) ? true : false;
  if (!result.mapWrapped[cur_ring] && wrap_around) {
    result.mapWrapped[cur_ring] = true;
  }

  if (host_rec == nullptr) {
    return nullptr;
  } else {
    std::shared_ptr<HostRecord> h = host_groups[host_rec->group_index][host_rec->host_index];
    return h;
  }
}

NextHopConsistentHash::~NextHopConsistentHash()
{
  NH_Dbg(NH_DBG_CTL, "destructor called for strategy named: %s", strategy_name.c_str());
}

NextHopConsistentHash::NextHopConsistentHash(const std::string_view name, const NHPolicyType &policy, ts::Yaml::Map &n)
  : NextHopSelectionStrategy(name, policy, n)
{
  ATSHash64Sip24 hash;

  try {
    if (n["hash_url"]) {
      auto hash_url_val = n["hash_url"].Scalar();
      if (hash_url_val == hash_url_request) {
        hash_url = NHHashUrlType::REQUEST;
      } else if (hash_url_val == hash_url_cache) {
        hash_url = NHHashUrlType::CACHE;
      } else if (hash_url_val == hash_url_parent) {
        hash_url = NHHashUrlType::PARENT;
      } else {
        hash_url = NHHashUrlType::REQUEST;
        NH_Note("Invalid 'hash_url' value, '%s', for the strategy named '%s', using default '%s'.", hash_url_val.c_str(),
                strategy_name.c_str(), hash_url_request.data());
      }
    }
  } catch (std::exception &ex) {
    throw std::invalid_argument("Error parsing the strategy named '" + strategy_name + "' due to '" + ex.what() +
                                "', this strategy will be ignored.");
  }

  try {
    if (n["hash_key"]) {
      auto hash_key_val = n["hash_key"].Scalar();
      if (hash_key_val == hash_key_url) {
        hash_key = NHHashKeyType::URL_HASH_KEY;
      } else if (hash_key_val == hash_key_hostname) {
        hash_key = NHHashKeyType::HOSTNAME_HASH_KEY;
      } else if (hash_key_val == hash_key_path) {
        hash_key = NHHashKeyType::PATH_HASH_KEY;
      } else if (hash_key_val == hash_key_path_query) {
        hash_key = NHHashKeyType::PATH_QUERY_HASH_KEY;
      } else if (hash_key_val == hash_key_path_fragment) {
        hash_key = NHHashKeyType::PATH_FRAGMENT_HASH_KEY;
      } else if (hash_key_val == hash_key_cache) {
        // ToDo: Deprecated in 10.0.x, remove in 11.0.0
        hash_key = NHHashKeyType::CACHE_HASH_KEY;
      } else {
        hash_key = NHHashKeyType::PATH_HASH_KEY;
        NH_Note("Invalid 'hash_key' value, '%s', for the strategy named '%s', using default '%s'.", hash_key_val.c_str(),
                strategy_name.c_str(), hash_key_path.data());
      }
    }
  } catch (std::exception &ex) {
    throw std::invalid_argument("Error parsing the strategy named '" + strategy_name + "' due to '" + ex.what() +
                                "', this strategy will be ignored.");
  }

  // load up the hash rings.
  for (uint32_t i = 0; i < groups; i++) {
    std::shared_ptr<ATSConsistentHash> hash_ring = std::make_shared<ATSConsistentHash>();
    for (uint32_t j = 0; j < host_groups[i].size(); j++) {
      // ATSConsistentHash needs the raw pointer.
      HostRecord *p = host_groups[i][j].get();
      // need to copy the 'hash_string' or 'hostname' cstring to 'name' for insertion into ATSConsistentHash.
      if (!p->hash_string.empty()) {
        p->name = const_cast<char *>(p->hash_string.c_str());
      } else {
        p->name = const_cast<char *>(p->hostname.c_str());
      }
      p->group_index = host_groups[i][j]->group_index;
      p->host_index  = host_groups[i][j]->host_index;
      hash_ring->insert(p, p->weight, &hash);
      NH_Dbg(NH_DBG_CTL, "Loading hash rings - ring: %d, host record: %d, name: %s, hostname: %s, strategy: %s", i, j, p->name,
             p->hostname.c_str(), strategy_name.c_str());
    }
    hash.clear();
    rings.push_back(std::move(hash_ring));
  }
}

// returns a hash key calculated from the request and 'hash_key' configuration
// parameter.
uint64_t
NextHopConsistentHash::getHashKey(uint64_t sm_id, const HttpRequestData &hrdata, ATSHash64 *h)
{
  URL        *url            = nullptr;
  int         len            = 0;
  const char *url_string_ref = nullptr;

  switch (hash_url) {
  case NHHashUrlType::REQUEST:
    break;
  case NHHashUrlType::CACHE:
    if (hrdata.cache_info_lookup_url) {
      url = *(hrdata.cache_info_lookup_url);
    }
    break;
  case NHHashUrlType::PARENT:
    if (hrdata.cache_info_parent_selection_url) {
      url = *(hrdata.cache_info_parent_selection_url);
    }
    break;
  }

  // Make sure we default to the request URL if nothing else worked
  if (!url) {
    url = hrdata.hdr->url_get();
  }

  // calculate a hash using the selected config.
  switch (hash_key) {
  case NHHashKeyType::URL_HASH_KEY:
    url_string_ref = url->string_get_ref(&len, URLNormalize::LC_SCHEME_HOST);
    if (url_string_ref && len > 0) {
      h->update(url_string_ref, len);
      NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] url hash string: %s", sm_id, url_string_ref);
    }
    break;
  // hostname hash
  case NHHashKeyType::HOSTNAME_HASH_KEY:
    if (auto host{url->host_get()}; !host.empty()) {
      h->update(host.data(), host.length());
    }
    break;
  // path + query string
  case NHHashKeyType::PATH_QUERY_HASH_KEY:
    h->update("/", 1);
    if (auto path{url->path_get()}; !path.empty()) {
      h->update(path.data(), path.length());
    }
    if (auto query{url->query_get()}; !query.empty()) {
      h->update("?", 1);
      h->update(query.data(), query.length());
    }
    break;
  // path + fragment hash
  case NHHashKeyType::PATH_FRAGMENT_HASH_KEY:
    h->update("/", 1);
    if (auto path{url->path_get()}; !path.empty()) {
      h->update(path.data(), path.length());
    }
    if (auto fragment{url->fragment_get()}; !fragment.empty()) {
      h->update("?", 1);
      h->update(fragment.data(), fragment.length());
    }
    break;
  // use the cache key created by the TSCacheUrlSet() API (e.g. the cachekey plugin)
  // ToDo: Deprecated in 10.0.x, remove in 11.0.0
  case NHHashKeyType::CACHE_HASH_KEY:
    if (hrdata.cache_info_parent_selection_url && *(hrdata.cache_info_parent_selection_url)) {
      url            = *(hrdata.cache_info_parent_selection_url);
      url_string_ref = url->string_get_ref(&len);
      if (url_string_ref && len > 0) {
        NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] using parent selection over-ride string:'%.*s'.", sm_id, len, url_string_ref);
        h->update(url_string_ref, len);
      }
    } else {
      // URL defaults to hrdata.hdr->url_get() above
      h->update("/", 1);
      if (auto path{url->path_get()}; !path.empty()) {
        NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] the parent selection over-ride url is not set, using default path: %.*s.", sm_id,
               static_cast<int>(path.length()), path.data());
        h->update(path.data(), path.length());
      }
    }
    break;
  // use the path as the hash, default.
  case NHHashKeyType::PATH_HASH_KEY:
  default:
    h->update("/", 1);
    if (auto path{url->path_get()}; !path.empty()) {
      h->update(path.data(), path.length());
    }
    break;
  }

  h->final();
  return h->get();
}

void
NextHopConsistentHash::findNextHop(TSHttpTxn txnp, void * /* ih ATS_UNUSED */, time_t now)
{
  uint32_t const NO_RING_USE_POST_REMAP = uint32_t(0) - 1;

  HttpSM                     *sm           = reinterpret_cast<HttpSM *>(txnp);
  ParentResult               &result       = sm->t_state.parent_result;
  HttpRequestData            &request_info = sm->t_state.request_data;
  int64_t                     sm_id        = sm->sm_id;
  int64_t                     retry_time   = sm->t_state.txn_conf->parent_retry_time;
  time_t                      _now         = now;
  bool                        firstcall    = false;
  bool                        nextHopRetry = false;
  bool                        wrapped      = false;
  std::vector<bool>           wrap_around(groups, false);
  uint32_t                    cur_ring  = 0; // there is a hash ring for each host group
  uint32_t                    lookups   = 0;
  std::shared_ptr<HostRecord> pRec      = nullptr;
  HostStatus                 &pStatus   = HostStatus::instance();
  TSHostStatus                host_stat = TSHostStatus::TS_HOST_STATUS_INIT;
  HostStatRec                *hst       = nullptr;
  Machine                    *machine   = Machine::instance();
  std::string_view            first_call_host;
  int                         first_call_port = 0;

  if (result.line_number == -1 && result.result == ParentResultType::UNDEFINED) {
    firstcall = true;
  }

  // firstcall indicates that this is the first time the state machine has called findNextHop() for this
  // particular transaction so, a parent will be looked up using a hash from the request to locate a
  // parent on the consistent hash ring.  If not first call, then the transaction was unable to use the parent
  // returned from the "firstcall" due to some error so, subsequent calls will not search using a hash but,
  // will instead just increment the hash table iterator to find the next parent on the ring
  if (firstcall) {
    NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] firstcall, line_number: %d, result: %s", sm_id, result.line_number,
           ParentResultStr[static_cast<int>(result.result)]);
    result.line_number = distance;
    cur_ring           = 0;
    for (uint32_t i = 0; i < groups; i++) {
      result.chash_init[i] = false;
      wrap_around[i]       = false;
    }
  } else {
    // not first call, save the previously tried parent.
    if (result.hostname) {
      first_call_host = result.hostname;
      first_call_port = result.port;
    }
    NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] not firstcall, line_number: %d, result: %s", sm_id, result.line_number,
           ParentResultStr[static_cast<int>(result.result)]);
    switch (ring_mode) {
    case NHRingMode::ALTERNATE_RING:
      if (groups > 1) {
        cur_ring = (result.last_group + 1) % groups;
      } else {
        cur_ring = result.last_group;
      }
      break;
    case NHRingMode::PEERING_RING:
      if (groups == 1) {
        result.last_group = cur_ring = NO_RING_USE_POST_REMAP;
      } else {
        ink_assert(groups == 2);
        // look for the next parent on the
        // upstream ring.
        result.last_group = cur_ring = 1;
      }
      break;
    case NHRingMode::EXHAUST_RING:
    default:
      cur_ring = result.last_group;
      break;
    }
  }

  if (cur_ring != NO_RING_USE_POST_REMAP) {
    do {
      // all host groups have been searched and there are no available parents found
      if (isWrapped(wrap_around, groups)) {
        NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] No available parents.", sm_id);
        pRec = nullptr;
        break;
      }

      // search for available parent
      std::shared_ptr<ATSConsistentHash> r = rings[cur_ring];
      pRec                                 = chashLookup(r, cur_ring, result, request_info, &wrapped, sm_id);
      hst                                  = (pRec) ? pStatus.getHostStatus(pRec->hostname.c_str()) : nullptr;
      wrap_around[cur_ring]                = wrapped;
      lookups++;

      // found a parent
      if (pRec) {
        bool is_self = machine->is_self(pRec->hostname.c_str());
        host_stat    = (hst) ? hst->status : TSHostStatus::TS_HOST_STATUS_UP;

        // if the config ignore_self_detect is set to true and the host is down due to SELF_DETECT reason
        // ignore the down status and mark it as available
        if ((host_stat == TS_HOST_STATUS_DOWN && is_self && ignore_self_detect)) {
          if (hst->reasons == Reason::SELF_DETECT) {
            host_stat = TS_HOST_STATUS_UP;
          }
        }

        if (firstcall) {
          result.first_choice_status = (hst) ? hst->status : TSHostStatus::TS_HOST_STATUS_UP;
          // if peering and the selected host is myself, change rings and search for an upstream parent.
          if (ring_mode == NHRingMode::PEERING_RING && (pRec->self || is_self)) {
            if (groups == 1) {
              // use host from post-remap URL
              cur_ring = NO_RING_USE_POST_REMAP;
              pRec     = nullptr;
              break;
            } else {
              // switch to and search the upstream ring.
              cur_ring = 1;
              pRec     = nullptr;
              continue;
            }
          }
        } else {
          // not first call, make sure we're not re-using the same parent, search again if we are.
          if (first_call_host.size() > 0 && first_call_host == pRec->hostname && first_call_port == pRec->getPort(scheme)) {
            pRec = nullptr;
            continue;
          }
        }
        // if the parent is not available check to see if the retry window has expired making it available
        // for retry.
        if (!pRec->available.load() && host_stat == TS_HOST_STATUS_UP) {
          _now == 0 ? _now = time(nullptr) : _now = now;
          if ((pRec->failedAt.load() + retry_time) < _now) {
            nextHopRetry       = true;
            result.last_parent = pRec->host_index;
            result.last_lookup = pRec->group_index;
            result.retry       = nextHopRetry;
            result.result      = ParentResultType::SPECIFIED;
            NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] next hop %s is now retryable", sm_id, pRec->hostname.c_str());
            break;
          }
        }

        // use the available selected parent
        if (pRec->available.load() && host_stat == TS_HOST_STATUS_UP) {
          break;
        }
      }
      // try other rings per the ring mode
      switch (ring_mode) {
      case NHRingMode::ALTERNATE_RING:
        if (pRec && groups > 0) {
          cur_ring = (pRec->group_index + 1) % groups;
        } else {
          cur_ring = 0;
        }
        break;
      case NHRingMode::EXHAUST_RING:
      default:
        if (wrap_around[cur_ring] && groups > 1) {
          cur_ring = (cur_ring + 1) % groups;
        }
        break;
      }

      if (pRec) {
        // if the selected host is down, search again.
        if (!pRec->available || host_stat == TS_HOST_STATUS_DOWN) {
          NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] hostname: %s, available: %s, host_stat: %s", sm_id, pRec->hostname.c_str(),
                 pRec->available ? "true" : "false", HostStatusNames[host_stat]);
          pRec = nullptr;
          continue;
        }
      }
    } while (!pRec);

    NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] Initial parent lookups: %d", sm_id, lookups);
  }

  // ----------------------------------------------------------------------------------------------------
  // Validate and return the final result.
  // ----------------------------------------------------------------------------------------------------

  if (pRec && host_stat == TS_HOST_STATUS_UP && (pRec->available.load() || result.retry)) {
    result.result      = ParentResultType::SPECIFIED;
    result.hostname    = pRec->hostname.c_str();
    result.last_parent = pRec->host_index;
    result.last_lookup = result.last_group = cur_ring;
    switch (scheme) {
    case NHSchemeType::NONE:
    case NHSchemeType::HTTP:
      result.port = pRec->getPort(scheme);
      break;
    case NHSchemeType::HTTPS:
      result.port = pRec->getPort(scheme);
      break;
    }
    result.retry = nextHopRetry;
    // if using a peering ring mode and the parent selected came from the 'peering' group,
    // cur_ring == 0, then if the config allows it, set the flag to not cache the result.
    if (ring_mode == NHRingMode::PEERING_RING && !cache_peer_result && cur_ring == 0) {
      result.do_not_cache_response = true;

      NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] setting do not cache response from a peer per config: %s", sm_id,
             (result.do_not_cache_response) ? "true" : "false");
    }

    // We want to use the pristine/pre-remap URL when going to a peer so it can handle
    // the request without needing extra remaps to handle the post-remap URL
    if (ring_mode == NHRingMode::PEERING_RING && cur_ring == 0 && use_pristine) {
      result.use_pristine = true;
      NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] setting use pristine to true", sm_id);
    }

    ink_assert(result.hostname != nullptr);
    ink_assert(result.port != 0);
    NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] result->result: %s Chosen parent: %s.%d", sm_id,
           ParentResultStr[static_cast<int>(result.result)], result.hostname, result.port);
  } else {
    if (go_direct == true) {
      result.result = ParentResultType::DIRECT;
    } else {
      result.result = ParentResultType::FAIL;
    }
    result.hostname = nullptr;
    result.port     = 0;
    result.retry    = false;

    NH_Dbg(NH_DBG_CTL, "[%" PRIu64 "] result.result: %s set hostname null port 0 retry false", sm_id,
           ParentResultStr[static_cast<int>(result.result)]);
  }

  setHostHeader(txnp, result.hostname);

  return;
}
