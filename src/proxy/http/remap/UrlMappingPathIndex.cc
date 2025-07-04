/** @file

    A brief file description

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

#include "proxy/http/remap/UrlMappingPathIndex.h"

namespace
{
DbgCtl dbg_ctl_UrlMappingPathIndex_Insert{"UrlMappingPathIndex::Insert"};
DbgCtl dbg_ctl_UrlMappingPathIndex_Search{"UrlMappingPathIndex::Search"};

} // end anonymous namespace

UrlMappingPathIndex::~UrlMappingPathIndex()
{
  for (auto &m_trie : m_tries) {
    delete m_trie.second; // Delete the Trie
  }
  m_tries.clear();
}

bool
UrlMappingPathIndex::Insert(url_mapping *mapping)
{
  int             scheme_idx;
  int             port = (mapping->fromURL).port_get();
  UrlMappingTrie *trie;

  trie = _GetTrie(&(mapping->fromURL), scheme_idx, port);

  if (!trie) {
    trie = new UrlMappingTrie();
    m_tries.insert(UrlMappingGroup::value_type(UrlMappingTrieKey(scheme_idx, port), trie));
    Dbg(dbg_ctl_UrlMappingPathIndex_Insert, "Created new trie for scheme index, port combo <%d, %d>", scheme_idx, port);
  }

  auto from_path{mapping->fromURL.path_get()};
  if (!trie->Insert(from_path.data(), mapping, mapping->getRank(), static_cast<int>(from_path.length()))) {
    Error("Couldn't insert into trie!");
    return false;
  }
  Dbg(dbg_ctl_UrlMappingPathIndex_Insert, "Inserted new element!");
  return true;
}

url_mapping *
UrlMappingPathIndex::Search(URL *request_url, int request_port, bool normal_search /* = true */) const
{
  url_mapping     *retval = nullptr;
  int              scheme_idx;
  UrlMappingTrie  *trie;
  int              path_len;
  std::string_view path{};

  trie = _GetTrie(request_url, scheme_idx, request_port, normal_search);

  if (!trie) {
    Dbg(dbg_ctl_UrlMappingPathIndex_Search, "No mappings exist for scheme index, port combo <%d, %d>", scheme_idx, request_port);
    goto lFail;
  }

  path     = request_url->path_get();
  path_len = static_cast<int>(path.length());
  if (!(retval = trie->Search(path.data(), path_len))) {
    Dbg(dbg_ctl_UrlMappingPathIndex_Search, "Couldn't find entry for url with path [%.*s]", path_len, path.data());
    goto lFail;
  }
  return retval;

lFail:
  return nullptr;
}

void
UrlMappingPathIndex::Print() const
{
  for (auto &m_trie : m_tries) {
    m_trie.second->Print();
  }
}

std::string
UrlMappingPathIndex::PrintUrlMappingPathIndex() const
{
  std::string result;
  for (auto &m_trie : m_tries) {
    for (auto const &node : *m_trie.second) {
      result += node.PrintRemapHitCount();
      result += ",\n";
    }
  }
  return result;
}
