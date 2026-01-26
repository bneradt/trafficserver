/** @file

  IPData implementation for abuse detection.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
  agreements.  See the NOTICE file distributed with this work for additional information regarding
  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with the License.  You may obtain
  a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed under the License
  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
  or implied. See the License for the specific language governing permissions and limitations under
  the License.
*/

#include "ip_data.h"

#include <chrono>

namespace abuse_shield
{

namespace
{
  uint64_t
  now_ms()
  {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
  }
} // namespace

void
IPData::record_h2_error(uint8_t error_code, bool is_client_error)
{
  if (is_client_error) {
    client_errors.fetch_add(1, std::memory_order_relaxed);
  } else {
    server_errors.fetch_add(1, std::memory_order_relaxed);
  }

  if (error_code < NUM_H2_ERROR_CODES) {
    h2_error_counts[error_code].fetch_add(1, std::memory_order_relaxed);
  }

  last_seen.store(now_ms(), std::memory_order_relaxed);
}

void
IPData::record_success()
{
  successes.fetch_add(1, std::memory_order_relaxed);
  last_seen.store(now_ms(), std::memory_order_relaxed);
}

void
IPData::record_connection()
{
  conn_count.fetch_add(1, std::memory_order_relaxed);
  last_seen.store(now_ms(), std::memory_order_relaxed);
}

void
IPData::record_request()
{
  req_count.fetch_add(1, std::memory_order_relaxed);
  last_seen.store(now_ms(), std::memory_order_relaxed);
}

bool
IPData::is_blocked() const
{
  uint64_t until = blocked_until.load(std::memory_order_relaxed);
  return until > 0 && now_ms() < until;
}

void
IPData::block_until(uint64_t until_ms)
{
  blocked_until.store(until_ms, std::memory_order_relaxed);
}

} // namespace abuse_shield
