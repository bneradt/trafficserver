/** @file

  Implementation of Parent Proxy routing

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

#include "proxy/ParentSelection.h"

namespace
{
DbgCtl dbg_ctl_parent_select{"parent_select"};

} // end anonymous namespace

void
ParentSelectionStrategy::markParentDown(ParentResult *result, unsigned int fail_threshold, unsigned int retry_time)
{
  time_t   now;
  pRecord *pRec, *parents = result->rec->selection_strategy->getParents(result);
  int      new_fail_count = 0;

  //  Make sure that we are being called back with a
  //   result structure with a parent
  ink_assert(result->result == ParentResultType::SPECIFIED);
  if (result->result != ParentResultType::SPECIFIED) {
    return;
  }
  // If we were set through the API we currently have not failover
  //   so just return fail
  if (result->is_api_result()) {
    return;
  }

  ink_assert((result->last_parent) < numParents(result));
  pRec = (parents + result->last_parent);

  // If the parent has already been marked down, just increment
  //   the failure count.  If this is the first mark down on a
  //   parent we need to both set the failure time and set
  //   count to one.  It's possible for the count and time get out
  //   sync due there being no locks.  Therefore the code should
  //   handle this condition.  If this was the result of a retry, we
  //   must update move the failedAt timestamp to now so that we continue
  //   negative cache the parent
  if (pRec->failedAt.load() == 0 || result->retry == true) {
    // Reread the current time.  We want this to be accurate since
    //   it relates to how long the parent has been down.
    now = time(nullptr);

    // Mark the parent failure time.
    pRec->failedAt = now;

    // If this is clean mark down and not a failed retry, we
    //   must set the count to reflect this
    if (result->retry == false) {
      new_fail_count = pRec->failCount = 1;
    }

    Note("Parent %s marked as down %s:%d for request %s", (result->retry) ? "retry" : "initially", pRec->hostname, pRec->port,
         result->url);
  } else {
    int old_count = 0;
    now           = time(nullptr);

    // if the last failure was outside the retry window, set the failcount to 1
    // and failedAt to now.
    if ((pRec->failedAt.load() + retry_time) < now) {
      // coverity[check_return]
      pRec->failCount = 1;
      pRec->failedAt  = now;
    } else {
      old_count = pRec->failCount.fetch_add(1, std::memory_order_relaxed);
    }

    Dbg(dbg_ctl_parent_select, "Parent fail count increased to %d for %s:%d", old_count + 1, pRec->hostname, pRec->port);
    new_fail_count = old_count + 1;
  }

  if (new_fail_count > 0 && new_fail_count >= static_cast<int>(fail_threshold)) {
    Note("Failure threshold met failcount:%d >= threshold:%d, http parent proxy %s:%d marked down with request: %s", new_fail_count,
         fail_threshold, pRec->hostname, pRec->port, result->url);
    pRec->available = false;
    Dbg(dbg_ctl_parent_select, "Parent %s:%d marked unavailable, pRec->available=%d", pRec->hostname, pRec->port,
        pRec->available.load());
  }
}

void
ParentSelectionStrategy::markParentUp(ParentResult *result)
{
  pRecord *pRec, *parents = result->rec->selection_strategy->getParents(result);
  int      num_parents = result->rec->selection_strategy->numParents(result);

  //  Make sure that we are being called back with a
  //   result structure with a parent that is being retried
  ink_release_assert(result->retry == true);
  ink_assert(result->result == ParentResultType::SPECIFIED);
  if (result->result != ParentResultType::SPECIFIED) {
    return;
  }
  // If we were set through the API we currently have not failover
  //   so just return fail
  if (result->is_api_result()) {
    ink_assert(0);
    return;
  }

  ink_assert((int)(result->last_parent) < num_parents);
  pRec            = parents + result->last_parent;
  pRec->available = true;

  pRec->failedAt = static_cast<time_t>(0);
  int old_count  = pRec->failCount.exchange(0, std::memory_order_relaxed);
  // a retry succeeded, just reset retriers

  if (old_count > 0) {
    Note("http parent proxy %s:%d restored with request %s", pRec->hostname, pRec->port, result->url);
  }
}
