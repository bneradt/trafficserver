/** @file

  ThrottledMessage declaration.

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

#include "tscore/ThrottledMessage.h"

#include "tscore/Diags.h"

namespace
{
void
message_helper(DiagsLevel level, SourceLocation const &loc, Throttler &throttler, const char *fmt, va_list ap)
{
  uint64_t count_since_last_log = 0;
  if (!throttler(count_since_last_log)) {
    return;
  }
  if (count_since_last_log > 0) {
    diags->error(level, &loc, "Skipped the following message %lu times.", count_since_last_log);
  }
  diags->error_va(level, &loc, fmt, ap);
}

} // namespace

ThrottledMessage::ThrottledMessage(std::chrono::seconds seconds_between) : _throttler{seconds_between} {}

void
ThrottledMessage::status(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Status, loc, _throttler, fmt, args);
  va_end(args);
}

void
ThrottledMessage::note(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Note, loc, _throttler, fmt, args);
  va_end(args);
}

void
ThrottledMessage::warning(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Warning, loc, _throttler, fmt, args);
  va_end(args);
}

void
ThrottledMessage::error(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Error, loc, _throttler, fmt, args);
  va_end(args);
}
