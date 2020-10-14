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

ThrottledMessage::ThrottledMessage(std::chrono::seconds seconds_between)
  : _last_log_time{TimePoint{}}, _seconds_between{seconds_between}
{
}

void
ThrottledMessage::status(const char *fmt, ...)
{
  uint32_t count_since_last_log = 0;
  if (!should_emit_log(count_since_last_log)) {
    return;
  }
  Status("Skipped the following message %d times.", count_since_last_log);

  va_list args;
  va_start(args, fmt);
  StatusV(fmt, args);
  va_end(args);
}

void
ThrottledMessage::note(const char *fmt, ...)
{
  uint32_t count_since_last_log = 0;
  if (!should_emit_log(count_since_last_log)) {
    return;
  }
  Note("Skipped the following message %d times.", count_since_last_log);

  va_list args;
  va_start(args, fmt);
  NoteV(fmt, args);
  va_end(args);
}

void
ThrottledMessage::warning(const char *fmt, ...)
{
  uint32_t count_since_last_log = 0;
  if (!should_emit_log(count_since_last_log)) {
    return;
  }
  Warning("Skipped the following message %d times.", count_since_last_log);

  va_list args;
  va_start(args, fmt);
  WarningV(fmt, args);
  va_end(args);
}

void
ThrottledMessage::error(const char *fmt, ...)
{
  uint32_t count_since_last_log = 0;
  if (!should_emit_log(count_since_last_log)) {
    return;
  }
  Error("Skipped the following message %d times.", count_since_last_log);

  va_list args;
  va_start(args, fmt);
  ErrorV(fmt, args);
  va_end(args);
}
