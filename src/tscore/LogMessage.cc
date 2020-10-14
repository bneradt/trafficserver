/** @file

  LogMessage implementation.

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

#include "tscore/LogMessage.h"

#include "tscore/Diags.h"

std::atomic<std::chrono::milliseconds> LogMessage::default_log_throttling_interval{std::chrono::milliseconds{0}};
std::atomic<std::chrono::milliseconds> LogMessage::default_debug_throttling_interval{std::chrono::milliseconds{0}};

// static
void
LogMessage::set_default_log_throttling_interval(std::chrono::milliseconds new_interval)
{
  default_log_throttling_interval = new_interval;
}

// static
void
LogMessage::set_default_debug_throttling_interval(std::chrono::milliseconds new_interval)
{
  default_debug_throttling_interval = new_interval;
}

void
LogMessage::message_helper(DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args)
{
  if (!_throttling_value_is_explicitly_set) {
    _throttler.set_throttling_interval(default_log_throttling_interval.load());
  }
  uint64_t count_since_last_log = 0;
  if (!_throttler(count_since_last_log)) {
    return;
  }
  if (count_since_last_log > 0) {
    diags->error(level, &loc, "Skipped the following message %lu times.", count_since_last_log);
  }
  diags->error_va(level, &loc, fmt, args);
}

/** Same as above, but catered for the diag and debug variants.
 *
 * Note that this uses the diags-log variant which takes a debug tag.
 */
void
LogMessage::message_debug_helper(const char *tag, DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args)
{
  if (!_throttling_value_is_explicitly_set) {
    _throttler.set_throttling_interval(default_debug_throttling_interval.load());
  }
  uint64_t count_since_last_log = 0;
  if (!_throttler(count_since_last_log)) {
    return;
  }
  if (count_since_last_log > 0) {
    diags->log(tag, level, &loc, "Skipped the following message %lu times.", count_since_last_log);
  }
  diags->log_va(tag, level, &loc, fmt, args);
}

/** Same as above, but uses the tag-ignoring diags->print variant.
 */
void
LogMessage::message_print_helper(const char *tag, DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args)
{
  if (!_throttling_value_is_explicitly_set) {
    if (level == DL_Diag || level == DL_Debug) {
      _throttler.set_throttling_interval(default_debug_throttling_interval.load());
    } else {
      _throttler.set_throttling_interval(default_log_throttling_interval.load());
    }
  }
  uint64_t count_since_last_log = 0;
  if (!_throttler(count_since_last_log)) {
    return;
  }
  if (count_since_last_log > 0) {
    diags->print(tag, level, &loc, "Skipped the following message %lu times.", count_since_last_log);
  }
  diags->print(tag, level, &loc, fmt, args);
}

LogMessage::LogMessage()
  // Turn throttling off by default. Each log event will check the configured
  // throttling interval.
  : _throttler{std::chrono::milliseconds{0}}, _throttling_value_is_explicitly_set{false}
{
}

LogMessage::LogMessage(std::chrono::milliseconds throttling_interval)
  : _throttler{throttling_interval}, _throttling_value_is_explicitly_set{true}
{
}

void
LogMessage::diag(const char *tag, SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_debug_helper(tag, DL_Diag, loc, fmt, args);
  va_end(args);
}

void
LogMessage::debug(const char *tag, SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_debug_helper(tag, DL_Debug, loc, fmt, args);
  va_end(args);
}

void
LogMessage::status(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Status, loc, fmt, args);
  va_end(args);
}

void
LogMessage::note(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Note, loc, fmt, args);
  va_end(args);
}

void
LogMessage::warning(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Warning, loc, fmt, args);
  va_end(args);
}

void
LogMessage::error(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Error, loc, fmt, args);
  va_end(args);
}

void
LogMessage::fatal(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Fatal, loc, fmt, args);
  va_end(args);
}

void
LogMessage::alert(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Alert, loc, fmt, args);
  va_end(args);
}

void
LogMessage::emergency(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(DL_Emergency, loc, fmt, args);
  va_end(args);
}

void
LogMessage::message(DiagsLevel level, SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_helper(level, loc, fmt, args);
  va_end(args);
}

void
LogMessage::print(const char *tag, DiagsLevel level, SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  message_print_helper(tag, level, loc, fmt, args);
  va_end(args);
}

void
LogMessage::diag_va(const char *tag, SourceLocation const &loc, const char *fmt, va_list args)
{
  message_debug_helper(tag, DL_Diag, loc, fmt, args);
}

void
LogMessage::debug_va(const char *tag, SourceLocation const &loc, const char *fmt, va_list args)
{
  message_debug_helper(tag, DL_Debug, loc, fmt, args);
}

void
LogMessage::status_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(DL_Status, loc, fmt, args);
}

void
LogMessage::note_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(DL_Note, loc, fmt, args);
}

void
LogMessage::warning_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(DL_Warning, loc, fmt, args);
}

void
LogMessage::error_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(DL_Error, loc, fmt, args);
}

void
LogMessage::fatal_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(DL_Fatal, loc, fmt, args);
}

void
LogMessage::alert_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(DL_Alert, loc, fmt, args);
}

void
LogMessage::emergency_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(DL_Emergency, loc, fmt, args);
}

void
LogMessage::message_va(DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(level, loc, fmt, args);
}
