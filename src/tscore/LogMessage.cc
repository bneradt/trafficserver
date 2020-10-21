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

std::atomic<std::chrono::milliseconds> LogMessage::_default_log_throttling_interval{std::chrono::milliseconds{0}};
std::atomic<std::chrono::milliseconds> LogMessage::_default_debug_throttling_interval{std::chrono::milliseconds{0}};

// 9216 is the default value for proxy.config.log.log_buffer_size.
std::atomic<int> LogMessage::_log_buffer_size{9216};

// static
void
LogMessage::set_default_log_throttling_interval(std::chrono::milliseconds new_interval)
{
  _default_log_throttling_interval = new_interval;
}

// static
void
LogMessage::set_default_debug_throttling_interval(std::chrono::milliseconds new_interval)
{
  _default_debug_throttling_interval = new_interval;
}

// static
void
LogMessage::set_max_log_buffer_size(int new_log_buffer_size)
{
  _log_buffer_size = new_log_buffer_size;
}

bool
LogMessage::is_same_as_last_message(const char *fmt, va_list args)
{
  char buf[_log_buffer_size.load()];
  std::vsnprintf(buf, _log_buffer_size, fmt, args);
  _this_message = std::string{buf};
  return _last_printed_message == _this_message;
}

void
LogMessage::message_helper(std::chrono::microseconds current_configured_interval, log_function_f log_function, const char *fmt,
                           va_list args)
{
  if (!_throttling_value_is_explicitly_set) {
    set_throttling_interval(current_configured_interval);
  }
  uint64_t number_of_suppressions = 0;
  bool print_previous_message     = false;
  if (!is_same_as_last_message(fmt, args)) {
    // This message differs from the last. Therefore we want to emit it and not
    // suppress it, regardless of throttling interval.
    number_of_suppressions = reset_counter();
    print_previous_message = number_of_suppressions > 0;
    if (number_of_suppressions > 0) {
      // This message differs from the last set that were the same and were
      // being throttled. We'll print the last message which was previously
      // suppressed. But since we'll print that last message, it will not
      // effectively be suppressed.  We account for that here.
      --number_of_suppressions;
    }
  } else if (is_throttled(number_of_suppressions)) {
    // The messages are the same and but we're still within the throttling
    // interval. Suppress this message.
    return;
  }
  // If we get here, the message should not be suppressed.
  if (number_of_suppressions > 0) {
    std::string message =
      std::string("The following message was suppressed ") + std::to_string(number_of_suppressions) + std::string(" times.");
    log_function(message.c_str());
  }
  if (print_previous_message && !_last_printed_message.empty()) {
    log_function(_last_printed_message.c_str());
  }
  log_function(_this_message.c_str());
  _last_printed_message = _this_message;
}

void
LogMessage::standard_message_helper(DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(
    _default_log_throttling_interval.load(), [level, &loc](const char *message) { diags->error(level, &loc, message); }, fmt, args);
}

void
LogMessage::message_debug_helper(const char *tag, DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(
    _default_debug_throttling_interval.load(), [tag, level, &loc](const char *message) { diags->log(tag, level, &loc, message); },
    fmt, args);
}

void
LogMessage::message_print_helper(const char *tag, DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args)
{
  message_helper(
    _default_debug_throttling_interval.load(), [tag, level, &loc](const char *message) { diags->print(tag, level, &loc, message); },
    fmt, args);
}

LogMessage::LogMessage()
  // Turn throttling off by default. Each log event will check the configured
  // throttling interval.
  : Throttler{std::chrono::milliseconds{0}}, _throttling_value_is_explicitly_set{false}
{
}

LogMessage::LogMessage(std::chrono::milliseconds throttling_interval)
  : Throttler{throttling_interval}, _throttling_value_is_explicitly_set{true}
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
  standard_message_helper(DL_Status, loc, fmt, args);
  va_end(args);
}

void
LogMessage::note(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  standard_message_helper(DL_Note, loc, fmt, args);
  va_end(args);
}

void
LogMessage::warning(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  standard_message_helper(DL_Warning, loc, fmt, args);
  va_end(args);
}

void
LogMessage::error(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  standard_message_helper(DL_Error, loc, fmt, args);
  va_end(args);
}

void
LogMessage::fatal(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  standard_message_helper(DL_Fatal, loc, fmt, args);
  va_end(args);
}

void
LogMessage::alert(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  standard_message_helper(DL_Alert, loc, fmt, args);
  va_end(args);
}

void
LogMessage::emergency(SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  standard_message_helper(DL_Emergency, loc, fmt, args);
  va_end(args);
}

void
LogMessage::message(DiagsLevel level, SourceLocation const &loc, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  standard_message_helper(level, loc, fmt, args);
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
  standard_message_helper(DL_Status, loc, fmt, args);
}

void
LogMessage::note_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  standard_message_helper(DL_Note, loc, fmt, args);
}

void
LogMessage::warning_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  standard_message_helper(DL_Warning, loc, fmt, args);
}

void
LogMessage::error_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  standard_message_helper(DL_Error, loc, fmt, args);
}

void
LogMessage::fatal_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  standard_message_helper(DL_Fatal, loc, fmt, args);
}

void
LogMessage::alert_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  standard_message_helper(DL_Alert, loc, fmt, args);
}

void
LogMessage::emergency_va(SourceLocation const &loc, const char *fmt, va_list args)
{
  standard_message_helper(DL_Emergency, loc, fmt, args);
}

void
LogMessage::message_va(DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args)
{
  standard_message_helper(level, loc, fmt, args);
}
