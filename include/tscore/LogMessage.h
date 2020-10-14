/** @file

  LogMessage declaration.

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

#pragma once

#include "DiagsTypes.h"
#include "SourceLocation.h"
#include "Throttler.h"

#include <atomic>
#include <chrono>

/** Represents a set of log messages for which throttling is desired. */
class LogMessage
{
public:
  /**
   * Log throttling will be constructed with the system wide configured values.
   */
  LogMessage();

  /**
   * @param[in] throttling_interval The minimum number of desired
   * milliseconds between log events. 0 implies no throttling.
   */
  LogMessage(std::chrono::milliseconds throttling_interval);

  /* TODO: Add BufferWriter overloads for these. */
  void diag(const char *tag, SourceLocation const &loc, const char *fmt, ...);
  void debug(const char *tag, SourceLocation const &loc, const char *fmt, ...);
  void status(SourceLocation const &loc, const char *fmt, ...);
  void note(SourceLocation const &loc, const char *fmt, ...);
  void warning(SourceLocation const &loc, const char *fmt, ...);
  void error(SourceLocation const &loc, const char *fmt, ...);
  void fatal(SourceLocation const &loc, const char *fmt, ...);
  void alert(SourceLocation const &loc, const char *fmt, ...);
  void emergency(SourceLocation const &loc, const char *fmt, ...);

  void message(DiagsLevel level, SourceLocation const &loc, const char *fmt, ...);
  void print(const char *tag, DiagsLevel level, SourceLocation const &loc, const char *fmt, ...);

  void diag_va(const char *tag, SourceLocation const &loc, const char *fmt, va_list args);
  void debug_va(const char *tag, SourceLocation const &loc, const char *fmt, va_list args);
  void status_va(SourceLocation const &loc, const char *fmt, va_list args);
  void note_va(SourceLocation const &loc, const char *fmt, va_list args);
  void warning_va(SourceLocation const &loc, const char *fmt, va_list args);
  void error_va(SourceLocation const &loc, const char *fmt, va_list args);
  void fatal_va(SourceLocation const &loc, const char *fmt, va_list args);
  void alert_va(SourceLocation const &loc, const char *fmt, va_list args);
  void emergency_va(SourceLocation const &loc, const char *fmt, va_list args);
  void message_va(DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args);

  /** Set a new system-wide default log throttling interval.
   *
   * @param[in] new_interval The new log throttling interval.
   */
  static void set_default_log_throttling_interval(std::chrono::milliseconds new_interval);

  /** Set a new system-wide default debug log throttling interval.
   *
   * @param[in] new_interval The new debug log throttling interval.
   */
  static void set_default_debug_throttling_interval(std::chrono::milliseconds new_interval);

private:
  /** Common message handling for each DiagsLevel. */
  void message_helper(DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args);

  /** Same as above, but catered for the diag and debug variants.
   *
   * Note that this uses the diags-log variant which takes a debug tag.
   */
  void message_debug_helper(const char *tag, DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args);

  /** Same as above, but uses the tag-ignoring diags->print variant. */
  void message_print_helper(const char *tag, DiagsLevel level, SourceLocation const &loc, const char *fmt, va_list args);

private:
  /** Used to throttle the log messages to the specified throttling interval. */
  Throttler _throttler;

  /** Whether the throttling value was explicitly set by the user.
   *
   * If the user explicitly set a throttling value, then it will not change as
   * the configured log throttling values change.
   */
  bool const _throttling_value_is_explicitly_set;

  /** The configured, system-wide default log throttling value. */
  static std::atomic<std::chrono::milliseconds> default_log_throttling_interval;

  /** The configured, system-wide default debug log throttling value. */
  static std::atomic<std::chrono::milliseconds> default_debug_throttling_interval;
};
