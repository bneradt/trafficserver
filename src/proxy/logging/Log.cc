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

/***************************************************************************
 Log.cc

 This file defines the implementation of the static Log class, which is
 primarily used as a namespace.  That is, there are no Log objects, but the
 class scope and static members provide a protected namespace for all of
 the logging routines and enumerated types.  When C++ namespaces are more
 widely-implemented, Log could be implemented as a namespace rather than a
 class.

 ***************************************************************************/
#include "tscore/ink_platform.h"
#include "tscore/TSSystemState.h"
#include "../../iocore/eventsystem/P_EventSystem.h"
#include "../../iocore/net/P_Net.h"
#include "iocore/utils/Machine.h"
#include "proxy/hdrs/HTTP.h"

#include "proxy/logging/LogAccess.h"
#include "proxy/logging/LogField.h"
#include "proxy/logging/LogFilter.h"
#include "proxy/logging/LogFormat.h"
#include "proxy/logging/LogFile.h"
#include "proxy/logging/LogObject.h"
#include "proxy/logging/LogConfig.h"
#include "proxy/logging/LogBuffer.h"
#include "proxy/logging/LogUtils.h"
#include "proxy/logging/Log.h"
#include "tscore/SimpleTokenizer.h"

#include "tscore/ink_apidefs.h"

#include "tscore/MgmtDefs.h"

#define PERIODIC_TASKS_INTERVAL_FALLBACK 5

// Log global objects
LogObject       *Log::error_log = nullptr;
LogFieldList     Log::global_field_list;
Log::LoggingMode Log::logging_mode = LOG_MODE_NONE;

// Flush thread stuff
EventNotify   *Log::preproc_notify;
EventNotify   *Log::flush_notify;
InkAtomicList *Log::flush_data_list;

// Log private objects
int      Log::preproc_threads;
int      Log::init_status                = 0;
int      Log::config_flags               = 0;
bool     Log::logging_mode_changed       = false;
bool     Log::log_rotate_signal_received = false;
uint32_t Log::periodic_tasks_interval    = PERIODIC_TASKS_INTERVAL_FALLBACK;

// Hash table for LogField symbols
std::unordered_map<std::string, LogField *> Log::field_symbol_hash;

LogsStatsBlock log_rsb;

/*-------------------------------------------------------------------------
  Log::change_configuration

  This routine is invoked when the current LogConfig object says it needs
  to be changed (as the result of a manager callback).
  -------------------------------------------------------------------------*/

LogConfig *Log::config = nullptr;

namespace
{
DbgCtl dbg_ctl_log_config{"log-config"};
DbgCtl dbg_ctl_log_api_mutex{"log-api-mutex"};
DbgCtl dbg_ctl_log_periodic{"log-periodic"};
DbgCtl dbg_ctl_log{"log"};
DbgCtl dbg_ctl_log_preproc{"log-preproc"};

unsigned log_configid = 0;

// Downcast from a Ptr<LogFieldAliasTable> to a Ptr<LogFieldAliasMap>.
static Ptr<LogFieldAliasMap>
make_alias_map(Ptr<LogFieldAliasTable> &table)
{
  return make_ptr(static_cast<LogFieldAliasMap *>(table.get()));
}

} // end anonymous namespace

void
Log::change_configuration()
{
  LogConfig *prev_config = Log::config;
  LogConfig *new_config  = nullptr;

  Dbg(dbg_ctl_log_config, "Changing configuration ...");

  new_config = new LogConfig;
  ink_assert(new_config != nullptr);
  new_config->read_configuration_variables();

  // grab the _APImutex so we can transfer the api objects to
  // the new config
  //
  ink_mutex_acquire(prev_config->log_object_manager._APImutex);
  Dbg(dbg_ctl_log_api_mutex, "Log::change_configuration acquired api mutex");

  new_config->init(prev_config);

  // Make the new LogConfig active.
  ink_atomic_swap(&Log::config, new_config);

  // XXX There is a race condition with API objects. If TSTextLogObjectCreate()
  // is called before the Log::config swap, then it will be blocked on the lock
  // on the *old* LogConfig and register it's LogObject with that manager. If
  // this happens, then the new TextLogObject will be immediately lost. Traffic
  // Server would crash the next time the plugin referenced the freed object.

  ink_mutex_release(prev_config->log_object_manager._APImutex);
  Dbg(dbg_ctl_log_api_mutex, "Log::change_configuration released api mutex");

  // Register the new config in the config processor; the old one will now be scheduled for a
  // future deletion. We don't need to do anything magical with refcounts, since the
  // configProcessor will keep a reference count, and drop it when the deletion is scheduled.
  configProcessor.set(log_configid, new_config);

  // If we replaced the logging configuration, flush any log
  // objects that weren't transferred to the new config ...
  prev_config->log_object_manager.flush_all_objects();

  Dbg(dbg_ctl_log_config, "... new configuration in place");
}

/*-------------------------------------------------------------------------
  PERIODIC EVENTS

  There are a number of things that need to get done on a periodic basis,
  such as checking the amount of space used, seeing if it's time to roll
  files, and flushing idle log buffers.  Most of these tasks require having
  exclusive access to the back-end structures, which is controlled by the
  flush_thread.  Therefore, we will simply instruct the flush thread to
  execute a periodic_tasks() function once per period.  To ensure that the
  tasks are executed AT LEAST once each period, we'll register a call-back
  with the system and trigger the flush thread's condition variable.  To
  ensure that the tasks are executed AT MOST once per period, the flush
  thread will keep track of executions per period.
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  PeriodicWakeup

  This continuation is invoked each second to wake-up the flush thread,
  just in case it's sleeping on the job.
  -------------------------------------------------------------------------*/

struct PeriodicWakeup;
using PeriodicWakeupHandler = int (PeriodicWakeup::*)(int, void *);
struct PeriodicWakeup : Continuation {
  int m_preproc_threads;
  int m_flush_threads;

  int
  wakeup(int /* event ATS_UNUSED */, Event * /* e ATS_UNUSED */)
  {
    for (int i = 0; i < m_preproc_threads; i++) {
      Log::preproc_notify[i].signal();
    }
    for (int i = 0; i < m_flush_threads; i++) {
      Log::flush_notify[i].signal();
    }
    return EVENT_CONT;
  }

  PeriodicWakeup(int preproc_threads, int flush_threads)
    : Continuation(new_ProxyMutex()), m_preproc_threads(preproc_threads), m_flush_threads(flush_threads)
  {
    SET_HANDLER(&PeriodicWakeup::wakeup);
  }
};

/*-------------------------------------------------------------------------
  Log::periodic_tasks

  This function contains all of the tasks that need to be done each
  PERIODIC_TASKS_INTERVAL seconds.
  -------------------------------------------------------------------------*/

void
Log::periodic_tasks(long time_now)
{
  Dbg(dbg_ctl_log_api_mutex, "entering Log::periodic_tasks");

  if (logging_mode_changed || Log::config->reconfiguration_needed) {
    Dbg(dbg_ctl_log_config, "Performing reconfiguration, init status = %d", init_status);

    if (logging_mode_changed) {
      int val;
      val = RecGetRecordInt("proxy.config.log.logging_enabled").value_or(0);

      if (val < LOG_MODE_NONE || val > LOG_MODE_FULL) {
        logging_mode = LOG_MODE_FULL;
        Warning("proxy.config.log.logging_enabled has an invalid "
                "value setting it to %d",
                logging_mode);
      } else {
        logging_mode = static_cast<LoggingMode>(val);
      }
      logging_mode_changed = false;
    }
    // even if we are disabling logging, we call change configuration
    // so that log objects are flushed
    //
    change_configuration();
  } else if (logging_mode > LOG_MODE_NONE || config->has_api_objects()) {
    Dbg(dbg_ctl_log_periodic, "Performing periodic tasks");
    Dbg(dbg_ctl_log_periodic, "Periodic task interval = %d", periodic_tasks_interval);

    // Check if space is ok and update the space used
    //
    if (config->space_is_short() || time_now % config->space_used_frequency == 0) {
      Log::config->update_space_used();
    }

    // See if there are any buffers that have expired
    //
    Log::config->log_object_manager.check_buffer_expiration(time_now);

    // Check if we received a request to roll, and roll if so, otherwise
    // give objects a chance to roll if they need to
    //
    if (Log::config->roll_log_files_now) {
      if (error_log) {
        error_log->roll_files(time_now);
      }
      Log::config->log_object_manager.roll_files(time_now);
      Log::config->roll_log_files_now = false;
    } else {
      if (error_log) {
        error_log->roll_files(time_now);
      }
      Log::config->log_object_manager.roll_files(time_now);
    }
    if (log_rotate_signal_received) {
      Log::config->log_object_manager.reopen_moved_log_files();
      log_rotate_signal_received = false;
    }
  }
}

/*-------------------------------------------------------------------------
  MAIN INTERFACE
  -------------------------------------------------------------------------*/
struct LoggingPreprocContinuation : public Continuation {
  int m_idx;

  int
  mainEvent(int /* event ATS_UNUSED */, void * /* data ATS_UNUSED */)
  {
    Log::preproc_thread_main((void *)&m_idx);
    return 0;
  }

  explicit LoggingPreprocContinuation(int idx) : Continuation(nullptr), m_idx(idx)
  {
    SET_HANDLER(&LoggingPreprocContinuation::mainEvent);
  }
};

struct LoggingFlushContinuation : public Continuation {
  int m_idx;

  int
  mainEvent(int /* event ATS_UNUSED */, void * /* data ATS_UNUSED */)
  {
    Log::flush_thread_main((void *)&m_idx);
    return 0;
  }

  explicit LoggingFlushContinuation(int idx) : Continuation(nullptr), m_idx(idx)
  {
    SET_HANDLER(&LoggingFlushContinuation::mainEvent);
  }
};

/*-------------------------------------------------------------------------
  Log::init_fields

  Define the available logging fields.
  This used to be part of the init() function, but now is separate so that
  standalone programs that do not require more services (e.g., that do not
  need to read records.yaml) can just call init_fields.

  Note that the LogFields are added to the list with the copy flag false so
  that the LogFieldList destructor will reclaim this memory.
  -------------------------------------------------------------------------*/
void
Log::init_fields()
{
  if (init_status & FIELDS_INITIALIZED) {
    return;
  }

  LogField *field;

  //
  // Initializes material to find a milestone name from their
  // name in a rapid manner.
  LogField::init_milestone_container();

  // client -> proxy fields
  field = new LogField("client_host_ip", "chi", LogField::IP, &LogAccess::marshal_client_host_ip, &LogAccess::unmarshal_ip_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("chi", field);

  field =
    new LogField("client_host_port", "chp", LogField::sINT, &LogAccess::marshal_client_host_port, &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("chp", field);

  field =
    new LogField("client_host_ip_hex", "chih", LogField::IP, &LogAccess::marshal_client_host_ip, &LogAccess::unmarshal_ip_to_hex);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("chih", field);

  // interface ip

  field =
    new LogField("host_interface_ip", "hii", LogField::IP, &LogAccess::marshal_host_interface_ip, &LogAccess::unmarshal_ip_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("hii", field);

  field = new LogField("host_interface_ip_hex", "hiih", LogField::IP, &LogAccess::marshal_host_interface_ip,
                       &LogAccess::unmarshal_ip_to_hex);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("hiih", field);
  // interface ip end
  field = new LogField("client_auth_user_name", "caun", LogField::STRING, &LogAccess::marshal_client_auth_user_name,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("caun", field);

  field = new LogField("plugin_identity_id", "piid", LogField::sINT, &LogAccess::marshal_plugin_identity_id,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("piid", field);

  field = new LogField("plugin_identity_tag", "pitag", LogField::STRING, &LogAccess::marshal_plugin_identity_tag,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pitag", field);

  field = new LogField("client_req_timestamp_sec", "cqts", LogField::sINT, &LogAccess::marshal_client_req_timestamp_sec,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqts", field);

  field = new LogField("client_req_timestamp_hex_sec", "cqth", LogField::sINT, &LogAccess::marshal_client_req_timestamp_sec,
                       &LogAccess::unmarshal_int_to_str_hex);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqth", field);

  field = new LogField("client_req_timestamp_squid", "cqtq", LogField::sINT, &LogAccess::marshal_client_req_timestamp_ms,
                       &LogAccess::unmarshal_ttmsf);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqtq", field);

  field = new LogField("client_req_timestamp_netscape", "cqtn", LogField::sINT, &LogAccess::marshal_client_req_timestamp_sec,
                       &LogAccess::unmarshal_int_to_netscape_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqtn", field);

  field = new LogField("client_req_timestamp_date", "cqtd", LogField::sINT, &LogAccess::marshal_client_req_timestamp_sec,
                       &LogAccess::unmarshal_int_to_date_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqtd", field);

  field = new LogField("client_req_timestamp_time", "cqtt", LogField::sINT, &LogAccess::marshal_client_req_timestamp_sec,
                       &LogAccess::unmarshal_int_to_time_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqtt", field);

  field = new LogField("client_req_http_method", "cqhm", LogField::STRING, &LogAccess::marshal_client_req_http_method,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqhm", field);

  field = new LogField("client_req_url", "cqu", LogField::STRING, &LogAccess::marshal_client_req_url, &LogAccess::unmarshal_str,
                       &LogAccess::set_client_req_url);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqu", field);

  field = new LogField("client_req_url", "pqu", LogField::STRING, &LogAccess::marshal_client_req_url, &LogAccess::unmarshal_str,
                       &LogAccess::set_client_req_url);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqu", field);

  field = new LogField("client_req_url_canonical", "cquc", LogField::STRING, &LogAccess::marshal_client_req_url_canon,
                       &LogAccess::unmarshal_str, &LogAccess::set_client_req_url_canon);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cquc", field);

  field = new LogField("client_req_url_canonical", "pquc", LogField::STRING, &LogAccess::marshal_client_req_url_canon,
                       &LogAccess::unmarshal_str, &LogAccess::set_client_req_url_canon);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pquc", field);

  field =
    new LogField("client_req_unmapped_url_canonical", "cquuc", LogField::STRING, &LogAccess::marshal_client_req_unmapped_url_canon,
                 &LogAccess::unmarshal_str, &LogAccess::set_client_req_unmapped_url_canon);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cquuc", field);

  field = new LogField("client_req_unmapped_url_path", "cquup", LogField::STRING, &LogAccess::marshal_client_req_unmapped_url_path,
                       &LogAccess::unmarshal_str, &LogAccess::set_client_req_unmapped_url_path);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cquup", field);

  field = new LogField("client_req_unmapped_url_host", "cquuh", LogField::STRING, &LogAccess::marshal_client_req_unmapped_url_host,
                       &LogAccess::unmarshal_str, &LogAccess::set_client_req_unmapped_url_host);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cquuh", field);

  field = new LogField("client_req_url_scheme", "cqus", LogField::STRING, &LogAccess::marshal_client_req_url_scheme,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqus", field);

  field = new LogField("client_req_url_scheme", "pqus", LogField::STRING, &LogAccess::marshal_client_req_url_scheme,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqus", field);

  field = new LogField("client_req_url_path", "cqup", LogField::STRING, &LogAccess::marshal_client_req_url_path,
                       &LogAccess::unmarshal_str, &LogAccess::set_client_req_url_path);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqup", field);

  field = new LogField("client_req_url_path", "pqup", LogField::STRING, &LogAccess::marshal_client_req_url_path,
                       &LogAccess::unmarshal_str, &LogAccess::set_client_req_url_path);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqup", field);

  field = new LogField("client_req_protocol_version", "cqpv", LogField::dINT, &LogAccess::marshal_client_req_protocol_version,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqpv", field);

  field = new LogField("server_req_protocol_version", "sqpv", LogField::dINT, &LogAccess::marshal_server_req_protocol_version,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("sqpv", field);

  field = new LogField("client_req_header_len", "cqhl", LogField::sINT, &LogAccess::marshal_client_req_header_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqhl", field);

  field = new LogField("client_req_squid_len", "cqql", LogField::sINT, &LogAccess::marshal_client_req_squid_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqql", field);

  field = new LogField("cache_lookup_url_canonical", "cluc", LogField::STRING, &LogAccess::marshal_cache_lookup_url_canon,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cluc", field);

  field = new LogField("client_sni_server_name", "cssn", LogField::STRING, &LogAccess::marshal_client_sni_server_name,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cssn", field);

  field = new LogField("client_ssl_cert_provided", "cscert", LogField::STRING, &LogAccess::marshal_client_provided_cert,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cscert", field);

  field = new LogField("proxy_ssl_cert_provided", "pscert", LogField::STRING, &LogAccess::marshal_proxy_provided_cert,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pscert", field);

  field = new LogField("process_uuid", "puuid", LogField::STRING, &LogAccess::marshal_process_uuid, &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("puuid", field);

  field =
    new LogField("process_snowflake_id", "psfid", LogField::STRING, &LogAccess::marshal_process_sfid, &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("psfid", field);

  field = new LogField("client_req_content_len", "cqcl", LogField::sINT, &LogAccess::marshal_client_req_content_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqcl", field);

  field = new LogField("client_req_tcp_reused", "cqtr", LogField::dINT, &LogAccess::marshal_client_req_tcp_reused,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqtr", field);

  field = new LogField("client_req_is_ssl", "cqssl", LogField::dINT, &LogAccess::marshal_client_req_is_ssl,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqssl", field);

  field = new LogField("client_req_ssl_reused", "cqssr", LogField::dINT, &LogAccess::marshal_client_req_ssl_reused,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqssr", field);

  field = new LogField("client_req_is_internal", "cqint", LogField::sINT, &LogAccess::marshal_client_req_is_internal,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqint", field);

  field = new LogField("client_req_mptcp", "cqmpt", LogField::sINT, &LogAccess::marshal_client_req_mptcp_state,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqmpt", field);

  field = new LogField("client_sec_protocol", "cqssv", LogField::STRING, &LogAccess::marshal_client_security_protocol,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqssv", field);

  field = new LogField("client_cipher_suite", "cqssc", LogField::STRING, &LogAccess::marshal_client_security_cipher_suite,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqssc", field);

  field =
    new LogField("client_curve", "cqssu", LogField::STRING, &LogAccess::marshal_client_security_curve, &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqssu", field);

  field =
    new LogField("client_group", "cqssg", LogField::STRING, &LogAccess::marshal_client_security_group, &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqssg", field);

  field =
    new LogField("client_sec_alpn", "cqssa", LogField::STRING, &LogAccess::marshal_client_security_alpn, &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqssa", field);

  Ptr<LogFieldAliasTable> finish_status_map = make_ptr(new LogFieldAliasTable);
  finish_status_map->init(N_LOG_FINISH_CODE_TYPES, LOG_FINISH_FIN, "FIN", LOG_FINISH_INTR, "INTR", LOG_FINISH_TIMEOUT, "TIMEOUT");

  field = new LogField("client_finish_status_code", "cfsc", LogField::sINT, &LogAccess::marshal_client_finish_status_code,
                       &LogAccess::unmarshal_finish_status, make_alias_map(finish_status_map));
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cfsc", field);

  field =
    new LogField("client_req_id", "crid", LogField::sINT, &LogAccess::marshal_client_req_id, &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("crid", field);

  field =
    new LogField("client_req_uuid", "cruuid", LogField::STRING, &LogAccess::marshal_client_req_uuid, &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cruuid", field);

  field = new LogField("client_rx_error_code", "crec", LogField::STRING, &LogAccess::marshal_client_rx_error_code,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("crec", field);

  field = new LogField("client_tx_error_code", "ctec", LogField::STRING, &LogAccess::marshal_client_tx_error_code,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ctec", field);

  field = new LogField("client_request_all_header_fields", "cqah", LogField::STRING,
                       &LogAccess::marshal_client_req_all_header_fields, &LogUtils::unmarshalMimeHdr);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cqah", field);

  // proxy -> client fields
  field = new LogField("proxy_resp_content_type", "psct", LogField::STRING, &LogAccess::marshal_proxy_resp_content_type,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("psct", field);

  field = new LogField("proxy_resp_reason_phrase", "prrp", LogField::STRING, &LogAccess::marshal_proxy_resp_reason_phrase,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("prrp", field);

  field = new LogField("proxy_resp_squid_len", "psql", LogField::sINT, &LogAccess::marshal_proxy_resp_squid_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("psql", field);

  field = new LogField("proxy_resp_content_len", "pscl", LogField::sINT, &LogAccess::marshal_proxy_resp_content_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pscl", field);

  field = new LogField("proxy_resp_content_len_hex", "psch", LogField::sINT, &LogAccess::marshal_proxy_resp_content_len,
                       &LogAccess::unmarshal_int_to_str_hex);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("psch", field);

  field = new LogField("proxy_resp_status_code", "pssc", LogField::sINT, &LogAccess::marshal_proxy_resp_status_code,
                       &LogAccess::unmarshal_http_status);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pssc", field);

  field = new LogField("proxy_resp_header_len", "pshl", LogField::sINT, &LogAccess::marshal_proxy_resp_header_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pshl", field);

  field = new LogField("proxy_finish_status_code", "pfsc", LogField::sINT, &LogAccess::marshal_proxy_finish_status_code,
                       &LogAccess::unmarshal_finish_status, make_alias_map(finish_status_map));
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pfsc", field);

  Ptr<LogFieldAliasTable> cache_code_map = make_ptr(new LogFieldAliasTable);
  cache_code_map->init(
    53, SquidLogCode::EMPTY, "UNDEFINED", SquidLogCode::TCP_HIT, "TCP_HIT", SquidLogCode::TCP_DISK_HIT, "TCP_DISK_HIT",
    SquidLogCode::TCP_MEM_HIT, "TCP_MEM_HIT", SquidLogCode::TCP_MISS, "TCP_MISS", SquidLogCode::TCP_EXPIRED_MISS,
    "TCP_EXPIRED_MISS", SquidLogCode::TCP_REFRESH_HIT, "TCP_REFRESH_HIT", SquidLogCode::TCP_REF_FAIL_HIT, "TCP_REFRESH_FAIL_HIT",
    SquidLogCode::TCP_REFRESH_MISS, "TCP_REFRESH_MISS", SquidLogCode::TCP_CLIENT_REFRESH, "TCP_CLIENT_REFRESH_MISS",
    SquidLogCode::TCP_IMS_HIT, "TCP_IMS_HIT", SquidLogCode::TCP_IMS_MISS, "TCP_IMS_MISS", SquidLogCode::TCP_SWAPFAIL,
    "TCP_SWAPFAIL_MISS", SquidLogCode::TCP_DENIED, "TCP_DENIED", SquidLogCode::TCP_WEBFETCH_MISS, "TCP_WEBFETCH_MISS",
    SquidLogCode::TCP_FUTURE_2, "TCP_FUTURE_2", SquidLogCode::TCP_HIT_REDIRECT, "TCP_HIT_REDIRECT", SquidLogCode::TCP_MISS_REDIRECT,
    "TCP_MISS_REDIRECT", SquidLogCode::TCP_HIT_X_REDIRECT, "TCP_HIT_X_REDIRECT", SquidLogCode::TCP_MISS_X_REDIRECT,
    "TCP_MISS_X_REDIRECT", SquidLogCode::UDP_HIT, "UDP_HIT", SquidLogCode::UDP_WEAK_HIT, "UDP_WEAK_HIT", SquidLogCode::UDP_HIT_OBJ,
    "UDP_HIT_OBJ", SquidLogCode::UDP_MISS, "UDP_MISS", SquidLogCode::UDP_DENIED, "UDP_DENIED", SquidLogCode::UDP_INVALID,
    "UDP_INVALID", SquidLogCode::UDP_RELOADING, "UDP_RELOADING", SquidLogCode::UDP_FUTURE_1, "UDP_FUTURE_1",
    SquidLogCode::UDP_FUTURE_2, "UDP_FUTURE_2", SquidLogCode::ERR_READ_TIMEOUT, "ERR_READ_TIMEOUT", SquidLogCode::ERR_LIFETIME_EXP,
    "ERR_LIFETIME_EXP", SquidLogCode::ERR_POST_ENTITY_TOO_LARGE, "ERR_POST_ENTITY_TOO_LARGE", SquidLogCode::ERR_NO_CLIENTS_BIG_OBJ,
    "ERR_NO_CLIENTS_BIG_OBJ", SquidLogCode::ERR_READ_ERROR, "ERR_READ_ERROR", SquidLogCode::ERR_CLIENT_ABORT, "ERR_CLIENT_ABORT",
    SquidLogCode::ERR_CLIENT_READ_ERROR, "ERR_CLIENT_READ_ERROR", SquidLogCode::ERR_CONNECT_FAIL, "ERR_CONNECT_FAIL",
    SquidLogCode::ERR_INVALID_REQ, "ERR_INVALID_REQ", SquidLogCode::ERR_UNSUP_REQ, "ERR_UNSUP_REQ", SquidLogCode::ERR_INVALID_URL,
    "ERR_INVALID_URL", SquidLogCode::ERR_NO_FDS, "ERR_NO_FDS", SquidLogCode::ERR_DNS_FAIL, "ERR_DNS_FAIL",
    SquidLogCode::ERR_NOT_IMPLEMENTED, "ERR_NOT_IMPLEMENTED", SquidLogCode::ERR_CANNOT_FETCH, "ERR_CANNOT_FETCH",
    SquidLogCode::ERR_NO_RELAY, "ERR_NO_RELAY", SquidLogCode::ERR_DISK_IO, "ERR_DISK_IO", SquidLogCode::ERR_ZERO_SIZE_OBJECT,
    "ERR_ZERO_SIZE_OBJECT", SquidLogCode::ERR_PROXY_DENIED, "ERR_PROXY_DENIED", SquidLogCode::ERR_WEBFETCH_DETECTED,
    "ERR_WEBFETCH_DETECTED", SquidLogCode::ERR_FUTURE_1, "ERR_FUTURE_1", SquidLogCode::ERR_LOOP_DETECTED, "ERR_LOOP_DETECTED",
    SquidLogCode::ERR_UNKNOWN, "ERR_UNKNOWN", SquidLogCode::TCP_CF_HIT, "TCP_CF_HIT");

  Ptr<LogFieldAliasTable> cache_subcode_map = make_ptr(new LogFieldAliasTable);
  cache_subcode_map->init(2, SquidSubcode::EMPTY, "NONE", SquidSubcode::NUM_REDIRECTIONS_EXCEEDED, "NUM_REDIRECTIONS_EXCEEDED");

  Ptr<LogFieldAliasTable> cache_hit_miss_map = make_ptr(new LogFieldAliasTable);
  cache_hit_miss_map->init(21, SQUID_HIT_RESERVED, "HIT", SQUID_HIT_LEVEL_1, "HIT_RAM", // Also SQUID_HIT_RAM
                           SQUID_HIT_LEVEL_2, "HIT_SSD",                                // Also SQUID_HIT_SSD
                           SQUID_HIT_LEVEL_3, "HIT_DISK",                               // Also SQUID_HIT_DISK
                           SQUID_HIT_LEVEL_4, "HIT_CLUSTER",                            // Also SQUID_HIT_CLUSTER
                           SQUID_HIT_LEVEL_5, "HIT_NET",                                // Also SQUID_HIT_NET
                           SQUID_HIT_LEVEL_6, "HIT_RWW", SQUID_HIT_LEVEL_7, "HIT_LEVEL_7", SQUID_HIT_LEVEL_8, "HIT_LEVEL_8",
                           SQUID_HIT_LEVEl_9, "HIT_LEVEL_9", SQUID_MISS_NONE, "MISS", SQUID_MISS_HTTP_NON_CACHE,
                           "MISS_HTTP_NON_CACHE", SQUID_MISS_HTTP_NO_DLE, "MISS_HTTP_NO_DLE", SQUID_MISS_HTTP_NO_LE,
                           "MISS_HTTP_NO_LE", SQUID_MISS_HTTP_CONTENT, "MISS_HTTP_CONTENT", SQUID_MISS_PRAGMA_NOCACHE,
                           "MISS_PRAGMA_NOCACHE", SQUID_MISS_PASS, "MISS_PASS", SQUID_MISS_PRE_EXPIRED, "MISS_PRE_EXPIRED",
                           SQUID_MISS_ERROR, "MISS_ERROR", SQUID_MISS_CACHE_BYPASS, "MISS_CACHE_BYPASS",
                           SQUID_HIT_MISS_INVALID_ASSIGNED_CODE, "INVALID_CODE");

  field = new LogField("cache_result_code", "crc", LogField::sINT, &LogAccess::marshal_cache_result_code,
                       &LogAccess::unmarshal_cache_code, make_alias_map(cache_code_map));
  global_field_list.add(field, false);
  field_symbol_hash.emplace("crc", field);

  // Reuse the unmarshalling code from crc
  field = new LogField("cache_result_subcode", "crsc", LogField::sINT, &LogAccess::marshal_cache_result_subcode,
                       &LogAccess::unmarshal_cache_code, make_alias_map(cache_subcode_map));
  global_field_list.add(field, false);
  field_symbol_hash.emplace("crsc", field);

  field = new LogField("cache_hit_miss", "chm", LogField::sINT, &LogAccess::marshal_cache_hit_miss,
                       &LogAccess::unmarshal_cache_hit_miss, make_alias_map(cache_hit_miss_map));
  global_field_list.add(field, false);
  field_symbol_hash.emplace("chm", field);

  field = new LogField("proxy_response_all_header_fields", "psah", LogField::STRING,
                       &LogAccess::marshal_proxy_resp_all_header_fields, &LogUtils::unmarshalMimeHdr);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("psah", field);

  // proxy -> server fields
  field = new LogField("proxy_req_header_len", "pqhl", LogField::sINT, &LogAccess::marshal_proxy_req_header_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqhl", field);

  field = new LogField("proxy_req_squid_len", "pqql", LogField::sINT, &LogAccess::marshal_proxy_req_squid_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqql", field);

  field = new LogField("proxy_req_content_len", "pqcl", LogField::sINT, &LogAccess::marshal_proxy_req_content_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqcl", field);

  field = new LogField("proxy_req_server_ip", "pqsi", LogField::IP, &LogAccess::marshal_proxy_req_server_ip,
                       &LogAccess::unmarshal_ip_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqsi", field);

  field = new LogField("proxy_req_server_port", "pqsp", LogField::sINT, &LogAccess::marshal_proxy_req_server_port,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqsp", field);

  field = new LogField("next_hop_ip", "nhi", LogField::IP, &LogAccess::marshal_next_hop_ip, &LogAccess::unmarshal_ip_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("nhi", field);

  field = new LogField("next_hop_port", "nhp", LogField::IP, &LogAccess::marshal_next_hop_port, &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("nhp", field);

  Ptr<LogFieldAliasTable> hierarchy_map = make_ptr(new LogFieldAliasTable);
  hierarchy_map->init(
    36, SquidHierarchyCode::EMPTY, "EMPTY", SquidHierarchyCode::NONE, "NONE", SquidHierarchyCode::DIRECT, "DIRECT",
    SquidHierarchyCode::SIBLING_HIT, "SIBLING_HIT", SquidHierarchyCode::PARENT_HIT, "PARENT_HIT",
    SquidHierarchyCode::DEFAULT_PARENT, "DEFAULT_PARENT", SquidHierarchyCode::SINGLE_PARENT, "SINGLE_PARENT",
    SquidHierarchyCode::FIRST_UP_PARENT, "FIRST_UP_PARENT", SquidHierarchyCode::NO_PARENT_DIRECT, "NO_PARENT_DIRECT",
    SquidHierarchyCode::FIRST_PARENT_MISS, "FIRST_PARENT_MISS", SquidHierarchyCode::LOCAL_IP_DIRECT, "LOCAL_IP_DIRECT",
    SquidHierarchyCode::FIREWALL_IP_DIRECT, "FIREWALL_IP_DIRECT", SquidHierarchyCode::NO_DIRECT_FAIL, "NO_DIRECT_FAIL",
    SquidHierarchyCode::SOURCE_FASTEST, "SOURCE_FASTEST", SquidHierarchyCode::SIBLING_UDP_HIT_OBJ, "SIBLING_UDP_HIT_OBJ",
    SquidHierarchyCode::PARENT_UDP_HIT_OBJ, "PARENT_UDP_HIT_OBJ", SquidHierarchyCode::PASSTHROUGH_PARENT, "PASSTHROUGH_PARENT",
    SquidHierarchyCode::SSL_PARENT_MISS, "SSL_PARENT_MISS", SquidHierarchyCode::INVALID_CODE, "INVALID_CODE",
    SquidHierarchyCode::TIMEOUT_DIRECT, "TIMEOUT_DIRECT", SquidHierarchyCode::TIMEOUT_SIBLING_HIT, "TIMEOUT_SIBLING_HIT",
    SquidHierarchyCode::TIMEOUT_PARENT_HIT, "TIMEOUT_PARENT_HIT", SquidHierarchyCode::TIMEOUT_DEFAULT_PARENT,
    "TIMEOUT_DEFAULT_PARENT", SquidHierarchyCode::TIMEOUT_SINGLE_PARENT, "TIMEOUT_SINGLE_PARENT",
    SquidHierarchyCode::TIMEOUT_FIRST_UP_PARENT, "TIMEOUT_FIRST_UP_PARENT", SquidHierarchyCode::TIMEOUT_NO_PARENT_DIRECT,
    "TIMEOUT_NO_PARENT_DIRECT", SquidHierarchyCode::TIMEOUT_FIRST_PARENT_MISS, "TIMEOUT_FIRST_PARENT_MISS",
    SquidHierarchyCode::TIMEOUT_LOCAL_IP_DIRECT, "TIMEOUT_LOCAL_IP_DIRECT", SquidHierarchyCode::TIMEOUT_FIREWALL_IP_DIRECT,
    "TIMEOUT_FIREWALL_IP_DIRECT", SquidHierarchyCode::TIMEOUT_NO_DIRECT_FAIL, "TIMEOUT_NO_DIRECT_FAIL",
    SquidHierarchyCode::TIMEOUT_SOURCE_FASTEST, "TIMEOUT_SOURCE_FASTEST", SquidHierarchyCode::TIMEOUT_SIBLING_UDP_HIT_OBJ,
    "TIMEOUT_SIBLING_UDP_HIT_OBJ", SquidHierarchyCode::TIMEOUT_PARENT_UDP_HIT_OBJ, "TIMEOUT_PARENT_UDP_HIT_OBJ",
    SquidHierarchyCode::TIMEOUT_PASSTHROUGH_PARENT, "TIMEOUT_PASSTHROUGH_PARENT",
    SquidHierarchyCode::TIMEOUT_TIMEOUT_SSL_PARENT_MISS, "TIMEOUT_TIMEOUT_SSL_PARENT_MISS",
    SquidHierarchyCode::INVALID_ASSIGNED_CODE, "INVALID_ASSIGNED_CODE");

  field = new LogField("proxy_hierarchy_route", "phr", LogField::sINT, &LogAccess::marshal_proxy_hierarchy_route,
                       &LogAccess::unmarshal_hierarchy, make_alias_map(hierarchy_map));
  global_field_list.add(field, false);
  field_symbol_hash.emplace("phr", field);

  field = new LogField("proxy_host_name", "phn", LogField::STRING, &LogAccess::marshal_proxy_host_name, &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("phn", field);

  field = new LogField("proxy_host_ip", "phi", LogField::IP, &LogAccess::marshal_proxy_host_ip, &LogAccess::unmarshal_ip_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("phi", field);

  field =
    new LogField("proxy_host_port", "php", LogField::sINT, &LogAccess::marshal_proxy_host_port, &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("php", field);

  field = new LogField("proxy_req_is_ssl", "pqssl", LogField::sINT, &LogAccess::marshal_proxy_req_is_ssl,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqssl", field);

  field = new LogField("proxy_req_ssl_reused", "pqssr", LogField::dINT, &LogAccess::marshal_proxy_req_ssl_reused,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqssr", field);

  field = new LogField("proxy_request_all_header_fields", "pqah", LogField::STRING, &LogAccess::marshal_proxy_req_all_header_fields,
                       &LogUtils::unmarshalMimeHdr);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("pqah", field);

  // server -> proxy fields
  field = new LogField("server_host_ip", "shi", LogField::IP, &LogAccess::marshal_server_host_ip, &LogAccess::unmarshal_ip_to_str);

  global_field_list.add(field, false);
  field_symbol_hash.emplace("shi", field);

  field =
    new LogField("server_host_name", "shn", LogField::STRING, &LogAccess::marshal_server_host_name, &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("shn", field);

  field = new LogField("server_resp_status_code", "sssc", LogField::sINT, &LogAccess::marshal_server_resp_status_code,
                       &LogAccess::unmarshal_http_status);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("sssc", field);

  field = new LogField("server_resp_content_len", "sscl", LogField::sINT, &LogAccess::marshal_server_resp_content_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("sscl", field);

  field = new LogField("server_resp_header_len", "sshl", LogField::sINT, &LogAccess::marshal_server_resp_header_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("sshl", field);

  field = new LogField("server_resp_squid_len", "ssql", LogField::sINT, &LogAccess::marshal_server_resp_squid_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ssql", field);

  field = new LogField("server_resp_http_version", "sshv", LogField::dINT, &LogAccess::marshal_server_resp_http_version,
                       &LogAccess::unmarshal_http_version);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("sshv", field);

  field = new LogField("server_resp_time", "stms", LogField::sINT, &LogAccess::marshal_server_resp_time_ms,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("stms", field);

  field = new LogField("server_resp_time_hex", "stmsh", LogField::sINT, &LogAccess::marshal_server_resp_time_ms,
                       &LogAccess::unmarshal_int_to_str_hex);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("stmsh", field);

  field = new LogField("server_resp_time_fractional", "stmsf", LogField::sINT, &LogAccess::marshal_server_resp_time_ms,
                       &LogAccess::unmarshal_ttmsf);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("stmsf", field);

  field = new LogField("server_resp_time_sec", "sts", LogField::sINT, &LogAccess::marshal_server_resp_time_s,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("sts", field);

  field = new LogField("server_transact_count", "sstc", LogField::sINT, &LogAccess::marshal_server_transact_count,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("sstc", field);

  field = new LogField("server_unavailable_retry_count", "surc", LogField::sINT, &LogAccess::marshal_server_unavailable_retry_count,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("surc", field);

  field = new LogField("server_simple_retry_count", "ssrc", LogField::sINT, &LogAccess::marshal_server_simple_retry_count,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ssrc", field);

  field = new LogField("server_connect_attempts", "sca", LogField::sINT, &LogAccess::marshal_server_connect_attempts,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("sca", field);

  field = new LogField("origin_response_all_header_fields", "ssah", LogField::STRING,
                       &LogAccess::marshal_server_resp_all_header_fields, &LogUtils::unmarshalMimeHdr);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ssah", field);

  field = new LogField("cached_resp_status_code", "csssc", LogField::sINT, &LogAccess::marshal_cache_resp_status_code,
                       &LogAccess::unmarshal_http_status);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("csssc", field);

  field = new LogField("cached_resp_content_len", "csscl", LogField::sINT, &LogAccess::marshal_cache_resp_content_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("csscl", field);

  field = new LogField("cached_resp_header_len", "csshl", LogField::sINT, &LogAccess::marshal_cache_resp_header_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("csshl", field);

  field = new LogField("cached_resp_squid_len", "cssql", LogField::sINT, &LogAccess::marshal_cache_resp_squid_len,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cssql", field);

  field = new LogField("cached_resp_http_version", "csshv", LogField::dINT, &LogAccess::marshal_cache_resp_http_version,
                       &LogAccess::unmarshal_http_version);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("csshv", field);

  field = new LogField("cache_origin_response_all_header_fields", "cssah", LogField::STRING,
                       &LogAccess::marshal_cache_resp_all_header_fields, &LogUtils::unmarshalMimeHdr);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cssah", field);

  field = new LogField("client_retry_after_time", "crat", LogField::sINT, &LogAccess::marshal_client_retry_after_time,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("crat", field);

  // cache write fields

  Ptr<LogFieldAliasTable> cache_write_code_map = make_ptr(new LogFieldAliasTable);
  cache_write_code_map->init(N_LOG_CACHE_WRITE_TYPES, LOG_CACHE_WRITE_NONE, "-", LOG_CACHE_WRITE_LOCK_MISSED, "WL_MISS",
                             LOG_CACHE_WRITE_LOCK_ABORTED, "INTR", LOG_CACHE_WRITE_ERROR, "ERR", LOG_CACHE_WRITE_COMPLETE, "FIN");
  field = new LogField("cache_write_result", "cwr", LogField::sINT, &LogAccess::marshal_cache_write_code,
                       &LogAccess::unmarshal_cache_write_code, make_alias_map(cache_write_code_map));
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cwr", field);

  field = new LogField("cache_write_transform_result", "cwtr", LogField::sINT, &LogAccess::marshal_cache_write_transform_code,
                       &LogAccess::unmarshal_cache_write_code, make_alias_map(cache_write_code_map));
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cwtr", field);

  // other fields

  field = new LogField("transfer_time_ms", "ttms", LogField::sINT, &LogAccess::marshal_transfer_time_ms,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ttms", field);

  field = new LogField("transfer_time_ms_hex", "ttmsh", LogField::sINT, &LogAccess::marshal_transfer_time_ms,
                       &LogAccess::unmarshal_int_to_str_hex);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ttmsh", field);

  field = new LogField("transfer_time_ms_fractional", "ttmsf", LogField::sINT, &LogAccess::marshal_transfer_time_ms,
                       &LogAccess::unmarshal_ttmsf);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ttmsf", field);

  field =
    new LogField("transfer_time_sec", "tts", LogField::sINT, &LogAccess::marshal_transfer_time_s, &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("tts", field);

  field = new LogField("file_size", "fsiz", LogField::sINT, &LogAccess::marshal_file_size, &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("fsiz", field);

  field = new LogField("client_connection_id", "ccid", LogField::sINT, &LogAccess::marshal_client_http_connection_id,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ccid", field);

  field = new LogField("client_transaction_id", "ctid", LogField::sINT, &LogAccess::marshal_client_http_transaction_id,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ctid", field);

  field = new LogField("cache_read_retry_attempts", "crra", LogField::dINT, &LogAccess::marshal_cache_read_retries,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("crra", field);

  field = new LogField("cache_write_retry_attempts", "cwra", LogField::dINT, &LogAccess::marshal_cache_write_retries,
                       &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cwra", field);

  field = new LogField("cache_collapsed_connection_success", "cccs", LogField::dINT,
                       &LogAccess::marshal_cache_collapsed_connection_success, &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("cccs", field);

  field = new LogField("client_transaction_priority_weight", "ctpw", LogField::sINT,
                       &LogAccess::marshal_client_http_transaction_priority_weight, &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ctpw", field);

  field = new LogField("client_transaction_priority_dependence", "ctpd", LogField::sINT,
                       &LogAccess::marshal_client_http_transaction_priority_dependence, &LogAccess::unmarshal_int_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ctpd", field);

  field = new LogField("proxy_protocol_version", "ppv", LogField::dINT, &LogAccess::marshal_proxy_protocol_version,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ppv", field);

  field = new LogField("proxy_protocol_src_ip", "pps", LogField::IP, &LogAccess::marshal_proxy_protocol_src_ip,
                       &LogAccess::unmarshal_ip_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ppsip", field);

  field = new LogField("proxy_protocol_dst_ip", "ppd", LogField::IP, &LogAccess::marshal_proxy_protocol_dst_ip,
                       &LogAccess::unmarshal_ip_to_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ppdip", field);

  field = new LogField("proxy_protocol_authority", "ppa", LogField::IP, &LogAccess::marshal_proxy_protocol_authority,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("ppa", field);

  field = new LogField("version_build_number", "vbn", LogField::STRING, &LogAccess::marshal_version_build_number,
                       &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("vbn", field);

  field = new LogField("version_string", "vs", LogField::STRING, &LogAccess::marshal_version_string, &LogAccess::unmarshal_str);
  global_field_list.add(field, false);
  field_symbol_hash.emplace("vs", field);

  init_status |= FIELDS_INITIALIZED;
}

/*-------------------------------------------------------------------------

  Initialization functions

  -------------------------------------------------------------------------*/
int
Log::handle_logging_mode_change(const char * /* name ATS_UNUSED */, RecDataT /* data_type ATS_UNUSED */,
                                RecData /* data ATS_UNUSED */, void * /* cookie ATS_UNUSED */)
{
  Dbg(dbg_ctl_log_config, "Enabled status changed");
  logging_mode_changed = true;
  return 0;
}

int
Log::handle_periodic_tasks_int_change(const char * /* name ATS_UNUSED */, RecDataT /* data_type ATS_UNUSED */, RecData data,
                                      void * /* cookie ATS_UNSED */)
{
  Dbg(dbg_ctl_log_periodic, "periodic task interval changed");
  if (data.rec_int <= 0) {
    periodic_tasks_interval = PERIODIC_TASKS_INTERVAL_FALLBACK;
    Error("new periodic tasks interval = %d is invalid, falling back to default = %d", (int)data.rec_int,
          PERIODIC_TASKS_INTERVAL_FALLBACK);
  } else {
    periodic_tasks_interval = static_cast<uint32_t>(data.rec_int);
    Dbg(dbg_ctl_log_periodic, "periodic task interval changed to %u", periodic_tasks_interval);
  }
  return REC_ERR_OKAY;
}

int
Log::handle_log_rotation_request()
{
  Dbg(dbg_ctl_log, "Request to reopen rotated log files.");
  log_rotate_signal_received = true;
  return 0;
}

void
Log::init(int flags)
{
  preproc_threads = 1;

  // store the configuration flags
  //
  config_flags = flags;

  // create the configuration object
  config = new LogConfig();
  ink_assert(config != nullptr);

  log_configid = configProcessor.set(log_configid, config);

  // set the logging_mode and read config variables if needed
  //
  if (config_flags & LOGCAT) {
    logging_mode = LOG_MODE_NONE;
  } else {
    LogConfig::register_stat_callbacks();

    config->read_configuration_variables();
    preproc_threads = config->preproc_threads;

    int val;
    val = RecGetRecordInt("proxy.config.log.logging_enabled").value_or(0);
    if (val < LOG_MODE_NONE || val > LOG_MODE_FULL) {
      logging_mode = LOG_MODE_FULL;
      Warning("proxy.config.log.logging_enabled has an invalid "
              "value, setting it to %d",
              logging_mode);
    } else {
      logging_mode = static_cast<LoggingMode>(val);
    }
    // periodic task interval are set on a per instance basis
    MgmtInt pti;
    pti = RecGetRecordInt("proxy.config.log.periodic_tasks_interval").value_or(0);
    if (pti <= 0) {
      Error("proxy.config.log.periodic_tasks_interval = %" PRId64 " is invalid", pti);
      Note("falling back to default periodic tasks interval = %d", PERIODIC_TASKS_INTERVAL_FALLBACK);
      periodic_tasks_interval = PERIODIC_TASKS_INTERVAL_FALLBACK;
    } else {
      periodic_tasks_interval = static_cast<uint32_t>(pti);
    }

    RecRegisterConfigUpdateCb("proxy.config.log.periodic_tasks_interval", &Log::handle_periodic_tasks_int_change, nullptr);
  }

  init_fields();
  if (!(config_flags & LOGCAT)) {
    RecRegisterConfigUpdateCb("proxy.config.log.logging_enabled", &Log::handle_logging_mode_change, nullptr);

    Dbg(dbg_ctl_log_config, "Log::init(): logging_mode = %d init status = %d", logging_mode, init_status);
    config->init();
    init_when_enabled();
  }
}

void
Log::init_when_enabled()
{
  // make sure the log config has been initialized
  ink_release_assert(config->initialized == true);

  if (!(init_status & FULLY_INITIALIZED)) {
    LogConfig::register_config_callbacks();

    // create the flush thread
    create_threads();
    eventProcessor.schedule_every(new PeriodicWakeup(preproc_threads, 1), HRTIME_SECOND, ET_CALL);

    init_status |= FULLY_INITIALIZED;
  }

  Note("logging initialized[%d], logging_mode = %d", init_status, logging_mode);
  if (dbg_ctl_log_config.on()) {
    config->display();
  }
}

void
Log::create_threads()
{
  char desc[64];
  preproc_notify = new EventNotify[preproc_threads];

  size_t stacksize;
  stacksize = RecGetRecordInt("proxy.config.thread.default.stacksize").value_or(0);

  // start the preproc threads
  //
  // no need for the conditional var since it will be relying on
  // on the event system.
  for (int i = 0; i < preproc_threads; i++) {
    Continuation *preproc_cont = new LoggingPreprocContinuation(i);
    snprintf(desc, sizeof(desc), "[LOG_PREPROC %d]", i);
    eventProcessor.spawn_thread(preproc_cont, desc, stacksize);
  }

  // Now, only one flush thread is supported.
  // TODO: Enable multiple flush threads, such as
  //       one flush thread per file.
  //
  flush_notify    = new EventNotify;
  flush_data_list = new InkAtomicList;

  ink_atomiclist_init(flush_data_list, "Logging flush buffer list", 0);
  Continuation *flush_cont = new LoggingFlushContinuation(0);
  eventProcessor.spawn_thread(flush_cont, "[LOG_FLUSH]", stacksize);
}

/*-------------------------------------------------------------------------
  Log::access

  Make an entry in the access log for the data supplied by the given
  LogAccess object.
  -------------------------------------------------------------------------*/

int
Log::access(LogAccess *lad)
{
  // See if transaction logging is disabled
  //
  if (!transaction_logging_enabled()) {
    return Log::SKIP;
  }

  ink_assert(init_status & FULLY_INITIALIZED);
  ink_assert(lad != nullptr);

  int         ret;
  static long sample = 1;
  long        this_sample;

  // See if we're sampling and it is not time for another sample
  //
  if (Log::config->sampling_frequency > 1) {
    this_sample = sample++;
    if (this_sample && this_sample % Log::config->sampling_frequency) {
      Dbg(dbg_ctl_log, "sampling, skipping this entry ...");
      Metrics::Counter::increment(log_rsb.event_log_access_skip);
      ret = Log::SKIP;
      goto done;
    } else {
      Dbg(dbg_ctl_log, "sampling, LOGGING this entry ...");
      sample = 1;
    }
  }

  if (Log::config->log_object_manager.get_num_objects() == 0) {
    Dbg(dbg_ctl_log, "no log objects, skipping this entry ...");
    Metrics::Counter::increment(log_rsb.event_log_access_skip);
    ret = Log::SKIP;
    goto done;
  }
  // initialize this LogAccess object and process
  //
  lad->init();
  ret = config->log_object_manager.log(lad);

done:
  return ret;
}

/*-------------------------------------------------------------------------
  Log::error

  Make an entry into the current error log.  For convenience, it is given in
  both variable argument (format, ...) and stdarg (format, va_list) forms.
  -------------------------------------------------------------------------*/

int
Log::error(const char *format, ...)
{
  va_list ap;
  int     ret;

  va_start(ap, format);
  ret = Log::va_error(format, ap);
  va_end(ap);

  return ret;
}

int
Log::va_error(const char *format, va_list ap)
{
  int ret_val = Log::SKIP;

  if (error_log) {
    ink_assert(format != nullptr);
    ret_val = error_log->va_log(nullptr, format, ap);

    switch (ret_val) {
    case Log::LOG_OK:
      Metrics::Counter::increment(log_rsb.event_log_error_ok);
      break;
    case Log::SKIP:
      Metrics::Counter::increment(log_rsb.event_log_error_skip);
      break;
    case Log::AGGR:
      Metrics::Counter::increment(log_rsb.event_log_error_aggr);
      break;
    case Log::FULL:
      Metrics::Counter::increment(log_rsb.event_log_error_full);
      break;
    case Log::FAIL:
      Metrics::Counter::increment(log_rsb.event_log_error_fail);
      break;
    default:
      ink_release_assert(!"Unexpected result");
    }

    return ret_val;
  }

  Metrics::Counter::increment(log_rsb.event_log_error_skip);

  return ret_val;
}

/*-------------------------------------------------------------------------
  Log::preproc_thread_main

  This function defines the functionality of the logging flush preprocess
  thread, whose purpose is to consume full LogBuffer objects, do some prepare
  work (such as convert to ascii), and then forward to flush thread.
  -------------------------------------------------------------------------*/

void *
Log::preproc_thread_main(void *args)
{
  int idx = *static_cast<int *>(args);

  Dbg(dbg_ctl_log_preproc, "log preproc thread is alive ...");

  Log::preproc_notify[idx].lock();

  while (true) {
    if (TSSystemState::is_event_system_shut_down()) {
      return nullptr;
    }
    LogConfig *current = static_cast<LogConfig *>(configProcessor.get(log_configid));

    if (likely(current)) {
      size_t buffers_preproced = current->log_object_manager.preproc_buffers(idx);

      // config->increment_space_used(bytes_to_disk);
      // TODO: the bytes_to_disk should be set to Log

      Dbg(dbg_ctl_log_preproc, "%zu buffers preprocessed from LogConfig %p (refcount=%d) this round", buffers_preproced, current,
          current->refcount());

      configProcessor.release(log_configid, current);
    }

    // wait for more work; a spurious wake-up is ok since we'll just
    // check the queue and find there is nothing to do, then wait
    // again.
    //
    Log::preproc_notify[idx].wait();
  }

  /* NOTREACHED */
  Log::preproc_notify[idx].unlock();
  return nullptr;
}

void *
Log::flush_thread_main(void * /* args ATS_UNUSED */)
{
  LogBuffer                                 *logbuffer;
  LogFlushData                              *fdata;
  ink_hrtime                                 now, last_time = 0;
  ssize_t                                    len, total_bytes;
  SLL<LogFlushData, LogFlushData::Link_link> link, invert_link;

  Log::flush_notify->lock();

  while (true) {
    if (TSSystemState::is_event_system_shut_down()) {
      return nullptr;
    }
    fdata = static_cast<LogFlushData *>(ink_atomiclist_popall(flush_data_list));

    // invert the list
    //
    link.head = fdata;
    while ((fdata = link.pop())) {
      invert_link.push(fdata);
    }

    // process each flush data
    //
    while ((fdata = invert_link.pop())) {
      char    *buf           = nullptr;
      ssize_t  bytes_written = 0;
      LogFile *logfile       = fdata->m_logfile.get();

      if (logfile->m_file_format == LOG_FILE_BINARY) {
        logbuffer                      = static_cast<LogBuffer *>(fdata->m_data);
        LogBufferHeader *buffer_header = logbuffer->header();

        buf         = reinterpret_cast<char *>(buffer_header);
        total_bytes = buffer_header->byte_count;

      } else if (logfile->m_file_format == LOG_FILE_ASCII || logfile->m_file_format == LOG_FILE_PIPE) {
        buf         = static_cast<char *>(fdata->m_data);
        total_bytes = fdata->m_len;

      } else {
        ink_release_assert(!"Unknown file format type!");
      }

      // make sure we're open & ready to write
      logfile->check_fd();
      if (!logfile->is_open()) {
        SiteThrottledWarning("File:%s was closed, have dropped (%ld) bytes.", logfile->get_name(), total_bytes);

        Metrics::Counter::increment(log_rsb.bytes_lost_before_written_to_disk, total_bytes);
        delete fdata;
        continue;
      }

      int logfilefd = logfile->get_fd();
      // This should always be true because we just checked it.
      ink_assert(logfilefd >= 0);

      // write *all* data to target file as much as possible
      //
      while (total_bytes - bytes_written) {
        if (Log::config->logging_space_exhausted) {
          Dbg(dbg_ctl_log, "logging space exhausted, failed to write file:%s, have dropped (%ld) bytes.", logfile->get_name(),
              (total_bytes - bytes_written));

          Metrics::Counter::increment(log_rsb.bytes_lost_before_written_to_disk, total_bytes - bytes_written);
          break;
        }

        len = ::write(logfilefd, &buf[bytes_written], total_bytes - bytes_written);

        if (len < 0) {
          SiteThrottledError("Failed to write log to %s: [tried %ld, wrote %ld, %s]", logfile->get_name(),
                             total_bytes - bytes_written, bytes_written, strerror(errno));

          Metrics::Counter::increment(log_rsb.bytes_lost_before_written_to_disk, total_bytes - bytes_written);
          break;
        }
        Dbg(dbg_ctl_log, "Successfully wrote some stuff to %s", logfile->get_name());
        bytes_written += len;
      }

      Metrics::Counter::increment(log_rsb.bytes_written_to_disk, bytes_written);

      if (logfile->m_log) {
        ink_atomic_increment(&logfile->m_log->m_bytes_written, bytes_written);
      }

      delete fdata;
    }

    // Time to work on periodic events??
    //
    now = ink_get_hrtime() / HRTIME_SECOND;
    if (now >= last_time + periodic_tasks_interval) {
      Dbg(dbg_ctl_log_preproc, "periodic tasks for %" PRId64, (int64_t)now);
      periodic_tasks(now);
      last_time = ink_get_hrtime() / HRTIME_SECOND;
    }

    // wait for more work; a spurious wake-up is ok since we'll just
    // check the queue and find there is nothing to do, then wait
    // again.
    //
    Log::flush_notify->wait();
  }

  /* NOTREACHED */
  Log::flush_notify->unlock();
  return nullptr;
}
