/** @file

  Abuse Shield Plugin - HTTP/2 error tracking and IP-based abuse detection.

  Uses the Udi "King of the Hill" algorithm for efficient, bounded-memory IP tracking.

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

#include <atomic>
#include <cinttypes>
#include <fstream>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unistd.h>
#include <vector>

#include "ts/ts.h"
#include "swoc/swoc_ip.h"
#include "swoc/IPRange.h"
#include "swoc/BufferWriter.h"
#include "swoc/bwf_ip.h"
#include "tsutil/DbgCtl.h"

#include "ip_tracker.h"

#include <yaml-cpp/yaml.h>

namespace
{
DbgCtl dbg_ctl{"abuse_shield"};

// Plugin name for logging and metrics
constexpr char PLUGIN_NAME[] = "abuse_shield";

// ============================================================================
// Metrics (ATS stats)
// ============================================================================
// Action counters
int stat_rules_matched        = -1; // Total times any rule matched
int stat_actions_blocked      = -1; // Total block actions executed
int stat_actions_closed       = -1; // Total close actions executed
int stat_actions_logged       = -1; // Total log actions executed
int stat_connections_rejected = -1; // Connections rejected at VCONN_START (blocked IPs)

// Tracker (UdiTable) metrics
int stat_tracker_events       = -1; // Total events processed (record_event calls)
int stat_tracker_slots_used   = -1; // Current slots in use (gauge)
int stat_tracker_contests     = -1; // Total contest attempts
int stat_tracker_contests_won = -1; // Contests won by new IP
int stat_tracker_evictions    = -1; // IPs evicted (score reached 0)

// Helper to convert IPAddr to string
std::string
ip_to_string(const swoc::IPAddr &ip)
{
  swoc::LocalBufferWriter<64> writer;
  writer.print("{}", ip);
  return std::string(writer.view());
}

// Default configuration values
constexpr size_t DEFAULT_SLOTS              = 50000;
constexpr size_t DEFAULT_PARTITIONS         = 64;
constexpr int    DEFAULT_BLOCK_DURATION_SEC = 300;

// ============================================================================
// Action types
// ============================================================================
enum class Action : uint8_t {
  LOG       = 1 << 0,
  BLOCK     = 1 << 1,
  CLOSE     = 1 << 2,
  DOWNGRADE = 1 << 3,
};

using ActionSet = uint8_t;

inline bool
has_action(ActionSet set, Action action)
{
  return (set & static_cast<uint8_t>(action)) != 0;
}

inline ActionSet
add_action(ActionSet set, Action action)
{
  return set | static_cast<uint8_t>(action);
}

// ============================================================================
// Rule configuration
// ============================================================================
struct RuleFilter {
  int h2_error_code{-1};       // Specific H2 error code (-1 = any)
  int h2_min_count{0};         // Minimum count of h2_error_code
  int h2_min_client_errors{0}; // Minimum total client errors
  int h2_min_server_errors{0}; // Minimum total server errors
  int max_successes{-1};       // Maximum successes (-1 = unlimited)
  int max_conn_rate{0};        // Max connections per window
  int max_req_rate{0};         // Max requests per window
};

struct Rule {
  std::string name;
  RuleFilter  filter;
  ActionSet   actions{0};
};

// ============================================================================
// Configuration
// ============================================================================
struct Config {
  size_t slots{DEFAULT_SLOTS};
  size_t partitions{DEFAULT_PARTITIONS};
  int    block_duration_sec{DEFAULT_BLOCK_DURATION_SEC};
  int    window_seconds{60}; // Default window period: 60 seconds

  std::vector<Rule>   rules;
  swoc::IPSpace<bool> trusted_ips;

  bool enabled{true};

  // Config file path
  std::string config_path;
};

// Global state
std::unique_ptr<abuse_shield::IPTracker> g_tracker;
std::shared_ptr<Config>                  g_config;
std::shared_mutex                        g_config_mutex; // Protects g_config pointer swaps

// ============================================================================
// Configuration parsing
// ============================================================================
std::vector<std::string>
parse_action_list(const YAML::Node &node)
{
  std::vector<std::string> actions;
  if (node.IsSequence()) {
    for (const auto &item : node) {
      actions.push_back(item.as<std::string>());
    }
  }
  return actions;
}

ActionSet
actions_from_strings(const std::vector<std::string> &strings)
{
  ActionSet set = 0;
  for (const auto &s : strings) {
    if (s == "log") {
      set = add_action(set, Action::LOG);
    } else if (s == "block") {
      set = add_action(set, Action::BLOCK);
    } else if (s == "close") {
      set = add_action(set, Action::CLOSE);
    } else if (s == "downgrade") {
      set = add_action(set, Action::DOWNGRADE);
    } else {
      TSError("[%s] Unknown action '%s' - ignoring", PLUGIN_NAME, s.c_str());
    }
  }
  return set;
}

bool
load_trusted_ips(Config &config, const std::string &path)
{
  std::ifstream file(path);
  if (!file.is_open()) {
    TSError("[%s] Failed to open trusted IPs file: %s", PLUGIN_NAME, path.c_str());
    return false;
  }

  std::string line;
  while (std::getline(file, line)) {
    // Skip comments and empty lines
    size_t start = line.find_first_not_of(" \t");
    if (start == std::string::npos || line[start] == '#') {
      continue;
    }

    std::string ip_str = line.substr(start);
    // Remove trailing whitespace/comments
    size_t end = ip_str.find_first_of(" \t#");
    if (end != std::string::npos) {
      ip_str = ip_str.substr(0, end);
    }

    if (!ip_str.empty()) {
      swoc::IPRange range;
      if (range.load(ip_str)) {
        config.trusted_ips.fill(range, true);
        Dbg(dbg_ctl, "Added trusted IP: %s", ip_str.c_str());
      } else {
        TSError("[%s] Invalid IP in trusted file: %s", PLUGIN_NAME, ip_str.c_str());
      }
    }
  }

  return true;
}

std::shared_ptr<Config>
parse_config(const std::string &path)
{
  auto config = std::make_shared<Config>();

  try {
    YAML::Node root = YAML::LoadFile(path);

    // IP reputation table settings
    if (root["ip_reputation"]) {
      auto ip_rep            = root["ip_reputation"];
      config->slots          = ip_rep["slots"].as<size_t>(DEFAULT_SLOTS);
      config->window_seconds = ip_rep["window_seconds"].as<int>(60);
    }

    // Blocking settings
    if (root["blocking"]) {
      auto blocking              = root["blocking"];
      config->block_duration_sec = blocking["duration_seconds"].as<int>(DEFAULT_BLOCK_DURATION_SEC);
    }

    // Trusted IPs file
    if (root["trusted_ips_file"]) {
      std::string trusted_path = root["trusted_ips_file"].as<std::string>();
      load_trusted_ips(*config, trusted_path);
    }

    // Rules
    if (root["rules"]) {
      for (const auto &rule_node : root["rules"]) {
        Rule rule;
        rule.name = rule_node["name"].as<std::string>("");

        if (rule_node["filter"]) {
          auto filter_node                 = rule_node["filter"];
          rule.filter.h2_error_code        = filter_node["h2_error"].as<int>(-1);
          rule.filter.h2_min_count         = filter_node["min_count"].as<int>(0);
          rule.filter.h2_min_client_errors = filter_node["min_client_errors"].as<int>(0);
          rule.filter.h2_min_server_errors = filter_node["min_server_errors"].as<int>(0);
          rule.filter.max_successes        = filter_node["max_successes"].as<int>(-1);
          rule.filter.max_conn_rate        = filter_node["max_conn_rate"].as<int>(0);
          rule.filter.max_req_rate         = filter_node["max_req_rate"].as<int>(0);
        }

        if (rule_node["action"]) {
          auto action_strings = parse_action_list(rule_node["action"]);
          rule.actions        = actions_from_strings(action_strings);
        }

        config->rules.push_back(std::move(rule));
        Dbg(dbg_ctl, "Loaded rule: %s", rule.name.c_str());
      }
    }

    config->enabled = root["enabled"].as<bool>(true);

  } catch (const YAML::Exception &e) {
    TSError("[%s] YAML parse error in %s at line %d, column %d: %s", PLUGIN_NAME, path.c_str(), e.mark.line + 1, e.mark.column + 1,
            e.what());
    return nullptr;
  }

  return config;
}

// ============================================================================
// Rule evaluation
// ============================================================================
bool
rule_matches(const Rule &rule, const abuse_shield::IPSlot &slot)
{
  const auto &filter = rule.filter;

  // Check specific H2 error count
  if (filter.h2_error_code >= 0 && filter.h2_min_count > 0) {
    if (filter.h2_error_code < static_cast<int>(abuse_shield::NUM_H2_ERROR_CODES)) {
      if (slot.h2_error_counts[filter.h2_error_code].load(std::memory_order_relaxed) < static_cast<uint16_t>(filter.h2_min_count)) {
        return false;
      }
    }
  }

  // Check total client errors
  if (filter.h2_min_client_errors > 0) {
    if (slot.client_errors.load(std::memory_order_relaxed) < static_cast<uint32_t>(filter.h2_min_client_errors)) {
      return false;
    }
  }

  // Check total server errors
  if (filter.h2_min_server_errors > 0) {
    if (slot.server_errors.load(std::memory_order_relaxed) < static_cast<uint32_t>(filter.h2_min_server_errors)) {
      return false;
    }
  }

  // Check max successes (for "pure attack" detection)
  if (filter.max_successes >= 0) {
    if (slot.successes.load(std::memory_order_relaxed) > static_cast<uint32_t>(filter.max_successes)) {
      return false;
    }
  }

  // Check connection rate
  if (filter.max_conn_rate > 0) {
    if (slot.conn_count.load(std::memory_order_relaxed) < static_cast<uint32_t>(filter.max_conn_rate)) {
      return false; // Under limit, rule doesn't match
    }
  }

  // Check request rate
  if (filter.max_req_rate > 0) {
    if (slot.req_count.load(std::memory_order_relaxed) < static_cast<uint32_t>(filter.max_req_rate)) {
      return false; // Under limit, rule doesn't match
    }
  }

  return true;
}

ActionSet
evaluate_rules(const abuse_shield::IPSlot &slot, const Config &config)
{
  for (const auto &rule : config.rules) {
    if (rule_matches(rule, slot)) {
      Dbg(dbg_ctl, "Rule matched: %s", rule.name.c_str());
      return rule.actions;
    }
  }
  return 0;
}

// ============================================================================
// Hook handlers
// ============================================================================

// Helper struct for error info
struct H2Errors {
  uint32_t cls{0};  // Error class (1 = connection, 2 = stream)
  uint64_t code{0}; // HTTP/2 error code
};

// Check if error code is typically client-caused
bool
is_client_caused_error(uint64_t error_code)
{
  // Client errors: PROTOCOL_ERROR(1), FLOW_CONTROL_ERROR(3), SETTINGS_TIMEOUT(4),
  //                STREAM_CLOSED(5), FRAME_SIZE_ERROR(6), CANCEL(8), COMPRESSION_ERROR(9)
  return (error_code == 1 || error_code == 3 || error_code == 4 || error_code == 5 || error_code == 6 || error_code == 8 ||
          error_code == 9);
}

// Called at connection start to block known abusive IPs
int
handle_vconn_start(TSCont /* contp */, TSEvent /* event */, void *edata)
{
  TSVConn vconn = static_cast<TSVConn>(edata);

  // Get config with shared lock
  std::shared_ptr<Config> config;
  {
    std::shared_lock lock(g_config_mutex);
    config = g_config;
  }

  if (!config || !config->enabled || !g_tracker) {
    TSVConnReenable(vconn);
    return TS_SUCCESS;
  }

  // Only handle SSL connections
  if (TSVConnIsSsl(vconn) == 0) {
    TSVConnReenable(vconn);
    return TS_SUCCESS;
  }

  // Get client IP
  sockaddr const *client_addr = TSNetVConnRemoteAddrGet(vconn);
  if (!client_addr) {
    TSVConnReenable(vconn);
    return TS_SUCCESS;
  }

  swoc::IPAddr ip(client_addr);

  // Check if trusted - skip all abuse checking for trusted IPs
  if (config->trusted_ips.find(ip) != config->trusted_ips.end()) {
    Dbg(dbg_ctl, "Skipping trusted IP: %s", ip_to_string(ip).c_str());
    TSVConnReenable(vconn);
    return TS_SUCCESS;
  }

  // Check if IP is currently blocked
  auto slot = g_tracker->find(ip);
  if (slot && slot->is_blocked()) {
    // IP is blocked - shutdown the connection
    Dbg(dbg_ctl, "Blocking connection from %s (blocked IP)", ip_to_string(ip).c_str());
    TSStatIntIncrement(stat_connections_rejected, 1);

    int fd = TSVConnFdGet(vconn);
    if (fd >= 0) {
      // Use shutdown() instead of close() because:
      // 1. close() would free the fd, but ATS still owns it
      // 2. shutdown() signals EOF to the peer, allowing graceful termination
      // 3. ATS will handle the actual close when the vconn is destroyed
      shutdown(fd, SHUT_RDWR);
      // Drain any pending data to ensure clean shutdown
      char buffer[4096];
      while (read(fd, buffer, sizeof(buffer)) > 0) {
        // drain pending data
      }
    }
  }

  TSVConnReenable(vconn);
  return TS_SUCCESS;
}

// Called on transaction close to track errors and successes
int
handle_txn_close(TSCont /* contp */, TSEvent /* event */, void *edata)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);

  // Get config with shared lock
  std::shared_ptr<Config> config;
  {
    std::shared_lock lock(g_config_mutex);
    config = g_config;
  }

  if (!config || !config->enabled || !g_tracker) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return TS_SUCCESS;
  }

  // Get client IP from session
  TSHttpSsn       ssn         = TSHttpTxnSsnGet(txnp);
  TSVConn         vconn       = TSHttpSsnClientVConnGet(ssn);
  sockaddr const *client_addr = TSNetVConnRemoteAddrGet(vconn);
  if (!client_addr) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return TS_SUCCESS;
  }

  swoc::IPAddr ip(client_addr);

  // Check if trusted - skip all abuse checking for trusted IPs
  if (config->trusted_ips.find(ip) != config->trusted_ips.end()) {
    Dbg(dbg_ctl, "Skipping trusted IP in txn_close: %s", ip_to_string(ip).c_str());
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return TS_SUCCESS;
  }

  // Get HTTP/2 errors
  H2Errors received_error; // Client received (stream error)
  H2Errors sent_error;     // Client sent (connection error)
  TSHttpTxnClientReceivedErrorGet(txnp, &received_error.cls, &received_error.code);
  TSHttpTxnClientSentErrorGet(txnp, &sent_error.cls, &sent_error.code);

  // Check for HTTP/2 errors
  bool     has_error       = false;
  uint64_t error_code      = 0;
  bool     is_client_error = true;

  // Stream-level error (class 2)
  if (received_error.cls == 2 && received_error.code != 0) {
    has_error       = true;
    error_code      = received_error.code;
    is_client_error = is_client_caused_error(error_code);
    Dbg(dbg_ctl, "Stream error from %s: code=%" PRIu64, ip_to_string(ip).c_str(), error_code);
  }

  // Connection-level error (class 1)
  if (sent_error.cls == 1 && sent_error.code != 0) {
    has_error       = true;
    error_code      = sent_error.code;
    is_client_error = is_client_caused_error(error_code);
    Dbg(dbg_ctl, "Connection error from %s: code=%" PRIu64, ip_to_string(ip).c_str(), error_code);
  }

  // Create or get slot for this IP (always, for rate limiting support).
  auto slot = g_tracker->record_event(ip, 1);
  if (!slot) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return TS_SUCCESS;
  }

  // Record the request count for rate limiting.
  slot->record_request();

  // Track errors if present.
  if (has_error) {
    TSStatIntIncrement(stat_tracker_events, 1);
    slot->record_h2_error(static_cast<uint8_t>(error_code), is_client_error);
  } else {
    // No error - check for success.
    TSMBuffer bufp;
    TSMLoc    hdr_loc;
    if (TSHttpTxnClientRespGet(txnp, &bufp, &hdr_loc) == TS_SUCCESS) {
      TSHttpStatus status = TSHttpHdrStatusGet(bufp, hdr_loc);
      TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);

      // Record success for 2xx responses.
      if (status >= 200 && status < 300) {
        slot->record_success();
      }
    }
  }

  // Evaluate rules on every request (for rate limiting and error-based rules).
  ActionSet actions = evaluate_rules(*slot, *config);

  if (actions != 0) {
    TSStatIntIncrement(stat_rules_matched, 1);

    // Log if requested.
    if (has_action(actions, Action::LOG)) {
      TSStatIntIncrement(stat_actions_logged, 1);
      TSError("[%s] IP=%s client_errors=%u server_errors=%u successes=%u req_count=%u", PLUGIN_NAME, ip_to_string(ip).c_str(),
              slot->client_errors.load(std::memory_order_relaxed), slot->server_errors.load(std::memory_order_relaxed),
              slot->successes.load(std::memory_order_relaxed), slot->req_count.load(std::memory_order_relaxed));
    }

    // Block if requested.
    if (has_action(actions, Action::BLOCK)) {
      TSStatIntIncrement(stat_actions_blocked, 1);
      uint64_t block_until =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() +
        (config->block_duration_sec * 1000);
      slot->block_until(block_until);
      Dbg(dbg_ctl, "Blocked IP %s for %d seconds", ip_to_string(ip).c_str(), config->block_duration_sec);
    }

    // Close connection if requested.
    if (has_action(actions, Action::CLOSE)) {
      TSStatIntIncrement(stat_actions_closed, 1);
      int fd = TSVConnFdGet(vconn);
      if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
        Dbg(dbg_ctl, "Closed connection from %s", ip_to_string(ip).c_str());
      }
    }
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return TS_SUCCESS;
}

// Sync UdiTable stats to ATS metrics
void
sync_tracker_stats()
{
  if (g_tracker) {
    TSStatIntSet(stat_tracker_slots_used, static_cast<int64_t>(g_tracker->slots_used()));
    TSStatIntSet(stat_tracker_contests, static_cast<int64_t>(g_tracker->contests()));
    TSStatIntSet(stat_tracker_contests_won, static_cast<int64_t>(g_tracker->contests_won()));
    TSStatIntSet(stat_tracker_evictions, static_cast<int64_t>(g_tracker->evictions()));
  }
}

// Handle plugin messages for dynamic config reload and data dump
int
handle_lifecycle_msg(TSCont /* contp */, TSEvent /* event */, void *edata)
{
  TSPluginMsg *msg = static_cast<TSPluginMsg *>(edata);

  std::string_view tag(msg->tag, strlen(msg->tag));

  if (tag == "abuse_shield.reload") {
    std::string config_path;
    {
      std::shared_lock lock(g_config_mutex);
      if (g_config) {
        config_path = g_config->config_path;
      }
    }
    Dbg(dbg_ctl, "Reloading configuration from %s", config_path.c_str());

    auto new_config = parse_config(config_path);
    if (new_config) {
      new_config->config_path = config_path; // Preserve config path for future reloads
      std::unique_lock lock(g_config_mutex);
      g_config = new_config;
      TSError("[%s] Configuration reloaded successfully", PLUGIN_NAME);
    } else {
      TSError("[%s] Configuration reload failed", PLUGIN_NAME);
    }
  } else if (tag == "abuse_shield.dump") {
    if (g_tracker) {
      sync_tracker_stats(); // Update ATS metrics before dump
      std::string dump = g_tracker->dump();
      TSError("[%s] Dump:\n%s", PLUGIN_NAME, dump.c_str());
    }
  } else if (tag == "abuse_shield.stats") {
    // Just sync stats without full dump
    sync_tracker_stats();
    TSError("[%s] Stats synced", PLUGIN_NAME);
  } else if (tag == "abuse_shield.reset") {
    if (g_tracker) {
      g_tracker->reset_metrics();
      TSError("[%s] Metrics reset", PLUGIN_NAME);
    }
  } else if (tag == "abuse_shield.enabled") {
    if (msg->data_size > 0) {
      bool             enabled = (static_cast<const char *>(msg->data)[0] == '1');
      std::unique_lock lock(g_config_mutex);
      if (g_config) {
        g_config->enabled = enabled;
        TSError("[%s] Plugin %s", PLUGIN_NAME, enabled ? "enabled" : "disabled");
      }
    }
  }

  return TS_SUCCESS;
}

} // anonymous namespace

// ============================================================================
// Plugin initialization
// ============================================================================

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;
  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] Plugin registration failed", PLUGIN_NAME);
    return;
  }

  // Parse command line arguments
  if (argc < 2) {
    TSError("[%s] Usage: abuse_shield.so <config_file>", PLUGIN_NAME);
    return;
  }

  std::string config_path = argv[1];

  // If path is relative, make it relative to config dir
  if (config_path[0] != '/') {
    config_path = std::string(TSConfigDirGet()) + "/" + config_path;
  }

  // Load configuration
  g_config = parse_config(config_path);
  if (!g_config) {
    TSError("[%s] Failed to load configuration from %s", PLUGIN_NAME, config_path.c_str());
    return;
  }

  // Store config path for reload
  g_config->config_path = config_path;

  // Create the IP tracker (uses fixed 64 partitions from UdiTable template)
  g_tracker = std::make_unique<abuse_shield::IPTracker>(g_config->slots);
  Dbg(dbg_ctl, "Created IP tracker with %zu slots", g_config->slots);

  // Create stats - action counters
  stat_rules_matched =
    TSStatCreate("abuse_shield.rules.matched", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  stat_actions_blocked =
    TSStatCreate("abuse_shield.actions.blocked", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  stat_actions_closed =
    TSStatCreate("abuse_shield.actions.closed", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  stat_actions_logged =
    TSStatCreate("abuse_shield.actions.logged", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  stat_connections_rejected =
    TSStatCreate("abuse_shield.connections.rejected", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);

  // Create stats - tracker (UdiTable) metrics
  stat_tracker_events =
    TSStatCreate("abuse_shield.tracker.events", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
  stat_tracker_slots_used =
    TSStatCreate("abuse_shield.tracker.slots_used", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_SUM);
  stat_tracker_contests =
    TSStatCreate("abuse_shield.tracker.contests", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_SUM);
  stat_tracker_contests_won =
    TSStatCreate("abuse_shield.tracker.contests_won", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_SUM);
  stat_tracker_evictions =
    TSStatCreate("abuse_shield.tracker.evictions", TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_SUM);

  // Register hooks
  TSCont vconn_cont = TSContCreate(handle_vconn_start, nullptr);
  TSHttpHookAdd(TS_VCONN_START_HOOK, vconn_cont);

  TSCont txn_cont = TSContCreate(handle_txn_close, nullptr);
  TSHttpHookAdd(TS_HTTP_TXN_CLOSE_HOOK, txn_cont);

  TSCont msg_cont = TSContCreate(handle_lifecycle_msg, nullptr);
  TSLifecycleHookAdd(TS_LIFECYCLE_MSG_HOOK, msg_cont);

  TSError("[%s] Plugin initialized with %zu slots, %zu rules", PLUGIN_NAME, g_config->slots, g_config->rules.size());
}
