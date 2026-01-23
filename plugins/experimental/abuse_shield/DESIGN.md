# Abuse Shield Plugin - Design Document

## Problem Statement

The January 16, 2026 HTTP/2 attack exposed critical gaps:

- `block_errors.so` only tracks 2 of 12 HTTP/2 error codes (missed 99% of attack)
- Attack IPs generated errors with **zero successful requests** - not currently detected
- No unified approach combining error tracking and rate limiting

---

## Features

### HTTP/2 Error Tracking

| Feature | Description |

|---------|-------------|

| **Client Errors** | Track protocol violations caused by clients - these trigger blocking |

| **Server Errors** | Track errors caused by server issues - log only, don't blame client |

| **Per-Error Limits** | Configure different thresholds per error code |

| **Total Limits** | Overall limit for all client/server errors combined |

| **Pure Attack Detection** | Detect IPs with client errors but zero successful requests |

### Rate Limiting

| Feature | Description |

|---------|-------------|

| **Per-IP Concurrent Connections** | Limit simultaneous connections from a single IP |

| **Per-IP Connection Rate** | Limit new connections per second per IP |

| **Per-IP Request Rate** | Limit requests per second per IP |

| **Server-wide Request Rate** | Global rate limit for entire server |

| **Latency-based Blocking** | Start blocking when server latency exceeds threshold |

### Actions (Independent, Combinable)

Each rule specifies a list of actions. All actions are independent:

| Action | Description |

|--------|-------------|

| `log` | Log the event with all tracked attributes to diags.log |

| `block` | Add IP to block list for configured duration |

| `close` | Close the current connection immediately |

| `downgrade` | Disable HTTP/2, force HTTP/1.1 for this IP |

| `rate_limit` | Return 429 Too Many Requests |

**Example combinations:**

- `action: [log]` - Monitor only
- `action: [block]` - Block without logging
- `action: [log, block]` - Log and block
- `action: [log, close]` - Log and close, but don't block future requests
- `action: [log, block, close]` - Full enforcement
- `action: [log, downgrade]` - Log and force HTTP/1.1

### Log Format

When `log` action is triggered, all tracked attributes are logged:

```
[abuse_shield] rule=<name> action=<actions> ip=<addr> \
  client_errors=<n> server_errors=<n> successes=<n> score=<n> \
  h2_errors=[0x01:<n>,0x09:<n>,...] \
  conn_concurrent=<n> conn_rate=<n>/s req_rate=<n>/s \
  blocked=<yes/no> blocked_until=<timestamp>
```

### Operations

| Feature | Description |

|---------|-------------|

| **Dynamic Config Reload** | `traffic_ctl plugin msg abuse_shield.reload` |

| **Data Dump** | `traffic_ctl plugin msg abuse_shield.dump` |

| **Reset Metrics** | `traffic_ctl plugin msg abuse_shield.reset` |

| **Trusted IP Bypass** | Never block IPs in trusted list |

---

## HTTP/2 Error Codes (RFC 9113)

| Code | Name | Type | CVE | Description |

|------|------|------|-----|-------------|

| 0x00 | NO_ERROR | - | - | Graceful shutdown |

| 0x01 | PROTOCOL_ERROR | **Client** | CVE-2019-9513, CVE-2019-9518 | Protocol violation |

| 0x02 | INTERNAL_ERROR | **Server** | - | Internal error |

| 0x03 | FLOW_CONTROL_ERROR | **Client** | CVE-2019-9511, CVE-2019-9517 | Flow control violation |

| 0x04 | SETTINGS_TIMEOUT | **Client** | CVE-2019-9515 | Settings ACK timeout |

| 0x05 | STREAM_CLOSED | **Client** | - | Frame on closed stream |

| 0x06 | FRAME_SIZE_ERROR | **Client** | - | Invalid frame size |

| 0x07 | REFUSED_STREAM | **Server** | - | Stream refused (at capacity) |

| 0x08 | CANCEL | **Client** | CVE-2023-44487 | Stream cancelled (Rapid Reset) |

| 0x09 | COMPRESSION_ERROR | **Client** | CVE-2016-1544 | HPACK compression error |

| 0x0a | CONNECT_ERROR | Either | - | CONNECT method failed |

| 0x0b | ENHANCE_YOUR_CALM | **Server** | - | Rate limit (server overwhelmed) |

**Jan 16 attack:** 0x01 (PROTOCOL_ERROR) and 0x09 (COMPRESSION_ERROR)

---

## Core Algorithm: Udi "King of the Hill"

Adapted from [carp/yahoo/YahooHotSpot.cc](dev/yahoo/ATSPlugins/carp/yahoo/YahooHotSpot.cc) (Patent 7533414).

### Data Structures

```
Hash Table:  IP -> Slot Index     (O(1) lookup)
Slot Array:  [0] [1] [2] ... [N-1]  (fixed size, stores IPSlot)
Contest Ptr: index into slot array  (advances after each contest)
```

### Request Flow

```
1. Event arrives from IP (error, connection, request)

2. Acquire mutex, then hash lookup: Is IP already tracked?

   YES -> slot = slots[lookup[IP]]
          slot.score += score_delta
          return shared_ptr<Data>     // caller updates Data atomically
          -> DONE

   NO  -> Contest for a slot:

          contest_idx = contest_ptr
          contest_ptr = (contest_ptr + 1) % N   // advance pointer

          if (slots[contest_idx].is_empty() || incoming_score > current_score):
              // NEW IP WINS - takes the slot
              if (!slot.is_empty()):
                  lookup.erase(slot.key)     // evict old key
                  evictions++
              slot.key = new_ip
              slot.score = incoming_score
              slot.data = make_shared<Data>()
              lookup[new_ip] = contest_idx
              return slot.data             // caller updates Data
          else:
              // NEW IP LOSES - existing slot survives but weakened
              slot.score--
              return nullptr               // new IP not tracked

3. Caller receives shared_ptr<Data> and updates atomically:

   if (data) {
       data->client_errors.fetch_add(1);
       data->h2_error_counts[error_code].fetch_add(1);
       // Check thresholds, take action if exceeded
   }
```

**Key implementation details:**

- `is_empty()` checks `!data` (not `score == 0`) - fixes stale key bug
- Returns `shared_ptr<Data>` so reference survives eviction
- Score is managed by UdiTable, not exposed to callers
- Data counters use atomics for lock-free updates after mutex released

### Why This Works

| Property | Benefit |
|----------|---------|
| **Rotating pointer** | Every slot eventually contested, no safe havens |
| **Score contest** | Hot IPs win, cold IPs evicted |
| **Success decrements** | Good behavior redeems an IP |
| **Fixed memory** | N slots = bounded memory, no growth |
| **Self-cleaning** | No cleanup thread needed |

**Why:** Fixed memory, self-cleaning, battle-tested in Yahoo CARP plugin.

---

## Data Structure: IPData

The IPData struct stores application-specific tracking data for each IP. The key and score
are managed internally by UdiTable.

```cpp
struct IPData {
    // Counters - atomic for concurrent access
    std::atomic<uint32_t> client_errors{0};   // Client-caused HTTP/2 errors
    std::atomic<uint32_t> server_errors{0};   // Server-caused HTTP/2 errors
    std::atomic<uint32_t> successes{0};       // Successful requests (2xx)

    std::atomic<uint16_t> h2_error_counts[16]{};  // Per error code (0x00-0x0f)

    // Rate limiting
    std::atomic<uint32_t> conn_count{0};      // Connections in window
    std::atomic<uint32_t> req_count{0};       // Requests in window

    // Timing
    std::atomic<uint64_t> window_start{0};    // Rate window start (epoch ms)
    std::atomic<uint64_t> last_seen{0};       // Last activity (epoch ms)
    std::atomic<uint64_t> blocked_until{0};   // Block expiration (epoch ms)
};
```

**Memory:** 50,000 slots ≈ 8.4 MB (includes shared_ptr overhead)

### Thread Safety - Current Implementation

The current UdiTable uses a **single global mutex** for simplicity:

```cpp
template<typename Key, typename Data, typename Hash = std::hash<Key>>
class UdiTable {
    mutable std::mutex mutex_;                        // Global lock
    std::unordered_map<Key, size_t, Hash> lookup_;   // Key → slot index
    std::vector<Slot> slots_;                         // Fixed-size slot array
    size_t contest_ptr_{0};                           // Rotating contest pointer

    struct Slot {
        Key key{};
        uint32_t score{0};
        std::shared_ptr<Data> data;                   // Safe reference

        bool is_empty() const { return !data; }       // Check data, not score
    };

public:
    // All operations acquire the global mutex
    std::shared_ptr<Data> find(Key const &key);
    std::shared_ptr<Data> process_event(Key const &key, uint32_t score_delta = 1);
};
```

**Key design decisions:**

| Aspect | Design | Rationale |
|--------|--------|-----------|
| **Locking** | Single `std::mutex` | Simple, correct, sufficient for most workloads |
| **Data ownership** | `shared_ptr<Data>` | Callers hold safe references even after eviction |
| **Empty check** | `!data` (not `score==0`) | Fixed bug where stale keys polluted lookup map |
| **Score** | Plain `uint32_t` | Protected by mutex, no atomic needed |

**Thread safety guarantees:**

| Operation | Locking | Contention |
|-----------|---------|------------|
| `find()` | Mutex lock | Serialized |
| `process_event()` | Mutex lock | Serialized |
| `contest()` | Called with mutex held | Serialized |
| IPData counter updates | Lock-free atomics | Cache-line only |

**Returned `shared_ptr<Data>` is safe:**
- Callers can use the Data even after releasing the table lock
- If the slot is evicted, the shared_ptr keeps the Data alive
- No use-after-free possible

### Benchmark Results: Locking Strategy Comparison

Benchmarked on zeus (16-core x86_64, GCC 15.2.1, Release -O3):

| Strategy | 16 Threads (Zipf) | Notes |
|----------|-------------------|-------|
| **A: Partitioned (16)** | **15.7M ops/sec** | 7x faster, recommended for high-throughput |
| D: Single mutex (current) | 2.2M ops/sec | Simple, sufficient for moderate load |
| C: shared_mutex | 2.0M ops/sec | Upgrade lock overhead hurts |
| B: Hybrid lock | 1.8M ops/sec | Two-phase locking adds overhead |

**Future optimization:** For very high throughput (>5M ops/sec), consider partitioned locking:

```cpp
// Partitioned design (not yet implemented)
template<typename Key, typename Data, size_t NumPartitions = 16>
class UdiTable_Partitioned {
    struct Partition {
        std::mutex mutex;
        std::unordered_map<Key, size_t> lookup;
        std::vector<Slot> slots;
        size_t contest_ptr{0};
    };
    std::array<Partition, NumPartitions> partitions_;

    // Key hash determines partition - threads hitting different partitions run in parallel
    size_t partition_for(Key const &key) { return hasher_(key) % NumPartitions; }
};
```

**Trade-off:** Partitioned design sacrifices global view (keys only compete within their partition) for 7x better throughput at high thread counts

---

## Configuration (YAML)

```yaml
ip_reputation:
  slots: 50000
  window_seconds: 60

blocking:
  duration_seconds: 300       # 5 minutes

trusted_ips_file: /etc/trafficserver/abuse_shield_trusted.txt

server_limits:
  max_req_rate: 10000
  max_latency_ms: 500
  window_seconds: 5

# All detection logic is unified under rules
# Rules evaluated in order, first match wins
rules:
  # --- H2 Client Errors (block/downgrade) ---
  - name: "protocol_error_flood"
    filter:
      h2_error: 0x01            # PROTOCOL_ERROR
      min_count: 10
    action: [log, block, close]
    # CVE-2019-9513, CVE-2019-9518

  - name: "compression_error_flood"
    filter:
      h2_error: 0x09            # COMPRESSION_ERROR
      min_count: 5
    action: [log, block, close]
    # CVE-2016-1544 (HPACK bomb)

  - name: "flow_control_error"
    filter:
      h2_error: 0x03            # FLOW_CONTROL_ERROR
      min_count: 5
    action: [log, block]
    # CVE-2019-9511, CVE-2019-9517

  - name: "frame_size_error"
    filter:
      h2_error: 0x06            # FRAME_SIZE_ERROR
      min_count: 5
    action: [log, block]

  - name: "cancel_flood"
    filter:
      h2_error: 0x08            # CANCEL (RST_STREAM)
      min_count: 50
    action: [log, downgrade]
    # CVE-2023-44487 (Rapid Reset)

  # --- H2 Server Errors (log only) ---
  - name: "internal_error"
    filter:
      h2_error: 0x02            # INTERNAL_ERROR
      min_count: 100
    action: [log]

  - name: "refused_stream"
    filter:
      h2_error: 0x07            # REFUSED_STREAM
      min_count: 100
    action: [log]

  - name: "enhance_your_calm"
    filter:
      h2_error: 0x0b            # ENHANCE_YOUR_CALM
      min_count: 10
    action: [log]

  # --- Aggregate Error Rules ---
  - name: "total_client_errors"
    filter:
      min_client_errors: 20
    action: [log, block, close]

  - name: "pure_attack"
    filter:
      min_client_errors: 10
      max_successes: 0          # Errors with zero successful requests
    action: [log, block, close]

  # --- Combined Conditions ---
  - name: "compression_pure_attack"
    filter:
      h2_error: 0x09            # COMPRESSION_ERROR
      min_count: 3
      max_successes: 0          # Combined: specific error + no successes
    action: [log, block, close]

  # --- Rate Limits ---
  - name: "conn_rate_flood"
    filter:
      max_conn_rate: 50
    action: [log, block]

  - name: "req_rate_flood"
    filter:
      max_req_rate: 500
    action: [log, block]

enabled: true
```

### Filter Fields

| Field | Description |
|-------|-------------|
| `h2_error` | Specific HTTP/2 error code (0x00-0x0d) |
| `min_count` | Minimum occurrences of that h2_error |
| `min_client_errors` | Total client-caused errors |
| `min_server_errors` | Total server-caused errors |
| `max_successes` | Maximum successful requests (0 = pure attack) |
| `max_conn_rate` | Max connections per second |
| `max_req_rate` | Max requests per second |

---

## File Structure

### Udi Algorithm (Reusable Library in tsutil)

```
include/tsutil/
└── UdiTable.h                    # Udi "King of the Hill" template class (header-only)

src/tsutil/
├── benchmark_UdiTable.cc         # Throughput benchmark with Zipf distribution
├── benchmark_UdiTable_locking.cc # Locking strategy comparison benchmark
└── unit_tests/
    └── test_UdiTable.cc          # Unit tests (contest, eviction, thread safety)
```

**Thread Safety:** Uses single `std::mutex` for all operations:
- Simple and correct
- All operations serialized
- Returns `shared_ptr<Data>` for safe access after mutex released
- Data counters use atomics for lock-free updates

### Plugin Files

```
plugins/experimental/abuse_shield/
├── CMakeLists.txt            # Build (links yaml-cpp, tsutil)
├── README.md                 # Usage docs
├── abuse_shield.cc           # Plugin entry, hooks, YAML parsing
├── abuse_shield.yaml         # Sample config
├── abuse_shield_trusted.txt  # Sample trusted IPs file
├── ip_tracker.h              # IPTracker using UdiTable<IPSlot>
└── ip_tracker.cc             # IPTracker implementation
```

### Tests

```
tests/gold_tests/pluginTest/abuse_shield/
├── abuse_shield.test.py      # Autest - end-to-end plugin tests
├── abuse_shield.yaml         # Test config
└── gold/                     # Expected output files
```

### Documentation (Sphinx)

```
doc/admin-guide/plugins/
└── abuse_shield.en.rst       # Admin guide documentation
```

### Trusted IPs File Format

```
# abuse_shield_trusted.txt
# One IP or CIDR per line, # for comments

# Localhost
127.0.0.1
::1

# Internal networks
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# Monitoring servers
# 203.0.113.50

# Load balancers
# 198.51.100.0/24
```

---

## Metrics

All metrics are prefixed with `abuse_shield.`

### Implemented Metrics (Phase 1)

These ATS stats are exposed via `traffic_ctl metric get abuse_shield.*`:

| Metric | Type | Description |
|--------|------|-------------|
| `rules.matched` | counter | Total times any rule filter condition was true |
| `actions.blocked` | counter | Total times block action executed (IP added to block list) |
| `actions.closed` | counter | Total times close action executed (connection shutdown) |
| `actions.logged` | counter | Total times log action executed |
| `connections.rejected` | counter | Connections rejected at VCONN_START (previously blocked IPs) |

**Example:**
```bash
traffic_ctl metric get abuse_shield.rules.matched
traffic_ctl metric get abuse_shield.actions.blocked
traffic_ctl metric get abuse_shield.connections.rejected
```

### Planned Metrics (Phase 2)

Per-rule counters (dynamic, one set for each rule defined in config):

| Metric | Type | Description |
|--------|------|-------------|
| `rule.<name>.matched` | counter | Times this specific rule matched |
| `rule.<name>.blocked` | counter | Times block action executed for this rule |

Per HTTP/2 error code counters:

| Metric | Type | Description |
|--------|------|-------------|
| `h2_error.0x01` | counter | PROTOCOL_ERROR count |
| `h2_error.0x09` | counter | COMPRESSION_ERROR count |
| `h2_error.client_total` | counter | Sum of all client-caused errors |
| `h2_error.server_total` | counter | Sum of all server-caused errors |

### Tracker (Udi Table) Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tracker.slots_total` | gauge | Configured number of slots |
| `tracker.slots_used` | gauge | Currently occupied slots |
| `tracker.slots_pct` | gauge | Utilization percentage (used/total * 100) |
| `tracker.contests` | counter | Total contest attempts (new IP vs existing slot) |
| `tracker.contests_won` | counter | Contests where new IP took the slot |
| `tracker.contests_lost` | counter | Contests where existing slot survived |
| `tracker.evictions` | counter | IPs evicted due to score reaching 0 |
| `tracker.lookups` | counter | Total hash table lookups |
| `tracker.lookup_hits` | counter | Lookups where IP was found |
| `tracker.lookup_misses` | counter | Lookups where IP was not found |
| `tracker.last_reset` | gauge | Epoch timestamp of last reset (or startup) |
| `tracker.seconds_since_reset` | gauge | Seconds elapsed since last reset (or startup) |

### Block List Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `blocked.current` | gauge | Number of IPs currently blocked |
| `blocked.added` | counter | Total IPs added to block list |
| `blocked.expired` | counter | Blocks that expired (duration elapsed) |
| `blocked.removed` | counter | Blocks manually removed (if supported) |

### Trusted IP Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trusted.checks` | counter | Times trusted IP list was checked |
| `trusted.bypassed` | counter | Requests from trusted IPs (skipped all rules) |

### Operational Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `config.reloads` | counter | Successful config reloads |
| `config.reload_errors` | counter | Failed config reload attempts |
| `config.last_reload` | gauge | Timestamp of last successful reload |
| `dumps` | counter | Data dump requests via plugin msg |
| `enabled` | gauge | 1 if plugin enabled, 0 if disabled |

### Key Metrics for Attack Monitoring

| Metric | What It Tells You |
|--------|-------------------|
| `tracker.slots_pct` | Are we running out of tracking capacity? (>80% = concern) |
| `h2_error.client_total` | Attack volume - how many errors are we seeing? |
| `h2_error.0x01` | PROTOCOL_ERROR count - key attack signature |
| `h2_error.0x09` | COMPRESSION_ERROR count - key attack signature |
| `actions.blocked` | Defense effectiveness - are we blocking attackers? |
| `blocked.current` | How many IPs are currently blocked? |
| `rule.<name>.matched` | Which rules are firing? Helps tune thresholds |
| `contests_won / contests` | Contest win ratio - high = aggressive new attackers |
| `tracker.evictions` | IPs being evicted - healthy table turnover |

### Example Grafana Queries

```promql
# Attack detection - spike in client H2 errors
rate(abuse_shield_h2_error_client_total[1m])

# Defense effectiveness - blocks per minute
rate(abuse_shield_actions_blocked[1m])

# Table utilization
abuse_shield_tracker_slots_pct

# Top firing rules
topk(5, rate(abuse_shield_rule_matched[5m]))

# Contest aggression (new attackers vs existing)
rate(abuse_shield_tracker_contests_won[1m]) / rate(abuse_shield_tracker_contests[1m])
```

---

## Implementation Phases

### Phase 1 (This PR)

**Core Library (tsutil):**
- UdiTable template class - reusable thread-safe Udi algorithm
- Unit tests for UdiTable (contest logic, eviction, thread safety)

**Plugin:**
- IPTracker using UdiTable<IPSlot>
- HTTP/2 error tracking (client vs server, per-error-code)
- Per-IP rate limiting (conn/sec, req/sec)
- Server-wide rate limiting
- Configurable blocking with duration
- Independent actions: log, block, close, downgrade
- Trusted IP bypass (from separate file)
- YAML config with dynamic reload
- Data dump via plugin message
- Reset metrics via plugin message (zero table-level metrics: contests, evictions)
- Metrics

**Testing:**
- Unit tests for UdiTable in tsutil
- Autests (gold_tests) for plugin end-to-end testing

**Documentation:**
- Sphinx docs (doc/admin-guide/plugins/abuse_shield.en.rst)

### Phase 2 (Future)

- Per-IP concurrent connection limits
- rate_limit action (return 429 Too Many Requests)
- Multiple Udi tables (separate tables per event type: H2 errors, TLS errors, connections, requests)
- Metrics cleanup (deduplicate with existing ATS metrics like proxy.process.http2.*)
- Cluster host sharing (sync blocked IPs across ATS hosts)
- MaxMind GeoIP integration
- Country/ASN blocklists