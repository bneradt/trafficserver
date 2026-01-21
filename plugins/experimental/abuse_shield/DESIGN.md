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
1. Error arrives from IP

2. Hash lookup: Is IP already tracked?

   YES -> slot = slots[hash[IP]]
          slot.score++
          slot.client_errors++
          slot.h2_error_counts[error_code]++
          -> Check thresholds, take action if exceeded
          -> DONE

   NO  -> Contest using pointer:

          contest_idx = contest_pointer
          contest_pointer = (contest_pointer + 1) % N   // advance

          if (incoming_score > slots[contest_idx].score):
              // NEW IP WINS - takes the slot
              old_ip = slots[contest_idx].addr
              hash.remove(old_ip)
              hash[new_ip] = contest_idx
              slots[contest_idx] = new IPSlot(new_ip, score=1)
          else:
              // NEW IP LOSES - slot survives but weakened
              slots[contest_idx].score--
              // new IP stays out of table

3. Success (2xx response) arrives from IP

   If IP in hash:
       slot.score--
       slot.successes++
       if (slot.score == 0):
           hash.remove(IP)     // evict - IP redeemed itself
```

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

## Data Structure: IPSlot (128 bytes)

```cpp
struct IPSlot {
    union { uint32_t ip4; uint8_t ip6[16]; } addr;
    uint8_t  addr_family;
    uint8_t  blocked;
    uint8_t  padding[2];
    
    // Use atomics for counters updated from multiple threads
    std::atomic<uint32_t> client_errors;    // Client-caused HTTP/2 errors
    std::atomic<uint32_t> server_errors;    // Server-caused HTTP/2 errors
    std::atomic<uint32_t> successes;        // Successful requests (2xx)
    std::atomic<uint32_t> score;            // Udi algorithm score
    
    std::atomic<uint16_t> h2_error_counts[16];  // Per error code (0x00-0x0f)
    
    std::atomic<uint32_t> conn_count;       // Connections in window
    std::atomic<uint32_t> req_count;        // Requests in window
    
    std::atomic<uint64_t> window_start;
    std::atomic<uint64_t> last_seen;
    std::atomic<uint64_t> blocked_until;
};
```

**Memory:** 50,000 slots = ~8.4 MB (recommended)

### Thread Safety - Minimized Locking

The Udi table uses **partitioned locking** to minimize contention:

```cpp
template<typename Slot, size_t NumPartitions = 64>
class UdiTable {
    // Partitioned hash table - each partition has its own lock
    struct Partition {
        std::unordered_map<IPAddr, size_t> lookup;
        mutable std::shared_mutex mutex;
        std::atomic<size_t> contest_ptr{0};  // Per-partition contest pointer
    };
    
    std::array<Partition, NumPartitions> partitions_;
    std::vector<Slot> slots_;    // Slots accessed via atomic operations
    
    size_t partition_for(const IPAddr& ip) const {
        return std::hash<IPAddr>{}(ip) % NumPartitions;
    }

public:
    // Lookup - only locks one partition (shared lock)
    Slot* find(const IPAddr& ip) const {
        auto& part = partitions_[partition_for(ip)];
        std::shared_lock lock(part.mutex);
        auto it = part.lookup.find(ip);
        return (it != part.lookup.end()) ? &slots_[it->second] : nullptr;
    }
    
    // Contest - only locks one partition (exclusive lock)
    void contest(const IPAddr& ip, int incoming_score);
};
```

**Partitioning Strategy:**

```
┌─────────────────────────────────────────────────────────────────┐
│  64 Partitions (each with own mutex)                            │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐     ┌─────────┐           │
│  │ Part 0  │ │ Part 1  │ │ Part 2  │ ... │ Part 63 │           │
│  │ lookup  │ │ lookup  │ │ lookup  │     │ lookup  │           │
│  │ mutex   │ │ mutex   │ │ mutex   │     │ mutex   │           │
│  │ contest │ │ contest │ │ contest │     │ contest │           │
│  │ ptr     │ │ ptr     │ │ ptr     │     │ ptr     │           │
│  └─────────┘ └─────────┘ └─────────┘     └─────────┘           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Slot Array (atomic fields, no lock needed for reads)           │
│  [0] [1] [2] ... [781] ... [49999]                              │
│       │           │                                             │
│       └───────────┴── Accessed via atomic operations            │
└─────────────────────────────────────────────────────────────────┘
```

**Slot fields use atomics (lock-free access):**

```cpp
struct IPSlot {
    // Identity (immutable once set, only changed during contest under lock)
    union { uint32_t ip4; uint8_t ip6[16]; } addr;
    std::atomic<uint8_t> addr_family{0};
    
    // Counters - lock-free atomic operations
    std::atomic<uint32_t> client_errors{0};
    std::atomic<uint32_t> server_errors{0};
    std::atomic<uint32_t> successes{0};
    std::atomic<uint32_t> score{0};
    std::atomic<uint16_t> h2_error_counts[16]{};
    
    // Timing
    std::atomic<uint64_t> last_seen{0};
    std::atomic<uint64_t> blocked_until{0};
    
    // Increment error - completely lock-free
    void record_error(uint8_t error_code) {
        client_errors.fetch_add(1, std::memory_order_relaxed);
        h2_error_counts[error_code].fetch_add(1, std::memory_order_relaxed);
        score.fetch_add(1, std::memory_order_relaxed);
        last_seen.store(now(), std::memory_order_relaxed);
    }
};
```

| Operation | Locking | Contention |
|-----------|---------|------------|
| `find()` | Shared lock on 1/64 partitions | Very low |
| `record_event()` on existing IP | Lock-free atomics | None |
| `contest()` | Exclusive lock on 1/64 partitions | Low |
| Counter reads | Lock-free | None |

**Benefits:**
- 64 partitions = 64x less contention than single lock
- Slot updates are lock-free (atomic operations)
- Different IPs in different partitions never contend
- Read operations (most common) are very fast

---

## Configuration (YAML)

```yaml
tracker:
  slots: 50000
  window_seconds: 1

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
src/tsutil/
├── include/tsutil/
│   └── UdiTable.h            # Udi "King of the Hill" template class
├── src/
│   └── UdiTable.cc           # Implementation (if needed, mostly header-only)
└── unit_tests/
    └── test_UdiTable.cc      # Unit tests for Udi algorithm
```

**Thread Safety:** Uses `std::shared_mutex` for read-write locking:
- Multiple readers (lookups) can proceed concurrently
- Single writer (contest/update) blocks other writers
- Atomic operations for counters where possible

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

### Rule Metrics

Per-rule counters (one set for each rule defined in config):

| Metric | Type | Description |
|--------|------|-------------|
| `rule.<name>.matched` | counter | Times rule filter condition was true |
| `rule.<name>.blocked` | counter | Times block action executed |
| `rule.<name>.closed` | counter | Times close action executed |
| `rule.<name>.downgraded` | counter | Times downgrade action executed |
| `rule.<name>.logged` | counter | Times log action executed |

Example with rules from config:
```
abuse_shield.rule.protocol_error_flood.matched
abuse_shield.rule.protocol_error_flood.blocked
abuse_shield.rule.compression_error_flood.matched
abuse_shield.rule.pure_attack.matched
abuse_shield.rule.pure_attack.blocked
abuse_shield.rule.conn_rate_flood.matched
...
```

### HTTP/2 Error Metrics

Per-error-code counters:

| Metric | Error Code | Type | Description |
|--------|------------|------|-------------|
| `h2_error.0x00` | NO_ERROR | counter | Graceful shutdown |
| `h2_error.0x01` | PROTOCOL_ERROR | counter | Protocol violation (Client) |
| `h2_error.0x02` | INTERNAL_ERROR | counter | Internal error (Server) |
| `h2_error.0x03` | FLOW_CONTROL_ERROR | counter | Flow control violation (Client) |
| `h2_error.0x04` | SETTINGS_TIMEOUT | counter | Settings ACK timeout (Client) |
| `h2_error.0x05` | STREAM_CLOSED | counter | Frame on closed stream (Client) |
| `h2_error.0x06` | FRAME_SIZE_ERROR | counter | Invalid frame size (Client) |
| `h2_error.0x07` | REFUSED_STREAM | counter | Stream refused (Server) |
| `h2_error.0x08` | CANCEL | counter | Stream cancelled (Client) |
| `h2_error.0x09` | COMPRESSION_ERROR | counter | HPACK error (Client) |
| `h2_error.0x0a` | CONNECT_ERROR | counter | CONNECT failed |
| `h2_error.0x0b` | ENHANCE_YOUR_CALM | counter | Rate limit (Server) |
| `h2_error.0x0c` | INADEQUATE_SECURITY | counter | TLS error (Server) |
| `h2_error.0x0d` | HTTP_1_1_REQUIRED | counter | Use HTTP/1.1 (Server) |

Aggregate counters:

| Metric | Type | Description |
|--------|------|-------------|
| `h2_error.client_total` | counter | Sum of all client-caused errors |
| `h2_error.server_total` | counter | Sum of all server-caused errors |
| `h2_error.total` | counter | Sum of all H2 errors |

### Action Totals

Aggregate action counters across all rules:

| Metric | Type | Description |
|--------|------|-------------|
| `actions.blocked` | counter | Total IPs added to block list |
| `actions.closed` | counter | Total connections closed |
| `actions.downgraded` | counter | Total connections downgraded to HTTP/1.1 |
| `actions.logged` | counter | Total events logged |

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