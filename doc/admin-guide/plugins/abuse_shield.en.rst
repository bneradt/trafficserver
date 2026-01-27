.. Licensed to the Apache Software Foundation (ASF) under one
   or more contributor license agreements.  See the NOTICE file
   distributed with this work for additional information
   regarding copyright ownership.  The ASF licenses this file
   to you under the Apache License, Version 2.0 (the
   "License"); you may not use this file except in compliance
   with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.


   .. include:: ../../common.defs

.. _admin-plugins-abuse_shield:

Abuse Shield Plugin
*******************

Description
===========

The ``abuse_shield`` plugin provides consolidated abuse protection for Apache
Traffic Server, providing IP-based abuse detection for high rates of
connections, requests, and various errors.

Key features:

* YAML based configuration, dynamically reloadable via ``traffic_ctl``.
* IP-based abuse detection for both high rates of connections and requests.
* IP allow-listing for trusted IPs (such as in-network IPs).
* Detects "pure attacks" (many errors with zero successful requests).
* **Per-IP request rate limiting** - Block IPs exceeding request thresholds.
* **Per-IP connection rate limiting** - Block IPs opening too many connections.
* A configurable variety of actions per rule, such as logging, blocking,
  connection closing, and protocol downgrading to HTTP/1.1.

Algorithm
=========

The plugin uses an enhanced "Udi King of the Hill" algorithm for IP tracking,
based on the Udi algorithm described in the now expired US Patent 7533414B1:

https://patents.google.com/patent/US7533414B1

Key enhancements over the original algorithm:

**EWMA Scoring**
  IP scores use Exponential Weighted Moving Average (EWMA) decay. Scores naturally
  decrease over time, so inactive IPs become easier to evict while active abusers
  maintain high scores. The decay rate is controlled by ``window_seconds``.

**Multi-Probe Eviction**
  When the table is full and a new IP needs a slot, the algorithm probes 4 random
  slots and evicts the one with the lowest decayed score. This "power of N choices"
  approach significantly improves eviction quality compared to single-slot selection.

**Window-Based Expiration**
  IPs that haven't been seen for longer than ``window_seconds`` are automatically
  considered stale and can be evicted without score comparison. This prevents
  "zombie" entries from occupying slots indefinitely.

This algorithm uses a fixed-size table configured by ``slots``.

Installation
============

Build with CMake::

    cmake .. -DENABLE_ABUSE_SHIELD=ON
    cmake --build . --target abuse_shield

Configuration
=============

To enable the plugin, add it to :file:`plugin.config`::

    abuse_shield.so abuse_shield.yaml

Create the configuration file :file:`abuse_shield.yaml` in the config directory.

Configuration File Format
-------------------------

The configuration uses YAML format with the following structure:

.. code-block:: yaml

    global:
      ip_tracking:
        slots: 50000                    # Number of IP tracking slots
        window_decay_seconds: 60        # EWMA decay window (default 60s)
        window_expiration_seconds: 60   # Staleness expiration window (default 60s)

      blocking:
        duration_seconds: 300     # How long to block abusive IPs

      trusted_ips_file: /etc/trafficserver/abuse_shield_trusted.yaml

    rules:
      - name: "protocol_error_flood"
        filter:
          h2_error: 0x01        # PROTOCOL_ERROR
          min_count: 10
        action: [log, block, close]

      - name: "pure_attack"
        filter:
          min_client_errors: 10
          max_successes: 0
        action: [log, block, close]

    enabled: true

IP Tracking Settings
--------------------

The ``ip_tracking`` section controls the IP tracking table behavior:

============================= ======= ============================================================
Setting                       Default Description
============================= ======= ============================================================
``slots``                     50000   Maximum number of IPs to track simultaneously. Memory usage
                                      is approximately 128 bytes per slot.
``window_decay_seconds``      60      Controls the EWMA decay rate for IP scores. Scores decay
                                      exponentially over time. After this many seconds, an
                                      inactive IP's score will have decayed to approximately
                                      37% (1/e) of its original value.
``window_expiration_seconds`` 60      Controls staleness expiration. IPs that haven't been seen
                                      for longer than this many seconds are automatically
                                      considered stale and can be evicted without score
                                      comparison, even if they had high scores previously.
============================= ======= ============================================================

**Tuning the decay window** (``window_decay_seconds``):

* **Shorter decay** (e.g., 30s): Scores decay faster, so brief pauses in attack
  traffic may allow the attacker to "reset" their score. Better for detecting
  burst attacks.

* **Longer decay** (e.g., 300s): Scores persist longer, better for detecting
  slow, sustained attacks.

**Tuning the expiration window** (``window_expiration_seconds``):

* **Shorter expiration** (e.g., 30s): IPs are evicted sooner, freeing slots for
  new IPs. Good when you have many unique IPs.

* **Longer expiration** (e.g., 300s): IPs remain tracked longer even when idle.
  Useful if attackers pause and resume attacks.

In most cases, setting both to the same value is appropriate.

Rule Filters
------------

Each rule has a ``filter`` section that defines when the rule matches:

====================== ===========================================================
Filter                 Description
====================== ===========================================================
``h2_error``           Specific HTTP/2 error code (0x00-0x0f)
``min_count``          Minimum count of the specific ``h2_error``
``min_client_errors``  Total client-caused HTTP/2 errors
``min_server_errors``  Total server-caused HTTP/2 errors
``max_successes``      Maximum successful requests (use 0 for "pure attack" detection)
``max_conn_rate``      Maximum connections per rate window
``max_req_rate``       Maximum requests per rate window
====================== ===========================================================

Actions
-------

Each rule has an ``action`` list with one or more actions:

============== ============================================================
Action         Description
============== ============================================================
``log``        Log the abuse detection with all tracked attributes
``block``      Block the IP for ``blocking.duration_seconds``
``close``      Immediately close the connection
``downgrade``  Downgrade to HTTP/1.1 (future feature)
============== ============================================================

HTTP/2 Error Codes
------------------

The plugin tracks all HTTP/2 error codes. Client-caused errors are typically
indicative of abuse, while server-caused errors usually indicate server issues.

============ ====================== ============= ==================================
Code         Name                   Typical Cause CVEs
============ ====================== ============= ==================================
0x01         PROTOCOL_ERROR         Client        CVE-2019-9513, CVE-2019-9518
0x02         INTERNAL_ERROR         Server
0x03         FLOW_CONTROL_ERROR     Client        CVE-2019-9511, CVE-2019-9517
0x04         SETTINGS_TIMEOUT       Client
0x05         STREAM_CLOSED          Client
0x06         FRAME_SIZE_ERROR       Client
0x07         REFUSED_STREAM         Server
0x08         CANCEL (RST_STREAM)    Client        CVE-2023-44487 (Rapid Reset)
0x09         COMPRESSION_ERROR      Client        CVE-2016-1544 (HPACK bomb)
0x0a         CONNECT_ERROR          Either
0x0b         ENHANCE_YOUR_CALM      Server
0x0c         INADEQUATE_SECURITY    Either
0x0d         HTTP_1_1_REQUIRED      Server
============ ====================== ============= ==================================

Rate Limiting
-------------

The plugin supports per-IP rate limiting for both connections and requests.
Rate counters use EWMA (Exponential Weighted Moving Average) scoring, which
provides smooth decay over the ``window_seconds`` time period. This is more
robust than simple sliding windows because it doesn't have abrupt "cliff"
effects when events age out.

**Connection Rate Limiting** (``max_conn_rate``):

Tracks new connections per IP within the time window. Useful for detecting
connection floods or slowloris-style attacks.

**Request Rate Limiting** (``max_req_rate``):

Tracks HTTP requests per IP within the time window. Useful for detecting
aggressive scrapers, API abuse, or application-layer DDoS.

Example rate limiting rules:

.. code-block:: yaml

    rules:
      # Block IPs making more than 500 requests per minute
      - name: "high_request_rate"
        filter:
          max_req_rate: 500
        action: [log, block]

      # Block IPs opening more than 50 connections per minute
      - name: "high_connection_rate"
        filter:
          max_conn_rate: 50
        action: [log, block, close]

Trusted IPs
-----------

Create a YAML file containing a sequence of trusted IP addresses under the
``trusted_ips`` key. The following IP formats are supported:

======================= ===========================================================
Example                 Effect
======================= ===========================================================
``10.0.2.123``          Exempt a single IP Address.
``10.0.3.1-10.0.3.254`` Exempt a range of IP addresses.
``10.0.4.0/24``         Exempt a range of IP addresses specified by CIDR notation.
======================= ===========================================================

Example :file:`abuse_shield_trusted.yaml`:

.. code-block:: yaml

    trusted_ips:
      # Localhost
      - 127.0.0.1
      - "::1"

      # Internal networks
      - 10.0.0.0/8
      - 192.168.0.0/16

      # Monitoring servers
      - 203.0.113.50

      # Range example
      - 172.16.0.1-172.16.0.100

Runtime Control
===============

The plugin supports runtime control via ``traffic_ctl plugin msg``:

Reload Configuration
--------------------

The plugin supports dynamic configuration reload without requiring an ATS restart.
Reload the YAML configuration at runtime::

    traffic_ctl plugin msg abuse_shield.reload

This reloads all settings including rules, blocking duration, and trusted IPs.
Tracked IP data and current block states are preserved across reloads.

Dump Tracked IPs
----------------

Dump all currently tracked IPs and their statistics to the error log::

    traffic_ctl plugin msg abuse_shield.dump

The dump output includes:

* Last reset timestamp and age (e.g., "2026-01-21 14:32:05 (2h 15m ago)")
* Slots used vs total
* Contest statistics (total contests, wins)
* Eviction count
* Per-IP details: client errors, server errors, successes, score, block status

Reset Metrics
-------------

Reset the table-level metrics (contests, evictions) without removing tracked IPs::

    traffic_ctl plugin msg abuse_shield.reset

This is useful for getting clean metrics after a known event or for periodic monitoring.

Enable/Disable
--------------

Enable or disable the plugin at runtime::

    traffic_ctl plugin msg abuse_shield.enabled 1
    traffic_ctl plugin msg abuse_shield.enabled 0

Metrics
=======

The plugin exposes ATS statistics for monitoring. View with::

    traffic_ctl metric get abuse_shield.*

Available metrics:

======================================= =========================================================
Metric                                  Description
======================================= =========================================================
``abuse_shield.rules.matched``          Total times any rule filter condition was true
``abuse_shield.actions.blocked``        Total times block action executed (IP added to blocklist)
``abuse_shield.actions.closed``         Total times close action executed (connection shutdown)
``abuse_shield.actions.logged``         Total times log action executed
``abuse_shield.connections.rejected``   Connections rejected at start (previously blocked IPs)
======================================= =========================================================

These metrics are useful for:

* Monitoring attack detection in production
* Alerting on sudden spikes in blocked IPs
* Verifying rules are triggering as expected
* Measuring the effectiveness of abuse protection

Example Configuration
=====================

Basic protection against HTTP/2 attacks:

.. code-block:: yaml

    global:
      ip_tracking:
        slots: 50000
        window_decay_seconds: 60
        window_expiration_seconds: 60

      blocking:
        duration_seconds: 300

      trusted_ips_file: /etc/trafficserver/abuse_shield_trusted.yaml

    rules:
      # Block protocol errors (CVE-2019-9513, CVE-2019-9518)
      - name: "protocol_error_flood"
        filter:
          h2_error: 0x01
          min_count: 10
        action: [log, block, close]

      # Block compression errors (HPACK bomb, CVE-2016-1544)
      - name: "compression_error_flood"
        filter:
          h2_error: 0x09
          min_count: 5
        action: [log, block, close]

      # Block rapid reset attacks (CVE-2023-44487)
      - name: "cancel_flood"
        filter:
          h2_error: 0x08
          min_count: 50
        action: [log, block]

      # Block pure attacks (errors with no successful requests)
      - name: "pure_attack"
        filter:
          min_client_errors: 10
          max_successes: 0
        action: [log, block, close]

      # Rate limit: block IPs with too many requests per window
      - name: "request_rate_flood"
        filter:
          max_req_rate: 1000        # More than 1000 requests per window
        action: [log, block]

      # Rate limit: block IPs opening too many connections
      - name: "connection_rate_flood"
        filter:
          max_conn_rate: 100        # More than 100 connections per window
        action: [log, block]

    enabled: true

Memory Usage
============

Memory is bounded by the ``slots`` configuration:

======= =========
Slots   Memory
======= =========
10,000  ~1.6 MB
50,000  ~8.0 MB
100,000 ~16.0 MB
======= =========

Each slot is approximately 128 bytes and includes all tracking counters.

Comparison with Other Plugins
=============================

The ``abuse_shield`` plugin combines features from both ``block_errors`` and
``rate_limit`` plugins, providing a unified abuse protection solution:

================================ ============== ============== ==============
Feature                          abuse_shield   block_errors   rate_limit
================================ ============== ============== ==============
**Error Tracking**
HTTP/2 error codes               All 16         Only 2         No
Client vs server errors          Yes            No             No
Pure attack detection            Yes            No             No
**Rate Limiting**
Per-IP request rate              Yes            No             No
Per-IP connection rate           Yes            No             No
Per-remap/SNI limits             No             No             Yes
Request queuing                  No             No             Yes
**IP Management**
Per-IP tracking                  Yes            Yes            Yes (IP rep)
IP blocking with duration        Yes            Yes            Yes
Trusted IP bypass                Yes            No             Yes
**Configuration**
YAML configuration               Yes            No             Yes
Dynamic reload                   Yes            Partial        Yes
Memory bounded                   Yes (Udi)      No             Yes (LRU)
================================ ============== ============== ==============

**When to use which plugin:**

* Use ``abuse_shield`` for HTTP/2 attack protection and per-IP abuse detection
* Use ``rate_limit`` for per-service (remap/SNI) rate limiting with queuing
* Use ``block_errors`` for simple HTTP/2 error blocking (legacy)

See Also
========

* :ref:`admin-plugins-block_errors`
* :ref:`admin-plugins-rate_limit`
