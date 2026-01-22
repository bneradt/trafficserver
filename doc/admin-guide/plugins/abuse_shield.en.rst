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

The ``abuse_shield`` plugin provides unified abuse protection for Apache Traffic Server,
including HTTP/2 error tracking, IP-based abuse detection, and rate limiting. It uses
the Udi "King of the Hill" algorithm for efficient, bounded-memory IP tracking.

Key features:

* Tracks all 16 HTTP/2 error codes per IP
* Distinguishes between client-caused and server-caused errors
* Detects "pure attacks" (many errors with zero successful requests)
* Bounded memory usage via the Udi algorithm
* Dynamic configuration reload via ``traffic_ctl``
* YAML-based configuration with flexible rules

Algorithm
=========

The plugin uses the "Udi King of the Hill" algorithm for IP tracking:

* Fixed-size slot array (configurable, default 50K slots)
* New IPs contest existing slots based on their error score
* High-score (abusive) IPs naturally remain in the table
* Low-activity IPs are automatically evicted
* Memory is bounded regardless of traffic volume

Each IP slot tracks:

* Client-caused HTTP/2 errors
* Server-caused HTTP/2 errors
* Per-error-code counts (all 16 HTTP/2 error codes)
* Successful request count
* Connection and request rates
* Block status and expiration

Installation
============

Build with CMake::

    cmake .. -DENABLE_ABUSE_SHIELD=ON
    cmake --build . --target abuse_shield

Configuration
=============

To enable the plugin, add to :file:`plugin.config`::

    abuse_shield.so abuse_shield.yaml

Create the configuration file :file:`abuse_shield.yaml` in the config directory.

Configuration File Format
-------------------------

The configuration uses YAML format with the following structure:

.. code-block:: yaml

    ip_reputation:
      slots: 50000              # Number of IP tracking slots
      window_seconds: 60        # Time window for rate calculations (default 60s)

    blocking:
      duration_seconds: 300     # How long to block abusive IPs

    trusted_ips_file: /etc/trafficserver/abuse_shield_trusted.txt

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

Rule Filters
------------

Each rule has a ``filter`` section that defines when the rule matches:

==================== ===========================================================
Filter               Description
==================== ===========================================================
``h2_error``         Specific HTTP/2 error code (0x00-0x0f)
``min_count``        Minimum count of the specific ``h2_error``
``min_client_errors`` Total client-caused HTTP/2 errors
``min_server_errors`` Total server-caused HTTP/2 errors
``max_successes``    Maximum successful requests (use 0 for "pure attack" detection)
``max_conn_rate``    Maximum connections per rate window
``max_req_rate``     Maximum requests per rate window
==================== ===========================================================

Actions
-------

Each rule has an ``action`` list with one or more actions:

============ ============================================================
Action       Description
============ ============================================================
``log``      Log the abuse detection with all tracked attributes
``block``    Block the IP for ``blocking.duration_seconds``
``close``    Immediately close the connection
``downgrade`` Downgrade to HTTP/1.1 (future feature)
============ ============================================================

HTTP/2 Error Codes
------------------

The plugin tracks all HTTP/2 error codes. Client-caused errors are typically
indicative of abuse, while server-caused errors usually indicate server issues.

============ ====================== ============ ==================================
Code         Name                   Typical Cause CVEs
============ ====================== ============ ==================================
0x01         PROTOCOL_ERROR         Client       CVE-2019-9513, CVE-2019-9518
0x02         INTERNAL_ERROR         Server
0x03         FLOW_CONTROL_ERROR     Client       CVE-2019-9511, CVE-2019-9517
0x04         SETTINGS_TIMEOUT       Client
0x05         STREAM_CLOSED          Client
0x06         FRAME_SIZE_ERROR       Client
0x07         REFUSED_STREAM         Server
0x08         CANCEL (RST_STREAM)    Client       CVE-2023-44487 (Rapid Reset)
0x09         COMPRESSION_ERROR      Client       CVE-2016-1544 (HPACK bomb)
0x0a         CONNECT_ERROR          Either
0x0b         ENHANCE_YOUR_CALM      Server
0x0c         INADEQUATE_SECURITY    Either
0x0d         HTTP_1_1_REQUIRED      Server
============ ====================== ============ ==================================

Trusted IPs
-----------

Create :file:`abuse_shield_trusted.txt` with one IP or CIDR per line::

    # Localhost
    127.0.0.1
    ::1

    # Internal networks
    10.0.0.0/8
    192.168.0.0/16

    # Monitoring servers
    203.0.113.50

Lines starting with ``#`` are comments.

Runtime Control
===============

The plugin supports runtime control via ``traffic_ctl plugin msg``:

Reload Configuration
--------------------

Reload the YAML configuration without restarting ATS::

    traffic_ctl plugin msg abuse_shield.reload

Dump Tracked IPs
----------------

Dump all currently tracked IPs and their statistics to the error log::

    traffic_ctl plugin msg abuse_shield.dump

Enable/Disable
--------------

Enable or disable the plugin at runtime::

    traffic_ctl plugin msg abuse_shield.enabled 1
    traffic_ctl plugin msg abuse_shield.enabled 0

Example Configuration
=====================

Basic protection against HTTP/2 attacks:

.. code-block:: yaml

    ip_reputation:
      slots: 50000
      window_seconds: 60

    blocking:
      duration_seconds: 300

    trusted_ips_file: /etc/trafficserver/abuse_shield_trusted.txt

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

Comparison with block_errors
============================

The ``abuse_shield`` plugin is designed as a more comprehensive replacement
for the ``block_errors`` plugin:

========================= ============== ==============
Feature                   abuse_shield   block_errors
========================= ============== ==============
HTTP/2 error codes        All 16         Only 2
Client vs server errors   Yes            No
Memory bounded            Yes (Udi)      No
YAML configuration        Yes            No
Dynamic reload            Yes            Partial
Pure attack detection     Yes            No
========================= ============== ==============

See Also
========

* :ref:`admin-plugins-block_errors`
* :ref:`admin-plugins-rate_limit`
