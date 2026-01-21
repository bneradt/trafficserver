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

.. include:: ../../../../common.defs

.. _udi-table:

UdiTable
********

The ``ts::UdiTable`` class implements the Udi "King of the Hill" algorithm for
tracking entities (IP addresses, URLs, etc.) with bounded memory. When the table
is full, new entries compete with existing entries based on a score - the higher
score wins the slot.

Synopsis
========

.. code-block:: cpp

   #include "tsutil/udi_table.h"

   // Define your slot type
   struct MySlot {
     std::string key;
     std::atomic<uint32_t> score{0};
     std::atomic<uint32_t> count{0};
     void clear() { key.clear(); score = 0; count = 0; }
   };

   // Create accessor functions
   auto get_key = [](const MySlot& s) -> const std::string& { return s.key; };
   auto set_key = [](MySlot& s, const std::string& k) { s.key = k; };
   auto get_score = [](const MySlot& s) { return s.score.load(); };
   auto set_score = [](MySlot& s, uint32_t v) { s.score.store(v); };
   auto is_empty = [](const MySlot& s) { return s.key.empty(); };

   // Create table with 10000 slots
   ts::UdiTable<std::string, MySlot> table(10000, get_key, set_key, get_score, set_score, is_empty);

   // Record an event (creates or updates slot)
   MySlot* slot = table.record("some_key", 1);
   if (slot) {
     slot->count.fetch_add(1);
   }

   // Find existing entry
   MySlot* found = table.find("some_key");

   // Decrement score (may evict if score reaches 0)
   table.decrement("some_key", 1);

Description
===========

The Udi algorithm provides several key properties:

**Fixed Memory**
   The table allocates a fixed number of slots at construction time. Memory usage
   is bounded regardless of how many unique keys are tracked.

**Self-Cleaning**
   No background cleanup thread is needed. The table manages eviction automatically
   through the contest mechanism.

**Hot Tracking**
   Frequently-accessed keys naturally stay in the table because they have higher
   scores and win contests against less active entries.

**Lock-Efficient**
   The table uses partitioned locking (default 64 partitions) to minimize contention.
   Most operations only lock a single partition.

Algorithm
---------

When a new key is recorded and it's not already in the table:

1. The table picks a "contest slot" using a rotating pointer
2. The new key's score is compared against the existing slot's score
3. If the new key has a higher score, it takes the slot (evicting the old entry)
4. If the existing slot has a higher score, it survives but its score is decremented

This ensures that high-activity keys stay in the table while low-activity keys
are eventually evicted.

Template Parameters
===================

.. code-block:: cpp

   template <typename Key, typename Slot, typename Hash = std::hash<Key>, size_t NumPartitions = 64>
   class UdiTable;

``Key``
   The key type used to identify entries. Must be hashable. Common choices:
   ``std::string``, ``swoc::IPAddr``.

``Slot``
   The slot type that stores data associated with each key. Must be default-constructible.

``Hash``
   Hash function for keys. Defaults to ``std::hash<Key>``.

``NumPartitions``
   Number of hash table partitions. Default is 64. More partitions means less
   lock contention but more memory overhead.

Constructor
===========

.. code-block:: cpp

   UdiTable(size_t num_slots,
            get_key_fn get_key,
            set_key_fn set_key,
            get_score_fn get_score,
            set_score_fn set_score,
            slot_empty_fn is_empty = nullptr,
            slot_clear_fn clear_slot = nullptr);

``num_slots``
   Total number of slots to allocate. Memory usage is approximately
   ``num_slots * sizeof(Slot)``.

``get_key``
   Function to get the key from a slot: ``Key const& (Slot const&)``

``set_key``
   Function to set the key in a slot: ``void(Slot&, Key const&)``

``get_score``
   Function to get the score from a slot: ``uint32_t(Slot const&)``

``set_score``
   Function to set the score in a slot: ``void(Slot&, uint32_t)``

``is_empty``
   Optional function to check if a slot is empty. Defaults to checking if
   ``get_score(slot) == 0``.

``clear_slot``
   Optional function to clear a slot. Defaults to calling ``slot.clear()``.

Methods
=======

find
----

.. code-block:: cpp

   Slot* find(Key const& key);
   Slot const* find(Key const& key) const;

Find an existing entry by key. Returns ``nullptr`` if not found.

Thread-safe: uses a shared lock on one partition.

record
------

.. code-block:: cpp

   Slot* record(Key const& key, uint32_t score_delta = 1);

Record an event for a key. If the key exists, increments its score and returns
the slot. If the key doesn't exist, attempts to contest for a slot using the
Udi algorithm.

Returns ``nullptr`` if the key lost the contest and couldn't get a slot.

Thread-safe: uses an exclusive lock on one partition.

decrement
---------

.. code-block:: cpp

   bool decrement(Key const& key, uint32_t amount = 1);

Decrement the score for a key. If the score reaches 0, the key is evicted from
the table.

Returns ``true`` if the key was found, ``false`` otherwise.

Thread-safe: uses an exclusive lock on one partition.

remove
------

.. code-block:: cpp

   bool remove(Key const& key);

Remove a key from the table regardless of its score.

Returns ``true`` if the key was found and removed.

Thread-safe: uses an exclusive lock on one partition.

Statistics
----------

.. code-block:: cpp

   size_t num_slots() const;        // Total allocated slots
   size_t num_partitions() const;   // Number of partitions (template parameter)
   size_t slots_used() const;       // Currently occupied slots
   uint64_t contests() const;       // Total contest attempts
   uint64_t contests_won() const;   // Contests won by new keys
   uint64_t evictions() const;      // Keys evicted due to score reaching 0

dump
----

.. code-block:: cpp

   std::string dump(slot_format_fn format_slot = nullptr) const;

Dump all entries to a string for debugging. If ``format_slot`` is provided,
it's called for each slot to format the output.

Example: IP Address Tracking
============================

.. code-block:: cpp

   #include "tsutil/udi_table.h"
   #include "swoc/swoc_ip.h"

   struct IPSlot {
     swoc::IPAddr addr;
     std::atomic<uint32_t> score{0};
     std::atomic<uint32_t> error_count{0};
     std::atomic<uint64_t> blocked_until{0};

     void clear() {
       addr = swoc::IPAddr{};
       score = 0;
       error_count = 0;
       blocked_until = 0;
     }

     bool empty() const { return !addr.is_valid(); }
   };

   // Create table
   ts::UdiTable<swoc::IPAddr, IPSlot> table(
     50000,  // 50k slots
     [](const IPSlot& s) -> const swoc::IPAddr& { return s.addr; },
     [](IPSlot& s, const swoc::IPAddr& ip) { s.addr = ip; },
     [](const IPSlot& s) { return s.score.load(); },
     [](IPSlot& s, uint32_t v) { s.score.store(v); },
     [](const IPSlot& s) { return s.empty(); }
   );

   // Track an error from an IP
   void record_error(const swoc::IPAddr& ip) {
     if (auto* slot = table.record(ip, 1)) {
       slot->error_count.fetch_add(1);
       if (slot->error_count.load() > 100) {
         // Block this IP
         slot->blocked_until.store(now_ms() + 300000);  // 5 minutes
       }
     }
   }

   // Check if IP is blocked
   bool is_blocked(const swoc::IPAddr& ip) {
     if (auto* slot = table.find(ip)) {
       uint64_t until = slot->blocked_until.load();
       return until > 0 && now_ms() < until;
     }
     return false;
   }

Thread Safety
=============

The ``UdiTable`` is thread-safe for concurrent access:

- ``find()`` uses a shared lock (multiple concurrent readers allowed)
- ``record()``, ``decrement()``, and ``remove()`` use exclusive locks
- Locks are partitioned: operations on different keys in different partitions
  don't contend

**Important**: After calling ``find()`` or ``record()``, modifications to the
returned slot should use atomic operations since other threads may be accessing
the same slot concurrently.

Memory Sizing
=============

The memory usage is approximately:

.. code-block:: text

   Total = num_slots * sizeof(Slot) + NumPartitions * sizeof(Partition)

For IP tracking with the example ``IPSlot`` above (approximately 64 bytes):

- 10,000 slots ≈ 640 KB
- 50,000 slots ≈ 3.2 MB
- 100,000 slots ≈ 6.4 MB

See Also
========

- :ref:`abuse-shield-plugin` - Uses UdiTable for IP abuse tracking
- :ref:`block-errors-plugin` - Could be refactored to use UdiTable
