.. Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed
   with this work for additional information regarding copyright
   ownership.  The ASF licenses this file to you under the Apache
   License, Version 2.0 (the "License"); you may not use this file
   except in compliance with the License.  You may obtain a copy of
   the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   implied.  See the License for the specific language governing
   permissions and limitations under the License.

.. include:: ../../../common.defs
.. default-domain:: cpp

TSRecordDataType
****************

Synopsis
========

.. code-block:: cpp

    #include <ts/apidefs.h>

.. enum:: TSRecordDataType

   The underlying data type of a data record (configuration variable or statistic).

   .. enumerator:: TS_RECORDDATATYPE_NULL

      No data type. Used as an invalid initialization value.

   .. enumerator:: TS_RECORDDATATYPE_INT

      An integer.

   .. enumerator:: TS_RECORDDATATYPE_FLOAT

       Floating point.

   .. enumerator:: TS_RECORDDATATYPE_STRING

      A string.

   .. enumerator:: TS_RECORDDATATYPE_COUNTER

      A counter which has a count and a sum.

   .. enumerator:: TS_RECORDDATATYPE_STAT_CONST

      A value that is unchangeable.

   .. enumerator:: TS_RECORDDATATYPE_STAT_FX

      Unknown.

.. union:: TSRecordData

   A union that holds the data for a record. The correct member is indicated by a :enum:`TSRecordType` value.

   .. var:: int rec_int

      Data for :enumerator:`TS_RECORDDATATYPE_INT`.

   .. var:: float rec_float

      Data for :enumerator:`TS_RECORDDATATYPE_FLOAT`.

   .. var:: char * rec_string

      Data for :enumerator:`TS_RECORDDATATYPE_STRING`.

   .. var:: int64_t rec_counter

      Data for :enumerator:`TS_RECORDDATATYPE_COUNTER`.

Description
===========

This data type describes the data stored in a management value such as a configuration value or a
statistic value.
