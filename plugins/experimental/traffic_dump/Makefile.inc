#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

pkglib_LTLIBRARIES += experimental/traffic_dump/traffic_dump.la

experimental_traffic_dump_traffic_dump_la_SOURCES = \
	experimental/traffic_dump/address.cc \
	experimental/traffic_dump/traffic_dump.cc

check_PROGRAMS += experimental/traffic_dump/test_address

experimental_traffic_dump_test_address_CPPFLAGS = \
	$(AM_CPPFLAGS) \
        -I$(abs_top_srcdir)/tests/include \
        -I$(abs_top_srcdir)/plugins/experimental/traffic_dump \
        -DURI_SIGNING_UNIT_TEST

experimental_traffic_dump_test_address_LDADD = \
	@LIBJANSSON@ \
        @LIBCJOSE@ \
        @LIBPCRE@ \
        -lm \
        -lcrypto

experimental_traffic_dump_test_address_SOURCES = \
	experimental/traffic_dump/unit_tests/test_address.cc \
	experimental/traffic_dump/unit_tests/unit_test_main.cc \
	experimental/traffic_dump/address.cc
