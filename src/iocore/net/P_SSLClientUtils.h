/** @file

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

#include "P_SSLConfig.h"

#include <openssl/ssl.h>

// BoringSSL does not have this include file
#if __has_include(<openssl/opensslconf.h>)
#include <openssl/opensslconf.h>
#endif

// Create and initialize a SSL client context.
SSL_CTX *SSLInitClientContext(const struct SSLConfigParams *param);
SSL_CTX *SSLCreateClientContext(const struct SSLConfigParams *params, const char *ca_bundle_file, const char *ca_bundle_path,
                                const char *cert_path, const char *key_path);

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);
