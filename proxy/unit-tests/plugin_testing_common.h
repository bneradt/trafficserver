/** @file

  A test plugin header for testing Plugin's Dynamic Shared Objects (DSO)

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

  @section details Details

  Implements code necessary for Reverse Proxy which mostly consists of
  general purpose hostname substitution in URLs.

 */

#pragma once

#include <string>
#include <iostream>

#include <stdio.h>
#include <stdarg.h>
#include "tscore/ts_file.h"

/* A temp sandbox to play with our toys used for all fun with this test-bench */
ts::file::path getTemporaryDir();

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#undef Debug
#define Debug(category, fmt, ...) PrintToStdErr("(%s) %s:%d:%s() " fmt "\n", category, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#undef Error
#define Error(fmt, ...) PrintToStdErr("%s:%d:%s() " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
void PrintToStdErr(const char *fmt, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */
