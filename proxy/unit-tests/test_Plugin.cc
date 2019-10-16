/** @file

  Unit tests for a class that deals with remap plugins

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

#define CATCH_CONFIG_MAIN /* include main function */
#include <catch.hpp>      /* catch unit-test framework */
#include <fstream>        /* ofstream */
#include <string>

#include "plugin_testing_common.h"
#include "../Plugin.h"

std::error_code ec;

namespace fs = ts::file;

/* The following are paths that are used commonly in the unit-tests */
static fs::path sandboxDir     = getTemporaryDir();
static fs::path runtimeDir     = sandboxDir / "runtime";
static fs::path searchDir      = sandboxDir / "search";
static fs::path pluginBuildDir = fs::current_path() / "unit-tests/.libs";

void
cleanupSandBox()
{
  fs::remove(sandboxDir, ec);
}

fs::path
setupSandBox(const fs::path pluginFilename)
{
  cleanupSandBox();

  return pluginBuildDir / pluginFilename;
}

SCENARIO("loading remap plugins", "[plugin][core]")
{
  REQUIRE_FALSE(sandboxDir.empty());

  std::string error;

  GIVEN("a plugin which has only minimum required call back functions")
  {
    const auto pluginFilename = fs::path("has_required_plugin_api.so");
    const auto pluginPath     = setupSandBox(pluginFilename);

    WHEN("loading")
    {
      void *handle, *initptr;
      bool loaded = plugin_dso_load(pluginPath.c_str(), handle, initptr, error);

      THEN("expect it to successfully load")
      {
        CHECK(loaded);
        CHECK(error.empty());
        CHECK(nullptr != handle);
        CHECK(nullptr != initptr);
      }
      cleanupSandBox();
    }
  }

  GIVEN("a plugin which is missing the plugin TSREMAP_FUNCNAME_INIT function")
  {
    const auto pluginFilename = fs::path("missing_ts_plugin_init.so");
    const auto pluginPath     = setupSandBox(pluginFilename);

    WHEN("loading")
    {
      void *handle, *initptr;
      bool loaded = plugin_dso_load(pluginPath.c_str(), handle, initptr, error);

      THEN("expect it to fail load")
      {
        CHECK_FALSE(loaded);
        CHECK_FALSE(error.empty());
        CHECK(nullptr == handle);
        CHECK(nullptr == initptr);
      }
      cleanupSandBox();
    }
  }
}
