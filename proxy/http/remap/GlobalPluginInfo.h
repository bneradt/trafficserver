/** @file

  Information about remap plugins.

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

#include <string>
#include <tuple>

#include "tscore/ink_platform.h"
#include "ts/apidefs.h"
#include "ts/remap.h"
#include "PluginDso.h"

extern thread_local PluginThreadContext *pluginThreadContext;

static constexpr const char *const TSGLOBAL_FUNCNAME_INIT = "TSPluginInit";

/**
 * Holds information for a global plugin, global specific callback entry points
 * for plugin init/done and instance init/done, origin server response,
 */
class GlobalPluginInfo : public PluginDso
{
public:
  using Init_F = void(int argc, const char *argv[]);

  Init_F *init_cb = nullptr;

  GlobalPluginInfo(const fs::path &configPath, const fs::path &effectivePath, const fs::path &runtimePath);
  ~GlobalPluginInfo();

  /* Overload to add / execute remap plugin specific tasks during the plugin loading */
  bool load(std::string &error) override;

  /* Used by the factory to invoke callbacks during plugin load, init and unload  */
  bool init(std::string &error) override;
  void done(void) override;

  /* Used by traffic server core to indicate configuration reload */
  void indicatePreReload() override;
  void indicatePostReload(TSReturnCode reloadStatus) override;

protected:
  static constexpr const char *const _tag = "plugin_global"; /** @brief log tag used by this class */

  PluginThreadContext *_tempContext = nullptr;
};
