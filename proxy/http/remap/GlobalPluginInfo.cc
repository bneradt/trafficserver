/** @file

  Information about remap plugin libraries.

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

#include "GlobalPluginInfo.h"
#include "tscore/Diags.h"

GlobalPluginInfo::GlobalPluginInfo(const fs::path &configPath, const fs::path &effectivePath, const fs::path &runtimePath)
  : PluginDso(configPath, effectivePath, runtimePath)
{
}

GlobalPluginInfo::~GlobalPluginInfo() = default;

bool
GlobalPluginInfo::load(std::string &error)
{
  error.clear();

  if (!PluginDso::load(error)) {
    return false;
  }

  init_cb = getFunctionSymbol<Init_F>(TSGLOBAL_FUNCNAME_INIT);

  /* Validate if the callback global plugin functions are specified correctly in the plugin. */
  bool valid = true;
  if (!init_cb) {
    error = missingRequiredSymbolError(_configPath.string(), TSGLOBAL_FUNCNAME_INIT);
    valid = false;
  }

  if (valid) {
    Debug(_tag, "plugin '%s' callbacks validated", _configPath.c_str());
  } else {
    Error("plugin '%s' callbacks validation failed: %s", _configPath.c_str(), error.c_str());
  }
  return valid;
}

bool
GlobalPluginInfo::init(std::string &error)
{
  return true;
}

void
GlobalPluginInfo::done()
{
}

void
GlobalPluginInfo::indicatePreReload()
{
}

void
GlobalPluginInfo::indicatePostReload(TSReturnCode reloadStatus)
{
}
