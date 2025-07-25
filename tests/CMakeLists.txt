#######################
#
#  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
#  agreements.  See the NOTICE file distributed with this work for additional information regarding
#  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
#  (the "License"); you may not use this file except in compliance with the License.  You may obtain
#  a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
#  or implied. See the License for the specific language governing permissions and limitations under
#  the License.
#
#######################

include(add_atsplugin)

function(ADD_AUTEST_PLUGIN _NAME)
  add_library(${_NAME} MODULE ${ARGN})
  if(LINK_PLUGINS AND BUILD_SHARED_LIBS)
    target_link_libraries(${_NAME} PRIVATE ts::tsapi ts::tsutil)
  else()
    target_include_directories(
      ${_NAME} PRIVATE "$<TARGET_PROPERTY:libswoc::libswoc,INCLUDE_DIRECTORIES>"
                       "$<TARGET_PROPERTY:yaml-cpp::yaml-cpp,INCLUDE_DIRECTORIES>"
    )
  endif()
  set_target_properties(
    ${_NAME}
    PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/.libs"
               PREFIX ""
               SUFFIX ".so"
  )
endfunction()

add_subdirectory(tools/plugins)
add_subdirectory(gold_tests/chunked_encoding)
add_subdirectory(gold_tests/continuations/plugins)
add_subdirectory(gold_tests/jsonrpc/plugins)
add_subdirectory(gold_tests/pluginTest/polite_hook_wait)
add_subdirectory(gold_tests/pluginTest/tsapi)
add_subdirectory(gold_tests/pluginTest/TSVConnFd)
add_subdirectory(gold_tests/timeout)
add_subdirectory(gold_tests/tls)

set(RUNPIPENV PIPENV_VENV_IN_PROJECT=True ${PipEnv})

set(CMAKE_GOLD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gold_tests")
set(CMAKE_SKIP_GOLD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/_skipped_uds_gold_tests")
set(CURL_UDS_FLAG "")
if(ENABLE_AUTEST_UDS)
  set(CURL_UDS_FLAG "--curl-uds")
endif()

configure_file(Pipfile Pipfile COPYONLY)
configure_file(autest.sh.in autest.sh)

add_custom_target(
  autest
  COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target install
  COMMAND ${RUNPIPENV} install
  COMMAND
    ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_GOLD_DIR}/remap:$ENV{PYTHONPATH} ${RUNPIPENV} run env autest --directory
    ${CMAKE_GOLD_DIR} --ats-bin=${CMAKE_INSTALL_PREFIX}/bin --proxy-verifier-bin ${PROXY_VERIFIER_PATH} --build-root
    ${CMAKE_BINARY_DIR} --sandbox ${AUTEST_SANDBOX} ${CURL_UDS_FLAG} ${AUTEST_OPTIONS}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  USES_TERMINAL
)

add_custom_target(
  autest_no_install
  COMMAND ${RUNPIPENV} install
  COMMAND
    ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_GOLD_DIR}/remap:$ENV{PYTHONPATH} ${RUNPIPENV} run env autest --directory
    ${CMAKE_GOLD_DIR} --ats-bin=${CMAKE_INSTALL_PREFIX}/bin --proxy-verifier-bin ${PROXY_VERIFIER_PATH} --build-root
    ${CMAKE_BINARY_DIR} --sandbox ${AUTEST_SANDBOX} ${CURL_UDS_FLAG} ${AUTEST_OPTIONS}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  USES_TERMINAL
)

# autest uds specific target that skips tests and runs with curl flag
add_custom_target(
  autest-uds
  COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target install
  COMMAND ${RUNPIPENV} install
  COMMAND ${CMAKE_COMMAND} -E rename ${CMAKE_GOLD_DIR}/h2 ${CMAKE_SKIP_GOLD_DIR}/h2
  COMMAND ${CMAKE_COMMAND} -E rename ${CMAKE_GOLD_DIR}/tls ${CMAKE_SKIP_GOLD_DIR}/tls
  COMMAND
    ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_GOLD_DIR}/remap:$ENV{PYTHONPATH} ${RUNPIPENV} run env autest --directory
    ${CMAKE_GOLD_DIR} --ats-bin=${CMAKE_INSTALL_PREFIX}/bin --proxy-verifier-bin ${PROXY_VERIFIER_PATH} --build-root
    ${CMAKE_BINARY_DIR} --sandbox ${AUTEST_SANDBOX} ${CURL_UDS_FLAG} ${AUTEST_OPTIONS}
  COMMAND ${CMAKE_COMMAND} -E rename {CMAKE_SKIP_GOLD_DIR}/h2 ${CMAKE_GOLD_DIR}/h2
  COMMAND ${CMAKE_COMMAND} -E rename ${CMAKE_SKIP_GOLD_DIR}/tls ${CMAKE_GOLD_DIR}/tls
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  USES_TERMINAL
)
