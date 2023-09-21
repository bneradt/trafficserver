/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
Plugin for testing that a data sink plugin can close the connection.
*/

#include "ts/apidefs.h"
#include "tscore/ink_assert.h"
#include <cstring>
#include <string>

#include <ts/ts.h>
#include <ts/DbgCtl.h>
#include <unistd.h>

namespace
{
// Reject request bodies containing this contet.
std::string const REJECT_TOKEN{"rejected"};

std::string const PNAME{"filter_body"};
DbgCtl dbg_ctl{PNAME.c_str()};

struct TransformData {
public:
  TransformData(int client_fd) : client_fd{client_fd} { end_of_last_read.resize(REJECT_TOKEN.size()); }

  /** The last set of bytes from the previous read.
   *
   * This keeps track of the necessary bytes to determine whether the phrase
   * "rejected" is in the request body stream.
   */
  std::string end_of_last_read;

  /** The client connection's file descriptor. */
  int client_fd{0};
};

int
request_body_reader(TSCont contp, TSEvent event, void *edata)
{
  TransformData *transform_data = static_cast<TransformData *>(TSContDataGet(contp));

  // If we got closed, we're done.
  if (TSVConnClosedGet(contp)) {
    delete transform_data;
    TSContDestroy(contp);
    return 0;
  }

  if (transform_data == nullptr) {
    TSError("%s: Couldn't retrieve transform data.", PNAME.c_str());
    return 0;
  }

  TSVIO input_vio = TSVConnWriteVIOGet(contp);

  switch (event) {
  case TS_EVENT_ERROR:
    Dbg(dbg_ctl, "Error event");
    TSContCall(TSVIOContGet(input_vio), TS_EVENT_ERROR, input_vio);
    break;
  case TS_EVENT_VCONN_READ_COMPLETE:
    Dbg(dbg_ctl, "READ_COMPLETE");
    break;
  case TS_EVENT_VCONN_READ_READY:
  case TS_EVENT_IMMEDIATE:
    Dbg(dbg_ctl, "Data event - %s", event == TS_EVENT_IMMEDIATE ? "IMMEDIATE" : "READ_READY");
    // Look for data and if we find any, consume it.
    if (TSVIOBufferGet(input_vio)) {
      TSIOBufferReader reader = TSVIOReaderGet(input_vio);
      size_t const n          = TSIOBufferReaderAvail(reader);
      if (n > 0) {
        std::string this_content;
        this_content.resize(n + transform_data->end_of_last_read.size());
        std::memcpy(this_content.data(), transform_data->end_of_last_read.data(), transform_data->end_of_last_read.size());
        auto const offset = transform_data->end_of_last_read.size();
        TSIOBufferReaderCopy(reader, this_content.data() + offset, n);

        auto const pos = this_content.find(REJECT_TOKEN);
        if (pos != std::string::npos) {
          Dbg(dbg_ctl, "Found reject token: %s", REJECT_TOKEN.c_str());
          int const client_fd = transform_data->client_fd;
          Dbg(dbg_ctl, "Closing the client (%d).", client_fd);
          // Use shutdown() instead of close() to avoid double close or fd
          // reuse. ATS will close the fd when it is shutdown like this.
          if (client_fd >= 0) {
            shutdown(client_fd, SHUT_RDWR);
          }
        }
        TSIOBufferReaderConsume(reader, n);
        TSVIONDoneSet(input_vio, TSVIONDoneGet(input_vio) + n);
        Dbg(dbg_ctl, "Consumed %zd bytes", n);
      }
      // Only send the happy events if we're not aborting the vconn.
      if (TSVIONTodoGet(input_vio) > 0) {
        // Signal that we can accept more data.
        TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_READY, input_vio);
      } else {
        Dbg(dbg_ctl, "Done reading request body.");
        TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_COMPLETE, input_vio);
      }
    } else { // The buffer is gone so we're done.
      Dbg(dbg_ctl, "Upstream buffer disappeared.");
    }
    break;
  default:
    Dbg(dbg_ctl, "unhandled event %d", event);
    break;
  }
  return 0;
}

bool
txn_is_post_request(TSHttpTxn txnp)
{
  TSMBuffer req_bufp = nullptr;
  TSMLoc req_hdr_loc = nullptr;

  if (TSHttpTxnClientReqGet(txnp, &req_bufp, &req_hdr_loc) != TS_SUCCESS) {
    TSError("%s: Couldn't retrieve the client request header", PNAME.c_str());
    return false;
  }

  int len      = 0;
  bool is_post = TSHttpHdrMethodGet(req_bufp, req_hdr_loc, &len) == TS_HTTP_METHOD_POST;
  Dbg(dbg_ctl, "Request is post: %s", is_post ? "true" : "false");

  TSHandleMLocRelease(req_bufp, TS_NULL_MLOC, req_hdr_loc);
  return is_post;
}

int
request_header_handler(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);
  switch (event) {
  case TS_EVENT_HTTP_READ_REQUEST_HDR: {
    if (txnp == nullptr) {
      TSError("%s: Couldn't retrieve the transaction object.", PNAME.c_str());
      return TS_ERROR;
    }
    // Check whether this is a post request.
    if (!txn_is_post_request(txnp)) {
      Dbg(dbg_ctl, "Skipping a non-POST request.");
      break;
    }
    TSHttpSsn ssnp       = nullptr;
    TSVConn client_vconn = nullptr;
    if ((ssnp = TSHttpTxnSsnGet(txnp)) == nullptr || (client_vconn = TSHttpSsnClientVConnGet(ssnp)) == nullptr) {
      Dbg(dbg_ctl, "Failed to retrieve ssn/vconn object.");
      break;
    }
    int const client_fd = TSVConnFdGet(client_vconn);
    auto transform_data = new TransformData{client_fd};
    TSVConn transform   = TSTransformCreate(request_body_reader, txnp);
    TSContDataSet(transform, transform_data);

    Dbg(dbg_ctl, "Registering the request body reader.");
    TSHttpTxnHookAdd(txnp, TS_HTTP_REQUEST_CLIENT_HOOK, transform);

    break;
  }
  default:
    TSError("[%s] Unexpected event: %d", PNAME.c_str(), event);
    break;
  }
  if (txnp != nullptr) {
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  }
  return TS_SUCCESS;
}

} // end anonymous namespace

void
TSPluginInit(int n_arg, char const *arg[])
{
  Dbg(dbg_ctl, "Initializing plugin.");

  TSPluginRegistrationInfo info;

  info.plugin_name   = const_cast<char *>(PNAME.c_str());
  info.vendor_name   = const_cast<char *>("apache");
  info.support_email = const_cast<char *>("edge@yahooinc.com");

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("%s: failure calling TSPluginRegister.", PNAME.c_str());
    return;
  }

  TSCont cont = TSContCreate(request_header_handler, nullptr);
  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, cont);
  Dbg(dbg_ctl, "Plugin registration succeeded.");
}
