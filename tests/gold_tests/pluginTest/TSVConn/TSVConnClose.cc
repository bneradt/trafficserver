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
Plugin for testing TSVConnClose().
*/

#include <cstring>
#include <string>

#include <ts/ts.h>
#include <ts/DbgCtl.h>

namespace
{
// Reject request bodies containing this contet.
std::string const REJECT_TOKEN{"rejected"};

std::string const PNAME{"TSVConnClose"};
DbgCtl dbg_ctl{PNAME.c_str()};

int session_arg_index = -1;

struct SessionData {
  SessionData() { end_of_last_read.resize(REJECT_TOKEN.size()); }

  /** A reference to the client side connection. */
  TSVConn client_vconn{nullptr};

  /** The last set of bytes from the previous read.
   *
   * This keeps track of the necessary bytes to determine whether the phrase
   * "rejected" is in the request body stream.
   */
  std::string end_of_last_read;

  /** Whether the current connection should be closed. */
  bool should_close_vconn{false};
};

int
request_body_reader(TSCont contp, TSEvent event, void *edata)
{
  SessionData *data = static_cast<SessionData *>(TSContDataGet(contp));

  // If we got closed, we're done.
  if (TSVConnClosedGet(contp)) {
    delete data;
    TSContDestroy(contp);
    return 0;
  }

  TSVIO input_vio = TSVConnWriteVIOGet(contp);

  if (data == nullptr) {
    TSError("%s: Couldn't retrieve session data.", PNAME.c_str());
    return 0;
  }

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
        this_content.resize(n + data->end_of_last_read.size());
        std::memcpy(this_content.data(), data->end_of_last_read.data(), data->end_of_last_read.size());
        auto const offset = data->end_of_last_read.size();
        TSIOBufferReaderCopy(reader, this_content.data() + offset, n);

        auto const pos = this_content.find(REJECT_TOKEN);
        if (pos != std::string::npos) {
          Dbg(dbg_ctl, "Found reject token: %s", REJECT_TOKEN.c_str());
          data->should_close_vconn = true;
        }

        TSIOBufferReaderConsume(reader, n);
        TSVIONDoneSet(input_vio, TSVIONDoneGet(input_vio) + n);
        Dbg(dbg_ctl, "Consumed %zd bytes", n);
      }
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

  if (data->should_close_vconn) {
    if (data->client_vconn != nullptr) {
      Dbg(dbg_ctl, "Closing the vconn.");
      TSVConnClose(data->client_vconn);
      delete data;
    } else {
      TSError("%s: No client vconn to close.", PNAME.c_str());
    }
  }

  return 0;
}

bool
txn_is_post_request(TSHttpTxn txnp)
{
  TSMBuffer req_bufp = nullptr;
  TSMLoc req_hdr_loc = nullptr;

  if (TSHttpTxnClientReqGet(txnp, &req_bufp, &req_hdr_loc) != TS_SUCCESS) {
    TSError("%s: Couldn't retrieve client request header", PNAME.c_str());
    return false;
  }

  int len      = 0;
  bool is_post = TSHttpHdrMethodGet(req_bufp, req_hdr_loc, &len) == TS_HTTP_METHOD_POST;
  Dbg(dbg_ctl, "Request is post: %s", is_post ? "true" : "false");

  TSHandleMLocRelease(req_bufp, TS_NULL_MLOC, req_hdr_loc);
  return is_post;
}

int
request_header_hook(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);

  Dbg(dbg_ctl, "Checking transaction for any flags to enable transaction data sink.");
  switch (event) {
  case TS_EVENT_HTTP_READ_REQUEST_HDR:
    // Check whether this is a post request.
    if (txn_is_post_request(txnp)) {
      auto transform = TSTransformCreate(request_body_reader, txnp);
      auto data      = new SessionData;

      TSHttpSsn ssn        = TSHttpTxnSsnGet(txnp);
      TSVConn client_vconn = TSHttpSsnClientVConnGet(ssn);
      data->client_vconn   = client_vconn;

      TSContDataSet(transform, data);

      TSHttpTxnHookAdd(txnp, TS_HTTP_REQUEST_CLIENT_HOOK, transform);
      Dbg(dbg_ctl, "Registering the request body reader.");
    }
    break;
  default:
    break;
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 0;
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

  if (TS_SUCCESS != TSUserArgIndexReserve(TS_USER_ARGS_SSN, PNAME.c_str(), "Track request body data", &session_arg_index)) {
    TSError("[%s] Unable to initialize plugin: failed to reserve ssn arg.", PNAME.c_str());
    return;
  }
  auto cont = TSContCreate(request_header_hook, nullptr);
  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, cont);
  Dbg(dbg_ctl, "Plugin registration succeeded.");
}
