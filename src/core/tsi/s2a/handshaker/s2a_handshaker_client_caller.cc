/*
 *
 * Copyright 2019 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <grpc/support/port_platform.h>

#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"

#include <grpc/support/alloc.h>
#include <grpc/support/log.h>

namespace grpc_core {
namespace experimental {

/** This file contains the implementation details of the |make_grpc_call| member
 *  function of the |S2AHandshakerClient| class. This method enables the S2A
 *  handshaker client to make a gRPC call to the S2A service. **/

tsi_result S2AHandshakerClient::MakeGrpcCall(bool is_start) {
  // TODO(mattstev): implement.
  return TSI_UNIMPLEMENTED;
}

void S2AHandshakerClient::MaybeCompleteTsiNext(
    bool receive_status_finished,
    s2a_recv_message_result* pending_recv_message_result) {
  // TODO(mattstev): implement.
  return;
}

}  // namespace experimental
}  // namespace grpc_core
