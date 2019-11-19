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

#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"

namespace grpc {
namespace experimental {

tsi_result s2a_handshaker_client_start_client(
    const s2a_handshaker_client* client) {
  return TSI_UNIMPLEMENTED;
}

tsi_result s2a_handshaker_client_start_server(
    const s2a_handshaker_client* client, grpc_slice* bytes_received) {
  return TSI_UNIMPLEMENTED;
}

tsi_result s2a_handshaker_client_next(const s2a_handshaker_client* client,
                                      grpc_slice* bytes_received) {
  return TSI_UNIMPLEMENTED;
}

void s2a_handshaker_client_shutdown(const s2a_handshaker_client* client) {
  return;
}

tsi_result s2a_handshaker_client_create(
    s2a_tsi_handshaker* handshaker, grpc_channel* channel,
    const char* handshaker_service_url, grpc_pollset_set* interested_parties,
    grpc_s2a_credentials_options* options, const grpc_slice& target_name,
    grpc_iomgr_cb_func grpc_cb, tsi_handshaker_on_next_done_cb cb,
    void* user_data, bool is_client, s2a_handshaker_client** client,
    char** error_details) {
  return TSI_UNIMPLEMENTED;
}

void s2a_handshaker_client_destroy(s2a_handshaker_client* client) { return; }

}  // namespace experimental
}  // namespace grpc
