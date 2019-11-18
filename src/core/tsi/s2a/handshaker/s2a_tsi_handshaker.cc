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

#include "src/core/tsi/s2a/handshaker/s2a_tsi_handshaker.h"

namespace grpc {
namespace experimental {

tsi_result s2a_tsi_handshaker_create(
    const grpc_s2a_credentials_options* options, const char* target_name,
    const char* handshaker_service_url, bool is_client,
    grpc_pollset_set* interested_parties, tsi_handshaker** self,
    char** error_details) {
  return TSI_UNIMPLEMENTED;
}

tsi_result s2a_tsi_handshaker_result_create(s2a_SessionResp* response,
                                            bool is_client,
                                            tsi_handshaker_result** result) {
  return TSI_UNIMPLEMENTED;
}

void s2a_tsi_handshaker_result_set_unused_bytes(tsi_handshaker_result* result,
                                                grpc_slice* recv_bytes,
                                                size_t bytes_consumed) {
  return;
}

bool s2a_tsi_handshaker_has_shutdown(s2a_tsi_handshaker* handshaker) {
  return false;
}

}  // namespace experimental
}  // namespace grpc
