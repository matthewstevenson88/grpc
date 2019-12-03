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
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <vector>
#include "src/core/tsi/s2a/s2a_constants.h"
#include "src/core/tsi/transport_security_grpc.h"
#include "src/core/tsi/transport_security_interface.h"

namespace grpc_core {
namespace experimental {

// TODO(mattstev): remove this declaration once PR #2 is merged.
struct grpc_s2a_credentials_options {};

static void s2a_test_tsi_handshaker_create_and_destroy() {
  grpc_s2a_credentials_options options;
  tsi_handshaker* handshaker = nullptr;
  char* error_details = nullptr;
  tsi_result create_result = s2a_tsi_handshaker_create(
      &options, "target_name", /** is_client **/ true,
      /** interested_parties **/ nullptr, &handshaker, &error_details);
  GPR_ASSERT(create_result == TSI_OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(handshaker != nullptr);

  s2a_check_tsi_handshaker_for_testing(
      handshaker, grpc_slice_from_static_string("target_name"),
      /** is_client **/ true,
      /** has_send_start_message **/ false,
      /** has_created_handshaker_client **/ false,
      /** shutdown **/ false);

  tsi_handshaker_shutdown(handshaker);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  GPR_ASSERT(s2a_tsi_handshaker_has_shutdown(s2a_handshaker));
  tsi_handshaker_destroy(handshaker);
}

static void s2a_test_tsi_handshaker_next() {
  grpc_s2a_credentials_options options;
  tsi_handshaker* handshaker = nullptr;
  char* error_details = nullptr;
  tsi_result create_result = s2a_tsi_handshaker_create(
      &options, "target_name", /** is_client **/ true,
      /** interested_parties **/ nullptr, &handshaker, &error_details);
  GPR_ASSERT(create_result == TSI_OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(handshaker != nullptr);

  tsi_result result = tsi_handshaker_next(
      handshaker,
      /** received bytes **/ nullptr, /** received_bytes_size **/ 0,
      /** bytes_to_send **/ nullptr, /** bytes_to_send_size **/ 0,
      /** result **/ nullptr, /** cb **/ nullptr, /** user_data **/ nullptr);
  GPR_ASSERT(result == TSI_UNIMPLEMENTED);
  tsi_handshaker_destroy(handshaker);
}

static void s2a_test_tsi_handshaker_result_create_and_destroy() {
  /** Prepare an s2a_SessionResp instance. **/
  upb::Arena arena;
  s2a_SessionState* session_state = s2a_SessionState_new(arena.ptr());
  s2a_SessionState_set_tls_version(session_state, /** TLS 1.3 **/ 0);
  s2a_SessionState_set_tls_ciphersuite(
      session_state, static_cast<int32_t>(kTlsAes128GcmSha256));
  s2a_SessionState_set_in_sequence(session_state, 0);
  s2a_SessionState_set_out_sequence(session_state, 0);
  std::vector<char> traffic_secret = {'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k',
                                      'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k'};
  s2a_SessionState_set_in_key(
      session_state,
      upb_strview_make(traffic_secret.data(), traffic_secret.size()));
  s2a_SessionState_set_out_key(
      session_state,
      upb_strview_make(traffic_secret.data(), traffic_secret.size()));

  s2a_Identity* peer_identity = s2a_Identity_new(arena.ptr());
  char* spiffe_id = "spiffe_id";
  s2a_Identity_set_spiffe_id(peer_identity, upb_strview_make(spiffe_id, 9));

  s2a_SessionResult* session_result = s2a_SessionResult_new(arena.ptr());
  s2a_SessionResult_set_state(session_result, session_state);

  s2a_SessionResp* session_response = s2a_SessionResp_new(arena.ptr());
  s2a_SessionResp_set_result(session_response, session_result);

  /** Unexpected nullptr arguments. **/
  tsi_result result = s2a_tsi_handshaker_result_create(session_response,
                                                       /** is_client **/ true,
                                                       /** self **/ nullptr);
  GPR_ASSERT(result == TSI_INVALID_ARGUMENT);

  tsi_handshaker_result* handshaker_result = nullptr;
  /** Invalid peer identity. **/
  result = s2a_tsi_handshaker_result_create(session_response,
                                            /** is_client **/ true,
                                            &handshaker_result);
  GPR_ASSERT(result == TSI_FAILED_PRECONDITION);
  GPR_ASSERT(handshaker_result == nullptr);

  s2a_SessionResult_set_peer_identity(session_result, peer_identity);
  // s2a_SessionResp_set_result(session_response, session_result);

  /** Successfully create handshaker result, set unused bytes, and check that
   *  the result is correct.  **/
  result = s2a_tsi_handshaker_result_create(session_response,
                                            /** is_client **/ true,
                                            &handshaker_result);
  GPR_ASSERT(result == TSI_OK);
  GPR_ASSERT(handshaker_result != nullptr);

  char* recv_bytes = "recv_bytes";
  grpc_slice recv_slice = grpc_slice_from_static_string(recv_bytes);
  size_t recv_size = GRPC_SLICE_LENGTH(recv_slice);
  s2a_tsi_handshaker_result_set_unused_bytes(handshaker_result, &recv_slice,
                                             /** bytes_consumed **/ 0);
  s2a_check_tsi_handshaker_result_for_testing(
      handshaker_result, /** TLS 1.3 **/ 0, kTlsAes128GcmSha256,
      reinterpret_cast<uint8_t*>(traffic_secret.data()),
      reinterpret_cast<uint8_t*>(traffic_secret.data()), traffic_secret.size(),
      spiffe_id, 9, /** hostname **/ nullptr, 0,
      reinterpret_cast<unsigned char*>(recv_bytes), recv_size,
      /** is_client **/ true);

  tsi_handshaker_result_destroy(handshaker_result);
}

}  // namespace experimental
}  // namespace grpc_core

int main(int argc, char** argv) {
  grpc_core::experimental::s2a_test_tsi_handshaker_create_and_destroy();
  grpc_core::experimental::s2a_test_tsi_handshaker_next();
  grpc_core::experimental::s2a_test_tsi_handshaker_result_create_and_destroy();
  return 0;
}
