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
#include <grpc/grpc_security.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <vector>
#include "src/core/lib/iomgr/exec_ctx.h"
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "src/core/tsi/transport_security_grpc.h"
#include "src/core/tsi/transport_security_interface.h"
#include "test/core/tsi/s2a/s2a_test_data.h"
#include "test/core/tsi/s2a/s2a_test_util.h"

using ::experimental::grpc_s2a_credentials_options;
using ::experimental::grpc_s2a_credentials_options_create;
using ::experimental::grpc_s2a_credentials_options_destroy;

namespace grpc_core {
namespace experimental {

std::vector<char> traffic_secret(32, 'k');

char spiffe_id[] = "spiffe_id";

static void s2a_tsi_handshaker_create_and_destroy_test() {
  grpc_s2a_credentials_options* options = grpc_s2a_credentials_options_create();
  tsi_handshaker* handshaker = nullptr;
  char* error_details = nullptr;
  tsi_result create_result =
      s2a_tsi_handshaker_create(options, "target_name", /*is_client=*/true,
                                /*interested_parties=*/nullptr,
                                /*is_test=*/true, &handshaker, &error_details);
  GPR_ASSERT(create_result == TSI_OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(handshaker != nullptr);

  s2a_check_tsi_handshaker_for_testing(
      handshaker, grpc_slice_from_static_string("target_name"),
      /*is_client=*/true,
      /*has_sent_start_message=*/false,
      /*has_created_handshaker_client=*/false,
      /*shutdown=*/false);

  tsi_handshaker_shutdown(handshaker);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  GPR_ASSERT(s2a_tsi_handshaker_has_shutdown(s2a_handshaker));
  tsi_handshaker_destroy(handshaker);
  grpc_s2a_credentials_options_destroy(options);
}

static s2a_SessionResp* s2a_setup_test_session_resp(upb_arena* arena,
                                                    bool has_peer_identity) {
  s2a_SessionState* session_state = s2a_SessionState_new(arena);
  s2a_SessionState_set_tls_version(session_state, s2a_TLS1_3);
  s2a_SessionState_set_tls_ciphersuite(session_state, s2a_AES_128_GCM_SHA256);
  s2a_SessionState_set_in_sequence(session_state, 0);
  s2a_SessionState_set_out_sequence(session_state, 0);
  s2a_SessionState_set_in_key(
      session_state,
      upb_strview_make(traffic_secret.data(), traffic_secret.size()));
  s2a_SessionState_set_out_key(
      session_state,
      upb_strview_make(traffic_secret.data(), traffic_secret.size()));

  s2a_Identity* peer_identity = s2a_Identity_new(arena);
  s2a_Identity_set_spiffe_id(peer_identity, upb_strview_make(spiffe_id, 9));

  s2a_SessionResult* session_result = s2a_SessionResult_new(arena);
  s2a_SessionResult_set_state(session_result, session_state);
  if (has_peer_identity) {
    s2a_SessionResult_set_peer_identity(session_result, peer_identity);
  }
  s2a_SessionResp* session_response = s2a_SessionResp_new(arena);
  s2a_SessionResp_set_result(session_response, session_result);
  return session_response;
}

static void s2a_tsi_handshaker_result_create_and_destroy_test() {
  /** Prepare an s2a_SessionResp instance and a new channel. **/
  upb::Arena arena;
  s2a_SessionResp* session_response =
      s2a_setup_test_session_resp(arena.ptr(), /*has_peer_identity=*/false);
  grpc_channel* channel = new grpc_channel();

  /** Unexpected nullptr arguments. **/
  tsi_result result =
      s2a_tsi_handshaker_result_create(session_response, channel,
                                       /*is_client=*/true,
                                       /*self=*/nullptr);
  GPR_ASSERT(result == TSI_INVALID_ARGUMENT);

  tsi_handshaker_result* handshaker_result = nullptr;
  /** Invalid peer identity. **/
  result =
      s2a_tsi_handshaker_result_create(session_response, channel,
                                       /*is_client=*/true, &handshaker_result);
  GPR_ASSERT(result == TSI_FAILED_PRECONDITION);
  GPR_ASSERT(handshaker_result == nullptr);

  /** Successfully create handshaker result, set unused bytes, and check that
   *  the result is correct.  **/
  session_response =
      s2a_setup_test_session_resp(arena.ptr(), /*has_peer_identity=*/true);
  result =
      s2a_tsi_handshaker_result_create(session_response, channel,
                                       /*is_client=*/true, &handshaker_result);
  GPR_ASSERT(result == TSI_OK);
  GPR_ASSERT(handshaker_result != nullptr);

  char recv_bytes[] = "recv_bytes";
  grpc_slice recv_slice = grpc_slice_from_static_string(recv_bytes);
  size_t recv_size = GRPC_SLICE_LENGTH(recv_slice);
  s2a_tsi_handshaker_result_set_unused_bytes(handshaker_result, &recv_slice,
                                             /*bytes_consumed=*/0);
  s2a_check_tsi_handshaker_result_for_testing(
      handshaker_result, /*TLS 1.3=*/1, kTlsAes128GcmSha256,
      reinterpret_cast<uint8_t*>(traffic_secret.data()),
      reinterpret_cast<uint8_t*>(traffic_secret.data()), traffic_secret.size(),
      spiffe_id, /*spiffe_id_length=*/9, /*hostname=*/nullptr,
      /*hostname_length=*/0, reinterpret_cast<unsigned char*>(recv_bytes),
      recv_size,
      /*is_client=*/true);

  grpc_core::ExecCtx exec_ctx;
  tsi_zero_copy_grpc_protector* protector = nullptr;
  size_t max_protected_frame_size = 0;
  tsi_result frame_protector_result =
      tsi_handshaker_result_create_zero_copy_grpc_protector(
          handshaker_result, &max_protected_frame_size, &protector);
  GPR_ASSERT(frame_protector_result == TSI_OK);
  GPR_ASSERT(protector != nullptr);

  std::vector<uint8_t> test_plaintext = {'1', '2', '3', '4', '5', '6'};
  grpc_slice test_slice = grpc_slice_from_static_buffer(test_plaintext.data(),
                                                        test_plaintext.size());
  grpc_slice_buffer plaintext_buffer;
  grpc_slice_buffer_init(&plaintext_buffer);
  grpc_slice_buffer_add(&plaintext_buffer, test_slice);
  grpc_slice_buffer record_buffer;
  grpc_slice_buffer_init(&record_buffer);

  GPR_ASSERT(tsi_zero_copy_grpc_protector_protect(protector, &plaintext_buffer,
                                                  &record_buffer) == TSI_OK);
  GPR_ASSERT(record_buffer.count == 1);
  uint8_t* record = GRPC_SLICE_START_PTR(record_buffer.slices[0]);
  size_t record_size = GRPC_SLICE_LENGTH(record_buffer.slices[0]);
  GPR_ASSERT(record_size == expected_message_size(test_plaintext.size()));
  for (size_t i = 0; i < record_size; i++) {
    GPR_ASSERT(record[i] == s2a_test_data::aes_128_gcm_decrypt_record_1[i]);
  }

  // Cleanup.
  grpc_slice_buffer_destroy_internal(&plaintext_buffer);
  grpc_slice_buffer_destroy_internal(&record_buffer);
  tsi_zero_copy_grpc_protector_destroy(protector);
  tsi_handshaker_result_destroy(handshaker_result);
  delete channel;
  grpc_core::ExecCtx::Get()->Flush();
}

static bool s2a_compare_peer_property_with_string(
    const tsi_peer_property* property, const char* string, size_t string_size) {
  GPR_ASSERT(property->value.length == string_size);
  for (size_t i = 0; i < string_size; i++) {
    GPR_ASSERT(property->value.data[i] == string[i]);
  }
  return true;
}

static void s2a_tsi_handshaker_result_extract_peer_test() {
  upb::Arena arena;
  s2a_SessionResp* session_response =
      s2a_setup_test_session_resp(arena.ptr(), /*has_peer_identity=*/true);
  grpc_channel* channel = new grpc_channel();
  tsi_handshaker_result* handshaker_result = nullptr;
  tsi_result result =
      s2a_tsi_handshaker_result_create(session_response, channel,
                                       /*is_client=*/true, &handshaker_result);
  GPR_ASSERT(result == TSI_OK);
  GPR_ASSERT(handshaker_result != nullptr);

  tsi_peer peer;
  tsi_result extract_peer_result =
      tsi_handshaker_result_extract_peer(handshaker_result, &peer);
  GPR_ASSERT(extract_peer_result == TSI_OK);

  const tsi_peer_property* cert_type =
      tsi_peer_get_property_by_name(&peer, TSI_CERTIFICATE_TYPE_PEER_PROPERTY);
  GPR_ASSERT(cert_type != nullptr);
  GPR_ASSERT(s2a_compare_peer_property_with_string(
      cert_type, kTsiS2ACertificateType, /*string_size=*/3));

  const tsi_peer_property* peer_spiffe_id =
      tsi_peer_get_property_by_name(&peer, kTsiS2AServiceAccountPeerProperty);
  GPR_ASSERT(spiffe_id != nullptr);
  GPR_ASSERT(s2a_compare_peer_property_with_string(peer_spiffe_id, spiffe_id,
                                                   /*string_size=*/9));

  tsi_peer_destruct(&peer);
  tsi_handshaker_result_destroy(handshaker_result);
  delete channel;
}

}  // namespace experimental
}  // namespace grpc_core

int main(int argc, char** argv) {
  grpc_core::experimental::s2a_tsi_handshaker_create_and_destroy_test();
  grpc_core::experimental::s2a_tsi_handshaker_result_create_and_destroy_test();
  grpc_core::experimental::s2a_tsi_handshaker_result_extract_peer_test();
  return 0;
}
