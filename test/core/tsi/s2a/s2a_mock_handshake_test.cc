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

#include <stdio.h>
#include <stdlib.h>

#include <grpc/grpc.h>
#include <grpc/support/sync.h>

#include "src/core/lib/gprpp/thd.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"
#include "src/core/tsi/s2a/handshaker/s2a_tsi_handshaker.h"

using ::experimental::grpc_s2a_credentials_options;
using ::experimental::grpc_s2a_credentials_options_create;
using ::experimental::grpc_s2a_credentials_options_destroy;

namespace grpc_core {
namespace experimental {

constexpr char kS2AMockHandshakeTestRecvBytes[] = "Hello World";
constexpr char kS2AMockHandshakeTestOutFrame[] = "Hello Google";
constexpr char kS2AMockHandshakeTestConsumedBytes[] = "Hello";
constexpr char kS2AMockHandshakeTestRemainBytes[] = "Google";
constexpr char kS2AMockHandshakeTestPeerIdentity[] = "chapi@service.google.com";
constexpr char kS2AMockHandshakeTestKey[] =
    "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKL";
constexpr size_t kS2AMockHandshakeTestBufferSize = 100;
constexpr size_t kS2AMockHandshakeTestSleepTimeInSeconds = 2;

static bool should_handshaker_client_api_succeed = true;

/** S2A mock notification. **/
typedef struct notification {
  gpr_cv cv;
  gpr_mu mu;
  bool notified;
} notification;

/** Type of S2A handshaker response. **/
enum S2AResponseType {
  INVALID,
  FAILED,
  CLIENT_START,
  SERVER_START,
  CLIENT_NEXT,
  SERVER_NEXT,
};

static S2AHandshakerClient* cb_event = nullptr;
static notification caller_to_tsi_notification;
static notification tsi_to_caller_notification;

static void notification_init(notification* n) {
  gpr_mu_init(&n->mu);
  gpr_cv_init(&n->cv);
  n->notified = false;
}

static void notification_destroy(notification* n) {
  gpr_mu_destroy(&n->mu);
  gpr_cv_destroy(&n->cv);
}

static void signal(notification* n) {
  gpr_mu_lock(&n->mu);
  n->notified = true;
  gpr_cv_signal(&n->cv);
  gpr_mu_unlock(&n->mu);
}

static void wait(notification* n) {
  gpr_mu_lock(&n->mu);
  while (!n->notified) {
    gpr_cv_wait(&n->cv, &n->mu, gpr_inf_future(GPR_CLOCK_REALTIME));
  }
  n->notified = false;
  gpr_mu_unlock(&n->mu);
}

/** This method mocks the S2A handshaker service to generate handshaker response
 *  for a specific request. **/
static grpc_byte_buffer* generate_handshaker_response(S2AResponseType type) {
  upb::Arena arena;
  s2a_SessionResult* result;
  s2a_Identity* peer_identity;
  s2a_SessionState* state;
  s2a_SessionResp* resp = s2a_SessionResp_new(arena.ptr());
  s2a_SessionStatus* status = s2a_SessionResp_mutable_status(resp, arena.ptr());
  s2a_SessionStatus_set_code(status, 0);
  /**
  switch (type) {
    case S2AResponseType::INVALID:
      break;
    case S2AResponseType::CLIENT_START:
    case S2AResponseType::SERVER_START:
      s2a_SessionResp_set_out_frames(
          resp, upb_strview_makez(kS2AMockHandshakeTestOutFrame));
      break;
    case S2AResponseType::CLIENT_NEXT:
      s2a_SessionResp_set_out_frames(
          resp, upb_strview_makez(kS2AMockHandshakeTestOutFrame));
      s2a_SessionResp_set_bytes_consumed(
          resp, strlen(kS2AMockHandshakeTestConsumedBytes));
      result = s2a_SessionResp_mutable_result(resp, arena.ptr());
      peer_identity =
          s2a_SessionResult_mutable_peer_identity(result, arena.ptr());
      s2a_Identity_set_spiffe_id(
          peer_identity, upb_strview_makez(kS2AMockHandshakeTestPeerIdentity));
      state = s2a_SessionResult_mutable_state(result, arena.ptr());
      // s2a_SessionState_set_tls_ciphersuite(
      s2a_SessionState_set_in_key(kS2AMockHandshakeTestKey);
      s2a_SessionState_set_out_key(kS2AMockHandshakeTestKey);
      s2a_SessionResult_set_application_protocol(kS2AApplicationProtocol);
      /**
      grpc_gcp_HandshakerResult_set_application_protocol(
          result,
          upb_strview_makez(ALTS_TSI_HANDSHAKER_TEST_APPLICATION_PROTOCOL));
      grpc_gcp_HandshakerResult_set_record_protocol(
          result, upb_strview_makez(ALTS_TSI_HANDSHAKER_TEST_RECORD_PROTOCOL));
      **/
  /**
      break;
    case S2AResponseType::SERVER_NEXT:
      /**
      grpc_gcp_HandshakerResp_set_bytes_consumed(
          resp, strlen(ALTS_TSI_HANDSHAKER_TEST_OUT_FRAME));
      result = grpc_gcp_HandshakerResp_mutable_result(resp, arena.ptr());
      peer_identity =
          grpc_gcp_HandshakerResult_mutable_peer_identity(result, arena.ptr());
      grpc_gcp_Identity_set_service_account(
          peer_identity,
          upb_strview_makez(ALTS_TSI_HANDSHAKER_TEST_PEER_IDENTITY));
      grpc_gcp_HandshakerResult_set_key_data(
          result, upb_strview_makez(ALTS_TSI_HANDSHAKER_TEST_KEY_DATA));
      grpc_gcp_HandshakerResult_set_application_protocol(
          result,
          upb_strview_makez(ALTS_TSI_HANDSHAKER_TEST_APPLICATION_PROTOCOL));
      grpc_gcp_HandshakerResult_set_record_protocol(
          result, upb_strview_makez(ALTS_TSI_HANDSHAKER_TEST_RECORD_PROTOCOL));
      **/
  /**
      break;
    case S2AResponseType::FAILED:
      s2a_SessionStatus_set_code(status, /*INVALID ARGUMENT=*//**3);
      break;
  }**/
  size_t buf_len;
  char* buf = s2a_SessionResp_serialize(resp, arena.ptr(), &buf_len);
  grpc_slice slice = gpr_slice_from_copied_buffer(buf, buf_len);
  if (type == INVALID) {
    grpc_slice bad_slice =
        grpc_slice_split_head(&slice, GRPC_SLICE_LENGTH(slice) - 1);
    grpc_slice_unref(slice);
    slice = grpc_slice_ref(bad_slice);
    grpc_slice_unref(bad_slice);
  }
  grpc_byte_buffer* buffer =
      grpc_raw_byte_buffer_create(&slice, /*number of slices=*/1);
  grpc_slice_unref(slice);
  return buffer;
}

static void check_must_not_be_called(tsi_result /*status*/, void* /*user_data*/,
                                     const unsigned char* /*bytes_to_send*/,
                                     size_t /*bytes_to_send_size*/,
                                     tsi_handshaker_result* /*result*/) {
  GPR_ASSERT(0);
}

static void on_client_start_success_cb(tsi_result status, void* user_data,
                                       const unsigned char* bytes_to_send,
                                       size_t bytes_to_send_size,
                                       tsi_handshaker_result* result) {
  GPR_ASSERT(status == TSI_OK);
  GPR_ASSERT(user_data == nullptr);
  GPR_ASSERT(bytes_to_send_size == strlen(kS2AMockHandshakeTestOutFrame));
  GPR_ASSERT(memcmp(bytes_to_send, kS2AMockHandshakeTestOutFrame,
                    bytes_to_send_size) == 0);
  GPR_ASSERT(result == nullptr);
  /* Validate peer identity. */
  tsi_peer peer;
  GPR_ASSERT(tsi_handshaker_result_extract_peer(result, &peer) ==
             TSI_INVALID_ARGUMENT);
  /* Validate frame protector. */
  tsi_frame_protector* protector = nullptr;
  GPR_ASSERT(tsi_handshaker_result_create_frame_protector(
                 result, nullptr, &protector) == TSI_INVALID_ARGUMENT);
  /* Validate unused bytes. */
  const unsigned char* unused_bytes = nullptr;
  size_t unused_bytes_size = 0;
  GPR_ASSERT(tsi_handshaker_result_get_unused_bytes(result, &unused_bytes,
                                                    &unused_bytes_size) ==
             TSI_INVALID_ARGUMENT);
  signal(&tsi_to_caller_notification);
}

static void on_server_start_success_cb(tsi_result status, void* user_data,
                                       const unsigned char* bytes_to_send,
                                       size_t bytes_to_send_size,
                                       tsi_handshaker_result* result) {
  GPR_ASSERT(status == TSI_OK);
  GPR_ASSERT(user_data == nullptr);
  GPR_ASSERT(bytes_to_send_size == strlen(kS2AMockHandshakeTestOutFrame));
  GPR_ASSERT(memcmp(bytes_to_send, kS2AMockHandshakeTestOutFrame,
                    bytes_to_send_size) == 0);
  GPR_ASSERT(result == nullptr);
  /* Validate peer identity. */
  tsi_peer peer;
  GPR_ASSERT(tsi_handshaker_result_extract_peer(result, &peer) ==
             TSI_INVALID_ARGUMENT);
  /* Validate frame protector. */
  tsi_frame_protector* protector = nullptr;
  GPR_ASSERT(tsi_handshaker_result_create_frame_protector(
                 result, nullptr, &protector) == TSI_INVALID_ARGUMENT);
  /* Validate unused bytes. */
  const unsigned char* unused_bytes = nullptr;
  size_t unused_bytes_size = 0;
  GPR_ASSERT(tsi_handshaker_result_get_unused_bytes(result, &unused_bytes,
                                                    &unused_bytes_size) ==
             TSI_INVALID_ARGUMENT);
  signal(&tsi_to_caller_notification);
}

static void on_client_next_success_cb(tsi_result status, void* user_data,
                                      const unsigned char* bytes_to_send,
                                      size_t bytes_to_send_size,
                                      tsi_handshaker_result* result) {
  GPR_ASSERT(status == TSI_OK);
  GPR_ASSERT(user_data == nullptr);
  GPR_ASSERT(bytes_to_send_size == strlen(kS2AMockHandshakeTestOutFrame));
  GPR_ASSERT(memcmp(bytes_to_send, kS2AMockHandshakeTestOutFrame,
                    bytes_to_send_size) == 0);
  GPR_ASSERT(result != nullptr);
  /* Validate peer identity. */
  tsi_peer peer;
  GPR_ASSERT(tsi_handshaker_result_extract_peer(result, &peer) == TSI_OK);
  GPR_ASSERT(peer.property_count == kTsiS2ANumOfPeerProperties);
  GPR_ASSERT(memcmp(kTsiS2ACertificateType, peer.properties[0].value.data,
                    peer.properties[0].value.length) == 0);
  GPR_ASSERT(memcmp(kS2AMockHandshakeTestPeerIdentity,
                    peer.properties[1].value.data,
                    peer.properties[1].value.length) == 0);
  /* Validate alts context. */
  /**upb::Arena context_arena;
  grpc_gcp_AltsContext* ctx = grpc_gcp_AltsContext_parse(
      peer.properties[3].value.data, peer.properties[3].value.length,
      context_arena.ptr());
  GPR_ASSERT(ctx != nullptr);
  upb_strview application_protocol =
      grpc_gcp_AltsContext_application_protocol(ctx);
  upb_strview record_protocol = grpc_gcp_AltsContext_record_protocol(ctx);
  upb_strview peer_account = grpc_gcp_AltsContext_peer_service_account(ctx);
  upb_strview local_account = grpc_gcp_AltsContext_local_service_account(ctx);
  GPR_ASSERT(memcmp(ALTS_TSI_HANDSHAKER_TEST_APPLICATION_PROTOCOL,
                    application_protocol.data, application_protocol.size) == 0);
  GPR_ASSERT(memcmp(ALTS_TSI_HANDSHAKER_TEST_RECORD_PROTOCOL,
                    record_protocol.data, record_protocol.size) == 0);
  GPR_ASSERT(memcmp(ALTS_TSI_HANDSHAKER_TEST_PEER_IDENTITY, peer_account.data,
                    peer_account.size) == 0);
  GPR_ASSERT(memcmp(ALTS_TSI_HANDSHAKER_TEST_LOCAL_IDENTITY, local_account.data,
                    local_account.size) == 0);
  tsi_peer_destruct(&peer);
  **/
  /* Validate unused bytes. */
  /**const unsigned char* bytes = nullptr;
  size_t bytes_size = 0;
  GPR_ASSERT(tsi_handshaker_result_get_unused_bytes(result, &bytes,
                                                    &bytes_size) == TSI_OK);
  GPR_ASSERT(bytes_size == strlen(ALTS_TSI_HANDSHAKER_TEST_REMAIN_BYTES));
  GPR_ASSERT(memcmp(bytes, ALTS_TSI_HANDSHAKER_TEST_REMAIN_BYTES, bytes_size) ==
             0);
  **/
  /* Validate frame protector. */
  tsi_frame_protector* protector = nullptr;
  GPR_ASSERT(tsi_handshaker_result_create_frame_protector(
                 result, nullptr, &protector) == TSI_OK);
  GPR_ASSERT(protector != nullptr);
  tsi_frame_protector_destroy(protector);
  tsi_handshaker_result_destroy(result);
  signal(&tsi_to_caller_notification);
}

static void on_server_next_success_cb(tsi_result status, void* user_data,
                                      const unsigned char* bytes_to_send,
                                      size_t bytes_to_send_size,
                                      tsi_handshaker_result* result) {
  GPR_ASSERT(status == TSI_OK);
  GPR_ASSERT(user_data == nullptr);
  GPR_ASSERT(bytes_to_send_size == 0);
  GPR_ASSERT(bytes_to_send == nullptr);
  GPR_ASSERT(result != nullptr);
  /* Validate peer identity. */
  /**tsi_peer peer;
  GPR_ASSERT(tsi_handshaker_result_extract_peer(result, &peer) == TSI_OK);
  GPR_ASSERT(peer.property_count == kTsiAltsNumOfPeerProperties);
  GPR_ASSERT(memcmp(TSI_ALTS_CERTIFICATE_TYPE, peer.properties[0].value.data,
                    peer.properties[0].value.length) == 0);
  GPR_ASSERT(memcmp(ALTS_TSI_HANDSHAKER_TEST_PEER_IDENTITY,
                    peer.properties[1].value.data,
                    peer.properties[1].value.length) == 0);
  **/
  /* Validate alts context. */
  /**upb::Arena context_arena;
  grpc_gcp_AltsContext* ctx = grpc_gcp_AltsContext_parse(
      peer.properties[3].value.data, peer.properties[3].value.length,
      context_arena.ptr());
  GPR_ASSERT(ctx != nullptr);
  upb_strview application_protocol =
      grpc_gcp_AltsContext_application_protocol(ctx);
  upb_strview record_protocol = grpc_gcp_AltsContext_record_protocol(ctx);
  upb_strview peer_account = grpc_gcp_AltsContext_peer_service_account(ctx);
  upb_strview local_account = grpc_gcp_AltsContext_local_service_account(ctx);
  GPR_ASSERT(memcmp(ALTS_TSI_HANDSHAKER_TEST_APPLICATION_PROTOCOL,
                    application_protocol.data, application_protocol.size) == 0);
  GPR_ASSERT(memcmp(ALTS_TSI_HANDSHAKER_TEST_RECORD_PROTOCOL,
                    record_protocol.data, record_protocol.size) == 0);
  GPR_ASSERT(memcmp(ALTS_TSI_HANDSHAKER_TEST_PEER_IDENTITY, peer_account.data,
                    peer_account.size) == 0);
  GPR_ASSERT(memcmp(ALTS_TSI_HANDSHAKER_TEST_LOCAL_IDENTITY, local_account.data,
                    local_account.size) == 0);
  tsi_peer_destruct(&peer);
  **/
  /* Validate unused bytes. */
  /**const unsigned char* bytes = nullptr;
  size_t bytes_size = 0;
  GPR_ASSERT(tsi_handshaker_result_get_unused_bytes(result, &bytes,
                                                    &bytes_size) == TSI_OK);
  GPR_ASSERT(bytes_size == 0);
  GPR_ASSERT(bytes == nullptr);
  **/
  /* Validate frame protector. */
  tsi_frame_protector* protector = nullptr;
  GPR_ASSERT(tsi_handshaker_result_create_frame_protector(
                 result, nullptr, &protector) == TSI_OK);
  GPR_ASSERT(protector != nullptr);
  tsi_frame_protector_destroy(protector);
  tsi_handshaker_result_destroy(result);
  signal(&tsi_to_caller_notification);
}

class MockHandshakerClient : public S2AHandshakerClient {
 public:
  MockHandshakerClient(s2a_tsi_handshaker* handshaker, grpc_channel* channel,
                       grpc_pollset_set* interested_parties,
                       const grpc_s2a_credentials_options* options,
                       const grpc_slice& target_name,
                       grpc_iomgr_cb_func grpc_cb,
                       tsi_handshaker_on_next_done_cb cb, void* user_data,
                       bool is_client, bool is_test)
      : S2AHandshakerClient(handshaker, channel, interested_parties, options,
                            target_name, grpc_cb, cb, user_data, is_client,
                            is_test) {}

  tsi_result ClientStart() {
    if (!should_handshaker_client_api_succeed) {
      return TSI_INTERNAL_ERROR;
    }
    CheckFieldsForTesting(on_client_start_success_cb,
                          /*user_data=*/nullptr,
                          /*has_sent_start_message=*/true,
                          /*recv_bytes=*/nullptr);
    /** Populate handshaker response for client_start request. **/
    grpc_byte_buffer** recv_buffer_ptr = recv_buffer_addr_for_testing();
    GPR_ASSERT(recv_buffer_ptr != nullptr);
    *recv_buffer_ptr = generate_handshaker_response(CLIENT_START);
    cb_event = this;
    signal(&caller_to_tsi_notification);
    return TSI_OK;
  }

  tsi_result ServerStart(grpc_slice* bytes_received) {
    if (!should_handshaker_client_api_succeed) {
      return TSI_INTERNAL_ERROR;
    }
    CheckFieldsForTesting(on_server_start_success_cb,
                          /*user_data=*/nullptr,
                          /*has_sent_start_message=*/true,
                          /*recv_bytes=*/nullptr);
    grpc_slice slice = grpc_empty_slice();
    GPR_ASSERT(grpc_slice_cmp(*bytes_received, slice) == 0);
    /** Populate handshaker response for server_start request. **/
    grpc_byte_buffer** recv_buffer_ptr = recv_buffer_addr_for_testing();
    GPR_ASSERT(recv_buffer_ptr != nullptr);
    *recv_buffer_ptr = generate_handshaker_response(SERVER_START);
    cb_event = this;
    grpc_slice_unref(slice);
    signal(&caller_to_tsi_notification);
    return TSI_OK;
  }

  tsi_result Next(grpc_slice* bytes_received) {
    if (!should_handshaker_client_api_succeed) {
      return TSI_INTERNAL_ERROR;
    }
    s2a_tsi_handshaker* handshaker = handshaker_for_testing();
    bool is_client = is_client_for_testing();
    tsi_handshaker_on_next_done_cb cb =
        is_client ? on_client_next_success_cb : on_server_next_success_cb;
    set_cb_for_testing(cb);
    set_recv_bytes_for_testing(bytes_received);
    CheckFieldsForTesting(cb, /*user_data=*/nullptr,
                          /*has_sent_start_message=*/true, bytes_received);
    GPR_ASSERT(bytes_received != nullptr);
    GPR_ASSERT(memcmp(GRPC_SLICE_START_PTR(*bytes_received),
                      kS2AMockHandshakeTestRecvBytes,
                      GRPC_SLICE_LENGTH(*bytes_received)) == 0);
    /** Populate handshaker response for next request. **/
    grpc_slice out_frame =
        grpc_slice_from_static_string(kS2AMockHandshakeTestOutFrame);
    grpc_byte_buffer** recv_buffer_ptr = recv_buffer_addr_for_testing();
    GPR_ASSERT(recv_buffer_ptr != nullptr);
    *recv_buffer_ptr = is_client ? generate_handshaker_response(CLIENT_NEXT)
                                 : generate_handshaker_response(SERVER_NEXT);
    set_recv_bytes_for_testing(&out_frame);
    cb_event = this;
    signal(&caller_to_tsi_notification);
    grpc_slice_unref(out_frame);
    return TSI_OK;
  }

  void Shutdown() {}
};

static tsi_result s2a_create_mock_handshaker_client(
    s2a_tsi_handshaker* handshaker, grpc_channel* channel,
    grpc_pollset_set* interested_parties,
    const grpc_s2a_credentials_options* options, const grpc_slice& target_name,
    grpc_iomgr_cb_func grpc_cb, tsi_handshaker_on_next_done_cb cb,
    void* user_data, bool is_client, S2AHandshakerClient** client) {
  if (channel == nullptr || client == nullptr ||
      options->handshaker_service_url().empty()) {
    gpr_log(GPR_ERROR, kS2AHandshakerClientNullptrArguments);
    return TSI_INVALID_ARGUMENT;
  }
  *client = new MockHandshakerClient(handshaker, channel, interested_parties,
                                     options, target_name, grpc_cb, cb,
                                     user_data, is_client, /*is_test=*/true);
  return TSI_OK;
}

static tsi_handshaker* create_test_handshaker(bool is_client) {
  tsi_handshaker* handshaker = nullptr;
  grpc_s2a_credentials_options* options = grpc_s2a_credentials_options_create();
  options->set_handshaker_service_url(kS2AHandshakerServiceUrlForTesting);
  char* error_details = nullptr;
  tsi_result create_result =
      s2a_tsi_handshaker_create(options, "target_name", is_client,
                                /*interested_parties=*/nullptr,
                                /*is_test=*/true, &handshaker, &error_details);
  GPR_ASSERT(create_result == TSI_OK);
  GPR_ASSERT(error_details == nullptr);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  s2a_tsi_handshaker_set_create_mock_handshaker_client(
      s2a_handshaker, s2a_create_mock_handshaker_client);
  return handshaker;
}

static void run_tsi_handshaker_destroy_with_exec_ctx(
    tsi_handshaker* handshaker) {
  grpc_core::ExecCtx exec_ctx;
  grpc_s2a_credentials_options_destroy(
      const_cast<grpc_s2a_credentials_options*>(
          s2a_tsi_handshaker_options_for_testing(handshaker)));
  tsi_handshaker_destroy(handshaker);
}

static void s2a_check_handshaker_next_invalid_input() {
  /** Initialization. **/
  tsi_handshaker* handshaker = create_test_handshaker(/*is_client=*/true);
  /** Check nullptr handshaker. **/
  GPR_ASSERT(
      tsi_handshaker_next(/*handshaker=*/nullptr, /*received_bytes=*/nullptr,
                          /*received_bytes_size=*/0,
                          /*bytes_to_send=*/nullptr,
                          /*bytes_to_send_size=*/nullptr, /*result=*/nullptr,
                          check_must_not_be_called,
                          /*user_data=*/nullptr) == TSI_INVALID_ARGUMENT);
  /** Check nullptr callback. **/
  GPR_ASSERT(tsi_handshaker_next(handshaker, /*received_bytes=*/nullptr,
                                 /*received_bytes_size=*/0,
                                 /*bytes_to_send=*/nullptr,
                                 /*bytes_to_send_size=*/nullptr,
                                 /*result=*/nullptr, /*cb=*/nullptr,
                                 /*user_data=*/nullptr) ==
             TSI_INVALID_ARGUMENT);
  /** Cleanup. **/
  run_tsi_handshaker_destroy_with_exec_ctx(handshaker);
}

static void s2a_check_handshaker_shutdown_invalid_input() {
  /** Initialization. **/
  tsi_handshaker* handshaker = create_test_handshaker(/*is_client=*/true);
  /** Check nullptr handshaker. **/
  tsi_handshaker_shutdown(/*self=*/nullptr);
  /** Cleanup. **/
  run_tsi_handshaker_destroy_with_exec_ctx(handshaker);
}

static void s2a_check_handshaker_next_success() {
  /** Create handshakers for which internal mock client is going to do
   *  correctness check. **/
  tsi_handshaker* client_handshaker =
      create_test_handshaker(/*is_client=*/true);
  tsi_handshaker* server_handshaker =
      create_test_handshaker(/*is_client=*/false);
  /** Client start. **/
  GPR_ASSERT(tsi_handshaker_next(client_handshaker, /*received_bytes=*/nullptr,
                                 /*received_bytes_size=*/0,
                                 /*bytes_to_send=*/nullptr,
                                 /*bytes_to_send_size=*/nullptr,
                                 /*result=*/nullptr, on_client_start_success_cb,
                                 /*user_data=*/nullptr) == TSI_ASYNC);
  wait(&tsi_to_caller_notification);
  /** Client next. **/
  GPR_ASSERT(tsi_handshaker_next(client_handshaker,
                                 reinterpret_cast<const unsigned char*>(
                                     kS2AMockHandshakeTestRecvBytes),
                                 strlen(kS2AMockHandshakeTestRecvBytes),
                                 /*bytes_to_send=*/nullptr,
                                 /*bytes_to_send_size=*/nullptr,
                                 /*result=*/nullptr, on_client_next_success_cb,
                                 /*user_data=*/nullptr) == TSI_ASYNC);
  wait(&tsi_to_caller_notification);
  /** Server start. **/
  GPR_ASSERT(tsi_handshaker_next(server_handshaker, /*received_bytes=*/nullptr,
                                 /*received_bytes_size=*/0,
                                 /*bytes_to_send=*/nullptr,
                                 /*bytes_to_send_size=*/nullptr,
                                 /*result=*/nullptr, on_server_start_success_cb,
                                 /*user_data=*/nullptr) == TSI_ASYNC);
  wait(&tsi_to_caller_notification);
  /** Server next. **/
  GPR_ASSERT(tsi_handshaker_next(server_handshaker,
                                 reinterpret_cast<const unsigned char*>(
                                     kS2AMockHandshakeTestRecvBytes),
                                 strlen(kS2AMockHandshakeTestRecvBytes),
                                 /*bytes_to_send=*/nullptr,
                                 /*bytes_to_send_size=*/nullptr,
                                 /*result=*/nullptr, on_server_next_success_cb,
                                 /*user_data=*/nullptr) == TSI_ASYNC);
  wait(&tsi_to_caller_notification);
  /** Cleanup. **/
  run_tsi_handshaker_destroy_with_exec_ctx(server_handshaker);
  run_tsi_handshaker_destroy_with_exec_ctx(client_handshaker);
}

static void s2a_check_handshaker_next_with_shutdown() {
  tsi_handshaker* handshaker = create_test_handshaker(/*is_client=*/true);
  /* next(success) -- shutdown(success) -- next (fail) */
  GPR_ASSERT(tsi_handshaker_next(handshaker, /*received_bytes=*/nullptr,
                                 /*received_bytes_size=*/0,
                                 /*bytes_to_send=*/nullptr,
                                 /*bytes_to_send_size=*/nullptr,
                                 /*result=*/nullptr, on_client_start_success_cb,
                                 /*user_data=*/nullptr) == TSI_ASYNC);
  wait(&tsi_to_caller_notification);
  tsi_handshaker_shutdown(handshaker);
  GPR_ASSERT(tsi_handshaker_next(
                 handshaker,
                 reinterpret_cast<const unsigned char*>(
                     kS2AMockHandshakeTestRecvBytes),
                 strlen(kS2AMockHandshakeTestRecvBytes),
                 /*bytes_to_send=*/nullptr, /*bytes_to_send_size=*/nullptr,
                 /*result=*/nullptr, on_client_next_success_cb,
                 /*user_data=*/nullptr) == TSI_HANDSHAKE_SHUTDOWN);
  /** Cleanup. **/
  run_tsi_handshaker_destroy_with_exec_ctx(handshaker);
}

static void s2a_check_handle_response_with_shutdown(void* /*unused*/) {
  wait(&caller_to_tsi_notification);
  GPR_ASSERT(cb_event != nullptr);
  cb_event->HandleResponse(/*is_ok=*/true);
}

static void s2a_check_handshaker_next_failure() {
  /** Create handshakers for which internal mock client is always going to fail.
   *  **/
  tsi_handshaker* client_handshaker =
      create_test_handshaker(/*is_client=*/true);
  tsi_handshaker* server_handshaker =
      create_test_handshaker(/*is_client=*/false);
  /** Client start. **/
  GPR_ASSERT(tsi_handshaker_next(client_handshaker, /*received_bytes=*/nullptr,
                                 /*received_bytes_size=*/0,
                                 /*bytes_to_send=*/nullptr,
                                 /*bytes_to_send_size=*/nullptr,
                                 /*result=*/nullptr, check_must_not_be_called,
                                 /*user_data=*/nullptr) == TSI_INTERNAL_ERROR);
  /** Server start. **/
  GPR_ASSERT(tsi_handshaker_next(server_handshaker, /*received_bytes=*/nullptr,
                                 /*received_bytes_size=*/0,
                                 /*bytes_to_send=*/nullptr,
                                 /*bytes_to_send_size=*/nullptr,
                                 /*result=*/nullptr, check_must_not_be_called,
                                 /*user_data=*/nullptr) == TSI_INTERNAL_ERROR);
  /** Server next. **/
  GPR_ASSERT(tsi_handshaker_next(server_handshaker,
                                 reinterpret_cast<const unsigned char*>(
                                     kS2AMockHandshakeTestRecvBytes),
                                 strlen(kS2AMockHandshakeTestRecvBytes),
                                 /*bytes_to_send=*/nullptr,
                                 /*bytes_to_send_size=*/nullptr,
                                 /*result=*/nullptr, check_must_not_be_called,
                                 /*user_data=*/nullptr) == TSI_INTERNAL_ERROR);
  /** Client next. **/
  GPR_ASSERT(tsi_handshaker_next(client_handshaker,
                                 reinterpret_cast<const unsigned char*>(
                                     kS2AMockHandshakeTestRecvBytes),
                                 strlen(kS2AMockHandshakeTestRecvBytes),
                                 /*bytes_to_send=*/nullptr,
                                 /*bytes_to_send_size=*/nullptr,
                                 /*result=*/nullptr, check_must_not_be_called,
                                 /*user_data=*/nullptr) == TSI_INTERNAL_ERROR);
  /** Cleanup. **/
  run_tsi_handshaker_destroy_with_exec_ctx(server_handshaker);
  run_tsi_handshaker_destroy_with_exec_ctx(client_handshaker);
}

static void on_invalid_input_cb(tsi_result status, void* user_data,
                                const unsigned char* bytes_to_send,
                                size_t bytes_to_send_size,
                                tsi_handshaker_result* result) {
  GPR_ASSERT(status == TSI_INTERNAL_ERROR);
  GPR_ASSERT(user_data == nullptr);
  GPR_ASSERT(bytes_to_send == nullptr);
  GPR_ASSERT(bytes_to_send_size == 0);
  GPR_ASSERT(result == nullptr);
}

static void on_failed_grpc_call_cb(tsi_result status, void* user_data,
                                   const unsigned char* bytes_to_send,
                                   size_t bytes_to_send_size,
                                   tsi_handshaker_result* result) {
  GPR_ASSERT(status == TSI_INTERNAL_ERROR);
  GPR_ASSERT(user_data == nullptr);
  GPR_ASSERT(bytes_to_send == nullptr);
  GPR_ASSERT(bytes_to_send_size == 0);
  GPR_ASSERT(result == nullptr);
}

static void s2a_check_handle_response_nullptr_handshaker() {
  /** Initialization. **/
  notification_init(&caller_to_tsi_notification);
  notification_init(&tsi_to_caller_notification);
  /** Create a handshaker at the client side, for which internal mock client is
   *  always going to fail. **/
  tsi_handshaker* handshaker = create_test_handshaker(/*is_client=*/true);
  tsi_handshaker_next(
      handshaker, /*received_bytes=*/nullptr, /*received_bytes_size=*/0,
      /*bytes_to_send=*/nullptr, /*bytes_to_send_size=*/nullptr,
      /*result=*/nullptr, on_client_start_success_cb, /*user_data=*/nullptr);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  grpc_slice slice = grpc_empty_slice();
  grpc_byte_buffer* recv_buffer = grpc_raw_byte_buffer_create(&slice, 1);
  S2AHandshakerClient* client =
      s2a_tsi_handshaker_client_for_testing(s2a_handshaker);
  /** Check nullptr handshaker. **/
  GPR_ASSERT(client != nullptr);
  client->SetFieldsForTesting(/*handshaker=*/nullptr, on_invalid_input_cb,
                              /*user_data=*/nullptr, recv_buffer,
                              GRPC_STATUS_OK);
  client->HandleResponse(/*is_ok=*/true);
  /* Note: here and elsewhere in this test, we first ref the handshaker in order
   * to match the unref that on_status_received will do. This necessary
   * because this test mocks out the grpc call in such a way that the code
   * path that would usually take this ref is skipped. */
  client->ref_for_testing();
  {
    grpc_core::ExecCtx exec_ctx;
    client->on_status_received_for_testing(GRPC_STATUS_OK, GRPC_ERROR_NONE);
  }
  /** Cleanup. **/
  grpc_slice_unref(slice);
  run_tsi_handshaker_destroy_with_exec_ctx(handshaker);
  notification_destroy(&caller_to_tsi_notification);
  notification_destroy(&tsi_to_caller_notification);
}

static void s2a_check_handle_response_nullptr_recv_bytes() {
  /** Initialization. **/
  notification_init(&caller_to_tsi_notification);
  notification_init(&tsi_to_caller_notification);
  /** Create a handshaker at the client side, for which internal mock client is
   *  always going to fail. **/
  tsi_handshaker* handshaker = create_test_handshaker(/*is_client=*/true);
  tsi_handshaker_next(handshaker, /*received_bytes=*/nullptr,
                      /*received_bytes_size=*/0, /*bytes_to_send=*/nullptr,
                      /*bytes_to_send_size=*/nullptr, /*result=*/nullptr,
                      on_client_start_success_cb, /*user_data=*/nullptr);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  S2AHandshakerClient* client =
      s2a_tsi_handshaker_client_for_testing(s2a_handshaker);
  /** Check nullptr recv_bytes. **/
  GPR_ASSERT(client != nullptr);
  client->SetFieldsForTesting(s2a_handshaker, on_invalid_input_cb,
                              /*user_data=*/nullptr,
                              /*recv_buffer=*/nullptr, GRPC_STATUS_OK);
  client->HandleResponse(/*is_ok=*/true);
  client->ref_for_testing();
  {
    grpc_core::ExecCtx exec_ctx;
    client->on_status_received_for_testing(GRPC_STATUS_OK, GRPC_ERROR_NONE);
  }
  /** Cleanup. **/
  run_tsi_handshaker_destroy_with_exec_ctx(handshaker);
  notification_destroy(&caller_to_tsi_notification);
  notification_destroy(&tsi_to_caller_notification);
}

static void s2a_check_handle_response_failed_grpc_call_to_handshaker_service() {
  /** Initialization. **/
  notification_init(&caller_to_tsi_notification);
  notification_init(&tsi_to_caller_notification);
  /** Create a handshaker at the client side, for which internal mock client is
   *  always going to fail. **/
  tsi_handshaker* handshaker = create_test_handshaker(/*is_client=*/true);
  tsi_handshaker_next(
      handshaker, /*received_bytes=*/nullptr, /*received_bytes_size=*/0,
      /*bytes_to_send=*/nullptr, /*bytes_to_send_size=*/nullptr,
      /*result=*/nullptr, on_client_start_success_cb, /*user_data=*/nullptr);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  grpc_slice slice = grpc_empty_slice();
  grpc_byte_buffer* recv_buffer = grpc_raw_byte_buffer_create(&slice, 1);
  S2AHandshakerClient* client =
      s2a_tsi_handshaker_client_for_testing(s2a_handshaker);
  /** Check failed grpc call made to handshaker service. **/
  GPR_ASSERT(client != nullptr);
  client->SetFieldsForTesting(s2a_handshaker, on_failed_grpc_call_cb,
                              /*user_data=*/nullptr, recv_buffer,
                              GRPC_STATUS_UNKNOWN);
  client->HandleResponse(/*is_ok=*/true);
  client->ref_for_testing();
  {
    grpc_core::ExecCtx exec_ctx;
    client->on_status_received_for_testing(GRPC_STATUS_UNKNOWN,
                                           GRPC_ERROR_NONE);
  }
  /** Cleanup. **/
  grpc_slice_unref(slice);
  run_tsi_handshaker_destroy_with_exec_ctx(handshaker);
  notification_destroy(&caller_to_tsi_notification);
  notification_destroy(&tsi_to_caller_notification);
}

static void
s2a_check_handle_response_failed_recv_message_from_handshaker_service() {
  /** Initialization. **/
  notification_init(&caller_to_tsi_notification);
  notification_init(&tsi_to_caller_notification);
  /** Create a handshaker at the client side, for which internal mock client is
   *  always going to fail. **/
  tsi_handshaker* handshaker = create_test_handshaker(/*is_client=*/true);
  tsi_handshaker_next(
      handshaker, /*received_bytes=*/nullptr, /*received_bytes_size=*/0,
      /*bytes_to_send=*/nullptr, /*bytes_to_send_size=*/nullptr,
      /*result=*/nullptr, on_client_start_success_cb, /*user_data=*/nullptr);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  grpc_slice slice = grpc_empty_slice();
  grpc_byte_buffer* recv_buffer = grpc_raw_byte_buffer_create(&slice, 1);
  S2AHandshakerClient* client =
      s2a_tsi_handshaker_client_for_testing(s2a_handshaker);
  /** Check failed recv message op from handshaker service. **/
  GPR_ASSERT(client != nullptr);
  client->SetFieldsForTesting(s2a_handshaker, on_failed_grpc_call_cb,
                              /*user_data=*/nullptr, recv_buffer,
                              GRPC_STATUS_OK);
  client->HandleResponse(/*is_ok=*/false);
  client->ref_for_testing();
  {
    grpc_core::ExecCtx exec_ctx;
    client->on_status_received_for_testing(GRPC_STATUS_OK, GRPC_ERROR_NONE);
  }
  /** Cleanup. **/
  grpc_slice_unref(slice);
  run_tsi_handshaker_destroy_with_exec_ctx(handshaker);
  notification_destroy(&caller_to_tsi_notification);
  notification_destroy(&tsi_to_caller_notification);
}

static void on_invalid_resp_cb(tsi_result status, void* user_data,
                               const unsigned char* bytes_to_send,
                               size_t bytes_to_send_size,
                               tsi_handshaker_result* result) {
  GPR_ASSERT(status == TSI_DATA_CORRUPTED);
  GPR_ASSERT(user_data == nullptr);
  GPR_ASSERT(bytes_to_send == nullptr);
  GPR_ASSERT(bytes_to_send_size == 0);
  GPR_ASSERT(result == nullptr);
}

static void s2a_check_handle_response_invalid_resp() {
  /** Initialization. **/
  notification_init(&caller_to_tsi_notification);
  notification_init(&tsi_to_caller_notification);
  /** Create a handshaker at the client side, for which internal mock client is
   *  always going to fail. **/
  tsi_handshaker* handshaker = create_test_handshaker(/*is_client=*/true);
  tsi_handshaker_next(
      handshaker, /*received_bytes=*/nullptr, /*received_bytes_size=*/0,
      /*bytes_to_send=*/nullptr, /*bytes_to_send_size=*/nullptr,
      /*result=*/nullptr, on_client_start_success_cb, /*user_data=*/nullptr);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  S2AHandshakerClient* client =
      s2a_tsi_handshaker_client_for_testing(s2a_handshaker);
  /** Tests. **/
  grpc_byte_buffer* recv_buffer = generate_handshaker_response(INVALID);
  GPR_ASSERT(client != nullptr);
  client->SetFieldsForTesting(s2a_handshaker, on_invalid_resp_cb,
                              /*user_data=*/nullptr, recv_buffer,
                              GRPC_STATUS_OK);
  client->HandleResponse(/*is_ok=*/true);
  client->ref_for_testing();
  {
    grpc_core::ExecCtx exec_ctx;
    client->on_status_received_for_testing(GRPC_STATUS_OK, GRPC_ERROR_NONE);
  }
  /** Cleanup. **/
  run_tsi_handshaker_destroy_with_exec_ctx(handshaker);
  notification_destroy(&caller_to_tsi_notification);
  notification_destroy(&tsi_to_caller_notification);
}

static void s2a_check_handle_response_success(void* /*unused*/) {
  /** Client start. **/
  wait(&caller_to_tsi_notification);
  GPR_ASSERT(cb_event != nullptr);
  cb_event->HandleResponse(/*is_ok=*/true);
  /** Client next. **/
  wait(&caller_to_tsi_notification);
  cb_event->HandleResponse(/*is_ok=*/true);
  cb_event->ref_for_testing();
  {
    grpc_core::ExecCtx exec_ctx;
    cb_event->on_status_received_for_testing(GRPC_STATUS_OK, GRPC_ERROR_NONE);
  }
  /** Server start. **/
  wait(&caller_to_tsi_notification);
  cb_event->HandleResponse(/*is_ok=*/true);
  /** Server next. **/
  wait(&caller_to_tsi_notification);
  cb_event->HandleResponse(/*is_ok=*/true);
  cb_event->ref_for_testing();
  {
    grpc_core::ExecCtx exec_ctx;
    cb_event->on_status_received_for_testing(GRPC_STATUS_OK, GRPC_ERROR_NONE);
  }
}

static void on_failed_resp_cb(tsi_result status, void* user_data,
                              const unsigned char* bytes_to_send,
                              size_t bytes_to_send_size,
                              tsi_handshaker_result* result) {
  GPR_ASSERT(status == TSI_INVALID_ARGUMENT);
  GPR_ASSERT(user_data == nullptr);
  GPR_ASSERT(bytes_to_send == nullptr);
  GPR_ASSERT(bytes_to_send_size == 0);
  GPR_ASSERT(result == nullptr);
}

static void s2a_check_handle_response_failure() {
  /** Initialization. **/
  notification_init(&caller_to_tsi_notification);
  notification_init(&tsi_to_caller_notification);
  /** Create a handshaker at the client side, for which internal mock client is
   *  always going to fail. **/
  tsi_handshaker* handshaker = create_test_handshaker(/*is_client=*/true);
  tsi_handshaker_next(
      handshaker, /*received_bytes=*/nullptr, /*received_bytes_size=*/0,
      /*bytes_to_send=*/nullptr, /*bytes_to_send_size=*/nullptr,
      /*result=*/nullptr, on_client_start_success_cb, /*user_data=*/nullptr);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  S2AHandshakerClient* client =
      s2a_tsi_handshaker_client_for_testing(s2a_handshaker);
  /** Tests. **/
  grpc_byte_buffer* recv_buffer = generate_handshaker_response(FAILED);
  GPR_ASSERT(client != nullptr);
  client->SetFieldsForTesting(s2a_handshaker, on_failed_resp_cb,
                              /*user_data=*/nullptr, recv_buffer,
                              GRPC_STATUS_OK);
  client->HandleResponse(/*is_ok=*/true);
  client->ref_for_testing();
  {
    grpc_core::ExecCtx exec_ctx;
    client->on_status_received_for_testing(GRPC_STATUS_OK, GRPC_ERROR_NONE);
  }
  /** Cleanup. **/
  run_tsi_handshaker_destroy_with_exec_ctx(handshaker);
  notification_destroy(&caller_to_tsi_notification);
  notification_destroy(&tsi_to_caller_notification);
}

static void on_shutdown_resp_cb(tsi_result status, void* user_data,
                                const unsigned char* bytes_to_send,
                                size_t bytes_to_send_size,
                                tsi_handshaker_result* result) {
  GPR_ASSERT(status == TSI_HANDSHAKE_SHUTDOWN);
  GPR_ASSERT(user_data == nullptr);
  GPR_ASSERT(bytes_to_send == nullptr);
  GPR_ASSERT(bytes_to_send_size == 0);
  GPR_ASSERT(result == nullptr);
}

static void s2a_check_handle_response_after_shutdown() {
  /** Initialization. **/
  notification_init(&caller_to_tsi_notification);
  notification_init(&tsi_to_caller_notification);
  tsi_handshaker* handshaker = create_test_handshaker(/*is_client=*/true);
  tsi_handshaker_next(
      handshaker, /*received_bytes=*/nullptr, /*received_bytes_size=*/0,
      /*bytes_to_send=*/nullptr, /*bytes_to_send_size=*/nullptr,
      /*result=*/nullptr, on_client_start_success_cb, /*user_data=*/nullptr);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  S2AHandshakerClient* client =
      s2a_tsi_handshaker_client_for_testing(s2a_handshaker);
  GPR_ASSERT(client != nullptr);
  grpc_byte_buffer** recv_buffer_ptr = client->recv_buffer_addr_for_testing();
  GPR_ASSERT(recv_buffer_ptr != nullptr);
  grpc_byte_buffer_destroy(*recv_buffer_ptr);

  /** Tests. **/
  tsi_handshaker_shutdown(handshaker);
  grpc_byte_buffer* recv_buffer = generate_handshaker_response(CLIENT_START);
  client->SetFieldsForTesting(s2a_handshaker, on_shutdown_resp_cb,
                              /*user_data=*/nullptr, recv_buffer,
                              GRPC_STATUS_OK);
  client->HandleResponse(/*is_ok=*/true);
  client->ref_for_testing();
  {
    grpc_core::ExecCtx exec_ctx;
    client->on_status_received_for_testing(GRPC_STATUS_OK, GRPC_ERROR_NONE);
  }
  /** Cleanup. **/
  run_tsi_handshaker_destroy_with_exec_ctx(handshaker);
  notification_destroy(&caller_to_tsi_notification);
  notification_destroy(&tsi_to_caller_notification);
}

void s2a_check_handshaker_next_fails_after_shutdown() {
  /** Initialization. **/
  notification_init(&caller_to_tsi_notification);
  notification_init(&tsi_to_caller_notification);
  cb_event = nullptr;
  /** Tests. **/
  grpc_core::Thread thd("s2a_mock_handshake_test",
                        &s2a_check_handle_response_with_shutdown,
                        /*arg=*/nullptr);
  thd.Start();
  s2a_check_handshaker_next_with_shutdown();
  thd.Join();
  /** Cleanup. **/
  notification_destroy(&caller_to_tsi_notification);
  notification_destroy(&tsi_to_caller_notification);
}

void s2a_check_handshaker_success() {
  /** Initialization. **/
  notification_init(&caller_to_tsi_notification);
  notification_init(&tsi_to_caller_notification);
  /** Tests. **/
  grpc_core::Thread thd("s2a_mock_handshake_test",
                        &s2a_check_handle_response_success, /*arg=*/nullptr);
  thd.Start();
  s2a_check_handshaker_next_success();
  thd.Join();
  /** Cleanup. **/
  notification_destroy(&caller_to_tsi_notification);
  notification_destroy(&tsi_to_caller_notification);
}

}  //  namespace experimental
}  //  namespace grpc_core

int main(int /*argc*/, char** /*argv*/) {
  /** Initialization. **/
  grpc_init();
  /** Tests. **/
  grpc_core::experimental::should_handshaker_client_api_succeed = true;
  grpc_core::experimental::s2a_check_handshaker_success();
  grpc_core::experimental::s2a_check_handshaker_next_invalid_input();
  grpc_core::experimental::s2a_check_handshaker_next_fails_after_shutdown();
  grpc_core::experimental::s2a_check_handle_response_after_shutdown();
  grpc_core::experimental::should_handshaker_client_api_succeed = false;
  grpc_core::experimental::s2a_check_handshaker_shutdown_invalid_input();
  grpc_core::experimental::s2a_check_handshaker_next_failure();
  grpc_core::experimental::s2a_check_handle_response_nullptr_handshaker();
  grpc_core::experimental::s2a_check_handle_response_nullptr_recv_bytes();
  grpc_core::experimental::
      s2a_check_handle_response_failed_grpc_call_to_handshaker_service();
  grpc_core::experimental::
      s2a_check_handle_response_failed_recv_message_from_handshaker_service();
  grpc_core::experimental::s2a_check_handle_response_invalid_resp();
  grpc_core::experimental::s2a_check_handle_response_failure();
  /** Cleanup. **/
  grpc_shutdown();
  return 0;
}
