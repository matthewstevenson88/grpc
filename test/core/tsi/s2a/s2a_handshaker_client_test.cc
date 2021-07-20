/*
 *
 * Copyright 2021 gRPC authors.
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

#include <grpc/slice.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "s2a/src/proto/upb-generated/proto/common.upb.h"
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_util.h"
#include "src/core/tsi/s2a/handshaker/s2a_tsi_test_utilities.h"
#include "src/core/tsi/s2a/s2a_security.h"
#include "src/core/tsi/s2a/s2a_shared_resource.h"
#include "src/core/tsi/s2a/s2a_tsi_handshaker.h"
#include "src/core/tsi/transport_security_grpc.h"
#include "src/core/tsi/transport_security_interface.h"
#include "upb/upb.hpp"

namespace s2a {
namespace tsi {
namespace {

const size_t kHandshakerClientOpNum = 4;
constexpr char kTargetName[] = "target_name";
constexpr char kOutFrame[] = "out_frame";
constexpr char kTargetSpiffeId[] = "target_spiffe_id";
constexpr char kTargetHostname[] = "target_hostname";
constexpr char kClientLocalSpiffeId[] = "client_local_spiffe_id";
constexpr char kServerLocalSpiffeId[] = "server_local_spiffe_id";
constexpr char kServerLocalHostname[] = "server_local_hostname";

static bool validate_op(S2AHandshakerClient* client, const grpc_op* op,
                        size_t nops, bool is_start) {
  GPR_ASSERT(client != nullptr && op != nullptr && nops != 0);
  bool ok = true;
  grpc_op* start_op = const_cast<grpc_op*>(op);
  if (is_start) {
    ok &= (op->op == GRPC_OP_SEND_INITIAL_METADATA);
    ok &= (op->data.send_initial_metadata.count == 0);
    op++;
    GPR_ASSERT((size_t)(op - start_op) <= kHandshakerClientOpNum);
    ok &= (op->op == GRPC_OP_RECV_INITIAL_METADATA);
    ok &= (op->data.recv_initial_metadata.recv_initial_metadata ==
           client->initial_metadata_for_testing());
    op++;
    GPR_ASSERT((size_t)(op - start_op) <= kHandshakerClientOpNum);
  }
  ok &= (op->op == GRPC_OP_SEND_MESSAGE);
  ok &=
      (op->data.send_message.send_message == client->send_buffer_for_testing());
  op++;
  GPR_ASSERT((size_t)(op - start_op) <= kHandshakerClientOpNum);
  ok &= (op->op == GRPC_OP_RECV_MESSAGE);
  ok &= (op->data.recv_message.recv_message ==
         client->recv_buffer_addr_for_testing());
  op++;
  GPR_ASSERT((size_t)(op - start_op) <= kHandshakerClientOpNum);
  return ok;
}

static bool is_recv_status_op(const grpc_op* op, size_t nops) {
  if (nops == 1 && op->op == GRPC_OP_RECV_STATUS_ON_CLIENT) {
    return true;
  }
  return false;
}

static grpc_call_error check_client_start_success(grpc_call* /*call*/,
                                                  const grpc_op* op,
                                                  size_t nops,
                                                  grpc_closure* closure) {
  if (is_recv_status_op(op, nops)) {
    return GRPC_CALL_OK;
  }
  GPR_ASSERT(closure != nullptr);
  upb::Arena arena;
  S2AHandshakerClient* client =
      static_cast<S2AHandshakerClient*>(closure->cb_arg);
  GPR_ASSERT(client->closure_for_testing() == closure);
  s2a_proto_SessionReq* session_request = s2a_deserialize_session_req(
      arena.ptr(), client->send_buffer_for_testing());
  GPR_ASSERT(s2a_proto_SessionReq_has_client_start(session_request));
  s2a_proto_ClientSessionStartReq* client_start =
      s2a_proto_SessionReq_mutable_client_start(session_request, arena.ptr());

  size_t application_protocols_size;
  const upb_strview* application_protocols =
      s2a_proto_ClientSessionStartReq_application_protocols(
          client_start, &application_protocols_size);
  GPR_ASSERT(application_protocols_size == 1);
  GPR_ASSERT(application_protocols != nullptr);
  GPR_ASSERT(upb_strview_eql(application_protocols[0],
                             upb_strview_makez(kS2AApplicationProtocol)));

  GPR_ASSERT(s2a_proto_ClientSessionStartReq_min_tls_version(client_start) ==
             s2a_proto_TLS1_3);
  GPR_ASSERT(s2a_proto_ClientSessionStartReq_max_tls_version(client_start) ==
             s2a_proto_TLS1_3);

  size_t tls_ciphersuites_size;
  const int* tls_ciphersuites =
      s2a_proto_ClientSessionStartReq_tls_ciphersuites(client_start,
                                                       &tls_ciphersuites_size);
  GPR_ASSERT(tls_ciphersuites_size == 3);
  GPR_ASSERT(tls_ciphersuites != nullptr);
  GPR_ASSERT(tls_ciphersuites[0] == s2a_proto_AES_128_GCM_SHA256);
  GPR_ASSERT(tls_ciphersuites[1] == s2a_proto_AES_256_GCM_SHA384);
  GPR_ASSERT(tls_ciphersuites[2] == s2a_proto_CHACHA20_POLY1305_SHA256);

  const s2a_proto_Identity* local_identity =
      s2a_proto_ClientSessionStartReq_local_identity(client_start);
  GPR_ASSERT(s2a_proto_Identity_has_spiffe_id(local_identity));
  GPR_ASSERT(upb_strview_eql(s2a_proto_Identity_spiffe_id(local_identity),
                             upb_strview_makez(kClientLocalSpiffeId)));

  size_t target_identities_size;
  const s2a_proto_Identity* const* target_identities =
      s2a_proto_ClientSessionStartReq_target_identities(
          client_start, &target_identities_size);
  GPR_ASSERT(target_identities_size == 2);
  for (size_t i = 0; i < target_identities_size; i++) {
    GPR_ASSERT(target_identities + i != nullptr);
    if (s2a_proto_Identity_has_spiffe_id(*(target_identities + i))) {
      GPR_ASSERT(upb_strview_eql(
          s2a_proto_Identity_spiffe_id(*(target_identities + i)),
          upb_strview_makez(kTargetSpiffeId)));
    }
    if (s2a_proto_Identity_has_hostname(*(target_identities + i))) {
      GPR_ASSERT(
          upb_strview_eql(s2a_proto_Identity_hostname(*(target_identities + i)),
                          upb_strview_makez(kTargetHostname)));
    }
  }

  GPR_ASSERT(validate_op(client, op, nops, /*is_start=*/true));
  return GRPC_CALL_OK;
}

static grpc_call_error check_server_start_success(grpc_call* /*call*/,
                                                  const grpc_op* op,
                                                  size_t nops,
                                                  grpc_closure* closure) {
  if (is_recv_status_op(op, nops)) {
    return GRPC_CALL_OK;
  }
  GPR_ASSERT(closure != nullptr);
  upb::Arena arena;
  S2AHandshakerClient* client =
      static_cast<S2AHandshakerClient*>(closure->cb_arg);
  GPR_ASSERT(client->closure_for_testing() == closure);
  s2a_proto_SessionReq* session_request = s2a_deserialize_session_req(
      arena.ptr(), client->send_buffer_for_testing());
  GPR_ASSERT(s2a_proto_SessionReq_has_server_start(session_request));
  s2a_proto_ServerSessionStartReq* server_start =
      s2a_proto_SessionReq_mutable_server_start(session_request, arena.ptr());

  size_t application_protocols_size;
  const upb_strview* application_protocols =
      s2a_proto_ServerSessionStartReq_application_protocols(
          server_start, &application_protocols_size);
  GPR_ASSERT(application_protocols_size == 1);
  GPR_ASSERT(application_protocols != nullptr);
  GPR_ASSERT(upb_strview_eql(application_protocols[0],
                             upb_strview_makez(kS2AApplicationProtocol)));

  GPR_ASSERT(s2a_proto_ServerSessionStartReq_min_tls_version(server_start) ==
             s2a_proto_TLS1_3);
  GPR_ASSERT(s2a_proto_ServerSessionStartReq_max_tls_version(server_start) ==
             s2a_proto_TLS1_3);

  size_t tls_ciphersuites_size;
  const int* tls_ciphersuites =
      s2a_proto_ServerSessionStartReq_tls_ciphersuites(server_start,
                                                       &tls_ciphersuites_size);
  GPR_ASSERT(tls_ciphersuites_size == 3);
  GPR_ASSERT(tls_ciphersuites[0] == s2a_proto_AES_128_GCM_SHA256);
  GPR_ASSERT(tls_ciphersuites[1] == s2a_proto_AES_256_GCM_SHA384);
  GPR_ASSERT(tls_ciphersuites[2] == s2a_proto_CHACHA20_POLY1305_SHA256);

  size_t local_identities_size = 0;
  const s2a_proto_Identity* const* local_identities =
      s2a_proto_ServerSessionStartReq_local_identities(server_start,
                                                       &local_identities_size);
  GPR_ASSERT(local_identities_size == 2);
  for (size_t i = 0; i < local_identities_size; i++) {
    GPR_ASSERT(local_identities + i != nullptr);
    if (s2a_proto_Identity_has_spiffe_id(*(local_identities + i))) {
      GPR_ASSERT(
          upb_strview_eql(s2a_proto_Identity_spiffe_id(*(local_identities + i)),
                          upb_strview_makez(kServerLocalSpiffeId)));
    }
    if (s2a_proto_Identity_has_hostname(*(local_identities + i))) {
      GPR_ASSERT(
          upb_strview_eql(s2a_proto_Identity_hostname(*(local_identities + i)),
                          upb_strview_makez(kServerLocalHostname)));
    }
  }

  upb_strview in_bytes = s2a_proto_ServerSessionStartReq_in_bytes(server_start);
  GPR_ASSERT(upb_strview_eql(in_bytes, upb_strview_makez(kOutFrame)));

  GPR_ASSERT(validate_op(client, op, nops, /*is_start=*/true));
  return GRPC_CALL_OK;
}

static grpc_call_error check_next_success(grpc_call* /*call*/,
                                          const grpc_op* op, size_t nops,
                                          grpc_closure* closure) {
  GPR_ASSERT(closure != nullptr);
  upb::Arena arena;
  S2AHandshakerClient* client =
      static_cast<S2AHandshakerClient*>(closure->cb_arg);
  GPR_ASSERT(client->closure_for_testing() == closure);
  s2a_proto_SessionReq* session_request = s2a_deserialize_session_req(
      arena.ptr(), client->send_buffer_for_testing());
  GPR_ASSERT(s2a_proto_SessionReq_has_next(session_request));
  s2a_proto_SessionNextReq* next =
      s2a_proto_SessionReq_mutable_next(session_request, arena.ptr());
  upb_strview in_bytes = s2a_proto_SessionNextReq_in_bytes(next);
  GPR_ASSERT(upb_strview_eql(in_bytes, upb_strview_makez(kOutFrame)));
  GPR_ASSERT(validate_op(client, op, nops, /*is_start=*/false));
  return GRPC_CALL_OK;
}

static grpc_call_error check_grpc_call_failure(grpc_call* /*call*/,
                                               const grpc_op* op, size_t nops,
                                               grpc_closure* /*tag*/) {
  if (is_recv_status_op(op, nops)) {
    return GRPC_CALL_OK;
  }
  return GRPC_CALL_ERROR;
}

grpc_s2a_credentials_options* CreateTestOptions(bool is_client) {
  grpc_s2a_credentials_options* options = new grpc_s2a_credentials_options();
  options->s2a_options.set_s2a_address(kS2AHandshakerServiceUrlForTesting);
  options->s2a_options.add_supported_ciphersuite(
      s2a_options::S2AOptions::Ciphersuite::AES_128_GCM_SHA256);
  options->s2a_options.add_supported_ciphersuite(
      s2a_options::S2AOptions::Ciphersuite::AES_256_GCM_SHA384);
  options->s2a_options.add_supported_ciphersuite(
      s2a_options::S2AOptions::Ciphersuite::CHACHA20_POLY1305_SHA256);
  if (is_client) {
    options->s2a_options.add_target_spiffe_id(kTargetSpiffeId);
    options->s2a_options.add_target_hostname(kTargetHostname);
    options->s2a_options.add_local_spiffe_id(kClientLocalSpiffeId);
  } else {
    options->s2a_options.add_local_spiffe_id(kServerLocalSpiffeId);
    options->s2a_options.add_local_hostname(kServerLocalHostname);
  }
  return options;
}

class S2AHandshakerClientTest : public ::testing::Test {
 protected:
  S2AHandshakerClientTest() {}

  void SetUp() override {
    channel_ = new grpc_channel();
    client_options_ = CreateTestOptions(/*is_client=*/true);
    server_options_ = CreateTestOptions(/*is_client=*/false);

    S2ATsiHandshakerOptions client_tsi_options;
    client_tsi_options.is_client = true;
    client_tsi_options.s2a_options = client_options_;
    client_tsi_options.target_name = kTargetName;
    absl::StatusOr<tsi_handshaker*> client_handshaker =
        CreateS2ATsiHandshakerForTesting(client_tsi_options);
    EXPECT_TRUE(client_handshaker.ok());
    client_tsi_handshaker_ = *client_handshaker;

    S2ATsiHandshakerOptions server_tsi_options;
    server_tsi_options.is_client = false;
    server_tsi_options.s2a_options = server_options_;
    server_tsi_options.target_name = kTargetName;
    absl::StatusOr<tsi_handshaker*> server_handshaker =
        CreateS2ATsiHandshakerForTesting(server_tsi_options);
    EXPECT_TRUE(client_handshaker.ok());
    server_tsi_handshaker_ = *server_handshaker;

    tsi_result client_result = S2AHandshakerClientCreate(
        client_tsi_handshaker_, channel_,
        /*interested_parties=*/nullptr, client_options_,
        grpc_slice_from_static_string(kTargetName),
        /*grpc_cb=*/nullptr, /*cb=*/nullptr, /*user_data=*/nullptr,
        /*is_client=*/true, /*is_test=*/true, &client_);
    EXPECT_EQ(client_result, TSI_OK);
    EXPECT_NE(client_, nullptr);

    tsi_result server_result = S2AHandshakerClientCreate(
        server_tsi_handshaker_, channel_,
        /*interested_parties=*/nullptr, server_options_,
        grpc_slice_from_static_string(kTargetName),
        /*grpc_cb=*/nullptr, /*cb=*/nullptr, /*user_data=*/nullptr,
        /*is_client=*/false, /*is_test=*/true, &server_);
    EXPECT_EQ(server_result, TSI_OK);
    EXPECT_NE(server_, nullptr);

    out_frame_ = grpc_slice_from_static_string(kOutFrame);
  }

  void TearDown() override {
    s2a_handshaker_client_on_status_received_for_testing(
        client_, GRPC_STATUS_OK, GRPC_ERROR_NONE);
    s2a_handshaker_client_on_status_received_for_testing(
        server_, GRPC_STATUS_OK, GRPC_ERROR_NONE);
    delete channel_;
    S2AHandshakerClientDestroy(client_);
    S2AHandshakerClientDestroy(server_);
    tsi_handshaker_destroy(client_tsi_handshaker_);
    tsi_handshaker_destroy(server_tsi_handshaker_);
    delete client_options_;
    delete server_options_;
    grpc_slice_unref(out_frame_);
  }

  grpc_channel* channel_ = nullptr;
  grpc_s2a_credentials_options* client_options_ = nullptr;
  grpc_s2a_credentials_options* server_options_ = nullptr;
  tsi_handshaker* client_tsi_handshaker_ = nullptr;
  S2AHandshakerClient* client_ = nullptr;
  tsi_handshaker* server_tsi_handshaker_ = nullptr;
  S2AHandshakerClient* server_ = nullptr;
  grpc_slice out_frame_;
};

TEST_F(S2AHandshakerClientTest, ScheduleRequestSuccess) {
  client_->set_grpc_caller_for_testing(check_client_start_success);
  grpc_slice empty_slice = grpc_empty_slice();
  EXPECT_EQ(client_->Next(&empty_slice), TSI_OK);

  server_->set_grpc_caller_for_testing(check_server_start_success);
  EXPECT_EQ(server_->Next(&out_frame_), TSI_OK);

  client_->set_grpc_caller_for_testing(check_next_success);
  EXPECT_EQ(client_->Next(&out_frame_), TSI_OK);

  server_->set_grpc_caller_for_testing(check_next_success);
  EXPECT_EQ(server_->Next(&out_frame_), TSI_OK);
}

TEST_F(S2AHandshakerClientTest, ScheduleRequestGrpcCallFailure) {
  client_->set_grpc_caller_for_testing(check_grpc_call_failure);
  grpc_slice empty_slice = grpc_empty_slice();
  EXPECT_EQ(client_->Next(&empty_slice), TSI_INTERNAL_ERROR);

  server_->set_grpc_caller_for_testing(check_grpc_call_failure);
  EXPECT_EQ(server_->Next(&out_frame_), TSI_INTERNAL_ERROR);

  EXPECT_EQ(client_->Next(&out_frame_), TSI_INTERNAL_ERROR);

  EXPECT_EQ(server_->Next(&out_frame_), TSI_INTERNAL_ERROR);
}

}  // namespace
}  // namespace tsi
}  // namespace s2a

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  grpc_init();
  grpc_s2a_shared_resource_dedicated_init();
  int ret = RUN_ALL_TESTS();
  grpc_s2a_shared_resource_dedicated_shutdown();
  grpc_shutdown();
  return ret;
}
