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
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_util.h"
#include "src/core/tsi/s2a/handshaker/s2a_tsi_handshaker.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "src/core/tsi/transport_security_grpc.h"
#include "src/core/tsi/transport_security_interface.h"

using ::experimental::grpc_s2a_credentials_options;
using ::experimental::grpc_s2a_credentials_options_create;
using ::experimental::grpc_s2a_credentials_options_destroy;

namespace grpc_core {
namespace experimental {

/** The tests in this file are small modifications of their ALTS counterparts,
 *  which can be found in alts_handshaker_client.cc. **/

const size_t kHandshakerClientOpNum = 4;
const char kS2AHandshakerClientTestTargetName[] = "bigtable.google.api.com";
const char kS2AHandshakerClientTestOutFrame[] = "Hello Google!";

struct s2a_handshaker_client_test_config {
  grpc_channel* channel;
  grpc_s2a_credentials_options* options;
  tsi_handshaker* client_tsi_handshaker;
  S2AHandshakerClient* client;
  tsi_handshaker* server_tsi_handshaker;
  S2AHandshakerClient* server;
  grpc_slice out_frame;
};

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

static grpc_call_error check_must_not_be_called(grpc_call* /*call*/,
                                                const grpc_op* /*ops*/,
                                                size_t /*nops*/,
                                                grpc_closure* /*tag*/) {
  GPR_ASSERT(0);
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
  s2a_SessionReq* session_request = s2a_deserialize_session_req(
      arena.ptr(), client->send_buffer_for_testing());
  GPR_ASSERT(s2a_SessionReq_has_client_start(session_request));
  s2a_ClientSessionStartReq* client_start =
      s2a_SessionReq_mutable_client_start(session_request, arena.ptr());

  size_t application_protocols_size;
  const upb_strview* application_protocols =
      s2a_ClientSessionStartReq_application_protocols(
          client_start, &application_protocols_size);
  GPR_ASSERT(application_protocols_size == 1);
  GPR_ASSERT(application_protocols != nullptr);
  GPR_ASSERT(upb_strview_eql(application_protocols[0],
                             upb_strview_makez(kS2AApplicationProtocol)));

  GPR_ASSERT(s2a_ClientSessionStartReq_min_tls_version(client_start) ==
             s2a_TLS1_3);
  GPR_ASSERT(s2a_ClientSessionStartReq_max_tls_version(client_start) ==
             s2a_TLS1_3);

  size_t tls_ciphersuites_size;
  const int* tls_ciphersuites = s2a_ClientSessionStartReq_tls_ciphersuites(
      client_start, &tls_ciphersuites_size);
  GPR_ASSERT(tls_ciphersuites_size == 3);
  GPR_ASSERT(tls_ciphersuites != nullptr);
  GPR_ASSERT(tls_ciphersuites[0] == kTlsAes128GcmSha256);
  GPR_ASSERT(tls_ciphersuites[1] == kTlsAes256GcmSha384);
  GPR_ASSERT(tls_ciphersuites[2] == kTlsChacha20Poly1305Sha256);

  size_t target_identities_size;
  const s2a_Identity* const* target_identities =
      s2a_ClientSessionStartReq_target_identities(client_start,
                                                  &target_identities_size);
  GPR_ASSERT(target_identities_size == 1);
  GPR_ASSERT(target_identities != nullptr);
  GPR_ASSERT(s2a_Identity_has_spiffe_id(*target_identities));
  GPR_ASSERT(upb_strview_eql(s2a_Identity_spiffe_id(*target_identities),
                             upb_strview_makez("target_service_account")));

  GPR_ASSERT(validate_op(client, op, nops, /* is_start=*/true));
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
  s2a_SessionReq* session_request = s2a_deserialize_session_req(
      arena.ptr(), client->send_buffer_for_testing());
  GPR_ASSERT(s2a_SessionReq_has_server_start(session_request));
  s2a_ServerSessionStartReq* server_start =
      s2a_SessionReq_mutable_server_start(session_request, arena.ptr());

  size_t application_protocols_size;
  const upb_strview* application_protocols =
      s2a_ServerSessionStartReq_application_protocols(
          server_start, &application_protocols_size);
  GPR_ASSERT(application_protocols_size == 1);
  GPR_ASSERT(application_protocols != nullptr);
  GPR_ASSERT(upb_strview_eql(application_protocols[0],
                             upb_strview_makez(kS2AApplicationProtocol)));

  GPR_ASSERT(s2a_ServerSessionStartReq_min_tls_version(server_start) ==
             s2a_TLS1_3);
  GPR_ASSERT(s2a_ServerSessionStartReq_max_tls_version(server_start) ==
             s2a_TLS1_3);

  size_t tls_ciphersuites_size;
  const int* tls_ciphersuites = s2a_ServerSessionStartReq_tls_ciphersuites(
      server_start, &tls_ciphersuites_size);
  GPR_ASSERT(tls_ciphersuites_size == 3);
  GPR_ASSERT(tls_ciphersuites[0] == kTlsAes128GcmSha256);
  GPR_ASSERT(tls_ciphersuites[1] == kTlsAes256GcmSha384);
  GPR_ASSERT(tls_ciphersuites[2] == kTlsChacha20Poly1305Sha256);

  upb_strview in_bytes = s2a_ServerSessionStartReq_in_bytes(server_start);
  GPR_ASSERT(upb_strview_eql(
      in_bytes, upb_strview_makez(kS2AHandshakerClientTestOutFrame)));

  GPR_ASSERT(validate_op(client, op, nops, /* is_start=*/true));
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
  s2a_SessionReq* session_request = s2a_deserialize_session_req(
      arena.ptr(), client->send_buffer_for_testing());
  GPR_ASSERT(s2a_SessionReq_has_next(session_request));
  s2a_SessionNextReq* next =
      s2a_SessionReq_mutable_next(session_request, arena.ptr());
  upb_strview in_bytes = s2a_SessionNextReq_in_bytes(next);
  GPR_ASSERT(upb_strview_eql(
      in_bytes, upb_strview_makez(kS2AHandshakerClientTestOutFrame)));
  GPR_ASSERT(validate_op(client, op, nops, false /* is_start */));
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

static grpc_s2a_credentials_options* s2a_create_test_credentials_options() {
  grpc_s2a_credentials_options* options = grpc_s2a_credentials_options_create();
  options->set_handshaker_service_url(kS2AHandshakerServiceUrlForTesting);
  options->add_supported_ciphersuite(kTlsAes128GcmSha256);
  options->add_supported_ciphersuite(kTlsAes256GcmSha384);
  options->add_supported_ciphersuite(kTlsChacha20Poly1305Sha256);
  options->add_target_service_account("target_service_account");
  return options;
}

static s2a_handshaker_client_test_config* s2a_create_config() {
  s2a_handshaker_client_test_config* config =
      new s2a_handshaker_client_test_config();
  config->channel = grpc_insecure_channel_create(
      kS2AHandshakerServiceUrlForTesting, nullptr, nullptr);
  config->options = s2a_create_test_credentials_options();

  char* error_details = nullptr;
  tsi_result client_handshaker_result = s2a_tsi_handshaker_create(
      config->options, kS2AHandshakerClientTestTargetName, /* is_client=*/true,
      /* interested_parties=*/nullptr, &(config->client_tsi_handshaker),
      &error_details);
  GPR_ASSERT(client_handshaker_result == TSI_OK);
  GPR_ASSERT(error_details == nullptr);

  tsi_result server_handshaker_result = s2a_tsi_handshaker_create(
      config->options, kS2AHandshakerClientTestTargetName, /* is_client=*/false,
      /* interested_parties=*/nullptr, &(config->server_tsi_handshaker),
      &error_details);
  GPR_ASSERT(server_handshaker_result == TSI_OK);
  GPR_ASSERT(error_details == nullptr);

  tsi_result client_result = S2AHandshakerClientCreate(
      reinterpret_cast<s2a_tsi_handshaker*>(config->client_tsi_handshaker),
      config->channel, /* interested_parties=*/nullptr, config->options,
      grpc_slice_from_static_string(kS2AHandshakerClientTestTargetName),
      /* grpc_cb=*/nullptr, /* cb=*/nullptr, /* user_data=*/nullptr,
      /* is_client=*/true, /* is_test=*/true, &(config->client));
  GPR_ASSERT(client_result == TSI_OK);
  GPR_ASSERT(config->client != nullptr);

  tsi_result server_result = S2AHandshakerClientCreate(
      reinterpret_cast<s2a_tsi_handshaker*>(config->server_tsi_handshaker),
      config->channel, /* interested_parties=*/nullptr, config->options,
      grpc_slice_from_static_string(kS2AHandshakerClientTestTargetName),
      /* grpc_cb=*/nullptr, /* cb=*/nullptr, /* user_data=*/nullptr,
      /* is_client=*/false, /* is_test=*/true, &(config->server));
  GPR_ASSERT(server_result == TSI_OK);
  GPR_ASSERT(config->server != nullptr);

  config->out_frame =
      grpc_slice_from_static_string(kS2AHandshakerClientTestOutFrame);
  return config;
}

static void s2a_destroy_config(s2a_handshaker_client_test_config* config) {
  if (config == nullptr) {
    return;
  }
  grpc_channel_destroy(config->channel);
  S2AHandshakerClientDestroy(config->client);
  S2AHandshakerClientDestroy(config->server);
  tsi_handshaker_destroy(config->client_tsi_handshaker);
  tsi_handshaker_destroy(config->server_tsi_handshaker);
  grpc_s2a_credentials_options_destroy(config->options);
  grpc_slice_unref(config->out_frame);
  delete config;
}

static void s2a_schedule_request_success_test() {
  s2a_handshaker_client_test_config* config = s2a_create_config();

  config->client->set_grpc_caller_for_testing(check_client_start_success);
  GPR_ASSERT(config->client->ClientStart() == TSI_OK);

  config->server->set_grpc_caller_for_testing(check_server_start_success);
  GPR_ASSERT(config->server->ServerStart(&(config->out_frame)) == TSI_OK);

  config->client->set_grpc_caller_for_testing(check_next_success);
  GPR_ASSERT(config->client->Next(&(config->out_frame)) == TSI_OK);

  config->server->set_grpc_caller_for_testing(check_next_success);
  GPR_ASSERT(config->server->Next(&(config->out_frame)) == TSI_OK);

  /** Cleanup. **/
  s2a_handshaker_client_on_status_received_for_testing(
      config->client, GRPC_STATUS_OK, GRPC_ERROR_NONE);
  s2a_handshaker_client_on_status_received_for_testing(
      config->server, GRPC_STATUS_OK, GRPC_ERROR_NONE);
  s2a_destroy_config(config);
}

static void s2a_schedule_request_grpc_call_failure_test() {
  s2a_handshaker_client_test_config* config = s2a_create_config();

  config->client->set_grpc_caller_for_testing(check_grpc_call_failure);
  GPR_ASSERT(config->client->ClientStart() == TSI_INTERNAL_ERROR);

  config->server->set_grpc_caller_for_testing(check_grpc_call_failure);
  GPR_ASSERT(config->server->ServerStart(&(config->out_frame)) ==
             TSI_INTERNAL_ERROR);

  GPR_ASSERT(config->client->Next(&(config->out_frame)) == TSI_INTERNAL_ERROR);

  GPR_ASSERT(config->server->Next(&(config->out_frame)) == TSI_INTERNAL_ERROR);

  /** Cleanup. **/
  s2a_handshaker_client_on_status_received_for_testing(
      config->client, GRPC_STATUS_OK, GRPC_ERROR_NONE);
  s2a_handshaker_client_on_status_received_for_testing(
      config->server, GRPC_STATUS_OK, GRPC_ERROR_NONE);
  s2a_destroy_config(config);
}

}  // namespace experimental
}  // namespace grpc_core

int main(int argc, char** argv) {
  grpc_init();
  grpc_core::experimental::s2a_schedule_request_success_test();
  grpc_core::experimental::s2a_schedule_request_grpc_call_failure_test();
  grpc_shutdown();
  return 0;
}
