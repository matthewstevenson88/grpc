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

constexpr char kS2AHandshakerClientTestTargetName[] = "target_name";

struct s2a_tsi_handshaker_config {
  grpc_s2a_credentials_options* options;
  grpc_channel* channel;
  tsi_handshaker* handshaker;
};

struct s2a_handshaker_client_config {
  s2a_tsi_handshaker_config* tsi_config;
  S2AHandshakerClient* client;
};

static s2a_tsi_handshaker_config* s2a_tsi_handshaker_config_setup(
    bool is_client, const std::string& handshaker_service_url) {
  s2a_tsi_handshaker_config* config = new s2a_tsi_handshaker_config();
  config->options = grpc_s2a_credentials_options_create();
  config->options->set_handshaker_service_url(handshaker_service_url);
  config->options->add_supported_ciphersuite(kTlsAes128GcmSha256);
  config->options->add_supported_ciphersuite(kTlsAes256GcmSha384);
  config->options->add_supported_ciphersuite(kTlsChacha20Poly1305Sha256);
  config->options->add_target_service_account("target_service_account");
  config->channel = ::grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  tsi_result handshaker_result = s2a_tsi_handshaker_create(
      config->options, kS2AHandshakerClientTestTargetName, is_client,
      /*interested_parties=*/nullptr, &(config->handshaker), &error_details);
  GPR_ASSERT(handshaker_result == TSI_OK);
  GPR_ASSERT(error_details == nullptr);
  return config;
}

static void s2a_tsi_handshaker_config_destroy(
    s2a_tsi_handshaker_config* config) {
  if (config == nullptr) {
    return;
  }
  grpc_s2a_credentials_options_destroy(config->options);
  ::grpc_core::Delete<grpc_channel>(config->channel);
  tsi_handshaker_destroy(config->handshaker);
  delete config;
  config = nullptr;
}

static s2a_handshaker_client_config* s2a_handshaker_client_config_setup(
    bool is_client) {
  s2a_handshaker_client_config* config = new s2a_handshaker_client_config();
  std::string handshaker_url(kS2AHandshakerServiceUrlForTesting);
  config->tsi_config =
      s2a_tsi_handshaker_config_setup(is_client, handshaker_url);
  tsi_result result = S2AHandshakerClientCreate(
      reinterpret_cast<s2a_tsi_handshaker*>(config->tsi_config->handshaker),
      config->tsi_config->channel,
      /*interested_parties=*/nullptr, config->tsi_config->options,
      grpc_slice_from_static_string(kS2AHandshakerClientTestTargetName),
      /* grpc_cb=*/nullptr,
      /* cb=*/nullptr,
      /* user_data=*/nullptr, is_client,
      /* is_test=*/true, &(config->client));
  GPR_ASSERT(result == TSI_OK);
  config->client->set_no_calls_for_testing(/* no_calls=*/true);
  return config;
}

static void s2a_handshaker_client_config_destroy(
    s2a_handshaker_client_config* config) {
  if (config == nullptr) {
    return;
  }
  s2a_tsi_handshaker_config_destroy(config->tsi_config);
  S2AHandshakerClientDestroy(config->client);
  delete config;
  config = nullptr;
}

static void s2a_handshaker_client_create_and_destroy_test() {
  s2a_handshaker_client_config* client_config =
      s2a_handshaker_client_config_setup(/*is_client=*/true);
  s2a_handshaker_client_config* server_config =
      s2a_handshaker_client_config_setup(/*is_client=*/false);

  // Cleanup.
  s2a_handshaker_client_config_destroy(client_config);
  s2a_handshaker_client_config_destroy(server_config);
}

static void s2a_handshaker_client_client_start_test() {
  s2a_handshaker_client_config* config =
      s2a_handshaker_client_config_setup(/* is_client=*/true);
  GPR_ASSERT(config->client->ClientStart() == TSI_OK);

  grpc_byte_buffer* send_buffer = config->client->send_buffer_for_testing();

  upb::Arena arena;
  s2a_SessionReq* session_request =
      s2a_deserialize_session_req(arena.ptr(), send_buffer);
  GPR_ASSERT(s2a_SessionReq_has_client_start(session_request));
  s2a_ClientSessionStartReq* request =
      s2a_SessionReq_mutable_client_start(session_request, arena.ptr());

  size_t application_protocols_size;
  const upb_strview* application_protocols =
      s2a_ClientSessionStartReq_application_protocols(
          request, &application_protocols_size);
  GPR_ASSERT(application_protocols_size == 1);
  GPR_ASSERT(application_protocols != nullptr);
  GPR_ASSERT(upb_strview_eql(application_protocols[0],
                             upb_strview_makez(kS2AApplicationProtocol)));

  size_t tls_versions_size;
  const int* tls_versions =
      s2a_ClientSessionStartReq_tls_versions(request, &tls_versions_size);
  GPR_ASSERT(tls_versions_size == 1);
  GPR_ASSERT(tls_versions != nullptr);
  GPR_ASSERT(tls_versions[0] == /*TLS 1.3=*/0);

  size_t tls_ciphersuites_size;
  const int* tls_ciphersuites = s2a_ClientSessionStartReq_tls_ciphersuites(
      request, &tls_ciphersuites_size);
  GPR_ASSERT(tls_ciphersuites_size == 3);
  GPR_ASSERT(tls_ciphersuites != nullptr);
  GPR_ASSERT(tls_ciphersuites[0] == kTlsAes128GcmSha256);
  GPR_ASSERT(tls_ciphersuites[1] == kTlsAes256GcmSha384);
  GPR_ASSERT(tls_ciphersuites[2] == kTlsChacha20Poly1305Sha256);

  size_t target_identities_size;
  const s2a_Identity* const* target_identities =
      s2a_ClientSessionStartReq_target_identities(request,
                                                  &target_identities_size);
  GPR_ASSERT(target_identities_size == 1);
  GPR_ASSERT(target_identities != nullptr);
  GPR_ASSERT(s2a_Identity_has_spiffe_id(*target_identities));
  GPR_ASSERT(upb_strview_eql(s2a_Identity_spiffe_id(*target_identities),
                             upb_strview_makez("target_service_account")));

  // Cleanup.
  s2a_handshaker_client_config_destroy(config);
}

static void s2a_handshaker_client_server_start_test() {
  s2a_handshaker_client_config* config =
      s2a_handshaker_client_config_setup(/*is_client=*/false);
  grpc_slice bytes_received = grpc_slice_from_static_string("bytes_received");
  GPR_ASSERT(config->client->ServerStart(&bytes_received) == TSI_OK);

  grpc_byte_buffer* send_buffer = config->client->send_buffer_for_testing();
  upb::Arena arena;
  s2a_SessionReq* session_request =
      s2a_deserialize_session_req(arena.ptr(), send_buffer);
  GPR_ASSERT(s2a_SessionReq_has_server_start(session_request));
  s2a_ServerSessionStartReq* request =
      s2a_SessionReq_mutable_server_start(session_request, arena.ptr());

  size_t application_protocols_size;
  const upb_strview* application_protocols =
      s2a_ServerSessionStartReq_application_protocols(
          request, &application_protocols_size);
  GPR_ASSERT(application_protocols_size == 1);
  GPR_ASSERT(application_protocols != nullptr);
  GPR_ASSERT(upb_strview_eql(application_protocols[0],
                             upb_strview_makez(kS2AApplicationProtocol)));

  size_t tls_versions_size;
  const int* tls_versions =
      s2a_ServerSessionStartReq_tls_versions(request, &tls_versions_size);
  GPR_ASSERT(tls_versions_size == 1);
  GPR_ASSERT(tls_versions != nullptr);
  GPR_ASSERT(tls_versions[0] == s2a_TLS1_3);

  size_t tls_ciphersuites_size;
  const int* tls_ciphersuites = s2a_ServerSessionStartReq_tls_ciphersuites(
      request, &tls_ciphersuites_size);
  GPR_ASSERT(tls_ciphersuites_size == 3);
  GPR_ASSERT(tls_ciphersuites != nullptr);
  GPR_ASSERT(tls_ciphersuites[0] == kTlsAes128GcmSha256);
  GPR_ASSERT(tls_ciphersuites[1] == kTlsAes256GcmSha384);
  GPR_ASSERT(tls_ciphersuites[2] == kTlsChacha20Poly1305Sha256);

  upb_strview in_bytes = s2a_ServerSessionStartReq_in_bytes(request);
  GPR_ASSERT(upb_strview_eql(in_bytes, upb_strview_makez("bytes_received")));

  // Cleanup.
  s2a_handshaker_client_config_destroy(config);
}

static void s2a_handshaker_client_next_test() {
  s2a_handshaker_client_config* config =
      s2a_handshaker_client_config_setup(/*is_client=*/true);
  grpc_slice bytes_received = grpc_slice_from_static_string("bytes_received");
  GPR_ASSERT(config->client->Next(&bytes_received) == TSI_OK);

  grpc_byte_buffer* send_buffer = config->client->send_buffer_for_testing();
  upb::Arena arena;
  s2a_SessionReq* session_request =
      s2a_deserialize_session_req(arena.ptr(), send_buffer);
  GPR_ASSERT(s2a_SessionReq_has_next(session_request));
  s2a_SessionNextReq* request =
      s2a_SessionReq_mutable_next(session_request, arena.ptr());

  upb_strview in_bytes = s2a_SessionNextReq_in_bytes(request);
  GPR_ASSERT(upb_strview_eql(in_bytes, upb_strview_makez("bytes_received")));

  // Cleanup.
  s2a_handshaker_client_config_destroy(config);
}

}  // namespace experimental
}  // namespace grpc_core

int main(int argc, char** argv) {
  grpc_core::experimental::s2a_handshaker_client_create_and_destroy_test();
  grpc_core::experimental::s2a_handshaker_client_client_start_test();
  grpc_core::experimental::s2a_handshaker_client_server_start_test();
  grpc_core::experimental::s2a_handshaker_client_next_test();
  return 0;
}
