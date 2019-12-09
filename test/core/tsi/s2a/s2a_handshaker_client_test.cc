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
#include "src/core/tsi/s2a/s2a_constants.h"
#include "src/core/tsi/transport_security_grpc.h"
#include "src/core/tsi/transport_security_interface.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_util.h"
#include "src/core/tsi/s2a/handshaker/s2a_tsi_handshaker.h"

using ::experimental::grpc_s2a_credentials_options;
using ::experimental::grpc_s2a_credentials_options_create;
using ::experimental::grpc_s2a_credentials_options_destroy;

namespace grpc_core {
namespace experimental {

// TODO(mattstev): add tests analogous to those in
// alts_handshaker_client_test.cc. This is blocked by the implementation of
// |make_grpc_call| and |handle_response|.

constexpr char kS2AHandshakerClientTestTargetName[] = "target_name";

struct s2a_tsi_handshaker_config {
  grpc_s2a_credentials_options* options;
  grpc_channel* channel;
  tsi_handshaker* handshaker;
};

struct s2a_handshaker_client_config {
  s2a_tsi_handshaker_config* tsi_config;
  s2a_handshaker_client* client;
};

static s2a_tsi_handshaker_config* s2a_tsi_handshaker_config_setup(bool is_client,
                                                                  const char* handshaker_service_url) {
  s2a_tsi_handshaker_config* config = new s2a_tsi_handshaker_config();
  config->options = grpc_s2a_credentials_options_create();
  config->options->set_handshaker_service_url(handshaker_service_url);
  config->channel = ::grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  tsi_result handshaker_result = s2a_tsi_handshaker_create(
      config->options, kS2AHandshakerClientTestTargetName, is_client,
      /* interested_parties=*/nullptr,
      &(config->handshaker),
      &error_details);
  GPR_ASSERT(handshaker_result == TSI_OK);
  GPR_ASSERT(error_details == nullptr);
  return config;
}

static void s2a_tsi_handshaker_config_destroy(s2a_tsi_handshaker_config* config) {
  if (config == nullptr) {
    return;
  }
  grpc_s2a_credentials_options_destroy(config->options);
  ::grpc_core::Delete<grpc_channel>(config->channel);
  tsi_handshaker_destroy(config->handshaker);
  delete config;
  config = nullptr;
}

static s2a_handshaker_client_config* s2a_handshaker_client_config_setup(bool is_client) {
  s2a_handshaker_client_config* config = new s2a_handshaker_client_config();
  config->tsi_config = s2a_tsi_handshaker_config_setup(is_client, kS2AHandshakerServiceUrlForTesting);
  tsi_result result = s2a_handshaker_client_create(reinterpret_cast<s2a_tsi_handshaker*>(config->tsi_config->handshaker),
                                                   config->tsi_config->channel,
                                                   /* interested_parties=*/nullptr,
                                                   config->tsi_config->options,
                                                   grpc_slice_from_static_string(kS2AHandshakerClientTestTargetName),
                                                   /* grpc_cb=*/nullptr,
                                                   /* cb=*/nullptr,
                                                   /* user_data=*/nullptr,
                                                   is_client,
                                                   &(config->client));
  GPR_ASSERT(result == TSI_OK);
  return config;
}

static void s2a_handshaker_client_config_destroy(s2a_handshaker_client_config* config) {
  if (config == nullptr) {
    return;
  }
  s2a_tsi_handshaker_config_destroy(config->tsi_config);
  s2a_handshaker_client_destroy(config->client);
  delete config;
  config = nullptr;
}

static void s2a_handshaker_client_bad_options_test() {
  s2a_tsi_handshaker_config* config = s2a_tsi_handshaker_config_setup(/* is_client=*/true,
                                                                      /* handshaker_service_url=*/nullptr);
  s2a_handshaker_client* client = nullptr;
  tsi_result result = s2a_handshaker_client_create(reinterpret_cast<s2a_tsi_handshaker*>(config->handshaker),
                                                   config->channel,
                                                   /* interested_parties=*/nullptr,
                                                   config->options,
                                                   grpc_slice_from_static_string(kS2AHandshakerClientTestTargetName),
                                                   /* grpc_cb=*/nullptr,
                                                   /* cb=*/nullptr,
                                                   /* user_data=*/nullptr,
                                                   /* is_client=*/true,
                                                   &client);
  GPR_ASSERT(result == TSI_INVALID_ARGUMENT);
  GPR_ASSERT(client == nullptr);

  // Cleanup.
  s2a_tsi_handshaker_config_destroy(config);
}

static void s2a_handshaker_client_create_and_destroy_test() {
  s2a_handshaker_client_config* client_config = s2a_handshaker_client_config_setup(/* is_client=*/true);
  s2a_handshaker_client_config* server_config = s2a_handshaker_client_config_setup(/* is_client=*/false);

  // Cleanup.
  s2a_handshaker_client_config_destroy(client_config);
  s2a_handshaker_client_config_destroy(server_config);
}

static void s2a_handshaker_client_client_start_test() {
  s2a_handshaker_client_config* config = s2a_handshaker_client_config_setup(/* is_client=*/true);
  tsi_result result = config->client->client_start();
  /** The |result| should be TSI_UNIMPLEMENTED because the |make_grpc_call| API
   *  currently unimplemented. In order to check that |client_start| was
   *  successful, we verify that the |send_buffer_| field of |config->client| is
   *  correct. **/
  // TODO(mattstev): change the check to |result == TSI_OK| once
  // |make_grpc_call| has been implemented.
  GPR_ASSERT(result == TSI_UNIMPLEMENTED);

  grpc_byte_buffer* send_buffer = config->client->get_send_buffer_for_testing();
  upb::Arena arena;
  s2a_SessionReq* request = s2a_deserialize_session_req(&arena, send_buffer);
  

  // Cleanup.
  s2a_handshaker_client_config_destroy(config);
}

}  // namespace experimental
}  // namespace grpc_core

int main(int argc, char** argv) {
  grpc_core::experimental::s2a_handshaker_client_bad_options_test();
  grpc_core::experimental::s2a_handshaker_client_create_and_destroy_test();
  return 0;
}
