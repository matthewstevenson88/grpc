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

#include "src/core/tsi/s2a/handshaker/s2a_tsi_handshaker.h"

#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <grpc/support/string_util.h>
#include <grpc/support/sync.h>

#include "src/core/lib/slice/slice_internal.h"
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"
#include "src/core/tsi/s2a/s2a_constants.h"

namespace grpc_core {
namespace experimental {

/** The main struct for the S2A TSI handshaker. **/
struct s2a_tsi_handshaker {
  tsi_handshaker base;
  grpc_slice target_name;
  bool is_client;
  bool has_sent_start_message;
  bool has_created_handshaker_client;
  grpc_pollset_set* interested_parties;
  grpc_s2a_credentials_options* options;
  grpc_channel* channel;
  /** The mutex |mu| synchronizes the fields |client| and |shutdown|. These are
   *  the only fields of the s2a_tsi_handshaker that could be accessed
   * concurrently (due to the potential concurrency of the
   * |tsi_handshaker_shutdown| and |tsi_handshaker_next| methods). **/
  gpr_mu mu;
  S2AHandshakerClient* client;
  bool shutdown;
};

/** The main struct for the S2A TSI handshaker result. **/
typedef struct s2a_tsi_handshaker_result {
  tsi_handshaker_result base;
  /** The TLS version negotiated during the handshake. **/
  uint16_t tls_version;
  /** The TLS ciphersuite negotiated during the handshake. **/
  uint16_t tls_ciphersuite;
  /** The in and out traffic secrets produced from the handshake. They will be
   *  populated using the |in_key| and |out_key| fields from a |SessionState|
   *  message; see s2a.proto for the message definitions. **/
  uint8_t* in_traffic_secret;
  uint8_t* out_traffic_secret;
  size_t traffic_secret_size;
  /** The SPIFFE ID or hostname of the peer. Only one of these two fields will
   *  be populated, namely whichever is populated in the |SessionResult| message
   *  received from the S2A service. **/
  char* spiffe_id;
  char* hostname;
  /** A buffer used to store any unused bytes of the |SessionResp| message
   *  received from the S2A service. **/
  unsigned char* unused_bytes;
  size_t unused_bytes_size;
  /** The |is_client| variable is true iff the handshaker result is on the
   *  client-side, and false iff the handshaker result is on the server-side.
   * **/
  bool is_client;
} s2a_tsi_handshaker_result;

static tsi_result handshaker_next(
    tsi_handshaker* self, const unsigned char* received_bytes,
    size_t received_bytes_size, const unsigned char** /** bytes_to_send **/,
    size_t* /** bytes_to_send_size **/, tsi_handshaker_result** /** result **/,
    tsi_handshaker_on_next_done_cb cb, void* user_data) {
  // TODO(mattstev): implement.
  return TSI_UNIMPLEMENTED;
}

static void handshaker_shutdown(tsi_handshaker* self) {
  GPR_ASSERT(self != nullptr);
  s2a_tsi_handshaker* handshaker = reinterpret_cast<s2a_tsi_handshaker*>(self);
  grpc_core::MutexLock lock(&(handshaker->mu));
  if (handshaker->shutdown) {
    return;
  }
  if (handshaker->client != nullptr) {
    handshaker->client->Shutdown();
  }
  handshaker->shutdown = true;
}

static void handshaker_destroy(tsi_handshaker* self) {
  if (self == nullptr) {
    return;
  }
  s2a_tsi_handshaker* handshaker = reinterpret_cast<s2a_tsi_handshaker*>(self);
  s2a_handshaker_client_destroy(handshaker->client);
  grpc_slice_unref_internal(handshaker->target_name);
  grpc_s2a_credentials_options_destroy(handshaker->options);
  if (handshaker->channel != nullptr) {
    grpc_channel_destroy_internal(handshaker->channel);
  }
  gpr_mu_destroy(&(handshaker->mu));
  gpr_free(handshaker);
}

static const tsi_handshaker_vtable handshaker_vtable = {
    nullptr,         nullptr,
    nullptr,         nullptr,
    nullptr,         handshaker_destroy,
    handshaker_next, handshaker_shutdown};

tsi_result s2a_tsi_handshaker_create(
    const grpc_s2a_credentials_options* options, const char* target_name,
    bool is_client, grpc_pollset_set* interested_parties, tsi_handshaker** self,
    char** error_details) {
  if (options == nullptr || (is_client && target_name == nullptr) ||
      self == nullptr) {
    gpr_log(GPR_ERROR, kS2ATsiHandshakerNullptrArguments);
    return TSI_INVALID_ARGUMENT;
  }
  s2a_tsi_handshaker* handshaker =
      static_cast<s2a_tsi_handshaker*>(gpr_zalloc(sizeof(s2a_tsi_handshaker)));
  gpr_mu_init(&(handshaker->mu));
  handshaker->is_client = is_client;
  handshaker->target_name = (target_name == nullptr)
                                ? grpc_empty_slice()
                                : grpc_slice_from_static_string(target_name);
  handshaker->interested_parties = interested_parties;
  handshaker->options = options->Copy();
  handshaker->base.vtable = &handshaker_vtable;

  *self = &(handshaker->base);
  return TSI_OK;
}

static tsi_result s2a_handshaker_result_extract_peer(
    const tsi_handshaker_result* self, tsi_peer* peer) {
  // TODO(mattstev): implement.
  return TSI_UNIMPLEMENTED;
}

static tsi_result s2a_handshaker_result_create_zero_copy_grpc_protector(
    const tsi_handshaker_result* self, size_t* max_output_protected_frame_size,
    tsi_zero_copy_grpc_protector** protector) {
  // TODO(mattstev): the implementation is blocked because the necessary API's
  // are exposed in a PR that is not yet merged.
  return TSI_UNIMPLEMENTED;
}

static tsi_result s2a_handshaker_result_get_unused_bytes(
    const tsi_handshaker_result* self, const unsigned char** bytes,
    size_t* bytes_size) {
  if (self == nullptr || bytes == nullptr || bytes_size == nullptr) {
    gpr_log(GPR_ERROR, kS2ATsiHandshakerResultUnusedBytesNullptr);
    return TSI_INVALID_ARGUMENT;
  }
  s2a_tsi_handshaker_result* result =
      reinterpret_cast<s2a_tsi_handshaker_result*>(
          const_cast<tsi_handshaker_result*>(self));
  *bytes = result->unused_bytes;
  *bytes_size = result->unused_bytes_size;
  return TSI_OK;
}

static void s2a_handshaker_result_destroy(tsi_handshaker_result* self) {
  if (self == nullptr) {
    return;
  }
  s2a_tsi_handshaker_result* result =
      reinterpret_cast<s2a_tsi_handshaker_result*>(self);
  gpr_free(result->in_traffic_secret);
  gpr_free(result->out_traffic_secret);
  gpr_free(result->spiffe_id);
  gpr_free(result->hostname);
  gpr_free(result->unused_bytes);
  gpr_free(result);
}

static const tsi_handshaker_result_vtable s2a_result_vtable = {
    s2a_handshaker_result_extract_peer,
    s2a_handshaker_result_create_zero_copy_grpc_protector, nullptr,
    s2a_handshaker_result_get_unused_bytes, s2a_handshaker_result_destroy};

tsi_result s2a_tsi_handshaker_result_create(s2a_SessionResp* response,
                                            bool is_client,
                                            tsi_handshaker_result** self) {
  if (self == nullptr || response == nullptr) {
    gpr_log(GPR_ERROR, kS2ATsiHandshakerResultNullptrArguments);
    return TSI_INVALID_ARGUMENT;
  }
  const s2a_SessionResult* handshake_result = s2a_SessionResp_result(response);
  if (handshake_result == nullptr) {
    gpr_log(GPR_ERROR, kS2ATsiHandshakerResultEmpty);
    return TSI_FAILED_PRECONDITION;
  }
  const s2a_Identity* peer_identity =
      s2a_SessionResult_peer_identity(handshake_result);
  if (peer_identity == nullptr) {
    gpr_log(GPR_ERROR, kS2ATsiHandshakerResultInvalidPeerIdentity);
    return TSI_FAILED_PRECONDITION;
  }
  const s2a_SessionState* handshake_state =
      s2a_SessionResult_state(handshake_result);
  if (handshake_state == nullptr) {
    gpr_log(GPR_ERROR, kS2ATsiHandshakerResultInvalidSessionState);
    return TSI_FAILED_PRECONDITION;
  }
  upb_strview in_traffic_secret = s2a_SessionState_in_key(handshake_state);
  upb_strview out_traffic_secret = s2a_SessionState_out_key(handshake_state);
  if (in_traffic_secret.size != out_traffic_secret.size) {
    gpr_log(GPR_ERROR, kS2ATrafficSecretSizeMismatch);
    return TSI_FAILED_PRECONDITION;
  }

  /** Instantiate S2A TSI handshaker result. **/
  s2a_tsi_handshaker_result* tsi_result =
      static_cast<s2a_tsi_handshaker_result*>(
          gpr_zalloc(sizeof(s2a_tsi_handshaker_result)));
  tsi_result->is_client = is_client;
  tsi_result->base.vtable = &s2a_result_vtable;
  *self = &(tsi_result->base);

  /** Populate fields of |tsi_result| using |peer_identity|. **/
  if (s2a_Identity_has_spiffe_id(peer_identity)) {
    upb_strview spiffe_id = s2a_Identity_spiffe_id(peer_identity);
    tsi_result->spiffe_id = gpr_strdup(spiffe_id.data);
  }
  if (s2a_Identity_has_hostname(peer_identity)) {
    upb_strview hostname = s2a_Identity_hostname(peer_identity);
    tsi_result->hostname = gpr_strdup(hostname.data);
  }

  /** Populate fields of |tsi_result| using |handshake_state|. **/
  tsi_result->tls_version = s2a_SessionState_tls_version(handshake_state);
  tsi_result->tls_ciphersuite =
      s2a_SessionState_tls_ciphersuite(handshake_state);
  tsi_result->traffic_secret_size = in_traffic_secret.size;
  tsi_result->in_traffic_secret = static_cast<uint8_t*>(
      gpr_zalloc(in_traffic_secret.size * sizeof(uint8_t)));
  memcpy(tsi_result->in_traffic_secret, in_traffic_secret.data,
         in_traffic_secret.size);
  tsi_result->out_traffic_secret = static_cast<uint8_t*>(
      gpr_zalloc(out_traffic_secret.size * sizeof(uint8_t)));
  memcpy(tsi_result->out_traffic_secret, out_traffic_secret.data,
         out_traffic_secret.size);
  return TSI_OK;
}

void s2a_tsi_handshaker_result_set_unused_bytes(tsi_handshaker_result* self,
                                                grpc_slice* recv_bytes,
                                                size_t bytes_consumed) {
  GPR_ASSERT(self != nullptr && recv_bytes != nullptr);
  if (GRPC_SLICE_LENGTH(*recv_bytes) == bytes_consumed) {
    return;
  }
  s2a_tsi_handshaker_result* result =
      reinterpret_cast<s2a_tsi_handshaker_result*>(self);
  result->unused_bytes_size = GRPC_SLICE_LENGTH(*recv_bytes) - bytes_consumed;
  result->unused_bytes =
      static_cast<uint8_t*>(gpr_zalloc(result->unused_bytes_size));
  memcpy(result->unused_bytes,
         GRPC_SLICE_START_PTR(*recv_bytes) + bytes_consumed,
         result->unused_bytes_size);
}

bool s2a_tsi_handshaker_has_shutdown(s2a_tsi_handshaker* handshaker) {
  GPR_ASSERT(handshaker != nullptr);
  grpc_core::MutexLock lock(&(handshaker->mu));
  return handshaker->shutdown;
}

void s2a_check_tsi_handshaker_for_testing(tsi_handshaker* base,
                                          grpc_slice target_name,
                                          bool is_client,
                                          bool has_sent_start_message,
                                          bool has_created_handshaker_client,
                                          bool shutdown) {
  // TODO(mattstev): expand this implementation once more fields of
  // s2a_tsi_handshaker are populated.
  s2a_tsi_handshaker* handshaker = reinterpret_cast<s2a_tsi_handshaker*>(base);
  GPR_ASSERT(grpc_slice_eq(target_name, handshaker->target_name) == 1);
  GPR_ASSERT(is_client == handshaker->is_client);
  GPR_ASSERT(has_sent_start_message == handshaker->has_sent_start_message);
  GPR_ASSERT(has_created_handshaker_client ==
             handshaker->has_created_handshaker_client);
  GPR_ASSERT(shutdown == handshaker->shutdown);
}

void s2a_check_tsi_handshaker_result_for_testing(
    tsi_handshaker_result* base, uint16_t tls_version, uint16_t tls_ciphersuite,
    uint8_t* in_traffic_secret, uint8_t* out_traffic_secret,
    size_t traffic_secret_size, char* spiffe_id, size_t spiffe_id_size,
    char* hostname, size_t hostname_size, unsigned char* unused_bytes,
    size_t unused_bytes_size, bool is_client) {
  s2a_tsi_handshaker_result* result =
      reinterpret_cast<s2a_tsi_handshaker_result*>(base);
  GPR_ASSERT(tls_version == result->tls_version);
  GPR_ASSERT(tls_ciphersuite == result->tls_ciphersuite);
  GPR_ASSERT(traffic_secret_size == result->traffic_secret_size);
  for (size_t i = 0; i < traffic_secret_size; i++) {
    GPR_ASSERT(in_traffic_secret[i] == result->in_traffic_secret[i]);
    GPR_ASSERT(out_traffic_secret[i] == result->out_traffic_secret[i]);
  }
  if (spiffe_id == nullptr || result->spiffe_id == nullptr) {
    GPR_ASSERT(spiffe_id == nullptr && result->spiffe_id == nullptr);
  } else {
    GPR_ASSERT(strncmp(spiffe_id, result->spiffe_id, spiffe_id_size) == 0);
  }
  if (hostname == nullptr || result->hostname == nullptr) {
    GPR_ASSERT(hostname == nullptr && result->hostname == nullptr);
  } else {
    GPR_ASSERT(strncmp(hostname, result->hostname, hostname_size) == 0);
  }
  GPR_ASSERT(unused_bytes_size == result->unused_bytes_size);
  for (size_t j = 0; j < unused_bytes_size; j++) {
    GPR_ASSERT(unused_bytes[j] == result->unused_bytes[j]);
  }
  GPR_ASSERT(is_client == result->is_client);
}

}  // namespace experimental
}  // namespace grpc_core
