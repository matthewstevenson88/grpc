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

#include "src/core/tsi/s2a/s2a_tsi_handshaker.h"

#include <grpc/slice.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <grpc/support/string_util.h>
#include <grpc/support/sync.h>

#include "src/core/tsi/s2a/frame_protector/s2a_zero_copy_grpc_protector.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"
#include "src/core/tsi/s2a/handshaker/s2a_tsi_test_utilities.h"
#include "src/core/tsi/s2a/s2a_security.h"
#include "absl/status/statusor.h"
#include "src/core/lib/slice/slice_internal.h"
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/transport_security.h"
#include "s2a/include/s2a_frame_protector.h"
#include "s2a/src/proto/upb-generated/proto/common.upb.h"
#include "s2a/src/proto/upb-generated/proto/s2a.upb.h"
#include "s2a/src/proto/upb-generated/proto/s2a_context.upb.h"
#include "upb/upb.hpp"

namespace s2a {
namespace tsi {

using Identity = s2a_options::S2AOptions::Identity;

/** The main struct for the S2A TSI handshaker. **/
struct s2a_tsi_handshaker {
  tsi_handshaker base;
  grpc_slice target_name;
  bool is_client;
  bool is_test;
  create_mock_handshaker_client create_mock;
  bool has_sent_start_message;
  bool has_created_handshaker_client;
  grpc_pollset_set* interested_parties;
  grpc_s2a_credentials_options* options;
  grpc_channel* channel;
  /** The mutex |mu| synchronizes the fields |client| and |shutdown|. These are
   *  the only fields of the s2a_tsi_handshaker that could be accessed
   *  concurrently (due to the potential concurrency of the
   *  |tsi_handshaker_shutdown| and |tsi_handshaker_next| methods). **/
  grpc_core::Mutex mu;
  S2AHandshakerClient* client;
  bool shutdown;
};

/** The main struct for the S2A TSI handshaker result. **/
typedef struct s2a_tsi_handshaker_result {
  tsi_handshaker_result base;
  std::unique_ptr<s2a_proxy::S2AProxy> proxy;
  // |unused_bytes| is a buffer used to store any bytes left over from the
  // handshake, which may be populated e.g. with a TLS record (containing
  // application data) that was appended to a handshake message.
  std::vector<uint8_t> unused_bytes;
} s2a_tsi_handshaker_result;

struct s2a_tsi_handshaker_continue_handshaker_next_args {
  s2a_tsi_handshaker* handshaker;
  std::unique_ptr<uint8_t> received_bytes;
  size_t received_bytes_size;
  tsi_handshaker_on_next_done_cb cb;
  void* user_data;
  grpc_closure closure;
};

/** A gRPC-provided callback function that is used when gRPC thread model is
 *  applied. */
static void on_handshaker_service_resp_recv(void* arg,
                                            grpc_error_handle error) {
  GPR_ASSERT(arg != nullptr);
  S2AHandshakerClient* client = static_cast<S2AHandshakerClient*>(arg);
  bool success = true;
  if (error != GRPC_ERROR_NONE) {
    gpr_log(GPR_ERROR,
            "In the S2A TSI handshaker's |on_handshaker_service_resp_recv| "
            "method, there is the error: %s",
            grpc_error_std_string(error).c_str());
    success = false;
  }
  client->HandleResponse(success);
}

static tsi_result s2a_tsi_handshaker_continue_handshaker_next(
    s2a_tsi_handshaker* handshaker, const uint8_t* received_bytes,
    size_t received_bytes_size, tsi_handshaker_on_next_done_cb cb,
    void* user_data) {
  GPR_ASSERT(handshaker != nullptr);
  grpc_core::MutexLock lock(&handshaker->mu);
  if (!handshaker->has_created_handshaker_client) {
    S2AHandshakerClient* client = nullptr;
    tsi_result client_create_result = TSI_OK;
    if (handshaker->is_test) {
      GPR_ASSERT(handshaker->create_mock != nullptr);
      client_create_result = handshaker->create_mock(
          &(handshaker->base), handshaker->channel,
          handshaker->interested_parties, handshaker->options,
          handshaker->target_name, on_handshaker_service_resp_recv, cb,
          user_data, handshaker->is_client, &client);
    } else {
      client_create_result = S2AHandshakerClientCreate(
          &(handshaker->base), handshaker->channel,
          handshaker->interested_parties, handshaker->options,
          handshaker->target_name, on_handshaker_service_resp_recv, cb,
          user_data, handshaker->is_client, handshaker->is_test, &client);
    }
    GPR_ASSERT(client != nullptr);
    GPR_ASSERT(client_create_result == TSI_OK);
    GPR_ASSERT(handshaker->client == nullptr);
    handshaker->client = client;
    if (handshaker->shutdown) {
      gpr_log(GPR_ERROR, "TSI handshake shutdown.");
      return TSI_HANDSHAKE_SHUTDOWN;
    }
    handshaker->has_created_handshaker_client = true;
  }

  grpc_slice slice = (received_bytes == nullptr || received_bytes_size == 0)
                         ? grpc_empty_slice()
                         : grpc_slice_from_copied_buffer(
                               reinterpret_cast<const char*>(received_bytes),
                               received_bytes_size);
  GPR_ASSERT(handshaker->client != nullptr);
  if (!handshaker->has_sent_start_message) {
    handshaker->has_sent_start_message = true;
  }
  tsi_result ok = handshaker->client->Next(&slice);
  grpc_slice_unref_internal(slice);
  return ok;
}

static void s2a_tsi_handshaker_create_channel_and_continue_handshaker_next(
    void* arg, grpc_error_handle unused_error) {
  GPR_ASSERT(arg != nullptr);
  s2a_tsi_handshaker_continue_handshaker_next_args* next_args =
      static_cast<s2a_tsi_handshaker_continue_handshaker_next_args*>(arg);
  s2a_tsi_handshaker* handshaker = next_args->handshaker;
  GPR_ASSERT(handshaker != nullptr);
  GPR_ASSERT(handshaker->channel == nullptr);
  handshaker->channel = ::grpc_insecure_channel_create(
      next_args->handshaker->options->s2a_options.s2a_address()
          .c_str(),
      nullptr, nullptr);
  tsi_result continue_next_result = s2a_tsi_handshaker_continue_handshaker_next(
      handshaker, next_args->received_bytes.get(),
      next_args->received_bytes_size, next_args->cb, next_args->user_data);
  if (continue_next_result != TSI_OK) {
    next_args->cb(continue_next_result, next_args->user_data, nullptr, 0,
                  nullptr);
  }
  delete next_args;
}

static tsi_result handshaker_next(
    tsi_handshaker* self, const unsigned char* received_bytes,
    size_t received_bytes_size, const unsigned char** /** bytes_to_send **/,
    size_t* /** bytes_to_send_size **/, tsi_handshaker_result** /** result **/,
    tsi_handshaker_on_next_done_cb cb, void* user_data) {
  if (self == nullptr || cb == nullptr) {
    gpr_log(GPR_ERROR, "Invalid nullptr arguments to |handshaker_next|.");
    return TSI_INVALID_ARGUMENT;
  }
  s2a_tsi_handshaker* handshaker = reinterpret_cast<s2a_tsi_handshaker*>(self);
  {
    grpc_core::MutexLock lock(&handshaker->mu);
    if (handshaker->shutdown) {
      gpr_log(GPR_ERROR, "TSI handshake shutdown.");
      return TSI_HANDSHAKE_SHUTDOWN;
    }
  }
  if (handshaker->channel == nullptr && !handshaker->is_test) {
    s2a_tsi_handshaker_continue_handshaker_next_args* args =
        new s2a_tsi_handshaker_continue_handshaker_next_args();
    args->handshaker = handshaker;
    args->received_bytes = nullptr;
    args->received_bytes_size = received_bytes_size;
    if (received_bytes_size > 0) {
      args->received_bytes = std::unique_ptr<uint8_t>(
          static_cast<uint8_t*>(gpr_zalloc(received_bytes_size)));
      memcpy(args->received_bytes.get(), received_bytes, received_bytes_size);
    }
    args->cb = cb;
    args->user_data = user_data;
    GRPC_CLOSURE_INIT(
        &args->closure,
        s2a_tsi_handshaker_create_channel_and_continue_handshaker_next, args,
        grpc_schedule_on_exec_ctx);
    grpc_core::ExecCtx::Run(DEBUG_LOCATION, &args->closure, GRPC_ERROR_NONE);
  } else {
    tsi_result ok = s2a_tsi_handshaker_continue_handshaker_next(
        handshaker, received_bytes, received_bytes_size, cb, user_data);
    if (ok != TSI_OK) {
      gpr_log(GPR_ERROR, "Failed to schedule S2A handshaker requests.");
      return ok;
    }
  }
  return TSI_ASYNC;
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
  {
    grpc_core::MutexLock lock(&(handshaker->mu));
    S2AHandshakerClientDestroy(handshaker->client);
  }
  grpc_slice_unref_internal(handshaker->target_name);
  if (handshaker->channel != nullptr) {
    grpc_channel_destroy_internal(handshaker->channel);
  }
  gpr_free(handshaker);
}

static const tsi_handshaker_vtable handshaker_vtable = {
    nullptr,         nullptr,
    nullptr,         nullptr,
    nullptr,         handshaker_destroy,
    handshaker_next, handshaker_shutdown};

absl::StatusOr<tsi_handshaker*> CreateS2ATsiHandshaker(
    S2ATsiHandshakerOptions& options) {
  if (options.s2a_options == nullptr ||
      (options.is_client && options.target_name == nullptr)) {
    return absl::InvalidArgumentError(kS2ATsiHandshakerNullptrArguments);
  }
  s2a_tsi_handshaker* handshaker =
      static_cast<s2a_tsi_handshaker*>(gpr_zalloc(sizeof(s2a_tsi_handshaker)));
  handshaker->is_client = options.is_client;
  handshaker->target_name =
      (options.target_name == nullptr)
          ? grpc_empty_slice()
          : grpc_slice_from_static_string(options.target_name);
  handshaker->interested_parties = options.interested_parties;
  handshaker->options = options.s2a_options;
  handshaker->base.vtable = &handshaker_vtable;
  return &(handshaker->base);
}

absl::StatusOr<tsi_handshaker*> CreateS2ATsiHandshakerForTesting(
    S2ATsiHandshakerOptions& options) {
  absl::StatusOr<tsi_handshaker*> handshaker = CreateS2ATsiHandshaker(options);
  if (handshaker.ok()) {
    s2a_tsi_handshaker* s2a_handshaker =
        reinterpret_cast<s2a_tsi_handshaker*>(*handshaker);
    s2a_handshaker->is_test = true;
  }
  return handshaker;
}

static tsi_result s2a_handshaker_result_extract_peer(
    const tsi_handshaker_result* self, tsi_peer* peer) {
  if (self == nullptr || peer == nullptr) {
    gpr_log(GPR_ERROR,
            "Invalid argument to |s2a_handshaker_result_extract_peer|.");
    return TSI_INVALID_ARGUMENT;
  }
  s2a_tsi_handshaker_result* result =
      reinterpret_cast<s2a_tsi_handshaker_result*>(
          const_cast<tsi_handshaker_result*>(self));
  GPR_ASSERT(kTsiS2ANumOfPeerProperties == 4);

  // Construct TSI peer.
  tsi_result ok = tsi_construct_peer(kTsiS2ANumOfPeerProperties, peer);
  int index = 0;
  if (ok != TSI_OK) {
    gpr_log(GPR_ERROR, "Failed to construct TSI peer.");
    return ok;
  }
  GPR_ASSERT(&peer->properties[index] != nullptr);

  // Retrieve |S2AContext| from |S2AProxy|.
  absl::variant<absl::Status, std::unique_ptr<s2a_context::S2AContext>>
      context_status = result->proxy->GetS2AContext();
  switch (context_status.index()) {
    case 0:
      gpr_log(GPR_INFO, "Failed to get |S2AContext|: %s",
              std::string(absl::get<0>(context_status).message()).c_str());
      return TSI_INTERNAL_ERROR;
    case 1:
      break;
    default:  // Unexpected variant case.
      gpr_log(GPR_ERROR, "Unexpected variant case.");
      ABSL_ASSERT(0);
  }

  // Construct the TSI certificate type peer property.
  ok = tsi_construct_string_peer_property_from_cstring(
      TSI_CERTIFICATE_TYPE_PEER_PROPERTY, kTsiS2ACertificateType,
      &peer->properties[index]);
  if (ok != TSI_OK) {
    tsi_peer_destruct(peer);
    gpr_log(GPR_ERROR,
            "Failed to set TSI peer property: TSI certificate type.");
    return ok;
  }
  index++;
  GPR_ASSERT(&peer->properties[index] != nullptr);

  // Construct the TSI S2A peer identity peer property. This will be either in
  // the form of a SPIFFE ID or a hostname.
  ok = tsi_construct_string_peer_property_from_cstring(
      kTsiS2APeerIdentityPeerProperty,
      absl::get<1>(context_status)->PeerIdentity().GetIdentityCString(),
      &peer->properties[index]);
  if (ok != TSI_OK) {
    tsi_peer_destruct(peer);
    gpr_log(GPR_ERROR,
            "Failed to set TSI peer property: TSI S2A peer identity.");
    return ok;
  }
  index++;
  GPR_ASSERT(&peer->properties[index] != nullptr);

  // Construct the TSI security level peer property.
  ok = tsi_construct_string_peer_property_from_cstring(
      TSI_SECURITY_LEVEL_PEER_PROPERTY,
      tsi_security_level_to_string(TSI_PRIVACY_AND_INTEGRITY),
      &peer->properties[index]);
  if (ok != TSI_OK) {
    tsi_peer_destruct(peer);
    gpr_log(GPR_ERROR, "Failed to set TSI peer property: TSI security level.");
    return ok;
  }
  index++;
  GPR_ASSERT(&peer->properties[index] != nullptr);

  // Construct the TSI S2A context peer property.
  absl::variant<absl::Status, std::unique_ptr<std::vector<char>>>
      serialized_context_status =
          absl::get<1>(context_status)->GetSerializedContext();
  switch (serialized_context_status.index()) {
    case 0:
      gpr_log(GPR_INFO, "Failed to serialize S2A context: %s",
              std::string(absl::get<0>(serialized_context_status).message())
                  .c_str());
      return TSI_INTERNAL_ERROR;
    case 1:
      break;
    default:  // Unexpected variant case.
      gpr_log(GPR_ERROR, "Unexpected variant case.");
      ABSL_ASSERT(0);
  }
  ok = tsi_construct_string_peer_property(
      kTsiS2AContext, absl::get<1>(serialized_context_status)->data(),
      absl::get<1>(serialized_context_status)->size(),
      &peer->properties[index]);
  if (ok != TSI_OK) {
    tsi_peer_destruct(peer);
    gpr_log(GPR_ERROR, "Failed to set TSI peer property: TSI S2A context.");
    return ok;
  }
  GPR_ASSERT(++index == kTsiS2ANumOfPeerProperties);
  return ok;
}

static tsi_result s2a_handshaker_result_create_zero_copy_grpc_protector(
    const tsi_handshaker_result* self, size_t* max_output_protected_frame_size,
    tsi_zero_copy_grpc_protector** protector) {
  if (self == nullptr || protector == nullptr) {
    gpr_log(GPR_ERROR,
            "Invalid nullptr argument to "
            "|s2a_handshaker_result_create_zero_copy_grpc_protector|.");
    return TSI_INVALID_ARGUMENT;
  }
  s2a_tsi_handshaker_result* result =
      reinterpret_cast<s2a_tsi_handshaker_result*>(
          const_cast<tsi_handshaker_result*>(self));
  absl::StatusOr<std::unique_ptr<frame_protector::S2AFrameProtector>>
      s2a_protector_or = result->proxy->CreateFrameProtector();
  if (!s2a_protector_or.ok()) {
    gpr_log(GPR_INFO, "Failed to create frame protector: %s",
            std::string(s2a_protector_or.status().message()).c_str());
    return TSI_INTERNAL_ERROR;
  }
  absl::StatusOr<tsi_zero_copy_grpc_protector*> protector_or =
      s2a_zero_copy_grpc_protector_create(std::move(*s2a_protector_or));
  if (!protector_or.ok()) {
    gpr_log(GPR_INFO, "Failed to create zero copy grpc protector: %s",
            std::string(protector_or.status().message()).c_str());
    return TSI_INTERNAL_ERROR;
  }
  *protector = *protector_or;
  return TSI_OK;
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
  *bytes = result->unused_bytes.data();
  *bytes_size = result->unused_bytes.size();
  return TSI_OK;
}

static void s2a_handshaker_result_destroy(tsi_handshaker_result* self) {
  if (self == nullptr) {
    return;
  }
  s2a_tsi_handshaker_result* result =
      reinterpret_cast<s2a_tsi_handshaker_result*>(self);
  delete result;
}

static const tsi_handshaker_result_vtable s2a_result_vtable = {
    s2a_handshaker_result_extract_peer,
    s2a_handshaker_result_create_zero_copy_grpc_protector, nullptr,
    s2a_handshaker_result_get_unused_bytes, s2a_handshaker_result_destroy};

absl::StatusOr<tsi_handshaker_result*> CreateS2ATsiHandshakerResult(
    std::unique_ptr<s2a_proxy::S2AProxy> proxy) {
  if (proxy == nullptr) {
    return absl::InvalidArgumentError(
        "Unexpected nullptr argument to |s2a_tsi_handshaker_result_create|.");
  }
  if (!proxy->IsHandshakeFinished()) {
    return absl::FailedPreconditionError("Handshake is not complete.");
  }
  s2a_tsi_handshaker_result* result = new s2a_tsi_handshaker_result();
  result->base.vtable = &s2a_result_vtable;
  result->proxy = std::move(proxy);
  return &(result->base);
}

void SetUnusedBytes(tsi_handshaker_result* result, grpc_slice* recv_bytes,
                    size_t bytes_consumed) {
  GPR_ASSERT(result != nullptr);
  GPR_ASSERT(recv_bytes != nullptr);
  if (GRPC_SLICE_LENGTH(*recv_bytes) == bytes_consumed) {
    return;
  }
  s2a_tsi_handshaker_result* s2a_result =
      reinterpret_cast<s2a_tsi_handshaker_result*>(result);
  size_t bytes_remaining = GRPC_SLICE_LENGTH(*recv_bytes) - bytes_consumed;
  s2a_result->unused_bytes.resize(bytes_remaining);
  memcpy(s2a_result->unused_bytes.data(),
         GRPC_SLICE_START_PTR(*recv_bytes) + bytes_consumed, bytes_remaining);
}

bool IsShutdown(tsi_handshaker* handshaker) {
  GPR_ASSERT(handshaker != nullptr);
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  grpc_core::MutexLock lock(&(s2a_handshaker->mu));
  return s2a_handshaker->shutdown;
}

void s2a_check_tsi_handshaker_for_testing(tsi_handshaker* base,
                                          grpc_slice target_name,
                                          bool is_client,
                                          bool has_sent_start_message,
                                          bool has_created_handshaker_client,
                                          bool shutdown) {
  s2a_tsi_handshaker* handshaker = reinterpret_cast<s2a_tsi_handshaker*>(base);
  if (!handshaker->is_test) {
    return;
  }
  GPR_ASSERT(grpc_slice_eq(target_name, handshaker->target_name) == 1);
  GPR_ASSERT(is_client == handshaker->is_client);
  GPR_ASSERT(has_sent_start_message == handshaker->has_sent_start_message);
  GPR_ASSERT(has_created_handshaker_client ==
             handshaker->has_created_handshaker_client);
  GPR_ASSERT(shutdown == handshaker->shutdown);
}

const ::grpc_s2a_credentials_options* s2a_tsi_handshaker_options_for_testing(
    tsi_handshaker* base) {
  s2a_tsi_handshaker* handshaker = reinterpret_cast<s2a_tsi_handshaker*>(base);
  if (handshaker == nullptr || !handshaker->is_test) {
    return nullptr;
  }
  return handshaker->options;
}

S2AHandshakerClient* s2a_tsi_handshaker_client_for_testing(
    tsi_handshaker* handshaker) {
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  if (s2a_handshaker == nullptr || !s2a_handshaker->is_test) {
    return nullptr;
  }
  return s2a_handshaker->client;
}

bool s2a_tsi_handshaker_has_sent_start_message_for_testing(
    tsi_handshaker* handshaker) {
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  if (s2a_handshaker == nullptr || !s2a_handshaker->is_test) {
    return false;
  }
  return s2a_handshaker->has_sent_start_message;
}

void s2a_tsi_handshaker_set_create_mock_handshaker_client(
    tsi_handshaker* handshaker, create_mock_handshaker_client create_mock) {
  s2a_tsi_handshaker* s2a_handshaker =
      reinterpret_cast<s2a_tsi_handshaker*>(handshaker);
  if (s2a_handshaker == nullptr || !s2a_handshaker->is_test) {
    return;
  }
  s2a_handshaker->create_mock = create_mock;
}

}  // namespace tsi
}  // namespace s2a

