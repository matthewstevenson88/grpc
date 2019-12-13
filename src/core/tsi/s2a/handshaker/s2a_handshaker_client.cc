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

#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"

#include <grpc/support/alloc.h>
#include <grpc/support/log.h>

#include "src/core/lib/slice/slice_internal.h"
#include "src/core/lib/surface/call.h"
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "src/proto/grpc/gcp/s2a.upb.h"

namespace grpc_core {
namespace experimental {

/** ------------ Preparation of client start messages. --------------- **/

grpc_byte_buffer* S2AHandshakerClient::SerializedStartClient() {
  upb::Arena arena;
  s2a_SessionReq* request = s2a_SessionReq_new(arena.ptr());
  s2a_ClientSessionStartReq* start_client =
      s2a_SessionReq_mutable_client_start(request, arena.ptr());

  /** Set application protocol. **/
  s2a_ClientSessionStartReq_add_application_protocols(
      start_client, upb_strview_makez(kS2AApplicationProtocol), arena.ptr());

  /** Set TLS version. **/
  int32_t* tls_versions = s2a_ClientSessionStartReq_resize_tls_versions(
      start_client, /*len=*/1, arena.ptr());
  GPR_ASSERT(tls_versions != nullptr);
  tls_versions[0] = s2a_TLS1_3;

  /** Set supported TLS ciphersuites. **/
  int32_t* tls_ciphersuites = s2a_ClientSessionStartReq_resize_tls_ciphersuites(
      start_client, options_->supported_ciphersuites().size(), arena.ptr());
  GPR_ASSERT(tls_ciphersuites != nullptr);
  for (size_t i = 0; i < options_->supported_ciphersuites().size(); i++) {
    tls_ciphersuites[i] = options_->supported_ciphersuites()[i];
  }

  /** Set SPIFFE ID of target service accounts. **/
  for (size_t j = 0; j < options_->target_service_account_list().size(); j++) {
    s2a_Identity* identity = s2a_ClientSessionStartReq_add_target_identities(
        start_client, arena.ptr());
    s2a_Identity_set_spiffe_id(
        identity,
        upb_strview_makez(options_->target_service_account_list()[j].c_str()));
  }

  /** Set target name. **/
  s2a_ClientSessionStartReq_set_target_name(
      start_client, upb_strview_make(reinterpret_cast<const char*>(
                                         GRPC_SLICE_START_PTR(target_name_)),
                                     GRPC_SLICE_LENGTH(target_name_)));
  return s2a_get_serialized_session_req(request, arena.ptr());
}

tsi_result S2AHandshakerClient::ClientStart() {
  grpc_byte_buffer* buffer = SerializedStartClient();
  if (buffer == nullptr) {
    gpr_log(GPR_ERROR, kS2AGetSerializedStartClientFailed);
    return TSI_INTERNAL_ERROR;
  }
  grpc_byte_buffer_destroy(send_buffer_);
  send_buffer_ = buffer;
  tsi_result call_result = MakeGrpcCall(/*is_start=*/true);
  if (call_result != TSI_OK) {
    gpr_log(GPR_ERROR, kS2AMakeGrpcCallFailed);
  }
  return call_result;
}

/** ------------ Preparation of server start messages. --------------- **/

grpc_byte_buffer* S2AHandshakerClient::SerializedStartServer(
    grpc_slice* bytes_received) {
  GPR_ASSERT(bytes_received != nullptr);
  upb::Arena arena;
  s2a_SessionReq* request = s2a_SessionReq_new(arena.ptr());
  s2a_ServerSessionStartReq* start_server =
      s2a_SessionReq_mutable_server_start(request, arena.ptr());

  /** Set application protocols. **/
  s2a_ServerSessionStartReq_add_application_protocols(
      start_server, upb_strview_makez(kS2AApplicationProtocol), arena.ptr());

  /** Set TLS version. **/
  int32_t* tls_versions = s2a_ServerSessionStartReq_resize_tls_versions(
      start_server, /*len=*/1, arena.ptr());
  GPR_ASSERT(tls_versions != nullptr);
  tls_versions[0] = s2a_TLS1_3;

  /** Set supported TLS ciphersuites. **/
  int32_t* tls_ciphersuites = s2a_ServerSessionStartReq_resize_tls_ciphersuites(
      start_server, options_->supported_ciphersuites().size(), arena.ptr());
  GPR_ASSERT(tls_ciphersuites != nullptr);
  for (size_t i = 0; i < options_->supported_ciphersuites().size(); i++) {
    tls_ciphersuites[i] = options_->supported_ciphersuites()[i];
  }

  /** Set in bytes received from peer. **/
  s2a_ServerSessionStartReq_set_in_bytes(
      start_server, upb_strview_make(reinterpret_cast<const char*>(
                                         GRPC_SLICE_START_PTR(*bytes_received)),
                                     GRPC_SLICE_LENGTH(*bytes_received)));
  return s2a_get_serialized_session_req(request, arena.ptr());
}

tsi_result S2AHandshakerClient::ServerStart(grpc_slice* bytes_received) {
  GPR_ASSERT(bytes_received != nullptr);
  grpc_byte_buffer* buffer = SerializedStartServer(bytes_received);
  if (buffer == nullptr) {
    gpr_log(GPR_ERROR, kS2AGetSerializedStartServerFailed);
    return TSI_INTERNAL_ERROR;
  }
  grpc_byte_buffer_destroy(send_buffer_);
  send_buffer_ = buffer;
  tsi_result call_result = MakeGrpcCall(/*is_start=*/true);
  if (call_result != TSI_OK) {
    gpr_log(GPR_ERROR, kS2AMakeGrpcCallFailed);
  }
  return call_result;
}

/** ------------ Preparation of next messages. --------------- **/

grpc_byte_buffer* S2AHandshakerClient::SerializedNext(
    grpc_slice* bytes_received) {
  GPR_ASSERT(bytes_received != nullptr);
  upb::Arena arena;
  s2a_SessionReq* request = s2a_SessionReq_new(arena.ptr());
  s2a_SessionNextReq* next = s2a_SessionReq_mutable_next(request, arena.ptr());

  /** Set in bytes received from peer. **/
  s2a_SessionNextReq_set_in_bytes(
      next, upb_strview_make(reinterpret_cast<const char*>(
                                 GRPC_SLICE_START_PTR(*bytes_received)),
                             GRPC_SLICE_LENGTH(*bytes_received)));
  return s2a_get_serialized_session_req(request, arena.ptr());
}

tsi_result S2AHandshakerClient::Next(grpc_slice* bytes_received) {
  GPR_ASSERT(bytes_received != nullptr);
  grpc_slice_unref_internal(recv_bytes_);
  recv_bytes_ = grpc_slice_ref_internal(*bytes_received);
  grpc_byte_buffer* buffer = SerializedNext(bytes_received);
  if (buffer == nullptr) {
    gpr_log(GPR_ERROR, kS2AGetSerializedNextFailed);
    return TSI_INTERNAL_ERROR;
  }
  grpc_byte_buffer_destroy(send_buffer_);
  send_buffer_ = buffer;
  tsi_result call_result = MakeGrpcCall(/*is_start=*/false);
  if (call_result != TSI_OK) {
    gpr_log(GPR_ERROR, kS2AMakeGrpcCallFailed);
  }
  return call_result;
}

/** ------------------- Callback methods. -------------------------------- **/

static void S2AOnStatusReceived(void* arg, grpc_error* error) {
  // TODO(mattstev): implement.
  return;
}

/** ------------------- Create, shutdown, & destroy methods. ------------- **/

S2AHandshakerClient::S2AHandshakerClient(
    s2a_tsi_handshaker* handshaker, grpc_channel* channel,
    grpc_pollset_set* interested_parties,
    const grpc_s2a_credentials_options* options, const grpc_slice& target_name,
    grpc_iomgr_cb_func grpc_cb, tsi_handshaker_on_next_done_cb cb,
    void* user_data, bool is_client)
    : handshaker_(handshaker),
      cb_(cb),
      user_data_(user_data),
      send_buffer_(nullptr),
      recv_buffer_(nullptr),
      grpc_caller_(grpc_call_start_batch_and_execute),
      target_name_(grpc_slice_copy(target_name)),
      recv_bytes_(grpc_empty_slice()),
      is_client_(is_client),
      buffer_size_(kS2AInitialBufferSize),
      handshake_status_details_(grpc_empty_slice()),
      options_(options) {
  gpr_mu_init(&mu_);
  gpr_ref_init(&refs_, 1);
  grpc_metadata_array_init(&recv_initial_metadata_);
  buffer_ = static_cast<uint8_t*>(gpr_zalloc(buffer_size_));
  grpc_slice slice =
      grpc_slice_from_copied_string(options->handshaker_service_url().c_str());
  call_ = (options->handshaker_service_url().compare(
               kS2AHandshakerServiceUrlForTesting) == 0)
              ? nullptr
              : grpc_channel_create_pollset_set_call(
                    channel, /*parent_call=*/nullptr, GRPC_PROPAGATE_DEFAULTS,
                    interested_parties,
                    grpc_slice_from_static_string(kS2AServiceMethod), &slice,
                    GRPC_MILLIS_INF_FUTURE, /*reserved=*/nullptr);
  GRPC_CLOSURE_INIT(&on_handshaker_service_resp_recv_, grpc_cb, this,
                    grpc_schedule_on_exec_ctx);
  GRPC_CLOSURE_INIT(&on_status_received_, S2AOnStatusReceived, this,
                    grpc_schedule_on_exec_ctx);
  grpc_slice_unref_internal(slice);
}

tsi_result s2a_handshaker_client_create(
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
  *client =
      new S2AHandshakerClient(handshaker, channel, interested_parties, options,
                              target_name, grpc_cb, cb, user_data, is_client);
  return TSI_OK;
}

void S2AHandshakerClient::Shutdown() {
  if (call_ != nullptr) {
    grpc_call_cancel_internal(call_);
  }
}

/** This method destroys the grpc_call owned by the s2a_handshaker_client. **/
static void S2AHandshakerCallUnref(void* arg, grpc_error* error) {
  grpc_call* call = static_cast<grpc_call*>(arg);
  grpc_call_unref(call);
}

S2AHandshakerClient::~S2AHandshakerClient() {
  if (gpr_unref(&refs_)) {
    if (call_ != nullptr) {
      grpc_core::ExecCtx::Run(DEBUG_LOCATION,
                              GRPC_CLOSURE_CREATE(S2AHandshakerCallUnref, call_,
                                                  grpc_schedule_on_exec_ctx),
                              GRPC_ERROR_NONE);
    }
    grpc_byte_buffer_destroy(send_buffer_);
    grpc_byte_buffer_destroy(recv_buffer_);
    send_buffer_ = nullptr;
    recv_buffer_ = nullptr;
    grpc_metadata_array_destroy(&recv_initial_metadata_);
    grpc_slice_unref_internal(recv_bytes_);
    grpc_slice_unref_internal(target_name_);
    gpr_free(buffer_);
    grpc_slice_unref_internal(handshake_status_details_);
    gpr_mu_destroy(&mu_);
  }
}

void s2a_handshaker_client_destroy(S2AHandshakerClient* client) {
  if (client == nullptr) {
    return;
  }
  delete client;
}

/** ------------------- Testing methods. -------------------------- **/

grpc_byte_buffer* S2AHandshakerClient::get_send_buffer_for_testing() {
  return send_buffer_;
}

}  // namespace experimental
}  // namespace grpc_core
