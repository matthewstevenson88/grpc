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

tsi_result S2AHandshakerClient::MakeGrpcCallUtil(bool is_start) {
  tsi_result call_result = MakeGrpcCall(is_start);
  if (call_result != TSI_OK) {
    gpr_log(GPR_ERROR, kS2AMakeGrpcCallFailed);
    return call_result;
  }
  return TSI_OK;
}

/** ------------ Preparation of client start messages. --------------- **/

grpc_byte_buffer* S2AHandshakerClient::SerializedStartClient() {
  upb::Arena arena;
  s2a_SessionReq* request = s2a_SessionReq_new(arena.ptr());
  s2a_ClientSessionStartReq* start_client =
      s2a_SessionReq_mutable_client_start(request, arena.ptr());

  /** Set application protocol. **/
  s2a_ClientSessionStartReq_add_application_protocols(
      start_client, upb_strview_makez(kS2AApplicationProtocol), arena.ptr());

  /** Set min and max TLS version. **/
  s2a_ClientSessionStartReq_set_min_tls_version(start_client, s2a_TLS1_3);
  s2a_ClientSessionStartReq_set_max_tls_version(start_client, s2a_TLS1_3);

  /** Set supported TLS ciphersuites. **/
  int32_t* tls_ciphersuites = s2a_ClientSessionStartReq_resize_tls_ciphersuites(
      start_client, options_->supported_ciphersuites().size(), arena.ptr());
  GPR_ASSERT(tls_ciphersuites != nullptr);
  size_t index = 0;
  for (auto ciphersuite : options_->supported_ciphersuites()) {
    tls_ciphersuites[index] = ciphersuite;
    index++;
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
  return MakeGrpcCallUtil(/*is_start=*/true);
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

  /** Set min and max TLS version. **/
  s2a_ServerSessionStartReq_set_min_tls_version(start_server, s2a_TLS1_3);
  s2a_ServerSessionStartReq_set_max_tls_version(start_server, s2a_TLS1_3);

  /** Set supported TLS ciphersuites. **/
  int32_t* tls_ciphersuites = s2a_ServerSessionStartReq_resize_tls_ciphersuites(
      start_server, options_->supported_ciphersuites().size(), arena.ptr());
  GPR_ASSERT(tls_ciphersuites != nullptr);
  size_t index = 0;
  for (auto ciphersuite : options_->supported_ciphersuites()) {
    tls_ciphersuites[index] = ciphersuite;
    index++;
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
  return MakeGrpcCallUtil(/*is_start=*/true);
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
  return MakeGrpcCallUtil(/*is_start=*/true);
}

/** ------------------- Callback methods. -------------------------------- **/

static void S2AOnStatusReceived(void* arg, grpc_error* error) {
  S2AHandshakerClient* client = static_cast<S2AHandshakerClient*>(arg);
  GPR_ASSERT(client != nullptr);
  if (client->handshake_status_code() != GRPC_STATUS_OK) {
    char* status_details =
        grpc_slice_to_c_string(client->handshake_status_details());
    gpr_log(GPR_INFO,
            "S2AHandshakerClient:%p on_status_received status:%d "
            "details:|%s| error:|%s|",
            client, client->handshake_status_code(), status_details,
            grpc_error_string(error));
    gpr_free(status_details);
  }
  client->MaybeCompleteTsiNext(/*receive_status_finished=*/true,
                               /*pending_recv_message_result=*/nullptr);
  client->Unref();
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
    void* user_data, bool is_client, bool is_test)
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
      options_(options),
      is_test_(is_test) {
  gpr_mu_init(&mu_);
  refs_ = static_cast<gpr_refcount*>(gpr_zalloc(sizeof(gpr_refcount)));
  gpr_ref_init(refs_, 1);
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

tsi_result S2AHandshakerClientCreate(
    s2a_tsi_handshaker* handshaker, grpc_channel* channel,
    grpc_pollset_set* interested_parties,
    const grpc_s2a_credentials_options* options, const grpc_slice& target_name,
    grpc_iomgr_cb_func grpc_cb, tsi_handshaker_on_next_done_cb cb,
    void* user_data, bool is_client, bool is_test,
    S2AHandshakerClient** client) {
  if (channel == nullptr || client == nullptr ||
      options->handshaker_service_url().empty()) {
    gpr_log(GPR_ERROR, kS2AHandshakerClientNullptrArguments);
    return TSI_INVALID_ARGUMENT;
  }
  *client = new S2AHandshakerClient(handshaker, channel, interested_parties,
                                    options, target_name, grpc_cb, cb,
                                    user_data, is_client, is_test);
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

void S2AHandshakerClient::Unref() {
  if (gpr_unref(refs_)) {
    if (call_ != nullptr) {
      grpc_core::ExecCtx::Run(DEBUG_LOCATION,
                              GRPC_CLOSURE_CREATE(S2AHandshakerCallUnref, call_,
                                                  grpc_schedule_on_exec_ctx),
                              GRPC_ERROR_NONE);
    }
    gpr_free(refs_);
    grpc_byte_buffer_destroy(send_buffer_);
    grpc_byte_buffer_destroy(recv_buffer_);
    grpc_metadata_array_destroy(&recv_initial_metadata_);
    grpc_slice_unref_internal(recv_bytes_);
    grpc_slice_unref_internal(target_name_);
    gpr_free(buffer_);
    grpc_slice_unref_internal(handshake_status_details_);
    gpr_mu_destroy(&mu_);
  }
}

S2AHandshakerClient::~S2AHandshakerClient() { Unref(); }

void S2AHandshakerClientDestroy(S2AHandshakerClient* client) {
  if (client == nullptr) {
    return;
  }
  delete client;
}

/** ------------------- Testing methods. -------------------------- **/

void S2AHandshakerClient::set_grpc_caller_for_testing(s2a_grpc_caller caller) {
  if (is_test_) {
    grpc_caller_ = caller;
  }
}

grpc_metadata_array* S2AHandshakerClient::initial_metadata_for_testing() {
  return is_test_ ? &recv_initial_metadata_ : nullptr;
}

grpc_byte_buffer** S2AHandshakerClient::recv_buffer_addr_for_testing() {
  return is_test_ ? &recv_buffer_ : nullptr;
}

grpc_byte_buffer* S2AHandshakerClient::send_buffer_for_testing() {
  return is_test_ ? send_buffer_ : nullptr;
}

grpc_closure* S2AHandshakerClient::closure_for_testing() {
  return is_test_ ? &on_handshaker_service_resp_recv_ : nullptr;
}

void S2AHandshakerClient::on_status_received_for_testing(
    grpc_status_code status, grpc_error* error) {
  if (is_test_) {
    handshake_status_code_ = status;
    handshake_status_details_ = grpc_empty_slice();
    grpc_core::Closure::Run(DEBUG_LOCATION, &on_status_received_, error);
  }
}

void s2a_handshaker_client_on_status_received_for_testing(
    S2AHandshakerClient* client, grpc_status_code status, grpc_error* error) {
  if (client == nullptr) {
    return;
  }
  client->on_status_received_for_testing(status, error);
}

}  // namespace experimental
}  // namespace grpc_core
