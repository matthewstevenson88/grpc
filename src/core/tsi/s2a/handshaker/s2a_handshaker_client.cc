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
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/s2a_constants.h"

namespace grpc_core {
namespace experimental {

/** ------------ Preparation of client start messages. --------------- **/

/** Create and populate a client_start handshaker request, then serialize it.
 *  The caller must ensure |client| was initialized with
 *  |s2a_grpc_handshaker_client_create| and, in particular, that |client| is not
 *  nullptr. **/
static grpc_byte_buffer* s2a_get_serialized_start_client(
    s2a_handshaker_client* client) {
  GPR_ASSERT(client != nullptr);
  s2a_grpc_handshaker_client* s2a_client =
      reinterpret_cast<s2a_grpc_handshaker_client*>(client);
  upb::Arena arena;
  s2a_SessionReq* request = s2a_SessionReq_new(arena.ptr());
  grpc_gcp_StartClientHandshakeReq* start_client =
      grpc_gcp_HandshakerReq_mutable_client_start(req, arena.ptr());
  grpc_gcp_StartClientHandshakeReq_set_handshake_security_protocol(
      start_client, grpc_gcp_ALTS);
  grpc_gcp_StartClientHandshakeReq_add_application_protocols(
      start_client, upb_strview_makez(ALTS_APPLICATION_PROTOCOL), arena.ptr());
  grpc_gcp_StartClientHandshakeReq_add_record_protocols(
      start_client, upb_strview_makez(ALTS_RECORD_PROTOCOL), arena.ptr());
  grpc_gcp_RpcProtocolVersions* client_version =
      grpc_gcp_StartClientHandshakeReq_mutable_rpc_versions(start_client,
                                                            arena.ptr());
  grpc_gcp_RpcProtocolVersions_assign_from_struct(
      client_version, arena.ptr(), &client->options->rpc_versions);
  grpc_gcp_StartClientHandshakeReq_set_target_name(
      start_client,
      upb_strview_make(reinterpret_cast<const char*>(
                           GRPC_SLICE_START_PTR(client->target_name)),
                       GRPC_SLICE_LENGTH(client->target_name)));
  target_service_account* ptr =
      (reinterpret_cast<grpc_alts_credentials_client_options*>(client->options))
          ->target_account_list_head;
  while (ptr != nullptr) {
    grpc_gcp_Identity* target_identity =
        grpc_gcp_StartClientHandshakeReq_add_target_identities(start_client,
                                                               arena.ptr());
    grpc_gcp_Identity_set_service_account(target_identity,
                                          upb_strview_makez(ptr->data));
    ptr = ptr->next;
  }
  return get_serialized_handshaker_req(req, arena.ptr());
}

tsi_result s2a_handshaker_client::client_start() {
  grpc_byte_buffer* buffer = s2a_get_serialized_start_client(this);
  if (buffer == nullptr) {
    gpr_log(GPR_ERROR, kS2AGetSerializedStartClientFailed);
    return TSI_INTERNAL_ERROR;
  }
  grpc_byte_buffer_destroy(send_buffer_);
  send_buffer_ = buffer;
  tsi_result call_result = make_grpc_call(/** is_start **/ true);
  if (result != TSI_OK) {
    gpr_log(GPR_ERROR, kS2AMakeGrpcCallFailed);
  }
  return call_result;
}

/** ------------------- Create & destroy methods. ------------------------- **/

s2a_handshaker_client::s2a_handshaker_client(
    s2a_tsi_handshaker* handshaker, grpc_channel* channel,
    grpc_pollset_set* interested_parties, grpc_s2a_credentials_options* options,
    const grpc_slice& target_name, grpc_iomgr_cb_func grpc_cb,
    tsi_handshaker_on_next_done_cb cb, void* user_data, bool is_client) {
  gpr_mu_init(&mu_);
  gpr_ref_init(&refs_, 1);
  grpc_caller_ = grpc_call_start_batch_and_execute;
  handshaker_ = handshaker;
  cb_ = cb;
  user_data_ = user_data;
  send_buffer_ = nullptr;
  recv_buffer_ = nullptr;
  target_name_ = grpc_slice_copy(target_name);
  // TODO(mattstev): the API used below is exposed in a PR that is not yet
  // merged.
  // options_ = options->copy();
  recv_bytes_ = grpc_empty_slice();
  grpc_metadata_array_init(&recv_initial_metadata_);
  is_client_ = is_client;
  buffer_size_ = kS2AInitialBufferSize;
  buffer_ = static_cast<uint8_t*>(gpr_zalloc(buffer_size_));
  // TODO(mattstev): the API used below is exposed in a PR that is not yet
  // merged.
  // grpc_slice slice =
  // grpc_slice_from_copied_string(options->handshaker_service_url());
  call_ = grpc_channel_create_pollset_set_call(
      channel, /** parent_call **/ nullptr, GRPC_PROPAGATE_DEFAULTS,
      interested_parties, grpc_slice_from_static_string(kS2AServiceMethod),
      &slice, GRPC_MILLIS_INF_FUTURE, /** reserved **/ nullptr);
  GRPC_CLOSURE_INIT(&on_handshaker_service_resp_recv_, grpc_cb, &this,
                    grpc_schedule_on_exec_ctx);
  GRPC_CLOSURE_INIT(&on_status_received_, on_status_received, &this,
                    grpc_schedule_on_exec_ctx);
  grpc_slice_unref_internal(slice);
}

tsi_result s2a_handshaker_client_create(
    s2a_tsi_handshaker* handshaker, grpc_channel* channel,
    grpc_pollset_set* interested_parties, grpc_s2a_credentials_options* options,
    const grpc_slice& target_name, grpc_iomgr_cb_func grpc_cb,
    tsi_handshaker_on_next_done_cb cb, void* user_data, bool is_client,
    s2a_handshaker_client** client) {
  if (channel == nullptr || handshaker_service_url == nullptr ||
      client == nullptr || options == nullptr) {
    gpr_log(GPR_ERROR, kS2AHandshakerClientNullptrArguments);
    return TSI_INVALID_ARGUMENT;
  }
  *client = new s2a_handshaker_client(handshaker, channel, interested_parties,
                                      options, target_name, grpc_cb, cb,
                                      user_data, is_client);
  return TSI_OK;
}

/** This method destroys the grpc_call owned by the s2a_handshaker_client. **/
static void s2a_handshaker_call_unref(void* arg, grpc_error* error) {
  grpc_call* call = static_cast<grpc_call*>(arg);
  grpc_call_unref(call);
}

s2a_handshaker_client::~s2a_handshaker_client() {
  if (gpr_unref(&refs_)) {
    if (call_ != nullptr) {
      grpc_core::ExecCtx::Run(
          DEBUG_LOCATION,
          GRPC_CLOSURE_CREATE(s2a_handshaker_call_unref, call_,
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
    // TODO(mattstev): the API used below is exposed in a PR that is not yet
    // merged.
    // grpc_s2a_credentials_options_destroy(options_);
    gpr_free(buffer_);
    grpc_slice_unref_internal(handshake_status_details_);
    gpr_mu_destroy(&mu_);
  }
}

void s2a_handshaker_client_destroy(s2a_handshaker_client* client) {
  if (client == nullptr) {
    return;
  }
  delete client;
}

}  // namespace experimental
}  // namespace grpc_core
