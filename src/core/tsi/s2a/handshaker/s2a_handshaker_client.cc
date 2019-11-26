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

struct s2a_handshaker_client {
  const s2a_handshaker_client_vtable* vtable;
};

typedef struct alts_grpc_handshaker_client {
  s2a_handshaker_client base;
  /* One ref is held by the entity that created this handshaker_client, and
   * another ref is held by the pending RECEIVE_STATUS_ON_CLIENT op. */
  gpr_refcount refs;
  s2a_tsi_handshaker* handshaker;
  grpc_call* call;
  /* A pointer to a function handling the interaction with handshaker service.
   * That is, it points to grpc_call_start_batch_and_execute when the handshaker
   * client is used in a non-testing use case and points to a custom function
   * that validates the data to be sent to handshaker service in a testing use
   * case. */
  s2a_grpc_caller grpc_caller;
  /* A gRPC closure to be scheduled when the response from handshaker service
   * is received. It will be initialized with the injected grpc RPC callback. */
  grpc_closure on_handshaker_service_resp_recv;
  /* Buffers containing information to be sent (or received) to (or from) the
   * handshaker service. */
  grpc_byte_buffer* send_buffer;
  grpc_byte_buffer* recv_buffer;
  grpc_status_code status;
  /* Initial metadata to be received from handshaker service. */
  grpc_metadata_array recv_initial_metadata;
  /* A callback function provided by an application to be invoked when response
   * is received from handshaker service. */
  tsi_handshaker_on_next_done_cb cb;
  void* user_data;
  /* S2A credential options passed in from the caller. */
  grpc_s2a_credentials_options* options;
  /* target name information to be passed to handshaker service for server
   * authorization check. */
  grpc_slice target_name;
  /* boolean flag indicating if the handshaker client is used at client
   * (is_client = true) or server (is_client = false) side. */
  bool is_client;
  /* a temporary store for data received from handshaker service used to extract
   * unused data. */
  grpc_slice recv_bytes;
  /* a buffer containing data to be sent to the grpc client or server's peer. */
  uint8_t* buffer;
  size_t buffer_size;
  /** callback for receiving handshake call status */
  grpc_closure on_status_received;
  /** gRPC status code of handshake call */
  grpc_status_code handshake_status_code;
  /** gRPC status details of handshake call */
  grpc_slice handshake_status_details;
  /* mu synchronizes all fields below including their internal fields. */
  gpr_mu mu;
  /* indicates if the handshaker call's RECV_STATUS_ON_CLIENT op is done. */
  bool receive_status_finished;
  /* if non-null, contains arguments to complete a TSI next callback. */
  recv_message_result* pending_recv_message_result;
} s2a_grpc_handshaker_client;

tsi_result s2a_handshaker_client_start_client(
    const s2a_handshaker_client* client) {
  return TSI_UNIMPLEMENTED;
}

tsi_result s2a_handshaker_client_start_server(
    const s2a_handshaker_client* client, grpc_slice* bytes_received) {
  return TSI_UNIMPLEMENTED;
}

tsi_result s2a_handshaker_client_next(const s2a_handshaker_client* client,
                                      grpc_slice* bytes_received) {
  return TSI_UNIMPLEMENTED;
}

void s2a_handshaker_client_shutdown(const s2a_handshaker_client* client) {
  return;
}

/** Create and populate a client_start handshaker request, then serialize it. The caller
 *  must ensure |client| was initialized with |s2a_grpc_handshaker_client_create| and,
 *  in particular, that |client| is not nullptr. **/
static grpc_byte_buffer* s2a_get_serialized_start_client(s2a_handshaker_client* client) {
  GPR_ASSERT(client != nullptr);
  s2a_grpc_handshaker_client* s2a_client = reinterpret_cast<s2a_grpc_handshaker_client*>(client);
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

static tsi_result s2a_handshaker_client_internal_start_client(s2a_handshaker_client* client) {
  if (client == nullptr) {
    gpr_log(GPR_ERROR, kS2AHandshakerClientStartClientNullptr);
    return TSI_INVALID_ARGUMENT;
  }
  grpc_byte_buffer* buffer = ...
  if (buffer == nullptr) {
    gpr_log(GPR_ERROR, ...);
    return TSI_INTERNAL_ERROR;
  }
  s2a_grpc_handshaker_client* s2a_client = reinterpret_cast<s2a_grpc_handshaker_client*>(client);
}

static const s2a_handshaker_client_vtable s2a_handshaker_client_internal_vtable = {
  s2a_handshaker_client_internal_start_client,
  s2a_handshaker_client_internal_start_server,
  s2a_handshaker_client_internal_next,
  s2a_handshaker_client_internal_shutdown,
  s2a_handshaker_client_internal_destruct};

tsi_result s2a_grpc_handshaker_client_create(
    s2a_tsi_handshaker* handshaker, grpc_channel* channel,
    const char* handshaker_service_url, grpc_pollset_set* interested_parties,
    grpc_s2a_credentials_options* options, const grpc_slice& target_name,
    grpc_iomgr_cb_func grpc_cb, tsi_handshaker_on_next_done_cb cb,
    void* user_data, bool is_client, s2a_handshaker_client** client) {
  if (channel == nullptr || handshaker_service_url == nullptr || client == nullptr) {
    gpr_log(GPR_ERROR, kS2AHandshakerClientNullptrArguments);
    return TSI_INVALID_ARGUMENT;
  }
  s2a_grpc_handshaker_client* s2a_client = static_cast<s2a_grpc_handshaker_client*>(gpr_zalloc(sizeof(s2a_grpc_handshaker_client)));
  gpr_mu_init(&(s2a_client->mu));
  gpr_ref_init(&(s2a_client->refs), 1);
  s2a_client->grpc_caller = grpc_call_start_batch_and_execute;
  s2a_client->handshaker = handshaker;
  s2a_client->cb = cb;
  s2a_client->user_data = user_data;
  s2a_client->send_buffer = nullptr;
  s2a_client->recv_buffer = nullptr;
  // TODO(mattstev): this API is exposed in a PR that is not yet merged.
  //s2a_client->options = grpc_s2a_credentials_options_copy(options);
  s2a_client->target_name = grpc_slice_copy(target_name);
  s2a_client->recv_bytes = grpc_empty_slice();
  grpc_metadata_array_init(&(s2a_client->recv_initial_metadata));
  s2a_client->is_client = is_client;
  s2a_client->buffer_size = kS2AInitialBufferSize;
  s2a_client->buffer = static_cast<uint8_t*>(gpr_zalloc(s2a_client->buffer_size));
  grpc_slice slice = grpc_slice_from_copied_string(handshaker_service_url);
  s2a_client->call = grpc_channel_create_pollset_set_call(
                channel, /** parent_call **/ nullptr, GRPC_PROPAGATE_DEFAULTS, interested_parties,
                grpc_slice_from_static_string(kS2AServiceMethod), &slice,
                GRPC_MILLIS_INF_FUTURE, /** reserved **/ nullptr);
  s2a_client->base.vtable = &s2a_handshaker_client_internal_vtable;
  GRPC_CLOSURE_INIT(&(s2a_client->on_handshaker_service_resp_recv), grpc_cb, s2a_client,
                    grpc_schedule_on_exec_ctx);
  GRPC_CLOSURE_INIT(&(s2a_client->on_status_received), on_status_received, s2a_client,
                    grpc_schedule_on_exec_ctx);
  grpc_slice_unref_internal(slice);
  *client = s2a_client->base;
  return TSI_OK;
}

void s2a_handshaker_client_destroy(s2a_handshaker_client* client) { return; }

}  // namespace experimental
}  // namespace grpc_core
