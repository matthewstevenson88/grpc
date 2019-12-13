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

#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include "src/core/tsi/alts/handshaker/alts_tsi_utils.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_util.h"
#include "src/core/tsi/s2a/handshaker/s2a_tsi_handshaker.h"

namespace grpc_core {
namespace experimental {

/** This file contains the implementation details of the |make_grpc_call| member
 *  function of the |S2AHandshakerClient| class. This method enables the S2A
 *  handshaker client to make a gRPC call to the S2A service. **/

const size_t kHandshakerClientOpNum = 4;

/** The implementation of |make_grpc_call| is nearly identical to that of its
 *  ALTS counterpart, the |make_grpc_call| method in alts_handshaker_client.cc.
 */
tsi_result S2AHandshakerClient::MakeGrpcCall(bool is_start) {
  grpc_op ops[kHandshakerClientOpNum];
  memset(ops, 0, sizeof(ops));
  grpc_op* op = ops;
  if (is_start) {
    op->op = GRPC_OP_RECV_STATUS_ON_CLIENT;
    op->data.recv_status_on_client.trailing_metadata = nullptr;
    op->data.recv_status_on_client.status = &handshake_status_code_;
    op->data.recv_status_on_client.status_details = &handshake_status_details_;
    op->flags = 0;
    op->reserved = nullptr;
    op++;
    GPR_ASSERT(op - ops <= kHandshakerClientOpNum);
    gpr_ref(refs_);
    GPR_ASSERT(grpc_caller_ != nullptr);
    grpc_call_error call_error = grpc_caller_(
        call_, ops, static_cast<size_t>(op - ops), &on_status_received_);
    GPR_ASSERT(call_error == GRPC_CALL_OK);
    memset(ops, 0, sizeof(ops));
    op = ops;
    op->op = GRPC_OP_SEND_INITIAL_METADATA;
    op->data.send_initial_metadata.count = 0;
    op++;
    GPR_ASSERT(op - ops <= kHandshakerClientOpNum);
    op->op = GRPC_OP_RECV_INITIAL_METADATA;
    op->data.recv_initial_metadata.recv_initial_metadata =
        &recv_initial_metadata_;
    op++;
    GPR_ASSERT(op - ops <= kHandshakerClientOpNum);
  }
  op->op = GRPC_OP_SEND_MESSAGE;
  op->data.send_message.send_message = send_buffer_;
  op++;
  GPR_ASSERT(op - ops <= kHandshakerClientOpNum);
  op->op = GRPC_OP_RECV_MESSAGE;
  op->data.recv_message.recv_message = &recv_buffer_;
  op++;
  GPR_ASSERT(op - ops <= kHandshakerClientOpNum);
  GPR_ASSERT(grpc_caller_ != nullptr);
  if (grpc_caller_(call_, ops, static_cast<size_t>(op - ops),
                   &on_handshaker_service_resp_recv_) != GRPC_CALL_OK) {
    gpr_log(GPR_ERROR, "Start batch operation failed");
    return TSI_INTERNAL_ERROR;
  }
  return TSI_OK;
}

/** The implementation of this method is nearly identical to its ALTS
 *  counterpart, |maybe_complete_tsi_next| in alts_handshaker_client.cc. **/
void S2AHandshakerClient::MaybeCompleteTsiNext(
    bool receive_status_finished,
    s2a_recv_message_result* pending_recv_message_result) {
  s2a_recv_message_result* r = nullptr;
  {
    grpc_core::MutexLock lock(&mu_);
    receive_status_finished_ |= receive_status_finished;
    if (pending_recv_message_result != nullptr) {
      GPR_ASSERT(pending_recv_message_result_ == nullptr);
      pending_recv_message_result_ = pending_recv_message_result;
    }
    if (pending_recv_message_result_ == nullptr) {
      return;
    }
    bool have_final_result =
        (pending_recv_message_result_->result != nullptr) ||
        (pending_recv_message_result_->status != TSI_OK);
    if (have_final_result && !receive_status_finished_) {
      return;
    }
    r = pending_recv_message_result_;
    pending_recv_message_result_ = nullptr;
  }
  GPR_ASSERT(cb_ != nullptr);
  GPR_ASSERT(r != nullptr);
  cb_(r->status, user_data_, r->bytes_to_send, r->bytes_to_send_size,
      r->result);
  gpr_free(r);
}

void S2AHandshakerClient::HandleResponseDone(tsi_result status,
                                             const uint8_t* bytes_to_send,
                                             size_t bytes_to_send_size,
                                             tsi_handshaker_result* result) {
  s2a_recv_message_result* p =
      static_cast<s2a_recv_message_result*>(gpr_zalloc(sizeof(*p)));
  p->status = status;
  p->bytes_to_send = bytes_to_send;
  p->bytes_to_send_size = bytes_to_send_size;
  p->result = result;
  MaybeCompleteTsiNext(/* receive_status_finished=*/false,
                       /* pending_recv_message_result=*/p);
}

void S2AHandshakerClient::HandleResponse(bool is_ok) {
  /** Invalid input check. **/
  if (cb_ == nullptr) {
    gpr_log(GPR_ERROR,
            "The |cb_| callback function is nullptr in |handle_response|.");
    return;
  }
  if (handshaker_ == nullptr) {
    gpr_log(GPR_ERROR,
            "The |handshaker_| field is nullptr in |handle_response|.");
    HandleResponseDone(TSI_INTERNAL_ERROR, /* bytes_to_send=*/nullptr,
                       /* bytes_to_send_size=*/0,
                       /* result=*/nullptr);
    return;
  }

  /** Handle the case when the TSI handshake has been shutdown. **/
  if (s2a_tsi_handshaker_has_shutdown(handshaker_)) {
    gpr_log(GPR_ERROR, "The TSI handshake was shutdown.");
    HandleResponseDone(TSI_HANDSHAKE_SHUTDOWN, /* bytes_to_send=*/nullptr,
                       /* bytes_to_send_size=*/0,
                       /* result=*/nullptr);
    return;
  }

  /** Failed grpc call check. **/
  if (!is_ok || status_ != GRPC_STATUS_OK) {
    gpr_log(GPR_ERROR,
            "The gRPC call made to the S2A handshaker service failed.");
    HandleResponseDone(TSI_INTERNAL_ERROR, /* bytes_to_send=*/nullptr,
                       /* bytes_to_send_size=*/0,
                       /* result=*/nullptr);
    return;
  }
  if (recv_buffer_ == nullptr) {
    gpr_log(GPR_ERROR,
            "The |recv_buffer_| buffer is nullptr in |handle_response|.");
    HandleResponseDone(TSI_INTERNAL_ERROR, /* bytes_to_send=*/nullptr,
                       /* bytes_to_send_size=*/0,
                       /* result=*/nullptr);
    return;
  }

  upb::Arena arena;
  s2a_SessionResp* response =
      s2a_deserialize_session_resp(arena.ptr(), recv_buffer_);
  grpc_byte_buffer_destroy(recv_buffer_);
  recv_buffer_ = nullptr;

  /** Invalid handshaker response check. **/
  if (response == nullptr) {
    gpr_log(GPR_ERROR, "The |s2a_deserialize_session_resp| method failed.");
    HandleResponseDone(TSI_DATA_CORRUPTED, /* bytes_to_send=*/nullptr,
                       /* bytes_to_send_size=*/0,
                       /* result=*/nullptr);
    return;
  }
  const s2a_SessionStatus* session_status = s2a_SessionResp_status(response);
  if (session_status == nullptr) {
    gpr_log(GPR_ERROR, "No status in the |SessionResp|.");
    HandleResponseDone(TSI_DATA_CORRUPTED, /* bytes_to_send=*/nullptr,
                       /* bytes_to_send_size=*/0,
                       /* result=*/nullptr);
    return;
  }
  upb_strview out_frames = s2a_SessionResp_out_frames(response);
  uint8_t* bytes_to_send = nullptr;
  size_t bytes_to_send_size = 0;
  if (out_frames.size > 0) {
    bytes_to_send_size = out_frames.size;
    while (bytes_to_send_size > buffer_size_) {
      buffer_size_ *= 2;
      buffer_ = static_cast<uint8_t*>(gpr_realloc(buffer_, buffer_size_));
    }
    memcpy(buffer_, out_frames.data, bytes_to_send_size);
    bytes_to_send = buffer_;
  }

  tsi_handshaker_result* result = nullptr;
  if (s2a_SessionResp_result(response)) {
    tsi_result create_result =
        s2a_tsi_handshaker_result_create(response, is_client_, &result);
    if (create_result != TSI_OK) {
      gpr_log(GPR_ERROR,
              "The |s2a_tsi_handshaker_result_create| method failed.");
      return;
    }
    s2a_tsi_handshaker_result_set_unused_bytes(
        result, &recv_bytes_,
        static_cast<size_t>(s2a_SessionResp_bytes_consumed(response)));
  }
  grpc_status_code code =
      static_cast<grpc_status_code>(s2a_SessionStatus_code(session_status));
  if (code != GRPC_STATUS_OK) {
    upb_strview details = s2a_SessionStatus_details(session_status);
    if (details.size > 0) {
      char* error_details = (char*)gpr_zalloc(details.size + 1);
      memcpy(error_details, details.data, details.size);
      gpr_log(GPR_ERROR, "Error from S2A handshaker service:%s", error_details);
      gpr_free(error_details);
    }
  }
  HandleResponseDone(alts_tsi_utils_convert_to_tsi_result(code), bytes_to_send,
                     bytes_to_send_size, result);
}

}  // namespace experimental
}  // namespace grpc_core
