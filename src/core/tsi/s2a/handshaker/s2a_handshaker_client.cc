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

#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"

#include <grpc/support/alloc.h>
#include <grpc/support/log.h>

#include "src/core/tsi/s2a/handshaker/s2a_handshaker_util.h"
#include "src/core/tsi/s2a/s2a_tsi_handshaker.h"
#include "src/core/tsi/s2a/handshaker/s2a_tsi_test_utilities.h"
#include "src/core/tsi/s2a/s2a_security.h"
#include "absl/strings/str_cat.h"
#include "src/core/lib/slice/slice_internal.h"
#include "src/core/lib/surface/call.h"
#include "src/core/lib/surface/channel.h"
#include "s2a/include/access_token_manager.h"
#include "s2a/include/access_token_manager_factory.h"
#include "s2a/include/s2a_proxy.h"
#include "s2a/src/proto/upb-generated/proto/common.upb.h"
#include "s2a/src/proto/upb-generated/proto/s2a.upb.h"
#include "upb/upb.hpp"

namespace s2a {
namespace tsi {
namespace {

void S2AProxyLogger(const std::string& message) {
  gpr_log(GPR_INFO, "%s", message.c_str());
}

}  // namespace

tsi_result S2AHandshakerClient::MakeGrpcCallUtil(bool is_start) {
  is_start_ = false;
  tsi_result call_result = MakeGrpcCall(is_start);
  if (call_result != TSI_OK) {
    gpr_log(GPR_ERROR, kS2AMakeGrpcCallFailed);
    return call_result;
  }
  return TSI_OK;
}

tsi_result S2AHandshakerClient::Next(grpc_slice* bytes_received) {
  GPR_ASSERT(bytes_received != nullptr);
  if (is_test_ && next_ != nullptr) {
    return next_(this, bytes_received);
  }
  grpc_slice_unref_internal(recv_bytes_);
  recv_bytes_ = grpc_slice_ref_internal(*bytes_received);

  auto bytes_from_peer =
      absl::make_unique<std::vector<char>>(GRPC_SLICE_LENGTH(recv_bytes_));
  if (bytes_from_peer != nullptr) {
    memcpy(bytes_from_peer->data(), GRPC_SLICE_START_PTR(recv_bytes_),
           GRPC_SLICE_LENGTH(recv_bytes_));
  }

  s2a_proxy::S2AProxy::ProxyStatus status =
      proxy_->GetBytesForS2A(std::move(bytes_from_peer));
  if (!status.status.ok()) {
    return TSI_INTERNAL_ERROR;
  }

  grpc_slice slice = status.buffer == nullptr
                         ? grpc_empty_slice()
                         : grpc_slice_from_copied_buffer(status.buffer->data(),
                                                         status.buffer->size());
  grpc_byte_buffer* byte_buffer = grpc_raw_byte_buffer_create(&slice, 1);
  grpc_slice_unref_internal(slice);
  if (byte_buffer == nullptr) {
    gpr_log(GPR_ERROR, "Failed to serialize request to S2A");
    return TSI_INTERNAL_ERROR;
  }
  grpc_byte_buffer_destroy(send_buffer_);
  send_buffer_ = byte_buffer;
  return MakeGrpcCallUtil(is_start_);
}

/** ------------------- Callback methods. -------------------------------- **/

static void S2AOnStatusReceived(void* arg, grpc_error_handle error) {
  S2AHandshakerClient* client = static_cast<S2AHandshakerClient*>(arg);
  GPR_ASSERT(client != nullptr);
  if (client->handshake_status_code() != GRPC_STATUS_OK) {
    char* status_details =
        grpc_slice_to_c_string(client->handshake_status_details());
    gpr_log(GPR_INFO,
            "S2AHandshakerClient:%p on_status_received status:%d "
            "details:|%s| error:|%s|",
            client, client->handshake_status_code(), status_details,
            grpc_error_std_string(error).c_str());
    gpr_free(status_details);
  }
  client->MaybeCompleteTsiNext(/*receive_status_finished=*/true,
                               /*pending_recv_message_result=*/nullptr);
  client->Unref();
}

/** ------------------- Create, shutdown, & destroy methods. ------------- **/

S2AHandshakerClient::S2AHandshakerClient(
    tsi_handshaker* handshaker, grpc_channel* channel,
    grpc_pollset_set* interested_parties, grpc_s2a_credentials_options* options,
    const grpc_slice& target_name, grpc_iomgr_cb_func grpc_cb,
    tsi_handshaker_on_next_done_cb cb, void* user_data, bool is_client,
    bool is_test, std::unique_ptr<s2a_proxy::S2AProxy> proxy)
    : handshaker_(handshaker),
      channel_(channel),
      grpc_caller_(grpc_call_start_batch_and_execute),
      send_buffer_(nullptr),
      recv_buffer_(nullptr),
      cb_(cb),
      user_data_(user_data),
      options_(options),
      target_name_(grpc_slice_copy(target_name)),
      is_client_(is_client),
      recv_bytes_(grpc_empty_slice()),
      buffer_size_(kS2AInitialBufferSize),
      handshake_status_details_(grpc_empty_slice()),
      is_test_(is_test),
      proxy_(std::move(proxy)) {
  refs_ = static_cast<gpr_refcount*>(gpr_zalloc(sizeof(gpr_refcount)));
  gpr_ref_init(refs_, 1);
  grpc_metadata_array_init(&recv_initial_metadata_);
  buffer_ = static_cast<uint8_t*>(gpr_zalloc(buffer_size_));
  grpc_slice slice = grpc_slice_from_copied_string(
      options->s2a_options.s2a_address().c_str());
  std::string test_handshaker_service_url(kS2AHandshakerServiceUrlForTesting);
  call_ = (options->s2a_options.s2a_address() ==
           test_handshaker_service_url)
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
    tsi_handshaker* handshaker, grpc_channel* channel,
    grpc_pollset_set* interested_parties, grpc_s2a_credentials_options* options,
    const grpc_slice& target_name, grpc_iomgr_cb_func grpc_cb,
    tsi_handshaker_on_next_done_cb cb, void* user_data, bool is_client,
    bool is_test, S2AHandshakerClient** client) {
  if (channel == nullptr || client == nullptr || options == nullptr ||
      options->s2a_options.s2a_address().empty()) {
    gpr_log(GPR_ERROR, kS2AHandshakerClientNullptrArguments);
    return TSI_INVALID_ARGUMENT;
  }
  std::string target_name_str(reinterpret_cast<char*>(const_cast<uint8_t*>(
                                  GRPC_SLICE_START_PTR(target_name))),
                              GRPC_SLICE_LENGTH(target_name));
  absl::StatusOr<std::unique_ptr<token_manager::AccessTokenManagerInterface>>
      token_manager = token_manager::BuildAccessTokenManager();
  if (!token_manager.ok()) {
    gpr_log(GPR_INFO, "%s",
            absl::StrCat("Failed to build access token manager: ",
                         token_manager.status().message())
                .c_str());
  }
  // TODO(b/161283415) Populate channel factory and channel options with C-core
  // implementations.
  s2a_proxy::S2AProxy::S2AProxyOptions proxy_options = {
      S2AProxyLogger,
      is_client,
      kS2AApplicationProtocol,
      target_name_str,
      options->s2a_options.Copy(),
      /*channel_factory=*/nullptr,
      /*channel_options=*/nullptr,
      token_manager.ok() ? std::move(*token_manager) : nullptr};
  *client = new S2AHandshakerClient(handshaker, channel, interested_parties,
                                    options, target_name, grpc_cb, cb,
                                    user_data, is_client, is_test,
                                    s2a_proxy::S2AProxy::Create(proxy_options));
  return TSI_OK;
}

void S2AHandshakerClient::Shutdown() {
  if (call_ != nullptr) {
    grpc_call_cancel_internal(call_);
  }
}

/** This method destroys the grpc_call owned by the s2a_handshaker_client. **/
static void S2AHandshakerCallUnref(void* arg, grpc_error_handle error) {
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
    delete this;
  }
}

S2AHandshakerClient::~S2AHandshakerClient() {}

void S2AHandshakerClientDestroy(S2AHandshakerClient* client) {
  if (client == nullptr) {
    return;
  }
  client->Unref();
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
    grpc_status_code status, grpc_error_handle error) {
  if (is_test_) {
    handshake_status_code_ = status;
    handshake_status_details_ = grpc_empty_slice();
    grpc_core::Closure::Run(DEBUG_LOCATION, &on_status_received_, error);
  }
}

void s2a_handshaker_client_on_status_received_for_testing(
    S2AHandshakerClient* client, grpc_status_code status,
    grpc_error_handle error) {
  if (client == nullptr) {
    return;
  }
  client->on_status_received_for_testing(status, error);
}

void S2AHandshakerClient::SetFieldsForTesting(tsi_handshaker* handshaker,
                                              tsi_handshaker_on_next_done_cb cb,
                                              void* user_data,
                                              grpc_byte_buffer* recv_buffer,
                                              grpc_status_code status) {
  if (!is_test_) {
    return;
  }
  handshaker_ = handshaker;
  cb_ = cb;
  user_data_ = user_data;
  recv_buffer_ = recv_buffer;
  status_ = status;
}

void S2AHandshakerClient::CheckFieldsForTesting(
    tsi_handshaker_on_next_done_cb cb, void* user_data,
    bool has_sent_start_message, grpc_slice* recv_bytes) {
  if (!is_test_) {
    return;
  }
  GPR_ASSERT(cb_ = cb);
  GPR_ASSERT(user_data_ == user_data);
  GPR_ASSERT(handshaker_ != nullptr);
  GPR_ASSERT(s2a_tsi_handshaker_has_sent_start_message_for_testing(
                 handshaker_) == has_sent_start_message);
  if (recv_bytes != nullptr) {
    GPR_ASSERT(grpc_slice_cmp(recv_bytes_, *recv_bytes) == 0);
  }
}

bool S2AHandshakerClient::is_client_for_testing() {
  if (!is_test_) {
    return false;
  }
  return is_client_;
}

void S2AHandshakerClient::set_cb_for_testing(
    tsi_handshaker_on_next_done_cb cb) {
  if (!is_test_) {
    return;
  }
  cb_ = cb;
}

void S2AHandshakerClient::set_recv_bytes_for_testing(grpc_slice* recv_bytes) {
  if (!is_test_) {
    return;
  }
  GPR_ASSERT(recv_bytes != nullptr);
  recv_bytes_ = grpc_slice_ref_internal(*recv_bytes);
}

void S2AHandshakerClient::ref_for_testing() {
  if (!is_test_) {
    return;
  }
  gpr_ref(refs_);
}

void S2AHandshakerClient::set_mock_next_for_testing(s2a_mock_next next) {
  if (!is_test_) {
    return;
  }
  next_ = next;
}

}  // namespace tsi
}  // namespace s2a
