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

#ifndef GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_TSI_TEST_UTILITIES_H_
#define GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_TSI_TEST_UTILITIES_H_

#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"
#include "src/core/tsi/s2a/s2a_tsi_handshaker.h"

namespace s2a {
namespace tsi {

/** The following methods are exposed for testing purposes only. **/

absl::StatusOr<tsi_handshaker*> CreateS2ATsiHandshakerForTesting(
    S2ATsiHandshakerOptions& options);

void s2a_check_tsi_handshaker_for_testing(tsi_handshaker* base,
                                          grpc_slice target_name,
                                          bool is_client,
                                          bool has_sent_start_message,
                                          bool has_created_handshaker_client,
                                          bool shutdown);

const ::grpc_s2a_credentials_options* s2a_tsi_handshaker_options_for_testing(
    tsi_handshaker* base);

S2AHandshakerClient* s2a_tsi_handshaker_client_for_testing(
    tsi_handshaker* handshaker);

bool s2a_tsi_handshaker_has_sent_start_message_for_testing(
    tsi_handshaker* handshaker);

void s2a_check_tsi_handshaker_result_for_testing(
    tsi_handshaker_result* base, uint16_t tls_version, uint16_t tls_ciphersuite,
    uint8_t* in_traffic_secret, uint8_t* out_traffic_secret,
    size_t traffic_secret_size, uint64_t in_sequence, uint64_t out_sequence,
    const s2a_options::S2AOptions::Identity& peer_identity,
    const s2a_options::S2AOptions::Identity& local_identity,
    unsigned char* unused_bytes, size_t unused_bytes_size, bool is_client,
    uint64_t connection_id);

typedef tsi_result (*create_mock_handshaker_client)(
    tsi_handshaker* handshaker, grpc_channel* channel,
    grpc_pollset_set* interested_parties, grpc_s2a_credentials_options* options,
    const grpc_slice& target_name, grpc_iomgr_cb_func grpc_cb,
    tsi_handshaker_on_next_done_cb cb, void* user_data, bool is_client,
    S2AHandshakerClient** client);

void s2a_tsi_handshaker_set_create_mock_handshaker_client(
    tsi_handshaker* handshaker, create_mock_handshaker_client create_mock);

void s2a_tsi_handshaker_result_set_channel_for_testing(
    tsi_handshaker_result* result, grpc_channel* channel);

}  // namespace tsi
}  // namespace s2a

#endif  // GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_TSI_TEST_UTILITIES_H_
