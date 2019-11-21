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

#ifndef GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_TSI_HANDSHAKER_H
#define GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_TSI_HANDSHAKER_H

#include <grpc/grpc.h>

#include "src/core/lib/iomgr/pollset_set.h"
#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"
#include "src/core/tsi/transport_security.h"
#include "src/core/tsi/transport_security_interface.h"
#include "src/proto/grpc/gcp/s2a.upb.h"

namespace grpc_core {
namespace experimental {

typedef struct s2a_tsi_handshaker s2a_tsi_handshaker;

/** This method populates |self| with an instance of the s2a_tsi_handshaker,
 *  which is configured using the other arguments.
 * - options: S2A-specific options used to configure the s2a_tsi_handshaker.
 * - target_name: the name of the endpoint to which the channel connects; this
 *   data will be used for a secure naming check.
 * - handshaker_service_url: the address of S2A handshaker service; it follows
 *   the format "host:port".
 * - is_client: a boolean that is true if |client| is used at the client side,
 *   and false if |client| is used at the server side.
 * - interested_parties: set of pollsets interested in this connection.
 * - self: the address of S2A TSI handshaker instance to be populated by the
 *   method; the caller must ensure that |self| is not nullptr.
 * - error_details: an error message for when the creation fails. It is legal
 *   (and expected) to have |error_details| point to a nullptr.
 *
 * It returns TSI_OK on success and an error status code on failure. Note that
 * if interested_parties is nullptr, a dedicated TSI thread will be created and
 * used. **/
tsi_result s2a_tsi_handshaker_create(
    const grpc_s2a_credentials_options* options, const char* target_name,
    const char* handshaker_service_url, bool is_client,
    grpc_pollset_set* interested_parties, tsi_handshaker** self,
    char** error_details);

/** This method creates an S2A TSI handshaker result instance.
 *  - response: the data received from the S2A handshaker service.
 *  - is_client: a boolean that is true if |client| is used at the client side,
 *    and false if |client| is used at the server side.
 *  - result: the address of the S2A TSI handshaker result instance to be
 *    populated by the method. **/
tsi_result s2a_tsi_handshaker_result_create(s2a_SessionResp* response,
                                            bool is_client,
                                            tsi_handshaker_result** result);

/** This method sets the unused bytes of an S2A TSI handshaker result instance.
 * - result: an S2A TSI handshaker result instance.
 * - recv_bytes: data received from the handshaker service.
 * - bytes_consumed: size of data consumed by the handshaker service. **/
void s2a_tsi_handshaker_result_set_unused_bytes(tsi_handshaker_result* result,
                                                grpc_slice* recv_bytes,
                                                size_t bytes_consumed);

/** This method returns a boolean value indicating whether or not an
 *  s2a_tsi_handshaker instance has been shutdown. **/
bool s2a_tsi_handshaker_has_shutdown(s2a_tsi_handshaker* handshaker);

}  // namespace experimental
}  // namespace grpc_core

#endif  // GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_TSI_HANDSHAKER_H
