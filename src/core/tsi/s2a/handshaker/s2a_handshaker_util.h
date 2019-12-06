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

#ifndef GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_UTIL_H
#define GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_UTIL_H

#include <grpc/byte_buffer.h>
#include <grpc/support/port_platform.h>
#include "src/proto/grpc/gcp/s2a.upb.h"

namespace grpc_core {
namespace experimental {

/** This method converts the ciphersuite bytes (as defined in s2a_constants.h)
 *  to the corresponding integer (as defined in s2a.proto). **/
int32_t s2a_convert_ciphersuite_to_enum(uint16_t ciphersuite);

/** This method serializes |request| into a buffer, and returns a newly created
 *  grpc_byte_buffer that holds this buffer. **/
grpc_byte_buffer* s2a_get_serialized_session_req(s2a_SessionReq* request,
                                                 upb_arena* arena);

}  // namespace experimental
}  // namespace grpc_core

#endif  // GRPC_CORE_TSI_S2A_HANDSHAKER_UTIL_H
